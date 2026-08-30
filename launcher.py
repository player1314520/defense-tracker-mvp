"""
防务数据追踪系统 V9 — 桌面应用启动器
使用 PyWebView 创建原生桌面窗口（无浏览器地址栏）
"""
import hmac
import os
import re
import socket
import sys
import threading
import time

# The packaged EXE doubles as the isolated PDF parser worker. Dispatch before
# runtime migration, Flask, scheduler, or GUI initialization so untrusted PDF
# handling cannot start the desktop application as a side effect.
if len(sys.argv) > 1 and sys.argv[1] == "--defense-tracker-pdf-worker":
    from document_safety import _pdf_worker_main

    raise SystemExit(_pdf_worker_main(["--pdf-worker-output", *sys.argv[2:]]))

# 桌面壳必须在导入 app 前强制启用鉴权。受信 WebView 稍后仅获得
# 一次性引导能力，由服务端换成 HttpOnly 会话，长期令牌不暴露给 JS。
os.environ["ACCESS_TOKEN_REQUIRED"] = "1"
os.environ["DEFENSE_TRACKER_DESKTOP_BOOTSTRAP"] = "1"

# ── 路径修正（PyInstaller 打包后文件在 _MEIPASS）─────────────
if getattr(sys, 'frozen', False):
    BASE_DIR = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

os.chdir(BASE_DIR)

from product_version import PRODUCT_VERSION, current_build_commit
from v9.webview2_runtime import detect_webview2_runtime


def _require_compatible_webview2_before_startup():
    if os.name != "nt":
        return
    detection = detect_webview2_runtime()
    if detection.compatible:
        return
    title = "DefenseTracker V9"
    message = (
        "需要 Microsoft Edge WebView2 Runtime (x64)。\n\n"
        "DefenseTracker 已阻止旧版 MSHTML 回退。请从微软官方下载并安装 "
        "WebView2 Runtime 后重新启动。"
    )
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, message, title, 0x10)
    except (AttributeError, OSError):
        print("[错误] 需要 Microsoft Edge WebView2 Runtime (x64)。")
    raise SystemExit(78)


if __name__ == "__main__":
    # Fail before runtime directories, Flask, schedulers, or authentication
    # state are initialized. A later renderer assertion independently catches
    # broken registrations and pywebview fallbacks.
    _require_compatible_webview2_before_startup()

# ── 可写运行目录（程序目录始终只读）──────────────────────────
from state import RUNTIME_LAYOUT, ensure_runtime_layout, migrate_legacy_runtime
from v9.desktop_smoke import (
    DESKTOP_SMOKE_ENDPOINT,
    DesktopSmokeEvidenceStore,
    normalize_desktop_smoke_renderer,
)

ensure_runtime_layout(RUNTIME_LAYOUT)
if getattr(sys, "frozen", False):
    # 仅为旧版本升级执行非破坏性迁移；已有新位置文件永不覆盖。
    migrate_legacy_runtime(os.path.dirname(sys.executable), RUNTIME_LAYOUT)

# ── 五个 Supabase Auth 预登记 loopback 端口（避免宽泛回调）────
AUTH_REDIRECT_PORTS = (49231, 49232, 49233, 49234, 49235)


def find_free_port(ports=AUTH_REDIRECT_PORTS):
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('127.0.0.1', port))
                return port
            except OSError:
                continue
    raise RuntimeError("五个已登记的 Supabase 登录回调端口均被占用")

PORT = find_free_port()

# ── 导入 Flask 应用（不触发 __main__ 块）────────────────────
from app import (
    app as flask_app,
    refresh_news,
    add_background_jobs,
    get_desktop_bootstrap_token,
    require_auth,
)
from apscheduler.schedulers.background import BackgroundScheduler
from flask import jsonify, request


_DESKTOP_SMOKE_TRANSPORT = "authenticated-loopback-v1"
_DESKTOP_SMOKE_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")


def _desktop_smoke_transport_token():
    transport = os.environ.get("DEFENSE_TRACKER_SMOKE_EVIDENCE", "").strip()
    if not transport:
        return None
    if transport != _DESKTOP_SMOKE_TRANSPORT:
        raise RuntimeError("unsupported desktop smoke evidence transport")
    token = os.environ.get("DEFENSE_TRACKER_SMOKE_TOKEN", "").strip()
    if _DESKTOP_SMOKE_TOKEN_RE.fullmatch(token) is None:
        raise RuntimeError("desktop smoke transport requires a 256-bit lowercase token")
    return token


_desktop_smoke_token = _desktop_smoke_transport_token()
_desktop_smoke_store = None
_desktop_renderer = None


if _desktop_smoke_token is not None:
    _desktop_smoke_store = DesktopSmokeEvidenceStore(
        PRODUCT_VERSION.semantic_version,
        PRODUCT_VERSION.display_version,
        PRODUCT_VERSION.release_tag,
        current_build_commit(),
    )

    @flask_app.context_processor
    def _desktop_smoke_template_context():
        return {"desktop_release_smoke_enabled": True}

    @flask_app.get(DESKTOP_SMOKE_ENDPOINT)
    def _get_desktop_smoke_evidence():
        supplied = request.headers.get("X-Defense-Tracker-Smoke", "")
        if (
            _DESKTOP_SMOKE_TOKEN_RE.fullmatch(supplied) is None
            or not hmac.compare_digest(supplied, _desktop_smoke_token)
        ):
            return "", 404
        evidence = _desktop_smoke_store.snapshot()
        if evidence is None:
            return "", 425
        payload = {
            "process_id": os.getpid(),
            "renderer": _desktop_smoke_store.renderer,
            "evidence": evidence,
        }
        response = jsonify(payload)
        response.headers["Cache-Control"] = "no-store"
        return response

    @flask_app.post(DESKTOP_SMOKE_ENDPOINT)
    @require_auth
    def _submit_desktop_smoke_evidence():
        expected_origin = f"http://127.0.0.1:{PORT}"
        if (
            request.host != f"127.0.0.1:{PORT}"
            or request.headers.get("Origin") != expected_origin
        ):
            return "", 404
        if request.mimetype != "application/json":
            return "", 400
        content_length = request.content_length
        if content_length is None or not 0 < content_length <= 4096:
            return "", 400
        payload = request.get_json(silent=True)
        if not _desktop_smoke_store.submit(payload):
            return "", 400
        return "", 204

# ── 后台 Flask 线程 ──────────────────────────────────────────
def _run_flask():
    flask_app.run(host='127.0.0.1', port=PORT, debug=False,
                  use_reloader=False, threaded=True)

# ── 等待 Flask 就绪 ──────────────────────────────────────────
def _wait_for_flask(timeout=30):
    import urllib.request, urllib.error
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(
                f'http://127.0.0.1:{PORT}/api/status', timeout=1)
            return True
        except urllib.error.HTTPError:
            # 收到 HTTP 响应（如 401 未授权）就证明 Flask 已就绪，require_auth 才能挡
            return True
        except Exception:
            time.sleep(0.4)
    return False


def _prepare_desktop_login_url():
    if not _wait_for_flask():
        raise RuntimeError("桌面服务启动超时")
    bootstrap = get_desktop_bootstrap_token()
    if not bootstrap:
        raise RuntimeError("桌面安全会话初始化失败")
    # fragment 不会进入 HTTP 请求/访问日志；登录页立即清除并 POST 交换。
    return f"http://127.0.0.1:{PORT}/login#desktop={bootstrap}"


def _accept_desktop_renderer(renderer):
    global _desktop_renderer
    normalized = normalize_desktop_smoke_renderer(renderer)
    _desktop_renderer = normalized
    if normalized != "edgechromium":
        print("[错误] 桌面渲染器不是 Microsoft Edge WebView2，已安全终止。")
        # pywebview Event.set() treats literal False as cancellation. This
        # callback runs before the native window is created and before its URL
        # is navigated, so rejecting here keeps the bootstrap capability out of
        # unsupported renderers.
        return False
    if _desktop_smoke_store is not None:
        try:
            _desktop_smoke_store.set_renderer(normalized)
        except ValueError:
            return False
    # Any value other than literal False allows pywebview to create the window.
    return None

# ════════════════════════════════════════════════════════════
# 主程序
# ════════════════════════════════════════════════════════════
if __name__ == '__main__':
    # 1. 启动后台新闻抓取：延迟 3 秒，让 UI 先出来再去抢网络/CPU
    print(f"[启动] 正在初始化情报系统 (端口 {PORT})…")
    def _delayed_refresh():
        time.sleep(3)
        refresh_news()
    threading.Thread(target=_delayed_refresh, daemon=True).start()

    # 2. 启动定时刷新调度器
    scheduler = BackgroundScheduler(daemon=True)
    add_background_jobs(scheduler)
    scheduler.start()

    # 3. 在后台线程启动 Flask
    threading.Thread(target=_run_flask, daemon=True).start()

    # 4. 导入 pywebview（延迟导入减少启动时间）
    try:
        import webview
    except ImportError:
        print("\n[错误] 未安装 pywebview，请运行：pip install pywebview\n")
        sys.exit(1)

    # 5. Flask 就绪后生成一次性引导 URL，再创建桌面窗口。
    try:
        desktop_login_url = _prepare_desktop_login_url()
    except RuntimeError as exc:
        print(f"[错误] {exc}")
        raise SystemExit(1)

    window = webview.create_window(
        title=f'防务数据追踪系统 {PRODUCT_VERSION.display_version} · Defense Command Hub',
        url=desktop_login_url,
        width=1440,
        height=900,
        min_size=(1024, 700),
        background_color='#060d1a',
    )

    window.events.initialized += _accept_desktop_renderer

    # 6. Explicit ephemeral WebView profile: auth/CSRF cookies and PKCE state do
    # not survive the desktop process or mix with another local browser app.
    webview.start(
        gui="edgechromium",
        debug=False,
        private_mode=True,
    )
