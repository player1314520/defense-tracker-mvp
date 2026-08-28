"""
防务数据追踪系统 V9 — 桌面应用启动器
使用 PyWebView 创建原生桌面窗口（无浏览器地址栏）
"""
import json
import sys, os, threading, time, socket
from pathlib import Path

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

from product_version import PRODUCT_VERSION

# ── 可写运行目录（程序目录始终只读）──────────────────────────
from state import RUNTIME_LAYOUT, ensure_runtime_layout, migrate_legacy_runtime

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
)
from apscheduler.schedulers.background import BackgroundScheduler

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


def _desktop_smoke_evidence_path():
    configured = os.environ.get("DEFENSE_TRACKER_SMOKE_EVIDENCE", "").strip()
    if not configured:
        return None
    runtime_root = Path(os.environ.get("DEFENSE_TRACKER_HOME", "")).resolve()
    evidence_path = Path(configured).resolve()
    if not runtime_root.is_dir() or evidence_path.parent != runtime_root:
        raise RuntimeError("desktop smoke evidence must be a direct child of the runtime directory")
    return evidence_path


def _start_desktop_smoke_probe(window):
    evidence_path = _desktop_smoke_evidence_path()
    if evidence_path is None:
        return

    script = """
    (async function () {
      const response = await fetch('/api/status', {
        credentials: 'same-origin', cache: 'no-store'
      });
      let payload = {};
      try { payload = await response.json(); } catch (_) {}
      return {
        schema: 1,
        http_status: response.status,
        pathname: window.location.pathname,
        workspace_ready: Boolean(document.querySelector('main.v9-workspace')),
        version: payload.version || '',
        display_version: payload.display_version || '',
        release_tag: payload.release_tag || '',
        build_commit: payload.build_commit || ''
      };
    })()
    """

    def _probe():
        deadline = time.time() + 45
        while time.time() < deadline:
            completed = threading.Event()
            result_box = {}

            def _receive(result):
                result_box["value"] = result
                completed.set()

            try:
                window.evaluate_js(script, callback=_receive)
                completed.wait(3)
                result = result_box.get("value")
                if (
                    isinstance(result, dict)
                    and result.get("http_status") == 200
                    and result.get("pathname") == "/"
                    and result.get("workspace_ready") is True
                ):
                    temporary = evidence_path.with_suffix(evidence_path.suffix + ".tmp")
                    temporary.write_text(
                        json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    os.replace(temporary, evidence_path)
                    return
            except Exception:
                pass
            time.sleep(0.5)

    threading.Thread(target=_probe, daemon=True).start()

# ── 加载页（Flask 就绪前显示）────────────────────────────────
LOADING_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  body {
    margin: 0; background: #0d0c0a;
    display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    height: 100vh; font-family: 'Songti SC','Microsoft YaHei',serif; color: #998f7e;
  }
  .logo { font-size: 64px; margin-bottom: 24px; }
  h1 { font-size: 26px; font-weight: 500; color: #eee7d9; margin: 0 0 8px; }
  .sub { font: 11px Consolas, monospace; letter-spacing: 3px; margin-bottom: 40px; color: #625b4f; }
  .spinner {
    width: 40px; height: 40px;
    border: 2px solid #302b24;
    border-top-color: #e34a31;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }
  .status { margin-top: 20px; font-size: 12px; color: #625b4f; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
  <div class="logo">🛡️</div>
  <h1>防务数据追踪系统</h1>
  <div class="sub">DEFENSE COMMAND HUB · __DISPLAY_VERSION__ · 闭环</div>
  <div class="spinner"></div>
  <div class="status">正在初始化情报系统，请稍候…</div>
</body>
</html>""".replace("__DISPLAY_VERSION__", PRODUCT_VERSION.display_version)

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

    # 5. 创建桌面窗口，先显示加载页
    window = webview.create_window(
        title=f'防务数据追踪系统 {PRODUCT_VERSION.display_version} · Defense Command Hub',
        html=LOADING_HTML,
        width=1440,
        height=900,
        min_size=(1024, 700),
        background_color='#060d1a',
    )

    # 6. Flask 就绪后跳转到应用
    def _on_shown():
        if _wait_for_flask():
            print(f"[启动] 服务就绪，加载应用…")
            bootstrap = get_desktop_bootstrap_token()
            if not bootstrap:
                window.load_html("""<body style="background:#060d1a;color:#ef4444;
                    font-family:sans-serif;display:flex;align-items:center;
                    justify-content:center;height:100vh;font-size:18px;">
                    ❌ 桌面安全会话初始化失败，请重启。</body>""")
                return
            # fragment 不会进入 HTTP 请求/访问日志；登录页立即清除并 POST 交换。
            window.load_url(f'http://127.0.0.1:{PORT}/login#desktop={bootstrap}')
            _start_desktop_smoke_probe(window)
        else:
            window.load_html("""<body style="background:#060d1a;color:#ef4444;
                font-family:sans-serif;display:flex;align-items:center;
                justify-content:center;height:100vh;font-size:18px;">
                ❌ 服务启动超时，请重试。</body>""")

    # Explicit ephemeral WebView profile: auth/CSRF cookies and PKCE state do
    # not survive the desktop process or mix with another local browser app.
    webview.start(_on_shown, debug=False, private_mode=True)
