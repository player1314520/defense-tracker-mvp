"""
追踪系统守护脚本 - 自动启动 app.py 和 ngrok 隧道
崩溃自动重启，优雅退出时清理子进程
"""

import ctypes
import hashlib
import hmac
import json
import logging
import os
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# 确保工作目录在项目根目录
PROJECT_ROOT = Path(__file__).resolve().parent.parent
os.chdir(PROJECT_ROOT)
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from product_version import PRODUCT_VERSION, current_build_commit  # noqa: E402

# ─── 配置 ──────────────────────────────────────────────
APP_CMD = [sys.executable, "app.py"]
APP_SUPERVISOR_SECRET_ENV = "DEFENSE_TRACKER_SUPERVISOR_SECRET"
APP_SUPERVISOR_CHALLENGE_HEADER = "X-DefenseTracker-Supervisor-Challenge"
NGROK_COMMAND = "ngrok"
NGROK_DOMAIN = os.environ.get("NGROK_DOMAIN", "").strip()
HEALTH_URL = "http://127.0.0.1:5000/health"
HEALTH_TIMEOUT = 30  # 等待 app.py 就绪的最大秒数
CHECK_INTERVAL = 5  # 子进程存活检查间隔（秒）
MAX_APP_RESTARTS = 3
MAX_NGROK_RESTARTS = 3
LOG_DIR = "logs"

EXIT_APP_UNAVAILABLE = 69
EXIT_NGROK_UNTRUSTED = 70
EXIT_APP_PORT_IN_USE = 71
EXIT_RESTART_LIMIT = 72
EXIT_SECURITY_CONFIG = 78

# ─── 日志目录 ──────────────────────────────────────────
os.makedirs(LOG_DIR, exist_ok=True)

# ─── 控制台日志 ─────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("auto_start")

# ─── 全局进程引用 ───────────────────────────────────────
app_proc = None
ngrok_proc = None
shutting_down = False
_ngrok_executable = None
_ngrok_identity = None
_app_supervisor_secret = None
class NgrokExecutableError(RuntimeError):
    """The ngrok executable could not be pinned to a safe local file."""


def _metadata_is_reparse(metadata):
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(metadata, "st_file_attributes", 0) & reparse_flag)


def _windows_path_is_remote(path):
    if sys.platform != "win32":
        return False
    drive_type_remote = 4
    return ctypes.windll.kernel32.GetDriveTypeW(str(path.anchor)) == drive_type_remote


def _file_identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as executable:
        for chunk in iter(lambda: executable.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.digest()


def _process_is_elevated():
    if sys.platform == "win32":
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0 or os.geteuid() != os.getuid()


def _assert_unprivileged_execution():
    if _process_is_elevated():
        raise NgrokExecutableError(
            "the local ngrok supervisor must not run with elevated privileges"
        )


def _validate_ngrok_executable(candidate):
    path = Path(candidate)
    if not path.is_absolute():
        raise NgrokExecutableError("ngrok path must be absolute")
    if sys.platform == "win32":
        if str(path).startswith("\\\\") or _windows_path_is_remote(path):
            raise NgrokExecutableError("ngrok path must be on a local filesystem")
        if path.suffix.casefold() != ".exe":
            raise NgrokExecutableError("ngrok must be a native .exe on Windows")

    try:
        current = path
        while True:
            component_metadata = os.lstat(current)
            if stat.S_ISLNK(component_metadata.st_mode) or _metadata_is_reparse(
                component_metadata
            ):
                raise NgrokExecutableError(
                    "ngrok path must not contain a symlink or reparse point"
                )
            if current.parent == current:
                break
            current = current.parent

        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode):
            raise NgrokExecutableError("ngrok path must be a regular file")
        if sys.platform != "win32":
            if before.st_uid not in {0, os.geteuid()} or before.st_mode & 0o022:
                raise NgrokExecutableError(
                    "ngrok file ownership or permissions are unsafe"
                )
            parent_metadata = os.lstat(path.parent)
            if parent_metadata.st_uid not in {0, os.geteuid()} or (
                parent_metadata.st_mode & 0o022
            ):
                raise NgrokExecutableError(
                    "ngrok parent ownership or permissions are unsafe"
                )
        if not os.access(path, os.X_OK):
            raise NgrokExecutableError("ngrok file is not executable")
        resolved = path.resolve(strict=True)
        if os.path.normcase(str(path)) != os.path.normcase(str(resolved)):
            raise NgrokExecutableError(
                "ngrok path must not contain a symlink or reparse point"
            )
        content_digest = _file_sha256(path)
        after = os.lstat(path)
    except NgrokExecutableError:
        raise
    except OSError as exc:
        raise NgrokExecutableError("ngrok path is missing or unreadable") from exc

    if _file_identity(before) != _file_identity(after):
        raise NgrokExecutableError("ngrok changed during validation")
    return resolved, (*_file_identity(after), content_digest)


def _pin_ngrok_executable():
    global _ngrok_executable, _ngrok_identity
    _assert_unprivileged_execution()
    if _ngrok_executable is not None:
        return _verified_ngrok_executable()
    located = shutil.which(NGROK_COMMAND)
    if not located:
        raise NgrokExecutableError(
            "ngrok executable was not found on the configured PATH"
        )
    executable, identity = _validate_ngrok_executable(located)
    _ngrok_executable = executable
    _ngrok_identity = identity
    return executable


def _verified_ngrok_executable():
    if _ngrok_executable is None or _ngrok_identity is None:
        return _pin_ngrok_executable()
    executable, identity = _validate_ngrok_executable(_ngrok_executable)
    if executable != _ngrok_executable or identity != _ngrok_identity:
        raise NgrokExecutableError("ngrok changed after resolution")
    return executable


def _validated_ngrok_domain():
    domain = NGROK_DOMAIN
    invalid_domain = "ngrok domain must be an exact lowercase DNS name"
    if not isinstance(domain, str):
        raise NgrokExecutableError(invalid_domain)
    if not domain:
        return ""
    if len(domain) > 253:
        raise NgrokExecutableError(invalid_domain)

    labels = domain.split(".")
    def is_ascii_alphanumeric(character):
        return "a" <= character <= "z" or "0" <= character <= "9"

    def is_valid_label(label):
        return (
            1 <= len(label) <= 63
            and is_ascii_alphanumeric(label[0])
            and is_ascii_alphanumeric(label[-1])
            and all(
                is_ascii_alphanumeric(character) or character == "-"
                for character in label
            )
        )

    if len(labels) < 2 or not all(is_valid_label(label) for label in labels[:-1]):
        raise NgrokExecutableError(invalid_domain)

    top_level_domain = labels[-1]
    if not 2 <= len(top_level_domain) <= 63 or any(
        not "a" <= character <= "z" for character in top_level_domain
    ):
        raise NgrokExecutableError(invalid_domain)
    return domain


def _ngrok_command():
    command = [str(_verified_ngrok_executable()), "http", "5000"]
    domain = _validated_ngrok_domain()
    if domain:
        command.extend(["--domain", domain])
    return command


def _ngrok_still_trusted():
    try:
        _verified_ngrok_executable()
    except NgrokExecutableError as exc:
        log.error("ngrok changed after startup; stopping the supervisor: %s", exc)
        return False
    return True


def open_log(name):
    """以追加模式打开日志文件"""
    path = os.path.join(LOG_DIR, name)
    return open(path, "a", encoding="utf-8", buffering=1)


def start_app():
    """启动 app.py 子进程"""
    global app_proc, _app_supervisor_secret
    log.info("启动 app.py ...")
    log_file = open_log("app.log")
    _app_supervisor_secret = secrets.token_bytes(32)
    child_env = os.environ.copy()
    child_env[APP_SUPERVISOR_SECRET_ENV] = _app_supervisor_secret.hex()
    try:
        app_proc = subprocess.Popen(
            APP_CMD,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            env=child_env,
        )
    except Exception:
        _app_supervisor_secret = None
        log_file.close()
        raise
    log.info(f"app.py 已启动 (PID={app_proc.pid})")
    return app_proc


def _app_health_is_ready():
    if _app_supervisor_secret is None:
        return False
    challenge = secrets.token_hex(16)
    try:
        req = urllib.request.Request(
            HEALTH_URL,
            method="GET",
            headers={APP_SUPERVISOR_CHALLENGE_HEADER: challenge},
        )
        with urllib.request.urlopen(req, timeout=3) as response:
            if response.status != 200:
                return False
            raw = response.read(4097)
        if len(raw) > 4096:
            return False
        payload = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeError, urllib.error.URLError, OSError):
        return False
    proof = payload.pop("supervisor_proof", "")
    identity_matches = payload == {
        "status": "ok",
        "service": "defense-tracker-workspace",
        "version": PRODUCT_VERSION.semantic_version,
        "build_commit": current_build_commit(),
        "wire_compatibility": "mvp-wire-v1",
    }
    expected_proof = hmac.new(
        _app_supervisor_secret,
        challenge.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return (
        identity_matches
        and isinstance(proof, str)
        and hmac.compare_digest(proof, expected_proof)
    )


def _local_app_port_is_occupied():
    try:
        with socket.create_connection(("127.0.0.1", 5000), timeout=0.5):
            return True
    except OSError:
        return False


def _preexisting_local_app():
    # A public /health identity cannot establish process ownership. Any listener
    # that predates this supervisor is therefore external and must fail closed.
    return _local_app_port_is_occupied() or _app_health_is_ready()


def wait_for_app_ready():
    """轮询健康接口，等待 app.py 就绪"""
    log.info(f"等待 app.py 就绪 (最多 {HEALTH_TIMEOUT}s) ...")
    deadline = time.time() + HEALTH_TIMEOUT
    while time.time() < deadline:
        if app_proc is not None and app_proc.poll() is not None:
            log.error("app.py 在健康检查通过前已退出")
            return False
        if (
            _app_health_is_ready()
            and app_proc is not None
            and app_proc.poll() is None
        ):
            log.info("app.py 已就绪!")
            return True
        time.sleep(1)
    log.error(f"app.py 在 {HEALTH_TIMEOUT}s 内未就绪，拒绝启动 ngrok")
    return False


def start_ngrok():
    """启动 ngrok 隧道"""
    global ngrok_proc
    log.info("启动 ngrok 隧道 ...")
    try:
        command = _ngrok_command()
    except NgrokExecutableError as exc:
        log.error("ngrok security check failed; refusing to start: %s", exc)
        raise
    log_file = open_log("ngrok.log")
    try:
        verified_executable = str(_verified_ngrok_executable())
        command[0] = verified_executable
    except NgrokExecutableError as exc:
        log_file.close()
        log.error("ngrok security check failed; refusing to start: %s", exc)
        raise
    ngrok_proc = subprocess.Popen(
        command,
        executable=verified_executable,
        shell=False,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
    )
    log.info(f"ngrok 已启动 (PID={ngrok_proc.pid})")
    if "--domain" in command:
        log.info(f"飞书 Webhook: https://{command[-1]}/api/feishu/webhook")
    else:
        log.info("未配置固定域名；请从 http://127.0.0.1:4040 获取 ngrok 公网地址")
    return ngrok_proc


def kill_proc(proc, name):
    """安全终止一个子进程"""
    if proc is None:
        return True
    if proc.poll() is not None:
        return True
    log.info(f"正在终止 {name} (PID={proc.pid}) ...")
    try:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            log.warning(f"{name} 未响应 terminate，强制 kill ...")
            proc.kill()
            proc.wait(timeout=3)
        log.info(f"{name} 已终止")
        return proc.poll() is not None
    except Exception as exc:
        log.error("终止 %s 时出错 (%s)", name, type(exc).__name__)
        return False


def _wait_for_app_exit(timeout):
    if app_proc is None:
        time.sleep(timeout)
        return False
    try:
        app_proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return False
    return True


def cleanup(*_args):
    """优雅退出：终止所有子进程"""
    global shutting_down
    if shutting_down:
        return
    shutting_down = True
    log.info("收到退出信号，正在清理 ...")
    kill_proc(ngrok_proc, "ngrok")
    kill_proc(app_proc, "app.py")
    log.info("所有子进程已清理，退出。")


def main():
    global app_proc, ngrok_proc
    app_restarts = 0
    ngrok_restarts = 0

    # 注册信号处理
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    if sys.platform == "win32":
        signal.signal(signal.SIGBREAK, cleanup)

    log.info("=" * 50)
    log.info("追踪系统守护脚本启动")
    log.info("工作目录与 Python 运行时已就绪")
    log.info("=" * 50)

    try:
        try:
            _pin_ngrok_executable()
        except NgrokExecutableError as exc:
            log.error("ngrok security check failed; refusing to start: %s", exc)
            return EXIT_SECURITY_CONFIG

        if _preexisting_local_app():
            log.error("本地端口 5000 已有外部服务；拒绝复用并拒绝启动 ngrok")
            return EXIT_APP_PORT_IN_USE
        start_app()
        if not wait_for_app_ready():
            return EXIT_APP_UNAVAILABLE
        start_ngrok()

        log.info(f"守护循环开始，每 {CHECK_INTERVAL}s 检查子进程状态 ...")

        # 守护循环
        while not shutting_down:
            _wait_for_app_exit(CHECK_INTERVAL)
            if shutting_down:
                break

            # 检查 app.py
            if app_proc and app_proc.poll() is not None:
                # The tunnel must not outlive the child that was proven healthy.
                if not kill_proc(ngrok_proc, "ngrok"):
                    log.error("app.py 退出后无法确认 ngrok 已停止，守护程序停止")
                    return EXIT_NGROK_UNTRUSTED
                ngrok_proc = None
                if app_restarts >= MAX_APP_RESTARTS:
                    log.error("app.py 重启次数已达上限，守护程序停止")
                    return EXIT_RESTART_LIMIT
                if _preexisting_local_app():
                    log.error("app.py 退出后端口 5000 被外部服务占用；拒绝继续 ngrok")
                    return EXIT_APP_PORT_IN_USE
                log.warning(f"app.py 崩溃 (退出码={app_proc.returncode})，正在重启 ...")
                app_restarts += 1
                start_app()
                if not wait_for_app_ready():
                    return EXIT_APP_UNAVAILABLE
                start_ngrok()

            if not _ngrok_still_trusted():
                return EXIT_NGROK_UNTRUSTED

            # 检查 ngrok
            if ngrok_proc and ngrok_proc.poll() is not None:
                if ngrok_restarts >= MAX_NGROK_RESTARTS:
                    log.error("ngrok 重启次数已达上限，守护程序停止")
                    return EXIT_RESTART_LIMIT
                log.warning(
                    f"ngrok 崩溃 (退出码={ngrok_proc.returncode})，正在重启 ..."
                )
                ngrok_restarts += 1
                start_ngrok()

    except NgrokExecutableError as exc:
        log.error("ngrok 路径复验失败，守护程序停止 (%s)", type(exc).__name__)
        return EXIT_SECURITY_CONFIG
    except KeyboardInterrupt:
        return 130
    finally:
        cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
