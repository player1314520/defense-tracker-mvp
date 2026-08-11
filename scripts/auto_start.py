"""
追踪系统守护脚本 - 自动启动 app.py 和 ngrok 隧道
崩溃自动重启，优雅退出时清理子进程
"""

import sys
import os

# 确保工作目录在项目根目录
os.chdir(os.path.dirname(os.path.abspath(__file__)) + '/..')

import subprocess
import time
import signal
import logging
import urllib.request
import urllib.error
from datetime import datetime

# ─── 配置 ──────────────────────────────────────────────
APP_CMD = [sys.executable, "app.py"]
NGROK_EXE = os.environ.get("NGROK_EXE", "ngrok").strip() or "ngrok"
NGROK_DOMAIN = os.environ.get("NGROK_DOMAIN", "").strip()
NGROK_CMD = [NGROK_EXE, "http", "5000"]
if NGROK_DOMAIN:
    NGROK_CMD.extend(["--domain", NGROK_DOMAIN])
HEALTH_URL = "http://127.0.0.1:5000/api/status"
HEALTH_TIMEOUT = 30        # 等待 app.py 就绪的最大秒数
CHECK_INTERVAL = 5         # 子进程存活检查间隔（秒）
LOG_DIR = "logs"

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


def open_log(name):
    """以追加模式打开日志文件"""
    path = os.path.join(LOG_DIR, name)
    return open(path, "a", encoding="utf-8", buffering=1)


def start_app():
    """启动 app.py 子进程"""
    global app_proc
    log.info("启动 app.py ...")
    log_file = open_log("app.log")
    app_proc = subprocess.Popen(
        APP_CMD,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
    )
    log.info(f"app.py 已启动 (PID={app_proc.pid})")
    return app_proc


def wait_for_app_ready():
    """轮询健康接口，等待 app.py 就绪"""
    log.info(f"等待 app.py 就绪 (最多 {HEALTH_TIMEOUT}s) ...")
    deadline = time.time() + HEALTH_TIMEOUT
    while time.time() < deadline:
        try:
            req = urllib.request.Request(HEALTH_URL, method="GET")
            resp = urllib.request.urlopen(req, timeout=3)
            if resp.status == 200:
                log.info("app.py 已就绪!")
                return True
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(1)
    log.warning(f"app.py 在 {HEALTH_TIMEOUT}s 内未就绪，仍将继续启动 ngrok")
    return False


def start_ngrok():
    """启动 ngrok 隧道"""
    global ngrok_proc
    log.info("启动 ngrok 隧道 ...")
    log_file = open_log("ngrok.log")
    ngrok_proc = subprocess.Popen(
        NGROK_CMD,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
    )
    log.info(f"ngrok 已启动 (PID={ngrok_proc.pid})")
    if NGROK_DOMAIN:
        log.info(f"飞书 Webhook: https://{NGROK_DOMAIN}/api/feishu/webhook")
    else:
        log.info("未配置固定域名；请从 http://127.0.0.1:4040 获取 ngrok 公网地址")
    return ngrok_proc


def kill_proc(proc, name):
    """安全终止一个子进程"""
    if proc is None:
        return
    if proc.poll() is not None:
        return
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
    except Exception as e:
        log.error(f"终止 {name} 时出错: {e}")


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

    # 注册信号处理
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    if sys.platform == "win32":
        signal.signal(signal.SIGBREAK, cleanup)

    log.info("=" * 50)
    log.info("追踪系统守护脚本启动")
    log.info(f"工作目录: {os.getcwd()}")
    log.info(f"Python: {sys.executable}")
    log.info("=" * 50)

    # 首次启动
    start_app()
    wait_for_app_ready()
    start_ngrok()

    log.info(f"守护循环开始，每 {CHECK_INTERVAL}s 检查子进程状态 ...")

    # 守护循环
    try:
        while not shutting_down:
            time.sleep(CHECK_INTERVAL)

            # 检查 app.py
            if app_proc and app_proc.poll() is not None:
                log.warning(f"app.py 崩溃 (退出码={app_proc.returncode})，正在重启 ...")
                start_app()
                wait_for_app_ready()

            # 检查 ngrok
            if ngrok_proc and ngrok_proc.poll() is not None:
                log.warning(f"ngrok 崩溃 (退出码={ngrok_proc.returncode})，正在重启 ...")
                start_ngrok()

    except KeyboardInterrupt:
        pass
    finally:
        cleanup()


if __name__ == "__main__":
    main()
