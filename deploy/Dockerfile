FROM python:3.11-slim@sha256:1042b61448fef4ba92d16a8c7eb4996d027568ce64792a7877fd88511e0af7c6

WORKDIR /app

ENV PIP_DISABLE_PIP_VERSION_CHECK=1

# 固定构建工具，并禁止 sdist 在隔离环境中临时拉取未锁定依赖。
COPY deploy/requirements.server-build.txt ./requirements.server-build.txt
COPY deploy/requirements.server.txt ./requirements.server.txt
RUN python -m pip install --no-cache-dir --only-binary=:all: --require-hashes \
        -r requirements.server-build.txt \
    && python -m pip install --no-cache-dir --only-binary=:all: \
        --no-binary=sgmllib3k --no-build-isolation --require-hashes \
        -r requirements.server.txt

# 复制项目文件（app.py 顶层 import 了下列本地模块，必须一并拷入，否则 gunicorn 加载即 ModuleNotFoundError）
COPY app.py state.py quality.py tracking.py auth_devices.py user_state.py feishu_bot.py feishu_common.py consulting_agent.py report_agent.py search_adapters.py pinned_http.py protected_secrets.py wechat_runtime.py product_version.py document_safety.py isolated_document_parser.py upload_safety.py feishu_webhook_security.py version.json ./
COPY v9/ v9/
COPY templates/ templates/
COPY static/ static/

# 创建非 root 用户运行应用（安全加固）
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# 运行时环境变量（可在 docker-compose 或 -e 中覆盖）
ENV PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    RUN_SCHEDULER=1 \
    DEFENSE_TRACKER_BIND_HOST=0.0.0.0 \
    PORT=5000

EXPOSE 5000

# 单 worker（保持内存缓存/调度器/限流一致 + 避免重复刷新）+ 多线程并发 + 优雅关闭
# timeout 300 > AI 调用 180s，避免慢 AI 触发 worker 被强杀返 502
CMD ["sh", "-c", \
     "exec gunicorn --workers 1 --threads 8 --bind \"${DEFENSE_TRACKER_BIND_HOST}:5000\" --timeout 300 --graceful-timeout 30 --access-logfile - --error-logfile - app:app"]
