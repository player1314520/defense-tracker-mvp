FROM python:3.11-slim

WORKDIR /app

# 安装系统依赖（BeautifulSoup lxml 解析器）
RUN apt-get update && apt-get install -y --no-install-recommends \
        libxml2 libxslt1.1 \
    && rm -rf /var/lib/apt/lists/*

# 仅安装服务器端依赖（去掉 pywebview / pyinstaller）
COPY requirements.server.txt .
RUN pip install --no-cache-dir -r requirements.server.txt

# 复制项目文件（app.py 顶层 import 了下列本地模块，必须一并拷入，否则 gunicorn 加载即 ModuleNotFoundError）
COPY app.py state.py quality.py tracking.py feishu_bot.py feishu_common.py consulting_agent.py report_agent.py search_adapters.py ./
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
