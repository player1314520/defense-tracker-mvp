# 防务追踪系统 — 公网部署指南

## 方案一：Docker + Nginx（推荐）

### 1. 准备服务器
- 推荐：Ubuntu 22.04，2核2G内存，20GB硬盘
- 国内云：阿里云/腾讯云轻量应用服务器（约 24元/月）
- 开放端口：80、443

### 2. 安装 Docker
```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

### 3. 上传项目文件
将整个 `追踪系统` 文件夹上传到服务器，例如 `/opt/defense-tracker/`

```bash
scp -r 追踪系统/ root@<服务器IP>:/opt/defense-tracker/
```

### 4. 申请 SSL 证书（Let's Encrypt 免费）
```bash
# 先将域名 DNS 解析到服务器 IP
sudo apt install certbot
sudo certbot certonly --standalone -d your-domain.com

# 证书位置：
# /etc/letsencrypt/live/your-domain.com/fullchain.pem
# /etc/letsencrypt/live/your-domain.com/privkey.pem

# 复制到项目 ssl/ 目录
mkdir -p /opt/defense-tracker/deploy/ssl
cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /opt/defense-tracker/deploy/ssl/
cp /etc/letsencrypt/live/your-domain.com/privkey.pem /opt/defense-tracker/deploy/ssl/
```

### 5. 配置环境变量
编辑 `deploy/docker-compose.yml`，填写必要信息：
```yaml
environment:
  ACCESS_TOKEN: "你的自定义访问令牌（至少16位字符）"
  AI_API_KEY:   "你的DeepSeek/OpenAI API Key"
  AI_BASE_URL:  "https://api.deepseek.com"
  AI_MODEL:     "deepseek-chat"
  # 如果使用飞书机器人：
  FEISHU_APP_ID:       "cli_xxxxxxxx"
  FEISHU_APP_SECRET:   "xxxxxxxx"
  FEISHU_VERIFY_TOKEN: "xxxxxxxx"
```

### 6. 修改 nginx.conf
将文件中所有 `your-domain.com` 替换为实际域名：
```bash
sed -i 's/your-domain.com/你的域名.com/g' /opt/defense-tracker/deploy/nginx.conf
```

### 7. 启动服务
```bash
cd /opt/defense-tracker/deploy
docker compose up -d

# 查看日志
docker compose logs -f tracker
```

### 8. 访问系统
浏览器打开 `https://your-domain.com`，输入 ACCESS_TOKEN 登录。

---

## 方案二：ngrok（快速测试，无需域名）

`scripts/飞书机器人启动.bat` 从环境变量读取 ngrok 可执行文件和保留域名：

```powershell
$env:NGROK_EXE = 'C:\path\to\ngrok.exe'
$env:NGROK_DOMAIN = 'your-ngrok-domain.example'
.\scripts\飞书机器人启动.bat
```

适合**本地开发 + 飞书机器人测试**，不适合长期公网运行。

---

## 安全检查清单

| 项目 | 状态 | 说明 |
|------|------|------|
| 访问令牌认证 | ✅ | 所有页面和API均需登录 |
| 登录速率限制 | ✅ | 5次/分钟，防暴力破解 |
| AI接口速率限制 | ✅ | 10次/分钟/IP |
| SSRF防护 | ✅ | 禁止访问私有/内网地址 |
| 安全响应头 | ✅ | CSP / X-Frame-Options / nosniff |
| 文件上传限制 | ✅ | 最大16MB |
| 飞书Webhook签名验证 | ✅ | 配置 FEISHU_VERIFY_TOKEN 后生效 |
| 飞书消息去重 | ✅ | 防重试导致重复生成 |
| HTTPS Cookie | ✅ | 公网HTTPS下自动设置 secure 标志 |
| Nginx限速 | ✅ | 登录页5r/m，API 30r/m |

---

## 飞书机器人配置（公网部署后）

1. 将飞书开放平台的事件订阅URL改为：
   ```
   https://your-domain.com/api/feishu/webhook
   ```
2. 在系统「💬 飞书机器人」标签页填入 App ID 和 App Secret
3. 复制「验证令牌」填入 docker-compose.yml 的 `FEISHU_VERIFY_TOKEN`
4. 重启容器：`docker compose restart tracker`

---

## 证书自动续期

```bash
# 添加 cron 任务，每天检查续期
echo "0 3 * * * certbot renew --quiet && \
      cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /opt/defense-tracker/deploy/ssl/ && \
      cp /etc/letsencrypt/live/your-domain.com/privkey.pem /opt/defense-tracker/deploy/ssl/ && \
      docker compose -f /opt/defense-tracker/deploy/docker-compose.yml restart nginx" | crontab -
```
