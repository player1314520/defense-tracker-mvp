# 防务追踪系统 — 旧版单机工作台部署指南

本文件只描述受控网络中的旧 Flask 工作台，不是 V9 社区 Portal 的生产部署说明。
公网 Portal 请使用 `docs/MVP_DEPLOY.md` 的独立 Supabase/Caddy 流程；不得把本地 AI、
写作素材、飞书配置或真实运行数据打包上传。

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

先确认宿主路由不与默认 `172.30.240.0/29` 冲突。若需覆盖，必须同时设置
`DEFENSE_TRACKER_DOCKER_SUBNET` 与位于该网段内的
`DEFENSE_TRACKER_NGINX_PROXY_IP`；后者作为精确单地址传给 Flask，不能改成信任整个
Docker bridge 网段。Nginx 会覆盖客户端自带的 `X-Forwarded-For`，tracker 仍只
`expose` 5000 而不向宿主发布。
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
  FEISHU_ENCRYPT_KEY:  "xxxxxxxx"
  FEISHU_TENANT_KEY:   "tenant-key-from-event"
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

将官方 `ngrok.exe` 放入本机 `PATH` 的绝对目录中；启动脚本只读取保留域名，
并统一调用带本地文件、重解析点和启动前身份复验的守护程序：

```powershell
$env:NGROK_DOMAIN = 'your-ngrok-domain.example'
.\scripts\飞书机器人启动.bat
```

适合**本地开发 + 飞书机器人测试**，不适合长期公网运行。

该守护程序的边界是：它不验证 ngrok 的 Authenticode Publisher 或官方发布哈希；
首次选择仍遵循当前用户的 `PATH` 顺序；文件身份复验不能完全消除同一用户在最终
检查与进程创建之间的极短替换窗口。因此它拒绝管理员/root 身份运行，安装来源与
首次文件真实性仍须由本地操作员独立核验，生产入口应使用受控反向代理而不是 ngrok。

### V9 本地开发数据库连续性

本地开发会继续使用已经存在的旧临时数据库；全新环境才创建权限更严格的新目录。
如果旧、新两个主库同时存在，启动会无条件安全阻断，不能因为两个主文件哈希相同就
自动选择——SQLite 的已提交数据仍可能只位于 `-wal`。处理冲突必须先停止全部旧版与
新版进程，再同时检查主库及 `-wal`、`-shm`、`-journal`、`-mj*`，用 SQLite 的正常
checkpoint/backup 完成一致性副本并通过 `PRAGMA integrity_check`。确认 canonical 后，
将另一套主库及其 sidecar 移到唯一且不覆盖的归档位置并记录 SHA-256；不要在应用启动
路径中自动移动或删除。生产固定 `/data` 路径不使用这段开发兼容逻辑。

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
| 飞书Webhook身份验证 | ✅ | 必须同时配置 Verify Token、Encrypt Key、Tenant Key；缺失时固定返回 503 |
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
3. 通过安全渠道把「验证令牌」「Encrypt Key」和预期 Tenant Key 分别注入
   `FEISHU_VERIFY_TOKEN`、`FEISHU_ENCRYPT_KEY`、`FEISHU_TENANT_KEY`；不要写入仓库。
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
