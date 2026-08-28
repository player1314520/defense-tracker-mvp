# V9 密文协调器部署说明

> 当前只完成本地 staging。Railway、Render、Fly、Supabase、飞书配置均不得在
> 未取得人工确认时执行。

## 云端职责

云端进程固定为 `v9_cloud:app`，只提供：

- 加密事件的幂等推送与按游标拉取；
- 任务 ID、状态、认领和审批动作元数据；
- 飞书 `claim TASK_ID`、`approve TASK_ID`、`status TASK_ID` 三类严格命令；
- 静态移动门户。记录正文由浏览器 Web Crypto 在本地解密。

旧 `feishu_cloud.py` 仍保留为本地兼容代码，但已从 Procfile、Railway、
Render、Fly、Docker 和 `.railwayignore` 的发布面移除。云端不安装 AI、
抓取、PDF、DOCX 或报告生成依赖。

## 运行变量

| 名称 | 含义 |
|---|---|
| `V9_COORDINATOR_TOKEN` | 仅供本地 staging 的高熵协调令牌；生产应切换为 Supabase Auth JWT/RLS |
| `FEISHU_APP_ID` | 飞书应用 ID；用于 schema 2.0 事件身份绑定 |
| `FEISHU_VERIFY_TOKEN` | 飞书事件负载中的 Verification Token；不作为签名密钥 |
| `FEISHU_ENCRYPT_KEY` | 飞书事件 Encrypt Key；用于新鲜度签名校验和加密 envelope 解密 |
| `FEISHU_TENANT_KEY` | 唯一允许的飞书租户 Key |
| `FEISHU_DEDUPE_DB` | webhook 租约/完成状态数据库的绝对路径，必须位于持久卷 |
| `V9_ALLOWED_ORIGINS` | 逗号分隔的明确门户 Origin；不接受 `*` |
| `V9_CLOUD_DB_PATH` | staging 密文事件数据库路径 |
| `DEFENSE_TRACKER_BUILD_COMMIT` | 正在运行的受保护 `main` 完整 40 位小写提交 SHA；生产必填 |
| `PORT` | HTTP 监听端口 |

不得配置 `AI_API_KEY`、`AI_BASE_URL`、`AI_MODEL`、飞书应用 Secret、业务数据
解密密钥或恢复码。`FEISHU_ENCRYPT_KEY` 仅用于飞书事件传输保护，不是业务数据
密钥。日志不得打印请求正文、Authorization、聊天 ID、事件 ID 或密文载荷。

飞书 webhook 永久禁止 token-only 模式。四项飞书身份/签名配置缺少任一项时
端点返回 503；签名必须使用 Encrypt Key、包含完整时间戳与 nonce，且通过新鲜度
校验。`FEISHU_DEDUPE_DB` 只保存事件 ID 的 SHA-256 与有限状态，不保存命令正文。

## 部署前门禁

1. 先创建 Supabase staging，执行 `supabase/migrations/202607250001_v9_zero_knowledge.sql`。
2. 使用两个真实 Auth 用户验证跨组织读取/写入均被 RLS 拒绝。
3. 把 staging 协调令牌替换为 Supabase JWT 校验，客户端仅访问自己 membership
   覆盖的组织；未完成前不得生产发布。
4. 设置明确的 `V9_ALLOWED_ORIGINS`，运行密文、日志和 CORS 回归。
5. 人工确认后才可执行 `railway up`、Render/Fly 发布或飞书 webhook 更新。
6. Render/Railway 启动命令分别从平台只读提交变量传入构建 SHA；Fly/Docker
   必须以 `--build-arg DEFENSE_TRACKER_BUILD_COMMIT=<R>` 构建。缺失或不是完整
   小写 SHA 时镜像构建/应用启动必须失败。
7. staging Compose 与 Fly 必须把 `/data` 挂到持久卷，同时把
   `FEISHU_DEDUPE_DB` 设为 `/data/feishu-event-dedupe.sqlite3`。Render Free 不支持
   持久磁盘，因此必须保持四项飞书 secret 未配置、让 webhook 维持 503；只有取得
   计费授权、升级付费实例并在 `/data` 挂载持久磁盘后，才可配置这些 secret。平台
   限制以 [Render Persistent Disks](https://render.com/docs/disks) 为准。

## 诚实边界

1. 当前本地协调令牌是 staging 适配器，不等同于生产级 Supabase 用户身份。
2. 未部署 Supabase staging，真实 PKCE 回调、JWT 和 RLS 尚未端到端验证。
3. 云端 SQLite 仅用于本地/单实例验收，多实例生产同步必须使用 Supabase。
4. 飞书只接受任务元数据，不能提交正文、附件或触发云端全文 AI。
5. webhook 去重依赖单个共享持久 SQLite 文件；未挂卷、只读卷或多实例独立磁盘
   都不具备跨重启/跨实例可靠性，必须阻断上线。
