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
| `FEISHU_VERIFY_TOKEN` | 飞书 webhook 签名校验材料 |
| `V9_ALLOWED_ORIGINS` | 逗号分隔的明确门户 Origin；不接受 `*` |
| `V9_CLOUD_DB_PATH` | staging 密文事件数据库路径 |
| `PORT` | HTTP 监听端口 |

不得配置 `AI_API_KEY`、`AI_BASE_URL`、`AI_MODEL`、飞书应用 Secret、解密密钥
或恢复码。日志不得打印请求正文、Authorization、聊天 ID 或密文载荷。

## 部署前门禁

1. 先创建 Supabase staging，执行 `supabase/migrations/202607250001_v9_zero_knowledge.sql`。
2. 使用两个真实 Auth 用户验证跨组织读取/写入均被 RLS 拒绝。
3. 把 staging 协调令牌替换为 Supabase JWT 校验，客户端仅访问自己 membership
   覆盖的组织；未完成前不得生产发布。
4. 设置明确的 `V9_ALLOWED_ORIGINS`，运行密文、日志和 CORS 回归。
5. 人工确认后才可执行 `railway up`、Render/Fly 发布或飞书 webhook 更新。

## 诚实边界

1. 当前本地协调令牌是 staging 适配器，不等同于生产级 Supabase 用户身份。
2. 未部署 Supabase staging，真实 PKCE 回调、JWT 和 RLS 尚未端到端验证。
3. 云端 SQLite 仅用于本地/单实例验收，多实例生产同步必须使用 Supabase。
4. 飞书只接受任务元数据，不能提交正文、附件或触发云端全文 AI。
