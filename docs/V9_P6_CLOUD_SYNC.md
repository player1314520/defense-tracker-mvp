# V9-P6 云网页、飞书与多设备同步

完成日期：2026-07-25（本地代码与 staging 验收）

## 已实现

- `v9/cloud.py`
  - 依照 Supabase 官方 OAuth PKCE 文档生成 43–128 字符 verifier、S256
    challenge 和随机 state；verifier 只返回客户端，不进入授权 URL。
  - 密文事件采用递归明文键检查和严格字段 allowlist。
  - 上传确认与入站已应用游标分离，拉取失败不会跳过远端事件。
- 一次性设备配对
  - 配对码只保存 SHA-256，60–600 秒过期，SQLite `BEGIN IMMEDIATE` 原子消费。
  - 远端只上传 X25519 公钥，私钥不离开新设备；配对结果只有设备 ID、
    key version 和组织密钥信封。
- `v9_cloud.py`
  - 只存密文事件与任务元数据；幂等 event ID、单调游标、显式 CORS。
  - 飞书只接受 `claim/approve/status + TASK_ID`，聊天 ID 仅保存 SHA-256；
    任意正文命令拒绝且不回显、不落库。
  - CSP、no-store、nosniff、拒绝 iframe；不记录请求正文。
- 移动门户 `web/v9-portal/`
  - 只提供总览、告警、审批和任务状态。
  - AES-256-GCM 数据密钥解封和正文解密全部由浏览器 Web Crypto 完成，
    与 Python 桌面信封互操作。
  - 当前会话令牌请求后立即清空，组织密钥仅保留在当前页面内存；
    不使用 localStorage/sessionStorage，关闭页面清空。
- 非破坏旧数据迁移
  - 对明确允许的 user state、报告 Agent、抓取 Agent、质量训练业务表，
    先建立经 `PRAGMA integrity_check` 验证的 `.pre-v9.bak`，再逐行加密导入
    默认个人组织。
  - 原数据库只读、不覆盖；记录引用保证重复启动幂等；一个损坏数据库不会
    阻断其他数据库或 V9 启动。
- 云发布面
  - Procfile、Railway、Render、Fly、Docker 均改为 `v9_cloud:app`。
  - 云依赖缩减为固定版本 Flask + gunicorn；旧全文飞书/AI/抓取/文档模块
    不进入云镜像 allowlist。

Supabase PKCE 参数依据：
<https://github.com/supabase/supabase/blob/master/apps/docs/content/guides/auth/oauth-server/oauth-flows.mdx>

## 本地验收

- Python 全量：234 项通过。
- Node：15 项通过，其中 2 项验证 Web Crypto 信封互操作与 PKCE。
- 浏览器：
  - 1440×900 和 390×844 均无横向溢出；
  - 390 宽度真实拉取一条密文告警并在浏览器本地解密；
  - 密钥/令牌输入框清空，Web Storage 为空；
  - console 0 error、0 warning，密文 API HTTP 200。
- 截图：`docs/release-evidence/P6/`。
- 本机迁移：4 个数据库、6091 条业务记录；导入数与源表计数一致，
  备份完整性与逐表行内容一致，成功标记已设置。
- 标准桌面门禁通过；正式 EXE 12,344,640 字节，SHA-256
  `422C900D4C50CC55A521304E324F5C0BE76B2ADACD1B7B5A008365B9CCB656D5`，
  发布清单记录 2832 个文件和提交 `ca996f89c77799e8c14af4968c9ea7ccd9c6d634`。
- 未执行任何 Supabase、Railway、Render、Fly 或飞书远程写入。

## 诚实边界

1. 真实 Supabase staging 尚未创建，因此 PKCE 回调、JWT、RLS、Storage 和
   两个真实 Auth 用户的运行验证仍需远程部署确认。
2. 当前协调令牌只适用于本地单实例 staging；生产必须改为 Supabase JWT/RLS，
   不能把共享协调令牌发给多租户网页用户。
3. 移动门户当前以当前会话导入组织密钥完成本地解密；持久化的非导出设备私钥、
   浏览器 X25519 配对和安全恢复 UX 尚未完成，不能作为生产密钥交付方式。
4. `.pre-v9.bak` 与旧数据库仍是历史明文，按计划保留用于校验；用户确认迁移
   完成前不能删除，取得同一 Windows 账户权限者仍可读取。
5. 被撤销设备已离线保存的旧密钥或明文无法远程抹除。
6. 飞书只能处理任务元数据；桌面离线或未解锁时全文 AI 只能排队。
