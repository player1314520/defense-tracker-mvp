# V9-P1 零知识数据层

## 信任边界

桌面客户端持有本地 master key、设备私钥和已封装的组织密钥。Supabase、
Railway 和飞书只允许处理组织 ID、设备 ID、版本、状态和密文；不得持有
可解密正文的密钥。

## 密钥层级

1. 每个组织一把 256 位组织密钥，并维护单调 `key_version`。
2. 每条记录、每个文件各生成独立 256 位数据密钥。
3. 正文/文件以 AES-256-GCM 加密，AAD 绑定组织、记录/对象、类型和版本。
4. 数据密钥由组织密钥以 AES-256-GCM 封装。
5. 组织密钥通过临时 X25519、HKDF-SHA256 和 AES-GCM 封装给设备公钥。
6. 恢复码使用 Scrypt 派生包装密钥；服务器只保存恢复信封，不保存恢复码。

## 本地表

- `organizations`、`memberships`、`devices`
- `key_envelopes`、`recovery_envelopes`、`local_secrets`
- `encrypted_records`
- `sync_outbox`、`sync_cursor`、`sync_events`、`conflicts`

`encrypted_records.record_type` 覆盖 source、evidence、entity、relation、
geo_event、alert、case、job、scenario、document、publication_item 和
audit_event。

## 同步与冲突

- outbox 只包含密文、nonce、封装数据密钥、版本、设备和哈希。
- `event_id` 幂等；已应用事件重复到达时不重复写入。
- 本地存在未发送修改时，新远端正文进入 `conflicts`，双方密文均保留。
- 过期版本不覆盖当前版本。
- 重试节奏为 1、5、30、120、600 秒；第五次之后再失败即进入人工处理。

## 撤销

撤销设备或非 Owner 成员时：

1. 生成新组织密钥和新恢复码。
2. 用旧组织密钥解开每条数据密钥，再以新组织密钥重封装。
3. 只为仍有效设备生成新组织密钥信封。
4. 撤销状态、全部重封装、恢复信封和组织版本在单一事务提交。

## 云端 SQL

`supabase/migrations/202607250001_v9_zero_knowledge.sql` 提供：

- Auth 用户、组织成员和六角色约束；
- `encrypted_records` 与 `encrypted_objects` 密文表；
- 私有 Storage bucket；
- 所有租户表 RLS；
- 角色到记录类型的写权限；
- 拒绝过期版本覆盖的触发器；
- 跨组织访问必须通过有效 membership。

## 诚实边界

1. 当前只完成 SQL 和静态门禁；没有 Supabase 本地容器或 staging，实际
   Postgres RLS 行为尚未运行验证。
2. 被撤销设备已离线保存的旧密钥或明文无法远程抹除。
3. 恢复码与全部有效设备同时丢失时，组织数据不可恢复。
4. 本地 master key 尚未使用 Windows DPAPI 封装；同账户完全失陷不在当前防护内。
5. 零知识云端不能进行全文搜索、服务端 AI 或正文级冲突合并。
6. Codex Security 原生 diff workspace 错误地拒绝了已确认的 Git 根目录；
   本批完成了人工安全差异评审与 gitleaks，但没有伪造原生扫描完成记录。
