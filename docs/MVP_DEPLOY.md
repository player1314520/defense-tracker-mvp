# DefenseTracker MVP 上线手册

本手册只覆盖 V9 Portal、自托管 Supabase 和 Caddy 反向代理。旧版完整
`app.py`、`deploy/Dockerfile`、飞书机器人、云端 AI 和素材库均不进入生产镜像，
也不得上传到 VPS。生产拓扑固定为：

```text
Internet :80/:443
        |
      Caddy (portal.example / api.example)
        |                         |
  127.0.0.1:18080          127.0.0.1:18000
        |                         |
   V9 Portal                 Supabase Kong
                                  |
                  Auth / Postgres / Storage / Realtime
```

Supabase 官方明确说明，自托管方自行承担服务器维护、安全加固、Postgres
维护、备份恢复、监控、扩缩容和高可用；本项目因此把这些项目设为上线门禁，
而不是把“容器已启动”视为完成。参考：

- [Supabase 自托管边界](https://supabase.com/docs/guides/self-hosting)
- [Supabase 官方 Docker 部署](https://supabase.com/docs/guides/self-hosting/docker)
- [Supabase 自托管 Functions](https://supabase.com/docs/guides/self-hosting/self-hosted-functions)
- [Supabase API_EXTERNAL_URL 变更说明](https://supabase.com/changelog/47093-self-hosted-supabase-api-external-url-to-include-auth-v1)
- [Supabase Storage 配置](https://supabase.com/docs/guides/self-hosting/storage/config)
- [Docker Compose secrets](https://docs.docker.com/compose/how-tos/use-secrets/)
- [Caddy 自动 HTTPS](https://caddyserver.com/docs/automatic-https)
- [Caddy reverse_proxy 头部契约](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#headers)
- [Microsoft SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)

## 1. 固定版本和目录

仅在 Ubuntu VPS 上执行；本机没有 Docker，本轮没有进行真实容器或远端验证。

1. 将本仓库的一个已审阅 Git SHA 放在
   `/opt/defense-tracker/releases/<sha>`，`current` 只指向已验收版本。
2. 按 Supabase 官方手册取得其 `docker/` 配置，记录并锁定上游完整 Git SHA；
   不使用浮动 `main` 快照。实际路径填入 `SUPABASE_STACK_DIR`。所有启动、备份和
   恢复命令都必须同时叠加 `supabase.production.override.yml`；该 overlay 要求
   Docker Compose 2.24.4 或更高版本。
3. Postgres、Storage、配置和备份暂存必须是四个明确且互不混用的持久路径；
   可把独立持久磁盘分别挂载到官方 `volumes/db/data` 与 `volumes/storage` 路径。
   `preflight.sh` 会比较官方 Compose 展开后的真实挂载源与配置值。
4. Caddy 镜像使用供应方已核验的 `@sha256:` 摘要；Portal 镜像标签必须是
   40 位 Git SHA，并且 OCI revision label 必须等于该 SHA。
5. 禁止运行 Supabase 的 reset/uninstall 脚本；它们不属于上线或回滚流程。

## 2. 配置和秘密

将 `deploy/mvp/production.env.example` 复制到仓库外的
`/etc/defense-tracker/production.env`，替换所有 `.invalid`、零 SHA 和摘要占位符，
权限设为 `0600`。Portal 与 API 必须使用两个不同的精确域名，禁止通配符。

Supabase 继续使用其官方、锁定版本附带的 `.env.example` 作为字段基线；把
`deploy/mvp/supabase.required.env.example` 中的非秘密网络项合并进去。所有
数据库/JWT/SMTP/Vault 密钥使用上游生成工具单独生成，留在权限为 `0600` 的
上游 `.env`，不得复制进仓库、命令行、工单或日志。

当前官方自托管 Auth 约定是
`API_EXTERNAL_URL=https://<API域名>/auth/v1`，而
`SUPABASE_PUBLIC_URL=https://<API域名>`；不要把两者都写成裸域名，也不要形成
重复的 `/auth/v1/auth/v1`。`FUNCTIONS_VERIFY_JWT=false` 是本 MVP 的刻意设置：
`access-applications` 的匿名 `apply` 必须先到达函数；其 `list/decision` 和
`invite-member` 仍在函数内调用 `auth.getUser`，并由 session/device-bound RPC
二次授权，不代表其他业务接口匿名开放。

创建以下仓库外文件，均为 `0600`：

| 文件 | 用途 |
|---|---|
| `secrets/supabase_publishable_key` | Portal 浏览器公开密钥；不得放 service-role key |
| `secrets/backup-age-recipient` | `age` 备份接收方公钥 |
| `secrets/rclone.conf` | 异机对象存储连接配置 |
| Supabase `.env` | 数据库、JWT、Vault、SMTP 等生产秘密 |

Supabase `.env` 还必须保存两把互不相同、各编码 32 byte 的 canonical base64url
申请密钥，以及 1..100 的密钥版本。`V9_ALLOWED_ORIGINS` 只能是 Portal 精确 HTTPS
origin，`V9_INVITE_REDIRECT_URL` 只能是该 origin 的 `/portal/`，不得包含凭据、
query 或 fragment。`preflight.sh` 会从 Compose 的最终展开配置中校验这些契约，
并直接读取官方 `.env`，用恒定时间比较仓库外 key 文件、官方单值/JSON map、Kong
与 Functions 的 `SUPABASE_PUBLISHABLE_KEY`；它不会打印 key。

Compose 只把获准的单个 key 文件挂到 Portal 的 `/run/secrets`。Docker 官方文档
指出 Compose secrets 以逐服务文件挂载方式提供；`portal-entrypoint.sh` 只读取
固定文件，不枚举或打印秘密。Portal 不接收 service-role、数据库或解密密钥。

MVP 硬上限已固化为 100 个活跃账号、20 个并发请求、每用户每日 1,000 次事件、
同步单页 500 条。`INVITED_SIGNUP_ENABLED` 在以下门禁全部通过前保持 `false`：

- 自定义 SMTP、SPF/DKIM/DMARC 与退信监控可用；
- Before User Created Hook 和公共 signup 关闭状态得到核验；
- 两名真实用户完成邮件、PKCE、设备审批、撤销和跨角色 RLS E2E；
- 管理员申请审批与 100 人硬上限验证通过。

## 3. 构建、预检与上线

Portal 构建上下文必须由 `scripts/prepare_mvp_portal_context.py` 从干净的 `HEAD`
生成。它只允许 `v9_cloud.py`、`v9/`、`web/v9-portal/`、Portal Dockerfile、入口
脚本和最小依赖清单进入 `build/mvp-portal-context`；本地配置、素材、测试、旧
Flask 工作台和未提交内容不能进入上下文。

`deploy/mvp/bin/build-portal-image.sh` 要求基础 Python 镜像带完整 SHA-256 摘要，
并将 Portal 标记为 `<repository>:<40位Git SHA>`。构建前工作树必须完全干净；镜像
同时携带该提交的 backend source manifest SHA-256、wire compatibility token 与
`expand-contract` migration policy 标签。manifest 覆盖全部
`supabase/migrations/*.sql`、`access-applications`、`invite-member` 和兼容性声明，
包括 `202608100025_mvp_first_owner_key_envelope.sql` 与
`202608100026_mvp_idempotent_device_registration.sql`。脚本默认只本地构建；只有另行
获得外部写入确认后才允许显式传入 `--push`。
push 成功时脚本必须输出 `Immutable release reference: <repository>@sha256:<64位>`；
把这个独立核准的内容摘要交给 release，不能把可覆盖的 Git-SHA tag 当作镜像内容证明。

VPS 上线前依次执行：

1. 校验两个域名 A/AAAA 记录只指向目标 VPS，防火墙只公网开放 80/443；SSH
   使用独立管理入口。生产 overlay 将 Kong 固定到 `127.0.0.1:18000`，清空
   Supavisor 的 5432/6543 宿主端口；Studio、DB、Storage 均不得发布公网端口。
2. 先把 `SUPABASE_FUNCTIONS_DEPLOY_DIR` 指到仓库外
   `/var/lib/defense-tracker-supabase-functions/current`。运行
   `start-supabase.sh`；它先要求运行脚本的项目 checkout 干净且 `HEAD` 为本次完整
   release SHA，并要求官方 Supabase checkout 干净且 `HEAD=SUPABASE_UPSTREAM_SHA`。
   随后把官方锁定版本的 `volumes/functions/main` 与本版本
   `access-applications`、`invite-member` 组合为哈希命名的不可变目录，再对官方
   Compose 与 overlay 执行 `pull`、`up --wait`，逐个安装
   `supabase/migrations/*.sql`，最后强制重建 Functions 容器并核验关键 RPC。
   每个迁移的文件名、SHA-256 和状态写入私有账本；另一个私有 backend release
   账本绑定项目 release SHA、source manifest、wire token、migration policy、Functions
   digest 与官方 Supabase SHA，并在主机 `MVP_RELEASE_STATE_DIR/backend.*` 留下同值
   状态。已登记迁移发生内容漂移、release 元数据不一致或上次尝试状态不明时会
   fail-closed，不能静默重跑。API 域名只放行 Auth、REST、
   GraphQL、Realtime、Storage 及两个指定函数路径，其他路径统一 404；默认
   `hello`、Studio 和管理路由不进入公网。Portal 域名也只放行 `/portal/*`、
   `/health`、`/ready`、根跳转和 favicon。
3. 运行 `deploy/mvp/bin/preflight.sh /etc/defense-tracker/production.env`。该脚本
   验证工具、权限、精确域名、两个干净 checkout 的 Git SHA、真实挂载、回环端口、
   两套 Compose、publishable key 一致性、函数密钥格式、迁移账本、backend release
   账本、关键 RPC（包括 `put_mvp_first_owner_key_envelope`）和函数挂载；不会
   打印展开后的秘密配置。

迁移 026 保持现有 `mvp-wire-v1`：公网 RPC 仍是七参数
`register_device(uuid,uuid,text,text,text,text,text)`，只允许 `authenticated` 执行，
`anon`、`service_role` 与 `PUBLIC` 均无执行权。它只把完全相同的 P-256 desktop
response-loss 重试变为幂等返回，不把注册改成 upsert，也不放宽 session、membership、
邀请绑定或 pending-device 限制。installer 的 `*.sql` hash ledger 与 exact-release
manifest 自动覆盖该文件，verifier 另行显式核验七参数 signature 和 ACL。

### 首位 Owner 站外引导

首位 Owner 不经过公开申请审批。初始空库的
`V9_AUTH_HOOK_ENABLED=false`，但官方 `DISABLE_SIGNUP=true` 始终不变，因此没有
公共注册窗口。把唯一地址写入仓库外 `0600` 文件（不要放进 argv 或 shell 历史），
执行：

```sh
deploy/mvp/bin/bootstrap-owner.sh /root/defense-first-owner.email \
  /etc/defense-tracker/production.env
```

脚本只允许 `auth.users`、组织、成员、设备和设备会话均为空时首次执行，数据库只记
地址 SHA-256 与状态，不记明文；相同文件重跑是幂等的，不会发送第二封邀请。收件人
必须在准备作为首台设备的桌面端完成邮件验证与登录。桌面端随后以
`build_mvp_owner_bootstrap_manifest` 生成 `schema_version=1` 的
`mvp-owner-bootstrap.json`：其中只有 organization/owner/session/device 标识、组织与设备
名称密文、nonce 和 P-256 公钥；Access Token、P-256 私钥与 org key 不得导出，仍只
留在桌面加密存储。Windows 桌面端在仓库根目录运行：

```powershell
py -3 .\scripts\export_mvp_owner_manifest.py `
  --output "$env:LOCALAPPDATA\DefenseTracker\vault\mvp-owner-bootstrap.json"
```

导出器只从已验证并刷新过的 Supabase session 取 user/session 标识，拒绝 CLI 注入身份、
拒绝覆盖既有文件，并把 ACL 限于当前登录 SID；它只打印最终路径，不打印内容。通过
受控通道转移到 VPS 后，文件必须为 root 所有且 `0600`。

把受保护配置改为 `V9_AUTH_HOOK_ENABLED=true`，再执行：

```sh
deploy/mvp/bin/bootstrap-owner.sh --finalize \
  /root/defense-first-owner.email /root/mvp-owner-bootstrap.json \
  /etc/defense-tracker/production.env
```

`--finalize` 严格拒绝多余字段、非 P-256/desktop 或不匹配的 owner。它只通过回环
Kong、使用官方 `.env` 的 service-role JWT 调用一次性
`bootstrap_mvp_first_owner` RPC；普通 `authenticated` 永久没有旧
`bootstrap_organization` 的执行权。RPC 验证唯一 Auth 用户、manifest session 确属
该用户、invite marker 匹配且业务表为空，再在同一事务创建唯一组织、active Owner、
active desktop P-256 device 与该 session 的绑定；advisory lock、marker 行锁与完整
payload SHA-256 使同参重试幂等、异参重试失败。脚本随后重建 Auth，并在容器内确认
公开 signup 仍关闭、Before User Created Hook 已启用，最后把 marker 置为 finalized。
若任一计数或返回值不唯一，脚本停止且不打印 manifest、地址或凭据。

Owner 首次进入 Portal 后，桌面端只可通过 authenticated RPC
`put_mvp_first_owner_key_envelope(integer,text,text,text)` 为 bootstrap 绑定的同一
desktop/session 发布一次 P-256 组织密钥 envelope，并要求返回 `status=ready`、同一
organization/device 与 key version。`anon`、`service_role` 与 `PUBLIC` 没有该 RPC
执行权，`authenticated` 也没有对 `public.key_envelopes` 的直接 `INSERT` 权；部署
verifier 会核验这些 ACL。这个需要真实登录 session 的成功响应仍属于上线后的用户 E2E，
不能由无凭据 public probe 替代。

4. 运行
   `release.sh <image-repository> <full-git-sha> <repository>@sha256:<64位摘要>`。在任何
   Supabase 写入前，脚本只 pull 该已核准的 immutable digest（不会按可变 tag 选取镜像），
   要求运行它的 checkout 完全干净且 `HEAD` 精确等于参数，重新计算 exact-commit
   backend manifest，先 pull 候选镜像，核对 revision/manifest/wire/policy 四类标签，
   并完成候选 Compose `config --quiet`。若已有 current Portal，它还必须声明与候选
   backend 相同的 wire token；否则发布在迁移前即 fail-closed。通过这些门禁后才安装/
   核验迁移与 Functions，backend 失败时不会启动候选 Portal。随后等待容器健康，并通过
   一个不打印 key 的探测器
   检查 Portal `/ready`、公共配置与官方 key 完全一致、Auth、Storage health、
   匿名 access apply 运行路径及 Realtime WebSocket 的 TLS/HTTP 101 握手。成功后
   才原子更新 current/previous 的 image/SHA/wire/manifest；失败只在 current 的 wire
   仍与 active backend 完全相同时恢复 current，且从不 image prune。
   `/ready` 需要 Portal 容器访问精确 Supabase HTTPS origin，因此 Portal 同时加入
   一个不承载其他服务的 egress bridge；原有 `portal-internal` 仍为 internal。
5. 外部再用两名真实账号走一次申请、邮件、登录、设备批准、密文同步、编辑提交、审批签发和
   撤销流程；观察 15 分钟 5xx、P95、内存、磁盘、邮件失败与同步滞后。

上传限制按层明确：Portal 请求上限 256 KiB；V9 record ciphertext 是
`16 MiB + 16 byte` AES-GCM tag，Storage 同样限制为 16 MiB 加 tag；同步事件的
编码 JSON 上限 24 MiB；Caddy API 传输上限 32 MiB 只用于容纳 JSON/base64 与协议
开销。Caddy 的 32 MiB 不是业务对象可以达到 32 MiB 的承诺。

匿名申请的来源契约固定在最外层 Caddy：它删除客户端提供的 `X-Real-IP`、
`X-Forwarded-For`、`CF-Connecting-IP` 与 `X-V9-Client-IP`，再用 TCP 对端
`{remote_host}` 生成单值
`X-V9-Client-IP` 和 `X-Forwarded-For`。Functions 只把该受信单值用于 source
bucket；缺失或非法时进入 global bucket，不能由客户端选择 bucket；Kong 只绑定
回环地址，公网不能绕过 Caddy 直接调用 Functions。标准 Caddy 镜像没有内置的
per-source/global request-rate 模块；`unhealthy_request_count` 是反向代理的被动
健康信号，**不是请求限流器**，因此本配置不伪装成网关限流。函数仍执行
email/source/global 三层业务限流，但上线前必须由 VPS 防火墙或 CDN/WAF 提供连接数、
请求速率和 DDoS 限制。若在 Caddy 前加入 CDN/WAF，必须先固定其出口 CIDR、在最外层
清洗来访转发头并重新审阅 Caddy `trusted_proxies`；未完成前不得直接信任 CDN
传来的来源头。

回滚触发条件：任一核心流程失败、5xx 持续超过 1%、P95 API 持续超过 2 秒、
出现跨用户/跨角色数据、备份超过 26 小时或磁盘剩余低于 20%。执行 `rollback.sh`
前，脚本先从数据库私有账本、Functions digest 与主机 `backend.*` 状态复验 active
backend，再要求 previous 镜像的 revision/manifest 与保留状态一致、policy 为
`expand-contract`，且 previous wire token 精确等于 active backend wire；任一缺失或
不一致都在 Portal 切换前 fail-closed。通过后只切换到 retained previous Portal，并把
被替换镜像保留为 roll-forward 候选；**不会回滚数据库或 Functions**。迁移必须保持
expand-contract/前向兼容，数据库恢复不能由 Portal 镜像回滚替代。需要改变 wire token
的版本不支持单步发布：必须先做经复核的两阶段兼容发布，使新旧 Portal 都能与过渡
backend 协作，再移除旧 wire；不要修改 token 后强行绕过门禁。

## 4. 备份、恢复与桌面发布

安装 `defense-tracker-backup.service/.timer` 后，systemd 每晚 02:15
（Asia/Shanghai，最多随机延迟 15 分钟）进入停写维护窗口。`backup.sh` 先取得与
发布/迁移共用的锁，停止 Kong、Auth、REST、Realtime、Storage、Functions 等所有
写入口，再生成 `postgres` 与 `_supabase` 的 custom-format dump、无密码的全局
角色清单、`/etc/postgresql-custom` 密钥卷和 Storage tar。数据库与文件快照完成后
立即恢复服务，后续配置打包、`age` 加密与异机上传不占用维护窗口。远端密文哈希
相同才记录成功；metadata 同时记录锁定的 Supabase 上游 SHA。脚本不删除远端备份，
保留周期由异机对象存储策略设置。

这里不直接恢复 `pg_dumpall` 的 `CREATE ROLE`：新的锁定 Supabase DB 镜像已经用
同版 init scripts 创建同名平台角色，重复执行会把正确恢复误判为失败。恢复演练
先核对备份 metadata、受保护配置和当前 checkout 的三个 Supabase SHA 完全相同，
再在 `--network none` 容器运行同版 init scripts，比较完整角色清单。恢复器过滤掉
会冲突的 `CREATE ROLE` 行，但继续应用无密码的其余全局 role 属性/成员关系，随后对
两个数据库执行 `pg_restore --clean --if-exists --exit-on-error`。这样既保留全局角色
设置与 dump 中的 owner/ACL 引用，也解决同名 role 冲突。

每周抽取最新备份运行 `restore-dry-run.sh <age文件> <identity文件> [sha文件]`。
它会验证外层/内层哈希，在 `--network none` 的临时 Postgres 容器恢复 SQL，并
只读校验 Storage/config 归档；不停止、连接或写入生产容器。以最近三次实际演练
计时证明 RTO 不超过 4 小时；成功备份年龄不超过 24 小时。正式灾难恢复必须在
全站维护、当前数据冻结、备份哈希复核和明确恢复授权后，将同一已演练包恢复到
全新的 Supabase 数据目录，再切换域名；禁止原地覆盖未知状态的数据目录。

桌面正式发布仍从 `scripts/Build-AndShip.ps1` 进入，但必须增加
`-RequireSignedInstaller`，并通过环境变量或参数提供预置的 `ISCC.exe`、
`signtool.exe`、CurrentUser 证书 thumbprint、HTTPS RFC 3161 时间戳 URL 与
Publisher。门禁不会安装工具、读取 PFX 或密码。它在 staging 中先签 EXE，使用
`/fd SHA256 /tr <URL> /td SHA256`，再由 Inno Setup 生成安装包并签名；两者都必须
同时通过 SignTool 和 `Get-AuthenticodeSignature`，且存在时间戳证书。上一版保留
在 `dist/DefenseTracker.previous`，安装包按完整 Git SHA 存入不可变目录。

## 5. 诚实边界

1. 本轮机器没有 Docker、真实 VPS、域名或证书，未验证 Compose 运行、ACME
   签发、SMTP 投递、20 并发和外网链路；静态检查不能替代这些生产证据。公开
   probe 不需要真实用户凭据，因此也不能验证设备绑定、RLS 跨角色、BYOK 解密、
   编辑审批和撤销；这些必须由两用户 E2E 证明。
2. 单 VPS 仍是单点故障；异机加密备份能支持恢复，但不提供无中断高可用。
3. 备份脚本能证明密文上传与隔离恢复，不会证明对象存储账号长期可用、保留策略
   正确或实际 RTO 达标；这些必须通过持续监控和定期演练证明。
4. 代码签名门禁能验证已提供证书的签名和时间戳，不能购买证书、保护硬件私钥、
   建立发行主体信誉，也不会绕过 Windows SmartScreen。
5. 自托管降低平台依赖但把补丁、监控、扩容、灾备责任转移给运营方；未完成这些
   门禁时，不得把 `INVITED_SIGNUP_ENABLED` 改为 `true`。
6. `repository@sha256` 固定的是已核准镜像字节，消除了可变 tag 选择风险，但目前
   没有镜像签名、keyless signature 或 provenance attestation；digest 本身不能证明
   构建者身份、源码来源或 CI 未被接管。
7. Portal Python 依赖目前只有版本 pin，没有完整传递依赖锁与 `--require-hashes`；
   因此相同 Git SHA 的重新构建不能称为可复现构建。上线使用已核准 digest，后续仍需
   补齐 wheel/hash lock、SBOM 与构建 provenance。
8. `current/previous` 的 image、SHA、wire、manifest 仍是多个文件分别原子 `mv`，不是单一 generation 的事务提交。
   进程或宿主在中间崩溃会留下混合状态；后续 release/
   rollback 会 fail-closed，但需要运营方按镜像 digest、backend 账本和备份手工复核
   修复，不能宣称该状态更新对断电完全原子。
