# 微信公众号每日发布链路

本链路把“内容准备、草稿入库、发布、群发”拆成四个明确动作。**当前生产运行范围只到准备和草稿**；真正公开发布或群发必须同时满足内容哈希审批、账号凭据和显式开关，任何业务 `errcode`、状态缺失或回查未完成均按未送达处理。

## 稳定入口

在项目根目录运行：

```powershell
py -3 scripts/run_daily_wechat.py --content .\private-input\wechat_issue.json --action prepare
py -3 scripts/run_daily_wechat.py --content .\private-input\wechat_issue.json --action draft
py -3 scripts/run_daily_wechat.py --content .\private-input\wechat_issue.json --action publish
py -3 scripts/run_daily_wechat.py --content .\private-input\wechat_issue.json --action mass-send
```

`private-input/` 是用户自行创建且已被 Git、Docker 和 Railway 排除的本地输入目录；不要把实际发布稿、账号素材或审批对象提交到仓库。

- `prepare`：绝不构造微信客户端或访问网络；本地 vault 存在时只读取其中的默认封面 `media_id` 注入内存 manifest，再预检、计算哈希并写入 SQLite 幂等账本。vault 缺失不阻断，损坏则以 `CREDENTIAL_VAULT_ERROR` 退出且不写账本。
- `draft`：创建一次草稿。若该期目标是 `mass` 或 `publish`，输出 `DRAFT_STAGED`，但仍明确标记 `delivery_verified=false`。
- `publish`：提交发布并调用发布状态接口回查；提交成功不等于发布成功。
- `mass-send`：使用确定性 `clientmsgid` 群发并调用群发状态接口回查；提交成功不等于送达。

账号配置完成后，可单独执行一次只读探测：

```powershell
py -3 scripts/probe_wechat_mp.py
```

探测脚本只从受限 DPAPI vault 读取 AppID、AppSecret 和永久封面 `media_id`，不接受命令行或普通环境变量传入凭据。它先以 `force_refresh=false` 调用一次稳定 token 接口，再用同一 token 依次 `GET /cgi-bin/draft/count` 和 `POST /cgi-bin/material/get_material`。只有只读请求明确返回 `40001`、`40014` 或 `42001` 时，整个探测最多再以 `force_refresh=false` 获取一次 token；其他错误不自动重试。

素材响应使用 `stream=True` 分块读取，硬上限 8 MiB，并在所有成功或失败分支关闭响应；内容仅留在内存，不写磁盘。当前使用 Python 标准库核验 PNG 的签名、chunk/CRC、尺寸和非交错像素流解压结构，或核验 JPEG 的签名、segment、帧尺寸、scan 与结束标记；成功时 `cover_kind` 仅可能为 `png` 或 `jpeg`。脚本不导入账本，也不会调用新增草稿、发布或群发接口。

只读探测的 `category` 分类如下：

| 微信 `errcode` / 本地错误 | `category` |
|---|---|
| `40002`、`40013`、`40125`、`41002`、`41004`、`43002` | `CONFIG` |
| `40164`、`45035`、`61004` | `IP_ALLOWLIST` |
| `48001`、`48004`、`89503`、`89506`、`89507` | `PERMISSION` |
| `40001`、`40014`、`42001` | `TOKEN` |
| `40007`、素材过大或图片结构无效 | `MATERIAL` |
| `-1` | `TRANSIENT` |
| `45009`、`45011` | `QUOTA` |
| HTTP、超时、非法 JSON/结构及未识别响应 | `UNKNOWN` |

Windows 源码运行时默认目录为 `%LOCALAPPDATA%\DefenseTracker\wechat`，默认账本为其中的 `wechat_publications.sqlite3`。可用 `WECHAT_RUNTIME_DIR` 显式覆盖整个私密运行目录，或用 `--ledger <path>` / `WECHAT_LEDGER_PATH` 单独覆盖账本；命令行覆盖优先。`WECHAT_RUNTIME_DIR` **只能指向当前用户专用且父目录不允许其他本地用户写入的位置**，不得指向共享目录、协作同步目录或其他用户可写父目录。非 Windows 默认使用 `$XDG_DATA_HOME/DefenseTracker/wechat`，未设置时使用 `~/.local/share/DefenseTracker/wechat`，不会回退到项目根目录。

首次使用新默认账本时，若旧的仓库内 `素材库/每日新闻/wechat_publications.sqlite3` 存在而新账本不存在，runner 会通过 SQLite 一致性复制生成临时副本。迁移会验证数据库完整性、必要列的类型与 `NOT NULL`、复合主键 ordinal 必须精确为 `channel=1 / publication_date=2 / edition=3`、不得存在重复 key，并逐行核对全部内容/来源哈希、状态、远端 ID、结果 JSON、操作租约和创建/更新时间。迁移在目标目录以 `O_CREAT|O_EXCL` 独占锁串行化；锁存在或来源不明时不会自动判“陈旧”并删除，而是 fail closed。核验通过后以同文件系统 hard link 原子创建目标，绝不覆盖已出现的目标账本。旧账本始终保留，核验失败会删除或隔离本进程创建的未完成副本并以 `LEDGER_MIGRATION_ERROR` 阻断。**vault 不做迁移。**

本机首次配置执行：

```powershell
py -3 scripts/configure_wechat_mp.py --approval-public-key-file D:\secure-review\approval-public.pem
```

AppID、AppSecret 和永久封面 `media_id` 三项输入均不回显；可选的 Ed25519 审批公钥来自 PEM 文件。它们作为一个 JSON 包，经当前 Windows 用户 DPAPI 加密后写入 `%LOCALAPPDATA%\DefenseTracker\wechat\.wechat_mp.vault`（或显式 `WECHAT_RUNTIME_DIR` 下的同名文件）。发布器和 vault **只持审批公钥，直接 vault API 与配置脚本都会拒绝私钥 PEM**；私钥必须留在隔离的人工签名端。脚本、命令历史和标准输出都不包含凭据或密钥内容。

配置脚本和 runner 在首次写入前都会建立私密目录。Windows 使用参数数组调用 `icacls.exe`，关闭继承，并回读目录及 vault/ledger 文件各自的 DACL；必须恰好只有当前用户、SYSTEM 与内置 Administrators 三个 SID，且均为完全控制。目标或任一祖先若是 symlink、junction、挂载点等 reparse point，会在任何 `icacls`/`chmod` 前阻断。非 Windows 目录强制为 `0700`，vault 与账本文件强制为 `0600`。SQLite journal/WAL/SHM 依赖同一专用安全父目录保护。

显式 `--ledger` / `WECHAT_LEDGER_PATH` 若指向已有父目录，runner **只读验证**其上述 DACL 或 `0700` 模式，绝不为了通过而修改共享父目录；不符合即 `RUNTIME_SECURITY_ERROR`。父目录尚不存在时，只允许在一个已存在的祖先下创建并加固最后一级专用目录，不递归创建多级路径。任何设置或回读失败均 fail closed，机器输出不包含路径。

## 输入 JSON 合同

文件必须为 UTF-8 JSON 对象，最大 2 MiB。最小可用示例：

```json
{
  "edition_date": "2026-08-14",
  "edition": "daily",
  "delivery": "mass",
  "title": "每日防务简报",
  "author": "防务开源情报",
  "digest": "仅整理可公开核验信息。",
  "content_html": "<p>正文及来源说明。</p>",
  "content_source_url": "https://example.org/brief/2026-08-14",
  "thumb_media_id": "永久封面素材 media_id",
  "source_urls": [
    "https://example.org/primary-source",
    "https://example.org/independent-cross-check"
  ]
}
```

字段要求：

- `edition_date`：`YYYY-MM-DD`，按 Asia/Shanghai 的自然日生成。
- `edition`：同一天存在多个版本时使用稳定名称；默认 `daily`。
- `delivery`：`mass`、`publish` 或 `draft`。`prepare`/`draft` 会保留该目标；`publish` 和 `mass-send` 动作会分别绑定对应目标。
- `title`、`digest`、`content_html`：不能为空。微信端仍会执行长度、格式和内容审核。
- `source_urls`：至少一个；也可改用 `sources` 对象数组保存标题、发布者、发布日期和 URL。
- `thumb_media_id`：草稿接口需要永久封面素材 ID。输入未提供时，`prepare` 会尝试从 vault（云端显式环境模式则从 Secret Store）补入运行时 manifest；它不会改写 issue JSON。仍无法取得时会写入待审账本并在 `blockers` 中返回 `THUMB_MEDIA_ID_MISSING`；任何微信网络动作都会硬阻断。补齐后须重新执行 `prepare` 并使用包含该封面 ID 的最新哈希审批。
- `approval`：仅公开动作需要，见下一节。

上线前预检还会阻断以下内容：标题超过 32 字、摘要超过 120 字；正文使用允许列表之外的标签或属性（包括 `style`、事件属性、SVG、表单、脚本等），链接或图片不是公网 HTTPS，或正文出现 `file:`、Windows 盘符路径或 UNC 路径；`content_source_url` 非空但不是公网 HTTPS；来源不是公开 `http(s)`、包含 userinfo/反斜杠、指向本地/非公网地址，或来自 `zhihu.com`、`weixin.qq.com`、`baidu.com` 及其子域。

## 审批与幂等

账本主键为 `channel + edition_date + edition`。同一主键再次提交相同内容会复用已有草稿/任务。纯 `review_pending` 且尚未请求微信时可重新准备并替换待审哈希；一旦草稿已创建，正文、目标动作或来源集合变化会触发 `IdempotencyConflict`，不会覆盖旧记录。

`prepare` 输出：

- `content_sha256`：绑定频道、日期、版本、目标动作和微信文章字段。
- `source_sha256`：绑定完整来源清单。

授权审核者核对正文与来源后，在**独立人工签名端**使用 `wechat_publisher.build_approval()` 和 Ed25519 私钥生成 `approval` 对象，再写回输入文件。自动任务不得加载私钥。审批对象包含：

```json
{
  "algorithm": "Ed25519",
  "scope": "wechat-publication-v1:wechat_official:2026-08-14:daily:mass",
  "content_sha256": "64 位十六进制摘要",
  "source_sha256": "64 位十六进制摘要",
  "approved_at": "带时区的 ISO 8601 时间",
  "signature": "Base64 编码的 Ed25519 签名"
}
```

签名时间必须是带时区 ISO 8601，不得晚于验证时刻，默认超过 24 小时即失效。任何字段不匹配或加密库不可用都会在首次微信网络请求前阻断；不会回退到 HMAC。不要让内容生成程序或自动发布任务持有审批私钥，否则“生成”和“批准”会退化成同一权限。

群发的 `clientmsgid` 由日期、版本和内容哈希确定，用于降低重复群发风险。SQLite 在每次草稿、发布、群发远端提交前原子抢占带 owner/lease 的操作状态；同一主键的并发调用者返回 `IN_PROGRESS`，不会再次提交。若租约过期但提交结果未知，则返回 `SUBMISSION_UNCERTAIN` 并要求人工核对，不自动重试。账本在响应后保存草稿 `media_id`、发布 `publish_id`、群发 `msg_id` 及回查状态。

## 运行时配置

本地默认且仅使用 DPAPI vault。云端没有 Windows DPAPI 时，必须显式设置 `WECHAT_CREDENTIAL_SOURCE=environment`，才允许从部署平台 Secret Store 注入；不能把秘密作为 CLI 参数、写入 issue JSON、Git、日志或任务提示词：

| 变量 | 用途 | 是否必需 |
|---|---|---|
| `WECHAT_MP_APP_ID` | 公众号 AppID | `draft/publish/mass-send` 必需 |
| `WECHAT_MP_APP_SECRET` | 公众号 AppSecret | `draft/publish/mass-send` 必需 |
| `WECHAT_APPROVAL_PUBLIC_KEY` | Ed25519 审批公钥 PEM（环境 Secret Store 模式） | `publish/mass-send` 必需 |
| `WECHAT_PUBLISH_ENABLED` | 公开写开关；仅 `true/1/yes/on` 放行 | 默认关闭 |
| `WECHAT_THUMB_MEDIA_ID` | 默认永久封面素材 ID | issue 未提供时必需 |
| `WECHAT_RUNTIME_DIR` | 私密运行目录绝对路径；同时决定默认 vault 与默认账本 | 测试/部署显式覆盖时可选 |
| `WECHAT_LEDGER_PATH` | 固定 SQLite 路径 | 可选 |
| `WECHAT_CREDENTIAL_SOURCE` | 云端显式设为 `environment`；本地保持默认 `vault` | 云端环境注入必需 |

账号还必须在微信公众平台配置调用 IP 白名单，并实际拥有相应草稿、发布或群发接口权限。代码不会尝试绕过账号类型、认证状态、原创审核或平台风控限制。

## 机器输出与退出码

标准输出永远只有一行 JSON；不输出 access token、AppSecret、审批公私钥或微信原始 `errmsg`。

只读探测固定只输出 `status`、`token_ok`、`draft_count_ok`、`total_count`、`cover_ok`、`cover_kind`、`code`、`category` 八个字段；AppID、token、`media_id`、AppSecret、原始请求值和微信 `errmsg` 均不进入输出。探测完全成功返回 `0`；本地运行目录、vault 或必需配置阻断返回 `2`；已发起只读请求但平台或响应验证失败返回 `3`。

| 退出码 | 典型状态 | 含义 |
|---|---|---|
| `0` | `REVIEW_PENDING`、`DRAFT_STAGED`、`PUBLISHED`、`DELIVERED` | 当前动作完成；只有后两者可将 `delivery_verified` 置为 `true` |
| `2` | `BLOCKED` | 配置、封面、审批、输入、运行目录 DACL、账本迁移或幂等冲突，未尝试越权继续 |
| `3` | `IN_PROGRESS`、`SUBMISSION_UNCERTAIN`、`PUBLISHING`、`SENDING`、`FAILED` | 并发处理中、提交结果需人工核对、已提交但尚未回查成功，或平台/内部失败；不得报告送达 |

自动任务必须以 `delivery_verified=true` 作为公开完成证据；`publish_id`、`msg_id`、HTTP 200 或 `errcode=0` 本身都不够。

## 官方接口依据

实现只调用微信官方服务器接口：

- 稳定版 access token：`POST https://api.weixin.qq.com/cgi-bin/stable_token`
- 草稿总数只读探测：`GET https://api.weixin.qq.com/cgi-bin/draft/count`
- 永久素材只读探测：`POST https://api.weixin.qq.com/cgi-bin/material/get_material`
- 新增草稿：`POST https://api.weixin.qq.com/cgi-bin/draft/add`
- 提交发布：`POST https://api.weixin.qq.com/cgi-bin/freepublish/submit`
- 发布状态：`POST https://api.weixin.qq.com/cgi-bin/freepublish/get`
- 群发：`POST https://api.weixin.qq.com/cgi-bin/message/mass/sendall`
- 群发状态：`POST https://api.weixin.qq.com/cgi-bin/message/mass/get`

对应官方文档入口：

- [新增草稿](https://developers.weixin.qq.com/doc/service/api/draftbox/draftmanage/api_draft_add)
- [发布接口](https://developers.weixin.qq.com/doc/service/api/public/api_freepublish_submit)
- [发布状态](https://developers.weixin.qq.com/doc/service/api/public/api_freepublish_get)
- [群发能力说明](https://developers.weixin.qq.com/doc/service/guide/product/message/Batch_Sends.html)
- [发布能力说明](https://developers.weixin.qq.com/doc/service/guide/product/publish.html)

接口权限和频率限制可能调整，上线前应再次以当前账号后台和官方文档为准。

## 诚实边界

1. 本地单元测试和模拟响应不能证明公众号当前具有发布/群发权限，也不能替代一次真实账号的受控试发。
2. SQLite 与远程微信接口无法组成分布式事务；进程若在微信接受请求后、账本落盘前崩溃，会进入需人工核对的 `SUBMISSION_UNCERTAIN`，不会自动重试。`clientmsgid` 只降低群发重复风险，仍不能证明所有接口严格 exactly-once。
3. `PUBLISHED` 只证明文章通过发布状态回查；`DELIVERED` 只证明群发任务返回成功，二者都不证明关注者已阅读、点击或转化。
4. 平台内容审核、原创校验、账号类型、认证状态、频率配额、IP 白名单或管理员确认均可能阻止当天自动送达，程序不会伪造成功。
5. 该链路校验来源清单和审批哈希，但不会自行证明每条防务事实为真；内容层仍须执行原始来源加独立交叉核验，并剔除敏感或无法公开验证的信息。
6. DPAPI vault 绑定当前 Windows 用户，不能直接复制到另一用户、另一台机器或 Linux 容器；云端必须重新用平台 Secret Store 配置，不能把 vault 纳入镜像。
7. 当前自动任务只准备内容并创建草稿；真实发布或群发仍需独立人工签名端、当前账号权限核验和显式公开写开关，不能把“草稿已创建”表述成“已发布”。
8. Windows DACL 回读能证明检查时目录仅有三个允许 SID，但不能证明后续管理员不会改 ACL；每次 runner/configure 启动都会重新设置并核验，仍不能替代主机账户与磁盘安全。
9. 一次性账本迁移会保留旧文件用于人工回退，因此旧仓库目录仍需按敏感运行数据保护并由用户另行决定何时归档；程序不会迁移、删除或覆盖旧 vault。
10. 当前 DPAPI vault 仍以一个加密 JSON 包整包解密到当前进程内存，再只把所需字段交给调用路径；它避免明文落盘，但不是字段级 least-secret 解密。拆分 vault 格式与字段级解密属于后续 P2，不在本轮兼容契约内。
11. 只读探测成功只证明该时刻能取得 token、读取草稿数量并取回指定封面；它不能证明新增草稿、发布或群发权限，更不会主动调用这些写接口验证。
12. PNG/JPEG 结构验证只能证明下载内容满足受支持图片格式的有限结构约束；它不能证明图片视觉内容正确、版权合规、适合作为封面或一定通过微信内容审核，其他图片格式会 fail closed。
13. 单次探测不能证明长期可用性、次日 IP 白名单状态、剩余接口配额或平台未来策略；`TRANSIENT`/`QUOTA`/`UNKNOWN` 也不会触发自动猛重试。
14. 探测不写账本或证据文件，因此它不能提供历史审计链；需要留存结果时，只能由外层受控系统保存这行已脱敏 JSON，不能保存请求或原始响应。
