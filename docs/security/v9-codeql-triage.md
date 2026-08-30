# DefenseTracker V9 CodeQL 告警复核记录

## 复核范围与结论

本记录只覆盖公开仓库 `main` 提交
`dbf8240f281b854c28646bd5fc54bb3082de49de` 上当时仍处于开放状态的 116 条
CodeQL 告警。复核逐条检查了最新实例所指向的代码、调用者、输入来源、执行边界和既有防护。

| 结果 | 数量 |
|---|---:|
| 建议以 `false positive` 关闭 | 111 |
| 建议以 `used in tests` 关闭 | 5 |
| 建议保留并修复 | 0 |
| **覆盖合计** | **116 / 116** |

这里的“建议关闭”是对指定提交上指定静态告警的可利用性判断，不是“零漏洞”声明。
本文生成步骤没有在 GitHub 上执行 dismissal；远端操作仍应逐项使用下表中的原因和评语，并在操作后重新读取告警状态核验。

## 按规则聚合

下表是互斥的审计归类，合计 116 条。规则名称沿用扫描结果；“主要控制证据”概括的是判定依据，不替代代码审查。

| 复核类别 | 数量 | 主要区域 | 主要控制证据 |
|---|---:|---|---|
| `py/path-injection` | 88 | 构建、发布、证据收集 CLI 与运行时目录 | 工具输入来自同权限操作员或受信部署配置；关键路径另有绝对路径、常规文件、非符号链接、固定子目录、权限、哈希或签名约束。证据写入使用固定发布目录、逐层 `O_NOFOLLOW` 检查及排他或原子写。 |
| `py/stack-trace-exposure` | 13 | `app.py`、`tracking.py`、`v9/api.py`、`v9_cloud.py` | 返回的是项目自定义验证异常的固定或有限消息；没有序列化 traceback、异常 `repr`、文件路径、密钥或上游响应正文。 |
| `py/polynomial-redos` | 3 | `consulting_agent.py`、`report_agent.py` | 唯一入口在正则执行前强制 4,096 字符上限。 |
| `py/log-injection` | 3 | `auth_devices.py`、`feishu_cloud.py` | 一个值先经 Flask 整数路由转换；其余来自受信启动配置或固定管理员模式，并使用参数化日志。 |
| 测试专用告警 | 5 | `tests/js/*`、`tests/test_*` | 两个 Node VM 测试、一个脱敏过滤测试、一个 CSP 字面量断言和一个文件竞争模拟，不进入已发布运行时。 |
| critical 命令执行 / SSRF | 3 | `scripts/build_app.py`、`scripts/collect_deployment_evidence.py` | 子进程使用固定 argv 且 `shell=False`；网络探测绑定精确 HTTPS origin，检查公开地址并核对实际 TLS peer，且不跟随重定向。 |
| SHA-1 非安全标识 | 1 | `state.py` | SHA-1 只生成规范化公开文章 URL 的稳定标识，不用于密码、认证、MAC、签名或完整性保证。 |

## 关键控制证据

- [`scripts/build_app.py:128-240`](https://github.com/player1314520/defense-tracker-mvp/blob/dbf8240f281b854c28646bd5fc54bb3082de49de/scripts/build_app.py#L128-L240)：构建器从隔离解释器构造固定 PyInstaller argv，验证版本元数据，并以参数数组、`shell=False` 启动进程。
- [`scripts/collect_deployment_evidence.py:338-412, 894-1034`](https://github.com/player1314520/defense-tracker-mvp/blob/dbf8240f281b854c28646bd5fc54bb3082de49de/scripts/collect_deployment_evidence.py#L338-L412)：探测目标绑定到受信部署配置中的精确 HTTPS origin；解析结果必须为公开地址，连接使用已验证地址，随后核对实际 TLS peer，客户端不跟随重定向。
- [`scripts/collect_deployment_evidence.py:503-570, 592-632`](https://github.com/player1314520/defense-tracker-mvp/blob/dbf8240f281b854c28646bd5fc54bb3082de49de/scripts/collect_deployment_evidence.py#L503-L570)：证据输出被限制在固定发布 SHA 目录，按目录组件执行非跟随检查，并以排他创建或原子替换写入。
- [`scripts/collect_deployment_evidence.py:1629-1688, 2098-2171`](https://github.com/player1314520/defense-tracker-mvp/blob/dbf8240f281b854c28646bd5fc54bb3082de49de/scripts/collect_deployment_evidence.py#L1629-L1688)：可执行文件必须是绝对、常规、非符号链接文件；恢复流程还绑定固定 Git 上下文。
- [`consulting_agent.py:20, 406-422, 722-727`](https://github.com/player1314520/defense-tracker-mvp/blob/dbf8240f281b854c28646bd5fc54bb3082de49de/consulting_agent.py#L406-L422) 与 [`report_agent.py:59, 1076-1084, 1115-1127`](https://github.com/player1314520/defense-tracker-mvp/blob/dbf8240f281b854c28646bd5fc54bb3082de49de/report_agent.py#L1076-L1084)：进入相关正则前均有 4,096 字符硬上限。
- [`v9/cloud.py:180-278`](https://github.com/player1314520/defense-tracker-mvp/blob/dbf8240f281b854c28646bd5fc54bb3082de49de/v9/cloud.py#L180-L278)：解析异常在验证边界被替换为固定或受限的字段级消息。
- [`state.py:29-51`](https://github.com/player1314520/defense-tracker-mvp/blob/dbf8240f281b854c28646bd5fc54bb3082de49de/state.py#L29-L51)：SHA-1 输入是规范化的公开文章 URL，只服务于非安全标识用途。
- [`tests/test_search_adapters.py:200-208`](https://github.com/player1314520/defense-tracker-mvp/blob/dbf8240f281b854c28646bd5fc54bb3082de49de/tests/test_search_adapters.py#L200-L208)：脱敏测试使用合成哨兵验证过滤器，哨兵不由生产代码发出。

## 逐告警 dismissal 映射

每个告警编号在本表中恰好出现一次。合并在同一行的编号具有相同的代码边界、建议原因和评语；编号已展开列出，以便逐项操作和回读核验。

| Alert | `dismissed_reason` | Dismissal comment |
|---|---|---|
| #2, #3 | `used in tests` | This test intentionally executes a checked-in application script inside a Node vm context, and no user-provided code reaches any shipped runtime sink. |
| #37 | `used in tests` | This test logs a synthetic sentinel solely to verify that the installed redaction filter removes it, and production code does not emit the sentinel. |
| #60 | `used in tests` | This is a literal assertion against an expected CSP origin in a Flask test and performs no URL sanitization in shipped code. |
| #217 | `used in tests` | This monkeypatched open wrapper exists only to simulate a symlink race against the deployment-evidence root and is not included in the product runtime. |
| #57 | `false positive` | The executable and PyInstaller arguments are constructed from the isolated build interpreter, fixed flags, validated metadata, and operator-controlled build roots, while subprocess.run receives an argv list with shell execution disabled. |
| #58 | `false positive` | Every shipped caller supplies an absolute regular root-controlled Docker or Git executable or the hash-verified materialized recovery harness, and Popen receives an argv list with shell=False. |
| #61 | `false positive` | The collector binds the exact lowercase HTTPS origin to root-owned deployment configuration, rejects non-public DNS answers, pins the actual TLS peer to the validated address, and never follows redirects. |
| #7 | `false positive` | UnsupportedAiProvider is raised only with one of two fixed registry messages, so the response contains neither traceback data nor attacker-controlled exception detail. |
| #13 | `false positive` | record_quality_feedback raises only fixed validation messages and the authenticated route serializes no traceback object or internal exception context. |
| #22, #23, #25, #26 | `false positive` | These custom brief-reference exceptions contain only fixed stale or conflict messages and expose no stack trace, path, secret, or upstream exception text. |
| #258 | `false positive` | AIBudgetExceeded contains only fixed kill-switch or bounded numeric budget messages derived from trusted process configuration and never includes traceback data. |
| #34, #35 | `false positive` | _clean_topic_payload raises only the fixed label-empty validation message, and the authenticated JSON response contains no traceback or internal state. |
| #36 | `false positive` | validate_ciphertext_event replaces parser failures with bounded validation messages and only echoes field names already supplied by the authenticated caller in JSON-escaped form. |
| #4, #5, #6 | `false positive` | These snapshot ValueError paths contain only fixed state-invariant messages or a bounded local event count and never serialize traceback frames, paths, ciphertext, or upstream exception text. |
| #221 | `false positive` | dev_id is produced by Flask's int route converter and logged through parameterized logging, so it cannot inject log separators or control text. |
| #228, #229 | `false positive` | These startup-only log values come from trusted deployment configuration or fixed administrator-selected mode literals, while the interval is parsed as an integer. |
| #213 | `false positive` | SHA-1 is used only to derive a non-secret stable article URL identifier and provides no password storage, authentication, MAC, signature, or integrity guarantee. |
| #38, #39 | `false positive` | The only caller rejects consulting instructions longer than 4096 characters before these expressions run, so attacker-controlled input is strictly bounded. |
| #48 | `false positive` | The only caller rejects report requests longer than 4096 characters before this expression runs, so attacker-controlled input is strictly bounded. |
| #84, #85, #86 | `false positive` | Every shipped caller writes fixed filenames below SOURCE_ARCHIVE_DIR after session and evidence components pass _safe_asset_part, which removes separators and strips dot-only path components. |
| #115 | `false positive` | DEFENSE_TRACKER_PDF_WORKER_PYTHON is trusted same-process configuration and must resolve to an absolute existing regular file before execution. |
| #116, #117, #118 | `false positive` | The private PDF worker receives a randomized empty result file pre-created by its parent, verifies the fixed prefix, suffix, type, and zero size, and writes only in worker mode. |
| #121, #122, #123, #124, #125, #126 | `false positive` | The dedupe database path comes only from trusted deployment environment settings or OS state directories, is forbidden inside the source tree, and its directory and file permissions are tightened to 0700 and 0600. |
| #175, #176 | `false positive` | Production loads the bundled fixed version.json path, while the optional path parameter is a same-process test or tooling override that only reads and validates JSON. |
| #67, #68, #69 | `false positive` | This local release CLI intentionally inspects an operator-selected regular non-symlink PE file and performs no remote file selection or filesystem write. |
| #71, #72, #73, #74, #75, #76, #77, #78, #79, #80, #81, #82, #83, #282 | `false positive` | These paths belong to the isolated local build harness, and deletion is limited to the resolved release-staging child whose parent must exactly equal the operator-controlled build root. |
| #87, #88, #89, #90, #91, #92, #93 | `false positive` | This root-only deployment-evidence CLI reads operator-selected regular non-symlink inputs, bounds their size, and detects file changes while hashing. |
| #94, #95, #96, #97, #98, #99, #100, #101, #102, #103, #104, #105, #106, #107, #108 | `false positive` | Output names are fixed beneath the exact release-SHA evidence directory, whose full POSIX chain is opened with O_NOFOLLOW and verified root-owned before O_EXCL or atomic writes. |
| #109, #110 | `false positive` | The command executable must be an absolute existing non-symlink regular file and every shipped caller further binds it to a root-controlled fixed tool or verified harness. |
| #111, #112, #113, #119, #120 | `false positive` | Recovery inputs come from the root-controlled deployment environment and must be absolute existing non-symlink regular files before the fixed Git-bound recovery harness can read them. |
| #128, #129 | `false positive` | This local Windows helper writes one fixed VBS filename into the current user's Startup directory derived from trusted process environment, with no remote path input. |
| #133, #134, #135, #136, #137, #138, #139 | `false positive` | This protected release-review CLI accepts same-privilege operator paths, requires regular non-symlink evidence and canonical signing-request files, verifies exact SHA-256 plus repository/workflow/run/commit/subject bindings, and atomically writes only the requested review output. |
| #164, #165, #166, #167, #168, #171, #172, #173, #174 | `false positive` | This release-packaging CLI reads operator-selected inputs only after signing request/receipt SHA-256, schema, cross-run provenance, committed Publisher policy, component, payload, and commit bindings are validated. Offline files do not prove an approver identity; GitHub Environment audit evidence remains separate. |
| #207, #208 | `false positive` | This local Windows helper removes only the one fixed DefenseTracker VBS filename from the current user's trusted Startup directory. |
| #210, #211 | `false positive` | This local audit CLI reads only Git-indexed relative paths returned by git ls-files under the explicitly selected repository root and performs no product-runtime write. |
| #180, #181, #182, #183 | `false positive` | Runtime roots come from trusted same-process configuration or standard OS user-data variables, and subsequent creation rejects symlinks, reparse points, and non-directory entries. |
| #212 | `false positive` | WeChat runtime paths are trusted deployment or same-process configuration, must be absolute, and later security checks reject symlink and Windows reparse chains before private storage use. |

## 复核后的操作要求

1. 只对精确提交 `dbf8240f281b854c28646bd5fc54bb3082de49de` 的上述实例应用 dismissal；如果最新实例、规则、路径或代码已变化，应停止并重新复核。
2. 远端操作应逐项采用表中的 reason 和完整英文 comment，不使用批量“无说明关闭”。
3. 操作后重新查询开放告警，核对 116 个编号的状态、关闭原因、评语和最新实例 SHA；任何未匹配项都不得宣称已闭环。
4. 后续代码、工作流、依赖或权限模型发生变化时，重新运行 CodeQL 与人工复核；本文不能作为永久豁免。

## 诚实边界

- 本次是指定提交和指定 116 条静态告警的人工复核，没有运行漏洞 PoC、正则性能计时、完整构建或应用端到端测试。
- 结论不覆盖 CodeQL 未建模的逻辑缺陷、运行时配置错误、依赖供应链事件、零日漏洞或未来提交；不能据此声称仓库“没有漏洞”。
- dismissal 只能减少已解释的扫描噪声，不能修复后来出现的控制退化；路径、权限、调用者或输入来源变化后，原结论可能立即失效。
- 本次复核没有验证生产主机权限、WAF、备份、外部密钥、代码签名身份或真实部署网络边界。
- 本文没有执行或验证远端 dismissal。只有 GitHub 逐项回读与新一轮扫描结果才能证明远端告警状态已按预期更新。
