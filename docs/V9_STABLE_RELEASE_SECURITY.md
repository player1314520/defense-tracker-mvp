# V9 稳定版证书与发布原子性边界

稳定版工作流只接受受保护环境中显式配置的签名身份。以下值不得从待发布
二进制、证书 `CN`、本机信任库或 Release 清单反推：

- `DEFENSE_TRACKER_EXPECTED_SIGNER_SUBJECTS`：完整 X.500 Subject；单值，或最多
  4 项的 JSON 字符串数组。
- `DEFENSE_TRACKER_EXPECTED_SIGNER_SPKI_SHA256`：与 Subject 顺序一一对应的
  SPKI SHA-256；单值，或最多 4 项的 JSON 字符串数组。
- `DEFENSE_TRACKER_EXPECTED_SIGNER_ISSUERS`：完整 X.500 issuer；可用一个共享
  pin，或按签名者顺序逐项配置。
- `DEFENSE_TRACKER_EXPECTED_SIGNER_ROOT_SHA256`：根证书 DER SHA-256；可用一个
  共享 pin，或按签名者顺序逐项配置。
- DigiCert KeyLocker 还必须配置
  `DEFENSE_TRACKER_DIGICERT_CERT_FILE_SHA256`，并在签名前复核公开证书文件的
  完整 SHA-256。Azure Artifact Signing 不读取 DigiCert 文件。

轮换时先在受保护环境中加入新旧两个有序身份，重新通过候选与稳定版门禁，
再删除旧身份。不得仅添加一个新 CN，也不得使用从候选资产自动提取的哈希更新
受保护配置。

稳定版发布对本地候选、Draft、公开发布后的远端 API digest 和重新下载字节执行
固定六资产名称、长度及 SHA-256 复核；公开后在检查 `immutable=true` 前后各复核
一次。`v9-stable-release` concurrency 只串行化这个工作流，不会阻止具有
`contents:write` 的其他主体并发写 Release。

## 诚实边界

- GitHub 没有把“创建 Draft、校验、公开、观察 immutable”合并为一个仓库级原子
  事务；Draft 到公开之间仍存在窗口。仓库必须通过受保护 Environment、Tag/Release
  ruleset 和最小化 `contents:write` 确保唯一 writer，人工管理员在窗口内不得修改。
- 公开后复验可以发现 TOCTOU 差异，但无法安全替换已经 immutable 的资产；失败时
  必须保留证据、停止宣传，并用新补丁版本处理，不能移动 Tag 或覆盖资产。
- Subject、SPKI、issuer 和根证书 pin 证明预期证书身份，不替代 CA 吊销、可信时间戳、
  私钥托管审批或签名服务审计；这些外部条件任一不可用时仍须阻断稳定版。
- Authenticode 有效不等于 SmartScreen 已建立信誉，也不证明软件全部功能或生产 Portal
  已完成验收；桌面烟测和生产部署证据仍是独立门禁。
