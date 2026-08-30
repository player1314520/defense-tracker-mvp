# V9 稳定版证书与发布原子性边界

稳定版只接受受保护 `main` 中 `release/publisher-policy.json` 及其精确 SHA-256；
不得从待发布二进制、证书 `CN`、本机信任库、可变 Environment 变量或 Release
清单反推 Publisher 信任。当前 policy 为 `pending`，因此正式签名会故意阻断。

Azure Artifact Signing 绑定已提交的 Publisher、完整 Subject/issuer/root、
endpoint/account/profile、code-signing EKU、Public Trust EKU 和 durable identity
EKU。Azure 的短期叶证书会轮换，叶 SPKI 只记录为证据，不进入 allow decision。
DigiCert KeyLocker 才要求有序 Subject/SPKI pin，并固定 issuer/root、canonical
SM host、key alias 和公开 certificate-file SHA-256。任何 runtime 值与 committed
policy 不一致，都必须在读取 API key、客户端证书或执行 SignTool 之前 fail-closed。

Azure 轮换依靠持久身份与 EKU，不需要把新旧短期叶 SPKI 加入 allowlist。
DigiCert 轮换则先提交并复核新的完整证书/身份 pin，再运行候选与稳定版门禁；
不得仅添加新 CN，也不得从候选资产自动提取哈希回写策略。

稳定版发布对本地候选、Draft、公开发布后的远端 API digest 和重新下载字节执行
固定六资产名称、长度及 SHA-256 复核；公开后在检查 `immutable=true` 前后各复核
一次。工作流拆成只读 `verify-promotion` 与唯一具有 `contents:write` 的
`publish-stable-release`，但 concurrency 仍只串行化这个工作流，不会阻止其他
具有仓库写权限的主体并发写 Release。

## 诚实边界

- GitHub 没有把“创建 Draft、校验、公开、观察 immutable”合并为一个仓库级原子
  事务；Draft 到公开之间仍存在窗口。仓库必须通过受保护 Environment、Tag/Release
  ruleset 和最小化 `contents:write` 确保唯一 writer，人工管理员在窗口内不得修改。
- 公开后复验可以发现 TOCTOU 差异，但无法安全替换已经 immutable 的资产；失败时
  必须保留证据、停止宣传，并用新补丁版本处理，不能移动 Tag 或覆盖资产。
- Provider-specific Publisher、Subject/issuer/root、EKU，以及 DigiCert SPKI/文件
  pin 约束预期身份，但不替代 CA 吊销、可信时间戳、私钥托管审批或签名服务审计；
  这些外部条件任一不可用时仍须阻断稳定版。
- Authenticode 有效不等于 SmartScreen 已建立信誉，也不证明软件全部功能或生产 Portal
  已完成验收；桌面烟测和生产部署证据仍是独立门禁。
