# V9-P7 可靠性、安全与正式发布

完成日期：2026-07-25（本地发布）

## 本批交付

- 渐进分层
  - V9 新功能继续保持 Blueprint → service → repository/domain 分层，没有继续
    向旧 `app.py` 堆业务路由，也没有冒险一次性重写旧兼容接口。
  - 云端入口继续保持独立 `v9_cloud.py` 与最小 `v9/cloud.py` allowlist。
- 备份与恢复
  - `v9/backup.py` 使用 SQLite 在线 backup API，写入临时文件、执行
    `PRAGMA integrity_check` 后再原子提升。
  - 备份和恢复默认拒绝覆盖已有目标；Owner/Admin 可通过本机 loopback API
    生成密文数据库备份，恢复保持离线操作。
  - 本机已生成一份 99,721,216 字节的 P7 前密文数据库备份。
- 故障恢复
  - 云拉取不可用时不推进入站游标；已确认上传与未应用拉取游标分离。
  - 模拟磁盘满时既有记录版本/正文不变。
  - 错误本地 master key 明确失败，不返回伪解密内容。
  - 既有测试继续覆盖 RSS/网页抓取超时、本地 AI 超时和写作第二阶段失败后
    首稿保留。
- 日志与诊断
  - 默认日志过滤器脱敏 Bearer、OpenAI 风格 key、API key、app secret、
    access/verify token、恢复码和配对码。
  - 诊断 ZIP 只包含平台版本、按类型/状态计数、配置“是否存在”、日志数量/
    总字节和发布元数据；不包含正文、密文、日志内容、凭据、密钥、附件、
    用户名、主机名或本地路径。
- staging
  - 新增 `deploy/docker-compose.staging.yml`，只绑定
    `127.0.0.1:8088`，启用只读根文件系统、临时 `/tmp`、drop capabilities、
    no-new-privileges 和健康检查。
  - 云镜像 `/data` 由非 root 用户持有。

## 验证记录

- Python：243 项全量通过。
- JavaScript：15 项全量通过。
- 浏览器：
  - 主 V9 页面识别到 11 屏，1440×900 与 390×844 均无横向溢出；
  - 诊断 API 返回 HTTP 200、`application/zip`；
  - console 0 error、0 warning；V9 situation/rules/diagnostics 均 HTTP 200。
- 截图：`docs/release-evidence/P7/main-1440.png`、
  `docs/release-evidence/P7/main-390.png`。
- staged gitleaks：0。
- 标准桌面发布门禁通过：共享 Python 指纹不变、staging 递归秘密扫描、
  PE/时间戳、EXE 启动、HTTP/V9/窗口标题和原子提升全部成功。
- 最终 EXE：12,352,258 字节；SHA-256
  `162EC648CF3DC2FDBD8F904EB6C9123D1396D9B3E52FE3E467A1D252C13F1A8B`。
- 发布清单：2832 个文件；提交
  `88d507fabf12117fb982f881bfe52aa0de88c9b3`。
- 正式 EXE 运行态：窗口标题正确，主页面 HTTP 200，V9 总览 + 10 个导航屏
  完整加载；诊断 ZIP HTTP 200、`application/zip`、1369 字节。
- 打包运行态发现并修复 PowerShell UTF-8 BOM 清单兼容问题，新增回归测试后
  重新完成全量测试与正式构建。

## 诚实边界

1. 当前机器没有 Docker，因此 staging compose 仅完成静态门禁和单元测试，
   没有实际启动容器；不能表述为 Docker 运行验证通过。
2. 旧 `app.py` 仍包含大量历史功能；本轮只保证新 V9 功能按分层模块增长，
   尚未完成全部旧路由迁移。
3. EXE 尚未 Authenticode 签名，Windows 仍可能显示未知发布者。
4. 备份数据库虽不含业务明文，但包含租户/设备元数据和由本地 master key
   加密的 local secrets；仍应按敏感文件保护。
5. 真实 Supabase/Railway/飞书 staging 未获确认，生产 JWT/RLS、PKCE 回调、
   多实例同步和飞书日志仍未远程验收。
6. 被撤销设备的历史离线明文无法远程抹除；恢复码与全部有效设备同时丢失时
   组织数据不可恢复。
