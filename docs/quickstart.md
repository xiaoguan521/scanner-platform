# 本地快速开始

在仓库根目录运行 `make dev`，打开 http://127.0.0.1:8080，首次设置管理员，已有账号直接登录。Server 同时提供网页和现有 API，不再需要另起 Vite 或使用另一套账号数据库。

当前不再提供演示种子或浏览器 mock 数据。启动 Server 后请在资产页登记隔离靶机，完成端口授权，再从扫描任务页创建真实 SSH/自动综合扫描；默认 SQLite 模式下任务、发现项和审计记录均来自 `runtime/platform.db`。

默认 SQLite 为 `runtime/platform.db`，规则目录为 `vuln-data/`；两者均不会提交到 Git。初始管理员也可通过 `sec-server --init-admin admin` 在终端交互创建。旧的 `--dev-ui` 是统一 Server 的兼容参数；使用旧账号库时，请显式传入该库的绝对 `--db` 路径，程序不会擅自复制其他位置的账号或资产。

多进程节点的本地认证可显式启用：Server 的 `--node-token-file` 使用 owner-only 文件，每行写一个 `node-id=token`；Worker/Updater 分别使用自己的 `--node-token-file` 单令牌文件。令牌至少 16 个可打印 ASCII 字节，服务端会同时校验 `X-Node-ID`、Bearer 令牌和请求体中的节点 ID。生产部署可在 Server 上增加 `--node-listen 192.0.2.10:8443 --node-tls-cert <证书PEM> --node-tls-key <owner-only私钥PEM> --node-tls-client-ca <客户端CA PEM>`，并让 Worker/Updater 的 `--server` 指向该 HTTPS 地址；客户端用 `--node-ca-cert` 信任服务端 CA，用 `--node-client-cert`/`--node-client-key` 提供 mTLS 身份。Server 收到 `SIGHUP` 会原子重载证书、客户端 CA 和节点令牌；无效替换保留上一份有效配置。独立节点端口只暴露节点协议，网页仍留在回环端口。管理员可在节点页登记节点、签发一次性令牌并查看生命周期；令牌只在签发响应中显示一次，随后由管理员写入节点 owner-only 文件。心跳超时会生成离线通知，恢复后记录恢复事件。自动远程部署、证书自动签发和客户端自动注册仍待后续。当前回环开发模式仍可不配置令牌。

需要使用 PostgreSQL 时，先执行 `POSTGRES_DSN_FILE=/path/to/owner-only.dsn make migrate-postgres`，再执行 `sec-server --storage postgres --postgres-dsn-file /path/to/owner-only.dsn --init-admin <用户名> --password-file /path/to/owner-only-password`，最后使用 `POSTGRES_DSN_FILE=/path/to/owner-only.dsn make dev-postgres`。这是独立数据源，SQLite 资产和账号不会自动迁移；`/readyz` 可确认当前模式。

资产/端口、跳过标记、任务、定时、规则包和验证命令详见 [本地功能](local-functions.md)。运行 `make engines` 安装固定的 Nuclei/Trivy 与默认规则；需要 ZAP 被动检查时再运行 `make engines-zap`。详见 [引擎操作指南](engines.md)；真实服务器探测另行验证。

## 资产画像与报告

进入“资产”登记明确授权的数字 IP,填写业务组与责任人。进入“扫描任务”选择资产与自动扫描,选择常见、自定义、已登记或全端口以及排除项;全端口须在提示预计耗时和影响后确认。只在隔离实验目标上验收。ICMP 未响应表示未知,不妨碍后续 TCP 检测。

任务完成后查看资产画像、服务和登录入口;在发现项中按检测方式、置信度查看,版本推断表示未做原理验证。“知识库”支持规范 JSON 的公开数据导入,“节点/设置”维护常见端口与系统排除。“报告”选择范围、模板和 HTML/Excel/Word/CSV/JSON,生成后等待就绪并下载。失败项可使用原快照重试。弱口令处显示未启用。具体操作与边界见 [报告使用说明](product/report-usage.md),逐项验收见 [报告清单](product/report-checklist.md)。
