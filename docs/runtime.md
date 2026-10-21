# 本地运行
1. 在仓库根目录运行 `make dev`（Go、Node.js/npm、curl）；Server、Worker、Updater 会一起启动。
2. 打开 http://127.0.0.1:8080，首次创建管理员，已有账号直接登录。
3. 在资产页录入数字 IP 和端口，标记需要跳过的端口；任务页可立即运行或设置定时，发现项页查看结果；`make engines` 准备引擎后可选择真实扫描。
4. 节点页可导入/下载规则 ZIP 并激活或显式回滚；按 Ctrl+C 停止，数据留在 `runtime/platform.db`；详见 [本地功能](local-functions.md)。

## PostgreSQL 运行时

PostgreSQL 运行时必须显式选择，不会从 SQLite 自动复制数据或回退到第二个数据库。先准备 owner-only DSN 文件并执行迁移，然后初始化管理员：

```bash
POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" make migrate-postgres
POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" ./dist/sec-server \
  --storage postgres --postgres-dsn-file "$PWD/runtime/postgres/dsn" \
  --init-admin pgadmin --password-file /path/to/owner-only-password
POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" make dev-postgres
```

`make dev-postgres` 让 Web、Worker、Updater 共用 PostgreSQL Server；页面的 `/readyz` 会返回 `mode: postgres`。当前 PostgreSQL 运行时已覆盖账号、资产、授权、任务队列/投影、Worker 租约与进度、发现项、发现项处置扩展、报告、规则目录同步、规则作业队列、定时任务、通知/安全摘要 Webhook、系统设置、扫描策略、扫描方案、自定义规则、知识库和审计/隔离清册核心闭环。Worker 领取自动任务时仍按任务冻结版本和规则就绪状态检查；部分非核心系统管理端点仍会明确返回后端能力不可用，不能当作已实现。

## 独立节点 HTTPS 通道

网页和控制面默认只监听数字回环地址。多进程或生产部署时，可为 Worker/Updater 单独开启 HTTPS 节点端口：

```text
sec-server --listen 127.0.0.1:8080 \
  --node-listen 192.0.2.10:8443 \
  --node-tls-cert /path/to/node-cert.pem \
  --node-tls-key /path/to/node-key.pem \
  --node-tls-client-ca /path/to/node-client-ca.pem \
  --node-token-file /path/to/node-tokens
```

`--node-listen` 只接受明确的数字 IP 和端口，不能使用未指定地址、组播地址或主机名；私钥必须是 owner-only 普通文件。指定 `--node-tls-client-ca` 后，Server 会要求并校验节点客户端证书；Bearer 令牌仍保留，用于节点 ID 绑定和吊销。独立端口只路由 Worker、Updater 和 heartbeat 协议路径，强制 TLS 1.3，网页路径返回 404。Worker/Updater 的 `--server` 应指向 `https://` 节点地址，并使用各自的 owner-only 单令牌文件；需要自建 CA 时，额外传 `--node-ca-cert`，需要 mTLS 时再传成对的 `--node-client-cert` 与 `--node-client-key`。Server 收到 `SIGHUP` 会原子重载证书、客户端 CA 和节点令牌；新文件解析失败会保留上一份有效配置。客户端证书轮换后重启对应 Worker/Updater。节点生命周期首阶段由管理员显式注册/吊销，Server 根据心跳记录在线、离线和恢复事件并生成平台内离线通知；自动签发、部署编排和管理 UI 仍待后续。
