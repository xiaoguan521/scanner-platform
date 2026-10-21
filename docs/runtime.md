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

`--node-listen` 只接受明确的数字 IP 和端口，不能使用未指定地址、组播地址或主机名；私钥必须是 owner-only 普通文件。指定 `--node-tls-client-ca` 后，Server 会要求并校验节点客户端证书；Bearer 令牌仍保留，用于节点 ID 绑定和吊销。独立端口只路由 Worker、Updater 和 heartbeat 协议路径，强制 TLS 1.3，网页路径返回 404。Worker/Updater 的 `--server` 应指向 `https://` 节点地址，并使用各自的 owner-only 单令牌文件；需要自建 CA 时，额外传 `--node-ca-cert`，需要 mTLS 时再传成对的 `--node-client-cert` 与 `--node-client-key`。Server 收到 `SIGHUP` 会原子重载证书、客户端 CA 和节点令牌；新文件解析失败会保留上一份有效配置。客户端证书轮换后重启对应 Worker/Updater。节点生命周期首阶段由管理员显式注册/吊销，Server 根据心跳记录在线、离线和恢复事件并生成平台内离线通知。管理员可在节点清册为已登记节点签发一次性令牌；签发时原子更新 owner-only 注册表并写入审计，明文只返回一次，远程部署和证书自动签发仍由运维完成。

### 离线节点材料生成

`sec-node-provision` 可以在部署机上离线生成一套 Server/Worker/Updater 的 TLS 和令牌文件。它只接受明确的数字 Server IP、节点 ID 和节点类型，不连接网络；输出目录必须不存在，已有文件不会被覆盖。CA 私钥留在单独的 CA 目录，不会复制到节点材料目录；私钥和令牌文件使用 owner-only 权限，命令的 JSON 输出只包含路径和节点元数据，不包含密钥或令牌。

材料通过受信部署通道复制到节点后，可在目标机执行只读校验。校验不需要 CA 私钥，也不会连接 Server；它会检查 manifest、清单外文件、owner-only 目录/私钥/令牌权限、令牌注册表、证书链、证书与私钥匹配关系以及 Server IP SAN：

```bash
./dist/sec-node-provision --verify-dir /var/lib/scanner-platform/node-materials
```

校验成功只表示材料包适合交给服务管理器加载，不代表远程传输、服务编排、节点自动注册或 Linux 围栏已完成验收。

首次建立专用 CA：

```bash
make build
./dist/sec-node-provision \
  --output-dir /var/lib/scanner-platform/node-materials \
  --ca-dir /var/lib/scanner-platform/ca \
  --generate-ca \
  --server-ip 192.0.2.10 \
  --server-port 8443 \
  --node worker-node-1=worker \
  --node updater-primary=updater
```

增加节点时复用已有 CA，省略 `--generate-ca` 并使用新的输出目录。已有节点的本地证书轮换可以直接在原材料目录执行：

```bash
./dist/sec-node-provision \
  --rotate-dir /var/lib/scanner-platform/node-materials \
  --ca-dir /var/lib/scanner-platform/ca \
  --valid-for 90d
```

轮换前会校验 manifest、文件权限、节点清单和 CA；随后在同一父目录生成完整新目录并做目录级替换，旧的 `node-tokens`、节点令牌和 manifest 原样保留。轮换不会自动传输文件或重启进程：管理员应通过 owner-managed 部署通道分发新证书/私钥，Server 发送 `SIGHUP`，Worker/Updater 重启后才会加载新客户端证书。CA 私钥只用于签发和轮换，不部署到 Server/Worker/Updater。工具不会自动登记节点、复制文件或启动服务；管理员仍需先在节点清册登记节点，再按部署审计流程分发材料。

## Linux 围栏 Worker

Linux 生产执行器需要使用 `sec-worker --fence --once --fence-parent-netns-fd <fd> --fence-cgroup-root <dir>`，并由可信启动器在进入专属 network namespace 前打开父 namespace 文件句柄。该模式会在当前 namespace 安装精确 nftables 默认拒绝规则，随后以 uid 10001、无 capabilities、`no_new_privs` 的子进程执行任务；每个任务还必须加入部署提供的 cgroup v2 子组并使用 `cgroup.kill` 清理后代。Server 地址自动加入白名单，其他 DNS/Harbor/制品库地址必须逐项通过 `--fence-infra IP:port` 提供。每个 Worker 只处理一个任务并退出，不能在同一 namespace 复用规则。详细前置条件、SSH 文件权限和隔离验收见 [Linux Worker 围栏运行约定](worker-fence.md)。本地回环模式和 macOS/Windows 仍只提供应用层范围校验，不能替代 Linux namespace 验收。
