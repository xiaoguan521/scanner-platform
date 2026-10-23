# 部署手册

本文是平台部署入口。它区分三种场景：

| 场景 | 用途 | 当前结论 |
| --- | --- | --- |
| `make dev` | 本地开发、SQLite、隔离靶机验证 | 可直接使用 |
| `make dev-postgres` | 本地或隔离环境验证 PostgreSQL 控制面 | 可直接使用，需显式选择 |
| `deploy/compose.production.yaml` | 生产部署输入和静态安全门禁 | 可生成配置并校验；真实生产运行仍需完成运行态验收 |

**只想尽快在一台内网 Linux 服务器上用起来？** 用一键脚本：`fetch_release.sh` 下载并校验发布包和漏洞库，`sudo ./install.sh` 安装为 systemd 服务，`scanctl` 负责日常管理，见 [一键部署](../docs/deploy-quickstart.md)。本手册其余部分是手工步骤和生产集群部署。

本手册不提供默认账号、密钥、令牌、真实资产或真实扫描目标。所有密码、证书、令牌和 DSN 都必须由部署人员通过 owner-only 文件或 Docker secrets 提供。

## 1. 部署前准备

### 1.1 软件要求

- 本地模式：Go、Node.js/npm、Python 3 和 `curl`。
- PostgreSQL 模式：PostgreSQL 16 或兼容版本，以及 owner-only DSN 文件。
- Compose 模式：Docker Engine、Docker Compose v2 和 BuildKit。
- Linux 围栏 Worker：Linux、nftables、cgroup v2、`setpriv` 和允许创建 network namespace 的运行时权限。

先在仓库根目录完成基础检查：

```bash
make build
make lint
make test
```

### 1.2 目录和文件边界

| 路径 | 作用 | 说明 |
| --- | --- | --- |
| `runtime/` | SQLite、日志、输入、报告 | Git 忽略；不要提交内容 |
| `vuln-data/` | 当前规则包 | Worker 只读，Updater 唯一写入者 |
| `dist/` | 本地二进制 | Git 忽略 |
| `deploy/secrets/` | Compose secrets 来源 | 仅部署机保存，禁止提交 |
| `production.env` | 镜像 digest | owner-managed 文件，禁止提交 |

不要把 DSN、密码、私钥、节点令牌放入环境变量、命令日志、镜像或 Git。节点协议令牌使用单独文件，不能与 Server 的令牌注册表混用。

## 2. 本地 SQLite 部署

这是默认开发模式，适合先验证页面和隔离靶机扫描链路。

```bash
make engines             # 准备固定版本 Nuclei、Trivy 和默认规则
make dev                 # 启动 Server、Worker、Updater
```

打开 `http://127.0.0.1:8080`。首次在页面创建管理员；已有账号直接登录。启动后检查：

```bash
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
```

默认数据写入 `runtime/platform.db`。停止 `make dev` 后，SQLite 数据和日志仍保留在 `runtime/`。

Worker 需要 SSH 采集时，通过本地配置文件传入明确授权的 profile：

```bash
SCANNER_SSH_CONFIG=/path/to/owner-only-ssh.json make dev
```

本地模式只接受页面登记并明确授权的数字 IP 和端口。ICMP 无响应不会跳过 TCP 检查；全端口任务必须在页面完成二次确认。

ZAP 不是核心启动依赖。核心扫描只需 `make engines`；只有明确需要被动 HTTP 分析时才运行：

```bash
make engines-zap
```

Java 组件索引同样按需准备：

```bash
make engines-java
```

## 3. PostgreSQL 部署

PostgreSQL 必须显式选择，不会复制 SQLite 数据，也不会在 PostgreSQL 能力缺失时回退读取 SQLite。

### 3.1 准备 DSN 和管理员密码文件

DSN 和密码必须是 owner-only 普通文件，不能是符号链接或包含换行的多行文件：

```bash
chmod 600 /path/to/owner-only.dsn
chmod 600 /path/to/owner-only-admin-password
```

在隔离靶机环境中，项目提供的 `lab/orbstack-target/` PostgreSQL 仅用于测试，不是生产依赖。

### 3.2 迁移和初始化

```bash
POSTGRES_DSN_FILE=/path/to/owner-only.dsn make migrate-postgres

./dist/sec-server \
  --storage postgres \
  --postgres-dsn-file /path/to/owner-only.dsn \
  --init-admin admin \
  --password-file /path/to/owner-only-admin-password
```

### 3.3 启动 PostgreSQL 模式

```bash
POSTGRES_DSN_FILE=/path/to/owner-only.dsn make dev-postgres
```

确认 `/readyz` 返回 `mode: postgres`。PostgreSQL 模式覆盖账号、资产、授权、任务队列/投影、Worker 租约与进度、发现项、报告、规则同步、定时任务、通知、系统设置、扫描方案、自定义规则、知识库和审计核心闭环；部分非核心系统管理端点会明确返回能力不可用。

## 4. 生产镜像和 Compose

生产 Compose 不在运行时构建镜像，也不接受可变标签。先构建并推送三个 digest 固定的镜像：

```bash
docker buildx build --platform linux/amd64 --target server \
  --tag registry.example.invalid/scanner-platform-server:VERSION \
  --push -f deploy/Dockerfile .
docker buildx build --platform linux/amd64 --target worker \
  --tag registry.example.invalid/scanner-platform-worker:VERSION \
  --push -f deploy/Dockerfile .
docker buildx build --platform linux/amd64 --target updater \
  --tag registry.example.invalid/scanner-platform-updater:VERSION \
  --push -f deploy/Dockerfile .
```

将镜像仓库返回的完整 `@sha256:...` 写入 `production.env`。不要把 `production.env.example` 中的占位 digest 当作可运行配置：

```bash
cp deploy/production.env.example production.env
# 编辑 production.env，填入四个经过审批的 digest
chmod 600 production.env
```

### 4.1 Compose secrets

在 `deploy/secrets/` 创建以下 owner-managed 文件：

| 文件 | 用途 |
| --- | --- |
| `db_password` | PostgreSQL 密码 |
| `postgres_dsn` | Server 连接 PostgreSQL 的 DSN，主机名应指向 Compose 服务 |
| `server_cert.pem` / `server_key.pem` | Server 独立节点 HTTPS 证书和私钥 |
| `node_client_ca.pem` | Worker/Updater 客户端 CA |
| `node_tokens` | Server 节点 ID 与令牌注册表 |
| `worker.token`、`updater.token` | 对应节点的单令牌 |
| `worker-client-cert.pem` / `worker-client-key.pem` | Worker mTLS 材料 |
| `updater-client-cert.pem` / `updater-client-key.pem` | Updater mTLS 材料 |
| `bundle-signing-public-key.pem` | 规则包 Ed25519 公钥 |

```bash
chmod 700 deploy/secrets
chmod 600 deploy/secrets/*
```

Server 证书必须包含 Compose Worker 网络使用的数字 SAN `172.30.1.10`；证书和节点配置中的地址必须保持一致。证书、令牌和 CA 私钥的生成应使用离线材料工具，不能手工复制到镜像。

### 4.2 静态门禁和配置检查

启动任何生产服务前先执行：

```bash
set -a
. ./production.env
set +a

DEPLOY_COMPOSE_FILE=deploy/compose.production.yaml make verify-deploy
docker compose --env-file ./production.env \
  -f deploy/compose.production.yaml config --quiet
```

门禁会拒绝：缺失或非 digest 镜像、`build:`、host namespace、`privileged`、危险 capability、Worker 可写规则目录、Worker/Updater/PostgreSQL 宿主端口发布、明文敏感环境变量、缺少显式网络和非 owner-managed secret。

### 4.3 首次启动顺序

生产 Compose 文件使用 PostgreSQL 服务名作为网络内地址。建议按以下顺序执行：

```bash
# 先启动数据库并等待健康检查
docker compose --env-file ./production.env \
  -f deploy/compose.production.yaml up -d postgres
docker compose --env-file ./production.env \
  -f deploy/compose.production.yaml ps

# 使用同一 Server 镜像执行迁移；该命令不会启动常驻 Server
docker compose --env-file ./production.env \
  -f deploy/compose.production.yaml run --rm --no-deps sec-server \
  --migrate-postgres --postgres-dsn-file /run/secrets/postgres_dsn

# 初始化管理员；命令会在终端交互读取密码，不把密码写入命令行
docker compose --env-file ./production.env \
  -f deploy/compose.production.yaml run --rm --no-deps sec-server \
  --storage postgres --postgres-dsn-file /run/secrets/postgres_dsn \
  --init-admin admin

# 启动 Server、Updater 和 Worker
docker compose --env-file ./production.env \
  -f deploy/compose.production.yaml up -d
```

Web 端口只发布到本机回环地址：

```bash
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
docker compose --env-file ./production.env \
  -f deploy/compose.production.yaml ps
docker compose --env-file ./production.env \
  -f deploy/compose.production.yaml logs --tail=100 sec-server sec-updater sec-worker-1
```

`/readyz` 只表示控制面已就绪，不代表规则库、Worker 围栏或扫描引擎已就绪。登录页面后，还需要检查节点清册、规则版本和任务领取状态。

## 5. 多节点材料和部署

### 5.1 离线生成材料

`sec-node-provision` 只在部署机本地运行，接受明确的数字 Server IP、节点 ID 和角色，不发现主机、不连接网络。先构建工具：

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

完整材料目录只能留在受信部署机。按角色拆包，避免把 Server 私钥和其他节点令牌复制到 Worker/Updater：

```bash
./dist/sec-node-provision \
  --split-from /var/lib/scanner-platform/node-materials \
  --split-output-dir /var/lib/scanner-platform/packages/worker-node-1 \
  --package-role worker --node-id worker-node-1

./dist/sec-node-provision \
  --split-from /var/lib/scanner-platform/node-materials \
  --split-output-dir /var/lib/scanner-platform/packages/updater-primary \
  --package-role updater --node-id updater-primary

./dist/sec-node-provision \
  --split-from /var/lib/scanner-platform/node-materials \
  --split-output-dir /var/lib/scanner-platform/packages/server \
  --package-role server
```

传输后先做离线预检：

```bash
./dist/sec-node-provision --verify-dir /var/lib/scanner-platform/packages/worker-node-1
```

预检会拒绝清单外文件、权限过宽、证书链错误、证书与私钥不匹配、节点角色不匹配和错误的数字 Server IP SAN。预检成功不代表服务已经启动或节点已经登记。

### 5.2 显式 SSH 发布

`sec-node-deploy` 默认只生成计划。只有确认目标数字 IP、SSH 端口、固定 `known_hosts`、owner-only SSH 私钥、绝对远程目录和服务名后，才使用 `--dry-run=false`：

```bash
./dist/sec-node-deploy \
  --package-dir /var/lib/scanner-platform/packages/worker-node-1 \
  --target-ip 192.0.2.20 --ssh-port 22 --user scanner \
  --identity-file /etc/scanner-platform/deploy-key \
  --known-hosts-file /etc/scanner-platform/known_hosts \
  --remote-dir /var/lib/scanner-platform/node-materials \
  --service sec-worker --dry-run=false
```

首次发布拒绝覆盖已有远程目录。替换已有材料必须显式增加 `--rotate-existing`；工具会保留唯一回滚目录，只有发布和 `systemctl is-active` 检查都成功才清理旧材料。远程传输失败、服务重启失败或恢复失败都必须人工处理，不能把计划输出当成部署成功。

### 5.3 节点登记和令牌轮换

材料部署完成后，在平台节点页登记节点，再签发一次性令牌。令牌只在签发响应中出现一次，随后写入节点 owner-only 文件。节点吊销会立即拒绝后续协议请求；心跳超时会生成离线事件和平台内通知。

本地材料轮换：

```bash
./dist/sec-node-provision \
  --rotate-dir /var/lib/scanner-platform/node-materials \
  --ca-dir /var/lib/scanner-platform/ca \
  --valid-for 90d
```

轮换不会自动传输文件或重启服务。分发新材料后，Server 发送 `SIGHUP`，Worker/Updater 重启并检查新证书；失败时保留上一份有效配置。

## 6. Linux 围栏 Worker

生产 Linux Worker 必须由可信启动器和一次性 supervisor 拉起：

```bash
sec-worker-supervisor \
  --launcher /opt/sec/bin/sec-fence-launcher \
  --worker /opt/sec/bin/sec-worker \
  --restart-delay 2s --max-backoff 60s -- \
  --server https://192.0.2.10:8443 \
  --node-token-file /run/secrets/worker-token \
  --fence-cgroup-root /sys/fs/cgroup/sec-worker \
  --fence-infra tcp://192.0.2.53:53 \
  --bin-dir /opt/sec/bin --rules-dir /vuln-data \
  --runtime-dir /runtime/worker --inputs-dir /runtime/inputs
```

启动器负责专用 network namespace、父 namespace fd 和强制的 `--fence --once`；Worker 负责再次校验任务范围、规则和时间窗。引擎以非 root、无 capabilities、`no_new_privs` 运行；规则目录只读，runtime/input 目录独立可写。`--fence-infra` 只能逐项列出明确的 `IP:port`，不能填写网段。

macOS/Windows 本地模式只提供 Go 层范围校验，不能作为 Linux namespace、cgroup、nftables 或范围外 DROP 的生产证据。

## 7. 升级、备份和回滚

1. 先备份 PostgreSQL、报告卷、规则卷和当前生产环境文件；备份中不得包含仓库提交的密钥。
2. 构建并扫描新镜像，记录新的 digest；不要覆盖旧 digest。
3. 先运行 `make verify-deploy` 和 `docker compose config --quiet`。
4. 在维护窗口执行 PostgreSQL 迁移，再按 `postgres → Server → Updater/Worker` 顺序滚动更新。
5. 检查 `/readyz`、节点心跳、规则版本、任务领取和安全日志，再开放新任务。
6. 发现启动或迁移异常时，停止新任务并恢复上一组镜像 digest；不要删除仍被任务引用的规则版本或报告卷。

规则版本切换仍由 Updater 完成：签名、文件哈希、引擎兼容矩阵和防回滚检查全部通过后才能激活。历史任务使用创建时冻结的规则版本。

## 8. 验收清单

部署后至少完成以下检查，并把输出写入受限的运维记录，不要提交到仓库：

- [ ] `healthz` 返回存活，`readyz` 返回正确存储模式。
- [ ] Web 只绑定回环；节点 API 只在明确的 HTTPS 地址监听。
- [ ] PostgreSQL 迁移版本连续，备份和恢复演练有记录。
- [ ] Server、Worker、Updater 节点已登记，心跳状态为 `ONLINE`。
- [ ] 当前规则版本已验签且 `engineValidated=true`。
- [ ] 隔离目标上完成资产登记、授权、SSH 采集、Trivy/Nuclei 只读扫描和结果查看。
- [ ] Linux 环境完成 namespace、uid/gid、capability、`no_new_privs`、cgroup 清理和范围外 DROP 验收。
- [ ] 生产 Compose 没有 `hostNetwork`、`privileged`、危险 capability、可写 `/vuln-data` 或宿主端口误发布。

隔离实验回归需要显式声明环境：

```bash
LAB_ENV=isolated make test-lab
```

`make test-lab` 不能对非实验目标运行，也不能替代生产部署验收。发布级范围抓包、远程 service manager、自动证书签发、集群工作负载、真实服务器/国产系统覆盖目前仍是待验收项。

## 9. 相关文档

- [本地快速开始](../docs/quickstart.md)
- [运行说明](../docs/runtime.md)
- [Linux Worker 围栏](../docs/worker-fence.md)
- [引擎接入指南](../docs/engines.md)
- [OpenAPI 契约](../docs/api/openapi.yaml)
- [验证记录](../docs/verification-log.md)
- [架构文档](../docs/architecture-v3.2.md)
