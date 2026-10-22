# Verification log

## 2026-10-22：PostgreSQL 隔离仓储全量回归复核

- 确认 `scanner-lab-postgres-postgres-1` 健康、DSN 文件指向本机回环映射后，重新运行 `POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" go test -tags lab -race ./internal/repo -count=1`，114 秒完成并通过。
- 本次只使用隔离 PostgreSQL 夹具，不连接业务服务器，不输出 DSN、资产、漏洞或扫描结果；此前无输出是完整仓储 race 回归耗时较长，不是数据库停服。

## 2026-10-22：规则包引擎兼容矩阵

- manifest 新增 `engine_compatibility`。本地 `package_rules.py` 和 `--prepare-engines` 写入 Nuclei 3.11.1、Trivy 0.76.0 的精确版本范围；Trivy 同时写入主库 schema，包含 Java 数据库时写入 Java schema。
- Updater 导入后对清单结构、版本范围和 metadata schema 做只读校验，`engineValidated` 只有全部通过才为 true；普通激活和 Worker 执行都拒绝缺少/不匹配矩阵的版本。历史包仍可展示但不能启用。
- 新增精确版本、越界、主库 schema、Java schema 和格式失败测试；待在包含实际 Trivy/Java 数据库的隔离包上运行引擎回归。
- 已运行 `make test`（Go race 与 37 个 Python 测试）、`make lint`、`make build`、`make test-local`、`make verify-flags`、前端 38 项契约测试、前端生产构建、OpenAPI/Workflow YAML 解析和 `git diff --check`；本次兼容夹具使用临时 Trivy/Java metadata 与数据库文件，不包含真实漏洞数据。

## 2026-10-21：PostgreSQL 隔离仓储回归

- 使用当前运行时的时间基准修正 `postgres_queue_lab_test.go` 的租约夹具，避免固定日期被数据库当前时间判定为过期。
- `POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" go test -tags lab -race ./internal/repo` 通过（完整仓储隔离回归，未输出 DSN、资产或结果数据）。

## 2026-10-21：生产镜像与 Compose 部署契约

- 新增 `deploy/Dockerfile` 的 `server`、`worker`、`updater` BuildKit targets：Go 服务、Server UI、SHA-256 固定的 Nuclei/Trivy 和 Linux `nft`/`setpriv` 运行依赖在镜像阶段构建；运行目标不携带数据库凭据或节点秘密。
- 新增 `deploy/compose.production.yaml` 与 `production.env.example`。Compose 不含 `build:`，镜像必须使用 `@sha256`，Server Web 端口只绑定回环地址，节点 API 只在明确的 Worker 网络地址监听，Worker 规则目录只读、runtime 独立可写，secret 文件和 cgroup 挂载均显式声明。
- `scripts/verify_compose_security.py` 现在按 Compose 语义把短 secret target 规范化为 `/run/secrets/...`；已用临时 fixture secret 文件和四个 digest 形式的测试镜像引用运行 `DEPLOY_COMPOSE_FILE=deploy/compose.production.yaml make verify-deploy` 通过，并清理 fixture。新增短 target 单元测试；没有启动或拉取任何部署服务。
- `docker buildx build --check --target server -f deploy/Dockerfile .` 通过；首次实际构建曾因 GitHub 连接读超时退出，加入有界重试后已在 OrbStack arm64 构建器通过 `--network=host --load` 构建 `server`、`worker`、`updater` 三个 target。构建阶段校验了 Nuclei/Trivy 锁定 SHA-256，且三个本地镜像均成功导出；镜像尚未推送到生产仓库。
- 使用上述三个本地镜像的实际 image ID 组装临时 digest 引用，并配合临时 secret fixture 运行 `make verify-deploy` 与 `docker compose ... config --quiet`，两项均通过；fixture 已清理，未启动生产服务。
- 真实镜像推送、生产证书/令牌、远程节点服务管理、Linux namespace/cgroup/DROP 抓包仍需在隔离部署环境验收。

## 2026-10-21：节点材料远程轮换与失败恢复计划

- `sec-node-deploy` 新增显式 `--rotate-existing` 模式。首次安装仍拒绝覆盖已有远程目录；轮换模式先把既有目录移到唯一回滚目录，再复制并只读预检角色包，发布后重启固定服务，只有重启成功才清理回滚目录。
- 发布或服务重启失败时，计划执行固定的远端恢复和服务重启；恢复失败会包含在错误中并保留回滚目录。计划只接受数字 IP、固定 known_hosts、owner-only SSH 私钥、绝对路径和 allowlist 服务名，不生成、复制或记录 CA 私钥、节点令牌或主机发现结果。
- 新增安装发布守卫、轮换计划、重启失败回滚和恢复错误路径测试；已运行 `go test -race ./internal/deploy ./cmd/node-deploy`。真实 SSH 传输、systemd 服务和生产 Linux 围栏仍未在本批宣称通过。

## 2026-10-21：自动综合扫描阶段进度闭环

- Worker 现在按自动综合扫描阶段持续回报 `tcp_probe`、`service_identification`、`http_scan`、`ssh_collection`、`trivy_scan` 和 `application_scan` 的完成数/总数；单引擎任务统一回报 `engine_scan`。应用分析按成功完成的独立产物计数，SSH 采集失败不会误报完成。
- Server 继续使用既有 advisory progress 投影，不新增数据库表；SQLite 与 PostgreSQL 的进度边界保持一致，自动服务/HTTP 总数不得超过任务冻结的端口数，SSH/Trivy 为单步，应用分析最多 256 个输入。阶段排名拒绝回退或同阶段倒退。
- `/tasks` 清册与详情按阶段权重显示进度条和 `完成数/总数`，完成任务仍显示 100%；OpenAPI 阶段枚举已同步新增 `application_scan`。
- 新增仓储进度边界及 SQLite 实际更新测试；已运行 `go test -race ./internal/repo ./internal/executor ./internal/taskflow`，三包通过。尚未在真实靶机全端口任务中重新执行本轮 UI 进度回归；本轮未修改数据库结构、规则目录、SSH 配置或扫描目标。

## 2026-10-21：隔离 lab 总门禁与可选 ZAP

- `make test-lab` 原先无条件执行 ZAP；当前环境未安装可选 ZAP 时会把整套隔离门禁误判为失败。已让 Go loopback 引擎夹具与项目既有脚本保持一致：默认跳过 ZAP 并明确记录 `SKIP ZAP`，只有设置 `SCANNER_EXPECT_ZAP=1` 才要求 ZAP HTTP/HTTPS 两条用例。
- 使用 `LAB_ENV=isolated POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" make test-lab` 重新运行全仓 lab 测试通过；Nuclei、Trivy、SSH/输入隔离、规则和 PostgreSQL 夹具均通过，ZAP 因未安装按可选项跳过。另行运行 PostgreSQL 仓储 lab 全套测试也通过。
- 该回归只使用本机隔离夹具和临时测试数据，未修改主 SQLite 运行库、规则目录、SSH 配置或扫描目标；ZAP 仍需在需要纳入发布验收时显式安装并设置 `SCANNER_EXPECT_ZAP=1`。

## 2026-10-21：节点材料最小权限包与显式 SSH 部署计划

- `sec-node-provision` 新增角色拆包：从完整离线材料目录生成 Server、Worker 或 Updater 包。拆包前重新执行完整材料预检，输出目录采用 owner-only 临时目录和目录级 rename；Server 包不含客户端私钥，Worker/Updater 包只含本节点客户端证书、私钥和令牌，不携带其他节点材料。
- `--verify-dir` 现在识别角色包 manifest，按角色检查精确文件集、证书用途、节点身份、令牌格式、权限和清单外文件；旧版完整 manifest 仍保持兼容。新增测试覆盖成功拆包、令牌不进入 manifest、角色不匹配和最小文件集。
- 新增 `sec-node-deploy` 计划器和构建目标。它只接受数字 IP、owner-only SSH 私钥、固定 `known_hosts` 文件、绝对远程路径和 allowlist 服务名；默认 dry-run，显式执行才按“创建临时目录→复制角色包→远端预检→目录发布→重启服务”顺序调用 `ssh/scp`。预发布失败会清理暂存目录，发布或重启失败保留已发布材料并返回错误；命令不做主机发现、不使用本地 shell、不输出命令标准错误。
- 已运行 `go test ./internal/provision ./internal/deploy ./cmd/node-provision ./cmd/node-deploy`；真实远程传输、服务管理器、节点自动登记和生产 Linux 围栏仍未在本批宣称通过。

## 2026-10-21：节点材料传输后只读预检

- `sec-node-provision --verify-dir` 新增离线预检入口，不需要 CA 私钥、不连接 Server，也不修改材料目录。它严格校验 manifest、清单外文件、owner-only 目录/私钥/令牌权限、节点令牌注册表、证书链、证书与私钥匹配关系和数字 Server IP SAN。
- 失败路径覆盖清单外文件、私钥不匹配、令牌文件与注册表不一致以及目录权限过宽；成功结果只返回节点 ID、文件数和证书有效期，不回显令牌或密钥。新增 token 解析 fuzz 测试。
- `go test ./internal/provision ./cmd/node-provision` 已通过；完整 `make test`、`make lint`、`make build` 仍需在本批提交前运行。该预检不等同于远程传输、服务编排、自动节点注册或 Linux 围栏生产验收。

## 2026-10-21：围栏 DROP 计数进入任务回报与告警投影

- Worker 的 fenced adapter 现在把受信的 `fenceStatus=ENFORCED` 与 `dropCount` 送入任务回报；Server 对状态、计数上限和缺失状态做失败关闭校验。SQLite 任务详情和 PostgreSQL 任务安全投影均保存这两个字段，不新增数据库迁移。
- DROP 计数大于零时写入脱敏的 `fence_drop_observed` 审计事件，任务日志、任务详情和平台通知中心只显示静态提示与计数；不写入目标地址、规则、请求/响应或凭据。
- 新增 Worker、fenced adapter、SQLite 持久化/审计和输入校验测试；本记录只证明代码链路和单元测试，生产范围外发包抓包、部署告警和 Compose 网络约束仍待隔离部署验收。

## 2026-10-21：fenced Worker 一次性生命周期监督器

- 新增 `internal/supervisor` 重启策略和 Linux `cmd/worker-supervisor`。监督器只调用已固定的 `sec-fence-launcher`，不经过 shell；launcher 与 Worker 路径均要求绝对规范、普通文件、不可由 group/other 写入且父目录不可写。Worker 参数必须位于显式 `--` 后，并拒绝覆盖 fenced 模式边界。
- 正常的一次性任务退出使用固定延迟，连续失败使用有界指数退避；可用 `--max-restarts` 限制部署验收中的重启次数，SIGTERM/SIGINT 取消当前周期且不发起新周期。监督器没有数据库、规则库或扫描目标访问权。
- 新增策略、取消、失败退避、重启上限、路径权限和参数覆盖测试；`make build` 纳入 `sec-worker-supervisor`。该代码验证了进程生命周期边界，不替代生产 service manager 的 secret/证书/令牌编排、远程部署或范围外发包告警验收。

## 2026-10-21：Linux fenced Worker 可信启动器

- 新增 `cmd/fence-launcher`：仅 Linux 可用，要求 root 和绝对、非 group/other 可写的 Worker 可执行文件；启动前打开 `/proc/self/ns/net` 并校验 nsfs，使用 `CLONE_NEWNET` 创建专属 network namespace，以 fd 3 传递父 namespace，强制追加 `--fence --once --fence-parent-netns-fd=3`，拒绝调用方覆盖这些边界；父启动器退出时由 `Pdeathsig` 终止 Worker。
- `make build` 已纳入 `sec-fence-launcher` 和 `sec-worker-supervisor`；非 Linux 构建保留明确不可用入口。启动器和监督器不读取数据库、令牌或扫描结果，只负责 namespace 与进程生命周期边界。
- Linux arm64 特权容器验证通过：启动器运行独立 helper，子进程 network namespace 与容器父 namespace 不同，fd 3 保持 nsfs；Linux 启动器单元测试覆盖受保护参数覆盖、可执行文件权限和父 namespace 类型。该证据仍不等同于生产 Compose `hostNetwork`、真实 Worker 任务和部署 supervisor 验收。

## 2026-10-21：fenced Worker DROP 计数回报

- Linux fenced Worker 在应用 nftables 围栏后读取 `egress`/`forward` 默认 DROP 规则的内核 packet counter，任务结束时计算本次增量，并将 `fenceStatus=ENFORCED` 与脱敏的 `dropCount` 回传；计数读取失败、规则缺失、溢出或结果格式异常都会失败关闭，不把任务伪装成成功。
- 解析器只接受生成规则中同时包含 `counter` 与 `drop` 的表达式，限制 `nft -j` 输出大小，丢弃命令 stderr，不记录目标地址、请求或响应内容；Worker 安全日志仅记录计数数值，计数大于零时提升为 warning。
- 新增解析器正常/错误路径测试；在一次性 Linux arm64 特权实验容器中重新运行 `TestFencedCgroupKillsDescendants` 与 `TestFencedWorkerTask`，真实 `nft` 计数读取、setpriv 降权、cgroup 清理均通过。该证据仍未替代部署环境中的范围外发包实测、告警接入和 Compose `hostNetwork` 约束验收。

## 2026-10-21：fenced Worker cgroup v2 生命周期边界

- `internal/workerfence/cgroup_linux.go` 新增专用 cgroup v2 任务边界：只接受部署提供的绝对根目录，强制存在 `cgroup.controllers`、`cgroup.procs` 和 `cgroup.kill`，每个任务使用独立子 cgroup；加入失败或缺少 `cgroup.kill` 时在引擎启动前拒绝。
- fenced root 子进程在安装 nftables 前加入任务 cgroup，任务结束/取消/失败时使用内核 `cgroup.kill` 清理后代，再删除任务目录；root supervisor 会先回到父 cgroup，避免清理动作杀死自身。
- 单元测试覆盖根目录/路径越界、缺少 `cgroup.kill`、加入/kill 控制文件和清理；在一次性 Linux arm64 特权实验容器中，`TestFencedCgroupKillsDescendants` 与 `TestFencedWorkerTask` 均已通过，前者故意创建后代进程并验证内核 cgroup kill，后者实际创建临时 cgroup v2、完成 root 子进程加入、setpriv 执行和任务目录清理。该证据尚未覆盖范围外发包与告警链路或生产 Compose `hostNetwork` 约束。

## 2026-10-21：隔离引擎回归与可选 ZAP 行为

- `LAB_ENV=isolated make test-engines-local` 已通过：Nuclei 真实进程、Trivy 离线系统包/依赖/镜像归档、Java 归档、Go amd64/arm64 ELF、稳定去重、快照篡改拒绝、麒麟未适配拒绝和缺失输入失败路径均有回归证据。测试只创建本机回环 HTTP 夹具，不连接当前靶机或 PostgreSQL。
- 发现并修复测试入口问题：ZAP 按项目约定是可选引擎，未安装时默认跳过；设置 `SCANNER_EXPECT_ZAP=1` 才会要求 `make engines-zap` 和 Java 17+。本次环境输出 `SKIP ZAP`，不把可选引擎缺失误报为扫描任务失败。

## 2026-10-21：部署边界与当前运行契约

- `deploy/README.md` 已从占位说明更新为当前可运行模式和部署边界：SQLite/显式 PostgreSQL、本地节点 HTTPS、Linux `--fence --once` 以及规则目录/运行目录/令牌文件约束。
- 未新增生产 Compose 或镜像文件，避免把尚未完成的可信启动器、secret/certificate 编排和隔离 Linux 验收伪装成可上线配置。待验收项仍包括范围外发包与告警链路、降权属性、cgroup 后代回收、禁止 `hostNetwork`、备份恢复和远程部署。

## 2026-10-21：Linux Worker 围栏接入真实执行路径（代码回归）

- `internal/bootstrap` 已把 Linux `--fence` 模式接入现有 `taskflow.Worker` 的执行、端口探测和自动综合扫描回调。任务由 Server 固定为数字 IP 与端口后，root 阶段只生成精确 nftables 规则；应用成功后通过固定 `setpriv` 参数重新执行 `--fence-child`，子进程以 uid 10001、无 capabilities 和 `no_new_privs` 运行现有执行器。`--once` 强制每个专属 network namespace 只处理一个任务，避免复用旧规则。端口进度通过独立继承 fd 回传到现有 heartbeat，隐藏子进程入口还绑定了任务摘要 capability，避免伪造环境变量后改写任务。
- 离线 Trivy 任务不生成目标网络许可，只保留明确的控制面/基础设施白名单；Server 地址自动加入白名单，额外 DNS/制品库必须使用逐项 `--fence-infra IP:port`。主机名、CIDR、未指定地址和未知操作在子进程协议层拒绝。
- 新增围栏计划、离线任务、无解析目标、输入尾随数据和受限 argv 失败路径覆盖。已运行 `go test -race ./internal/bootstrap ./internal/workerfence`、`go vet ./internal/bootstrap ./internal/workerfence`、`GOOS=linux GOARCH=amd64 go build ./cmd/worker`、Linux bootstrap 测试二进制交叉编译和 `git diff --check`；未在 macOS 上伪造 Linux nftables 结果。
- 在一次性 OrbStack Linux 特权实验容器中安装临时 nftables，并运行 `pocs/01` 的 `TestIsolatedFenceInstall` 与 `TestFencedWorkerTask`：两个测试均通过。后者实际启动 Linux arm64 `sec-worker --fence-child`，验证新 network namespace、真实 nftables 配置、setpriv 子进程、任务摘要 fd capability 和端口进度 fd；任务目标仅为 namespace 内的 `127.0.0.1:1`，没有访问当前靶机或 PostgreSQL。该证据覆盖代码路径联调，不替代生产容器的 namespace、DROP 计数和后代回收验收。
- 新增降权硬闸后再次运行同一 Linux arm64 隔离实验：子进程实际 UID/GID 为 `10001`，`NoNewPrivs=1`，`CapInh/CapPrm/CapEff/CapBnd/CapAmb` 全为零；测试通过后才保留该路径。仍未把范围外发包、DROP 计数、cgroup 后代回收和 Compose `hostNetwork` 约束标记为生产验收。
- 仍待隔离 Linux 实验：真实父/子 network namespace、nftables DROP 计数、范围外发包、uid/capabilities/no-new-privs、SSH 文件对 uid 10001 的权限、cgroup 后代回收和禁止 `hostNetwork`。因此 PoC #1 和生产部署仍未验收。

## 2026-10-21：统一 API 错误契约与请求编号

- Server、节点协议和早期 scaffold 的 JSON 失败响应统一补充稳定 `code`、安全操作提示 `hint` 和服务端生成的 `request_id`；`X-Request-ID` 响应头与响应体保持一致。旧 `error` 字段保留为兼容别名，不含凭据、目标证据或引擎输出。
- 前端 API 客户端优先按 `code` 选择本地化文案，同时保留旧 `error` 响应兼容；`ApiRequestError` 暴露 code、hint 和 requestId，便于页面和日志关联。
- OpenAPI `APIError` 模型、`docs/api/error-codes.md`、产品现状和路线图已同步。
- 新增 `internal/api/errors_test.go`，覆盖错误结构、兼容别名、提示、响应头和嵌套处理器的请求编号稳定性。已运行：`make build`、`make lint`、`make test`（含 `go test -race ./...` 和脚本测试）、`go test -race ./internal/api -run 'TestAPIError|TestRequestID' -count=1`、全部 36 项前端测试、`npm --prefix web run build`、OpenAPI YAML 解析和 `git diff --check`，全部通过。

## 2026-10-21：PostgreSQL 报告模板、快照与作业适配

- 新增 `internal/repo/postgres_reports.go`，覆盖默认模板初始化、模板保存/读取、资产/任务/发现项冻结快照、分页历史、格式复用、失败重试、生成恢复、文件完整性读取和带 `FOR UPDATE SKIP LOCKED` 的报告队列。报告快照使用 PostgreSQL 资产画像/服务/登录入口、任务安全投影、任务观察和当前发现项投影，不读取目标或执行扫描。
- 默认单测覆盖空连接、搜索占位符绑定、排序白名单和共享报告格式校验；实验回归使用文档保留地址，验证任务范围快照、系统漏洞汇总、报告历史筛选、JSON 生成和文件大小校验。
- 已运行：`POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" go test -tags lab ./internal/repo -run 'TestPostgresReportStoreLab$' -count=2`，并与队列、任务投影、发现项、账号、资产、资产管理和授权适配器组合回归，全部通过。
- 该适配器仍未接入当前 SQLite Web 启动路径；Server 后端选择、报告之外的计划/通知 PostgreSQL 适配和 PostgreSQL 浏览器核心旅程仍待完成。报告文件只写入 Server 指定的本地输出目录，不把路径写入快照。

## 2026-10-21：PostgreSQL 发现项投影与生命周期适配

- 新增 PostgreSQL 迁移 `0009_finding_projection.sql` 和 `internal/repo/postgres_findings.go`。适配器以稳定指纹 `(asset_id, fingerprint_hash)` 去重，保留人工处置字段，支持接受风险到期、状态事件、任务观察、分页/搜索/风险筛选和固定排序；发现项投影保存完整页面字段，`security_findings` 的稳定身份与生命周期列保持权威。
- 默认单测覆盖空连接、稳定指纹输入边界、查询占位符绑定和排序白名单；`ExpireAcceptedRisks` 在关闭查询游标后再更新，避免 PostgreSQL 驱动连接复用错误。
- 在隔离 PostgreSQL 夹具上运行：`POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" go test -tags lab ./internal/repo -run 'TestPostgresFindingStoreLab$' -count=1`，并与任务队列、任务投影、账号、资产、资产管理和授权适配器组合运行，全部通过。`make migrate-postgres` 已将 `0009_finding_projection` 记录为已应用。
- 这仍是 Server 侧独立适配器；当前 Web/Server 默认 Repository 仍为 SQLite，报告适配、启动时后端选择和 PostgreSQL 浏览器核心旅程尚未完成。测试只使用隔离夹具和文档保留地址，不提交靶机结果、凭据或 DSN。

## 2026-10-21：PostgreSQL 任务安全投影与 Worker 进度

- 新增 PostgreSQL 迁移 `0008_task_projection.sql`，建立任务安全投影和 Worker advisory progress 表；新增 `PostgresTaskProjection`，从规范化队列读取状态、租约、目标块和归档时间，从投影读取其余页面字段，并在写入进度前校验当前运行 Worker。
- 默认单测覆盖空连接、状态/ID/进度边界和进度回退；在隔离 PostgreSQL 夹具上运行 `POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" go test -tags lab ./internal/repo -run 'TestPostgresTaskProjectionLab$' -count=1`，实际验证投影读取、领取后进度保存、回退拒绝和完成状态。
- 该适配器仍不切换现有 SQLite Web 运行时；发现项、报告和 Server 启动选择仍待后续工作。

## 2026-10-21：PostgreSQL 核心任务队列适配器

- 新增 `internal/repo/postgres_queue.go`，实现 Server 侧 `TaskStore`/`LeaseRegistry` 的 PostgreSQL 版本：任务和精确数字 IP:端口目标写入、`FOR UPDATE SKIP LOCKED` 单块领取、租约续期、完整/失败完成和按规则版本统计。
- 适配器在边界拒绝主机名、CIDR、未指定/组播地址、非法端口、空引擎和空目标；Worker/Updater 仍只有节点 API 凭据，不能直接取得数据库连接。
- 默认单测覆盖输入边界和空连接；在隔离 PostgreSQL 夹具上运行 `POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" go test -tags lab ./internal/repo -run '^TestPostgresTaskStoreLab$' -count=1`，实际验证创建、领取、续租、完成和运行计数。
- 该适配器尚未替换当前 SQLite Server；账号、资产、审批、完整任务投影、发现项/报告适配器和启动选择仍待完成，不能把本记录解释为平台已切换 PostgreSQL。

## 2026-10-21：PostgreSQL 账号与资产核心适配器

- 新增 `internal/account/postgres.go` 和 `internal/assets/postgres.go`，覆盖账号认证/会话/管理员变更，以及主机资产登记、编辑、端口申请、删除、分页搜索和可达性检查；连接池仍只由 Server 持有。
- 新增迁移 `0007_asset_catalog.sql`，补充业务组与 CSV 导入摘要所需的基础表；迁移目录和只读 schema inventory 已更新为 30 张业务表加 journal、七个版本。
- 在隔离 PostgreSQL 夹具上分别运行 `POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" go test -tags lab ./internal/account -run '^TestPostgresAccountRepositoryLab$' -count=1` 和 `POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" go test -tags lab ./internal/assets -run '^TestPostgresAssetRepositoryLab$' -count=1`，实际验证管理员登录/会话失效、用户生命周期、资产登记/端口/可达性/编辑/删除。
- 这些适配器仍未接入当前 Server 启动路径；审批、导入/业务组扩展、任务投影、发现项/报告和 PostgreSQL 后端选择仍待完成。

## 2026-10-21：PostgreSQL 授权范围与端口审批适配器

- 新增 `internal/approvals/postgres.go`，覆盖授权范围申请/编辑/撤销/删除/审批、端口请求列表/分页和人工批准/拒绝；审批状态、独立审批人、过期筛选、排除端口和审计写入均在 Server 事务内完成。
- 在隔离 PostgreSQL 夹具上运行 `POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" go test -tags lab ./internal/approvals -run '^TestPostgresApprovalRepositoryLab$' -count=1`，验证范围生命周期、过期筛选、端口分页、批准/拒绝和二次审批冲突；与其他三个 PostgreSQL lab 包并行运行也通过。
- 适配器尚未接入当前 SQLite Server 启动路径；资产导入/业务组扩展、任务投影、发现项/报告和 PostgreSQL 后端选择仍待完成。

## 2026-10-21：PostgreSQL 资产管理扩展

- `internal/assets/postgres_management.go` 已补业务组列表/创建/分页和 CSV 导入预览/确认、导入历史摘要；原始 CSV 行、地址和名称不会写入历史记录，确认过程仍在单事务内完成并支持预览占用和重复资产冲突。
- `POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" go test -tags lab ./internal/assets -run 'TestPostgresAsset(Repository|ManagementRepository)Lab$' -count=1` 已验证业务组计数、搜索分页、预览/确认、重复确认拒绝和导入历史摘要；与其他 PostgreSQL lab 包并行运行通过。
- 这些适配器仍未接入当前 Server 启动路径；完整任务投影、发现项/报告和 PostgreSQL 后端选择仍待完成。

## 2026-10-21：独立节点 HTTPS 监听器

- Server 新增独立的 `--node-listen`、`--node-tls-cert` 和 `--node-tls-key` 参数；监听地址必须是明确数字 IP:端口，拒绝主机名、未指定地址、组播地址和非法端口。网页仍使用单独的数字回环监听地址。
- 节点监听器只路由 Worker、Updater 和 heartbeat 协议路径，所有其他网页/人工路径返回 404；节点请求仍要求 owner-only 令牌文件、`X-Node-ID` 和 Bearer 令牌。TLS 配置强制最低 TLS 1.3，证书/私钥要求普通非符号链接文件，私钥必须 owner-only。
- 已新增 `internal/api` 路由隔离测试和 `internal/bootstrap` 地址、证书、权限、符号链接及 TLS 版本单测；已通过 `make test`（含 Go race 与 18 个 Python 测试）、`make build`、`make lint`、`npm --prefix web run build`、36 个前端源码测试、OpenAPI YAML 解析和 `git diff --check`。
- 当前只实现单向 TLS；客户端证书信任、mTLS、证书轮换和完整 PostgreSQL Repository 运行时仍未完成。独立监听器不改变扫描目标范围，也不提供攻击类能力。

## 2026-10-21：隔离靶机与 PostgreSQL 夹具实际启动

- OrbStack 隔离靶机已重新构建并运行，SSH 与 HTTP 监听端口均完成本机连通性检查；靶机仅作为明确授权的扫描目标使用。
- PostgreSQL 16.4 夹具已启动并通过 `pg_isready` 健康检查，DSN 保存在被 Git 忽略且 owner-only 的 `runtime/postgres/dsn` 中，密码未写入仓库或日志。
- 在该隔离数据库上运行 `POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" make migrate-postgres`，`0001_core` 至 `0007_asset_catalog` 七个迁移全部应用，并通过只读查询核对 `schema_migrations`。
- 这次验证只证明靶机连通性和 PostgreSQL 迁移执行；平台业务运行时仍使用 SQLite，完整 PostgreSQL Repository、Server 启动选择和生产节点部署仍未完成。

## 2026-10-21：隔离 PostgreSQL 验证夹具

- `lab/orbstack-target/compose-postgres.yaml` 新增独立 PostgreSQL 16.4 Bookworm 服务；端口仅绑定 `127.0.0.1:15432`，数据使用命名卷，健康检查使用 `pg_isready`，密码必须由环境变量提供，不提交凭据或卷数据。
- `lab/orbstack-target/README.md` 补充启动、owner-only DSN 文件、`make migrate-postgres` 和清理命令。该夹具用于迁移/Repository 回归，不会自动创建业务用户、资产、规则或扫描结果。
- 当前夹具已完成实际启动和健康检查；完整 PostgreSQL Repository 运行时仍未接入，因此不能把迁移成功等同于平台已切换 PostgreSQL。

## 2026-10-21：节点协议令牌认证基础

- Server 新增 `--node-token-file`，读取 owner-only 普通文件中的 `node-id=token` 注册表；拒绝符号链接、组/其他用户可读文件、空/重复节点、短令牌和不可见字符。Worker/Updater 新增各自的单令牌文件参数，并在节点请求中携带 `Authorization: Bearer ...` 与 `X-Node-ID`。
- Server 对 `/api/v1/nodes/heartbeat`、`/api/v1/worker/*` 和 `/api/v1/updater/*` 做恒时令牌比较，并把令牌对应的节点身份与 JSON 请求体中的节点 ID 再校验；浏览器 UI 和人工会话接口不受影响。未配置令牌时仅保留回环开发兼容模式。
- 已新增 API、Worker、Updater 单测，覆盖缺失/错误/未知节点、身份不匹配、文件权限/符号链接/重复项和凭据不回显。尚未宣称独立节点监听端口、TLS/mTLS 或多节点生产部署完成；这些是下一阶段安全部署工作。

## 2026-10-21：PostgreSQL 连接与迁移执行基础

- 新增 `internal/repo/postgres.go`，使用锁定版本 `pgx/v5`（MIT）注册 `database/sql` 驱动；迁移 SQL 嵌入 Server 二进制，按文件名验证顺序后执行。
- `POSTGRES_DSN_FILE=/path/to/owner-only-dsn make migrate-postgres` 只读取 0600 普通文件，Ping 数据库后获取 advisory lock；公共 schema 非空但没有迁移 journal、journal 含未知版本或存在断档时 fail closed。命令只输出已执行/已存在的版本名，不创建数据库、不写入用户/资产/规则示例数据。
- 新增迁移目录、DSN 保护和连接池配置单测；随后在隔离 PostgreSQL 夹具上实际执行并核对六个迁移版本。当前产品运行时仍使用 SQLite，完整 PostgreSQL Repository、索引/外键业务回归和生产启动选择仍列为下一阶段验收。

## 2026-10-21：授权范围与端口审批清册服务端分页

- `/api/v1/scopes` 和 `/api/v1/port-requests` 无查询参数时保留兼容清单；带分页参数时分别支持期限筛选、状态筛选和资产地址/ID 搜索。范围页额外返回全量七天内到期与已过期计数，页面不再用当前页数据推断全局提醒。
- Server 对页码、页大小、重复/未知查询参数和非法筛选值做 fail-closed 校验；端口搜索只覆盖已登记资产地址或 ID，`LIKE` 通配符和反斜杠均转义，不返回新增敏感字段。
- 已补审批仓储/API race 测试和前端源码契约测试；真实浏览器审批交互仍需隔离环境验收。

## 2026-10-21：低频清册服务端分页闭环

- 业务组、资产导入记录、漏洞知识库和通知中心增加可选的 `page`/`page_size` 分页查询；业务组和导入记录支持安全摘要搜索，知识库搜索归一化 JSON 元数据，通知分页保留全量未读计数。无分页参数的旧响应继续兼容。
- Server 对页码、页大小、重复/未知查询参数和 NUL/超长搜索做 fail-closed 校验；SQL `LIKE` 搜索转义 `%`、`_` 和反斜杠，返回字段仍不包含 CSV 原文、目标地址、凭据、原始请求/响应或引擎输出。
- 已补仓储/API race 覆盖分页、搜索、空结果、越界和未读计数，前端页面改为按页读取。发布前仍需在真实浏览器中核对分页与筛选交互。

## 2026-10-21：演示数据移除后的隔离靶机回归确认

- 用户确认已在隔离靶机完成真实 SSH/自动综合扫描回归：从空数据库登记明确授权的资产和端口后，平台能够执行任务并展示真实结果。该确认支持保留 Server-only 数据通道，不再需要演示账号、合成资产或预置任务。
- 本记录不保存目标地址、凭据、任务 ID 或扫描发现；`cmd/seed-demo`、`make seed-demo`、`--seed-demo` 和 `VITE_DATA_MODE` 继续保持移除状态。
- Playwright 浏览器脚本和授权范围抓包仍作为发布级验收证据单独保留，不能替代范围审计；它们不会改变扫描范围或恢复演示数据。

## 2026-10-21：安全摘要 Webhook 投递闭环

- 系统设置新增默认关闭的 Webhook 配置。非回环地址必须使用 HTTPS，禁止凭据、查询串、片段和重定向；回环 HTTP 仅用于隔离本机测试。配置保存写入审计，管理员以外的账号不能读取或修改。
- 站内通知创建时写入本地 outbox；Server 每 5 秒刷新通知并处理最多 20 条到期投递。投递只发送通知中心已有的安全摘要，失败按 10 秒起的指数退避重试，最多 5 次后标记 `DEAD`；响应正文不会写入日志或数据库。管理员可读取投递状态和受限错误摘要。
- 新增仓储/API race 测试和 Webhook `httptest` 测试，覆盖 URL 校验、权限、成功投递、失败重试和永久失败。需运行 `make test`、`make lint`、`make build`、`npm --prefix web run build`、前端源码测试、OpenAPI YAML 解析和 `git diff --check`；真实第三方 Webhook 和浏览器设置页面仍需隔离环境验收。

记录待核对项的来源、锁定版本、验证日期、结果和未决风险。未经实际验证的项目不得标记为已确认。

## 2026-10-21：报告历史服务端分页与筛选

- `GET /api/v1/reports` 无查询参数时继续返回兼容的完整历史；带 `page`、`page_size`、`q`、`status`、`format` 或 `sort` 时由 Server 执行有界分页、搜索、筛选和稳定排序。报告名称、创建人和快照 ID 仅作为归一化历史字段搜索，不读取或返回原始证据。
- `/reports` 页面使用 Server 分页结果，提供报告名称/创建人/快照搜索、状态和格式筛选、分页大小选择及加载状态；筛选改变时回到第一页，刷新和异步生成后保留当前查询。
- 已新增仓储、API 和前端源码契约测试，覆盖排序白名单、SQLite LIKE 转义、空结果分页大小、格式/状态筛选、重复/未知查询参数拒绝及页面响应字段。已通过 `make test`（含 race）、`make lint`、`make build`、`npm --prefix web run build`、`node web/src/pages/Reports/list.test.mjs`、Ruby OpenAPI YAML 解析和 `git diff --check`；真实浏览器交互仍需 `make test-browser`。

## 2026-10-21：节点与规则版本清册服务端分页

- `GET /api/v1/nodes` 与 `GET /api/v1/rules` 无查询参数时继续返回兼容的完整清单；带 `page`、`page_size`、`q` 或 `sort` 时由 Server 执行有界分页、白名单排序和字段限定搜索。节点搜索只覆盖节点 ID、类型和主机 ID，规则搜索只覆盖版本和渠道；不会扩大节点通信范围或读取规则原始文件。
- 节点与规则版本页面使用独立分页状态、搜索框和加载状态；节点心跳和规则目录仍按原轮询周期刷新，规则导入/激活操作保持原有权限、签名和版本门禁。
- 已新增仓储、API 和前端源码契约测试，覆盖分页/排序、搜索、空结果、重复/未知查询参数和排序白名单拒绝。已通过 `make test`（含 race）、`make lint`、`make build`、`npm --prefix web run build`、27 个前端源码契约测试、Ruby OpenAPI YAML 解析和 `git diff --check`；真实浏览器交互仍需 `make test-browser`。

## 2026-10-21：规则操作与自定义规则清册服务端分页

- `GET /api/v1/rule-jobs` 和 `GET /api/v1/custom-rules` 无查询参数时保持原有兼容清单；带分页参数时，规则操作支持类型/状态筛选与 ID、版本、说明搜索，自定义规则支持等级/启用状态筛选与 ID、名称、说明搜索。排序字段固定白名单，分页上限为每页 100 条。
- 节点页的规则操作记录和自定义规则表使用独立分页、搜索、筛选及加载状态；新增、修改、删除规则和导入/激活操作仍走原权限、CSRF、签名和规则编译门禁。
- 已新增仓储、API 和前端源码契约测试，覆盖 SQLite LIKE 转义、状态/类型/启用筛选、空结果、重复/未知查询参数和非法排序拒绝。已通过 `make test`（含 race）、`make lint`、`make build`、`npm --prefix web run build`、27 个前端源码契约测试、Ruby OpenAPI YAML 解析和 `git diff --check`；真实浏览器交互仍需 `make test-browser`。

## 2026-10-21：漏洞清册服务端分页与筛选

- `/api/v1/findings` 保留无查询参数时的兼容完整响应；带分页参数或筛选条件时由 Server 执行有界分页、稳定排序、搜索和分类计数。筛选只覆盖归一化发现字段，前端不再一次加载全部发现项；跨页批量选择继续携带状态/指派快照，由 Server 做最终并发校验。
- 新增仓储和 API race 覆盖严重度、风险类型、搜索、业务组/资产、仅已验证、空结果计数、非法查询拒绝和页面响应；OpenAPI、API README、产品现状与路线图同步更新。
- 已通过：`go test ./internal/repo ./internal/api`、`node web/src/pages/Findings/list.test.mjs`、`node web/src/pages/Findings/batch.test.mjs`、全部 32 项前端源码测试、`npm --prefix web run build`、`make test`、`make lint`、`make build`、OpenAPI YAML 解析和 `git diff --check`。真实浏览器分页体验仍待 `make test-browser`。

## 2026-10-21：管理员系统设置与会话策略

- 新增 `/settings` 管理员页面和 `GET/PUT /api/v1/system-settings`。时区限定为 `UTC`、`Asia/Shanghai`、`America/New_York`；会话时长限定为 30–1440 分钟；保存写入 `product_settings` 并记录 `update_system_settings` 审计动作。
- 登录时服务端会话到期时间和 HttpOnly Cookie 的 `Max-Age` 同时读取该设置；系统设置表或记录尚未初始化时安全回退到 8 小时默认值。已有会话不会因设置变更提前失效。
- `go test -race ./internal/account ./internal/repo ./internal/api`、`node --test web/src/pages/Settings/settings.test.mjs` 和前端生产构建用于本批回归；真实浏览器页面交互和 PostgreSQL 运行时仍待验收。外部通知投递没有在本批实现。

## 2026-10-21：平台内通知中心

- 新增 `/notifications` 和 `GET /api/v1/notifications`。Server 从已批准授权七天内到期/已过期、接受风险七天内到期/已过期和失败扫描任务生成确定性通知；消息只包含安全摘要和对象标识，不包含目标地址、凭据、原始请求/响应或引擎输出。
- 通知写入 SQLite `notifications` 表，刷新幂等；登录用户可筛选未读、标记单条或全部已读。读取和已读操作不会启动探测、扫描或外部网络请求；外部邮件/Webhook 投递保留到后续阶段。
- `go test -race ./internal/repo ./internal/api`、`node --test web/src/pages/Notifications/notifications.test.mjs web/src/components/Layout/navigation.test.mjs` 和前端生产构建通过；真实浏览器交互、PostgreSQL 运行时和外部投递未验收/未实现。

## 2026-10-21：报告 PDF 输出

- 报告格式新增 `pdf`，继续复用原有冻结快照、异步队列、重试、历史和同快照导出；下载接口返回 `application/pdf`，报告页面可生成和导出 PDF。
- PDF 使用 PDF 标准的 `STSong-Light` CJK 字体，离线生成 A4 文本与表格，保留八章内容、范围说明、漏洞明细和覆盖限制；不读取远程资源、不启动扫描器、不提交字体文件。
- `go test ./internal/reporting ./internal/repo ./internal/api`、合成 PDF 输出、`pdfinfo` 结构检查、前端生产构建和 OpenAPI YAML 解析通过。PDF 的原生办公软件视觉排版、PostgreSQL 运行时和真实浏览器点击仍待环境验收。

## 2026-10-21：移除演示种子与浏览器 mock 通道

- 根据隔离靶机真实 SSH/自动综合扫描结果，移除 `cmd/seed-demo`、`make seed-demo` 和 Server 的 `--seed-demo` 启动参数；本地启动不再自动写入合成资产、任务或发现项。`scripts/test_local.py` 改为从空数据库开始验证登录、资产、任务和 Worker API。
- 前端认证、总览、资产、授权、任务、漏洞、报告、节点、知识库、用户和审计页面统一走 Server API；删除 `web/src/mock`、`isDemoMode`/`VITE_DATA_MODE` 分支。API 失败只显示错误状态，不回退到浏览器内存数据。
- 已更新产品路线图、现状和快速开始文档，验收入口改为隔离靶机真实数据。`npm --prefix web run build`、前端源码契约测试、`make test`、`make lint`、`make build` 和 `git diff --check` 需在本批提交前重新运行。

## 2026-10-21：六域信息架构与导航基础

- 主导航由原来的平铺入口收敛为“总览、资产、扫描、漏洞、报告、系统”六个稳定域；系统域承载授权范围、节点与规则库、漏洞知识库、用户与角色、审计日志。每个子入口只指向已存在的真实路由，系统设置和通知中心在闭环完成前不展示空壳入口。
- 菜单定义集中在 `web/src/components/Layout/navigation.ts`，角色过滤仍由前端负责隐藏入口，后端权限校验保持不变；点击一级域标题会进入该域默认页面，直接访问既有路由不受影响。
- `node --test web/src/components/Layout/navigation.test.mjs` 和 `npm --prefix web run build` 通过。真实浏览器的折叠菜单、键盘导航和窄屏体验仍待 Stage 1 回归。

## 2026-10-21：Server 数据通道收敛（历史记录）

- 本节早期记录的演示种子已由上方“移除演示种子与浏览器 mock 通道”批次替代；仓库当前不再提供 `make seed-demo`、`cmd/seed-demo` 或 `VITE_DATA_MODE`。

## 2026-10-21：共享状态与表格组件

- 新增 `web/src/components/DataState.tsx`，集中提供 `LoadingState`、`ErrorState`、`EmptyState` 和 `DataTable`。`CollectionNotice` 统一使用加载/错误状态，资产、扫描、漏洞、报告、节点、授权、用户、审计、知识库和总览列表统一使用 `DataTable`。
- `DataTable` 默认提供可访问的空状态和稳定的空结果语义；页面仍可通过 `locale.emptyText` 提供领域化说明，不改变现有筛选、分页或权限行为。
- 新增 `DataState.test.mjs` 契约测试；共享组件批次通过 22 项前端测试和生产构建。真实浏览器的键盘导航、窄屏表格和 5 次点击核心旅程仍列入下一批验收。

## 2026-10-21：跨页面语义组件

- 新增 `web/src/components/Semantic.tsx`，集中维护严重度、漏洞生命周期、扫描任务和定时运行状态的标签颜色与中文/英文文案，并提供 `StatCard` 和 `LoadingSkeleton`。漏洞、总览、任务页面改用共享组件，删除页面内重复的状态映射，避免同一状态在不同页面显示不同含义。
- `Semantic.test.mjs` 契约测试覆盖全部状态枚举及主要页面的共享组件引用；前端源码测试共 24 项，生产构建通过。完整设计令牌、筛选条、详情抽屉和危险确认弹窗仍需按核心旅程继续抽取，未在本批扩大范围。

## 2026-10-21：真实靶机浏览器验收脚本

- 新增 `docs/browser-acceptance.md` 和 `web/e2e/core-journey.spec.mjs`。脚本要求 `LAB_ENV=isolated`、人为确认值、已有账号、单个数字 IP 和明确端口范围；不会创建演示账号、默认目标或扩大扫描范围。
- 验收步骤覆盖页面登录、资产登记、自动综合扫描向导、授权确认、任务完成轮询和任务详情结果检查。任务/资产默认保留，便于人工复核；真实执行需在隔离靶机上运行 `make test-browser`，本次提交只完成脚本和门槛，未代替用户授权运行。

## 2026-10-21：三条核心旅程浏览器验收覆盖

- 抽取 `web/e2e/helpers.mjs` 统一隔离环境、数字 IP、端口范围、账号和登录门槛；新增总览下钻/指定发现项详情以及定时/报告页面验收脚本。所有脚本共 5 个测试，深入发现项和报告选择分别需要显式提供现有 `SCANNER_E2E_FINDING_ID`、`SCANNER_E2E_TASK_ID`，不写入状态或创建报告。
- `node --test $(find web/src -name '*.test.mjs' -print)` 共 25 项通过；`npm --prefix web run test:e2e -- --list` 列出 5 个测试；`npm --prefix web run build` 通过。当前未连接正在运行的 Server，未宣称真实浏览器实跑或抓包证据已完成。

## 2026-10-20：单项接受风险、到期与状态事件

- 新增 finding_events SQLite 表及按发现项/时间索引；PATCH 接收状态、原因、到期，GET `/api/v1/findings/{id}/events` 返回时间线。Server 角色/CSRF 沿用现有写权限，非写角色只能查看。
- 接受风险仅允许 OPEN/REOPENED/IN_PROGRESS；原因按 UTF-8 字节限长且拒控制字符，到期必须 RFC3339 带时区并位于未来 365 天。拒绝手工 FIXED、从 FIXED 修改、重复状态、误报直接接受以及未撤销接受直接流转其他状态。
- 每分钟 Tick、列表/更新/回报入口补查到期与旧无期限接受；条件更新和事务保证并发只记录一次。扫描重复检出保留接受字段，自动 FIXED/REOPENED 和到期重开记录系统事件；Worker 协议未开放接受字段。架构要求的到期通知渠道尚无现有基础设施，本批只提供事件/时间线，通知投递列为后续缺口。
- Go 测试覆盖输入/状态边界、角色/CSRF/API、并发过期、旧无期限或格式错误期限、事件失败回滚、审计不含原因、回报前到期及自动生命周期事件。前端 helper/源码契约测试覆盖资格、UTF-8 限长、期限、纯文本表单与时间线；生产构建通过。
- 已运行 `go test -race ./internal/repo ./internal/api`、`node web/src/pages/Findings/disposition.test.mjs`、`npm --prefix web run build`。未进行真实浏览器交互、服务重启、真实扫描或 PostgreSQL 集成；最终全库门禁由主代理复核。

## 当前待核对项

| 项目 | 状态 | 说明 |
| --- | --- | --- |
| Nuclei / Trivy / ZAP 版本锁定 | 本机核验通过 | 3.11.1 / 0.76.0 / 2.17.0，官方程序版本、下载哈希与参数已在本机核对；见 2026-10-16 及后续记录。 |
| 引擎参数白名单 | 已安装版本核验通过 | `make verify-flags` 对实际帮助核对；2026-10-19 新增 rootfs 与 OS 包类型参数，不代表真实服务器已验收。 |
| Phase 0 PoC | 未运行 | 真实扫描、防火墙和抓包验证只允许在隔离实验环境开展。 |
| PoC #1 应用层准入（2026-10-16） | 单元测试通过，实验验收未运行 | 显式 IP:端口、审批/到期、端口隔离、时间窗均为纯逻辑验证；网络围栏、降权、DROP 告警和隔离靶场验收未做。 |
| PoC #1 Linux 围栏与受限启动预备代码（2026-10-16，历史记录） | 本地模拟通过，实验待验证 | 当时记录为尚未接入 cmd/worker；当前接入状态见本文件顶部 2026-10-21 条目。Linux nft/setpriv、namespace 隔离、实际无外联和 DROP 统计仍必须人工核对。 |
| 引擎受限启动硬闸（2026-10-16） | Worker 围栏子进程隔离联调通过；生产引擎全链路待验收 | Linux arm64 隔离实验实际核对 Worker 子进程 UID/GID 10001、NoNewPrivs 和全部 capability 清零；`internal/executor` 仍通过锁定版本的参数白名单启动引擎。独立 `RestrictedExec.Launch` 继续 fail-closed，生产环境的范围抓包、cgroup 后代回收和 Nuclei/Trivy 围栏内全链路仍待验证。 |
| GitHub Actions 六平台 CI / Release（2026-10-16） | 本地检查及 GitHub 云端 CI 通过；Release 未发布 | 提交 `798f832` 的 CI 已通过前端、race 测试、lint 和 Linux/macOS/Windows 六平台构建。标签构建只有完整 CI 通过才打包；发布权限仅 Release Job，标签仅创建 Draft + Pre-release。漏洞库手工工作流需另看当前签名步骤结果。 |
| 漏洞库 Ed25519 签名与平台验签 | 本地平台实现、隔离测试和当前主分支 GitHub Actions 均通过 | 当前工作流使用 `vulnerability-data-signing` 环境、`BUNDLE_SIGNING_PRIVATE_KEY_PEM` 密钥和 `BUNDLE_SIGNING_PUBLIC_KEY_PEM` 变量；云端已完成 8 个文件完整性校验、Ed25519 签名/验签和 `vulnerability-data` 制品上传。Updater 支持 2 GiB 以内的已签名本地/HTTPS 流式导入，网页 multipart 仍为 256 MiB；现已支持最多 3 把包外公钥的轮换重叠窗口和固定版本/Trivy schema 兼容性校验，跨版本扩大兼容范围仍未完成。 |
| SSH 指定目录 Java/Go 应用 | Go 与含 class 的 Java 合成 JAR 隔离路径通过；活动规则已切换到含 Java DB 的版本 | Go ELF 与 Java JAR 均完成 SSH 采集、快照校验、Trivy 类型确认和覆盖计数；缺少 Java 索引时仍明确为 `analysis_failed`，带 Java DB 的规则版本已验证 Java 选中/已分析均为 1。当前活动版本通过 Updater 本地显式准备，`signatureVerified=false`；仅覆盖合成输入，独立挂载目录和真实业务应用仍待验收。 |
| 自动综合扫描 HTTP 失败状态回报 | Worker/Server 回归与 V4 排除端口验证通过；最新 V5 任务界面显示已完成，结果仍待逐项复核 | HTTP 错误保持 FAILED 并保存明确的系统包阶段状态。此前路由阻塞记录为历史状态；本轮开发期间未重启原测试实例，新应用能力不属于该次实扫验收范围。 |
| 正式客户端签名/公证和供应链证明 | 未实施 | Phase 0 归档仅是占位骨架。缺少 Windows 代码签名、macOS 签名/公证及 Artifact Attestation；不能直接当作受信任的可部署产品发布。 |
| PoC #2 租约守护与本地任务租约（2026-10-20） | Scheduler、SQLite Server/Worker HTTP 联调及 race 单测通过；生产节点验收未执行 | 真实任务领取时生成 `pinned_rule_version`/`lease_expires_at`，`/worker/renew` 校验任务、Worker、版本、过期和 hard deadline，`Tick` 回收过期任务；Worker 租约失联时停止且不发送陈旧回报。仍需在 TLS/节点令牌、独立进程和强杀路径上实测。 |
| PoC #2 CURRENT 门禁与本地规则版本（2026-10-20） | 本地 CURRENT 读取、缺失等待、版本过滤和节点心跳单测通过；生产多节点验收未执行 | 真实 Worker 读取只读规则根的 CURRENT，缺失时上报 `WAITING_FOR_RULES` 并退避，不领取规则任务；规则任务只在 Server 看到相同 `localRuleVersion` 时领取，端口探测/ZAP 保持无规则兼容。无效 CURRENT 显式上报 `RULES_ERROR` 并停止；完整 manifest/hash 仍在引擎执行前复核。 |
| PoC #2 GC 两阶段文件操作（2026-10-20） | 本地文件实现与隔离竞态单测通过；真实 Updater 集成未执行 | 当前和最近备用版本保护、>=2h 退役宽限期、每阶段向 Server 复核本节点 RUNNING 任务；使用限定目录的 rename、持久隔离记录和二次检查后删除。缺少可信退役状态或隔离记录时拒绝回收；完整激活协调、真实 Node API 和 Windows 实机行为仍待集成验证。 |
| 发现项详情抽屉（2026-10-20） | 前端 helper/源码契约回归和生产构建通过；浏览器/Server 联调未运行 | ID 选中跟随当前集合，筛掉/删除关闭；文本字段无 HTML/自动链接且保留长文本，缺状态事件时明确提示。Esc/遮罩、焦点、窄屏和实际轮询体验仍待浏览器验收。 |
| Stage 2 自动综合扫描四步向导（2026-10-20） | 前端 helper 回归和生产构建通过；浏览器/Playwright 验收未运行 | 自动综合扫描立即任务按目标、方案、执行方式、确认分步，回退保留配置，确认页展示 Server 将重新校验的有效端口和排除项；未授权、无权限和未到确认步骤不会提交。定时、离线输入和旧任务复制保留旧流程；尚未补扫描方案资源和真实浏览器五次点击验收。 |
| 四入口与本地只读 API 骨架（2026-10-16） | 仅搭建结构，本轮按用户要求暂未运行测试 | 增加统一启动入口、Portable 编译入口、Server/Portable loopback 只读诊断 API 和数据库接口定义。业务接口 501，readyz 503，未启用 Node API、数据库、扫描或规则激活。须后续完成跨平台编译、API/安全边界测试与接口联调。 |
| UI 用户管理契约与前端发布构建（2026-10-16） | 本地前端双模式、Go、YAML/actionlint 通过；GitHub 云端未运行 | 新增用户/角色演示页面，GET `/api/v1/users` 仅返回 501；用户写入/认证/RBAC/审计不开放。CI 纳入 Node.js 22 npm ci + 双模式打包检查；Release 仅构建一次 Server-mode UI 作为 `web/` 静态资产加入每个平台的归档，不表示 Server 已支持 UI 静态服务。 |
| SQLite 账号管理（2026-10-16） | 单元/竞态及本机 HTTP 联调通过；远程部署未验收 | 使用纯 Go SQLite、bcrypt、HttpOnly/SameSite Cookie，账号 CRUD 需 admin 且写审计；本机测试包含初始化、登录、新增/停用、越权拒绝、登出。仅用于 loopback 开发，不表示平台扫描或节点 API 已可用。 |

## 2026-10-20：发现项详情抽屉

- `/findings` 以 Ant Design Drawer 替代行内展开，显式“查看详情”按钮支持键盘操作；状态操作均阻止事件传播，继续遵守原演示模式、Server 角色权限和 FIXED 限制。
- 仅保存选中 ID，内容每次从当前 findings 读取最新对象；选中记录被过滤或移除时关闭。支持 Esc/关闭按钮/遮罩、窄屏宽度，关闭后原按钮仍在 DOM 时恢复焦点。详情 ID 不加入 URL，分类筛选继续沿用现有查询参数。
- 展示已有检测依据、目标/归属、组件/版本、描述/影响/修复建议/证据/路径/参考、时间/连续未检出计数和关联 ID。空值统一“未提供”，不将现有时间伪造成事件时间线，并明确“暂无状态变更记录”。所有不可信字段按 React 文本渲染，长字段保留全文并放入可键盘滚动区域。
- 实际通过：`node web/src/pages/Findings/drawer.test.mjs`、`node web/src/pages/Findings/filters.test.mjs`、`node web/src/pages/Assets/import.test.mjs`、`node web/src/pages/Tasks/policy.test.mjs`、`node web/src/pages/Tasks/wizard.test.mjs`、`npm --prefix web run build`、`git diff --check`。新增纯函数和 TypeScript AST 源码契约检查，覆盖空值/零值、HTML 转义、长文本无截断、最新记录/筛掉/删除、触发按钮及状态按钮事件隔离。
- 未运行真实浏览器或 Server 联调；焦点恢复、Esc/遮罩、窄屏与实际轮询/PATCH 体验仍需独立浏览器验收。本次不修改后端、数据库或扫描行为。

## 2026-10-20：自动综合扫描四步创建向导

- `/tasks` 的自动综合扫描立即任务改为“目标 → 方案 → 执行方式 → 确认”四步向导。目标仍只能从已登记主机选择；端口策略、强度、任务排除、自定义规则和时间窗沿用原字段，未新增网段或范围外目标入口。
- 向导只在当前步骤校验，前后返回保留字段；修改配置会清除原运维授权。确认页显示有效端口预览、系统/资产/任务排除、隔离端口和时间窗；端口预览是提示，Server 仍通过原任务 API 重新校验并冻结范围。全端口和完整自定义范围继续提交前二次确认。
- 提交守卫拒绝无权限、未完成确认或未勾选授权；定时任务、模拟任务、离线 Trivy 输入和旧任务复制保留原表单路径。新增 `wizard.ts` 与端口预览 helper 的 Node 回归，使用文档保留地址段夹具，不访问网络。
- 实际通过：`node web/src/pages/Tasks/policy.test.mjs`、`node web/src/pages/Tasks/wizard.test.mjs`、`npm --prefix web run build`、`make test`、`make lint`、`make build`、`git diff --check`。未运行浏览器/Playwright 或真实扫描。

## 2026-10-20：大体积签名漏洞库导入

- 新增 Updater `--import-bundle-file`：对本地签名 ZIP 使用 `ReaderAt` 直接读取，单包上限 2 GiB；同时识别 GitHub Actions 下载的 `vuln-data/releases/<版本>/` 目录树 ZIP，只提取唯一版本目录，不把 `CURRENT`、说明文件或外层校验清单当作规则文件。
- HTTPS Fetch 改为在 Updater 私有临时文件中流式写入并计算整包 SHA-256，再复用同一签名、路径、文件哈希和防回滚校验；失败/取消清理暂存文件。网页上传仍为 256 MiB，避免 SQLite BLOB 与 JSON/base64 放大。
- `go test -race ./internal/rules`、`make test`、`make lint`、`make build` 通过；新增普通 ZIP、Actions 目录树 ZIP、超大稀疏文件和符号链接失败路径测试。
- 使用下载目录的 `vulnerability-data.zip`（约 1.1 GiB）完成本地 Ed25519 签名和全部 manifest 文件哈希校验，成功导入版本 `20261020.113500`。当前 `CURRENT` 仍为 `20261020.120359`，未自动切换；由于导入版本较旧，切换必须由操作员显式执行回滚并按平台审计流程处理。

## 2026-10-20：PoC #2 本地任务租约协议与 Worker 守护

- SQLite `scan_tasks` 新增 `pinned_rule_version`、`lease_expires_at`；旧库启动时自动补列。非模拟任务由 Server 在领取时生成有限租约，规则任务固定领取时的规则版本，端口探测绑定不参与规则回收的 `__no_rules__` 哨兵。
- 新增 `POST /api/v1/worker/renew`，只允许原任务、Worker 和绑定版本续租。Server 拒绝错误绑定、过期租约和 hard deadline 后续租，并把新到期时间限制在短租期和 hard deadline 内。任务结果回报也校验同一租约；`Tick` 将过期任务回收到 `PENDING` 或 `PAUSED_WINDOW`。
- Worker 真实启动路径使用 `scheduler.LeaseGuard`；续租失联达到最后确认租期后取消执行，租约错误不会再发送可能被重新分配任务的 FAILED/COMPLETED 回报。缺少真实租约字段时真实 Worker fail closed，旧 fake/synthetic 测试保持兼容。
- `go test -race ./internal/repo ./internal/api ./internal/taskflow ./internal/scheduler` 通过，覆盖旧 Schema 迁移、claim/renew 绑定、续租边界、Tick 回收、API 200/409、并发续租和 Worker 续租成功/失联自终止。该结果仅证明本地 SQLite 和回环 HTTP 协议；生产 TLS、节点令牌、独立进程强杀及跨节点重分配仍未验收。

## 2026-10-20：PoC #2 CURRENT 门禁与规则版本上报

- Runner 新增只读 `CurrentRuleVersion` 检查，使用 `versionmgr.ReadLocalCurrent`，拒绝缺失、非法指针、链接和不存在的当前版本目录；不创建或修改规则目录。真实 Worker bootstrap 接入该回调。
- Worker 首次及周期心跳携带 `localRuleVersion`；缺失 CURRENT 时节点状态为 `WAITING_FOR_RULES`，按轮询间隔等待，Server 领取过滤会把规则任务留在队列。当前版本不一致的规则任务同样不领取；`port-probe`/`zap` 不依赖规则，保留兼容路径。无效 CURRENT 状态为 `RULES_ERROR` 并停止领取。
- Server 在 LocalNode 的 `boundRuleVersion` 保存最近一次 Worker 版本；OpenAPI、API 文档与 PoC #2 已同步。新增 Worker 等待/无效 CURRENT、规则任务过滤、节点心跳持久化和 Runner 只读路径测试。生产节点 TLS/令牌、跨节点版本分发仍未验收。

## 2026-10-20：自动综合扫描失败回报修复与靶场进度

- 修复 HTTP 只读检查失败后自动任务报告缺少 SSH 系统包阶段状态的问题。失败与暂停报告保留明确的“尚未开始”状态，Server 对失败任务也持久化该状态；不会将未完成任务记为成功。Worker/Server 针对性 race 回归、`make test`、`make build`、`make lint`、Server 模式前端构建通过。
- V4 排除端口靶场验证通过：任务明细确认任务级排除生效、排除端口未进入 HTTP 检查，范围内 SSH 采集链路正常。结果明细保留在本机任务记录。
- V5 全 TCP 端口实扫仍待验收。用户已授权仅扫描单一靶机容器 IP；宿主机与 OrbStack 的直连路由冲突，需解决后再执行，不能将开发机回环地址上的其他服务归入靶场结果。
- 平台已用现有 SSH 配置重启，`/healthz` 与 `/readyz` 返回就绪；任务记录仍保存在本地 SQLite。

### V5 路由检查补充

- 用户已授权将 OrbStack 靶机容器的单个 IPv4 登记为独立资产，并仅以温和强度扫描该地址的 TCP `1–65535`。
- 用户也授权调整 OrbStack 全局 Docker 地址池并重启引擎。曾临时配置文档保留网段 `203.0.113.0/24` 中的独立地址池并重启 OrbStack；靶机获得新地址后，宿主机仍将该网段路由到 Wi‑Fi 网关，直连未恢复。该尝试不能作为对端可达的证据。
- 已把 `~/.orbstack/config/docker.json` 恢复为原先的空配置并再次重启 OrbStack；靶场 Compose 文件也恢复为仓库原配置。容器现已恢复运行，平台保持停止，避免周期性可达性检查继续访问路由不明的目标。
- 之前曾对实验地址的 SSH 端口做一次 TCP 建连探测，路由显示经过 VPN，无法确认对端身份；没有发送 SSH 握手、凭据或扫描请求。当前没有创建 V5 任务，也没有运行全端口探测或扫描引擎。
- V5 需等宿主机网络/VPN 路由可让 OrbStack 的容器直连功能启用，并在直连后核验 SSH 主机指纹，再对登记的单个靶机 IP 扫描。OrbStack 会在容器网段与 VPN/其他网络冲突时自动关闭容器 IP 直连；本机当前同时存在覆盖私网地址的 Wi‑Fi/VPN 路由，单独更改 Docker 地址池没有消除冲突。


## 2026-10-16：本地普通功能修复与非探测功能接通

- 用户范围：逐项修复并复测本地业务，并追加定时任务和规则更新；真实服务器探测及真实扫描留待次日。
- 修复资产测试的用户 ID 外键夹具；统一 Server 网页、账号、资产和任务入口；旧模拟资产表保留为 assets_legacy_runtime；SQLite 数据库共用，未读取或复制用户其他数据库。
- 已接通：网页首次管理员初始化、登录/退出、用户角色与启停、资产/显式端口/跳过端口、审批台账、任务创建/取消、模拟结果及状态修改、单次/间隔定时、跨午夜时间窗、节点心跳、规则包离线/HTTPS 导入与激活/显式回滚。
- 已修复并复测的执行问题：SQLite 并发领取锁冲突；排队后目标/跳过标记变化必须在领取前复查；到期报告不得插入成功发现项；误报/处理中可以恢复待处理；启动端口冲突不得把后台进程接到另一实例。
- make build、make lint、make test（go test -race ./...）通过；前端 Server/Demo 构建通过；Windows/Linux amd64 交叉编译通过，仅表示可编译，不表示已在这些系统运行。
- make test-local 实际通过 9 组本地业务检查：包含首次初始化、角色启停、IPv4/IPv6/镜像登记、审批与跳过、任务与结果、定时自动触发、规则导入/校验失败/切换/回滚、节点离线恢复、重启持久化/审计/退出。全部使用临时数据库、规则目录和回环端口，没有连接目标。
- make dev 已实际完成 npm ci --ignore-scripts、Server 前端构建、三个二进制构建和联合启动；Ctrl+C 后监听已退出；重复启动同端口会明确拒绝，原实例保持健康。
- 浏览器实际验证：首次初始化界面、登录、资产及跳过端口录入、任务完成与下发/跳过清单、网页定时任务自动完成、发现项状态修改/恢复、节点在线及规则 CURRENT 切换。用户创建/启停与审批等完整角色写流程由上述自动化实例验证。
- HTTPS 更新使用本地 TLS 测试源核对实际下载与包哈希错误；未对真实外部规则源联调。离线包工具已实际生成并导入示例包。
- 边界：Worker 只模拟执行，Nuclei/Trivy 真实扫描、真实目标结果、真实漏洞修复验证、生产部署和 PostgreSQL 迁移运行未验证。规则只校验文件完整性，未验签、未验证引擎兼容性；上游规则需先按本平台 manifest 打包，不会自动抓取最新 GitHub/OCI 数据。
- 规则由 Updater 唯一写入；Server 只保存作业和回报目录。规则 ZIP 上限 256 MiB、解压 2 GiB、5 万文件、单文件 1 GiB；文件流式哈希校验，不覆盖同名版本。
- API DTO、前端类型和 OpenAPI 同步；修正原 OpenAPI 两处 flow mapping 的描述字段格式错误。没有改工作流或依赖。
- 当前普通功能不依赖 Draft PR、人工逐行评审或 PoC 门禁。后续安排：按用户输入的靶机 IP:端口接入真实扫描验证；Harbor、AI、便携版继续后置。

## 2026-10-16：固定引擎安装与本地真实执行

按早期开发模式接入 Nuclei 3.11.1（MIT）、Trivy 0.76.0（Apache-2.0）、ZAP 2.17.0（Apache-2.0）。官方 release 地址、各平台压缩包 SHA-256 与许可证记录在 `config/engines.lock.json`；本机 Darwin arm64 三种程序已下载校验，ZAP 使用现有 Java 17。`bin/`、规则库、缓存和结果均被 Git 忽略，未提交程序或漏洞库数据；没有新增 Go/npm 依赖或修改工作流。

实际验证：

- `make build`、`make lint`、`make test`（`go test -race ./...`）：通过。
- `make verify-flags`：实际版本及帮助输出通过；Nuclei 23 项、Trivy 17 项、ZAP 7 项。原参数校验占位现已替换。
- `python3 scripts/test_local.py`：原有 9 组本地业务回归通过；测试 HTTP 客户端显式绕过环境代理，Worker 使用隔离规则/运行目录。
- `LAB_ENV=isolated go test -tags=lab ./internal/executor -run TestInstalledEnginesOnLoopbackFixture -v`：临时回环 HTTP 夹具通过，HTTP 夹具 Nuclei 检出 4 项、ZAP 检出 3 项；自签名 HTTPS 夹具分别检出 4/5 项。两种协议共收到 6 次根路径 GET，没有其他路径。
- `LAB_ENV=isolated go test -tags=lab ./internal/executor -run TestInstalledTrivyOnLocalDependencyFixture -v`：本地测试依赖锁文件检出 5 项。
- `LAB_ENV=isolated python3 scripts/test_engines_local.py`：独立 Server/Worker/Updater 和 SQLite 全链路通过。Nuclei 4 项、ZAP 4 项、本地依赖 5 项；自制 Docker-save 元数据夹具 49 项（计数依赖当前 DB）。验证跳过端口、不爬取路径、ZAP 仅分析记录响应、Trivy 不下载依赖/镜像、重复结果去重、镜像不可变标识、缺失输入失败且不制造成功结果。
- 浏览器：三个引擎显示固定版本与本地就绪；任务表单可选择 ZAP/HTTP 和 Trivy 本机输入；通过网页创建 Trivy 夹具任务，观察完成并在发现项页看到 5 条真实引擎输出，模拟记录单独标注。
- `GOOS=windows GOARCH=amd64 go build ./...`、`GOOS=linux GOARCH=amd64 go build ./...`：编译通过；没有声称在这两个系统运行过真实引擎。
- 新单元测试覆盖受限模板拒绝路径、范围外 HTTP/结果拒绝、重定向不跟随、解析/fuzz 入口、Trivy 输入越界/符号链接拒绝、多条发现入库、跨任务稳定去重与保留人工状态、不同归档名的相同镜像去重、子进程到期终止。

实测修正：Nuclei 3.11.1 的 `-fhr` 与 `-dr` 同传会拒绝启动，因此只使用 `-fhr` 限制同主机重定向；ZAP 分发包中的 exim 0.16.0 不认识新版文档的 `sendRequests`，使用该固定版本原生的离线 HAR 导入。Trivy 主库实际解压约 1.5 GiB，规则导入单文件上限改为 4 GiB、总量 8 GiB，压缩 ZIP 上限仍为 256 MiB。旧单条发现 Schema 兼容迁移到一任务多条发现，保留已有模拟记录。

未验证及边界：未连接任何真实业务服务器，明天使用用户指定的一两台服务器验证。Nuclei 仅只读根路径 HTTP 基线，未启用完整上游 YAML/CVE 模板库；ZAP 不含主动扫描或爬虫任务；Trivy 支持 Worker 本机依赖/镜像归档，不含 SSH、远程镜像拉取或 Docker socket。默认只准备 Trivy 主库，JAR 需额外导入 Java DB。签名、完整规则兼容矩阵、生产节点 TLS/独立令牌、系统网络围栏仍未验证或未启用；遵循本次早期开发范围。

操作说明：`docs/engines.md`。所有真实任务都由用户明确选引擎后创建，目标在创建和领取时复核；未检出不自动转 FIXED。本文计数只记录夹具验证摘要，不包含真实扫描结果或资产数据。

同日补充：Worker 会在发送前检查结果 JSON 的 4 MiB 上限，超出时回报明确失败并提示拆分输入，避免请求被拒后任务停留在执行中。新增超大结果回归测试；`go test -race ./internal/taskflow ./internal/api` 与 `make build` 通过。此项不改变 API 字段或现有大小限制。

## 2026-10-19：Linux 软件包快照与混合部署输入

- 新增 Trivy `rootfs --pkg-types os` 任务；API、Server 校验、调度输入、Worker、前端类型与 OpenAPI 同步。仍在已有任务/发现项页面操作；新增按目标、组件或 CVE 筛选，修正窄窗口下 CVE 和指纹挤压。系统包指纹忽略临时分析路径，使用稳定输入别名、包、安装版本与 CVE。
- 新增标准库 Python Linux 采集工具：只复制发行版/包数据库、明确指定的应用依赖文件、指定本地 Docker 镜像或预先导出的归档。RPM SQLite 使用一致备份（含已提交 WAL）；不枚举镜像/容器/集群，不自动登录，不执行应用，不保存 kubeconfig 或 Docker 凭据。每个组件生成文件 SHA-256 清单；输出私有权限并自带忽略全部内容的 `.gitignore`。
- Worker 扫描前后核对快照，拒绝漏传、修改、未声明文件、符号链接和越界路径。哈希阶段保留 context 取消/截止语义。采集失败不发布完整目录、不覆盖现有输出。
- 修复固定 Trivy 对 OCI tar 的输入差异：该版本要求 OCI layout 目录。Worker 私有解包白名单布局，核对 blob SHA-256，拒绝穿越、链接、重复、缺失或多平台歧义，不解开容器层，结束后清理；Docker tar 保持直接输入。
- 系统包检查使用实际发行版 ID；麒麟等未适配源明确失败，忽略 `ID_LIKE` 的厂商替代含义。不把 CentOS Stream / RHEL 10 的 SBOM 能力当作当前漏洞覆盖。Worker 只把显式定义的安全提示回传网页，原始诊断仍留在私有日志。
- `make build`、`make lint`、`make test`（race 与采集工具 8 项测试）、Server/Demo 前端构建通过；Linux amd64/arm64、Windows amd64 交叉编译通过。仅表示可编译，未在这些 Linux 系统或 CPU 上运行引擎。
- `make verify-flags` 核对 Nuclei 23 / Trivy 18 / ZAP 7 个参数；快照 JSON fuzz 实际运行约 32 万次，无失败；新 Linux release 与 OCI tar fuzz 入口包含在单元测试。
- 原有 `scripts/test_local.py` 9 组普通业务回归通过。`LAB_ENV=isolated python3 scripts/test_engines_local.py` 完整通过：合成 Debian 系统包 49 条、选定 Node 依赖 5 条、Docker 与 OCI 归档各 49 条且相同镜像跨格式去重；重复系统检查不重复，修改快照拒绝，模拟麒麟发行版明确失败，缺失输入拒绝。Nuclei/ZAP 既有回环夹具各 4 条。计数基于本机当前漏洞库；没有连接真实服务器、Docker/containerd daemon 或 Kubernetes API。
- 浏览器实际提交 rootfs 夹具任务，完成后查看系统包发现项：显示稳定来源、采集时间、组件、安装/修复版本，`lab-a/os` 筛选共 49 条；前端无 console error。原始证据留在本机私有临时目录，截图在本机可视化目录，未提交资产或结果。
- 已知边界：只实测合成 Debian / Node / 镜像；CentOS 7 RPM 实际识别、银河麒麟厂商源、源码安装中间件、国产数据库产品级检测、运行内核/进程/容器卷仍待专项适配和指定服务器验证。CentOS 使用 RHEL 公告的限制见官方文档；不能伪造发行版来补覆盖。Java 索引默认尚未准备，后续单独补齐。说明见 `docs/linux-server-scan.md`。

## 2026-10-19：离线 Java 索引与已部署应用

- 新增 `make engines-java` / Updater `--with-java-db`，通过锁定 Trivy 的 `--download-java-db-only` 显式下载 Java 组件索引；主漏洞库仍用于 CVE 匹配。实际 Java OCI 压缩层约 940 MiB，展开索引约 1.5 GiB；与主库合计约 3 GiB。
- Updater 本地准备改为流式复制、哈希、fsync 和私有暂存发布，避免把大库组装成内存 ZIP 或写进 Server 数据库。沿用不可覆盖版本、完整性核对、独立激活；失败/取消不切换 CURRENT。网页 ZIP 仍限 256 MiB，单文件 4 GiB、总展开 8 GiB 的限制均保持。支持完整缓存目录的离线准备，实际 `--skip-db-download` 安装并激活通过。
- 实测修正两个固定版本行为：Trivy filesystem 禁用 JAR/Go 二进制分析，需要 `rootfs --pkg-types library`；Go 默认按执行权限筛文件，需要固定 `--file-patterns gobinary:.*` 读取选中的非执行 ELF。新增 `artifact` 任务类型，API/OpenAPI/前端同步；不授予执行权限、不运行输入文件。锁文件与部署产物选错模式明确拒绝，混合应用采集自动拆为两个独立输入。
- Java 索引缺失的部署目录任务回报可操作的失败提示；节点状态区分主库和 Java 索引文件。采集脚本改为 Python 3.6 语法可用，SQLite RPM 一致备份要求 3.7+；旧解释器实际运行仍待目标环境验证。
- `make build`、`make lint`、`make test`（race、采集工具 9 项测试）通过；原有 9 组普通业务回归再次通过；前端 Server/Demo 构建、OpenAPI 四种输入枚举核对通过；Linux amd64/arm64、Windows amd64 交叉编译通过。`make verify-flags` 实测 Nuclei 23 / Trivy 20 / ZAP 7 个参数。
- `SCANNER_EXPECT_JAVA_DB=1 LAB_ENV=isolated python3 scripts/test_engines_local.py` 完整通过：Java 元数据 JAR 7 条（含预期 CVE-2021-44228）、Node 锁文件 5 条、合成 Debian 系统包 49 条；含相同 Java 元数据的 Docker/OCI 归档各 56 条并跨格式去重；Linux amd64/arm64 两个自建 Go ELF 均实际分析构建信息。没有执行夹具程序、加载脆弱库字节码、访问 Docker/Kubernetes 或真实业务服务器。
- 浏览器实际选择“已部署应用 / 中间件”、提交 Java 夹具任务并观察完成；筛选该输入仍为 7 条，重复检查保留首次时间；严重级别筛选及安装/修复版本展开正常。前端无 console error。测试实例已与用户数据库隔离，证据保留在本机私有目录。
- 新失败路径测试覆盖 Java 数据缺失、缓存链接、超限稀疏文件、取消、不可覆盖版本、CURRENT 保持、混合输入模式和时间窗取消语义；没有新增 Go/npm 依赖或修改 CI 工作流。
- 本地数据已具备 Java/Go/Node/系统包/镜像的通用分析链路；真实 CentOS 7、银河麒麟厂商公告源、具体中间件及国产数据库专项识别仍未完成。完整 Nuclei CVE 模板库、Kubernetes 自动接入与生产部署不在本次实现中。不能把合成夹具计数当真实资产结果。

### 同日补充：混合应用分流覆盖修复

- 合成夹具复现：根目录与已有 `artifacts/` 下的同名 JAR 在原地分流时发生覆盖，采集成功但嵌套内容丢失；已有 `dependencies/` 下的同名锁文件也受同一问题影响。改为在输出暂存目录内的独立目录分流，保留各文件的原相对路径，完成后替换组件目录；整个输出仍在最后原子发布，异常由现有清理逻辑移除暂存内容。
- 新增回归保留根/嵌套同名 JAR 和锁文件的全部内容及快照 SHA-256，并模拟分流中途存储失败，确认无输出发布、无暂存残留。开发先运行新增回归确认旧实现失败，修复后 `PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_collect_linux_inputs.py -v` 的 11 项测试通过；未运行全量引擎测试。
- 分工记录：本轮最初方案复核因高阶模型容量限制改由 GPT-5.6 Sol 只读执行；开发修复使用 GPT-6.1 Sol，独立验收使用 GPT-6 Sol 与 GPT-6 Luna。后续默认分工已按 Sol/Luna 调整，见 `AGENTS.md`。
- 混合目录覆盖修复后，GPT-6 Sol 独立复现并核对根目录、`artifacts/`、`dependencies/` 中同名 JAR/锁文件的全部字节及 SHA-256 清单；Python 11 项和完整本机引擎夹具均通过。证据目录位于本机私有临时目录，未写入仓库。
- GPT-6 Luna 独立运行 `LAB_ENV=isolated go test -tags=lab ./... -run '^$'`，全部包编译通过且未运行测试；同时确认所有 `PrepareDefault` 调用使用新签名，并复核 Go ELF 必须逐个显式选择的说明与命令行帮助。

## 2026-10-19：报告能力、资产画像与契约同步

- 依据 `report-capability-plan.md` 的已确认决策,同步 AGENTS、架构和产品方案:在明确授权目标内允许有界端口发现、服务识别与只读检查,不再逐端口申请审批;当前仍仅支持数字 IP,不声称域名 Server 固定解析已经实现。排除/隔离优先、无主机扩展、无口令猜测与默认口令尝试。方案 2.4 修正为 ICMP 未响应仅表示未知,继续 TCP 检测。
- SQLite 画像/服务/入口、发现元数据、知识库/策略、任务观察与报告快照/队列已接入;PostgreSQL 只新增 0004、保留已应用迁移,JSON 保持 TEXT。四迁移共 27 张业务表加 journal;静态脚本表名/版本核对与 `bash -n scripts/check-postgres-schema.sh` 通过。未连接 PostgreSQL 执行迁移,PG RuntimeStore adapter 尚未实现。
- OpenAPI 同步新路由与资产/任务/发现/报告类型,Worker 回报上限 32 MiB、报告快照 32 MiB、文件 64 MiB。Ruby YAML 解析与全部 schema `$ref` 核对通过,当前 54 个路径、46 个 schema;这不是生产节点鉴权/TLS验收。
- 文档/契约开发代理实际运行 `go test -race ./internal/reporting ./internal/repo` 和 `go test -race ./internal/findings ./internal/portprobe ./internal/executor`,全部通过;`git diff --check` 通过。报告覆盖 CVSS 边界、登录入口分计、稳定指纹去重、三格式公共内容/八章八表、TOP 截断、公式文本、冻结模板和任务历史观察、失败重试与恢复。端口/识别/配置检查使用假拨号器及回环服务,未对真实业务目标扫描。
- 知识库仅支持公开来源整理的规范 JSON 与自建中文内容,不自动导入 OSV 原始格式,不自动接入 CNNVD/CNVD。通用组件识别与版本推断不能证明 CentOS/麒麟、国产数据库或所有厂商产品覆盖。HTTP 预检/代理/原生检查共享端点请求预算及强度限速;TLS 隧道模板仍需模板白名单与引擎限速共同约束。
- 使用路径见 `docs/product/report-usage.md`,R1–R6、HTML/Word 八章、Excel 八表清单见 `docs/product/report-checklist.md`。真实隔离靶机和排除端口抓包、Word/Excel 原生软件视觉排版、PostgreSQL 实例、大规模内存/耗时与具体厂商覆盖均待环境验证。本轮未读取或提交参考报告的真实地址、资产、结果。
- 本轮约定方案 GPT-6 Sol、开发 GPT-6.1 Sol、独立验证 GPT-6 Luna;上述文档/契约开发检查由 GPT-6.1 Sol 实际执行。独立验证与最终全仓库门禁结果由协调代理另行记录,不以开发报告代替独立验收。

## 2026-10-19：合并后最终本地复核

- 修正 Nuclei 3.11.1 参数互斥错误：`-dr` 与 `-fhr` 同时传入会导致引擎拒绝启动，现仅传硬规则要求的 `-fhr`；`make verify-flags` 与隔离回环 Nuclei/ZAP 运行均通过。
- 远端并入的报告范围回归、同主机多端口影响资产去重、PostgreSQL 只读资产/范围适配和迁移工作流已通过 `make test` 的 race 测试；PostgreSQL 云端实例仍由 GitHub Actions 负责实际执行。
- 第三方 GitHub Actions 已固定到提交 SHA，并在行尾保留版本注释；YAML 解析通过，未使用 `pull_request_target`。
- 当前代理实际运行并通过：`make build`、`make lint`、`make test`、`make verify-flags`、`make test-local`、`make test-engines-local`、Server 模式前端构建、Windows/Linux/macOS 交叉编译，以及 HTML/XLSX/DOCX 合成报告结构检查。
- 仍未连接真实业务服务器、真实 CentOS 7/银河麒麟主机、生产 PostgreSQL、Microsoft Word/Excel 或生产网络围栏；本地引擎回归仅使用回环夹具、临时数据库和本地漏洞库，未读取真实资产或扫描结果。

## 2026-10-20：Nuclei 范围代理默认端口规范化

- HTTP(S) 代理请求缺少 URL 默认端口时，仅按 scheme 补齐 80/443 后与已授权的精确 IP:端口比较；HTTPS CONNECT 仍要求显式端口，不解析域名、不扩大授权集合。
- Worker 对代理拒绝记录固定原因类别和计数，不记录目标地址或原始请求。
- `go test -race ./internal/executor -run 'TestScopeProxy'`、`go test -race ./internal/executor`、`make build`、`make lint` 通过。另用本地假拨号器验证省略 HTTP 默认端口的请求只拨向匹配的授权端点；没有从该回归夹具连接外部主机。

## 2026-10-20：规则版本两阶段 GC 文件实现（隔离测试）

- 新增 `GCFiles.Quarantine` 和 `Delete` 两个显式入口，每个阶段重新读取本地 CURRENT、可信备用/退役状态和 Server 本节点的 RUNNING 数量。使用 Go 1.26 `os.Root` 限定文件操作目录，拒绝路径穿越、链接、目录替换、目标碰撞和查询期间的状态变化。
- 隔离后原子发布版本、节点、退役时间和隔离时间记录；缺失、损坏或不匹配的记录不允许自动删除。取消、查询失败或出现新保护状态时保持已有文件。删除部分失败不代表回滚，记录丢失的残留隔离目录需人工核查。
- 开发侧运行 `go test -race ./internal/versionmgr ./internal/scheduler` 通过；独立验证实际运行 `go test -race -count=1 ./internal/versionmgr ./internal/scheduler ./internal/workerfence`、对应包的 `go vet` 和目标文件 `git diff --check`，均通过。
- 方案使用 GPT-6 Sol，开发使用 GPT-6.1 Sol，独立验证配置 GPT-6 Luna。检查只使用临时目录和模拟 Server；未重启运行中的平台，未修改运行数据库、规则盘、SSH、靶机或网络。
- 这两个入口尚未接入真实 Updater/Node API，不启用自动回收。部署依赖单 Updater 独占规则根目录、完整激活与回收协调、Server 不再为退役版本发放新租约；真实进程联调、跨系统竞态、Windows 实机和断电持久性仍待验收。

## 2026-10-20：外部规则包 Ed25519 验签（隔离测试）

- Updater 新增包外受信公钥配置；普通 Import/Fetch/Activate 验证原始 manifest 与独立 raw64 Ed25519 签名，缺少信任、签名错误或内容不符均拒绝，CURRENT 不变。不会从包内取得公钥，也不会给已有 unsigned 版本自动补签。公钥仅支持严格 PKIX Ed25519 PUBLIC KEY PEM，受大小、普通文件、路径和目录身份检查约束。
- 本地 PrepareDefault 通过同一 Manager 实例中绑定根目录、版本和摘要的一次性记录执行专用激活；普通导入不能产生该记录，重启或失败尝试不会继承能力。历史无签名数据仍可只读展示，但不会声称已验签。页面依据实际签名字段显示状态，未验签版本禁用普通激活/回滚。
- Go 单测运行时生成测试密钥；Python/OpenSSL 打包的 raw64 签名已实际由 Go Import/Activate 接受。失败路径覆盖缺签名、签名长度/公钥错误、manifest 原始字节变化、激活前修改、旧版本冲突、本地准备能力复用、目录大小写别名，以及私钥混入打包目录或硬链接输入。
- 开发和独立验证均运行 `go test -race -count=1 ./internal/rules ./internal/versionmgr ./internal/bootstrap ./internal/executor` 通过；独立 `go vet` 与差异检查通过。主代理实际运行 `go build ./...`、`make lint`、`make test`（全仓 race 和 11 项 Python 采集测试）、前端 `tsc --noEmit`、`bash -n scripts/dev.sh`，均通过。编译未覆盖运行中的 dist，未执行 make dev、真实扫描、规则导入或规则切换。
- 分工：方案 GPT-6 Sol、开发 GPT-6.1 Sol、独立验证配置 GPT-6 Luna。只修改启动脚本的可选公钥文件路径传递，未配置或重启当前平台。完整业务实例/真实签名包联调、GitHub 云端执行、密钥轮换和完整引擎兼容矩阵仍待验收；无副作用的 `--status` 只报告模式，不验证运行配置。

## 2026-10-20：SSH 指定部署目录 Java/Go 应用（隔离测试）

- 按用户选择实现 Worker 本地 profile 的 `apps`，每项显式配置别名、具体部署目录及 Java/Go 类型。沿用同一数字 IP、明确选中且开放的 SSH 端口和固定 SSH 安全参数；无 apps 不增加连接，排除范围之外不尝试采集。原始部署路径不进入 Server 报告。
- Python 通过有界安全 token 接收配置，以目录句柄、O_NOFOLLOW、文件身份复核进行有界读取。每文件独立快照，Go 校验 tar 路径、类型、数量、SHA-256 与固定结构；Java ZIP 路径/中央目录/展开/嵌套均有预算，ELF 必须通过 Go build info。超限、空目录、变化、链接和不支持的产物明确失败，不静默截断。
- 每个文件顺序执行 Trivy，扫描前后检查快照；只有 Class=lang-pkgs、Type=jar/gobinary、非空 Target 才计为已分析，零漏洞可以完成。类型依据锁定 Trivy v0.76.0 的官方 [analyzer 常量](https://github.com/aquasecurity/trivy/blob/v0.76.0/pkg/fanal/analyzer/const.go)、[报告结构](https://github.com/aquasecurity/trivy/blob/v0.76.0/pkg/types/report.go) 和 [JSON writer](https://github.com/aquasecurity/trivy/blob/v0.76.0/pkg/report/json.go)，未新增引擎参数。
- Worker/Server/清册贯穿固定应用状态及选中/已分析计数，Server 限定最多 8 个别名、每项 16 文件、总计 32 文件；完成状态要求每项非空且全部分析。失败与暂停保存覆盖状态和系统包状态，失败报告不插入部分漏洞；兼容旧 Worker 无应用字段，界面明确显示旧任务没有应用覆盖记录。指纹继续使用稳定主机与包字段。
- 独立首轮回归发现 Java ZIP 的 `../escape` 可绕过单独 path.Clean 检查，开发显式拒绝父路径前缀后独立复验通过；未放松原检查。最后增补 C1 控制字符拒绝与种子回归。
- 主代理全仓 `make test`（race 与 18 项 Python 合成测试）、`make lint`、`go build ./...`、web 下 `tsc --noEmit`、OpenAPI YAML/全部本地 schema 引用检查、`bash -n scripts/dev.sh` 和差异检查通过。新增目录解析与 Trivy 类型门槛各实际 fuzz 2 秒通过。Windows amd64、Linux arm64 的 `go build ./...` 交叉编译通过，编译未生成或覆盖 dist/web/dist。
- 独立验证实际运行 `go test -race -count=1 ./internal/sshcollect ./internal/executor ./internal/taskflow ./internal/repo`、对应包 vet、无输出构建、web 类型检查、Python 18 项与差异检查，均通过。分工：方案 GPT-6 Sol、开发 GPT-6.1 Sol、独立验证配置 GPT-6 Luna；协调代理完成协议/持久化/前端贯穿与全仓检查。
- 上一轮代码验收未重启服务、修改当前运行数据库/规则/SSH 配置/靶机/网络，也未执行真实 SSH、扫描引擎或 lab。本批拒绝根设备之外的独立挂载目录，无法通过设备号区分同设备 bind mount；ZIP64、分卷、较大归档及超限目录仍不支持。完整应用安全覆盖、真实凭据/索引/产物联调需后续隔离靶场验收。

### 2026-10-20：SSH 应用隔离靶场验收续测

- 重新构建并启动最新 Server、Worker、Updater 和 Server-mode 前端；`/healthz`、`/readyz` 正常，当前本地服务继续使用既有 SQLite、规则目录和 SSH profile。
- 发现 `scripts/dev.sh` 在 `set -u` 下展开空的可选参数数组会导致启动失败；改为按是否配置 SSH 公钥和 SSH profile 分支启动，并用带 SSH profile、无 SSH profile 两种方式回归通过。修复已提交为 `db41202` 并推送到 `main`。
- 在隔离 OrbStack 靶机中放入合成 Go ELF 和 Java JAR，使用一次性临时 Server/SQLite 验收真实 SSH 采集链路。Go 路径任务完成，应用覆盖计数为选中 1、分析 1；系统包、SSH 服务和 HTTP 服务阶段也完成。靶机临时采集目录在任务结束后清理。
- Java 路径任务成功完成 SSH 采集，但由于当时规则目录缺少 Trivy Java 索引，任务以 `analysis_failed` 结束，应用计数为选中 1、分析 0；没有插入部分成功结果，验证了失败即关闭行为。该条记录保留为缺索引失败路径，成功路径见下方 Java DB 隔离复验。
- 独立运行 `go test -race -count=1 ./internal/versionmgr ./internal/scheduler ./internal/workerfence`、`go vet ./...`、`bash -n scripts/dev.sh` 和差异检查，均通过。未运行全端口扫描，也未修改主运行实例的数据库、规则库、网络或 SSH 凭据。
- 提交 `798f832` 的 GitHub CI 已云端完成并通过全部矩阵。随后以 `db41202` 为基线触发的 `Build Offline Vulnerability Data` 也已完成：8 个规则文件校验通过，签名步骤输出 `Signature Verified Successfully`，并上传 `vulnerability-data` 制品。此前历史运行早于签名步骤，未作为当前签名验收证据。

### 2026-10-20：隔离靶机 Java 内容补齐

- 在隔离靶机的明确部署目录中刷新合成 Java JAR：包含一个不执行的示例 class、Manifest，以及用于离线组件识别的 Maven 元数据；文件保持普通只读权限，未启动 Java 进程、未发起网络请求，也未加入仓库或扫描结果。
- 容器内回读并校验 JAR 中的 class 与元数据条目，确认采集输入不再是只有元数据的空壳夹具。此前 Java SSH 采集的失败路径记录仍保留：当前活动规则版本缺少 `trivy-java.db` 时，应用阶段必须回报 `analysis_failed`，选中项不能计入已分析，也不能显示成“无漏洞”。
- 用一次性临时 Server/Worker 重新回归当前夹具：Go 应用链路仍为 `completed` 且选中/已分析均为 1；Java 目录已选中 1 个文件并完成 SSH 采集，但因 Java 索引缺失以 `analysis_failed` 结束、已分析为 0。临时数据库、输入和日志均未写入仓库。
- 当前开发进度：Java 靶机输入已准备；SSH 有界采集、缺索引失败闭环和带 Java DB 的隔离成功路径均已验证；活动规则已切换到包含 Java DB 的版本，但该版本由本地显式准备产生，签名状态仍为未验签。该状态不代表真实业务 Java 应用或完整中间件覆盖已验收。
- 本次只验证容器文件内容和权限，没有停止正在运行的平台服务、修改主运行数据库/规则盘/SSH 凭据或扩大扫描目标。

### 2026-10-20：Java DB 隔离成功路径

- 使用下载目录中的 `vulnerability-data.zip`，先校验 `SHA256SUMS` 和 manifest 内 8 个文件的 SHA-256；包内包含 `manifest.json.sig`、主 Trivy DB 和 Java DB。GitHub Actions 已对该制品完成 Ed25519 签名验签；本机未配置对应公钥，因此没有把本次解包动作表述为再次本地验签。
- 规则包只解包到临时规则根，没有替换当前活动 `vuln-data`。一次性临时 Server/Worker 使用该规则版本和隔离靶机的显式 Java 应用目录重跑，SSH 采集、Java 类型识别和 Trivy 结果门槛均通过；任务为 `COMPLETED`，Java 应用状态为 `completed`，选中 1、已分析 1。Go 应用链路同时回归通过。
- 本次成功路径只验证合成 Java JAR 的有界采集与离线版本匹配，不代表真实业务 Java 应用、Tomcat/Kafka/Nacos 配置或完整主机安全审计。当时运行中的平台仍指向没有 Java DB 的旧规则版本，随后已按下方记录完成规则切换；活动版本的签名状态仍须按切换方式解读。

### 2026-10-20：活动规则切换与平台重启

- 停止原有 Server、Worker、Updater 进程后，使用下载制品中已通过哈希校验的主库和 Java DB 缓存，调用 Updater 的 `--prepare-engines --with-java-db --skip-db-download` 完成本地显式准备和切换；没有直接覆盖规则目录，也没有使用网页大 ZIP 导入路径。
- `CURRENT` 已切换到新规则版本，活动目录同时包含 `trivy/db` 与 `trivy/java-db` 的数据库和 metadata；平台以原 SSH 配置重启，Updater 同时加载包外 Ed25519 公钥，`/healthz` 与 `/readyz` 均正常。
- 该本地显式准备流程只验证输入缓存和文件完整性，不继承下载包中的 `manifest.json.sig`；因此活动版本的 `signatureVerified` 保持 `false`。后续若要求页面显示已验签激活，需要增加适用于大体积预安装制品的受信安装流程，不能把本次本地准备结果当作普通签名导入。

### 开发期间原测试状态补充

- 本轮结束前只读查看任务清册，原有全端口任务已显示“已完成”。这只确认平台终态，不据此宣布 V5 全部验收项通过，也不算新增应用采集能力的实机验证；结果完整性和覆盖仍待单独复核。未将地址、任务 ID 或扫描发现写入本文。

### 2026-10-20：PoC #6 时间窗暂停与恢复集成回归

- 新增本地 Server/Worker/SQLite 集成测试：第一次领取将任务硬截止压缩到几十毫秒，Worker 到点回报 `PAUSED_WINDOW`；Server 不写入发现项。
- 调用 `RuntimeStore.Tick` 后任务回到 `PENDING`，Worker 再次领取并完成，最终只保存一个发现项；重复提交同一完成回报仍保持单条结果。
- 该回归只使用临时数据库、回环 HTTP API 和文档保留地址；没有连接外部目标，也没有改变正在运行的平台实例。真实长任务、多块租约、节点 TLS/令牌和进程级强杀仍待隔离验收。

### 2026-10-20：PoC #5 连续未检出与自动 FIXED 状态机（本地回归）

- Worker 回报新增完整性、规则执行引擎集合和冻结规则版本元数据。Server 仅在任务为 `COMPLETED`、完整执行授权范围、至少一个漏洞规则引擎成功执行、且回报规则版本匹配任务冻结版本时处理未检出计数；端口探测、旧 Worker 回报、失败/暂停、规则版本不匹配和范围外发现项不会触发状态收敛。
- 当前活动策略新增 `fixedThreshold`（1–3，默认 1），在任务创建时冻结；活动发现项达到阈值后标记 `FIXED` 并记录 `resolvedAt`，再次检出恢复为 `REOPENED`、清零计数。`FALSE_POSITIVE` 与 `ACCEPTED_RISK` 不受自动状态机影响。自动综合扫描按实际成功执行的 Nuclei/ZAP/Trivy 引擎集合和 SSH/应用采集状态决定是否具备完整性。
- 新增仓储 race 测试覆盖首检、完整缺失、重现、旧元数据、失败、版本不匹配、范围隔离和阈值 2；实际运行 `go test -race ./internal/repo ./internal/taskflow ./internal/executor -count=1` 通过。
- 本批仅使用临时 SQLite、合成回报和文档保留地址，未连接外部网络或生产资产。真实靶机的中断/熔断抓包、节点认证和跨进程引擎回报仍待 lab 验收，不能据此宣称 PoC #5 已完成实机验收。

### 2026-10-20：资产 CSV 预览与事务确认（本地回归）

- 新增 Assets 页模板下载、文件上传、逐行预览和明确确认闭环。API 为 `GET /api/v1/assets/import/template`、`POST /api/v1/assets/import/preview`（原始 `text/csv`）和 `POST /api/v1/assets/import/confirm`（仅 `previewId`）。管理员/安全工程师及现有 CSRF 请求头限制同时生效；viewer/ops_approver 不可导入。
- CSV 严格采用 UTF-8 无 BOM 和固定顺序表头，限制 1 MiB / 1000 条数据记录；支持数字 IP host 与现有 image_repo 格式，name 可省略，拒绝任何端口列。非法行、文件内重复、已有资产逐行给原因；任何错误阻止整批确认。
- SQLite 动态初始化新增 `asset_import_previews`，仅暂存全有效规范化行、当前用户和 15 分钟有效期。新预览替换同用户旧预览；确认事务先原子领取预览，再按资产唯一约束整批插入 assets/profile 和仅含数量的审计，失败全部回滚。成功后清空暂存行，重复/过期/跨用户确认拒绝。
- 新增表驱动解析/权限/CSRF测试、解析 fuzz 种子、预览资产/profile/审计零写入、确认重复/过期/替换/同用户限制、后发资产冲突整批回滚和并发确认一次成功回归；Pinger 为失败即报错替身，没有连接目标或启动扫描。前端回归覆盖空文件/体积、显式勾选、错误预览和过期确认门禁。
- 实际运行 `go test -race ./internal/assets ./internal/api`、`go vet ./internal/assets ./internal/api`、`node web/src/pages/Assets/import.test.mjs`、`npm --prefix web run build`、`make build`、`git diff --check` 及 Ruby YAML 解析通过。全仓门禁由协调代理另行记录。
- 待验收：真实浏览器文件选择和操作体验；PostgreSQL 资产写入、导入历史查询和 CSV 导出尚未实现。本批不改变既有 Server 清册可达性后台轮询，确认后的新主机可能在后续正常轮询中被检测；导入端点自身没有 DNS/Ping/扫描调用。测试只使用临时 SQLite、文档保留地址和示例镜像地址。

### 2026-10-20：漏洞分类筛选 URL 状态（前端回归）

- `/findings` 的六项分类筛选直接从 React Router 查询参数派生；筛选修改使用 replace，刷新及前进/后退读取当前路由，避免组件内第二份分类状态覆盖导航结果。已有筛选交集和本地文本搜索继续生效。
- 纯函数白名单解析非法/重复枚举和布尔值为默认值，规范化时省略默认筛选、保留无关参数；自由文本不写 URL，已有 `q` 在当前页面规范化时移除，不能据此宣称进入页面之前的历史已清除。
- 实际运行 `node web/src/pages/Findings/filters.test.mjs`、`npm --prefix web run build` 和 `git diff --check`。测试使用文档保留地址作为隐私隔离样例，覆盖各合法值、异常值、重复键、组合往返、无关参数保留、输入不变性及规范化幂等性。真实浏览器交互验收尚未运行。
- 本批仅修改前端与文档；没有变更 API/数据库/扫描边界或连接目标。


### 2026-10-20：单项漏洞指派与追加备注（本地回归）

- 新增最小指派候选、单项指派/清除和追加式备注 API；新端点均要求登录，写操作沿用 admin/security_engineer 与 CSRF 限制。RuntimeStore 在写事务内再次校验执行者和被指派者启用状态/角色，不依赖可竞争的预检查；缺少账户表或认证配置时关闭操作。
- Finding 增加独立处置人 ID/名称快照，扫描合并保留；SQLite 增加 finding_assignment_events 与 finding_notes。指派、历史/备注和审计原子提交，审计只写关联 ID、状态或字节数，不复制备注正文；备注是 1–2000 UTF-8 字节的单行纯文本，只追加，无编辑删除入口。
- 抽屉支持候选选择、清除指派和追加备注，作者/时间和正文按文本显示；演示模式不伪造服务端持久化。没有扫描调用或目标连接，也不改变漏洞状态或资产 Owner。
- 实际运行聚焦 race 回归 `go test -race ./internal/repo ./internal/api -run 'Finding(Assignment|Notes|Work|DispositionAPI)' -count=1` 及前端构建通过；覆盖无效/停用/只读角色、空值/UTF-8 字节/控制字符、指派扫描保留、并发追加、审计失败全部回滚、权限/CSRF 和只读读取。全仓门禁由协调代理补记。
- 待验收：真实浏览器操作、指派历史查询 UI、备注分页和 PostgreSQL；本批未实现批量、复测或通知。

- 独立验证修正：候选列表进一步限制为管理员/安全工程师，viewer/ops_approver 返回 403；只读用户仍可加载备注。前后端备注校验同时拒绝 Unicode 行/段落分隔符 U+2028/U+2029，补充 API/仓储/前端回归。指派清除约定为空串，null/缺省字段拒绝，已写入 API 说明。

### 2026-10-20：批量漏洞状态处置（本地回归）

- 新增 `POST /api/v1/findings/batch-disposition`，仅处理显式选中的 1–100 个不同 ID 和原状态快照。单项与批量共享接受风险字段及状态流转校验，固定 ID 顺序预读、CAS 更新、逐项 finding_events 和审计全部处于一个 SQLite 事务；任一缺失/状态变化/非法流转/写入失败则整批回滚。
- UI 增加表格行选择、已选计数、清空、批量状态选择及含 ID/原状态的确认框。跨分页/筛选保留明确选择和状态快照；状态漂移阻止提交，服务端继续校验；接受风险统一填写原因/期限。失败保留选择，成功合并返回记录并清空，演示不保存。没有扫描调用，不改变指派/备注/指纹或任务状态。
- 已运行 repo/API 聚焦测试，覆盖空/超限/重复/不存在 ID、未知 JSON 字段、旧状态、FIXED/误报/活动接受风险限制、审计/事件/CAS 失败回滚、并发只成功一次、角色/CSRF 和既有无账户本地语义；新增 API 本地语义 race 回归通过。`node --test web/src/pages/Findings/*.test.mjs`（5 项）、`npm --prefix web run build`、`make lint`、`make build`、Ruby YAML 解析和 `git diff --check` 通过。`go test -race ./internal/repo ./internal/api` 全包通过（repo 87.396 秒、api 31.399 秒）。
- 批量方法不在事务外触发到期改写；自动到期仍由既有 Tick/列表/单项补查完成，保证失败批次完全无副作用。真实浏览器交互、批量指派、单项复测、到期通知和 PostgreSQL 运行时仍待完成。

## 2026-10-21 — 单项漏洞复测（代码与单元测试）

- `POST /api/v1/findings/{id}/retest` 只复用已完成父任务的冻结输入；独立 Nuclei/ZAP 任务缩小到当前发现项目标，自动综合扫描使用父任务已解析的精确端口集合。
- Server 在事务中重新校验登记资产、审批/排除/隔离端口、规则包和时间窗，写入发现项—复测任务关系及不含目标数据的审计记录；活动复测重复提交返回冲突。
- 合成发现项、误报、父任务未完成、范围外目标和不支持引擎均有失败路径测试；API 覆盖认证、CSRF、角色和严格 JSON。
- 已运行：`go test -race ./internal/repo ./internal/api`、`make test`、`make lint`、`make build`、`node --test web/src/pages/Findings/*.test.mjs`、`npm --prefix web run build`、Ruby YAML 解析和 `git diff --check`。真实浏览器点击和真实 Worker 执行仍待隔离环境验收。
## 2026-10-21：总览风险评分、趋势与下钻

- 总览新增 0–100 风险评分、有风险资产数、7/30/90 天活动漏洞趋势、风险业务组和风险资产表；严重度与检测口径数字链接到漏洞筛选。风险评分规则、活动状态和接受风险折扣见 `docs/product/risk-score.md`。
- 漏洞页新增业务组和资产 ID 的 URL 筛选，保留刷新、前进/后退和筛选标签移除语义；仍只在页面已加载的全量发现项上计算，未新增扫描目标、端口或引擎调用。
- `node --test web/src/pages/Findings/*.test.mjs`、`node web/src/pages/Dashboard/presentation.test.mjs`、`npm --prefix web run build`、`make test`、`make lint`、`make build`、Ruby YAML 解析和 `git diff --check` 均已通过。真实浏览器点击下钻和服务端大数据量聚合仍待独立验收。

## 2026-10-21：报告 CSV/JSON 输出

- 报告格式扩展为 CSV 与 JSON，并继续复用同一冻结快照、队列、重试和历史记录；CSV 是漏洞详情平面文件，JSON 包含完整资产、任务、发现项、汇总和范围快照。
- CSV 对以 `=`, `+`, `-`, `@` 开头的单元格增加前缀，避免导入电子表格时被当作公式；JSON 和 CSV 均通过现有 64 MiB 生成上限和离线渲染路径，不调用扫描器或外部网络。
- 已补充渲染、仓储格式复用、API 下载 Content-Type 和格式校验测试；`go test -race ./internal/reporting ./internal/repo ./internal/api`、`make test`、`make lint`、`make build`、前端生产构建、Ruby YAML 解析和 `git diff --check` 均已通过。真实浏览器下载、Office 原生打开和大数据量性能仍待环境验收。

## 2026-10-21：管理员审计日志只读查询

- 新增 `GET /api/v1/audit-logs` 和 `/audit` 页面，仅管理员可查询；支持操作者、动作、对象类型、RFC3339 时间范围和 1–200 条分页筛选，列表按时间和 ID 倒序返回。
- API 只返回稳定审计投影（记录 ID、操作者、动作、对象类型/ID、时间），刻意省略历史 `detail`，因此不会通过查询页面暴露目标地址、凭据或备注正文；没有编辑、删除或敏感导出入口。
- 新增仓储过滤/排序/分页及 API 认证、角色、非法参数和 detail 不返回测试；前端 helper 覆盖筛选裁剪和分页偏移。`go test -race ./internal/repo ./internal/api`、`make test`、`make lint`、`make build`、前端生产构建、Ruby YAML 解析和 `git diff --check` 均已通过；真实浏览器权限交互、大数据量查询和 PostgreSQL 运行时仍待环境验收。

## 2026-10-21：定时计划历史运行

- 定时计划触发现在写入独立 `schedule_runs` 表；成功触发关联生成的任务，任务状态查询时实时映射，非法触发写入失败记录并停用该单次计划。删除计划不删除历史，任务被删除后历史状态显示为 `DELETED`。
- 新增 `GET /api/v1/schedules/{id}/runs`，限制 1–200 条分页，仅返回触发时间、状态、任务 ID 和安全错误摘要；任务中心增加“历史运行”只读弹窗，未返回目标、输入路径或引擎输出。
- 仓储/API 测试覆盖成功、失败、分页、状态映射和删除计划后保留历史；`go test -race -count=1 ./...`、18 项 Python 测试、`make lint`、`make build`、前端生产构建、OpenAPI/Workflow YAML 检查和 `git diff --check` 均已通过。PostgreSQL 运行时和真实浏览器交互仍待验收。

## 2026-10-21：资产清册 CSV 导出

- 新增 `GET /api/v1/assets/export` 和资产页“导出 CSV”。导出复用当前地址、名称、业务组、负责人搜索条件；未传筛选时导出完整清册。
- CSV 只包含资产登记稳定字段（标识、类型、地址、名称、核心标记、业务归属、申请/排除/隔离端口、可达性状态和登记时间），不包含服务详情、登录入口、请求/响应证据或引擎输出。以 `=`, `+`, `-`, `@` 开头的单元格会加前缀，避免表格软件执行公式。
- 新增 API race 测试覆盖未登录拒绝、筛选隔离、重复/超长筛选拒绝、CSV 表头、公式前缀和敏感明细不导出；前端使用同源下载并在演示模式禁用服务端导出按钮。导出不会触发 Ping、端口探测、扫描器或外部网络。
- 待运行门禁：`go test -race ./internal/api`、`npm --prefix web run build`、`make test`、`make lint`、`make build`、OpenAPI/Workflow YAML 检查及 `git diff --check`。真实浏览器下载、PostgreSQL 运行时和大数据量分页性能仍待验收。

## 2026-10-21：总览首次使用清单与待处置卡片

- 总览在 Server 模式且数据尚未完成首次闭环时显示“登记资产→发起扫描→查看结果”三步清单；演示模式不把预置 fixture 当作新用户。完成项从当前资产、非模拟任务和已完成任务推导，清单完成后自动隐藏。
- 新增待处置严重/高危卡片，只纳入系统/Web 且状态为 `OPEN`、`REOPENED`、`IN_PROGRESS` 的发现项；按严重度和最近发现时间排序，最多展示 5 条，数量徽标保留完整计数，链接带业务组与严重度筛选。接受风险、误报和已修复项不会进入卡片。
- `node web/src/pages/Dashboard/presentation.test.mjs` 和 `npm --prefix web run build` 已通过；纯函数覆盖待处置过滤、重新打开状态和总数。真实浏览器首次使用清单、卡片跳转和大数据量后端聚合仍待验收。

## 2026-10-21：自动综合扫描预置方案卡片

- 向导第 2 步新增“快速检测”和“标准检测”卡片。快速检测固定常见端口/温和强度；标准检测固定常见端口加可选自定义范围/标准强度。选择只修改已有产品参数，最终仍经过原端口范围、排除、时间窗和运维授权校验，不新增引擎参数或扫描目标。
- 复制旧任务和编辑定时计划保留已有冻结配置；确认摘要显示当前方案名称，用户可继续调整参数。未知方案值安全回退到快速方案默认值。
- `node web/src/pages/Tasks/wizard.test.mjs`、前端生产构建和 `git diff --check` 已通过。真实浏览器卡片可用性、5 次点击旅程和 Server 端大数据量性能仍待验收。

## 2026-10-21：总览后端聚合

- 新增认证接口 `GET /api/v1/dashboard/summary?days=7|30|90`。Server 聚合资产、任务、发现项和当前规则，仅返回计数、趋势桶、风险业务组/资产排行、最多 5 条待处置严重/高危摘要和规则状态；不返回证据、凭据、原始请求/响应或引擎输出。Server 总览按趋势窗口轮询该接口，任务清册仍单独加载。
- 聚合保持既有风险口径：系统/Web 才进入漏洞计数，接受风险按 25% 计入评分，FIXED/FALSE_POSITIVE 不计入活动风险，待处置只包括 `OPEN`、`REOPENED`、`IN_PROGRESS`。
- 新增 API race 测试覆盖认证、资产/任务聚合、空规则/空发现项、7 天趋势、非法/重复 days 参数，以及风险评分、资产去重和待处置投影；前端 Server 聚合客户端和 11 项页面纯函数测试、前端构建已通过。真实浏览器和 PostgreSQL 聚合仍待验收。

## 2026-10-21：扫描任务详情、日志与结果导出

- `/api/v1/tasks/{id}` 提供单任务最新安全投影，补充当前发现数和 Worker advisory progress；`/logs` 只从任务审计记录映射静态事件文案，完全省略原始 `detail`；`/export?format=json|csv` 只导出稳定任务/发现字段，排除证据、凭据、原始请求/响应和引擎输出。CSV 复用公式前缀转义，空发现任务仍输出完整表头宽度。
- 任务中心新增“详情”抽屉，显示概览、目标级状态、进度、结果摘要、安全只读日志和 JSON/CSV 下载；演示模式明确不读取服务端日志。既有取消、归档、复用和删除流程不变。
- API 测试覆盖未登录拒绝、详情状态/发现数、日志脱敏、JSON/CSV 下载、非法格式和公式转义；真实浏览器抽屉键盘/窄屏交互仍待验收。

## 2026-10-21：扫描任务手动暂停与恢复

- 新增 `POST /api/v1/tasks/{id}/pause` 和 `/resume`。暂停会清除 Worker 租约并进入独立 `PAUSED` 状态；Worker 下一次心跳看到非 `RUNNING` 状态后停止当前执行，时间窗 Tick 不会自动恢复。恢复只把任务送回 `PENDING`，领取时仍重新校验时间窗、资产授权、排除项和规则就绪状态。
- 任务详情和任务清册提供暂停/恢复入口，暂停前二次确认；取消仍是终止操作，归档/删除只接受终态任务。PostgreSQL 状态契约和 OpenAPI 枚举同步更新。
- 仓储测试覆盖暂停持久性、时间窗 Tick 不误恢复、恢复回队列和取消；API 测试覆盖认证后的暂停/恢复状态。真实 Worker 中途引擎停止和浏览器交互仍待隔离实验/真实浏览器验收。

## 2026-10-21：授权范围到期提醒与筛选

- `AuthorizedScope` 增加 Server 计算的 `expiryState`：批准授权按截止时间分为 `ACTIVE`、`EXPIRING`（七天内到期）和 `EXPIRED`，待审核/驳回/撤销返回 `NOT_APPLICABLE`；`isActive` 与该状态保持一致。
- `/scopes` 每 60 秒刷新一次，页面显示已过期/即将到期提示，并提供“全部期限、七天内到期、已过期”筛选。提醒只基于已保存的授权截止时间，不会发起网络探测或改变授权。
- Go 表驱动测试覆盖非批准状态、七天边界、过期和撤销；前端契约测试覆盖状态分类和筛选。独立通知中心、邮件/消息渠道和批量续期仍未实现。

## 2026-10-21：扫描方案目录与自定义方案持久化

- `GET /api/v1/scan-plans` 由 Server 返回“快速检测”和“标准检测”只读预置以及已保存的自定义方案；`POST` 可从预置复制，`PUT`/`DELETE` 只允许操作 `CUSTOM` 方案，预置方案不能被覆盖或删除。
- 自定义方案只保存产品级字段：端口策略、端口范围、排除范围、强度和已启用规则选择；Server 校验文本长度、端口范围、强度、重复规则和规则存在性，不接受引擎命令行参数或路径。任务创建仍重新校验并冻结最终范围。
- `scan_plans` 使用 SQLite 持久化并记录创建/修改/删除审计；已创建任务不依赖方案记录，删除方案不会改变历史任务输入。
- Go 目录/API/仓储测试覆盖预置只读、创建、修改、删除、预置冲突、无效范围和缺失规则；前端 14 项契约测试及生产构建通过。真实浏览器五次点击验收仍待执行。

## 2026-10-21：管理员密码重置

- 管理员可通过 `POST /api/v1/users/{id}/password-reset` 重置其他账号密码；服务端只保存 bcrypt 哈希，事务内撤销目标账号的全部旧会话并写入不含密码的审计动作。
- 密码仍限制为 12–72 字节；非管理员、缺少同源变更头、未知用户和无效长度分别拒绝，接口响应只返回用户投影。
- 账号仓储/API 测试覆盖新密码登录、旧会话失效、权限和 CSRF 失败；用户管理页增加“重置密码”表单。真实浏览器交互仍待执行。

## 2026-10-21：资产业务组与导入记录

- 新增 `GET/POST /api/v1/business-groups` 和 `GET /api/v1/assets/import-history`。业务组以 SQLite 资源持久化并统计当前资产数；新增资产、更新资产和 CSV 确认导入会自动登记缺失业务组，旧库初始化会从已有资产回填，不创建演示资产。
- CSV 确认与导入历史写入同一事务。历史仅保留 ID、操作者、成功数量、总行数和时间，最多查询最近 200 条；不保存或返回 CSV 行、地址、名称、端口或扫描结果。普通登录用户可读业务组/历史，业务组创建仍限 admin/security_engineer 并要求 CSRF。
- 新增仓储/API race 测试覆盖业务组名称控制字符/重复、资产计数、导入摘要隐私和 viewer 只读权限；前端新增业务组和导入记录页面及导航路由，生产构建通过。未改变扫描目标、端口授权、Worker 或引擎调用。

## 2026-10-21：批量漏洞指派与指派历史（本地回归）

- 新增 `POST /api/v1/findings/batch-assignment` 和 `GET /api/v1/findings/{id}/assignments`。批量接口只接受显式选中的 1–100 个不同发现项、目标指派人和每项当前指派快照；固定 ID 顺序执行，任一记录缺失、快照过期、目标账号停用/角色不符、CAS/事件/审计写入失败都会整批回滚。
- 指派历史使用独立 SQLite 表和稳定字段（发现项 ID、前后指派人 ID、操作者、时间），不复制账号元数据；单项和批量指派共用事务审计，扫描结果合并继续保留人工指派。
- 漏洞详情抽屉显示指派时间线，列表工具栏支持批量指派并在选择快照变化时阻止提交；失败保留选择，成功合并返回对象并清空选择。没有新增扫描目标、端口或引擎调用。
- 新增仓储原子性/历史测试、API 认证角色 CSRF/严格 JSON 测试、前端批量选择契约测试；OpenAPI、产品现状、路线图和 API 说明同步更新。`make test`、全部 28 项 `node --test web/src/**/*.test.mjs`、`npm --prefix web run build`、`make lint`、`make build`、OpenAPI YAML 解析和 `git diff --check` 均通过。
- 待验收：真实浏览器批量操作和 PostgreSQL 运行时；当前历史接口返回单个发现项全量历史，尚未加入分页。

## 2026-10-21：资产清册扫描与风险摘要（前端回归）

- 资产清册新增“最近扫描”和“当前风险数”列：扫描历史按已登记资产分组，优先展示最近任务的完成时间/创建时间；风险数只统计当前活动发现项，`FIXED` 与 `FALSE_POSITIVE` 不计入，漏洞 API 失败时显示“未知”而不是伪造为 0。
- 资产画像新增漏洞摘要和扫描历史表，继续保留服务/技术栈、登录入口、端口排除与隔离信息。漏洞摘要读取 Server 当前发现项，扫描历史读取任务清册；未改变扫描目标、端口授权、Worker 或引擎参数。
- 新增资产页面契约回归，生产构建和全部 29 项前端契约测试通过；`make test`、`make lint`、`make build` 及 OpenAPI 校验也通过。真实浏览器详情抽屉和大数据量分页/排序仍待验收。

## 2026-10-21：资产清册服务端分页、搜索与排序

- `GET /api/v1/assets` 在带 `page`、`page_size`、`q` 或 `sort` 时使用 Server 端分页投影，限制每页最多 100 条；搜索只覆盖地址、名称、业务组和负责人，排序字段固定为创建时间、地址、业务组、负责人和名称，可用 `-` 指定倒序。未带查询参数的旧调用保留完整清册响应。
- 资产页面改为请求当前页并显示总数、页码和页大小切换；新增/编辑/删除/导入后刷新当前分页，导出仍独立返回完整筛选清单。重复参数、未知查询键、非法页码/页大小和非法排序均失败关闭。
- 仓储测试覆盖筛选、排序、分页元数据和非法排序；API 测试覆盖分页响应、重复/未知/越界查询；OpenAPI 和 API 说明同步。Go race 全量测试、lint、build、前端 30 项契约测试和生产构建均通过。当前只改资产列表，任务、漏洞等其他列表的服务端分页仍待后续工作包。

## 2026-10-21：扫描任务清册服务端分页与筛选

- `GET /api/v1/tasks` 带查询参数时使用 Server 端分页投影，支持归档、状态、引擎、任务 ID/明确目标/Worker 输入路径搜索和固定排序字段；响应返回 `page/pageSize/total/statusCounts`，不带查询参数的旧完整清册响应保留。
- `/tasks` 页面改为按当前页轮询，筛选和归档视图由 Server 执行，状态徽标使用服务端聚合计数；创建、取消、暂停、恢复、归档和删除后刷新当前页，不再把全量任务加载到浏览器后筛选。
- 仓储/API 测试覆盖页大小、归档和引擎筛选、搜索、状态计数、重复/未知/非法参数；新增前端任务列表契约测试。OpenAPI、API 说明、现状和路线图同步。任务列表改动尚未扩展到漏洞和报告列表，也未替代隔离靶机浏览器验收。

## 2026-10-21：PostgreSQL Server 运行时选择与核心任务回归

- `sec-server` 新增显式 `--storage sqlite|postgres` 选择；PostgreSQL 模式只接受 owner-only DSN 文件，启动时执行幂等迁移并将账号、资产、审批和任务/发现项/报告核心适配器接入同一数据库连接池。`/readyz` 与系统状态报告当前后端；未实现的 PostgreSQL 端点返回能力不可用，不回退到 SQLite。
- PostgreSQL 核心任务支持创建、领取、规则就绪门槛、Worker 租约/进度、完成回报、取消、暂停/恢复、归档和无关联发现项的彻底删除；删除前检查任务发现项并在事务内清理队列/投影。新增 `make dev-postgres` 启动路径，默认 `make dev` 仍使用 SQLite。
- 隔离 PostgreSQL 夹具上实际验证：Server 以 `mode=postgres` 启动，管理员登录，登记文档保留地址资产，完成端口与范围审批，创建 `port-probe` 任务，Worker 领取并回报完成，读取和删除任务，再删除范围/资产；回归数据未写入仓库。隔离靶机容器保持运行，映射端口由 Compose 配置提供。
- `make test`（`go test -race ./...` 与 18 项 Python 测试）、`make build`、`make lint`、`POSTGRES_DSN_FILE=... go test -tags=lab ./internal/repo ./internal/account ./internal/assets ./internal/approvals`、`bash -n scripts/dev.sh` 和 `git diff --check` 均通过。PostgreSQL 定时、通知、规则管理/部分系统管理及完整浏览器旅程仍待后续适配和验收。

## 2026-10-21：PostgreSQL 规则目录同步回归

- 新增 PostgreSQL 迁移 `0010_rule_catalog_projection.sql`，只保存规则版本、引擎、manifest 摘要、发布时间、当前/备用标记和验签/完整性元数据；规则文件与 `CURRENT` 指针仍只由 Updater 管理，Server 不保存规则包字节。
- `POST /api/v1/updater/state` 在显式 PostgreSQL 运行时会原子刷新规则目录，自动任务领取继续要求任务冻结版本存在且 Worker 报告规则就绪；规则导入、激活/回滚作业仍明确返回能力不可用。
- 隔离夹具已用当前本地规则目录同步 3 个版本，其中 1 个标记为当前活动版本；靶机 `127.0.0.1:12222`（SSH）和 `127.0.0.1:18080`（HTTP）保持可达。该回归只确认规则就绪与端口/控制面前置条件，尚未把 PG 自动 SSH 扫描结果冒充为已验收。

## 2026-10-21：PostgreSQL 自动综合扫描与隔离靶机回归

- 在独立 PostgreSQL 运行时启动 Server，使用已登记并完成授权的回环映射靶机执行一条自动综合扫描。PG 任务队列完成领取、租约、Worker 回报和报告入库；端口探测发现已授权的 SSH/HTTP 端口，服务识别得到 OpenSSH 与 Apache，Nuclei 只读根路径基线写入 4 条发现项。
- SSH 主机指纹未匹配 Worker 本地 `known_hosts` 时，报告仍以 `COMPLETED` 接收入库，但 `systemScanStatus` 明确标记“未采集”，没有将 SSH 系统包分析误报为“无漏洞”。`CompletedFully` 只用于发现项生命周期收敛，不阻止已完成端口/HTTP 结果入库。
- 修正 PostgreSQL 默认租约与 Worker 本地 45 秒租约上限一致，并让 Worker 报告携带明确目标，避免 PG 报告校验因缺失目标或租约过长而拒绝。临时回归夹具和数据已清理，未写入仓库。
- 该回归证明靶机与 PostgreSQL 的核心自动扫描链路可用；要验证 SSH 系统包/指定部署目录，还需在 Worker 本地配置与靶机匹配的已授权主机指纹和 SSH profile。PostgreSQL 规则目录可同步元数据，但规则 ZIP 导入/激活作业、定时任务、通知及部分系统管理能力仍按能力不可用处理。

## 2026-10-21：PostgreSQL SSH 与 Trivy 系统包完整回归

- 在本地实验靶机容器内核对当前 SSH 主机公钥并更新 Worker 本地 `known_hosts` 后，重新执行 PostgreSQL 自动综合扫描。扫描通过了授权端口探测、SSH/HTTP 服务识别、SSH 临时系统包采集、Trivy 本地规则分析、Nuclei 只读 HTTP 基线和报告入库。
- 任务最终状态为 `COMPLETED`，系统采集状态为“已通过 SSH 临时采集并完成本地系统包检查”；Worker 使用本地规则版本，不向外部目标或互联网扩展请求。测试过程使用临时任务和临时数据库记录，结束后已清理，密钥、主机公钥和扫描明细未写入仓库。
- 该结果补齐了 PostgreSQL 控制面与真实靶机之间的核心扫描闭环；Java/Go 指定部署目录、PostgreSQL 非核心管理作业、定时/通知、节点 mTLS 和完整浏览器旅程仍按路线图单独验收。

## 2026-10-21：PostgreSQL 开发启动回归

- 使用 `POSTGRES_DSN_FILE=... make dev-postgres` 启动 Web、Worker 和 Updater，`/readyz` 返回 `mode: postgres`；Updater 完成本地规则目录同步并保持规则作业轮询，未再因 PostgreSQL 能力缺失退出。
- Worker、Updater 进程和 PostgreSQL Server 在启动检查期间保持运行；退出开发命令后子进程均被清理。该启动路径不会切换或读取 SQLite 数据库。

## 2026-10-21：PostgreSQL 规则作业队列回归

- 新增迁移 `0011_rule_jobs.sql` 和 PostgreSQL 规则作业适配，覆盖 IMPORT/FETCH/ACTIVATE 校验、队列上限、`FOR UPDATE SKIP LOCKED` 领取、节点绑定、完成/失败回报、规则目录原子同步和分页清册。
- PostgreSQL lab 测试实际创建、领取、完成并清理一条 ACTIVATE 作业；Updater 可继续使用常规运行模式。规则 ZIP 的签名和文件完整性仍由 Updater 本地规则 Manager 验证，Server 只保存受限作业数据与目录元数据。

## 2026-10-21：PostgreSQL 定时任务回归

- 新增迁移 `0012_schedules.sql`，保存定时计划和独立运行历史；历史不依赖计划或生成任务的外键，删除计划或任务后仍可安全显示记录状态。
- PostgreSQL RuntimeStore 已接入计划增改删、启停、时间窗/资产/端口授权校验、到期触发和单次计划停用；到期触发持有计划行锁，避免同一 `NextRun` 被并发 Tick 重复消费，生成任务仍复用既有授权校验与规则冻结。
- 隔离 PostgreSQL lab 测试实际创建一条文档保留地址段的单次计划，执行两次 Tick，确认只生成一个 `PENDING` 任务、只写入一条运行历史，并在测试结束清理夹具数据；规则、目标、任务和运行结果未写入仓库。
- `POSTGRES_DSN_FILE=... go test -tags=lab ./internal/repo`、`POSTGRES_DSN_FILE=... make migrate-postgres` 均通过；通知、mTLS/证书轮换、非核心系统管理和 PostgreSQL 浏览器旅程仍未完成。

## 2026-10-21：PostgreSQL 通知中心与安全摘要投递回归

- 新增迁移 `0013_notifications.sql`，建立平台内通知和安全摘要 Webhook 投递队列；通知只保存授权范围、接受风险和失败任务的稳定摘要，不保存目标地址、凭据、请求/响应或引擎输出。
- PostgreSQL RuntimeStore 已接入通知刷新、未读筛选、分页、已读标记、管理员设置、投递状态查询和有界异步投递；Webhook 继续默认关闭，仅允许既有安全校验接受的 HTTPS/回环地址，失败按次数和退避重试，服务重启会回收陈旧投递声明。
- 隔离 PostgreSQL lab 测试使用文档保留地址段和本地 `httptest.Server`，实际验证授权到期摘要、失败任务摘要、已读状态、设置审计和 Webhook 投递均可用；未访问外部互联网。
- 已执行 `POSTGRES_DSN_FILE=... make migrate-postgres` 应用 0013，并执行 `POSTGRES_DSN_FILE=... go test -tags=lab ./internal/repo`；完整 `make test`、`make lint`、`make build` 和 PostgreSQL 启动回归将在本提交收口后再次运行。

## 2026-10-21：PostgreSQL 产品目录与管理面回归

- 新增迁移 `0014_product_catalog.sql`，建立自定义规则和自定义扫描方案表；系统设置、扫描策略和漏洞知识库复用已有产品表，Server 不再为这些页面回退读取 SQLite。
- PostgreSQL RuntimeStore 已接入系统设置、扫描策略、扫描方案、只读自定义规则、知识库、审计日志和端口隔离清册；创建任务时会冻结当前策略与启用的自定义只读模板，端口范围、排除项、强度和规则选择仍由 Server 重新校验。
- 隔离 PostgreSQL lab 测试实际覆盖默认/保存/非法系统设置、策略归一化、规则编译与分页筛选、方案增改删与缺失规则拒绝、知识库保存/导入/删除和审计投影，并在结束后清理夹具记录。测试未访问外部互联网，未写入真实资产、密钥或扫描结果。
- 已通过 `POSTGRES_DSN_FILE=... go test -count=1 -tags=lab ./internal/repo`、`POSTGRES_DSN_FILE=... make migrate-postgres`、PostgreSQL 41 张表/14 条迁移只读清点、`POSTGRES_DSN_FILE=... SCANNER_SKIP_BUILD=1 SCANNER_PORT=18083 make dev-postgres` 的 `/readyz` 检查，以及 `make test`、`make lint`、`make build` 和 `git diff --check`。
- PostgreSQL 发现项处置扩展、mTLS/证书轮换、跨后端浏览器旅程、真实服务器/国产系统覆盖和性能/无障碍/国际化仍按路线图保留，不能据此宣称整体产品已经完成。

## 2026-10-21：PostgreSQL 发现项处置、复测与生命周期安全回归

- 新增迁移 `0015_finding_work.sql` 和 `0016_freeze_threshold_marker.sql`。PostgreSQL 现在覆盖发现项备注、指派/清除及历史、批量指派、批量状态处置、单项复测关系与历史；`task_finding_observations` 保持不可变，处置更新只修改当前发现项投影、生命周期和审计/事件。
- 任务投影冻结 `fixed_threshold`。新任务保存阈值和冻结标记；迁移前的旧投影不参与自动 `FIXED` 收敛，避免阈值未知时误判。完成回报区分任务终态与 `completed_fully`，端口/HTTP 结果可以入库，未完成的全量扫描不会触发错误的生命周期收敛。
- PostgreSQL 复测在同一事务中重新校验已登记资产、当前授权范围、端口排除/隔离、时间窗、规则目录和父任务冻结端口集合；活动复测重复提交返回冲突。批量处置和指派使用固定 ID 顺序及当前快照校验，任一冲突或写入失败整批回滚；审计不复制备注正文。
- 隔离夹具回归通过：`POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" go test -tags=lab -count=1 ./internal/repo`，并单独复核 `TestPostgresFindingWorkLab`、`TestPostgresFindingRetestLab`；`make migrate-postgres` 已应用 0015/0016，公共 schema 只读清点为 43 张业务表加 `schema_migrations`，共 44 张表、16 条迁移。
- 本批仍未完成真实浏览器跨后端旅程、mTLS/证书轮换、真实服务器/国产系统覆盖以及性能、无障碍和国际化验收；这些是路线图后续工作，不能据此宣称整体产品已经完成。

## 2026-10-21：节点 mTLS 与证书/令牌轮换

- Server 独立节点监听新增可选 `--node-tls-client-ca`。配置客户端 CA 后，节点端口强制 TLS 1.3 和 `RequireAndVerifyClientCert`；现有 owner-only Bearer 令牌和 `X-Node-ID` 绑定继续生效，未配置客户端 CA 时保持单向 TLS 兼容模式。
- Worker/Updater 新增 `--node-ca-cert`、`--node-client-cert` 和 `--node-client-key`，分别用于自建 CA 信任和 mTLS 客户端身份；证书与私钥必须成对提供，私钥继续要求 owner-only 普通文件，HTTP 回环模式拒绝这些 TLS 参数。
- Server 在收到 `SIGHUP` 时原子重载节点证书、客户端 CA 和节点令牌注册表。替换文件缺失、不是普通文件、签名/PEM 无效或权限不合规时保留最后一份有效配置；客户端证书轮换需重启对应 Worker/Updater。
- 新增 bootstrap/API 失败路径测试，覆盖客户端 CA 无证书、客户端证书成对校验、无效轮换保留旧配置、令牌轮换立即生效和旧令牌失效；`go test -race ./internal/bootstrap ./internal/api ./internal/taskflow ./internal/rules` 通过。
- 使用临时自签 CA、Server 证书、Worker 客户端证书和 owner-only 令牌文件启动独立节点监听器，实际验证无客户端证书握手失败、带 mTLS 的心跳返回 200、替换 Server 证书后 SIGHUP 仍返回 200、SIGHUP 后旧令牌返回 401、新令牌返回 200；测试材料在临时目录结束时删除。
- 真实多节点证书部署、自动签发/完整节点生命周期和跨后端浏览器旅程仍待隔离环境验收；本批没有连接外部节点或写入真实证书、令牌。

## 2026-10-21：PostgreSQL 三条浏览器核心旅程回归

- 在独立临时 PostgreSQL 数据库和隔离靶机上实际运行 `make test-browser`，使用明确授权的单一数字 IP 与两个授权 TCP 端口；测试数据库、账号、授权范围、端口审批、任务和发现项均为临时夹具，回归结束后清理，未写入仓库。
- 五个 Playwright 用例全部通过：资产登记与自动综合扫描结果详情、总览下钻到漏洞清册、指定发现项只读详情、定时/报告页面、指定已完成任务的报告范围选择。核心任务实际完成了 TCP 探测、SSH/HTTP 服务识别、SSH 临时系统包采集、Trivy 本地分析和 Nuclei 只读 HTTP 基线。
- 修正验收脚本对 Ant Design 可访问名称、Select 容器和重复页面文本的脆弱选择器；选择器修正只影响测试，不放宽扫描范围、授权、引擎参数或 Server 校验。
- 本次实跑同时通过 `make build` 与前端生产构建；跨后端浏览器旅程至此有实际证据。完整节点生命周期自动签发/吊销、真实服务器/国产系统覆盖，以及性能、无障碍和国际化仍未完成。

## 2026-10-21：ZAP 可选安装边界

本地 SSH/Trivy/Nuclei 主链路不再要求安装 ZAP。`make engines` 现在只准备 Nuclei 与 Trivy；需要 ZAP 被动 HTTP 检查时显式运行 `make engines-zap`。`make verify-flags` 在缺少固定版本 ZAP JAR 时输出 `SKIP` 并继续核对 Nuclei/Trivy，`REQUIRE_ZAP=1 make verify-flags` 会在缺少 JAR 时失败。发布工作流默认只打包 Nuclei 与 Trivy，手动选择 `include_zap=true` 才会下载并打包 ZAP。

证据：`python3 -m unittest scripts/test_verify_engine_flags.py`（2 项通过）、`python3 -m py_compile scripts/install_engines.py scripts/verify_engine_flags.py scripts/test_verify_engine_flags.py`、本机 `python3 scripts/verify_engine_flags.py`（Nuclei 23 项、Trivy 20 项通过，ZAP 明确跳过）；未执行任何扫描。

## 2026-10-21：发布包 ZAP 可选化

- `Build & Release Artifacts` 工作流现在默认只安装并打包 SHA-256 固定的 Nuclei 与 Trivy；手动触发时显式设置 `include_zap=true` 才运行 ZAP 下载和制品校验，避免 SSH/Trivy/Nuclei 主链路无条件下载 ZAP。
- 同步离线包说明；新增无网络工作流契约测试，确认核心引擎、ZAP opt-in、未启用时目录不存在和包路径唯一。

## 2026-10-21：节点 TLS 与令牌离线 provisioning

- 新增 `sec-node-provision`，仅使用本地 Go 标准库生成专用 ECDSA CA、数字 Server IP 的 TLS Server 证书、Worker/Updater 客户端证书、Server 节点令牌注册表和各节点 owner-only 单令牌文件；不连接网络、不打印私钥或令牌，输出目录已存在时拒绝覆盖，CA 私钥不会复制到节点材料目录。
- 单元测试验证证书链、Server IP SAN、Server/Client EKU、令牌注册表一致性、私钥权限、CA 复用、路径嵌套和覆盖拒绝；CLI 仅输出非敏感路径与节点元数据。
- 证据：`go test ./internal/provision ./cmd/node-provision`、`go run ./cmd/node-provision ...` 临时目录实跑通过。远程传输、节点自动登记、证书轮换和 Linux Compose 运行时验收仍未完成。

## 2026-10-21：节点材料本地证书轮换

- `sec-node-provision --rotate-dir` 读取并严格校验既有 manifest、数字 Server 地址、节点清单、owner-only 文件和 CA；不生成新令牌，不读取或输出 CA 私钥之外的敏感值。
- 新证书和私钥先写入父目录下的 owner-only 临时目录，再以目录级 rename 替换现有材料目录；失败时保留原目录。Server/Worker/Updater 仍需由运维分发材料并 reload/restart，工具不做网络连接或远程部署。
- 单元测试覆盖证书链、证书确实替换、令牌和 manifest 保持不变、权限保留、未列出文件拒绝且失败不改动旧材料。
- 验证：`go test -race ./internal/provision ./cmd/node-provision`、`go vet ./internal/provision ./cmd/node-provision`、`git diff --check` 通过；未连接外部节点，未写入真实证书、令牌或资产。

## 2026-10-21：节点生命周期首阶段与 PostgreSQL 迁移回归

- 新增 PostgreSQL 迁移 `0017_node_lifecycle.sql`，SQLite 同步创建节点生命周期和事件表。管理员可登记/吊销明确的 Worker 或 Updater 节点；心跳将已登记节点置为 `ONLINE`，十秒无心跳后由 Server Tick 置为 `OFFLINE`，恢复时记录 `RECOVERED`，重复刷新不会重复生成事件；登记/吊销写入审计。
- 节点协议在启用 owner-only 令牌注册表时会在 Bearer 身份校验后查询生命周期，吊销节点返回 `403 node_revoked`，节点类型不匹配拒绝；未配置令牌注册表的回环兼容模式仍不伪造节点身份。离线事件进入 SQLite/PostgreSQL 平台内通知，通知不包含目标地址、凭据或引擎输出。
- 新增生命周期管理/查询 API 和 OpenAPI 契约；自动签发证书/令牌、部署编排及节点管理 UI 仍未实现，不会自动发现主机或扩大扫描范围。
- 验证：`make build`、`make lint`、`make test`（Go race 与 Python 采集测试）通过；`POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" make migrate-postgres` 应用并记录 `0017_node_lifecycle`；`POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" go test -tags=lab ./internal/repo -run TestPostgresNodeLifecycleLab -count=1` 通过；`git diff --check` 通过。测试使用隔离 PostgreSQL 和临时节点 ID，未写入真实 IP、密钥或扫描结果。

## 2026-10-21：节点清册生命周期管理回归

- `/nodes` 系统清册已接入节点生命周期闭环：管理员可登记明确的 Worker/Updater 元数据，清册可查看状态与有界事件时间线，管理员可吊销节点；页面提示该操作不会自动发现主机、签发凭据或扩大扫描范围。
- SQLite 与 PostgreSQL 的节点分页投影会合并已登记但尚未产生心跳的生命周期记录，保留 `REGISTERED`/`ONLINE`/`OFFLINE`/`REVOKED` 状态字段；搜索、排序和既有运行节点列表语义保持不变。
- 验证：`make build`、`make lint`、`make test`（Go race 与 Python 18 项采集测试）、`node web/src/pages/Nodes/pagination.test.mjs`、`npm --prefix web run build`、OpenAPI YAML 解析、`git diff --check` 均通过；`POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" go test -tags=lab -count=1 ./internal/repo` 通过。并补充 SQLite 注册-only 节点分页测试和 PostgreSQL lab 节点清册投影测试。

## 2026-10-21：节点凭据显式签发闭环

- 节点清册新增管理员“签发令牌”操作。签发只针对已登记且未吊销的节点，生成 32 字节随机 URL-safe Bearer 令牌；Server 在同一进程锁下原子更新既有 owner-only 注册表，审计只记录 `issue_node_credential` 动作，不保存明文令牌。响应设置 `Cache-Control: no-store`，页面只显示一次并提示写入节点 owner-only 文件；重复签发被拒绝，轮换继续通过运维替换注册表并发送 SIGHUP 完成。
- 新增 `POST /api/v1/nodes/{id}/issue` OpenAPI 契约、SQLite/PostgreSQL 审计适配和失败回滚；数据库只保存节点生命周期与审计状态，令牌仍属于受保护的文件注册表。远程部署、自动证书签发和客户端自动注册仍未实现。
- 验证：`make build`、`make lint`、`make test`（Go race 与 Python 18 项采集测试）、`node --test $(find web/src -name '*.test.mjs' -print)`（36 项）、`npm --prefix web run build`、`POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" go test -tags=lab -count=1 ./internal/repo`、OpenAPI YAML 解析和 `git diff --check` 均通过；新增 API 测试覆盖成功签发、owner-only 注册表写入、审计记录、重复签发、审计失败回滚和 `no-store` 响应。测试使用临时数据库、隔离 PostgreSQL、文档保留地址和临时令牌，未写入真实凭据或资产。

## 2026-10-21：节点令牌显式轮换闭环

- 节点清册新增管理员“轮换令牌”操作和 `POST /api/v1/nodes/{id}/rotate`。轮换只针对已登记且未吊销、已有令牌的节点；Server 在同一进程锁下原子替换 owner-only 注册表，立即使旧令牌失效，审计只记录 `rotate_node_credential` 动作，不保存明文令牌。新令牌只在 `Cache-Control: no-store` 响应中返回一次，页面提示运维及时替换节点 owner-only 文件并发送 SIGHUP。
- 新增 SQLite/PostgreSQL 审计适配、旧令牌失效和审计失败回滚测试；轮换缺少既有令牌时返回明确的 `node_credential_not_found`，不隐式签发新令牌。远程部署、自动证书/令牌轮换和客户端自动注册仍未实现。
- 验证：`make test`（Go race 与 Python 37 项）、`make lint`、`make build`、`node web/src/pages/Nodes/pagination.test.mjs`、`node --test $(find web/src -name '*.test.mjs' -print)`（37 项）、`npm --prefix web run build`、OpenAPI YAML 解析、`POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" go test -tags lab -race ./internal/repo`、`git diff --check` 均通过；PostgreSQL lab 实际执行了轮换审计写入。测试使用临时数据库、隔离 PostgreSQL、文档保留地址和临时令牌，未写入真实凭据或资产。

## 2026-10-22：授权范围批量续期

- 授权范围页新增跨页选择和批量续期。一次最多 100 条；Server 在同一事务内要求所有记录当前为 `APPROVED`，保留原资产、数字 IP 和时间窗，统一写入新的未来截止时间并清空审批字段，将记录重置为 `PENDING`。任何 ID 缺失、重复或状态不符都会整批回滚；每条记录写入脱敏审计。
- SQLite 单元/API 测试覆盖成功续期、重复 ID/无效截止时间和混合状态原子回滚；PostgreSQL lab 夹具覆盖续期后重新审批。未扩大扫描范围或直接授予执行权限。

## 2026-10-22：漏洞库签名密钥轮换

- `internal/rules` 支持 1–3 把规则根目录外的 Ed25519 公钥。Updater 可重复接收 `--trusted-rule-public-key`，本地 `scripts/dev.sh` 支持 `SCANNER_RULE_PUBLIC_KEY_FILES` 的逗号分隔当前/下一把公钥；旧单数环境变量仍兼容。
- 导入、HTTPS Fetch、普通激活和只读目录验签都会尝试全部受信公钥；重复公钥、超过 3 把、无效/符号链接/规则根目录内公钥均在加载阶段拒绝。公钥复制到进程内，规则包不能注入信任，运维需在确认新包后显式移除旧公钥。
- 新增轮换重叠、重复和上限测试；跨版本扩大兼容范围和生产密钥轮换演练仍待后续执行。

## 2026-10-21：远程节点部署服务状态闭环

- `sec-node-deploy` 的安装和轮换计划在 `systemctl restart` 成功后追加 `systemctl is-active --quiet`；服务未保持 active 时不报告成功，轮换会执行旧材料恢复、重启和恢复后的 active 检查。
- 新增轮换服务状态检查失败路径与恢复顺序测试；未宣称真实 SSH、systemd 或生产节点验收，仍需在明确授权的 Linux 节点上执行隔离实验。

## 2026-10-21：Compose 部署静态安全门禁

- 新增 `scripts/verify_compose_security.py`：通过 `docker compose config --format json` 规范化候选部署文件，随后不启动任何容器，失败即关闭。
- 校验服务角色、显式命名网络、禁止 `network_mode: host`/`hostNetwork`/`privileged`/危险 capability，要求每个服务使用 digest 固定镜像并拒绝直接 `build:` 上下文，限制 Server 仅回环发布端口，禁止 Worker/Updater/PostgreSQL 发布宿主端口，要求 secret 使用 owner-managed file，Updater 非 root，Worker `/vuln-data` 只读且 `/runtime` 可写。
- 新增无网络单元测试，覆盖合法配置、host namespace、特权、规则目录/runtime 权限、明文凭据、危险 capability、端口和 secret/网络缺失路径；`make test` 已纳入该测试文件。该门禁仍不能替代 Linux namespace、nftables、cgroup 和范围外抓包验收，也不声称生产 Compose 已完成。

## 2026-10-21：审计对象 ID 精确筛选

- `/api/v1/audit-logs` 新增 `objectId` 精确筛选，服务端限制长度并拒绝重复参数；SQLite 与 PostgreSQL 查询、计数和分页保持同一语义，仍只返回稳定投影，不暴露历史 detail。
- 审计页面新增“对象 ID”输入框，查询构造、清空和分页保持原有行为；OpenAPI、API 说明和现状文档已同步。
- `go test -race ./...`、审计 API/仓储测试、前端审计筛选测试和前端生产构建用于本项验证。

## 2026-10-21：SSH 运行态服务只读采集

- SSH 系统采集在同一明确授权主机的 rootfs 内枚举 systemd `*.service` 单元、`/etc/init.d` 脚本和 `/proc/<pid>/comm` 进程名；只写入名称、管理方式和 `installed/running` 状态，不读取 PID、命令行、参数、环境变量或服务文件内容。
- Worker 对归档路径、JSON schema、名称字符集、枚举值、重复项、条数和文件大小执行失败即关闭校验；结果写入现有资产画像 JSON，不新增数据库表或迁移。资产详情、报告资产表和 OpenAPI 已同步。
- 验证：`go test ./internal/inventory ./internal/sshcollect ./internal/assets ./internal/repo ./internal/reporting ./internal/executor`、`python3 -m unittest test_collect_linux_inputs.py`（在 `scripts/` 目录，19 项）、`git diff --check`；覆盖有效/无效 JSON、重复/越界服务名、归档路径、合成 systemd/init/proc 夹具、资产画像/报告持久化。
- 该能力仍是只读运行态线索，不等于服务已启动或配置审计；真实服务器、国产系统和容器/集群运行态盘点仍在路线图中。

## 2026-10-21：SSH 本机容器运行态元数据

- 在上一项 SSH 运行态服务采集基础上，对同一明确授权主机只读调用本机 Docker/Podman 的固定 `ps` 格式，记录容器名称、镜像引用和运行/停止状态；不读取容器内容、卷、进程命令行、环境变量，也不访问 Kubernetes 或其他集群 API。
- 采集器固定使用参数切片、`DOCKER_HOST` 隔离环境、20 秒超时、1 MiB 输出上限和最多 256 项；运行时缺失、命令失败、超时或返回非法字段时跳过，不因此扩大扫描范围。合成 rootfs 夹具不会调用宿主运行时。
- 资产画像、资产详情、报告资产表和 OpenAPI 已同步 `container`、`docker/podman`、`stopped` 与镜像字段；没有新增数据库表或迁移。
- 待执行验证：`go test -race ./internal/inventory ./internal/sshcollect ./internal/assets ./internal/repo ./internal/reporting ./internal/executor`、`PYTHONPATH=scripts python3 -m unittest scripts.test_collect_linux_inputs`、`npm --prefix web run build` 及全量 `make test && make lint && make build`。本批不连接外部节点、不执行容器内扫描，也不把容器记录成新的扫描目标。

