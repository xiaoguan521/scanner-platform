# PoC 01：Worker 围栏与并发隔离（实现进度）

依据：`docs/architecture-v3.2.md` §6.1、§6.2、§12；安全准则见 `AGENTS.md` 第 4 节。

## 已落地的代码及边界

- `internal/scope`：审批、时间窗、明确 IP:端口、端口分类和隔离状态的纯 Go 准入校验。
- `internal/workerfence/plan.go`：从 `READY`、具有未来硬截止时间的已批准目标与精确基础设施白名单生成 nftables 批量配置；TCP 目标端口、显式 TCP/UDP 基础设施端口；IPv4/IPv6 都覆盖，出站及转发默认 DROP；末尾 DROP 带 counter，可供后续监控读取。
- `internal/workerfence/supervisor.go`：先生成围栏并应用成功，才调用受限启动接口；单 Worker 单任务、不可重入、同一网络命名空间不可重复使用；围栏失败时启动次数必须为 0，硬截止时间由本地 context 控制。
- `internal/workerfence/nft_linux.go`：Linux 上只允许绝对路径的 `nft -f -` 一次性批量应用；**必须提供可信启动器在隔离前打开的父网络 namespace 文件句柄**，并校验 NSFS 类型与当前网络命名空间不同；非 root 或验收失败时拒绝执行。此检查不足以单独证明隔离环境正确，还必须由部署层约束禁止 `hostNetwork`，确保专属 netns。
- `internal/workerfence/restricted_linux.go`：预备经 `setpriv` 清除 UID/GID、附加组、inheritable/ambient/bounding capabilities，并设置 `no_new_privs` 后启动经信任的引擎；参数切片而非 shell，运行目录和环境变量私有化，原始 stdout/stderr 不直通日志，截止时间后杀进程组。Linux 镜像需内置并锁定 `nft`、`setpriv` 的版本与绝对路径。
- `internal/bootstrap` 已把 Linux 围栏接入真实 `taskflow.Worker` 执行回调。显式传入 `--fence --once --fence-parent-netns-fd <fd>` 时，Worker 在每个新建的专属网络命名空间中先应用精确 nftables 规则，再通过固定 `setpriv` 参数以 uid 10001 重启 `--fence-child`；端口探测、自动综合扫描和离线 Trivy 都走这条路径。普通回环开发模式和非 Linux 系统仍明确不启用 Linux 围栏。
- 围栏模式要求每个 Worker 进程只处理一个任务并随后退出；可信启动器必须在进入专属网络命名空间前打开父 namespace 文件句柄并把它以 fd 传入，部署层还必须禁止 `hostNetwork`。Server 节点地址会自动进入基础设施白名单，DNS、Harbor 或制品库只能通过 `--fence-infra` 逐项提供精确 IP:端口。
- 代码路径已经接入，但尚未把它标记为生产验收通过：真实 Linux namespace、nftables DROP 计数、uid/capabilities/no-new-privs 和后代进程回收仍需隔离实验验证。
- **启动器额外硬闸**：版本和参数白名单尚未由 `internal/executor` 核实，`RestrictedExec.Launch` 默认拒绝所有真实引擎启动（包括包含 `-code` 的参数）。`setpriv` 参数和取消逻辑目前仅用于代码级核查，不能声称实际降权已验证。

## 本地模拟测试（不执行网络命令）

```bash
make build
make test
make lint
# 可用交叉编译环境额外执行：
GOOS=linux GOARCH=amd64 go build ./...
GOOS=linux GOARCH=arm64 go build ./...
GOOS=windows GOARCH=amd64 go build ./...
```

模拟测试覆盖：精确 IP/协议/端口、默认 DROP、非法/重复白名单拒绝、外部端口拒绝、围栏失败不启动、并发不得启动第二任务、Worker 一次性执行、提前取消及本地 deadline、特权清除参数的构造。

## Linux 隔离实验（单独执行，未在 macOS 运行）

`pocs/01/fence_lab_test.go` 和 `pocs/01/worker_lab_test.go` 采用 `//go:build linux && lab`。只有在运维批准的 Linux 隔离实验机/CI 中才运行：

```bash
LAB_ENV=isolated make test-lab
# 真实 Worker 围栏联调需要先编译 Linux Worker，并显式提供它：
LAB_GOARCH=$(go env GOARCH)
GOOS=linux GOARCH=$LAB_GOARCH go build -o /tmp/sec-worker ./cmd/worker
GOOS=linux GOARCH=$LAB_GOARCH go test -tags=lab -c -o /tmp/poc01-lab.test ./pocs/01
LAB_ENV=isolated LAB_WORKER_BIN=/tmp/sec-worker \
  /tmp/poc01-lab.test -test.run='Test(IsolatedFenceInstall|FencedWorkerTask)$' -test.v
```

在已经编译好的 Linux 工作区也可以直接运行 `LAB_ENV=isolated LAB_WORKER_BIN=/path/to/sec-worker make test-fence-lab`；该目标会拒绝在 macOS/Windows 上执行。

此测试使用 `unshare --user --map-root-user --net` 创建**新的网络命名空间**后，才安装临时 nftables 表并读取验证规则；由父进程经 fd 3 传递隔离前 netns 句柄。需要 Linux 开启用户/网络 namespace 并具备 util-linux `unshare`、nftables。测试使用文档保留地址，不运行扫描器、也不接触真实资产。Linux 发行版中的 `nft` 路径可通过 `LAB_NFT_PATH` 设置绝对路径。

`worker_lab_test.go` 还会在新的 network namespace 中启动真实 `sec-worker --fence-child`，通过 fd 3/4 传递父 namespace 和进度通道，执行一项仅探测 `127.0.0.1:1` 的端口任务，确认 nft 安装、setpriv 降权、任务摘要 capability 和 heartbeat 进度回传均能连通。它不连接靶机，也不运行 Nuclei/Trivy；必须在容器或实验机中以 root 运行，不能把该测试输出解释为真实目标扫描验收。

## 仍需人工及隔离环境验收

1. 在真实受限容器/netns 内校验应用的 nftables 规则、DROP 计数可观测性和真实范围外发包被拒；**单纯规则字符串测试不证明网络隔离有效**。
2. 在同一环境验证子进程实际 UID=10001、GID=10001、有效/继承/环境/边界 capabilities 全为 0，`NoNewPrivs=1`；确认运行目录可由 UID10001 写入。
3. 部署网络命名空间隔离及 Worker 单任务生命周期、Server 节点 API 身份和授权信息可信传递；扫描目标只能取自服务端固定清单，不能从未验证的 Task 直接构造 `Plan`。
4. 与 `internal/executor` 参数白名单完成联调；锁定 Nuclei/Trivy 和 `nft`/`setpriv` 实际版本并执行 `make verify-flags`。Worker 围栏入口只允许 Server 预先下发的任务回调，未通过本项前**禁止在生产环境启用围栏扫描启动链**。
5. 确认进程组杀死子进程外，是否还需要 worker cgroup 终止所有后代；以及 Docker/Linux 内外 namespace 的流量路径、Nginx stream 代理的请求预算和熔断。
6. 独立校对内网 DNS、Harbor、制品库、Server 的白名单精确 IP:端口及协议；禁止通过 `0.0.0.0/0`、无协议端口、自动解析或宽网段临时放行来修复连接问题。

**状态：PoC #1 的计划生成、失败关闭测试和真实 Worker 接入已实现；隔离实验和生产部署验收尚未完成，不得视为 PoC 通过。**

