# PoC 01：Worker 围栏与并发隔离（实现进度）

依据：`docs/architecture-v3.2.md` §6.1、§6.2、§12；安全准则见 `AGENTS.md` 第 4 节。

## 已落地的代码及边界

- `internal/scope`：审批、时间窗、明确 IP:端口、端口分类和隔离状态的纯 Go 准入校验。
- `internal/workerfence/plan.go`：从 `READY`、具有未来硬截止时间的已批准目标与精确基础设施白名单生成 nftables 批量配置；TCP 目标端口、显式 TCP/UDP 基础设施端口；IPv4/IPv6 都覆盖，出站及转发默认 DROP；末尾 DROP 带 counter，可供后续监控读取。
- `internal/workerfence/supervisor.go`：先生成围栏并应用成功，才调用受限启动接口；单 Worker 单任务、不可重入、同一网络命名空间不可重复使用；围栏失败时启动次数必须为 0，硬截止时间由本地 context 控制。
- `internal/workerfence/nft_linux.go`：Linux 上只允许绝对路径的 `nft -f -` 一次性批量应用；**必须提供可信启动器在隔离前打开的父网络 namespace 文件句柄**，并校验 NSFS 类型与当前网络命名空间不同；非 root 或验收失败时拒绝执行。此检查不足以单独证明隔离环境正确，还必须由部署层约束禁止 `hostNetwork`，确保专属 netns。
- `internal/workerfence/restricted_linux.go`：预备经 `setpriv` 清除 UID/GID、附加组、inheritable/ambient/bounding capabilities，并设置 `no_new_privs` 后启动经信任的引擎；参数切片而非 shell，运行目录和环境变量私有化，原始 stdout/stderr 不直通日志，截止时间后杀进程组。Linux 镜像需内置并锁定 `nft`、`setpriv` 的版本与绝对路径。
- 非 Linux 系统明确返回“不支持 Linux 围栏/受限启动”；`cmd/worker` **仍然是拒绝启动的占位入口**，并未调用以上模块，更没有直接运行引擎。
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

`pocs/01/fence_lab_test.go` 采用 `//go:build linux && lab`。只有在运维批准的 Linux 隔离实验机/CI 中才运行：

```bash
LAB_ENV=isolated make test-lab
```

此测试使用 `unshare --user --map-root-user --net` 创建**新的网络命名空间**后，才安装临时 nftables 表并读取验证规则；由父进程经 fd 3 传递隔离前 netns 句柄。需要 Linux 开启用户/网络 namespace 并具备 util-linux `unshare`、nftables。测试使用文档保留地址，不运行扫描器、也不接触真实资产。Linux 发行版中的 `nft` 路径可通过 `LAB_NFT_PATH` 设置绝对路径。

## 仍需人工及隔离环境验收

1. 在真实受限容器/netns 内校验应用的 nftables 规则、DROP 计数可观测性和真实范围外发包被拒；**单纯规则字符串测试不证明网络隔离有效**。
2. 在同一环境验证子进程实际 UID=10001、GID=10001、有效/继承/环境/边界 capabilities 全为 0，`NoNewPrivs=1`；确认运行目录可由 UID10001 写入。
3. 部署网络命名空间隔离及 Worker 单任务生命周期、Server 节点 API 身份和授权信息可信传递；扫描目标只能取自服务端固定清单，不能从未验证的 Task 直接构造 `Plan`。
4. 与 `internal/executor` 参数白名单完成联调；锁定 Nuclei/Trivy 和 `nft`/`setpriv` 实际版本并执行 `make verify-flags`。在此之前**禁止启用生产扫描启动链**。
5. 确认进程组杀死子进程外，是否还需要 worker cgroup 终止所有后代；以及 Docker/Linux 内外 namespace 的流量路径、Nginx stream 代理的请求预算和熔断。
6. 独立校对内网 DNS、Harbor、制品库、Server 的白名单精确 IP:端口及协议；禁止通过 `0.0.0.0/0`、无协议端口、自动解析或宽网段临时放行来修复连接问题。

**状态：PoC #1 代码骨架与模拟测试已实现，隔离实验和生产集成尚未验收，不得视为 PoC 通过。**

