# Linux Worker 围栏运行约定

这份说明只描述已经接入代码的 Linux 执行路径。它不是可直接上线的 Compose 文件；真正部署前仍需在隔离 Linux 环境完成 `pocs/01` 的实验验收。

## 两种 Worker 模式

- 本机开发和便携模式继续使用普通 `sec-worker`。macOS/Windows 没有 Linux nftables 围栏时，Worker 只执行 Go 层范围校验，不能把这种模式当作生产隔离证明。
- Linux 执行器使用 `--fence`。该模式要求 root 仅作为可信 supervisor 启动，必须同时传 `--once` 和由启动器继承的父网络 namespace fd。一个进程只领取一个任务，任务结束后销毁 Worker 所在的专属 namespace，再启动新的 Worker 处理下一任务。

示意参数如下，地址和路径必须替换为部署环境的明确值：

```text
sec-worker \
  --server https://192.0.2.10:8443 \
  --node-token-file /run/secrets/worker-token \
  --fence --once --fence-parent-netns-fd 3 \
  --fence-cgroup-root /sys/fs/cgroup/sec-worker \
  --fence-infra tcp://192.0.2.53:53 \
  --bin-dir /opt/sec/bin --rules-dir /vuln-data \
  --runtime-dir /runtime/worker --inputs-dir /runtime/inputs
```

Server 的 HTTPS 地址会自动加入基础设施白名单；额外的 DNS、Harbor 或制品库只能通过 `--fence-infra` 逐项写成数字 `IP:端口`，不接受主机名、CIDR 或整段网络。所有扫描目标和端口仍由 Server 固定后随任务下发，Worker 不解析域名、不展开网段。

## 可信启动器的前置条件

1. 在 Worker 进入专属网络 namespace **之前**打开父 namespace 文件描述符，并以 fd 3 传入；fd 必须指向不同于当前 Worker namespace 的 Linux `nsfs` 对象。
2. 部署必须使用独立 network namespace，禁止 `hostNetwork` 或把 Worker 复用到宿主机 namespace。围栏规则只在当前 namespace 安装，代码会拒绝修改与父 namespace 相同的防火墙。
3. Worker 镜像固定 `nft` 和 `setpriv` 的绝对路径与版本。启动器只授予安装 nftables 所需的临时权限；子进程通过固定参数清除 UID/GID、附加组和全部 capabilities，并设置 `no_new_privs`。
4. 启动器必须预置专用、可写的 cgroup v2 根目录（例如 `/sys/fs/cgroup/sec-worker`），并提供 `cgroup.controllers`、`cgroup.procs` 和 `cgroup.kill`。每个任务创建一个子 cgroup，root 阶段先加入该组；缺少 `cgroup.kill` 或加入失败时不得启动引擎。
5. 规则目录以只读方式挂载；`/runtime` 和输入目录由 uid 10001 私有可写。若启用 SSH 采集，Worker-local SSH 配置、known_hosts、私钥文件或 SSH Agent 必须对 uid 10001 可用，且仍保持私钥 owner-only，不能把密钥内容传入 Server 或任务 JSON。
6. Server 节点 API 必须使用 HTTPS 和 owner-only 节点令牌文件；令牌不放入环境变量或日志。启动器负责在 namespace 内保留到 Server 的精确 `IP:端口` 通道。

## 代码执行顺序

`internal/bootstrap` 的 fenced adapter 接收现有 `taskflow.Task`，只把 Server 已解析的目标和端口转换成 `workerfence.Plan`。Linux 子进程先读取受限 JSON，校验硬截止时间和操作类型；root 阶段安装一次 nftables 事务，成功后用 `setpriv` 重新执行 `--fence-child`。降权阶段再构造现有 `executor.Runner`，因此引擎参数白名单、规则完整性校验、SSH/Trivy/Nuclei 的结果归一化仍由原执行器负责。

端口探测进度通过独立的继承 fd 逐行回传给父 Worker，仍使用现有 heartbeat `ProgressUpdate`，不会把扫描输出、响应正文或目标清单写进进度通道。任务摘要也通过 root 阶段建立的短期 fd capability 绑定到降权子进程；手工伪造环境变量或修改任务 JSON 会在子进程启动前失败。

端口探测/自动综合扫描最多生成 65535 个目标 TCP 许可；离线 Trivy 只保留基础设施白名单，不生成网络目标许可。围栏失败、输入不完整、硬截止时间到期或降权失败都会在引擎启动前拒绝任务。

## 现阶段验收边界

本地已通过计划生成、非法目标拒绝、围栏失败不启动、受限 argv 构造、交叉编译和 Go race 单测。在一次性 Linux arm64 隔离容器中，真实 `nft`/`setpriv`/network namespace Worker 联调也已通过，并核对了 uid/gid 10001、`NoNewPrivs=1` 和全部 capability 字段为零；这不是生产部署验收。以下仍必须在隔离 Linux 部署环境验证后才能进入部署清单：

- 范围外 TCP/UDP/DNS/HTTP 请求确实被 DROP，计数可观测；
- 任务结束或租约失联时进程组和 cgroup 后代全部终止；代码现在强制使用 cgroup v2 `cgroup.kill`，仍需在部署环境实测后代清理和超时行为；
- Docker/Compose 网络路径不会绕过 namespace，Server、规则库和 SSH 输入路径仅通过明确白名单访问。
