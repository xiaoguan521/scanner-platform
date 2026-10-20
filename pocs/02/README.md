# PoC 2：租约失联终止、GC 保护与规则版本切换

架构依据：`docs/architecture-v3.2.md` §5.3–5.6、§8。本文严格区分**本地逻辑单测**与**真实 Server/Updater/Worker 压测验收**。

## 本轮已实现：租约守护（不接实际扫描器）

- `internal/scheduler/lease_guard.go`：任务必须有 Server 绑定的 `TaskID`、`WorkerNodeID`、`PinnedRuleVersion`、`LeaseExpiresAt`、`HardDeadline`。
- 续租必须延长已有租约、不能超过配置的最大租期；RPC 失败不会延长最后确认的到期时间。
- 续租失联达到最后确认的租约期限时取消任务；续租 RPC 即便卡住也不能阻止本地超时。独立 `HardDeadline` 不依赖 Server。
- 使用 `context.Context` 通知 Worker 停止；`ShutdownGrace` 内未能确认任务退出时返回 `ErrWorkerStopTimeout`，**不能声称进程已杀死**。真实任务必须由进程/容器监督者升级杀进程组或 cgroup。
- 接收的租约不等于扫描授权：启动前仍须完成 `scope` 审批、网络围栏、版本绑定和已验证引擎参数的全链校验。

本轮单测涵盖正常续租、Server 断联、卡住的续约、硬截止、过长/过期租期、意外超长续租、任务取消以及执行器拒绝停止。

## 已实现：GC 资格检查

- `internal/versionmgr/gc_policy.go`：不允许清理 `CURRENT` 或最近备用版本，宽限期不得短于 2 小时；无当前/备用快照时失败即拒绝。
- 版本必须是数字日期版本格式（如 `20261015.01`），防止路径穿越字符串误用于后续文件操作。
- 两阶段 `QUARANTINE` 和 `DELETE` 分别**实时**查询 Server：本节点、指定版本的 `RUNNING` 任务数量。只接受返回值 0；网络失败、负数或非零都不得继续。
- 第二阶段必须有有效的 `QuarantinedAt`。该策略只做授权判定，文件操作由下面的独立 API 执行。

GC 单测覆盖进行中的租约保护、两阶段重新检查、Server 失联、无效版本、过短宽限期和非法删除阶段。

## 本轮已实现：两阶段本地文件 GC（尚未接入 Node API）

- `internal/versionmgr/gc_files.go` 提供 `GCFiles.Quarantine(ctx, version)` 和 `Delete(ctx, version)`，调用方必须分别显式调用，不含后台回收循环或命令行入口。`Root`、`NodeID` 来自固定部署配置；可信 `Snapshot` 回调按指定版本提供最新备用版本和退役时间，不接收用户提供的旧快照，不以目录 mtime 或版本排序推测元数据。
- 每阶段读取真实本地 `CURRENT`，获取可信元数据，调用 `GCPolicy.Check` 重新向 Server 查询本节点、指定版本的 `RUNNING` 数量。查询后再次读取元数据，复查 CURRENT 和目录身份，再进行文件变更。缺少状态、取消、查询失败、正在使用或状态在查询期间变化，均拒绝该阶段。
- 仅接受现有数字版本格式，根目录必须为可信绝对真实目录。Go 1.26 `os.Root` 锚定根、`releases`、`.trash` 和候选目录；这些目录及 CURRENT 不得是软链接，候选替换、目的碰撞和已有保留记录均拒绝。`releases` 和 `.trash` 必须由可信 Updater 预先创建，API 不自动创建或修复它们。
- 隔离使用 `releases/version` → `.trash/version` 的 rename，POSIX 同步两个父目录。随后在候选目录内原子写入保留文件 `.gc-quarantine.json`（版本、固定节点、可信退役时间、rename 成功后的隔离时间），按临时文件 → fsync → rename → 同步目录发布。记录写入失败保留隔离目录，缺失或损坏记录时禁止自动删除。
- 删除只使用已锚定 `.trash` 下的 `RemoveAll(version)`，并再次完成全部授权检查。记录按大小限制读取，只接受普通文件，拒绝未知字段、错误版本/节点/时间及与可信退役时间不一致的状态。新实例可恢复删除具有有效记录的隔离版本；不使用 mtime 推断隔离。架构未要求隔离后再等待额外宽限期，退役宽限期在两阶段各自检查。
- 两阶段与现有 CURRENT 写入共用进程内 `currentWriteMu`。部署必须保证单 Updater 独占本地规则根目录、非可信进程不可写，以及 Server 永不为退役版本发放新租约。未来集成还必须使完整的激活检查和 CURRENT 写入与 GC 协调：当前 `rules.Manager` 的检查到写指针之间尚未整段受此锁保护。这里没有建立跨 Server、进程和文件系统的原子事务，也不保证可抵御拥有根目录写权限的并发进程。
- `RemoveAll` 可能部分成功，不能把取消或删除错误视作回滚；若中途已删除隔离记录，残留目录需要人工核查，不能声称所有中断都能自动恢复。Windows 目录 fsync 和实机 rename 行为仍须独立实验验证，本地单测不能证明断电持久性。

文件单测全部使用 `t.TempDir` 与模拟 Server，覆盖两阶段分别查询、查询失败/新增 RUNNING、阶段间保护变化、查询期间目录/指针/元数据替换、无效或过近退役状态、路径与软链接、目的碰撞、预取消、隔离记录失败/损坏、重启恢复及与 CURRENT 写入的进程内互斥。

## 如何运行

```bash
make build
make lint
make test
go test -race -count=5 ./internal/scheduler ./internal/versionmgr
```

上面所有测试使用模拟 Server，不访问外部网络，不启动 Nuclei/Trivy。

## 未完成，不得视为 PoC 2 验收通过

1. Server 实际记录/续期任务块 `lease_expires_at`、可信节点身份绑定、固定扫描规则版本；以真实 Node API/TLS 实测网络分区、并发任务重新分配及失联进程终止。
2. Worker 实际消费本地 `CURRENT`；如果不存在，应上报 `WAITING_FOR_RULES` 并退避等待，而不是终止服务。
3. Updater 验证 manifest 签名、文件 hash、引擎兼容与防回滚；安全实现 `CURRENT` 临时写 → fsync → rename 覆盖，并在 Linux/Windows 实机测试（Windows rename 冲突重试）。
4. 将本地 GC API 接入真实 Updater 和经过 TLS/节点鉴权的 Server 查询，持久化并提供可信备用/退役元数据，协调完整激活过程；验证单 Updater 写入所有权及只读 Worker 挂载。文件 API 本身已实现，不代表这条实际链路完成。
5. 长任务压测：持续升级多个内容版本及回收，验证零误删、无多重并发任务、租约断联自终止、WINDOW hard deadline 正确。受真实引擎/网络影响的用例必须在隔离实验环境执行。
6. Server/Worker 时钟偏差与租约时戳容差、续租默认 60 秒及总租期须在部署参数和压测中确定；当前测试使用显式短间隔，并不代表生产建议配置。

**状态：PoC #2 的租约守护、GC 安全判定与显式两阶段本地文件操作已有实现；真实 Node API/Updater 集成、跨平台实验和压测未验收。**
