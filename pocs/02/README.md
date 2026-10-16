# PoC 2：租约失联终止、GC 保护与规则版本切换

架构依据：`docs/architecture-v3.2.md` §5.3–5.6、§8。本文严格区分**本地逻辑单测**与**真实 Server/Updater/Worker 压测验收**。

## 本轮已实现：租约守护（不接实际扫描器）

- `internal/scheduler/lease_guard.go`：任务必须有 Server 绑定的 `TaskID`、`WorkerNodeID`、`PinnedRuleVersion`、`LeaseExpiresAt`、`HardDeadline`。
- 续租必须延长已有租约、不能超过配置的最大租期；RPC 失败不会延长最后确认的到期时间。
- 续租失联达到最后确认的租约期限时取消任务；续租 RPC 即便卡住也不能阻止本地超时。独立 `HardDeadline` 不依赖 Server。
- 使用 `context.Context` 通知 Worker 停止；`ShutdownGrace` 内未能确认任务退出时返回 `ErrWorkerStopTimeout`，**不能声称进程已杀死**。真实任务必须由进程/容器监督者升级杀进程组或 cgroup。
- 接收的租约不等于扫描授权：启动前仍须完成 `scope` 审批、网络围栏、版本绑定和已验证引擎参数的全链校验。

本轮单测涵盖正常续租、Server 断联、卡住的续约、硬截止、过长/过期租期、意外超长续租、任务取消以及执行器拒绝停止。

## 本轮已实现：GC 资格检查（不触碰文件系统）

- `internal/versionmgr/gc_policy.go`：不允许清理 `CURRENT` 或最近备用版本，宽限期不得短于 2 小时；无当前/备用快照时失败即拒绝。
- 版本必须是数字日期版本格式（如 `20261015.01`），防止路径穿越字符串误用于后续文件操作。
- 两阶段 `QUARANTINE` 和 `DELETE` 分别**实时**查询 Server：本节点、指定版本的 `RUNNING` 任务数量。只接受返回值 0；网络失败、负数或非零都不得继续。
- 第二阶段必须有有效的 `QuarantinedAt`，但本轮不包含 `rename`、`rm` 等文件删除行为。实际执行文件变更前必须更新当前/备用快照，不能复用陈旧状态。

GC 单测覆盖进行中的租约保护、两阶段重新检查、Server 失联、无效版本、过短宽限期和非法删除阶段。

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
4. Updater 在可信本地目录实行 `releases/version` → `.trash/version` 的隔离 rename，重新读取 CURRENT 和备用版本、重新查询 Server 后才删除；谨防软链接、路径穿越和 TOCTOU，保护只读 Worker 挂载。
5. 长任务压测：持续升级多个内容版本及回收，验证零误删、无多重并发任务、租约断联自终止、WINDOW hard deadline 正确。受真实引擎/网络影响的用例必须在隔离实验环境执行。
6. Server/Worker 时钟偏差与租约时戳容差、续租默认 60 秒及总租期须在部署参数和压测中确定；当前测试使用显式短间隔，并不代表生产建议配置。

**状态：PoC #2 的租约守护和 GC 安全判定完成逻辑层实现；实际协议和文件操作未落地、未验收。**
