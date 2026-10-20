# PoC 6：时间窗中止与恢复

范围：任务分块、时区和跨午夜语义、Worker 本地硬截止时间及恢复。

验收：任务准入检查授权时间窗；到达块的硬截止时间后 Worker 本地停止；Server 暂时不可达不影响截止；后续恢复后结果无重复或丢失。

测试使用合成时间和文档保留地址，不访问外部网络。

## 当前进度

- `internal/scheduler` 已实现时间窗准入、跨午夜判断、Worker 本地硬截止和取消通知。
- `RuntimeStore.Tick` 会把 `WAITING_WINDOW` / `PAUSED_WINDOW` 任务仅在当前时间落入授权窗口时恢复为 `PENDING`；窗口外不会重新下发。
- `internal/api/runtime_test.go` 的集成回归通过本地 HTTP API 串起 Server、Worker 和 SQLite：第一次领取在本地截止时报告 `PAUSED_WINDOW`，不会写入发现项；`Tick` 后重新领取并完成；重复回报只保留一个发现项。

运行方式：

```bash
go test -race ./internal/api ./internal/repo ./internal/taskflow ./internal/scheduler -run 'Window|PauseResume|RuntimeWorker'
```

## 尚未完成的隔离验收

仍需在隔离环境中验证真实长任务的多块恢复、Server 暂时不可达时的本地截止、Worker 进程级终止以及跨时区/跨午夜的实际调度。当前回归使用临时 SQLite 和本地测试 HTTP 服务，不代表生产节点租约协议或 TLS 已验收。
