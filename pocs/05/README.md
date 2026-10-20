# PoC 5：稳定指纹与 FIXED 判定

范围：Nuclei/Trivy 稳定字段指纹、去重和发现项状态机。

验收：重复扫描不会重复入库；易变证据不改变指纹；中断、超时或熔断跳过不会误标 `FIXED`；规则不存在或未执行时保持未验证；再次检出已修复项时按状态机恢复。

测试使用合成结果，不访问外部网络。当前已实现本地状态机回归：Worker 回报只有在
`COMPLETED`、完整完成、至少一个规则引擎成功执行且规则版本与任务冻结版本一致时，
才会把授权范围内连续未检出的活动发现项计入 `ConsecutiveMisses`。达到系统扫描策略
中的 `fixedThreshold`（默认 1，可配置 1–3）后标记为 `FIXED`，记录 `ResolvedAt`；
失败、暂停、旧 Worker 未带完成元数据、规则版本不匹配、未执行规则和范围外发现项
均不会计数。再次检出会将 `FIXED` 置为 `REOPENED` 并清零未检出次数；
`FALSE_POSITIVE` 与 `ACCEPTED_RISK` 保持人工处置状态。

本地回归覆盖首检 `OPEN`、完整扫描缺失后 `FIXED`、重现、失败/旧元数据/版本不匹配、
范围隔离和阈值 2。运行：

```bash
go test -race ./internal/repo -run 'FindingLifecycle' -count=1
```

仍未完成隔离靶机上的真实中断/熔断抓包验收；这些情况下必须继续保持未验证而不能
自动标记 `FIXED`，待实验环境验收脚本补齐后再更新状态。
