# PoC 01：授权目标与端口范围（初始实现）

依据：docs/architecture-v3.2.md 第 6.1、6.2、12 章。本次只实现安全准入层，不宣称完成 PoC #1。

已做：明确 IP:port 白名单、审批人与工单、CIDR 范围、目标数量上限、端口 EXCLUDED_PROXY 分类、端口隔离、时间窗与本地截止时间计算，fail-closed 单测与解析 fuzz 测试。测试仅采用 192.0.2.0/24 等文档保留地址，不产生任何网络流量。

**未做**：Linux supervisor 默认 DROP 网络围栏；放行精确 IP:端口的真正防火墙规则；降权 uid 10001；capabilities 清空；同 Worker 并发隔离；抓包和 DROP 告警；Nginx stream 请求预算；执行器本地子进程强停。以上必须在隔离 lab 中验证，不能用本次纯函数单测代替。

验证：make build、make test、make lint。make verify-flags 在引擎版本未锁定前会明确报错，不会谎称参数已通过验证。
