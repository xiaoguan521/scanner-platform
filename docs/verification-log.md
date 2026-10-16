# Verification log

记录待核对项的来源、锁定版本、验证日期、结果和未决风险。未经实际验证的项目不得标记为已确认。

## 当前待核对项

| 项目 | 状态 | 说明 |
| --- | --- | --- |
| Nuclei / Trivy 版本锁定 | 未决 | 架构文档要求固定版本，但当前没有批准的版本号或二进制。版本确定后再运行 `make verify-flags`。 |
| 引擎参数白名单 | 未验证 | 按架构文档 §13 在锁定版本上核对；特别是被标记为“待核对”的参数，在核验通过前不得用于运行扫描。 |
| Phase 0 PoC | 未运行 | 真实扫描、防火墙和抓包验证只允许在隔离实验环境开展。 |
| PoC #1 应用层准入（2026-10-16） | 单元测试通过，实验验收未运行 | 显式 IP:端口、审批/到期、端口隔离、时间窗均为纯逻辑验证；网络围栏、降权、DROP 告警和隔离靶场验收未做。 |
| PoC #1 Linux 围栏与受限启动预备代码（2026-10-16） | 本地模拟通过，实验待验证 | nftables 原子规则、默认 DROP、精确协议+IP:端口白名单，netns 父句柄检查及 setpriv 去特权启动参数已实现；未接入 cmd/worker，未在 Linux 实测 nft 和 setpriv。必须人工核对 Linux 工具版本、ns 隔离有效性、内核行为、实际无外联和 DROP 统计。 |
| 引擎受限启动硬闸（2026-10-16） | 默认阻断，待参数验证 | 未接入 `internal/executor` 经版本锁定的参数白名单前，`RestrictedExec.Launch` 显式拒绝真正运行 Nuclei/Trivy；当前 setpriv 仅验证参数构造，未实测进程 UID/capabilities。 |
| GitHub Actions 六平台 CI / Release（2026-10-16） | 本地 actionlint、YAML、Go 测试和六平台交叉编译/压缩包校验通过；GitHub 云端未运行 | CI 可复用且覆盖六类原生 Runner；标签构建只有完整 CI 通过才打包；发布权限仅 Release Job，标签仅创建 Draft + Pre-release。Go 工具链以 go.mod 的 1.26.0 为准；本地 actionlint 1.7.12。运行 GitHub Actions 后需查看各 Runner 实际日志与 Release 草稿资产。 |
| 正式客户端签名/公证和供应链证明 | 未实施 | Phase 0 归档仅是占位骨架。缺少 Windows 代码签名、macOS 签名/公证及 Artifact Attestation；不能直接当作受信任的可部署产品发布。 |
| PoC #2 租约守护（2026-10-16） | 本地模拟单测通过；Server/Worker 联调未执行 | 根据最后确认租约截止和本地 hard deadline 取消工作，网络超时/失联不延长租期，未确认停止时返回 shutdown timeout；必须在真实进程层验证强杀、Node API 身份/时间戳与租约刷新。 |
| PoC #2 GC 两阶段安全判定（2026-10-16） | 本地模拟单测通过；Updater 文件操作未执行 | 当前和最近备用版本保护、>=2h 宽限期、每阶段向 Server 复核本节点 RUNNING 任务；仅校验，尚未实现 .trash rename、fsync、CURRENT 原子替换、Windows 实机重试及并发 TOCTOU 验收。 |
