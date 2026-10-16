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
| AGENTS 补充条款与 PR #1 拆分指令整理（2026-10-16） | make build、make lint、make test（含 -race）及文档一致性检查通过；未执行代码拆分 | 第 8.3 节合入人工评审范围，第 9–13 节与补充文件一致，硬规则 1–49 连续且无重复，保留 PR A 的 11 个评审问题；固定源 diff 的 55 个文件均可归入方案，共享片段及第 29/38/45 条冲突已列明。人工授权暂时维持 Public，不更改可见性；main ruleset 尚未要求 PR 评审和 CI，未找到 CODEOWNERS。补充条款待人工合并，portable 去留、规则冲突及关闭原 PR 均未获决定；历史信息排查与后续各代码 PR 的独立验收未完成。 |
| 按日计划补入文档 PR #2（2026-10-16） | 文档一致性与差异检查通过；本轮仅修改文档 | 纳入此前未跟踪的 dev-plan-daily.md，纠正 CURRENT 尚未开发和直接合并原 PR #1 的陈旧描述，明确替代 PR A 的评审与原 PR 的人工关闭条件；真实 Harbor 样本清单仅保留在获批环境，不提交仓库。未改变任务验收状态，计划仍待人工确认；未创建 A/B/C，未关闭或合并任何 PR。 |
