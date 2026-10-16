# Verification log

记录待核对项的来源、锁定版本、验证日期、结果和未决风险。未经实际验证的项目不得标记为已确认。

> 记录保留每次验证时的状态,后续变化以新增记录为准。PR #1 已于 2026-10-16 合并进 main(`bfeca59`);下表此前关于“尚待拆分/关闭”的记录属于历史状态,不代表当前仍可执行拆分。

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
| 四入口与本地只读 API 骨架（2026-10-16） | 仅搭建结构，本轮按用户要求暂未运行测试 | 增加统一启动入口、Portable 编译入口、Server/Portable loopback 只读诊断 API 和数据库接口定义。业务接口 501，readyz 503，未启用 Node API、数据库、扫描或规则激活。须后续完成跨平台编译、API/安全边界测试与接口联调。 |
| UI 用户管理契约与前端发布构建（2026-10-16） | 本地前端双模式、Go、YAML/actionlint 通过；GitHub 云端未运行 | 新增用户/角色演示页面，GET `/api/v1/users` 仅返回 501；用户写入/认证/RBAC/审计不开放。CI 纳入 Node.js 22 npm ci + 双模式打包检查；Release 仅构建一次 Server-mode UI 作为 `web/` 静态资产加入每个平台的归档，不表示 Server 已支持 UI 静态服务。 |
| AGENTS 补充条款与 PR #1 拆分指令整理（2026-10-16） | make build、make lint、make test（含 -race）及文档一致性检查通过；未执行代码拆分 | 第 8.3 节合入人工评审范围，第 9–13 节与补充文件一致，硬规则 1–49 连续且无重复，保留 PR A 的 11 个评审问题；固定源 diff 的 55 个文件均可归入方案，共享片段及第 29/38/45 条冲突已列明。人工授权暂时维持 Public，不更改可见性；main ruleset 尚未要求 PR 评审和 CI，未找到 CODEOWNERS。补充条款待人工合并，portable 去留、规则冲突及关闭原 PR 均未获决定；历史信息排查与后续各代码 PR 的独立验收未完成。 |
| 按日计划补入文档 PR #2（2026-10-16） | 文档一致性与差异检查通过；本轮仅修改文档 | 纳入此前未跟踪的 dev-plan-daily.md，纠正 CURRENT 尚未开发和直接合并原 PR #1 的陈旧描述，明确替代 PR A 的评审与原 PR 的人工关闭条件；真实 Harbor 样本清单仅保留在获批环境，不提交仓库。未改变任务验收状态，计划仍待人工确认；未创建 A/B/C，未关闭或合并任何 PR。 |
| PR #2 同步 main 并解决文档冲突（2026-10-16） | make build、make lint、make test（含 -race）、文档一致性与差异检查通过 | 以 merge 同步已合入 PR #1 的 main，不改写现有提交；双方原验证记录均保留且无重复。同步期间远端新增 .gitignore 提交 4af9ea7，保留并合入；最终 PR 相对 main 为五个文档及该既有忽略规则变更，两侧原忽略规则及正/反例检查通过。原拆分指令标为历史方案并暂停执行，计划改为评审已合并代码，合并不等于安全验收通过。原工作区修改保留；未回退代码、未创建 A/B/C、未自动合并文档 PR；实验验收和完整历史排查仍未完成。 |
