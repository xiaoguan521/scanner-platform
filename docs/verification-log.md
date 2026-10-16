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
| 四入口与本地只读 API 骨架（2026-10-16） | 仅搭建结构，本轮按用户要求暂未运行测试 | 增加统一启动入口、Portable 编译入口、Server/Portable loopback 只读诊断 API 和数据库接口定义。业务接口 501，readyz 503，未启用 Node API、数据库、扫描或规则激活。须后续完成跨平台编译、API/安全边界测试与接口联调。 |
| UI 用户管理契约与前端发布构建（2026-10-16） | 本地前端双模式、Go、YAML/actionlint 通过；GitHub 云端未运行 | 新增用户/角色演示页面，GET `/api/v1/users` 仅返回 501；用户写入/认证/RBAC/审计不开放。CI 纳入 Node.js 22 npm ci + 双模式打包检查；Release 仅构建一次 Server-mode UI 作为 `web/` 静态资产加入每个平台的归档，不表示 Server 已支持 UI 静态服务。 |
| SQLite 账号管理（2026-10-16） | 单元/竞态及本机 HTTP 联调通过；远程部署未验收 | 使用纯 Go SQLite、bcrypt、HttpOnly/SameSite Cookie，账号 CRUD 需 admin 且写审计；本机测试包含初始化、登录、新增/停用、越权拒绝、登出。仅用于 loopback 开发，不表示平台扫描或节点 API 已可用。 |


## 2026-10-16：本地普通功能修复与非探测功能接通

- 用户范围：逐项修复并复测本地业务，并追加定时任务和规则更新；真实服务器探测及真实扫描留待次日。
- 修复资产测试的用户 ID 外键夹具；统一 Server 网页、账号、资产和任务入口；旧模拟资产表保留为 assets_legacy_runtime；SQLite 数据库共用，未读取或复制用户其他数据库。
- 已接通：网页首次管理员初始化、登录/退出、用户角色与启停、资产/显式端口/跳过端口、审批台账、任务创建/取消、模拟结果及状态修改、单次/间隔定时、跨午夜时间窗、节点心跳、规则包离线/HTTPS 导入与激活/显式回滚。
- 已修复并复测的执行问题：SQLite 并发领取锁冲突；排队后目标/跳过标记变化必须在领取前复查；到期报告不得插入成功发现项；误报/处理中可以恢复待处理；启动端口冲突不得把后台进程接到另一实例。
- make build、make lint、make test（go test -race ./...）通过；前端 Server/Demo 构建通过；Windows/Linux amd64 交叉编译通过，仅表示可编译，不表示已在这些系统运行。
- make test-local 实际通过 9 组本地业务检查：包含首次初始化、角色启停、IPv4/IPv6/镜像登记、审批与跳过、任务与结果、定时自动触发、规则导入/校验失败/切换/回滚、节点离线恢复、重启持久化/审计/退出。全部使用临时数据库、规则目录和回环端口，没有连接目标。
- make dev 已实际完成 npm ci --ignore-scripts、Server 前端构建、三个二进制构建和联合启动；Ctrl+C 后监听已退出；重复启动同端口会明确拒绝，原实例保持健康。
- 浏览器实际验证：首次初始化界面、登录、资产及跳过端口录入、任务完成与下发/跳过清单、网页定时任务自动完成、发现项状态修改/恢复、节点在线及规则 CURRENT 切换。用户创建/启停与审批等完整角色写流程由上述自动化实例验证。
- HTTPS 更新使用本地 TLS 测试源核对实际下载与包哈希错误；未对真实外部规则源联调。离线包工具已实际生成并导入示例包。
- 边界：Worker 只模拟执行，Nuclei/Trivy 真实扫描、真实目标结果、真实漏洞修复验证、生产部署和 PostgreSQL 迁移运行未验证。规则只校验文件完整性，未验签、未验证引擎兼容性；上游规则需先按本平台 manifest 打包，不会自动抓取最新 GitHub/OCI 数据。
- 规则由 Updater 唯一写入；Server 只保存作业和回报目录。规则 ZIP 上限 256 MiB、解压 2 GiB、5 万文件、单文件 1 GiB；文件流式哈希校验，不覆盖同名版本。
- API DTO、前端类型和 OpenAPI 同步；修正原 OpenAPI 两处 flow mapping 的描述字段格式错误。没有改工作流或依赖。
- 当前普通功能不依赖 Draft PR、人工逐行评审或 PoC 门禁。后续安排：按用户输入的靶机 IP:端口接入真实扫描验证；Harbor、AI、便携版继续后置。
