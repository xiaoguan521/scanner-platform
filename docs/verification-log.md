# Verification log

记录待核对项的来源、锁定版本、验证日期、结果和未决风险。未经实际验证的项目不得标记为已确认。

## 2026-10-21：管理员系统设置与会话策略

- 新增 `/settings` 管理员页面和 `GET/PUT /api/v1/system-settings`。时区限定为 `UTC`、`Asia/Shanghai`、`America/New_York`；会话时长限定为 30–1440 分钟；保存写入 `product_settings` 并记录 `update_system_settings` 审计动作。
- 登录时服务端会话到期时间和 HttpOnly Cookie 的 `Max-Age` 同时读取该设置；系统设置表或记录尚未初始化时安全回退到 8 小时默认值。已有会话不会因设置变更提前失效。
- `go test -race ./internal/account ./internal/repo ./internal/api`、`node --test web/src/pages/Settings/settings.test.mjs` 和前端生产构建用于本批回归；真实浏览器页面交互和 PostgreSQL 运行时仍待验收。外部通知投递没有在本批实现。

## 2026-10-21：平台内通知中心

- 新增 `/notifications` 和 `GET /api/v1/notifications`。Server 从已批准授权七天内到期/已过期、接受风险七天内到期/已过期和失败扫描任务生成确定性通知；消息只包含安全摘要和对象标识，不包含目标地址、凭据、原始请求/响应或引擎输出。
- 通知写入 SQLite `notifications` 表，刷新幂等；登录用户可筛选未读、标记单条或全部已读。读取和已读操作不会启动探测、扫描或外部网络请求；外部邮件/Webhook 投递保留到后续阶段。
- `go test -race ./internal/repo ./internal/api`、`node --test web/src/pages/Notifications/notifications.test.mjs web/src/components/Layout/navigation.test.mjs` 和前端生产构建通过；真实浏览器交互、PostgreSQL 运行时和外部投递未验收/未实现。

## 2026-10-21：报告 PDF 输出

- 报告格式新增 `pdf`，继续复用原有冻结快照、异步队列、重试、历史和同快照导出；下载接口返回 `application/pdf`，报告页面可生成和导出 PDF。
- PDF 使用 PDF 标准的 `STSong-Light` CJK 字体，离线生成 A4 文本与表格，保留八章内容、范围说明、漏洞明细和覆盖限制；不读取远程资源、不启动扫描器、不提交字体文件。
- `go test ./internal/reporting ./internal/repo ./internal/api`、合成 PDF 输出、`pdfinfo` 结构检查、前端生产构建和 OpenAPI YAML 解析通过。PDF 的原生办公软件视觉排版、PostgreSQL 运行时和真实浏览器点击仍待环境验收。

## 2026-10-21：移除演示种子与浏览器 mock 通道

- 根据隔离靶机真实 SSH/自动综合扫描结果，移除 `cmd/seed-demo`、`make seed-demo` 和 Server 的 `--seed-demo` 启动参数；本地启动不再自动写入合成资产、任务或发现项。`scripts/test_local.py` 改为从空数据库开始验证登录、资产、任务和 Worker API。
- 前端认证、总览、资产、授权、任务、漏洞、报告、节点、知识库、用户和审计页面统一走 Server API；删除 `web/src/mock`、`isDemoMode`/`VITE_DATA_MODE` 分支。API 失败只显示错误状态，不回退到浏览器内存数据。
- 已更新产品路线图、现状和快速开始文档，验收入口改为隔离靶机真实数据。`npm --prefix web run build`、前端源码契约测试、`make test`、`make lint`、`make build` 和 `git diff --check` 需在本批提交前重新运行。

## 2026-10-21：六域信息架构与导航基础

- 主导航由原来的平铺入口收敛为“总览、资产、扫描、漏洞、报告、系统”六个稳定域；系统域承载授权范围、节点与规则库、漏洞知识库、用户与角色、审计日志。每个子入口只指向已存在的真实路由，系统设置和通知中心在闭环完成前不展示空壳入口。
- 菜单定义集中在 `web/src/components/Layout/navigation.ts`，角色过滤仍由前端负责隐藏入口，后端权限校验保持不变；点击一级域标题会进入该域默认页面，直接访问既有路由不受影响。
- `node --test web/src/components/Layout/navigation.test.mjs` 和 `npm --prefix web run build` 通过。真实浏览器的折叠菜单、键盘导航和窄屏体验仍待 Stage 1 回归。

## 2026-10-21：Server 数据通道收敛（历史记录）

- 本节早期记录的演示种子已由上方“移除演示种子与浏览器 mock 通道”批次替代；仓库当前不再提供 `make seed-demo`、`cmd/seed-demo` 或 `VITE_DATA_MODE`。

## 2026-10-21：共享状态与表格组件

- 新增 `web/src/components/DataState.tsx`，集中提供 `LoadingState`、`ErrorState`、`EmptyState` 和 `DataTable`。`CollectionNotice` 统一使用加载/错误状态，资产、扫描、漏洞、报告、节点、授权、用户、审计、知识库和总览列表统一使用 `DataTable`。
- `DataTable` 默认提供可访问的空状态和稳定的空结果语义；页面仍可通过 `locale.emptyText` 提供领域化说明，不改变现有筛选、分页或权限行为。
- 新增 `DataState.test.mjs` 契约测试；共享组件批次通过 22 项前端测试和生产构建。真实浏览器的键盘导航、窄屏表格和 5 次点击核心旅程仍列入下一批验收。

## 2026-10-21：跨页面语义组件

- 新增 `web/src/components/Semantic.tsx`，集中维护严重度、漏洞生命周期、扫描任务和定时运行状态的标签颜色与中文/英文文案，并提供 `StatCard` 和 `LoadingSkeleton`。漏洞、总览、任务页面改用共享组件，删除页面内重复的状态映射，避免同一状态在不同页面显示不同含义。
- `Semantic.test.mjs` 契约测试覆盖全部状态枚举及主要页面的共享组件引用；前端源码测试共 24 项，生产构建通过。完整设计令牌、筛选条、详情抽屉和危险确认弹窗仍需按核心旅程继续抽取，未在本批扩大范围。

## 2026-10-21：真实靶机浏览器验收脚本

- 新增 `docs/browser-acceptance.md` 和 `web/e2e/core-journey.spec.mjs`。脚本要求 `LAB_ENV=isolated`、人为确认值、已有账号、单个数字 IP 和明确端口范围；不会创建演示账号、默认目标或扩大扫描范围。
- 验收步骤覆盖页面登录、资产登记、自动综合扫描向导、授权确认、任务完成轮询和任务详情结果检查。任务/资产默认保留，便于人工复核；真实执行需在隔离靶机上运行 `make test-browser`，本次提交只完成脚本和门槛，未代替用户授权运行。

## 2026-10-21：三条核心旅程浏览器验收覆盖

- 抽取 `web/e2e/helpers.mjs` 统一隔离环境、数字 IP、端口范围、账号和登录门槛；新增总览下钻/指定发现项详情以及定时/报告页面验收脚本。所有脚本共 5 个测试，深入发现项和报告选择分别需要显式提供现有 `SCANNER_E2E_FINDING_ID`、`SCANNER_E2E_TASK_ID`，不写入状态或创建报告。
- `node --test $(find web/src -name '*.test.mjs' -print)` 共 25 项通过；`npm --prefix web run test:e2e -- --list` 列出 5 个测试；`npm --prefix web run build` 通过。当前未连接正在运行的 Server，未宣称真实浏览器实跑或抓包证据已完成。

## 2026-10-20：单项接受风险、到期与状态事件

- 新增 finding_events SQLite 表及按发现项/时间索引；PATCH 接收状态、原因、到期，GET `/api/v1/findings/{id}/events` 返回时间线。Server 角色/CSRF 沿用现有写权限，非写角色只能查看。
- 接受风险仅允许 OPEN/REOPENED/IN_PROGRESS；原因按 UTF-8 字节限长且拒控制字符，到期必须 RFC3339 带时区并位于未来 365 天。拒绝手工 FIXED、从 FIXED 修改、重复状态、误报直接接受以及未撤销接受直接流转其他状态。
- 每分钟 Tick、列表/更新/回报入口补查到期与旧无期限接受；条件更新和事务保证并发只记录一次。扫描重复检出保留接受字段，自动 FIXED/REOPENED 和到期重开记录系统事件；Worker 协议未开放接受字段。架构要求的到期通知渠道尚无现有基础设施，本批只提供事件/时间线，通知投递列为后续缺口。
- Go 测试覆盖输入/状态边界、角色/CSRF/API、并发过期、旧无期限或格式错误期限、事件失败回滚、审计不含原因、回报前到期及自动生命周期事件。前端 helper/源码契约测试覆盖资格、UTF-8 限长、期限、纯文本表单与时间线；生产构建通过。
- 已运行 `go test -race ./internal/repo ./internal/api`、`node web/src/pages/Findings/disposition.test.mjs`、`npm --prefix web run build`。未进行真实浏览器交互、服务重启、真实扫描或 PostgreSQL 集成；最终全库门禁由主代理复核。

## 当前待核对项

| 项目 | 状态 | 说明 |
| --- | --- | --- |
| Nuclei / Trivy / ZAP 版本锁定 | 本机核验通过 | 3.11.1 / 0.76.0 / 2.17.0，官方程序版本、下载哈希与参数已在本机核对；见 2026-10-16 及后续记录。 |
| 引擎参数白名单 | 已安装版本核验通过 | `make verify-flags` 对实际帮助核对；2026-10-19 新增 rootfs 与 OS 包类型参数，不代表真实服务器已验收。 |
| Phase 0 PoC | 未运行 | 真实扫描、防火墙和抓包验证只允许在隔离实验环境开展。 |
| PoC #1 应用层准入（2026-10-16） | 单元测试通过，实验验收未运行 | 显式 IP:端口、审批/到期、端口隔离、时间窗均为纯逻辑验证；网络围栏、降权、DROP 告警和隔离靶场验收未做。 |
| PoC #1 Linux 围栏与受限启动预备代码（2026-10-16） | 本地模拟通过，实验待验证 | nftables 原子规则、默认 DROP、精确协议+IP:端口白名单，netns 父句柄检查及 setpriv 去特权启动参数已实现；未接入 cmd/worker，未在 Linux 实测 nft 和 setpriv。必须人工核对 Linux 工具版本、ns 隔离有效性、内核行为、实际无外联和 DROP 统计。 |
| 引擎受限启动硬闸（2026-10-16） | 默认阻断，待参数验证 | 未接入 `internal/executor` 经版本锁定的参数白名单前，`RestrictedExec.Launch` 显式拒绝真正运行 Nuclei/Trivy；当前 setpriv 仅验证参数构造，未实测进程 UID/capabilities。 |
| GitHub Actions 六平台 CI / Release（2026-10-16） | 本地检查及 GitHub 云端 CI 通过；Release 未发布 | 提交 `798f832` 的 CI 已通过前端、race 测试、lint 和 Linux/macOS/Windows 六平台构建。标签构建只有完整 CI 通过才打包；发布权限仅 Release Job，标签仅创建 Draft + Pre-release。漏洞库手工工作流需另看当前签名步骤结果。 |
| 漏洞库 Ed25519 签名与平台验签 | 本地平台实现、隔离测试和当前主分支 GitHub Actions 均通过 | 当前工作流使用 `vulnerability-data-signing` 环境、`BUNDLE_SIGNING_PRIVATE_KEY_PEM` 密钥和 `BUNDLE_SIGNING_PUBLIC_KEY_PEM` 变量；云端已完成 8 个文件完整性校验、Ed25519 签名/验签和 `vulnerability-data` 制品上传。Updater 现支持 2 GiB 以内的已签名本地/HTTPS 流式导入，网页 multipart 仍为 256 MiB；单公钥轮换、多密钥过渡与完整引擎兼容矩阵仍未完成。 |
| SSH 指定目录 Java/Go 应用 | Go 与含 class 的 Java 合成 JAR 隔离路径通过；活动规则已切换到含 Java DB 的版本 | Go ELF 与 Java JAR 均完成 SSH 采集、快照校验、Trivy 类型确认和覆盖计数；缺少 Java 索引时仍明确为 `analysis_failed`，带 Java DB 的规则版本已验证 Java 选中/已分析均为 1。当前活动版本通过 Updater 本地显式准备，`signatureVerified=false`；仅覆盖合成输入，独立挂载目录和真实业务应用仍待验收。 |
| 自动综合扫描 HTTP 失败状态回报 | Worker/Server 回归与 V4 排除端口验证通过；最新 V5 任务界面显示已完成，结果仍待逐项复核 | HTTP 错误保持 FAILED 并保存明确的系统包阶段状态。此前路由阻塞记录为历史状态；本轮开发期间未重启原测试实例，新应用能力不属于该次实扫验收范围。 |
| 正式客户端签名/公证和供应链证明 | 未实施 | Phase 0 归档仅是占位骨架。缺少 Windows 代码签名、macOS 签名/公证及 Artifact Attestation；不能直接当作受信任的可部署产品发布。 |
| PoC #2 租约守护与本地任务租约（2026-10-20） | Scheduler、SQLite Server/Worker HTTP 联调及 race 单测通过；生产节点验收未执行 | 真实任务领取时生成 `pinned_rule_version`/`lease_expires_at`，`/worker/renew` 校验任务、Worker、版本、过期和 hard deadline，`Tick` 回收过期任务；Worker 租约失联时停止且不发送陈旧回报。仍需在 TLS/节点令牌、独立进程和强杀路径上实测。 |
| PoC #2 CURRENT 门禁与本地规则版本（2026-10-20） | 本地 CURRENT 读取、缺失等待、版本过滤和节点心跳单测通过；生产多节点验收未执行 | 真实 Worker 读取只读规则根的 CURRENT，缺失时上报 `WAITING_FOR_RULES` 并退避，不领取规则任务；规则任务只在 Server 看到相同 `localRuleVersion` 时领取，端口探测/ZAP 保持无规则兼容。无效 CURRENT 显式上报 `RULES_ERROR` 并停止；完整 manifest/hash 仍在引擎执行前复核。 |
| PoC #2 GC 两阶段文件操作（2026-10-20） | 本地文件实现与隔离竞态单测通过；真实 Updater 集成未执行 | 当前和最近备用版本保护、>=2h 退役宽限期、每阶段向 Server 复核本节点 RUNNING 任务；使用限定目录的 rename、持久隔离记录和二次检查后删除。缺少可信退役状态或隔离记录时拒绝回收；完整激活协调、真实 Node API 和 Windows 实机行为仍待集成验证。 |
| 发现项详情抽屉（2026-10-20） | 前端 helper/源码契约回归和生产构建通过；浏览器/Server 联调未运行 | ID 选中跟随当前集合，筛掉/删除关闭；文本字段无 HTML/自动链接且保留长文本，缺状态事件时明确提示。Esc/遮罩、焦点、窄屏和实际轮询体验仍待浏览器验收。 |
| Stage 2 自动综合扫描四步向导（2026-10-20） | 前端 helper 回归和生产构建通过；浏览器/Playwright 验收未运行 | 自动综合扫描立即任务按目标、方案、执行方式、确认分步，回退保留配置，确认页展示 Server 将重新校验的有效端口和排除项；未授权、无权限和未到确认步骤不会提交。定时、离线输入和旧任务复制保留旧流程；尚未补扫描方案资源和真实浏览器五次点击验收。 |
| 四入口与本地只读 API 骨架（2026-10-16） | 仅搭建结构，本轮按用户要求暂未运行测试 | 增加统一启动入口、Portable 编译入口、Server/Portable loopback 只读诊断 API 和数据库接口定义。业务接口 501，readyz 503，未启用 Node API、数据库、扫描或规则激活。须后续完成跨平台编译、API/安全边界测试与接口联调。 |
| UI 用户管理契约与前端发布构建（2026-10-16） | 本地前端双模式、Go、YAML/actionlint 通过；GitHub 云端未运行 | 新增用户/角色演示页面，GET `/api/v1/users` 仅返回 501；用户写入/认证/RBAC/审计不开放。CI 纳入 Node.js 22 npm ci + 双模式打包检查；Release 仅构建一次 Server-mode UI 作为 `web/` 静态资产加入每个平台的归档，不表示 Server 已支持 UI 静态服务。 |
| SQLite 账号管理（2026-10-16） | 单元/竞态及本机 HTTP 联调通过；远程部署未验收 | 使用纯 Go SQLite、bcrypt、HttpOnly/SameSite Cookie，账号 CRUD 需 admin 且写审计；本机测试包含初始化、登录、新增/停用、越权拒绝、登出。仅用于 loopback 开发，不表示平台扫描或节点 API 已可用。 |

## 2026-10-20：发现项详情抽屉

- `/findings` 以 Ant Design Drawer 替代行内展开，显式“查看详情”按钮支持键盘操作；状态操作均阻止事件传播，继续遵守原演示模式、Server 角色权限和 FIXED 限制。
- 仅保存选中 ID，内容每次从当前 findings 读取最新对象；选中记录被过滤或移除时关闭。支持 Esc/关闭按钮/遮罩、窄屏宽度，关闭后原按钮仍在 DOM 时恢复焦点。详情 ID 不加入 URL，分类筛选继续沿用现有查询参数。
- 展示已有检测依据、目标/归属、组件/版本、描述/影响/修复建议/证据/路径/参考、时间/连续未检出计数和关联 ID。空值统一“未提供”，不将现有时间伪造成事件时间线，并明确“暂无状态变更记录”。所有不可信字段按 React 文本渲染，长字段保留全文并放入可键盘滚动区域。
- 实际通过：`node web/src/pages/Findings/drawer.test.mjs`、`node web/src/pages/Findings/filters.test.mjs`、`node web/src/pages/Assets/import.test.mjs`、`node web/src/pages/Tasks/policy.test.mjs`、`node web/src/pages/Tasks/wizard.test.mjs`、`npm --prefix web run build`、`git diff --check`。新增纯函数和 TypeScript AST 源码契约检查，覆盖空值/零值、HTML 转义、长文本无截断、最新记录/筛掉/删除、触发按钮及状态按钮事件隔离。
- 未运行真实浏览器或 Server 联调；焦点恢复、Esc/遮罩、窄屏与实际轮询/PATCH 体验仍需独立浏览器验收。本次不修改后端、数据库或扫描行为。

## 2026-10-20：自动综合扫描四步创建向导

- `/tasks` 的自动综合扫描立即任务改为“目标 → 方案 → 执行方式 → 确认”四步向导。目标仍只能从已登记主机选择；端口策略、强度、任务排除、自定义规则和时间窗沿用原字段，未新增网段或范围外目标入口。
- 向导只在当前步骤校验，前后返回保留字段；修改配置会清除原运维授权。确认页显示有效端口预览、系统/资产/任务排除、隔离端口和时间窗；端口预览是提示，Server 仍通过原任务 API 重新校验并冻结范围。全端口和完整自定义范围继续提交前二次确认。
- 提交守卫拒绝无权限、未完成确认或未勾选授权；定时任务、模拟任务、离线 Trivy 输入和旧任务复制保留原表单路径。新增 `wizard.ts` 与端口预览 helper 的 Node 回归，使用文档保留地址段夹具，不访问网络。
- 实际通过：`node web/src/pages/Tasks/policy.test.mjs`、`node web/src/pages/Tasks/wizard.test.mjs`、`npm --prefix web run build`、`make test`、`make lint`、`make build`、`git diff --check`。未运行浏览器/Playwright 或真实扫描。

## 2026-10-20：大体积签名漏洞库导入

- 新增 Updater `--import-bundle-file`：对本地签名 ZIP 使用 `ReaderAt` 直接读取，单包上限 2 GiB；同时识别 GitHub Actions 下载的 `vuln-data/releases/<版本>/` 目录树 ZIP，只提取唯一版本目录，不把 `CURRENT`、说明文件或外层校验清单当作规则文件。
- HTTPS Fetch 改为在 Updater 私有临时文件中流式写入并计算整包 SHA-256，再复用同一签名、路径、文件哈希和防回滚校验；失败/取消清理暂存文件。网页上传仍为 256 MiB，避免 SQLite BLOB 与 JSON/base64 放大。
- `go test -race ./internal/rules`、`make test`、`make lint`、`make build` 通过；新增普通 ZIP、Actions 目录树 ZIP、超大稀疏文件和符号链接失败路径测试。
- 使用下载目录的 `vulnerability-data.zip`（约 1.1 GiB）完成本地 Ed25519 签名和全部 manifest 文件哈希校验，成功导入版本 `20261020.113500`。当前 `CURRENT` 仍为 `20261020.120359`，未自动切换；由于导入版本较旧，切换必须由操作员显式执行回滚并按平台审计流程处理。

## 2026-10-20：PoC #2 本地任务租约协议与 Worker 守护

- SQLite `scan_tasks` 新增 `pinned_rule_version`、`lease_expires_at`；旧库启动时自动补列。非模拟任务由 Server 在领取时生成有限租约，规则任务固定领取时的规则版本，端口探测绑定不参与规则回收的 `__no_rules__` 哨兵。
- 新增 `POST /api/v1/worker/renew`，只允许原任务、Worker 和绑定版本续租。Server 拒绝错误绑定、过期租约和 hard deadline 后续租，并把新到期时间限制在短租期和 hard deadline 内。任务结果回报也校验同一租约；`Tick` 将过期任务回收到 `PENDING` 或 `PAUSED_WINDOW`。
- Worker 真实启动路径使用 `scheduler.LeaseGuard`；续租失联达到最后确认租期后取消执行，租约错误不会再发送可能被重新分配任务的 FAILED/COMPLETED 回报。缺少真实租约字段时真实 Worker fail closed，旧 fake/synthetic 测试保持兼容。
- `go test -race ./internal/repo ./internal/api ./internal/taskflow ./internal/scheduler` 通过，覆盖旧 Schema 迁移、claim/renew 绑定、续租边界、Tick 回收、API 200/409、并发续租和 Worker 续租成功/失联自终止。该结果仅证明本地 SQLite 和回环 HTTP 协议；生产 TLS、节点令牌、独立进程强杀及跨节点重分配仍未验收。

## 2026-10-20：PoC #2 CURRENT 门禁与规则版本上报

- Runner 新增只读 `CurrentRuleVersion` 检查，使用 `versionmgr.ReadLocalCurrent`，拒绝缺失、非法指针、链接和不存在的当前版本目录；不创建或修改规则目录。真实 Worker bootstrap 接入该回调。
- Worker 首次及周期心跳携带 `localRuleVersion`；缺失 CURRENT 时节点状态为 `WAITING_FOR_RULES`，按轮询间隔等待，Server 领取过滤会把规则任务留在队列。当前版本不一致的规则任务同样不领取；`port-probe`/`zap` 不依赖规则，保留兼容路径。无效 CURRENT 状态为 `RULES_ERROR` 并停止领取。
- Server 在 LocalNode 的 `boundRuleVersion` 保存最近一次 Worker 版本；OpenAPI、API 文档与 PoC #2 已同步。新增 Worker 等待/无效 CURRENT、规则任务过滤、节点心跳持久化和 Runner 只读路径测试。生产节点 TLS/令牌、跨节点版本分发仍未验收。

## 2026-10-20：自动综合扫描失败回报修复与靶场进度

- 修复 HTTP 只读检查失败后自动任务报告缺少 SSH 系统包阶段状态的问题。失败与暂停报告保留明确的“尚未开始”状态，Server 对失败任务也持久化该状态；不会将未完成任务记为成功。Worker/Server 针对性 race 回归、`make test`、`make build`、`make lint`、Server 模式前端构建通过。
- V4 排除端口靶场验证通过：任务明细确认任务级排除生效、排除端口未进入 HTTP 检查，范围内 SSH 采集链路正常。结果明细保留在本机任务记录。
- V5 全 TCP 端口实扫仍待验收。用户已授权仅扫描单一靶机容器 IP；宿主机与 OrbStack 的直连路由冲突，需解决后再执行，不能将开发机回环地址上的其他服务归入靶场结果。
- 平台已用现有 SSH 配置重启，`/healthz` 与 `/readyz` 返回就绪；任务记录仍保存在本地 SQLite。

### V5 路由检查补充

- 用户已授权将 OrbStack 靶机容器的单个 IPv4 登记为独立资产，并仅以温和强度扫描该地址的 TCP `1–65535`。
- 用户也授权调整 OrbStack 全局 Docker 地址池并重启引擎。曾临时配置文档保留网段 `203.0.113.0/24` 中的独立地址池并重启 OrbStack；靶机获得新地址后，宿主机仍将该网段路由到 Wi‑Fi 网关，直连未恢复。该尝试不能作为对端可达的证据。
- 已把 `~/.orbstack/config/docker.json` 恢复为原先的空配置并再次重启 OrbStack；靶场 Compose 文件也恢复为仓库原配置。容器现已恢复运行，平台保持停止，避免周期性可达性检查继续访问路由不明的目标。
- 之前曾对实验地址的 SSH 端口做一次 TCP 建连探测，路由显示经过 VPN，无法确认对端身份；没有发送 SSH 握手、凭据或扫描请求。当前没有创建 V5 任务，也没有运行全端口探测或扫描引擎。
- V5 需等宿主机网络/VPN 路由可让 OrbStack 的容器直连功能启用，并在直连后核验 SSH 主机指纹，再对登记的单个靶机 IP 扫描。OrbStack 会在容器网段与 VPN/其他网络冲突时自动关闭容器 IP 直连；本机当前同时存在覆盖私网地址的 Wi‑Fi/VPN 路由，单独更改 Docker 地址池没有消除冲突。


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

## 2026-10-16：固定引擎安装与本地真实执行

按早期开发模式接入 Nuclei 3.11.1（MIT）、Trivy 0.76.0（Apache-2.0）、ZAP 2.17.0（Apache-2.0）。官方 release 地址、各平台压缩包 SHA-256 与许可证记录在 `config/engines.lock.json`；本机 Darwin arm64 三种程序已下载校验，ZAP 使用现有 Java 17。`bin/`、规则库、缓存和结果均被 Git 忽略，未提交程序或漏洞库数据；没有新增 Go/npm 依赖或修改工作流。

实际验证：

- `make build`、`make lint`、`make test`（`go test -race ./...`）：通过。
- `make verify-flags`：实际版本及帮助输出通过；Nuclei 23 项、Trivy 17 项、ZAP 7 项。原参数校验占位现已替换。
- `python3 scripts/test_local.py`：原有 9 组本地业务回归通过；测试 HTTP 客户端显式绕过环境代理，Worker 使用隔离规则/运行目录。
- `LAB_ENV=isolated go test -tags=lab ./internal/executor -run TestInstalledEnginesOnLoopbackFixture -v`：临时回环 HTTP 夹具通过，HTTP 夹具 Nuclei 检出 4 项、ZAP 检出 3 项；自签名 HTTPS 夹具分别检出 4/5 项。两种协议共收到 6 次根路径 GET，没有其他路径。
- `LAB_ENV=isolated go test -tags=lab ./internal/executor -run TestInstalledTrivyOnLocalDependencyFixture -v`：本地测试依赖锁文件检出 5 项。
- `LAB_ENV=isolated python3 scripts/test_engines_local.py`：独立 Server/Worker/Updater 和 SQLite 全链路通过。Nuclei 4 项、ZAP 4 项、本地依赖 5 项；自制 Docker-save 元数据夹具 49 项（计数依赖当前 DB）。验证跳过端口、不爬取路径、ZAP 仅分析记录响应、Trivy 不下载依赖/镜像、重复结果去重、镜像不可变标识、缺失输入失败且不制造成功结果。
- 浏览器：三个引擎显示固定版本与本地就绪；任务表单可选择 ZAP/HTTP 和 Trivy 本机输入；通过网页创建 Trivy 夹具任务，观察完成并在发现项页看到 5 条真实引擎输出，模拟记录单独标注。
- `GOOS=windows GOARCH=amd64 go build ./...`、`GOOS=linux GOARCH=amd64 go build ./...`：编译通过；没有声称在这两个系统运行过真实引擎。
- 新单元测试覆盖受限模板拒绝路径、范围外 HTTP/结果拒绝、重定向不跟随、解析/fuzz 入口、Trivy 输入越界/符号链接拒绝、多条发现入库、跨任务稳定去重与保留人工状态、不同归档名的相同镜像去重、子进程到期终止。

实测修正：Nuclei 3.11.1 的 `-fhr` 与 `-dr` 同传会拒绝启动，因此只使用 `-fhr` 限制同主机重定向；ZAP 分发包中的 exim 0.16.0 不认识新版文档的 `sendRequests`，使用该固定版本原生的离线 HAR 导入。Trivy 主库实际解压约 1.5 GiB，规则导入单文件上限改为 4 GiB、总量 8 GiB，压缩 ZIP 上限仍为 256 MiB。旧单条发现 Schema 兼容迁移到一任务多条发现，保留已有模拟记录。

未验证及边界：未连接任何真实业务服务器，明天使用用户指定的一两台服务器验证。Nuclei 仅只读根路径 HTTP 基线，未启用完整上游 YAML/CVE 模板库；ZAP 不含主动扫描或爬虫任务；Trivy 支持 Worker 本机依赖/镜像归档，不含 SSH、远程镜像拉取或 Docker socket。默认只准备 Trivy 主库，JAR 需额外导入 Java DB。签名、完整规则兼容矩阵、生产节点 TLS/独立令牌、系统网络围栏仍未验证或未启用；遵循本次早期开发范围。

操作说明：`docs/engines.md`。所有真实任务都由用户明确选引擎后创建，目标在创建和领取时复核；未检出不自动转 FIXED。本文计数只记录夹具验证摘要，不包含真实扫描结果或资产数据。

同日补充：Worker 会在发送前检查结果 JSON 的 4 MiB 上限，超出时回报明确失败并提示拆分输入，避免请求被拒后任务停留在执行中。新增超大结果回归测试；`go test -race ./internal/taskflow ./internal/api` 与 `make build` 通过。此项不改变 API 字段或现有大小限制。

## 2026-10-19：Linux 软件包快照与混合部署输入

- 新增 Trivy `rootfs --pkg-types os` 任务；API、Server 校验、调度输入、Worker、前端类型与 OpenAPI 同步。仍在已有任务/发现项页面操作；新增按目标、组件或 CVE 筛选，修正窄窗口下 CVE 和指纹挤压。系统包指纹忽略临时分析路径，使用稳定输入别名、包、安装版本与 CVE。
- 新增标准库 Python Linux 采集工具：只复制发行版/包数据库、明确指定的应用依赖文件、指定本地 Docker 镜像或预先导出的归档。RPM SQLite 使用一致备份（含已提交 WAL）；不枚举镜像/容器/集群，不自动登录，不执行应用，不保存 kubeconfig 或 Docker 凭据。每个组件生成文件 SHA-256 清单；输出私有权限并自带忽略全部内容的 `.gitignore`。
- Worker 扫描前后核对快照，拒绝漏传、修改、未声明文件、符号链接和越界路径。哈希阶段保留 context 取消/截止语义。采集失败不发布完整目录、不覆盖现有输出。
- 修复固定 Trivy 对 OCI tar 的输入差异：该版本要求 OCI layout 目录。Worker 私有解包白名单布局，核对 blob SHA-256，拒绝穿越、链接、重复、缺失或多平台歧义，不解开容器层，结束后清理；Docker tar 保持直接输入。
- 系统包检查使用实际发行版 ID；麒麟等未适配源明确失败，忽略 `ID_LIKE` 的厂商替代含义。不把 CentOS Stream / RHEL 10 的 SBOM 能力当作当前漏洞覆盖。Worker 只把显式定义的安全提示回传网页，原始诊断仍留在私有日志。
- `make build`、`make lint`、`make test`（race 与采集工具 8 项测试）、Server/Demo 前端构建通过；Linux amd64/arm64、Windows amd64 交叉编译通过。仅表示可编译，未在这些 Linux 系统或 CPU 上运行引擎。
- `make verify-flags` 核对 Nuclei 23 / Trivy 18 / ZAP 7 个参数；快照 JSON fuzz 实际运行约 32 万次，无失败；新 Linux release 与 OCI tar fuzz 入口包含在单元测试。
- 原有 `scripts/test_local.py` 9 组普通业务回归通过。`LAB_ENV=isolated python3 scripts/test_engines_local.py` 完整通过：合成 Debian 系统包 49 条、选定 Node 依赖 5 条、Docker 与 OCI 归档各 49 条且相同镜像跨格式去重；重复系统检查不重复，修改快照拒绝，模拟麒麟发行版明确失败，缺失输入拒绝。Nuclei/ZAP 既有回环夹具各 4 条。计数基于本机当前漏洞库；没有连接真实服务器、Docker/containerd daemon 或 Kubernetes API。
- 浏览器实际提交 rootfs 夹具任务，完成后查看系统包发现项：显示稳定来源、采集时间、组件、安装/修复版本，`lab-a/os` 筛选共 49 条；前端无 console error。原始证据留在本机私有临时目录，截图在本机可视化目录，未提交资产或结果。
- 已知边界：只实测合成 Debian / Node / 镜像；CentOS 7 RPM 实际识别、银河麒麟厂商源、源码安装中间件、国产数据库产品级检测、运行内核/进程/容器卷仍待专项适配和指定服务器验证。CentOS 使用 RHEL 公告的限制见官方文档；不能伪造发行版来补覆盖。Java 索引默认尚未准备，后续单独补齐。说明见 `docs/linux-server-scan.md`。

## 2026-10-19：离线 Java 索引与已部署应用

- 新增 `make engines-java` / Updater `--with-java-db`，通过锁定 Trivy 的 `--download-java-db-only` 显式下载 Java 组件索引；主漏洞库仍用于 CVE 匹配。实际 Java OCI 压缩层约 940 MiB，展开索引约 1.5 GiB；与主库合计约 3 GiB。
- Updater 本地准备改为流式复制、哈希、fsync 和私有暂存发布，避免把大库组装成内存 ZIP 或写进 Server 数据库。沿用不可覆盖版本、完整性核对、独立激活；失败/取消不切换 CURRENT。网页 ZIP 仍限 256 MiB，单文件 4 GiB、总展开 8 GiB 的限制均保持。支持完整缓存目录的离线准备，实际 `--skip-db-download` 安装并激活通过。
- 实测修正两个固定版本行为：Trivy filesystem 禁用 JAR/Go 二进制分析，需要 `rootfs --pkg-types library`；Go 默认按执行权限筛文件，需要固定 `--file-patterns gobinary:.*` 读取选中的非执行 ELF。新增 `artifact` 任务类型，API/OpenAPI/前端同步；不授予执行权限、不运行输入文件。锁文件与部署产物选错模式明确拒绝，混合应用采集自动拆为两个独立输入。
- Java 索引缺失的部署目录任务回报可操作的失败提示；节点状态区分主库和 Java 索引文件。采集脚本改为 Python 3.6 语法可用，SQLite RPM 一致备份要求 3.7+；旧解释器实际运行仍待目标环境验证。
- `make build`、`make lint`、`make test`（race、采集工具 9 项测试）通过；原有 9 组普通业务回归再次通过；前端 Server/Demo 构建、OpenAPI 四种输入枚举核对通过；Linux amd64/arm64、Windows amd64 交叉编译通过。`make verify-flags` 实测 Nuclei 23 / Trivy 20 / ZAP 7 个参数。
- `SCANNER_EXPECT_JAVA_DB=1 LAB_ENV=isolated python3 scripts/test_engines_local.py` 完整通过：Java 元数据 JAR 7 条（含预期 CVE-2021-44228）、Node 锁文件 5 条、合成 Debian 系统包 49 条；含相同 Java 元数据的 Docker/OCI 归档各 56 条并跨格式去重；Linux amd64/arm64 两个自建 Go ELF 均实际分析构建信息。没有执行夹具程序、加载脆弱库字节码、访问 Docker/Kubernetes 或真实业务服务器。
- 浏览器实际选择“已部署应用 / 中间件”、提交 Java 夹具任务并观察完成；筛选该输入仍为 7 条，重复检查保留首次时间；严重级别筛选及安装/修复版本展开正常。前端无 console error。测试实例已与用户数据库隔离，证据保留在本机私有目录。
- 新失败路径测试覆盖 Java 数据缺失、缓存链接、超限稀疏文件、取消、不可覆盖版本、CURRENT 保持、混合输入模式和时间窗取消语义；没有新增 Go/npm 依赖或修改 CI 工作流。
- 本地数据已具备 Java/Go/Node/系统包/镜像的通用分析链路；真实 CentOS 7、银河麒麟厂商公告源、具体中间件及国产数据库专项识别仍未完成。完整 Nuclei CVE 模板库、Kubernetes 自动接入与生产部署不在本次实现中。不能把合成夹具计数当真实资产结果。

### 同日补充：混合应用分流覆盖修复

- 合成夹具复现：根目录与已有 `artifacts/` 下的同名 JAR 在原地分流时发生覆盖，采集成功但嵌套内容丢失；已有 `dependencies/` 下的同名锁文件也受同一问题影响。改为在输出暂存目录内的独立目录分流，保留各文件的原相对路径，完成后替换组件目录；整个输出仍在最后原子发布，异常由现有清理逻辑移除暂存内容。
- 新增回归保留根/嵌套同名 JAR 和锁文件的全部内容及快照 SHA-256，并模拟分流中途存储失败，确认无输出发布、无暂存残留。开发先运行新增回归确认旧实现失败，修复后 `PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_collect_linux_inputs.py -v` 的 11 项测试通过；未运行全量引擎测试。
- 分工记录：本轮最初方案复核因高阶模型容量限制改由 GPT-5.6 Sol 只读执行；开发修复使用 GPT-6.1 Sol，独立验收使用 GPT-6 Sol 与 GPT-6 Luna。后续默认分工已按 Sol/Luna 调整，见 `AGENTS.md`。
- 混合目录覆盖修复后，GPT-6 Sol 独立复现并核对根目录、`artifacts/`、`dependencies/` 中同名 JAR/锁文件的全部字节及 SHA-256 清单；Python 11 项和完整本机引擎夹具均通过。证据目录位于本机私有临时目录，未写入仓库。
- GPT-6 Luna 独立运行 `LAB_ENV=isolated go test -tags=lab ./... -run '^$'`，全部包编译通过且未运行测试；同时确认所有 `PrepareDefault` 调用使用新签名，并复核 Go ELF 必须逐个显式选择的说明与命令行帮助。

## 2026-10-19：报告能力、资产画像与契约同步

- 依据 `report-capability-plan.md` 的已确认决策,同步 AGENTS、架构和产品方案:在明确授权目标内允许有界端口发现、服务识别与只读检查,不再逐端口申请审批;当前仍仅支持数字 IP,不声称域名 Server 固定解析已经实现。排除/隔离优先、无主机扩展、无口令猜测与默认口令尝试。方案 2.4 修正为 ICMP 未响应仅表示未知,继续 TCP 检测。
- SQLite 画像/服务/入口、发现元数据、知识库/策略、任务观察与报告快照/队列已接入;PostgreSQL 只新增 0004、保留已应用迁移,JSON 保持 TEXT。四迁移共 27 张业务表加 journal;静态脚本表名/版本核对与 `bash -n scripts/check-postgres-schema.sh` 通过。未连接 PostgreSQL 执行迁移,PG RuntimeStore adapter 尚未实现。
- OpenAPI 同步新路由与资产/任务/发现/报告类型,Worker 回报上限 32 MiB、报告快照 32 MiB、文件 64 MiB。Ruby YAML 解析与全部 schema `$ref` 核对通过,当前 54 个路径、46 个 schema;这不是生产节点鉴权/TLS验收。
- 文档/契约开发代理实际运行 `go test -race ./internal/reporting ./internal/repo` 和 `go test -race ./internal/findings ./internal/portprobe ./internal/executor`,全部通过;`git diff --check` 通过。报告覆盖 CVSS 边界、登录入口分计、稳定指纹去重、三格式公共内容/八章八表、TOP 截断、公式文本、冻结模板和任务历史观察、失败重试与恢复。端口/识别/配置检查使用假拨号器及回环服务,未对真实业务目标扫描。
- 知识库仅支持公开来源整理的规范 JSON 与自建中文内容,不自动导入 OSV 原始格式,不自动接入 CNNVD/CNVD。通用组件识别与版本推断不能证明 CentOS/麒麟、国产数据库或所有厂商产品覆盖。HTTP 预检/代理/原生检查共享端点请求预算及强度限速;TLS 隧道模板仍需模板白名单与引擎限速共同约束。
- 使用路径见 `docs/product/report-usage.md`,R1–R6、HTML/Word 八章、Excel 八表清单见 `docs/product/report-checklist.md`。真实隔离靶机和排除端口抓包、Word/Excel 原生软件视觉排版、PostgreSQL 实例、大规模内存/耗时与具体厂商覆盖均待环境验证。本轮未读取或提交参考报告的真实地址、资产、结果。
- 本轮约定方案 GPT-6 Sol、开发 GPT-6.1 Sol、独立验证 GPT-6 Luna;上述文档/契约开发检查由 GPT-6.1 Sol 实际执行。独立验证与最终全仓库门禁结果由协调代理另行记录,不以开发报告代替独立验收。

## 2026-10-19：合并后最终本地复核

- 修正 Nuclei 3.11.1 参数互斥错误：`-dr` 与 `-fhr` 同时传入会导致引擎拒绝启动，现仅传硬规则要求的 `-fhr`；`make verify-flags` 与隔离回环 Nuclei/ZAP 运行均通过。
- 远端并入的报告范围回归、同主机多端口影响资产去重、PostgreSQL 只读资产/范围适配和迁移工作流已通过 `make test` 的 race 测试；PostgreSQL 云端实例仍由 GitHub Actions 负责实际执行。
- 第三方 GitHub Actions 已固定到提交 SHA，并在行尾保留版本注释；YAML 解析通过，未使用 `pull_request_target`。
- 当前代理实际运行并通过：`make build`、`make lint`、`make test`、`make verify-flags`、`make test-local`、`make test-engines-local`、Server 模式前端构建、Windows/Linux/macOS 交叉编译，以及 HTML/XLSX/DOCX 合成报告结构检查。
- 仍未连接真实业务服务器、真实 CentOS 7/银河麒麟主机、生产 PostgreSQL、Microsoft Word/Excel 或生产网络围栏；本地引擎回归仅使用回环夹具、临时数据库和本地漏洞库，未读取真实资产或扫描结果。

## 2026-10-20：Nuclei 范围代理默认端口规范化

- HTTP(S) 代理请求缺少 URL 默认端口时，仅按 scheme 补齐 80/443 后与已授权的精确 IP:端口比较；HTTPS CONNECT 仍要求显式端口，不解析域名、不扩大授权集合。
- Worker 对代理拒绝记录固定原因类别和计数，不记录目标地址或原始请求。
- `go test -race ./internal/executor -run 'TestScopeProxy'`、`go test -race ./internal/executor`、`make build`、`make lint` 通过。另用本地假拨号器验证省略 HTTP 默认端口的请求只拨向匹配的授权端点；没有从该回归夹具连接外部主机。

## 2026-10-20：规则版本两阶段 GC 文件实现（隔离测试）

- 新增 `GCFiles.Quarantine` 和 `Delete` 两个显式入口，每个阶段重新读取本地 CURRENT、可信备用/退役状态和 Server 本节点的 RUNNING 数量。使用 Go 1.26 `os.Root` 限定文件操作目录，拒绝路径穿越、链接、目录替换、目标碰撞和查询期间的状态变化。
- 隔离后原子发布版本、节点、退役时间和隔离时间记录；缺失、损坏或不匹配的记录不允许自动删除。取消、查询失败或出现新保护状态时保持已有文件。删除部分失败不代表回滚，记录丢失的残留隔离目录需人工核查。
- 开发侧运行 `go test -race ./internal/versionmgr ./internal/scheduler` 通过；独立验证实际运行 `go test -race -count=1 ./internal/versionmgr ./internal/scheduler ./internal/workerfence`、对应包的 `go vet` 和目标文件 `git diff --check`，均通过。
- 方案使用 GPT-6 Sol，开发使用 GPT-6.1 Sol，独立验证配置 GPT-6 Luna。检查只使用临时目录和模拟 Server；未重启运行中的平台，未修改运行数据库、规则盘、SSH、靶机或网络。
- 这两个入口尚未接入真实 Updater/Node API，不启用自动回收。部署依赖单 Updater 独占规则根目录、完整激活与回收协调、Server 不再为退役版本发放新租约；真实进程联调、跨系统竞态、Windows 实机和断电持久性仍待验收。

## 2026-10-20：外部规则包 Ed25519 验签（隔离测试）

- Updater 新增包外受信公钥配置；普通 Import/Fetch/Activate 验证原始 manifest 与独立 raw64 Ed25519 签名，缺少信任、签名错误或内容不符均拒绝，CURRENT 不变。不会从包内取得公钥，也不会给已有 unsigned 版本自动补签。公钥仅支持严格 PKIX Ed25519 PUBLIC KEY PEM，受大小、普通文件、路径和目录身份检查约束。
- 本地 PrepareDefault 通过同一 Manager 实例中绑定根目录、版本和摘要的一次性记录执行专用激活；普通导入不能产生该记录，重启或失败尝试不会继承能力。历史无签名数据仍可只读展示，但不会声称已验签。页面依据实际签名字段显示状态，未验签版本禁用普通激活/回滚。
- Go 单测运行时生成测试密钥；Python/OpenSSL 打包的 raw64 签名已实际由 Go Import/Activate 接受。失败路径覆盖缺签名、签名长度/公钥错误、manifest 原始字节变化、激活前修改、旧版本冲突、本地准备能力复用、目录大小写别名，以及私钥混入打包目录或硬链接输入。
- 开发和独立验证均运行 `go test -race -count=1 ./internal/rules ./internal/versionmgr ./internal/bootstrap ./internal/executor` 通过；独立 `go vet` 与差异检查通过。主代理实际运行 `go build ./...`、`make lint`、`make test`（全仓 race 和 11 项 Python 采集测试）、前端 `tsc --noEmit`、`bash -n scripts/dev.sh`，均通过。编译未覆盖运行中的 dist，未执行 make dev、真实扫描、规则导入或规则切换。
- 分工：方案 GPT-6 Sol、开发 GPT-6.1 Sol、独立验证配置 GPT-6 Luna。只修改启动脚本的可选公钥文件路径传递，未配置或重启当前平台。完整业务实例/真实签名包联调、GitHub 云端执行、密钥轮换和完整引擎兼容矩阵仍待验收；无副作用的 `--status` 只报告模式，不验证运行配置。

## 2026-10-20：SSH 指定部署目录 Java/Go 应用（隔离测试）

- 按用户选择实现 Worker 本地 profile 的 `apps`，每项显式配置别名、具体部署目录及 Java/Go 类型。沿用同一数字 IP、明确选中且开放的 SSH 端口和固定 SSH 安全参数；无 apps 不增加连接，排除范围之外不尝试采集。原始部署路径不进入 Server 报告。
- Python 通过有界安全 token 接收配置，以目录句柄、O_NOFOLLOW、文件身份复核进行有界读取。每文件独立快照，Go 校验 tar 路径、类型、数量、SHA-256 与固定结构；Java ZIP 路径/中央目录/展开/嵌套均有预算，ELF 必须通过 Go build info。超限、空目录、变化、链接和不支持的产物明确失败，不静默截断。
- 每个文件顺序执行 Trivy，扫描前后检查快照；只有 Class=lang-pkgs、Type=jar/gobinary、非空 Target 才计为已分析，零漏洞可以完成。类型依据锁定 Trivy v0.76.0 的官方 [analyzer 常量](https://github.com/aquasecurity/trivy/blob/v0.76.0/pkg/fanal/analyzer/const.go)、[报告结构](https://github.com/aquasecurity/trivy/blob/v0.76.0/pkg/types/report.go) 和 [JSON writer](https://github.com/aquasecurity/trivy/blob/v0.76.0/pkg/report/json.go)，未新增引擎参数。
- Worker/Server/清册贯穿固定应用状态及选中/已分析计数，Server 限定最多 8 个别名、每项 16 文件、总计 32 文件；完成状态要求每项非空且全部分析。失败与暂停保存覆盖状态和系统包状态，失败报告不插入部分漏洞；兼容旧 Worker 无应用字段，界面明确显示旧任务没有应用覆盖记录。指纹继续使用稳定主机与包字段。
- 独立首轮回归发现 Java ZIP 的 `../escape` 可绕过单独 path.Clean 检查，开发显式拒绝父路径前缀后独立复验通过；未放松原检查。最后增补 C1 控制字符拒绝与种子回归。
- 主代理全仓 `make test`（race 与 18 项 Python 合成测试）、`make lint`、`go build ./...`、web 下 `tsc --noEmit`、OpenAPI YAML/全部本地 schema 引用检查、`bash -n scripts/dev.sh` 和差异检查通过。新增目录解析与 Trivy 类型门槛各实际 fuzz 2 秒通过。Windows amd64、Linux arm64 的 `go build ./...` 交叉编译通过，编译未生成或覆盖 dist/web/dist。
- 独立验证实际运行 `go test -race -count=1 ./internal/sshcollect ./internal/executor ./internal/taskflow ./internal/repo`、对应包 vet、无输出构建、web 类型检查、Python 18 项与差异检查，均通过。分工：方案 GPT-6 Sol、开发 GPT-6.1 Sol、独立验证配置 GPT-6 Luna；协调代理完成协议/持久化/前端贯穿与全仓检查。
- 上一轮代码验收未重启服务、修改当前运行数据库/规则/SSH 配置/靶机/网络，也未执行真实 SSH、扫描引擎或 lab。本批拒绝根设备之外的独立挂载目录，无法通过设备号区分同设备 bind mount；ZIP64、分卷、较大归档及超限目录仍不支持。完整应用安全覆盖、真实凭据/索引/产物联调需后续隔离靶场验收。

### 2026-10-20：SSH 应用隔离靶场验收续测

- 重新构建并启动最新 Server、Worker、Updater 和 Server-mode 前端；`/healthz`、`/readyz` 正常，当前本地服务继续使用既有 SQLite、规则目录和 SSH profile。
- 发现 `scripts/dev.sh` 在 `set -u` 下展开空的可选参数数组会导致启动失败；改为按是否配置 SSH 公钥和 SSH profile 分支启动，并用带 SSH profile、无 SSH profile 两种方式回归通过。修复已提交为 `db41202` 并推送到 `main`。
- 在隔离 OrbStack 靶机中放入合成 Go ELF 和 Java JAR，使用一次性临时 Server/SQLite 验收真实 SSH 采集链路。Go 路径任务完成，应用覆盖计数为选中 1、分析 1；系统包、SSH 服务和 HTTP 服务阶段也完成。靶机临时采集目录在任务结束后清理。
- Java 路径任务成功完成 SSH 采集，但由于当时规则目录缺少 Trivy Java 索引，任务以 `analysis_failed` 结束，应用计数为选中 1、分析 0；没有插入部分成功结果，验证了失败即关闭行为。该条记录保留为缺索引失败路径，成功路径见下方 Java DB 隔离复验。
- 独立运行 `go test -race -count=1 ./internal/versionmgr ./internal/scheduler ./internal/workerfence`、`go vet ./...`、`bash -n scripts/dev.sh` 和差异检查，均通过。未运行全端口扫描，也未修改主运行实例的数据库、规则库、网络或 SSH 凭据。
- 提交 `798f832` 的 GitHub CI 已云端完成并通过全部矩阵。随后以 `db41202` 为基线触发的 `Build Offline Vulnerability Data` 也已完成：8 个规则文件校验通过，签名步骤输出 `Signature Verified Successfully`，并上传 `vulnerability-data` 制品。此前历史运行早于签名步骤，未作为当前签名验收证据。

### 2026-10-20：隔离靶机 Java 内容补齐

- 在隔离靶机的明确部署目录中刷新合成 Java JAR：包含一个不执行的示例 class、Manifest，以及用于离线组件识别的 Maven 元数据；文件保持普通只读权限，未启动 Java 进程、未发起网络请求，也未加入仓库或扫描结果。
- 容器内回读并校验 JAR 中的 class 与元数据条目，确认采集输入不再是只有元数据的空壳夹具。此前 Java SSH 采集的失败路径记录仍保留：当前活动规则版本缺少 `trivy-java.db` 时，应用阶段必须回报 `analysis_failed`，选中项不能计入已分析，也不能显示成“无漏洞”。
- 用一次性临时 Server/Worker 重新回归当前夹具：Go 应用链路仍为 `completed` 且选中/已分析均为 1；Java 目录已选中 1 个文件并完成 SSH 采集，但因 Java 索引缺失以 `analysis_failed` 结束、已分析为 0。临时数据库、输入和日志均未写入仓库。
- 当前开发进度：Java 靶机输入已准备；SSH 有界采集、缺索引失败闭环和带 Java DB 的隔离成功路径均已验证；活动规则已切换到包含 Java DB 的版本，但该版本由本地显式准备产生，签名状态仍为未验签。该状态不代表真实业务 Java 应用或完整中间件覆盖已验收。
- 本次只验证容器文件内容和权限，没有停止正在运行的平台服务、修改主运行数据库/规则盘/SSH 凭据或扩大扫描目标。

### 2026-10-20：Java DB 隔离成功路径

- 使用下载目录中的 `vulnerability-data.zip`，先校验 `SHA256SUMS` 和 manifest 内 8 个文件的 SHA-256；包内包含 `manifest.json.sig`、主 Trivy DB 和 Java DB。GitHub Actions 已对该制品完成 Ed25519 签名验签；本机未配置对应公钥，因此没有把本次解包动作表述为再次本地验签。
- 规则包只解包到临时规则根，没有替换当前活动 `vuln-data`。一次性临时 Server/Worker 使用该规则版本和隔离靶机的显式 Java 应用目录重跑，SSH 采集、Java 类型识别和 Trivy 结果门槛均通过；任务为 `COMPLETED`，Java 应用状态为 `completed`，选中 1、已分析 1。Go 应用链路同时回归通过。
- 本次成功路径只验证合成 Java JAR 的有界采集与离线版本匹配，不代表真实业务 Java 应用、Tomcat/Kafka/Nacos 配置或完整主机安全审计。当时运行中的平台仍指向没有 Java DB 的旧规则版本，随后已按下方记录完成规则切换；活动版本的签名状态仍须按切换方式解读。

### 2026-10-20：活动规则切换与平台重启

- 停止原有 Server、Worker、Updater 进程后，使用下载制品中已通过哈希校验的主库和 Java DB 缓存，调用 Updater 的 `--prepare-engines --with-java-db --skip-db-download` 完成本地显式准备和切换；没有直接覆盖规则目录，也没有使用网页大 ZIP 导入路径。
- `CURRENT` 已切换到新规则版本，活动目录同时包含 `trivy/db` 与 `trivy/java-db` 的数据库和 metadata；平台以原 SSH 配置重启，Updater 同时加载包外 Ed25519 公钥，`/healthz` 与 `/readyz` 均正常。
- 该本地显式准备流程只验证输入缓存和文件完整性，不继承下载包中的 `manifest.json.sig`；因此活动版本的 `signatureVerified` 保持 `false`。后续若要求页面显示已验签激活，需要增加适用于大体积预安装制品的受信安装流程，不能把本次本地准备结果当作普通签名导入。

### 开发期间原测试状态补充

- 本轮结束前只读查看任务清册，原有全端口任务已显示“已完成”。这只确认平台终态，不据此宣布 V5 全部验收项通过，也不算新增应用采集能力的实机验证；结果完整性和覆盖仍待单独复核。未将地址、任务 ID 或扫描发现写入本文。

### 2026-10-20：PoC #6 时间窗暂停与恢复集成回归

- 新增本地 Server/Worker/SQLite 集成测试：第一次领取将任务硬截止压缩到几十毫秒，Worker 到点回报 `PAUSED_WINDOW`；Server 不写入发现项。
- 调用 `RuntimeStore.Tick` 后任务回到 `PENDING`，Worker 再次领取并完成，最终只保存一个发现项；重复提交同一完成回报仍保持单条结果。
- 该回归只使用临时数据库、回环 HTTP API 和文档保留地址；没有连接外部目标，也没有改变正在运行的平台实例。真实长任务、多块租约、节点 TLS/令牌和进程级强杀仍待隔离验收。

### 2026-10-20：PoC #5 连续未检出与自动 FIXED 状态机（本地回归）

- Worker 回报新增完整性、规则执行引擎集合和冻结规则版本元数据。Server 仅在任务为 `COMPLETED`、完整执行授权范围、至少一个漏洞规则引擎成功执行、且回报规则版本匹配任务冻结版本时处理未检出计数；端口探测、旧 Worker 回报、失败/暂停、规则版本不匹配和范围外发现项不会触发状态收敛。
- 当前活动策略新增 `fixedThreshold`（1–3，默认 1），在任务创建时冻结；活动发现项达到阈值后标记 `FIXED` 并记录 `resolvedAt`，再次检出恢复为 `REOPENED`、清零计数。`FALSE_POSITIVE` 与 `ACCEPTED_RISK` 不受自动状态机影响。自动综合扫描按实际成功执行的 Nuclei/ZAP/Trivy 引擎集合和 SSH/应用采集状态决定是否具备完整性。
- 新增仓储 race 测试覆盖首检、完整缺失、重现、旧元数据、失败、版本不匹配、范围隔离和阈值 2；实际运行 `go test -race ./internal/repo ./internal/taskflow ./internal/executor -count=1` 通过。
- 本批仅使用临时 SQLite、合成回报和文档保留地址，未连接外部网络或生产资产。真实靶机的中断/熔断抓包、节点认证和跨进程引擎回报仍待 lab 验收，不能据此宣称 PoC #5 已完成实机验收。

### 2026-10-20：资产 CSV 预览与事务确认（本地回归）

- 新增 Assets 页模板下载、文件上传、逐行预览和明确确认闭环。API 为 `GET /api/v1/assets/import/template`、`POST /api/v1/assets/import/preview`（原始 `text/csv`）和 `POST /api/v1/assets/import/confirm`（仅 `previewId`）。管理员/安全工程师及现有 CSRF 请求头限制同时生效；viewer/ops_approver 不可导入。
- CSV 严格采用 UTF-8 无 BOM 和固定顺序表头，限制 1 MiB / 1000 条数据记录；支持数字 IP host 与现有 image_repo 格式，name 可省略，拒绝任何端口列。非法行、文件内重复、已有资产逐行给原因；任何错误阻止整批确认。
- SQLite 动态初始化新增 `asset_import_previews`，仅暂存全有效规范化行、当前用户和 15 分钟有效期。新预览替换同用户旧预览；确认事务先原子领取预览，再按资产唯一约束整批插入 assets/profile 和仅含数量的审计，失败全部回滚。成功后清空暂存行，重复/过期/跨用户确认拒绝。
- 新增表驱动解析/权限/CSRF测试、解析 fuzz 种子、预览资产/profile/审计零写入、确认重复/过期/替换/同用户限制、后发资产冲突整批回滚和并发确认一次成功回归；Pinger 为失败即报错替身，没有连接目标或启动扫描。前端回归覆盖空文件/体积、显式勾选、错误预览和过期确认门禁。
- 实际运行 `go test -race ./internal/assets ./internal/api`、`go vet ./internal/assets ./internal/api`、`node web/src/pages/Assets/import.test.mjs`、`npm --prefix web run build`、`make build`、`git diff --check` 及 Ruby YAML 解析通过。全仓门禁由协调代理另行记录。
- 待验收：真实浏览器文件选择和操作体验；PostgreSQL 资产写入、导入历史查询和 CSV 导出尚未实现。本批不改变既有 Server 清册可达性后台轮询，确认后的新主机可能在后续正常轮询中被检测；导入端点自身没有 DNS/Ping/扫描调用。测试只使用临时 SQLite、文档保留地址和示例镜像地址。

### 2026-10-20：漏洞分类筛选 URL 状态（前端回归）

- `/findings` 的六项分类筛选直接从 React Router 查询参数派生；筛选修改使用 replace，刷新及前进/后退读取当前路由，避免组件内第二份分类状态覆盖导航结果。已有筛选交集和本地文本搜索继续生效。
- 纯函数白名单解析非法/重复枚举和布尔值为默认值，规范化时省略默认筛选、保留无关参数；自由文本不写 URL，已有 `q` 在当前页面规范化时移除，不能据此宣称进入页面之前的历史已清除。
- 实际运行 `node web/src/pages/Findings/filters.test.mjs`、`npm --prefix web run build` 和 `git diff --check`。测试使用文档保留地址作为隐私隔离样例，覆盖各合法值、异常值、重复键、组合往返、无关参数保留、输入不变性及规范化幂等性。真实浏览器交互验收尚未运行。
- 本批仅修改前端与文档；没有变更 API/数据库/扫描边界或连接目标。


### 2026-10-20：单项漏洞指派与追加备注（本地回归）

- 新增最小指派候选、单项指派/清除和追加式备注 API；新端点均要求登录，写操作沿用 admin/security_engineer 与 CSRF 限制。RuntimeStore 在写事务内再次校验执行者和被指派者启用状态/角色，不依赖可竞争的预检查；缺少账户表或认证配置时关闭操作。
- Finding 增加独立处置人 ID/名称快照，扫描合并保留；SQLite 增加 finding_assignment_events 与 finding_notes。指派、历史/备注和审计原子提交，审计只写关联 ID、状态或字节数，不复制备注正文；备注是 1–2000 UTF-8 字节的单行纯文本，只追加，无编辑删除入口。
- 抽屉支持候选选择、清除指派和追加备注，作者/时间和正文按文本显示；演示模式不伪造服务端持久化。没有扫描调用或目标连接，也不改变漏洞状态或资产 Owner。
- 实际运行聚焦 race 回归 `go test -race ./internal/repo ./internal/api -run 'Finding(Assignment|Notes|Work|DispositionAPI)' -count=1` 及前端构建通过；覆盖无效/停用/只读角色、空值/UTF-8 字节/控制字符、指派扫描保留、并发追加、审计失败全部回滚、权限/CSRF 和只读读取。全仓门禁由协调代理补记。
- 待验收：真实浏览器操作、指派历史查询 UI、备注分页和 PostgreSQL；本批未实现批量、复测或通知。

- 独立验证修正：候选列表进一步限制为管理员/安全工程师，viewer/ops_approver 返回 403；只读用户仍可加载备注。前后端备注校验同时拒绝 Unicode 行/段落分隔符 U+2028/U+2029，补充 API/仓储/前端回归。指派清除约定为空串，null/缺省字段拒绝，已写入 API 说明。

### 2026-10-20：批量漏洞状态处置（本地回归）

- 新增 `POST /api/v1/findings/batch-disposition`，仅处理显式选中的 1–100 个不同 ID 和原状态快照。单项与批量共享接受风险字段及状态流转校验，固定 ID 顺序预读、CAS 更新、逐项 finding_events 和审计全部处于一个 SQLite 事务；任一缺失/状态变化/非法流转/写入失败则整批回滚。
- UI 增加表格行选择、已选计数、清空、批量状态选择及含 ID/原状态的确认框。跨分页/筛选保留明确选择和状态快照；状态漂移阻止提交，服务端继续校验；接受风险统一填写原因/期限。失败保留选择，成功合并返回记录并清空，演示不保存。没有扫描调用，不改变指派/备注/指纹或任务状态。
- 已运行 repo/API 聚焦测试，覆盖空/超限/重复/不存在 ID、未知 JSON 字段、旧状态、FIXED/误报/活动接受风险限制、审计/事件/CAS 失败回滚、并发只成功一次、角色/CSRF 和既有无账户本地语义；新增 API 本地语义 race 回归通过。`node --test web/src/pages/Findings/*.test.mjs`（5 项）、`npm --prefix web run build`、`make lint`、`make build`、Ruby YAML 解析和 `git diff --check` 通过。`go test -race ./internal/repo ./internal/api` 全包通过（repo 87.396 秒、api 31.399 秒）。
- 批量方法不在事务外触发到期改写；自动到期仍由既有 Tick/列表/单项补查完成，保证失败批次完全无副作用。真实浏览器交互、批量指派、单项复测、到期通知和 PostgreSQL 运行时仍待完成。

## 2026-10-21 — 单项漏洞复测（代码与单元测试）

- `POST /api/v1/findings/{id}/retest` 只复用已完成父任务的冻结输入；独立 Nuclei/ZAP 任务缩小到当前发现项目标，自动综合扫描使用父任务已解析的精确端口集合。
- Server 在事务中重新校验登记资产、审批/排除/隔离端口、规则包和时间窗，写入发现项—复测任务关系及不含目标数据的审计记录；活动复测重复提交返回冲突。
- 合成发现项、误报、父任务未完成、范围外目标和不支持引擎均有失败路径测试；API 覆盖认证、CSRF、角色和严格 JSON。
- 已运行：`go test -race ./internal/repo ./internal/api`、`make test`、`make lint`、`make build`、`node --test web/src/pages/Findings/*.test.mjs`、`npm --prefix web run build`、Ruby YAML 解析和 `git diff --check`。真实浏览器点击和真实 Worker 执行仍待隔离环境验收。
## 2026-10-21：总览风险评分、趋势与下钻

- 总览新增 0–100 风险评分、有风险资产数、7/30/90 天活动漏洞趋势、风险业务组和风险资产表；严重度与检测口径数字链接到漏洞筛选。风险评分规则、活动状态和接受风险折扣见 `docs/product/risk-score.md`。
- 漏洞页新增业务组和资产 ID 的 URL 筛选，保留刷新、前进/后退和筛选标签移除语义；仍只在页面已加载的全量发现项上计算，未新增扫描目标、端口或引擎调用。
- `node --test web/src/pages/Findings/*.test.mjs`、`node web/src/pages/Dashboard/presentation.test.mjs`、`npm --prefix web run build`、`make test`、`make lint`、`make build`、Ruby YAML 解析和 `git diff --check` 均已通过。真实浏览器点击下钻和服务端大数据量聚合仍待独立验收。

## 2026-10-21：报告 CSV/JSON 输出

- 报告格式扩展为 CSV 与 JSON，并继续复用同一冻结快照、队列、重试和历史记录；CSV 是漏洞详情平面文件，JSON 包含完整资产、任务、发现项、汇总和范围快照。
- CSV 对以 `=`, `+`, `-`, `@` 开头的单元格增加前缀，避免导入电子表格时被当作公式；JSON 和 CSV 均通过现有 64 MiB 生成上限和离线渲染路径，不调用扫描器或外部网络。
- 已补充渲染、仓储格式复用、API 下载 Content-Type 和格式校验测试；`go test -race ./internal/reporting ./internal/repo ./internal/api`、`make test`、`make lint`、`make build`、前端生产构建、Ruby YAML 解析和 `git diff --check` 均已通过。真实浏览器下载、Office 原生打开和大数据量性能仍待环境验收。

## 2026-10-21：管理员审计日志只读查询

- 新增 `GET /api/v1/audit-logs` 和 `/audit` 页面，仅管理员可查询；支持操作者、动作、对象类型、RFC3339 时间范围和 1–200 条分页筛选，列表按时间和 ID 倒序返回。
- API 只返回稳定审计投影（记录 ID、操作者、动作、对象类型/ID、时间），刻意省略历史 `detail`，因此不会通过查询页面暴露目标地址、凭据或备注正文；没有编辑、删除或敏感导出入口。
- 新增仓储过滤/排序/分页及 API 认证、角色、非法参数和 detail 不返回测试；前端 helper 覆盖筛选裁剪和分页偏移。`go test -race ./internal/repo ./internal/api`、`make test`、`make lint`、`make build`、前端生产构建、Ruby YAML 解析和 `git diff --check` 均已通过；真实浏览器权限交互、大数据量查询和 PostgreSQL 运行时仍待环境验收。

## 2026-10-21：定时计划历史运行

- 定时计划触发现在写入独立 `schedule_runs` 表；成功触发关联生成的任务，任务状态查询时实时映射，非法触发写入失败记录并停用该单次计划。删除计划不删除历史，任务被删除后历史状态显示为 `DELETED`。
- 新增 `GET /api/v1/schedules/{id}/runs`，限制 1–200 条分页，仅返回触发时间、状态、任务 ID 和安全错误摘要；任务中心增加“历史运行”只读弹窗，未返回目标、输入路径或引擎输出。
- 仓储/API 测试覆盖成功、失败、分页、状态映射和删除计划后保留历史；`go test -race -count=1 ./...`、18 项 Python 测试、`make lint`、`make build`、前端生产构建、OpenAPI/Workflow YAML 检查和 `git diff --check` 均已通过。PostgreSQL 运行时和真实浏览器交互仍待验收。

## 2026-10-21：资产清册 CSV 导出

- 新增 `GET /api/v1/assets/export` 和资产页“导出 CSV”。导出复用当前地址、名称、业务组、负责人搜索条件；未传筛选时导出完整清册。
- CSV 只包含资产登记稳定字段（标识、类型、地址、名称、核心标记、业务归属、申请/排除/隔离端口、可达性状态和登记时间），不包含服务详情、登录入口、请求/响应证据或引擎输出。以 `=`, `+`, `-`, `@` 开头的单元格会加前缀，避免表格软件执行公式。
- 新增 API race 测试覆盖未登录拒绝、筛选隔离、重复/超长筛选拒绝、CSV 表头、公式前缀和敏感明细不导出；前端使用同源下载并在演示模式禁用服务端导出按钮。导出不会触发 Ping、端口探测、扫描器或外部网络。
- 待运行门禁：`go test -race ./internal/api`、`npm --prefix web run build`、`make test`、`make lint`、`make build`、OpenAPI/Workflow YAML 检查及 `git diff --check`。真实浏览器下载、PostgreSQL 运行时和大数据量分页性能仍待验收。

## 2026-10-21：总览首次使用清单与待处置卡片

- 总览在 Server 模式且数据尚未完成首次闭环时显示“登记资产→发起扫描→查看结果”三步清单；演示模式不把预置 fixture 当作新用户。完成项从当前资产、非模拟任务和已完成任务推导，清单完成后自动隐藏。
- 新增待处置严重/高危卡片，只纳入系统/Web 且状态为 `OPEN`、`REOPENED`、`IN_PROGRESS` 的发现项；按严重度和最近发现时间排序，最多展示 5 条，数量徽标保留完整计数，链接带业务组与严重度筛选。接受风险、误报和已修复项不会进入卡片。
- `node web/src/pages/Dashboard/presentation.test.mjs` 和 `npm --prefix web run build` 已通过；纯函数覆盖待处置过滤、重新打开状态和总数。真实浏览器首次使用清单、卡片跳转和大数据量后端聚合仍待验收。

## 2026-10-21：自动综合扫描预置方案卡片

- 向导第 2 步新增“快速检测”和“标准检测”卡片。快速检测固定常见端口/温和强度；标准检测固定常见端口加可选自定义范围/标准强度。选择只修改已有产品参数，最终仍经过原端口范围、排除、时间窗和运维授权校验，不新增引擎参数或扫描目标。
- 复制旧任务和编辑定时计划保留已有冻结配置；确认摘要显示当前方案名称，用户可继续调整参数。未知方案值安全回退到快速方案默认值。
- `node web/src/pages/Tasks/wizard.test.mjs`、前端生产构建和 `git diff --check` 已通过。真实浏览器卡片可用性、5 次点击旅程和 Server 端大数据量性能仍待验收。

## 2026-10-21：总览后端聚合

- 新增认证接口 `GET /api/v1/dashboard/summary?days=7|30|90`。Server 聚合资产、任务、发现项和当前规则，仅返回计数、趋势桶、风险业务组/资产排行、最多 5 条待处置严重/高危摘要和规则状态；不返回证据、凭据、原始请求/响应或引擎输出。Server 总览按趋势窗口轮询该接口，任务清册仍单独加载。
- 聚合保持既有风险口径：系统/Web 才进入漏洞计数，接受风险按 25% 计入评分，FIXED/FALSE_POSITIVE 不计入活动风险，待处置只包括 `OPEN`、`REOPENED`、`IN_PROGRESS`。
- 新增 API race 测试覆盖认证、资产/任务聚合、空规则/空发现项、7 天趋势、非法/重复 days 参数，以及风险评分、资产去重和待处置投影；前端 Server 聚合客户端和 11 项页面纯函数测试、前端构建已通过。真实浏览器和 PostgreSQL 聚合仍待验收。

## 2026-10-21：扫描任务详情、日志与结果导出

- `/api/v1/tasks/{id}` 提供单任务最新安全投影，补充当前发现数和 Worker advisory progress；`/logs` 只从任务审计记录映射静态事件文案，完全省略原始 `detail`；`/export?format=json|csv` 只导出稳定任务/发现字段，排除证据、凭据、原始请求/响应和引擎输出。CSV 复用公式前缀转义，空发现任务仍输出完整表头宽度。
- 任务中心新增“详情”抽屉，显示概览、目标级状态、进度、结果摘要、安全只读日志和 JSON/CSV 下载；演示模式明确不读取服务端日志。既有取消、归档、复用和删除流程不变。
- API 测试覆盖未登录拒绝、详情状态/发现数、日志脱敏、JSON/CSV 下载、非法格式和公式转义；真实浏览器抽屉键盘/窄屏交互仍待验收。

## 2026-10-21：扫描任务手动暂停与恢复

- 新增 `POST /api/v1/tasks/{id}/pause` 和 `/resume`。暂停会清除 Worker 租约并进入独立 `PAUSED` 状态；Worker 下一次心跳看到非 `RUNNING` 状态后停止当前执行，时间窗 Tick 不会自动恢复。恢复只把任务送回 `PENDING`，领取时仍重新校验时间窗、资产授权、排除项和规则就绪状态。
- 任务详情和任务清册提供暂停/恢复入口，暂停前二次确认；取消仍是终止操作，归档/删除只接受终态任务。PostgreSQL 状态契约和 OpenAPI 枚举同步更新。
- 仓储测试覆盖暂停持久性、时间窗 Tick 不误恢复、恢复回队列和取消；API 测试覆盖认证后的暂停/恢复状态。真实 Worker 中途引擎停止和浏览器交互仍待隔离实验/真实浏览器验收。

## 2026-10-21：授权范围到期提醒与筛选

- `AuthorizedScope` 增加 Server 计算的 `expiryState`：批准授权按截止时间分为 `ACTIVE`、`EXPIRING`（七天内到期）和 `EXPIRED`，待审核/驳回/撤销返回 `NOT_APPLICABLE`；`isActive` 与该状态保持一致。
- `/scopes` 每 60 秒刷新一次，页面显示已过期/即将到期提示，并提供“全部期限、七天内到期、已过期”筛选。提醒只基于已保存的授权截止时间，不会发起网络探测或改变授权。
- Go 表驱动测试覆盖非批准状态、七天边界、过期和撤销；前端契约测试覆盖状态分类和筛选。独立通知中心、邮件/消息渠道和批量续期仍未实现。

## 2026-10-21：扫描方案目录与自定义方案持久化

- `GET /api/v1/scan-plans` 由 Server 返回“快速检测”和“标准检测”只读预置以及已保存的自定义方案；`POST` 可从预置复制，`PUT`/`DELETE` 只允许操作 `CUSTOM` 方案，预置方案不能被覆盖或删除。
- 自定义方案只保存产品级字段：端口策略、端口范围、排除范围、强度和已启用规则选择；Server 校验文本长度、端口范围、强度、重复规则和规则存在性，不接受引擎命令行参数或路径。任务创建仍重新校验并冻结最终范围。
- `scan_plans` 使用 SQLite 持久化并记录创建/修改/删除审计；已创建任务不依赖方案记录，删除方案不会改变历史任务输入。
- Go 目录/API/仓储测试覆盖预置只读、创建、修改、删除、预置冲突、无效范围和缺失规则；前端 14 项契约测试及生产构建通过。真实浏览器五次点击验收仍待执行。

## 2026-10-21：管理员密码重置

- 管理员可通过 `POST /api/v1/users/{id}/password-reset` 重置其他账号密码；服务端只保存 bcrypt 哈希，事务内撤销目标账号的全部旧会话并写入不含密码的审计动作。
- 密码仍限制为 12–72 字节；非管理员、缺少同源变更头、未知用户和无效长度分别拒绝，接口响应只返回用户投影。
- 账号仓储/API 测试覆盖新密码登录、旧会话失效、权限和 CSRF 失败；用户管理页增加“重置密码”表单。真实浏览器交互仍待执行。

## 2026-10-21：资产业务组与导入记录

- 新增 `GET/POST /api/v1/business-groups` 和 `GET /api/v1/assets/import-history`。业务组以 SQLite 资源持久化并统计当前资产数；新增资产、更新资产和 CSV 确认导入会自动登记缺失业务组，旧库初始化会从已有资产回填，不创建演示资产。
- CSV 确认与导入历史写入同一事务。历史仅保留 ID、操作者、成功数量、总行数和时间，最多查询最近 200 条；不保存或返回 CSV 行、地址、名称、端口或扫描结果。普通登录用户可读业务组/历史，业务组创建仍限 admin/security_engineer 并要求 CSRF。
- 新增仓储/API race 测试覆盖业务组名称控制字符/重复、资产计数、导入摘要隐私和 viewer 只读权限；前端新增业务组和导入记录页面及导航路由，生产构建通过。未改变扫描目标、端口授权、Worker 或引擎调用。

## 2026-10-21：批量漏洞指派与指派历史（本地回归）

- 新增 `POST /api/v1/findings/batch-assignment` 和 `GET /api/v1/findings/{id}/assignments`。批量接口只接受显式选中的 1–100 个不同发现项、目标指派人和每项当前指派快照；固定 ID 顺序执行，任一记录缺失、快照过期、目标账号停用/角色不符、CAS/事件/审计写入失败都会整批回滚。
- 指派历史使用独立 SQLite 表和稳定字段（发现项 ID、前后指派人 ID、操作者、时间），不复制账号元数据；单项和批量指派共用事务审计，扫描结果合并继续保留人工指派。
- 漏洞详情抽屉显示指派时间线，列表工具栏支持批量指派并在选择快照变化时阻止提交；失败保留选择，成功合并返回对象并清空选择。没有新增扫描目标、端口或引擎调用。
- 新增仓储原子性/历史测试、API 认证角色 CSRF/严格 JSON 测试、前端批量选择契约测试；OpenAPI、产品现状、路线图和 API 说明同步更新。`make test`、全部 28 项 `node --test web/src/**/*.test.mjs`、`npm --prefix web run build`、`make lint`、`make build`、OpenAPI YAML 解析和 `git diff --check` 均通过。
- 待验收：真实浏览器批量操作和 PostgreSQL 运行时；当前历史接口返回单个发现项全量历史，尚未加入分页。

## 2026-10-21：资产清册扫描与风险摘要（前端回归）

- 资产清册新增“最近扫描”和“当前风险数”列：扫描历史按已登记资产分组，优先展示最近任务的完成时间/创建时间；风险数只统计当前活动发现项，`FIXED` 与 `FALSE_POSITIVE` 不计入，漏洞 API 失败时显示“未知”而不是伪造为 0。
- 资产画像新增漏洞摘要和扫描历史表，继续保留服务/技术栈、登录入口、端口排除与隔离信息。漏洞摘要读取 Server 当前发现项，扫描历史读取任务清册；未改变扫描目标、端口授权、Worker 或引擎参数。
- 新增资产页面契约回归，生产构建和全部 29 项前端契约测试通过；`make test`、`make lint`、`make build` 及 OpenAPI 校验也通过。真实浏览器详情抽屉和大数据量分页/排序仍待验收。
