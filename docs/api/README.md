# 本机业务 API

契约为 [openapi.yaml](openapi.yaml)，Go DTO 直接别名到实际返回模型，前端类型位于 `web/src/types/index.ts`。统一 Server 提供网页、账号、资产、任务、定时和规则操作；不再使用两套业务入口。

UI 使用 HttpOnly 的 `scanner_session` Cookie，所有写请求携带 `X-Requested-With: XMLHttpRequest`。管理员管理用户；管理员/安全工程师维护资产、任务、定时、发现项和规则包；审批由管理员/运维审批人处理，禁止自审；已登录只读用户可查询业务列表。

- `/auth/setup`：首次管理员初始化状态/创建，已有用户后拒绝再次初始化。
- `/auth/login`、`/auth/me`、`/auth/logout`、`/users`：账号与会话；管理员可通过 `/users/{id}/password-reset` 重置密码，重置会撤销目标账号全部旧会话，不返回密码哈希、密码或令牌。
- `/system-settings`：管理员读取和修改系统时区、后续新登录会话时长；保存写入审计，外部通知投递尚未启用。
- `/notifications`：登录用户读取 Server 生成的授权、接受风险和扫描失败通知，并可通过带 CSRF 请求头的接口标记已读；只保留安全摘要，不发送外部消息。
- `/audit-logs`：仅管理员可读的审计记录投影，支持按操作者、动作、对象类型和 RFC3339 时间范围筛选，并分页返回时间、动作和对象标识；不会返回历史 `detail`、目标地址或凭据等敏感内容，也不提供编辑、删除或导出入口。
- `/dashboard/summary`：登录用户可读取总览聚合，包括资产/任务/漏洞计数、7/30/90 天趋势、风险业务组与资产排行、最多 5 条待处置严重/高危摘要和当前规则版本；不返回证据、凭据、原始请求/响应或引擎输出。前端 Server 模式按趋势窗口轮询该接口，任务清册仍单独读取。
- `/assets`：数字 IP 或镜像仓库登记；`requestedPorts` 为端口申请，`skippedPorts` 为需要排除的端口。列表可用 `page`、`page_size`、`q`（地址/名称/业务组/负责人）和白名单 `sort` 进行 Server 端分页、搜索与排序，返回 `page/pageSize/total`；不带查询参数时保留完整清册响应。`GET /assets/export` 下载当前清册的 UTF-8 CSV，可用 `q` 复用地址、名称、业务组、负责人筛选；只导出稳定台账字段，不包含服务详情、登录入口、请求/响应证据或引擎输出，并对表格公式前缀做转义。`GET /business-groups` 和 `POST /business-groups` 提供可复用的业务组目录及当前资产数；`GET /assets/import-history` 仅返回最近 200 次 CSV 导入的操作者、数量和时间摘要，不返回 CSV 原文、地址或名称。`POST /assets/reachability-test` 测试表单中当前填写的单个数字 IP,不要求先登记资产且不保存测试结果。Server 启动后立即探测已登记主机,每轮完成后间隔 60 秒继续,清册状态自动刷新;无响应只作可达性提示。`POST /assets/{id}/reachability-check` 由新增/改 IP 后的页面流程用于立即更新该资产状态。`PATCH` 可修改资产，改 IP 会撤销已有范围授权并清除旧 Ping 结果；`DELETE` 在存在关联范围记录时返回冲突。`POST /assets/{id}/port-requests` 可把探测候选追加为待审批申请；不会直接授权扫描。`/port-quarantines` 读取实际隔离记录。
- `/scopes`、`/port-requests`：范围与端口审批台账。范围申请可通过 `PUT /scopes/{id}` 修改（重置为待审批）、通过 `POST /scopes/{id}/revoke` 撤销、通过 `DELETE /scopes/{id}` 删除；已批准范围须先撤销。范围返回 `expiryState`（`ACTIVE`、`EXPIRING`、`EXPIRED` 或 `NOT_APPLICABLE`），其中 `EXPIRING` 表示七天内到期；页面按此状态提醒并支持期限筛选。自动任务在明确目标和端口策略授权范围内执行只读检查,无需逐端口再审批;模拟任务不连接目标。
- `/scan-plans`：读取产品语言的快速/标准只读预置方案和已保存的自定义方案；`POST` 可从预置复制，`PUT`/`DELETE` 只允许操作自定义方案。返回的默认端口范围、强度、排除和规则选择仅用于向导回填，最终任务仍由 Server 重新校验和冻结；方案不暴露引擎命令行参数。
- `/tasks`:模拟任务不连接目标;自动任务使用 `engine: auto`、单个 `assetId` 和 `portProbe`,支持常见、自定义、已登记、全端口(确认)、强度与排除。独立 `port-probe` 只做 TCP 连接;自动流程继续有界服务识别和只读检查。数字 IP 固定在 Server,Worker 不扩展主机;领取前复核排除与隔离。Task 返回 `effectiveExclusions`、`quarantinedPorts`、`assetProfile`、`serviceResults` 和实际进度。`GET /tasks` 不带查询参数时保留完整清册；带 `page`、`page_size`、`q`、`status`、`engine`、`archived` 或 `sort` 时由 Server 执行有界分页，返回 `page/pageSize/total/statusCounts`，搜索只覆盖任务 ID、明确目标和 Worker 输入路径。`GET /tasks/{id}` 提供最新任务详情，`POST /tasks/{id}/pause|resume` 管理明确的手动暂停状态，`GET /tasks/{id}/logs` 只返回静态事件描述，`GET /tasks/{id}/export?format=json|csv` 下载稳定任务/发现字段，不包含证据、凭据、原始请求响应或引擎输出。终态任务可以归档/恢复；管理员可彻底删除没有关联发现项的终态任务。见 [端口策略](../port-probe.md)。

- `/findings`:不带查询参数时保留完整发现项清册响应；带 `page`、`page_size`、`q`、`severity`、`status`、`method`、`confidence`、`risk`、`onlyVerified`、`businessGroup`、`assetId` 或 `sort` 时由 Server 执行有界分页、筛选和稳定排序，返回 `page/pageSize/total/counts`。搜索只覆盖目标、软件包、模板/CVE 和标题；`counts` 与当前筛选条件一致，页面不会在浏览器加载全量结果。结果仍只返回归一化发现字段，不包含原始请求、响应、凭据或引擎输出。

- `/assets/{id}/port-requests/batch`：对已探测到的开放候选一次提交 1–1024 个独立端口申请。操作使用事务，任意端口已申请、跳过或隔离时整批拒绝；该接口不批准申请，也不直接授予扫描权限。
- `/tasks/{id}/cancel`：取消待处理或执行中任务。`/findings/{id}` 可更新 `OPEN/IN_PROGRESS/FALSE_POSITIVE/ACCEPTED_RISK`；不提供手工 FIXED 或从 FIXED 手工修改，拒绝重复状态。接受风险仅允许 OPEN/REOPENED/IN_PROGRESS，需 `reason`（trim 后 1–500 UTF-8 字节，无控制字符）和 `acceptedUntil`（RFC3339，未来 365 天内）；活动接受风险只能撤销到 OPEN。到期或历史无期限自动恢复 OPEN。`GET /findings/{id}/events` 返回状态时间线，原因纯文本展示，审计仅记录事件 ID/状态。
- `/tasks/{id}/archive` 与 `/restore`：归档或恢复终态任务，并分别写入审计日志。`DELETE /tasks/{id}` 仅允许管理员删除终态且没有关联发现项的任务；操作写入审计日志，已生成的冻结报告快照保留。
- `/report-templates`、`/reports`:持久化模板、冻结快照、异步生成 HTML/XLSX/DOCX/PDF/CSV/JSON、查询历史、下载和失败重试;CSV 是漏洞明细平面文件，JSON 是完整冻结快照;已就绪报告可通过 `POST /reports/{id}/formats` 复用同一冻结快照导出其他格式;生成不调用扫描器。`GET /reports` 不带查询参数时保留完整历史兼容响应；带 `page`、`page_size`、`q`、`status`、`format` 或 `sort` 时由 Server 返回有界分页、搜索、筛选和稳定排序。见 [报告使用说明](../product/report-usage.md)。
- `/detection-capabilities`、`/vulnerability-categories`、`/scan-policy`、`/knowledge`:检测能力状态、32 类字典、管理员端口策略、规范 JSON 知识库维护与导入;不自动抓取外部数据。
- `POST /port-quarantines/release`:管理员填写复核原因后解除隔离并审计。
- `/schedules`：首次运行时间、分钟间隔（0=单次）、显式目标、时间窗；`PUT /schedules/{id}` 修改，`PATCH` 启停，`DELETE` 删除后续调度，返回最近任务及错误。
- `GET /schedules/{id}/runs`：按时间倒序分页查看每次定时触发的任务状态；保留已删除计划的历史，只返回触发时间、状态、任务 ID 和安全错误摘要，不返回目标、输入或引擎输出。
- `/nodes`：真实本机心跳，10 秒未上报显示离线，并回报固定版本、安装与就绪状态 `engines`。`/nodes/heartbeat`、`/worker/*`、`/updater/*` 仅为绑定回环地址的本机进程协议，不是生产部署接口。
- `/rules`、`/rule-jobs`：Updater 回报的版本与操作状态。`/rules/import` 上传不超过 256 MiB 的 ZIP；`/rules/fetch` 提交 HTTPS ZIP URL 和包哈希，大签名包由 Updater 流式下载（最多 2 GiB）；`/rules/{version}/activate` 激活或通过 `rollback: true` 显式回滚。人工下载的大签名 ZIP 使用 Updater 的 `--import-bundle-file`，不经过 Server SQLite BLOB。

`/worker/claim` 为每个非模拟任务返回固定的 `pinnedRuleVersion` 和短期 `leaseExpiresAt`；真实 Worker 会在请求中携带本地 `localRuleVersion`/`rulesReady`。Server 只把规则版本匹配的规则任务交给该 Worker，缺少 CURRENT 时将规则任务留在队列；端口探测和被动 ZAP 不依赖规则，可继续领取。`/worker/renew` 只接受同一任务、Worker 和版本绑定，并把续租限制在任务 hard deadline 以内。租约到期后续租和结果回报均被拒绝，Server 的 `Tick` 会把任务回收到 `PENDING` 或 `PAUSED_WINDOW`，避免失联 Worker 永久占用任务。当前本地 API 仍只绑定回环地址，TLS 和节点令牌属于后续部署工作。

`/nodes/heartbeat` 保存 Worker 报告的本地规则版本到节点的 `boundRuleVersion`，并显示 `WAITING_FOR_RULES` 或 `RULES_ERROR`。缺少 CURRENT 会按 Worker 轮询间隔等待，不会伪装成扫描失败；CURRENT 格式或本地规则根无效时 Worker 明确停止领取任务。`/worker/report` 支持真实任务 COMPLETED/FAILED、最多 2000 条归一化发现项，32 MiB 请求上限；拒绝其他 Worker、其他引擎或范围外目标的结果。重复提交不重复入库，稳定指纹跨任务去重，镜像使用不可变 ImageID。原始响应不在 UI API 中传递。租约失效时 Worker 不发送过期的 FAILED/COMPLETED 回报，等待 Server 回收并重新分配。

完整字段与请求响应见 OpenAPI。`readyz=200` 只表示本地控制面可用，不代表扫描引擎、网络围栏、规则签名或兼容性已验证。

- 漏洞指派与备注：`GET /findings/assignees` 仅向已登录的 admin/security_engineer 提供 active admin/security_engineer 的最小 `{id,name}` 候选。`PUT /findings/{id}/assignee` 使用 `{assigneeId}` 指派，空串清除（null 和缺省字段拒绝）；同一事务校验执行者及目标当前状态，保留指派历史和审计，不改变资产 owner/漏洞状态。`GET /findings/{id}/assignments` 向已登录用户返回只含 ID、操作者和时间的历史投影；`POST /findings/batch-assignment` 使用 `{items:[{id,expectedAssigneeId}],assigneeId}` 原子处理显式选中的 1–100 个不同 ID，任一指派快照过期、缺失、无效或写入失败则整批回滚，拒绝未知字段。`GET/POST /findings/{id}/notes` 读取/追加备注；POST 使用 `{body}`，校验 trim 前 1–2000 UTF-8 字节、非空白且无控制字符及 Unicode 行/段落分隔符（U+2028/U+2029）。备注只追加，作者名快照保留，审计仅记录 noteId/字节数。写入沿用 admin/security_engineer 和 CSRF 约束，无账户认证配置时这些新端点拒绝服务。

- 批量漏洞处置：`POST /findings/batch-disposition` 使用 `{items:[{id,expectedStatus}],status,reason?,acceptedUntil?}`，仅处理显式选中的 1–100 个不同 ID，拒绝未知字段。固定 ID 顺序预读，任一不存在、状态快照过期、非法流转、CAS/事件/审计失败则整批回滚；返回 `{updated,items}`。状态和接受风险校验与单项共享，不开放手工 FIXED，保留指派/备注/指纹，不触发扫描。写权限和 CSRF 沿用原单项处置，无账户配置沿用本地处置语义。自动到期由原 Tick/列表/单项处理，不在失败批次之外额外改写到期记录。
- 漏洞复测：`POST /findings/{id}/retest` 只允许 admin/security_engineer，服务端复用已完成父任务的冻结输入；独立 HTTP 扫描缩小到该发现项的单个目标，自动综合扫描使用父任务已解析的精确端口集合，并重新校验资产登记、端口授权、排除项和规则就绪条件。合成发现项、误报、父任务未完成、超出原范围或不支持的引擎会失败；同一发现项同时只允许一个活动复测。复测任务与发现项关联写入审计但不复制目标、请求或响应；`GET /findings/{id}/retests` 查询历史。
