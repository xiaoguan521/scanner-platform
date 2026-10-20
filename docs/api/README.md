# 本机业务 API

契约为 [openapi.yaml](openapi.yaml)，Go DTO 直接别名到实际返回模型，前端类型位于 `web/src/types/index.ts`。统一 Server 提供网页、账号、资产、任务、定时和规则操作；不再使用两套业务入口。

UI 使用 HttpOnly 的 `scanner_session` Cookie，所有写请求携带 `X-Requested-With: XMLHttpRequest`。管理员管理用户；管理员/安全工程师维护资产、任务、定时、发现项和规则包；审批由管理员/运维审批人处理，禁止自审；已登录只读用户可查询业务列表。

- `/auth/setup`：首次管理员初始化状态/创建，已有用户后拒绝再次初始化。
- `/auth/login`、`/auth/me`、`/auth/logout`、`/users`：账号与会话。
- `/assets`：数字 IP 或镜像仓库登记；`requestedPorts` 为端口申请，`skippedPorts` 为需要排除的端口。`POST /assets/reachability-test` 测试表单中当前填写的单个数字 IP,不要求先登记资产且不保存测试结果。Server 启动后立即探测已登记主机,每轮完成后间隔 60 秒继续,清册状态自动刷新;无响应只作可达性提示。`POST /assets/{id}/reachability-check` 由新增/改 IP 后的页面流程用于立即更新该资产状态。`PATCH` 可修改资产，改 IP 会撤销已有范围授权并清除旧 Ping 结果；`DELETE` 在存在关联范围记录时返回冲突。`POST /assets/{id}/port-requests` 可把探测候选追加为待审批申请；不会直接授权扫描。`/port-quarantines` 读取实际隔离记录。
- `/scopes`、`/port-requests`：范围与端口审批台账。范围申请可通过 `PUT /scopes/{id}` 修改（重置为待审批）、通过 `POST /scopes/{id}/revoke` 撤销、通过 `DELETE /scopes/{id}` 删除；已批准范围须先撤销。自动任务在明确目标和端口策略授权范围内执行只读检查,无需逐端口再审批;模拟任务不连接目标。
- `/tasks`:模拟任务不连接目标;自动任务使用 `engine: auto`、单个 `assetId` 和 `portProbe`,支持常见、自定义、已登记、全端口(确认)、强度与排除。独立 `port-probe` 只做 TCP 连接;自动流程继续有界服务识别和只读检查。数字 IP 固定在 Server,Worker 不扩展主机;领取前复核排除与隔离。Task 返回 `effectiveExclusions`、`quarantinedPorts`、`assetProfile`、`serviceResults` 和实际进度。`GET /tasks?archived=false|true|all` 可筛选归档状态；默认返回全部。终态任务可以归档/恢复；管理员可彻底删除没有关联发现项的终态任务。见 [端口策略](../port-probe.md)。

- `/assets/{id}/port-requests/batch`：对已探测到的开放候选一次提交 1–1024 个独立端口申请。操作使用事务，任意端口已申请、跳过或隔离时整批拒绝；该接口不批准申请，也不直接授予扫描权限。
- `/tasks/{id}/cancel`：取消待处理或执行中任务。`/findings/{id}` 可更新 `OPEN/IN_PROGRESS/FALSE_POSITIVE/ACCEPTED_RISK`；不提供手工 FIXED 或从 FIXED 手工修改，拒绝重复状态。接受风险仅允许 OPEN/REOPENED/IN_PROGRESS，需 `reason`（trim 后 1–500 UTF-8 字节，无控制字符）和 `acceptedUntil`（RFC3339，未来 365 天内）；活动接受风险只能撤销到 OPEN。到期或历史无期限自动恢复 OPEN。`GET /findings/{id}/events` 返回状态时间线，原因纯文本展示，审计仅记录事件 ID/状态。
- `/tasks/{id}/archive` 与 `/restore`：归档或恢复终态任务，并分别写入审计日志。`DELETE /tasks/{id}` 仅允许管理员删除终态且没有关联发现项的任务；操作写入审计日志，已生成的冻结报告快照保留。
- `/report-templates`、`/reports`:持久化模板、冻结快照、异步生成 HTML/XLSX/DOCX、查询历史、下载和失败重试;已就绪报告可通过 `POST /reports/{id}/formats` 复用同一冻结快照导出其他格式;生成不调用扫描器。见 [报告使用说明](../product/report-usage.md)。
- `/detection-capabilities`、`/vulnerability-categories`、`/scan-policy`、`/knowledge`:检测能力状态、32 类字典、管理员端口策略、规范 JSON 知识库维护与导入;不自动抓取外部数据。
- `POST /port-quarantines/release`:管理员填写复核原因后解除隔离并审计。
- `/schedules`：首次运行时间、分钟间隔（0=单次）、显式目标、时间窗；`PUT /schedules/{id}` 修改，`PATCH` 启停，`DELETE` 删除后续调度，返回最近任务及错误。
- `/nodes`：真实本机心跳，10 秒未上报显示离线，并回报固定版本、安装与就绪状态 `engines`。`/nodes/heartbeat`、`/worker/*`、`/updater/*` 仅为绑定回环地址的本机进程协议，不是生产部署接口。
- `/rules`、`/rule-jobs`：Updater 回报的版本与操作状态。`/rules/import` 上传不超过 256 MiB 的 ZIP；`/rules/fetch` 提交 HTTPS ZIP URL 和包哈希，大签名包由 Updater 流式下载（最多 2 GiB）；`/rules/{version}/activate` 激活或通过 `rollback: true` 显式回滚。人工下载的大签名 ZIP 使用 Updater 的 `--import-bundle-file`，不经过 Server SQLite BLOB。

`/worker/claim` 为每个非模拟任务返回固定的 `pinnedRuleVersion` 和短期 `leaseExpiresAt`；真实 Worker 会在请求中携带本地 `localRuleVersion`/`rulesReady`。Server 只把规则版本匹配的规则任务交给该 Worker，缺少 CURRENT 时将规则任务留在队列；端口探测和被动 ZAP 不依赖规则，可继续领取。`/worker/renew` 只接受同一任务、Worker 和版本绑定，并把续租限制在任务 hard deadline 以内。租约到期后续租和结果回报均被拒绝，Server 的 `Tick` 会把任务回收到 `PENDING` 或 `PAUSED_WINDOW`，避免失联 Worker 永久占用任务。当前本地 API 仍只绑定回环地址，TLS 和节点令牌属于后续部署工作。

`/nodes/heartbeat` 保存 Worker 报告的本地规则版本到节点的 `boundRuleVersion`，并显示 `WAITING_FOR_RULES` 或 `RULES_ERROR`。缺少 CURRENT 会按 Worker 轮询间隔等待，不会伪装成扫描失败；CURRENT 格式或本地规则根无效时 Worker 明确停止领取任务。`/worker/report` 支持真实任务 COMPLETED/FAILED、最多 2000 条归一化发现项，32 MiB 请求上限；拒绝其他 Worker、其他引擎或范围外目标的结果。重复提交不重复入库，稳定指纹跨任务去重，镜像使用不可变 ImageID。原始响应不在 UI API 中传递。租约失效时 Worker 不发送过期的 FAILED/COMPLETED 回报，等待 Server 回收并重新分配。

完整字段与请求响应见 OpenAPI。`readyz=200` 只表示本地控制面可用，不代表扫描引擎、网络围栏、规则签名或兼容性已验证。
