# 本机业务 API

契约为 [openapi.yaml](openapi.yaml)，Go DTO 直接别名到实际返回模型，前端类型位于 `web/src/types/index.ts`。统一 Server 提供网页、账号、资产、任务、定时和规则操作；不再使用两套业务入口。

UI 使用 HttpOnly 的 `scanner_session` Cookie，所有写请求携带 `X-Requested-With: XMLHttpRequest`。管理员管理用户；管理员/安全工程师维护资产、任务、定时、发现项和规则包；审批由管理员/运维审批人处理，禁止自审；已登录只读用户可查询业务列表。

- `/auth/setup`：首次管理员初始化状态/创建，已有用户后拒绝再次初始化。
- `/auth/login`、`/auth/me`、`/auth/logout`、`/users`：账号与会话。
- `/assets`：数字 IP 或镜像仓库登记；`requestedPorts` 为显式目标端口，`skippedPorts` 为其中需要排除的端口。`/port-quarantines` 读取实际隔离记录。
- `/scopes`、`/port-requests`：范围与端口审批台账。早期模式不把审批作为模拟任务门禁；不会自动发起扫描。
- `/tasks`：接受模拟任务 `synthetic: true`；或真实任务 `synthetic: false` 加 `engine: nuclei/zap`、`scheme: http/https`、`targets: [IP:port]`；Trivy 使用 `engine: trivy`、`inputKind: filesystem/image-archive`、相对 Worker 输入目录的 `inputPath`、空 `targets`。均支持可选 `timeWindows`；返回实际下发目标、`skippedTargets`、`hardDeadline`、`ruleVersion` 与进度。未登记目标、全部跳过、重复目标、CIDR/域名均拒绝；领取前复查目标。
- `/tasks/{id}/cancel`：取消待处理或执行中任务。`/findings/{id}` 可更新 `OPEN/IN_PROGRESS/FALSE_POSITIVE`；不提供手工 FIXED。
- `/schedules`：首次运行时间、分钟间隔（0=单次）、显式目标、时间窗；PATCH 可启停，返回最近任务及错误。
- `/nodes`：真实本机心跳，10 秒未上报显示离线，并回报固定版本、安装与就绪状态 `engines`。`/nodes/heartbeat`、`/worker/*`、`/updater/*` 仅为绑定回环地址的本机进程协议，不是生产部署接口。
- `/rules`、`/rule-jobs`：Updater 回报的版本与操作状态。`/rules/import` 上传 ZIP；`/rules/fetch` 提交 HTTPS ZIP URL 和包哈希；`/rules/{version}/activate` 激活或通过 `rollback: true` 显式回滚。

`/worker/report` 支持真实任务 COMPLETED/FAILED、最多 2000 条归一化发现项，4 MiB 请求上限；拒绝其他 Worker、其他引擎或范围外目标的结果。重复提交不重复入库，稳定指纹跨任务去重，镜像使用不可变 ImageID。原始响应不在 UI API 中传递。

完整字段与请求响应见 OpenAPI。`readyz=200` 只表示本地控制面可用，不代表扫描引擎、网络围栏、规则签名或兼容性已验证。
