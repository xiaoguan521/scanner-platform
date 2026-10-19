# 本机业务 API

契约为 [openapi.yaml](openapi.yaml)，Go DTO 直接别名到实际返回模型，前端类型位于 `web/src/types/index.ts`。统一 Server 提供网页、账号、资产、任务、定时和规则操作；不再使用两套业务入口。

UI 使用 HttpOnly 的 `scanner_session` Cookie，所有写请求携带 `X-Requested-With: XMLHttpRequest`。管理员管理用户；管理员/安全工程师维护资产、任务、定时、发现项和规则包；审批由管理员/运维审批人处理，禁止自审；已登录只读用户可查询业务列表。

- `/auth/setup`：首次管理员初始化状态/创建，已有用户后拒绝再次初始化。
- `/auth/login`、`/auth/me`、`/auth/logout`、`/users`：账号与会话。
- `/assets`：数字 IP 或镜像仓库登记；`requestedPorts` 为端口申请，`skippedPorts` 为需要排除的端口。新增主机后只对登记 IP 发送一次有界 ICMP echo；可通过 `POST /assets/{id}/reachability-check` 重测，结果只作可达性提示。`PATCH` 可修改资产，改 IP 会撤销已有范围授权并清除旧 Ping 结果；`DELETE` 在存在关联范围记录时返回冲突。`POST /assets/{id}/port-requests` 可把探测候选追加为待审批申请；不会直接授权扫描。`/port-quarantines` 读取实际隔离记录。
- `/scopes`、`/port-requests`：范围与端口审批台账。范围申请可通过 `PUT /scopes/{id}` 修改（重置为待审批）、通过 `POST /scopes/{id}/revoke` 撤销、通过 `DELETE /scopes/{id}` 删除；已批准范围须先撤销。真实 Nuclei/ZAP 任务只能使用已登记且已审批的端口；模拟任务不连接目标。
- `/tasks`：接受模拟任务 `synthetic: true`；`nuclei/zap` 使用 `scheme: http/https` 和已审批的 `targets: [IP:port]`；Trivy 使用 `inputKind: filesystem/artifact/image-archive/rootfs`、相对 Worker 输入目录的 `inputPath`、空 `targets`。端口探测使用 `engine: port-probe`、单个 `assetId` 和 `portProbe` 范围/排除设置，配置须确认运维授权。服务端接受每任务最多 65535 个 TCP 端口，Worker 最多并发连接 64 个端口；只回报开放候选，不做服务识别或漏洞扫描。完整边界见 [单台主机 TCP 端口探测](../port-probe.md)。任务返回实际下发目标、探测清单、结果、`skippedTargets`、`hardDeadline`、`ruleVersion` 与进度；未登记目标、未审批扫描端口、全部跳过、重复目标、CIDR/域名均拒绝；领取前复查目标和授权。

- `/assets/{id}/port-requests/batch`：对已探测到的开放候选一次提交 1–1024 个独立端口申请。操作使用事务，任意端口已申请、跳过或隔离时整批拒绝；该接口不批准申请，也不直接授予扫描权限。
- `/tasks/{id}/cancel`：取消待处理或执行中任务。`/findings/{id}` 可更新 `OPEN/IN_PROGRESS/FALSE_POSITIVE`；不提供手工 FIXED。
- 报告由网页读取 `/assets`、`/tasks`、`/findings` 当前列表并生成 HTML/CSV/JSON 下载；不调用扫描器，当前没有报告历史 API。
- `/schedules`：首次运行时间、分钟间隔（0=单次）、显式目标、时间窗；`PUT /schedules/{id}` 修改，`PATCH` 启停，`DELETE` 删除后续调度，返回最近任务及错误。
- `/nodes`：真实本机心跳，10 秒未上报显示离线，并回报固定版本、安装与就绪状态 `engines`。`/nodes/heartbeat`、`/worker/*`、`/updater/*` 仅为绑定回环地址的本机进程协议，不是生产部署接口。
- `/rules`、`/rule-jobs`：Updater 回报的版本与操作状态。`/rules/import` 上传 ZIP；`/rules/fetch` 提交 HTTPS ZIP URL 和包哈希；`/rules/{version}/activate` 激活或通过 `rollback: true` 显式回滚。

`/worker/report` 支持真实任务 COMPLETED/FAILED、最多 2000 条归一化发现项，4 MiB 请求上限；拒绝其他 Worker、其他引擎或范围外目标的结果。重复提交不重复入库，稳定指纹跨任务去重，镜像使用不可变 ImageID。原始响应不在 UI API 中传递。

完整字段与请求响应见 OpenAPI。`readyz=200` 只表示本地控制面可用，不代表扫描引擎、网络围栏、规则签名或兼容性已验证。
