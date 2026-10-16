# UI API 契约（Phase 0）

架构规范以 `docs/architecture-v3.2.md` 为准；HTTP 请求/响应模型以本目录的 `openapi.yaml` 为唯一契约。两份文档的职责不同：OpenAPI 不能降低架构安全要求。

## 当前可用

- `GET /healthz`：仅表示进程存活，不表示扫描平台安全或就绪。
- `GET /readyz`：当前固定返回 503。
- `GET /api/v1/system/status` 与 `GET /api/v1/system/capabilities`：只读状态。
- 用户、资产、端口隔离、范围、任务、漏洞、节点、规则包共 8 个集合路由：仅 GET 占位，当前返回 501；未开放创建、审批、停止、回滚、删除或修改漏洞状态的接口。

用户管理计划采用 V3.2 的 `admin`、`security_engineer`、`ops_approver` 和 `viewer` 四类角色。`GET /api/v1/users` 暂时返回 501；账号、角色和凭证必须在 Server 完成认证、RBAC、审计与管理员授权后才能查询或修改。前端只包含不具备真实权限的用户列表演示页。

## 数据形状

统一 `application/json`，字段使用 camelCase；时间戳采用 RFC 3339，带明确时区偏移；版本号采用 `YYYYMMDD.nn`（例如 `20261016.01`），字段 `workerNodeId` 和 Server 任务分块模型对应。集合统一返回 `{ "items": [...], "total": 0 }`，错误返回 `{ "error": "...", "message": "..." }`。

Go 的 `internal/api/dto.go` 与 `web/src/types/index.ts` 当前人工对照 OpenAPI 定义，**尚未实现自动代码生成**。未来应采用经评审的生成器，避免 DTO 漂移；Repository 数据库存储结构不是 HTTP DTO。

## 前端双模式

```bash
cd web
npm ci
npm run dev                       # 默认演示：VITE_DATA_MODE=demo
VITE_DATA_MODE=server npm run dev # 连接本机 Server，只读且无 mock 回退
```

开发代理只绑定 `127.0.0.1`，把 `/api`、`/healthz`、`/readyz` 代理到 `http://127.0.0.1:8080`；服务端另行以 `go run ./cmd/server --dev-ui --listen 127.0.0.1:8080` 启动。

- **演示模式**：页面全部为样例数据；本地 UI 草稿修改会明确提示“仅演示”。新增端口不自动授权，新增范围默认未审批，新增任务默认 PENDING 且没有 Worker/租约。
- **Server 模式**：只读取 API。501/网络错误时显示不可用、不回退 Mock、不构造任务或扫描成功状态。所有敏感操作按钮保持禁用；FIXED 和 CURRENT 回滚在两种模式均禁用，直到具备完整 Server 决策和审计能力。
- 数据展示不证明 nftables 已设置、Worker 已降权、引擎已扫描或 Manifest 验签成功。未来接入真实数据时，需要另行设计会话鉴权、授权角色、CSRF、审计及 Server-Node API 独立监听和节点身份验证。

## 自动构建与发布

CI 使用 Node.js 22 + `npm ci` 锁定依赖，验证演示模式和 Server 模式的 TypeScript/Vite 构建。Release 只构建一次 `VITE_DATA_MODE=server` 的静态 UI，将它下载到每个操作系统/架构包的 `web/` 目录。该目录**尚未被 Go Server 嵌入或提供 HTTP 静态服务**；打包成功不代表用户管理或扫描平台已可部署。

## 未来开发顺序

1. 完成 HTTP API 的身份和角色模型，以及真正的只读列表 Handler 和分页过滤。
2. 完成 Server 唯一持有的 Repository 实现和查询，避免 UI 与 Node API 共用无鉴权业务路由。
3. 将页面的演示按钮替换成需要 Server 授权的业务命令。申请范围、人工审批端口解除、任务创建和撤销为不同的命令；`FIXED` 必须根据完整扫描证据由 Server 自动判定。
4. 通过 V3.2 规定的 manifest 验签、哈希、兼容矩阵、防回滚及人工审批/审计后，方能启用 CURRENT 切换，不允许仅由网页确认框激活版本。
