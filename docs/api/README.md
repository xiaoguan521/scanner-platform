# UI API 契约（Phase 0）

架构规范以 `docs/architecture-v3.2.md` 为准；HTTP 请求/响应模型以本目录的 `openapi.yaml` 为唯一契约。两份文档的职责不同：OpenAPI 不能降低架构安全要求。

## 当前可用

- `GET /healthz`：仅表示进程存活，不表示扫描平台安全或就绪。
- `GET /readyz`：当前固定返回 503。
- `GET /api/v1/system/status` 与 `GET /api/v1/system/capabilities`：只读状态。
- 用户接口现已开放登录、登出、获取当前用户，以及仅管理员可用的用户列表、创建和角色/状态更新。资产列表、资产登记和编辑现已连接同一 SQLite，仅管理员和安全工程师可写；端口登记为待审批请求，不构成扫描授权。范围申请、范围审核、端口人工审批的 API 和 SQLite 表已编写，**待明日联调**。端口隔离、任务、漏洞、节点和规则包等真实接口仍未开放。

SQLite 用户管理已采用 V3.2 的四种角色，并实现 HttpOnly/SameSite Cookie、管理员权限限制及用户变更审计。Node API 和扫描权限控制尚未实现。

## 数据形状

统一 `application/json`，字段使用 camelCase；时间戳采用 RFC 3339，带明确时区偏移；版本号采用 `YYYYMMDD.nn`（例如 `20261016.01`），字段 `workerNodeId` 和 Server 任务分块模型对应。集合统一返回 `{ "items": [...], "total": 0 }`，错误返回 `{ "error": "...", "message": "..." }`。

Go 的 `internal/api/dto.go` 与 `web/src/types/index.ts` 当前人工对照 OpenAPI 定义，**尚未实现自动代码生成**。未来应采用经评审的生成器，避免 DTO 漂移；Repository 数据库存储结构不是 HTTP DTO。

## 前端双模式

```bash
cd web
npm ci
npm run dev                       # 默认演示：VITE_DATA_MODE=demo
VITE_DATA_MODE=server npm run dev # 登录本地 Server，操作 SQLite 用户管理
```

开发代理只绑定 `127.0.0.1`，把 `/api`、`/healthz`、`/readyz` 代理到 `http://127.0.0.1:8080`；服务端另行以 `go run ./cmd/server --dev-ui --listen 127.0.0.1:8080` 启动。

- **演示模式**：页面全部为样例数据；本地 UI 草稿修改会明确提示“仅演示”。新增端口不自动授权，新增范围默认未审批，新增任务默认 PENDING 且没有 Worker/租约。
- **Server 模式**：必须登录。用户管理允许管理员操作真实 SQLite；资产管理允许管理员/安全工程师操作真实 SQLite；申请范围和审批记录已提供真实 API（尚未调试）；其他业务接口仍为 501/禁用、不回退 Mock；FIXED 与 CURRENT 回滚仍禁用。
- 数据展示不证明 nftables 已设置、Worker 已降权、引擎已扫描或 Manifest 验签成功。当前会话仅面向 loopback 本地开发，使用 HttpOnly/SameSite Cookie 与请求头防护。公网部署前仍需评审 HTTPS、CSRF、细粒度审计与 Node API 身份验证。

## 自动构建与发布

CI 使用 Node.js 22 + `npm ci` 锁定依赖，验证演示模式和 Server 模式的 TypeScript/Vite 构建。Release 只构建一次 `VITE_DATA_MODE=server` 的静态 UI，将它下载到每个操作系统/架构包的 `web/` 目录。该目录**尚未被 Go Server 嵌入或提供 HTTP 静态服务**；打包成功不代表用户管理或扫描平台已可部署。

## 当前待验证的授权流程

1. 安全工程师或管理员登记数字 IP 主机及拟申请端口。
2. 提交单主机 IP 的范围申请、单日时间窗和过期时间，初始状态 `PENDING`。
3. **由另一个账号**的运维审批人或管理员填写真实审批单，选择批准或驳回；不能审批自己的范围或端口请求。
4. 端口由审核人明确归类 `WEB` 或 `NON_WEB`；如果处于四层转发隔离状态，审批应拒绝。修改资产会使旧端口审批失效。
5. **仅保存审批记录，不派发任务、不自动放开防火墙，也不自动执行扫描。** 明日需要验证数据库迁移、浏览器交互和 API 权限行为。

## 未来开发顺序

1. 完成 HTTP API 的身份和角色模型，以及真正的只读列表 Handler 和分页过滤。
2. 完成 Server 唯一持有的 Repository 实现和查询，避免 UI 与 Node API 共用无鉴权业务路由。
3. 将页面的演示按钮替换成需要 Server 授权的业务命令。申请范围、人工审批端口解除、任务创建和撤销为不同的命令；`FIXED` 必须根据完整扫描证据由 Server 自动判定。
4. 通过 V3.2 规定的 manifest 验签、哈希、兼容矩阵、防回滚及人工审批/审计后，方能启用 CURRENT 切换，不允许仅由网页确认框激活版本。
