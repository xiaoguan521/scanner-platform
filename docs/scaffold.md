# Phase 0 项目骨架

当前代码优先完成模块边界与开发调试入口，不代表实际的扫描平台已经运行。

## 入口与职责

| 入口 | 预期职责 | 当前能力 |
| --- | --- | --- |
| `cmd/server` | UI API、节点 API、调度和唯一数据库连接方 | `--status`、手动启用只读本地调试 API |
| `cmd/updater` | 规则验签、发布、回收 | 只有 `--status`；真实激活/删除未开启 |
| `cmd/worker` | 领取任务、租约、围栏、执行引擎 | 只有 `--status`；不会启动扫描器 |
| `cmd/portable` | 未来的嵌入式单进程客户端 | `--status`、手动启用只读本地调试 API；不连接数据库 |
| `web/src/pages/Users` | 未来的用户与权限管理 | 仅样例列表/角色展示，所有账号写入及权限调整禁用；Server `GET /api/v1/users` 现为 501 |

`internal/bootstrap` 定义统一启动参数与默认拒绝启动策略；`internal/api` 当前仅暴露诊断路由；`internal/repo` 保留 SQLite / PostgreSQL 的共同接口。

## 最小启动方式（仅开发用途）

```bash
go run ./cmd/server --status
go run ./cmd/server --dev-ui --listen 127.0.0.1:8080

# Portable: 提前建立独立的跨平台构建入口
go run ./cmd/portable --status
go run ./cmd/portable --dev-ui --listen 127.0.0.1:8081
```

只读诊断地址为 `GET /healthz`、`GET /readyz`、`GET /api/v1/system/status`、`GET /api/v1/system/capabilities`。其中 `readyz` **始终返回 HTTP 503**，直到后续安全能力全部实现。业务 API 当前统一返回 `501 Not Implemented`，既不会发起扫描，也不会伪造漏洞数据。开发模式只允许**数字型 loopback IP 地址**，拒绝 `0.0.0.0`、公网地址和主机名。

`web/` 已由其他工作流并行搭建前端页面；页面数据不代表真实安全能力已经生效，不应作为生产监控。正式 Web UI、节点 API 两个监听端口仍需独立配置，节点协议已有可选的独立令牌文件鉴权，但不能把回环开发接口当作生产部署。

## 后续搭建顺序

1. 定义登录鉴权与 UI API 契约，完善资产、范围、任务、漏洞、节点、规则包的数据模型；当前接口只提供占位与明确的不可用状态。
2. 通过 `internal/repo` 统一 PostgreSQL / SQLite 存储接口，并保留单独的迁移目录。
3. Server 的 Node API 要求独立监听端口、TLS 和节点独立令牌文件；当前已落地令牌文件与身份绑定基础，继续补 TLS/部署隔离并落地 Server 侧租约与调度。
4. Updater 必须完成验签、哈希、兼容性和防回滚校验后才能接入 `CURRENT` 原子切换和 GC 文件操作。
5. Worker 需将已有 `scope`、网络围栏、租约和受控参数执行链全部打通，并完成隔离实验验收后才能执行真实扫描。
6. Portable 后续复用 Server、Updater、Worker 的服务层，但只绑定 `127.0.0.1`，并为 SQLite/规则目录提供私有的本地运行结构。

**当前任何入口都不提供业务数据库访问、网络扫描、规则升级或规则删除能力。**
## 当前已接入的本地账号管理

`sec-server --dev-ui` 现在可以使用 SQLite 登录、创建用户和修改角色/启停状态，仅在 loopback 开放。初次启动与密码安全输入方式见 [`quickstart.md`](quickstart.md)。Node API、扫描器及规则更新仍然关闭；`sec-portable` 仍只有占位功能。
