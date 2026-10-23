# Phase 0 项目骨架（历史说明）

> 本文记录最初的入口骨架，不能代表当前实现状态。当前功能和差距以 [`docs/product/current-state.md`](product/current-state.md)、[`docs/runtime.md`](runtime.md) 与 [`docs/verification-log.md`](verification-log.md) 为准。

当前代码优先完成模块边界与开发调试入口，不代表实际的扫描平台已经运行。

## 入口与职责

| 入口 | 预期职责 | 当前能力 |
| --- | --- | --- |
| `cmd/server` | UI API、节点 API、调度和唯一数据库连接方 | 可用：完整 Web UI 与 API、调度、可选独立 TLS 节点监听；默认 SQLite，可显式选择 PostgreSQL |
| `cmd/updater` | 规则验签、发布、回收 | 可用：领取规则作业、导入（配置可信公钥时验签）、引擎兼容性检查、激活与防回滚、`--prepare-engines`、`--import-bundle-file` |
| `cmd/worker` | 领取任务、租约、围栏、执行引擎 | 普通模式可领取真实任务；Linux 显式 `--fence --once` 时先安装专属 namespace 围栏并以 uid 10001 执行子进程，隔离实验仍待验收 |
| `cmd/portable` | 单进程便携版（Server、Worker、Updater 同进程，内嵌网页，SQLite，仅回环） | 可用：启动、`--status`、`prepare`；见 [portable.md](portable.md) |
| `web/src/pages/Users` | 用户与权限管理 | 可用：创建用户、修改角色与启停、管理员重置密码 |

`internal/bootstrap` 定义统一启动参数、节点 TLS/令牌和 Linux 围栏入口；`internal/api` 与 `internal/repo` 已提供 SQLite/显式 PostgreSQL 运行时。本文后续的“占位/501/readyz 503”描述仅适用于最初提交时的骨架。

## 最小启动方式（仅开发用途）

```bash
go run ./cmd/server --status
go run ./cmd/server --dev-ui --listen 127.0.0.1:8080

# 便携版：make portable 构建内嵌网页的单程序（见 portable.md）
go run ./cmd/portable --status
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

`sec-server --dev-ui` 现在可以使用 SQLite 登录、创建用户和修改角色/启停状态，仅在 loopback 开放。初次启动与密码安全输入方式见 [`quickstart.md`](quickstart.md)。（以上为当时记录；Node API、扫描和规则更新现已接入，`sec-portable` 已是可用的单程序便携版，见 [`portable.md`](portable.md)。）
