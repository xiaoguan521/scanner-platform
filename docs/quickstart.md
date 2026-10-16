# 本地快速启动：SQLite + 登录 + 用户管理

当前仅在本机开发模式下启用账号管理。**真实扫描、规则升级、授权审批和节点服务尚未开放。**

## 1. 初始化管理员（第一次运行）

在项目目录打开终端：

```bash
go run ./cmd/server --init-admin admin
```

命令会要求输入初始密码，长度为 **12–72 字节**；输入时终端不会回显。请设置自己的随机强密码，不要把密码写到命令行、配置文件或 Git 中。默认数据库位置是操作系统当前用户配置目录下的 `scanner-platform/server.sqlite`，文件权限自动限制为当前用户读写。

如需指定 SQLite 文件，可以在所有相关命令加上 `--db /绝对路径/server.sqlite`；管理员只允许初始化一次，后续增加用户在页面中操作。

无交互终端时，可指定仅当前用户可读的临时密码文件（POSIX 上权限 0600）：

```bash
go run ./cmd/server --init-admin admin --password-file /绝对路径/一次性密码文件
```

首次初始化成功后**立即删除该一次性密码文件**。

## 2. 启动 Go Server

打开第一个终端：

```bash
go run ./cmd/server --dev-ui --listen 127.0.0.1:8080
```

本地后端包含以下可用 API：

| 地址 | 功能 |
| --- | --- |
| `POST /api/v1/auth/login` | 登录并设置 HttpOnly 会话 Cookie |
| `GET /api/v1/auth/me` | 查询当前登录用户 |
| `POST /api/v1/auth/logout` | 注销 |
| `GET /api/v1/users` | 管理员查看用户列表 |
| `POST /api/v1/users` | 管理员创建账号 |
| `PATCH /api/v1/users/{id}` | 管理员修改角色与启停状态 |

密码在 SQLite 中保存的是 bcrypt 哈希；会话令牌数据库只保存 SHA-256 摘要；用户操作留下审计记录。其他扫描业务仍返回 501，`/readyz` 返回 503（扫描平台尚未就绪）。

## 3. 启动前端

打开第二个终端：

```bash
cd web
npm ci
VITE_DATA_MODE=server npm run dev
```

浏览器打开 **http://127.0.0.1:3000**，使用刚创建的管理员账号登录。进入“用户与权限”，可以新建账号、修改角色、停用账号；非管理员不会看到用户管理菜单，也无法请求用户管理 API。

`VITE_DATA_MODE=server` 很重要：不设置时会使用演示 Mock 数据，无法验证 SQLite 的实际改动。

## 范围与限制

- **仅用于本机开发**，不允许绑定 `0.0.0.0`、内网或公网地址。正式部署前需要 HTTPS、完善会话安全、登录风控及迁移/审计体系。
- SQLite 是当前第一步的存储引擎，后续将数据访问接口抽象到 PostgreSQL 共用 Repository。
- 项目不会因用户登录成功自动启用 Worker、Nuclei、Trivy、规则发布或越权扫描。
