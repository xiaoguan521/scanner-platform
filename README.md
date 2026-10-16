# 安全漏洞扫描平台

当前为早期开发模式：允许直接小步提交 main。架构见 [架构文档](docs/architecture-v3.2.md)，工作规则见 [AGENTS.md](AGENTS.md)。

## 本地启动

运行 `make dev`，打开 http://127.0.0.1:8080，首次创建管理员后登录。详细操作见 [本地功能与验证](docs/local-functions.md)。

已连通 SQLite 账号/用户管理、资产与显式端口、四层转发端口跳过标记、范围/端口审批记录、任务创建/取消、模拟 Worker 与发现项状态管理、定时任务/跨午夜时间窗、节点心跳、规则包在线/离线导入与激活/显式回滚。Server 提供网页和统一 API，Updater 是规则目录的唯一写入进程。

**任务执行当前仍为模拟，不连接目标、不调用 Nuclei/Trivy。规则导入验证文件哈希，不代表已验签或引擎兼容性通过。真实扫描与服务器探测另行验证。** Harbor、AI、便携版仍后置。

## 检查

```bash
make build
make lint
make test
make test-local
```

`make test-local` 使用临时数据库、规则目录与本机端口，结束时停止测试进程。API 契约见 [OpenAPI](docs/api/openapi.yaml)，验证证据见 [验证记录](docs/verification-log.md)。`make verify-flags` 和隔离实验测试仍不代表真实引擎已接通。

## 数据与发布边界

默认运行数据在 `runtime/`，规则在 `vuln-data/`，构建在 `dist/` / `web/dist/`，均被 Git 忽略。不要提交真实内部 IP、资产、扫描结果和密钥。

PostgreSQL 迁移仍为未接入 Go 的草稿，见 [迁移说明](internal/repo/migrations/README.md)。现有 GitHub Actions 构建与发布矩阵保持不变；便携入口、围栏/租约/GC 等旧模块不作为当前本地业务的完成前提。跨平台打包和生产部署不属于本次本地验证。
