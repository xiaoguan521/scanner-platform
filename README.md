# 安全漏洞扫描平台

当前为早期开发模式：允许直接小步提交 main。架构见 [架构文档](docs/architecture-v3.2.md)，工作规则见 [AGENTS.md](AGENTS.md)。

## 本地启动

运行 `make dev`，打开 http://127.0.0.1:8080，首次创建管理员后登录。详细操作见 [本地功能与验证](docs/local-functions.md)。

已连通 SQLite 账号/用户管理、资产与显式端口、四层转发端口跳过标记、范围/端口审批记录、任务创建/取消、模拟 Worker 与发现项状态管理、定时任务/跨午夜时间窗、节点心跳、规则包在线/离线导入与激活/显式回滚。Server 提供网页和统一 API，Updater 是规则目录的唯一写入进程。

已接入固定版本 Nuclei、Trivy，ZAP 作为可选被动引擎：运行 `make engines` 准备核心程序与主库；需要 ZAP 时再运行 `make engines-zap`，Java 检查再运行 `make engines-java`，然后 `make dev`。任务页可选只读 HTTP 基线、ZAP 被动分析、Trivy Linux 系统包快照/依赖清单/JAR 与 Go 部署文件/镜像归档，或原有模拟模式。操作与当前覆盖见 [引擎接入指南](docs/engines.md)，混合部署使用 [Linux 采集说明](docs/linux-server-scan.md)。Linux Worker 的专属 namespace 围栏已接入代码，但仍需隔离实验验收；真实服务器另行验证，Harbor、AI、便携版仍后置。

需要直接下载平台程序和扫描引擎时，在 GitHub Actions 手动运行 `Build & Release Artifacts`，按平台下载压缩包；离线规则库与 Java 索引的准备和目录布局见[离线平台包说明](docs/offline-package.md)。

## 检查

```bash
make build
make lint
make test
make test-local
```

`make test-local` 使用临时数据库、规则目录与本机端口，结束时停止测试进程。API 契约见 [OpenAPI](docs/api/openapi.yaml)，验证证据见 [验证记录](docs/verification-log.md)。`make verify-flags` 核对固定引擎版本和参数，`make test-engines-local` 验证真实引擎的本地夹具链路。

## 数据与发布边界

默认运行数据在 `runtime/`，规则在 `vuln-data/`，构建在 `dist/` / `web/dist/`，均被 Git 忽略。不要提交真实内部 IP、资产、扫描结果和密钥。

PostgreSQL 已提供显式 Server 运行时、迁移和核心任务/发现项/报告适配；默认 `make dev` 仍使用 SQLite，当前差距见 [运行说明](docs/runtime.md) 和 [产品现状](docs/product/current-state.md)。Linux 围栏的启动约定见 [Worker 围栏说明](docs/worker-fence.md)；跨平台打包和生产部署仍不属于本地验证。

多节点部署材料可用 `make build` 后运行 `dist/sec-node-provision` 离线生成；它只生成 owner-only 私钥/令牌文件和非敏感路径清单，不自动传输、登记或启动节点。详细参数见 [运行说明](docs/runtime.md)。
