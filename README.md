# 安全漏洞扫描平台

本仓库按 `docs/architecture-v3.2.md` 建设，当前目标是 Phase 0 PoC。架构文档是产品架构的唯一依据；工程和安全约束见 [`AGENTS.md`](AGENTS.md)。

## 当前状态

仓库目前提供 Go 项目骨架、构建入口和六项 PoC 的验收说明。PoC 1 已有不产生网络流量的目标准入校验、Linux nftables 围栏规则生成、受限启动器的预备代码，以及单元/fuzz/隔离实验测试入口（见 `pocs/01/README.md`）。**Linux 实际应用围栏、DROP 计数和 UID/capabilities 验收尚未执行**，且这些模块尚未与 Worker 入口集成。Server、Updater、Worker 当前均为 fail-closed 占位入口，不会连接数据库、写规则目录或启动扫描引擎。此骨架不是可部署的扫描平台。

## 目录

`cmd/` 保存服务入口，`internal/` 保存私有业务包，`deploy/` 保存部署资产，`docs/` 保存架构和验证记录，`pocs/` 保存 PoC 规格，`scripts/` 保存辅助工具。

## 本地命令

需要使用 `go.mod` 指定的 Go 版本和 GNU Make。

```bash
make build
make lint
make test
make verify-flags
make test-lab
```

`make verify-flags` 在 Nuclei、Trivy 版本和参数核验流程锁定前会明确失败。真实扫描类验收只能在隔离实验环境运行；详见 [`AGENTS.md`](AGENTS.md) 和各 PoC 说明。

## GitHub Actions：跨平台构建与发布

- `.github/workflows/ci.yml`：`main` Push / PR 执行格式检查、`-race` 单测，并在 Linux、macOS、Windows 的 amd64/arm64 托管 Runner 上分别运行 `go build ./...`。也提供 `workflow_call` 供发布流水线复用。Windows 构建不依赖 GNU Make。
- `.github/workflows/build-artifacts.yml`：手动运行 `workflow_dispatch` 或 Push `v*` 标签时，先**完整通过上述 CI**，再由 Ubuntu Runner 交叉编译六种平台打包为 `.zip` / `.tar.gz`，每个平台生成 SHA-256 校验文件。
- **手动触发只上传 Actions Artifacts，不创建 GitHub Release**；标签触发会在汇总前逐一验证校验文件，随后仅创建 **Draft + Pre-release**，需要人工审查后才能公开发布。
- 当前归档中的 `sec-server`、`sec-updater`、`sec-worker` 都还是安全拒绝启动的 Phase 0 骨架；`sec-portable` 只有存在 `cmd/portable/main.go` 后才会构建。构建通过不代表客户端已经可用。
- `go.mod` 目前没有外部依赖或 `go.sum`，Actions 暂时禁用 Go 缓存。未来应独立评审发布产物的 Windows 签名、macOS 签名/公证及 Artifact Attestation，不能把普通 SHA-256 文件当作软件签名。

相关本地与云端验证记录见 `docs/verification-log.md`。
