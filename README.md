# 安全漏洞扫描平台

本仓库按 `docs/architecture-v3.2.md` 建设，当前目标是 Phase 0 PoC。架构文档是产品架构的唯一依据；工程和安全约束见 [`AGENTS.md`](AGENTS.md)。

## 当前状态

仓库目前提供 Go 项目骨架、构建入口和六项 PoC 的验收说明。PoC 1 已有不产生网络流量的目标准入校验代码和单元/fuzz 测试，但尚未实现 supervisor 防火墙围栏等实验部分。Server、Updater、Worker 目前均为 fail-closed 占位入口，不会连接数据库、写规则目录或启动扫描引擎。此骨架不是可部署的扫描平台。

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
