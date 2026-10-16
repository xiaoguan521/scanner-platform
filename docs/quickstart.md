# 本地快速开始

在仓库根目录运行 `make dev`，打开 http://127.0.0.1:8080，首次设置管理员，已有账号直接登录。Server 同时提供网页和现有 API，不再需要另起 Vite 或使用另一套账号数据库。

默认 SQLite 为 `runtime/platform.db`，规则目录为 `vuln-data/`；两者均不会提交到 Git。初始管理员也可通过 `sec-server --init-admin admin` 在终端交互创建。旧的 `--dev-ui` 是统一 Server 的兼容参数；使用旧账号库时，请显式传入该库的绝对 `--db` 路径，程序不会擅自复制其他位置的账号或资产。

资产/端口、跳过标记、任务、定时、规则包和验证命令详见 [本地功能](local-functions.md)。运行 `make engines` 安装固定的 Nuclei/Trivy/ZAP 与默认规则后，可在任务页选择真实引擎。详见 [引擎操作指南](engines.md)；真实服务器探测另行验证。
