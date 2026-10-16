# 本地运行
1. 在仓库根目录运行 `make dev`（Go、Node.js/npm、curl）；Server、Worker、Updater 会一起启动。
2. 打开 http://127.0.0.1:8080，首次创建管理员，已有账号直接登录。
3. 在资产页录入数字 IP 和端口，标记需要跳过的端口；任务页可立即运行或设置定时，发现项页查看模拟结果。
4. 节点页可导入/下载规则 ZIP 并激活或显式回滚；按 Ctrl+C 停止，数据留在 `runtime/platform.db`；详见 [本地功能](local-functions.md)。
