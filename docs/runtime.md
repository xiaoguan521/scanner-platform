# 本地运行
1. 在仓库根目录运行 `make dev`（需要 Go 1.26、Node.js/npm 和 curl）。
2. 打开 http://127.0.0.1:8080/#/tasks，启动任务会由 Worker 领取并变为“已完成”；也可点击“创建模拟任务”再次运行。
3. 打开“漏洞发现”，可看到明确标注的模拟发现项；当前不会执行真实扫描或连接显示的目标。
4. 按 Ctrl+C 停止；SQLite 数据保留在 `runtime/platform.db`，日志在 `runtime/`。
