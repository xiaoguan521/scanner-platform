# 本地运行
1. 在仓库根目录运行 `make dev`（Go、Node.js/npm、curl）；Server、Worker、Updater 会一起启动。
2. 打开 http://127.0.0.1:8080，首次创建管理员，已有账号直接登录。
3. 在资产页录入数字 IP 和端口，标记需要跳过的端口；任务页可立即运行或设置定时，发现项页查看结果；`make engines` 准备引擎后可选择真实扫描。
4. 节点页可导入/下载规则 ZIP 并激活或显式回滚；按 Ctrl+C 停止，数据留在 `runtime/platform.db`；详见 [本地功能](local-functions.md)。

## 独立节点 HTTPS 通道

网页和控制面默认只监听数字回环地址。多进程或生产部署时，可为 Worker/Updater 单独开启 HTTPS 节点端口：

```text
sec-server --listen 127.0.0.1:8080 \
  --node-listen 192.0.2.10:8443 \
  --node-tls-cert /path/to/node-cert.pem \
  --node-tls-key /path/to/node-key.pem \
  --node-token-file /path/to/node-tokens
```

`--node-listen` 只接受明确的数字 IP 和端口，不能使用未指定地址、组播地址或主机名；私钥必须是 owner-only 普通文件。独立端口只路由 Worker、Updater 和 heartbeat 协议路径，强制 TLS 1.3 和节点 Bearer 令牌认证，网页路径返回 404。Worker/Updater 的 `--server` 应指向 `https://` 节点地址，并使用各自的 owner-only 单令牌文件；客户端必须信任服务端证书链。当前仍未提供 mTLS、证书轮换或 PostgreSQL 运行时切换。
