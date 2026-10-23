# 便携版 sec-portable

`sec-portable` 是单个程序：Server、Worker、Updater 在同一进程中运行，网页已内嵌，数据库使用 SQLite，只监听本机回环地址。适合单台电脑离线扫描已登记、已授权的主机。多台 Worker、PostgreSQL 和 Linux 网络围栏请使用集群部署（[deploy/README.md](../deploy/README.md)）。

## 目录结构

程序以自身所在目录为根目录（可用 `--home` 指定其他目录）：

```text
sec-portable/
├── sec-portable(.exe)
├── bin/                 nuclei、trivy（随发布包提供）
├── vuln-data/           规则与漏洞库（CURRENT、releases/），只由进程内的 Updater 写入
├── config/              可选：ssh-config.json、known_hosts、keys/、trusted-rule-keys/*.pem
└── runtime/             仅当前用户可访问（0700），启动时自动创建
    ├── platform.db      SQLite 数据库
    ├── reports/  worker/  inputs/  engine-data/trivy/
    ├── logs/portable.log
    └── portable.lock    防止两个副本共用同一份数据
```

## 使用

1. 在可联网的机器上准备漏洞库（只下载和打包，不扫描）：

   ```bash
   ./sec-portable prepare --with-java-db
   ```

   也可以把单独下载的离线数据包解压为 `vuln-data/`，或启动后在“节点与规则库”页面导入规则 ZIP。
2. 启动：

   ```bash
   ./sec-portable
   ```

   程序会打开浏览器访问 `http://127.0.0.1:8080/`；首次使用在页面上创建管理员。端口被占用时用 `--listen 127.0.0.1:18080` 换一个；不想自动打开浏览器时加 `--no-browser`。按 Ctrl+C 退出。
3. 需要 Linux 软件包采集时，在资产列表点“SSH 采集配置”生成 `ssh-config.json`，与 `known_hosts`、私钥一起放到 `config/` 后重启（详见 [SSH 采集](ssh-collection.md)）。

`./sec-portable --status` 输出目录、内嵌网页、引擎、规则是否就绪等信息，不会启动或创建任何内容。

## 安全边界

- 只监听数字回环地址，拒绝 `0.0.0.0`、局域网 IP 和主机名。
- Worker 和 Updater 仍只通过 Server 的节点接口通信。每次启动为它们各生成一个随机令牌，令牌只在内存中，不写入磁盘、日志或环境变量；本机其他程序没有令牌，调用节点接口会被拒绝（401）。Worker 不持有数据库连接。
- 没有 Linux 防火墙围栏：扫描范围由 Go 代码强制校验（AGENTS.md 4.1-8）。`--status` 中 `networkFence` 为 `false`。
- 规则目录对 Worker 只读由代码保证：同一进程无法用操作系统权限隔离，Worker 代码只读取 `vuln-data/`，只有 Updater 写入。
- 规则签名：`config/trusted-rule-keys/` 中有公钥时，导入的规则包必须由其中之一签名；没有公钥时保持现有的本地未签名行为（与 `sec-updater` 相同）。
- 运行期间 `prepare` 会被拒绝，避免与正在运行的 Updater 同时写规则目录。

## 构建

```bash
make portable
```

该目标先构建 `web/`，再把 `web/dist` 复制到 `internal/webui/dist`（复制的文件不提交）并编译 `dist/sec-portable`。直接 `go build ./cmd/portable` 得到的程序不含网页，启动时会提示改用 `make portable` 或传入 `--ui-dir`。发布流程 `Build & Release Artifacts` 使用同一份前端产物为每个平台编译。

## 尚未完成

- Windows、macOS 代码签名与公证。
- 在目标终端上进行杀毒软件 / EDR 误报测试（架构文档第二阶段验收要求）。
