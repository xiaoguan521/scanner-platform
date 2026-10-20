# 扫描引擎接入与服务器验证

已接入 Nuclei、Trivy 和 ZAP，并提供“自动综合扫描”：对单台已登记主机，在用户明确填写并获批的 TCP 范围内并发探测，再自动检查范围内开放的 HTTP(S) 服务；若 Worker 配置匹配的本机 SSH profile，且 SSH 端口包含在本次范围内，还会一次性采集系统包数据库并用本地 Trivy 漏洞库分析。SSH 细节见[Worker 本机 SSH 采集](ssh-collection.md)。启动服务、登记资产、导入规则本身不会自动扫描。Worker 不连接数据库。

| 引擎 | 固定版本 / 许可证 | 本机程序 | 当前用途 |
|---|---|---|---|
| Nuclei | 3.11.1 / MIT | `bin/nuclei`（Windows 为 `.exe`） | 指定 IP:端口的只读 HTTP 基线 |
| Trivy | 0.76.0 / Apache-2.0 | `bin/trivy`（Windows 为 `.exe`） | Linux 系统包快照、离线依赖目录、Docker-save / OCI 镜像归档 |
| ZAP | 2.17.0 / Apache-2.0 | `bin/zap/zap-2.17.0.jar` | 指定地址响应的离线被动检查；需要 Java 17+ |

官方来源：[Nuclei release](https://github.com/projectdiscovery/nuclei/releases/tag/v3.11.1)、[Trivy release](https://github.com/aquasecurity/trivy/releases/tag/v0.76.0)、[ZAP release](https://github.com/zaproxy/zaproxy/releases/tag/v2.17.0)。下载地址与各平台 SHA-256 固定在 `config/engines.lock.json`。安装器校验压缩包哈希后解压，保留许可证和安装来源。Git 只记录安装器、版本锁与代码；程序、漏洞库、扫描输入和结果留在被忽略的本机目录。

## 安装和启动

首次安装或在另一台机器准备环境：

```bash
make engines   # 下载三种官方引擎；Updater 下载 Trivy DB、安装并激活默认规则；核对参数
make engines-java # 检查 JAR/WAR/EAR 时额外准备 Java 索引；大库流式安装
make dev       # 启动网页、Server、Worker、Updater
```

不想在目标机安装 Go/Node.js 时，可在 GitHub Actions 手动运行 `Build & Release Artifacts`，下载对应平台的整机包。压缩包包含平台程序、`web/dist`、锁定版本的 Nuclei/Trivy/ZAP 及其版本/许可证元数据；Linux arm64、amd64，macOS arm64、amd64 和 Windows amd64 均有包。当前锁定的引擎未提供 Windows arm64 资产，因此该架构不打包。漏洞库可通过独立的 `Build Offline Vulnerability Data` 工作流手动生成并下载，详见[离线漏洞库下载包](offline-vulnerability-data.md)。ZAP 需要目标机预装 Java 17 或更高版本。

打开 `http://127.0.0.1:8080`，首次设置管理员。已完成安装时直接 `make dev`。默认规则目录 `vuln-data/`，输入目录 `runtime/inputs/`。漏洞库解压后较大，连同 Updater 下载缓存、Worker 私有缓存建议预留至少 6 GiB。`make engines` 需要互联网；已有程序和完整规则库时扫描不进行规则更新。

`make engines` 的规则准备也可以单独运行：`dist/sec-updater --prepare-engines`。它只安装数据、切换 CURRENT，不创建扫描任务；运行中的任务仍使用创建时固定的规则版本。随后启动的 Updater 会把实际目录状态同步到网页。`make verify-flags` 检查已安装程序版本和实际帮助输出，不扫描任何目标。

## 验证 Web 服务

1. 资产页登记你有权验证的服务器数字 IP 和明确端口；Nginx 四层转发端口填写“跳过端口”。不输入域名或 CIDR。
2. 节点页查看引擎版本与就绪状态。Nuclei 还需要当前规则版本含 `nuclei/`；ZAP 使用随程序固定的被动规则。
3. 任务页点击“创建任务”，选 Nuclei 或 ZAP、HTTP / HTTPS、已登记的 IP:端口。HTTPS 允许自签名证书；不发送登录凭据。
4. 观察任务从待领取到执行中、已完成；发现项页查看引擎、目标、匹配路径和说明。失败任务可展开查看提示，细节在 `runtime/worker/scan-*/engine.log`；ZAP 另有私有启动日志。
5. 可设置时间窗、定时运行或取消任务。Worker 轮询取消状态并终止子进程；到期中止，不把部分结果当完整成功。扫描无匹配时可完成且不制造发现项；连接失败、解析失败和引擎失败会显示失败。

Nuclei 当前默认四项基线：缺少 `X-Content-Type-Options`、缺少 CSP、缺少 `X-Frame-Options`、公开 Server 响应头。部分条目只具信息价值，需要结合应用用途判断。仅接受受限 JSON 模板：单次根路径 GET，以及字词/正则/状态匹配；不执行原始请求、请求体、动态载荷、代码、浏览器、DNS、网络协议或工作流。上游完整 YAML 漏洞模板库尚未接入，不能把本次结果解释为完整 CVE 覆盖。

Nuclei 使用 `-fhr` 将重定向限制在同一主机，禁用 OAST、httpx 探测和更新，默认每秒 5 请求、并发 1。根请求与代理只接受明确的数字 IP:端口。3.11.1 中 `-fhr` 与 `-dr` 互斥，因此只传 `-fhr`，避免引擎拒绝启动；实测帮助与执行结果见验证记录。

ZAP 由 Go 先读取指定根地址响应（不跟随重定向、单响应上限 2 MiB），随后以 HAR 导入，执行 passiveScan 和 JSON 报告。没有爬虫或主动扫描任务，插件只保留这条被动流水线及其依赖。使用 `-silent -notel` 关闭未请求的联网行为。实现依据：[HAR 导入](https://www.zaproxy.org/docs/desktop/addons/import-export/automation/)、[ZAP 命令行](https://www.zaproxy.org/docs/desktop/cmdline/)。固定分发包中的 exim 0.16.0 只支持导入记录响应，不支持新版文档中的 `sendRequests` 参数，代码未传该参数。

## Trivy：Linux 系统、依赖与镜像归档

Linux 上同时有 Docker 和直接部署时，使用 [Linux 采集与扫描说明](linux-server-scan.md)：在目标机器由操作员明确选择应用目录和本地镜像，采集主机软件包数据库、指定依赖与镜像，复制到 Worker，再分别创建 `rootfs`（系统包）、`filesystem`（依赖清单）、`artifact`（JAR/Go 部署文件）、`image-archive`（镜像）任务。采集不会发起网络探测或远程登录。

Trivy 0.76 的 `filesystem` 禁用 JAR/Go 部署产物分析，`rootfs` 禁用项目锁文件分析，因此 `artifact` 固定运行 `rootfs --pkg-types library`。已选 Go ELF 使用固定文件匹配规则识别，保持非执行权限；不执行输入。混合目录由采集工具拆开，对应分别创建任务；手工选错类型会拒绝，避免仅部分识别却报告完成。依据：[锁定版本的模式选择](https://github.com/aquasecurity/trivy/blob/v0.76.0/pkg/commands/artifact/run.go)。

将要检查的内容放到 Worker 本机输入根目录：

```text
runtime/inputs/deps/example-project/package-lock.json
runtime/inputs/images/example-image.tar
```

创建离线 Trivy 任务时，类型选“依赖目录”并填 `deps/example-project`，或者选“镜像归档”并填 `images/example-image.tar`。镜像归档由操作员使用 `docker save` 或 OCI 导出准备；离线输入模式不拉取镜像，也不连接 Docker socket。输入路径必须位于配置根目录内，拒绝符号链接。

Worker 使用固定规则版本中的 `trivy/db/trivy.db` 与 `metadata.json`，先复制到本节点按引擎/规则版本隔离的可写缓存；后续同版本复用缓存。启用 `--offline-scan`、禁用 DB/Java DB/检查规则/VEX 更新与遥测；只运行漏洞扫描，不加载输入目录的 Trivy 配置。JAR 分析需同一规则版本的 `trivy/java-db/{trivy-java.db,metadata.json}`：运行 `make engines-java` 准备，节点页会说明 Java 索引文件是否存在。没有索引的 JAR 目录任务明确失败，固定旧规则版本的排队任务不会自动换新库，准备后应重新创建任务。真实业务文件尚待验证。配置依据：[Trivy filesystem 参数](https://trivy.dev/latest/docs/references/configuration/cli/trivy_filesystem/)、[Java 索引与 DB 配置](https://trivy.dev/docs/latest/configuration/db/)。

Java 索引压缩包当前约 940 MiB（大小随上游变化），超过网页 ZIP 上限。Updater 直接把已下载主库/Java 索引流式复制、哈希、fsync 到暂存版本，再按现有不可覆盖版本逻辑安装并显式激活；不把大库放入 Server 数据库。网页规则 ZIP 仍限 256 MiB；单规则文件仍限 4 GiB、总展开量仍限 8 GiB。2026-10-19 本机主库与 Java 索引合计约 3 GiB；下载缓存、活动/备用规则和每个 Worker 私有缓存各占一份，应按实际 DB 体积准备磁盘。

离线准备时，把主库与 Java 索引缓存完整复制到 Updater 可读目录（包括各自 metadata），执行：

```bash
dist/sec-updater --prepare-engines --with-java-db --skip-db-download --db-cache /path/to/trivy-cache
```

缓存布局为 `db/{trivy.db,metadata.json}` 与 `java-db/{trivy-java.db,metadata.json}`。这条命令不联网、不扫描；只由 Updater 写规则盘。缺失、链接、文件变化、大小超限或复制中止均不激活新版本。没有 Java 索引时原有 Node.js/系统包任务仍可使用主库。Java 离线行为依据：[Trivy 受限网络配置](https://trivy.dev/docs/latest/guide/advanced/air-gap/)。

结果保留组件、安装版本、漏洞编号与修复版本。镜像使用 Trivy 返回的不可变 ImageID 去重，不依赖归档文件名；重复检测保留首次时间和人工处理状态。未检出不会自动标记 FIXED。

## 验证与当前边界

```bash
make build && make lint && make test
make verify-flags
make test-local
make test-engines-local   # 自建回环 HTTP 夹具、临时 SQLite 和本地依赖/镜像夹具
```

最后一条需要先完成引擎和数据库安装；不会读取登记资产，也不连接真实服务器。普通单元测试不需要引擎或互联网。引擎测试证据为终端打印的临时目录；原始扫描响应和运行日志不提交仓库。

这是早期本机运行模式：Server/节点 API 仍限回环地址，未提供生产 TLS/独立节点令牌与系统网络围栏。扫描 Worker 要使用普通用户运行，拒绝 root。Updater 的普通规则导入和激活要求包外受信 Ed25519 公钥及有效签名；显式本机数据准备使用同一进程的一次性本地激活记录，历史无签名包仍标为未验签。Worker 执行前复核文件完整性，不单独声明已验签。完整模板兼容性、真实服务器覆盖与生产部署未验证。本地夹具通过不表示真实服务器验证已通过。
