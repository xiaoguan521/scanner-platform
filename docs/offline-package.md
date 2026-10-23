# 平台包与离线规则

GitHub Actions 的 `Build & Release Artifacts` 工作流提供 Linux amd64/arm64、macOS amd64/arm64 和 Windows amd64 压缩包。Windows arm64 暂不打包，因为当前锁定的 Nuclei 与 Trivy 版本没有该平台的官方二进制及 SHA-256 校验值。

每个压缩包包含平台 Server、Worker、Updater、Server 模式网页（`web/dist/`）、Nuclei、Trivy、Linux 输入采集脚本、引擎版本/来源/许可证元数据，以及本文档。Nuclei 和 Trivy 的归档按 `config/engines.lock.json` 中固定的 SHA-256 校验；手动触发 `Build & Release Artifacts` 时选择 `include_zap=true` 才会额外打包裁剪为被动分析用途的 ZAP。压缩包另附整体 SHA-256 文件。启用 ZAP 时需要 Java 17 或更新版本，目标机需要预先安装 Java 并确保 `java` 在 PATH 中。

## 便携版（推荐）

压缩包中的 `sec-portable` 是单个程序，内嵌网页，启动后 Server、Worker、Updater 在同一进程运行：先运行 `./sec-portable prepare --with-java-db` 准备漏洞库，再运行 `./sec-portable` 并在打开的浏览器中创建管理员。详见 [便携版](portable.md)（压缩包内为 `docs/portable.md`）。下文是分别启动三个程序的方式，适合排查问题或需要单独配置时使用。

## 准备漏洞库

程序压缩包不包含规则发布目录和 Trivy 数据库。可在本机手动准备，也可以在 GitHub Actions 中运行 `Build Offline Vulnerability Data` 工作流下载独立数据包。操作步骤、校验方式和当前覆盖范围见[离线漏洞库下载包](offline-vulnerability-data.md)。

本机准备时，在可联网的机器上解压平台程序包，然后运行：

```bash
./sec-updater --prepare-engines --with-java-db
```

Windows PowerShell 使用：

```powershell
.\sec-updater.exe --prepare-engines --with-java-db
```

Updater 会将 Trivy 主漏洞库、Java 索引和平台内置的四项只读 Nuclei HTTP 基线准备到 `vuln-data/`，并激活该版本；加 `--nuclei-templates-dir` 时还会纳入已筛选的只读检测模板（离线漏洞库下载包已包含）。它不会下载完整上游 Nuclei 模板库；Worker 也不接受任意上游 YAML 模板，只接受单次同源只读 GET 的 JSON 模板。

离线部署时，把完整的 `vuln-data/` 目录（包括 `CURRENT` 和 `releases/`）复制到目标机解压后的平台包目录。只扫描 Java 以外的 Trivy 输入时，也可以不带 `--with-java-db`；JAR/WAR/EAR/PAR 检查必须准备 Java 索引。

## 采集 Linux 输入

Linux 目标机上可使用包内的 `tools/collect_linux_inputs.py`，需要 Python 3.6 或更新版本；SQLite RPM 数据库快照需要 Python 3.7 或更新版本。在有权检查的目标机上，只传入需要的应用路径或本机已有镜像，例如：

```bash
python3 tools/collect_linux_inputs.py --source server-a --output /tmp/server-a \
  --app app=/opt/approved-app
```

将脚本报告的组件和输入类型对应到任务页；把输出目录完整复制到 `runtime/inputs/`，包括隐藏的 `.scanner-input.json` 清单。工具只读取明确选择的文件、系统包数据库与本地镜像，不做网络发现、远程登录或容器启动。细节见包内 `docs/linux-server-scan.md`。

## 启动本机扫描服务

在平台包目录开启三个终端。第一个启动 Server：

```bash
./sec-server --listen 127.0.0.1:8080 --db runtime/platform.db --ui-dir web/dist
```

第二个启动 Worker：

```bash
./sec-worker --server http://127.0.0.1:8080 --bin-dir bin --rules-dir vuln-data --inputs-dir runtime/inputs --runtime-dir runtime/worker
```

第三个启动 Updater：

```bash
./sec-updater --server http://127.0.0.1:8080 --rules-dir vuln-data
```

Windows 使用对应的 `.exe` 文件，例如 `sec-server.exe`；命令参数相同。浏览器在扫描机打开 `http://127.0.0.1:8080`。先创建账号，再只登记获准扫描的数字 IP 和端口并手动创建任务。Nuclei 只执行规则包中的只读 GET 模板（见 [引擎指南](engines.md)）；ZAP 只做被动分析。

分别启动时，Server、Worker 与 Updater 通过 loopback 通信，默认不启用节点令牌；便携版每次启动会为 Worker 和 Updater 生成仅在内存中的令牌。两种方式都没有系统网络围栏（扫描范围由 Go 代码校验），不应作为公开网络上的生产集群部署。Trivy 规则库、Nuclei 模板和实际扫描覆盖边界见 [引擎指南](engines.md) 与 [Linux 采集说明](linux-server-scan.md)。
