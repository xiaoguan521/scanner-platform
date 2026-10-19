# Linux：Docker 与直接部署的检查

任务中心的“自动综合扫描”可先检查单台已登记主机的授权端口范围、开放 HTTP(S) 服务和选定自定义只读规则；Worker 按 [SSH 采集指南](ssh-collection.md) 配置后，还可临时采集系统软件包数据库并在本地用 Trivy 分析。需要检查直接部署的应用、Go/Java 文件、依赖清单和容器镜像时，继续按下表手工选择/传入明确的离线输入；当前不会自动遍历服务器目录、容器或 Kubernetes 工作负载。

同一台 Linux 服务器的离线输入按内容分四种，均在已有任务页选择 Trivy：

| 要检查的内容 | 采集内容 | 任务输入类型 | 示例输入路径 |
|---|---|---|---|
| 操作系统，以及 apt/rpm/apk 安装的中间件 | 发行版标识与软件包数据库 | Linux 系统包快照（rootfs） | `lab-a/os` |
| 应用项目依赖 | 指定目录中的依赖清单、lock 文件 | 应用依赖清单（filesystem） | `lab-a/apps/web` |
| 直接部署的 Java 中间件、Go 应用 | 指定 JAR/WAR/EAR/PAR 或 Go ELF | 已部署应用（artifact） | `lab-a/apps/java` |
| Docker 部署的应用和中间件 | 指定本地镜像的 `docker image save` 归档 | 镜像归档（image-archive） | `lab-a/images/middleware.tar` |

## 在服务器采集，再交给 Worker

把 `scripts/collect_linux_inputs.py` 复制到有权检查的 Linux 服务器，使用 Python 3.6+ 执行；存在 SQLite 格式 RPM 数据库时需要 Python 3.7+ 的一致备份接口。下面的路径和镜像名是占位示例，替换为你明确选择的应用与**本地已有**镜像；没有应用或镜像时可省略对应参数：

```bash
python3 collect_linux_inputs.py --source lab-a --output /tmp/lab-a \
  --app web=/opt/example-app \
  --image middleware=example/middleware:local
```

`--source` 是稳定的服务器别名；同一服务器后续沿用同一别名、组件名与 Worker 输入路径。多个应用或镜像重复传 `--app 名称=路径`、`--image 名称=镜像ID或标签`。目录输入只递归选择已知依赖清单、lock 文件和 JAR/WAR/EAR/PAR。`--app` 也可指定单个锁文件或 Java 归档；Go ELF 必须逐个显式传入，例如 `--app service=/path/to/service-elf`，不会从目录自动识别 ELF。ELF 是否包含可分析的 Go 包信息取决于程序构建方式，不执行该程序。采集依赖目录会忽略 `.env`、普通配置、源码、`.git`、node_modules、虚拟环境与常见缓存；依赖清单本身仍可能包含私有信息，整个输出留在私有工作目录，不提交 Git。

采集工具会打印每个组件的**输入类型和路径**。目录只选出依赖清单时生成 `filesystem`，只选出 Java 归档时生成 `artifact`；同时选出这两类内容时自动拆为 `apps/名称/dependencies` 和 `apps/名称/artifacts` 两个独立输入。单独指定的 Go ELF 生成自己的 `artifact` 输入，不参与目录递归采集或自动分流。按打印的类型创建任务。固定 Trivy 0.76 的 filesystem 模式会跳过部署产物，所以不能把 JAR 放入依赖清单任务；平台对此明确拒绝。artifact 模式使用受限的库分析，识别 Go ELF 时保持文件私有的非执行权限。

Kubernetes 管理的容器，先由操作员确定需要验证的工作负载和**实际镜像摘要**。使用 Docker 的节点可以按指定镜像 `--image`；使用 containerd 的节点先由操作员导出所选镜像为 OCI tar，再用 `--image-archive middleware=/path/to/selected-image.tar` 纳入采集。平台不读取 kubeconfig、不遍历集群、不自动访问 API Server 或运行时 socket；导出归档不代表已经核对运行中的 Pod、容器层或挂载卷。OCI 和 Docker 归档均由现有 `image-archive` 任务处理。

采集工具读取主机发行版和 dpkg/apk/rpm 数据，不枚举网络、容器或镜像，不启动容器，不拉取镜像。Docker 默认仅连接本机 `/var/run/docker.sock`；rootless Docker 可用 `--docker-socket` 显式指定本机 Unix socket，不沿用环境中的远程 Docker context。执行账户需要读取包数据库、指定文件及保存指定镜像的权限。扫描 Worker 仍以普通用户运行。输出目录自带忽略全部内容的 `.gitignore`，避免普通 Git 提交误带入私有清单。

将完整的 `lab-a/` 目录（**包括以点开头的校验清单**）复制到执行任务的 Worker 的 `runtime/inputs/`，或者其 `--inputs-dir` 指定目录。默认布局如下：

```text
runtime/inputs/lab-a/collection.json
runtime/inputs/lab-a/os/.scanner-input.json
runtime/inputs/lab-a/os/etc/os-release
runtime/inputs/lab-a/os/var/lib/dpkg/status
runtime/inputs/lab-a/apps/web/.scanner-input.json
runtime/inputs/lab-a/apps/web/package-lock.json
runtime/inputs/lab-a/images/middleware.tar
runtime/inputs/lab-a/images/middleware.tar.scanner-input.json
```

运行 `make dev`，在任务页选 Trivy，按上表分别创建系统包、依赖清单、已部署应用、镜像任务。自动综合扫描也可在 Worker 配好 SSH 后采集系统包。网页会显示排队、执行、完成或失败；发现项包含 CVE、软件包、安装版本、修复版本，以及快照别名与采集时间。系统包去重使用稳定输入路径、包名、安装版本和 CVE；重复检查不制造重复发现。没有可分析的软件包数据库时任务失败，不当作“未发现漏洞”。

每个组件带文件 SHA-256 清单，Worker 在扫描前后核对；漏传、改动、符号链接、越界路径或未列出的文件会拒绝。清单用于传输完整性核对，不能证明来源可信。现有手工准备的依赖目录/镜像和 rootfs 仍可使用，无清单时没有这项快照校验。每个带清单的组件最多 10000 文件、单文件 16 GiB、总计 32 GiB；扫描输出另受现有报告上限约束，过大应按组件拆分。

更新服务器后，重新采集到**新目录**；待该输入的运行中任务结束后，再完整替换 Worker 上对应的稳定路径。采集工具拒绝覆盖已有目录，失败时删除暂存数据。定时扫描只重新分析已有快照，不会自动重新采集服务器。

## 覆盖边界

- 操作系统：比对采集时已安装的软件包与漏洞库，包含通过系统包管理器安装的中间件；不能据此确认正在运行的内核、进程版本或补丁是否已重启生效。未安装的包不在覆盖中。
- 直接部署：依赖目录模式用于有受支持清单的应用。源码编译的 Nginx/Redis、自带库的原生程序，不能只凭一个目录就宣称覆盖；没有包元数据的部分需要后续专项识别。JAR 分析需先运行 `make engines-java`，将主漏洞库与 Java 索引安装在同一版本；大库离线准备见[引擎指南](engines.md)。未准备索引时不能视为 Java 检查完成。
- Docker：保存的是指定镜像，未自动确认某个运行中容器使用它。容器可写层、挂载卷和宿主机不包含在镜像中；需要单独指定挂载的应用依赖目录，并另建宿主机 rootfs 任务。
- 支持范围取决于 Trivy 锁定版本、发行版、包元数据和漏洞库。当前只实测合成 Debian 软件包夹具；RPM SQLite 采集测试验证 WAL 一致备份，未表示所有 RPM 发行版的漏洞识别已通过。Red Hat 的 rootfs 模式有上游覆盖限制，真实验证需按具体发行版核对。
- Nuclei 当前仍为四项只读 HTTP 基线，ZAP 为被动响应分析；没有宣称完成上游全量 CVE 模板接入。不会进行利用、爆破或自动发现服务器。

## 常见 Linux 部署的覆盖边界

| 环境 / 软件 | 当前处理方式与边界 |
|---|---|
| CentOS 7 | Trivy 有系统包支持，但其公告参考 RHEL，修复版本不保证在 CentOS 仓库可用；系统已结束常规维护，结果不能代表仍有完整持续更新的覆盖。需要真实 RPM 数据联调。 |
| 麒麟 | 当前未适配发行版漏洞源。rootfs 明确失败，不使用 `ID_LIKE=centos/rhel` 替换厂商判定；应用依赖可以单独检查。需明确产品线、版本、CPU 架构后接厂商公告。 |
| Tomcat、Kafka、ZooKeeper、Nacos 与 Java 应用 | 采集明确目录内 JAR/WAR/EAR，以 Java 组件漏洞检查为主；先 `make engines-java` 准备索引。不表示已覆盖全部安装版本、配置、权限与业务漏洞。 |
| Go / Node.js | 每个 Go ELF 用独立 `--app 名称=/path/to/elf` 显式选择，目录输入只选已知依赖清单与 Java 归档；Node.js 以 lock 文件记录的安装版本为依据。仅源码目录或无版本清单不能认为覆盖完整。 |
| Nginx、RabbitMQ、MySQL、PostgreSQL | 系统包或镜像中受支持的软件包由其对应公告源检查；源码安装、独立压缩包、第三方 RPM 及运行配置需要分别适配与核对，当前不宣称产品级完整覆盖。 |
| 国产数据库 | 需要具体产品和版本以选择厂商公告/版本判定，当前未实现通用国产数据库漏洞检测。 |
| Kubernetes 管理的 Docker / containerd | 已选镜像归档的离线分析；挂载应用与 Linux 宿主机分开采集。没有集群自动发现或 Kubernetes 配置审计。 |

官方覆盖依据：[Trivy 支持的 OS](https://trivy.dev/latest/docs/coverage/os/)、[CentOS 公告来源说明](https://trivy.dev/docs/latest/coverage/os/centos/)。麒麟与国产数据库是待适配项，不得通过伪造发行版或缺失结果来标记“检查通过”。

模式依据：[Trivy rootfs](https://trivy.dev/docs/latest/target/rootfs/)、[Trivy filesystem](https://trivy.dev/docs/latest/guide/target/filesystem/)。本机测试使用合成 Linux 包数据库和自制镜像归档；真实服务器、具体中间件覆盖仍需由你选定目标后验证。

## 本地回归

```bash
make test                # 含采集工具的纯本地夹具测试
make verify-flags        # 核对固定引擎，包括 rootfs 参数；不扫描
make test-engines-local  # 自建回环服务、合成 Linux 包数据库/依赖/镜像
```
