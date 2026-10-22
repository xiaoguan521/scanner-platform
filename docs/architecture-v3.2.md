# 企业安全漏洞扫描平台:架构设计与实施方案(V3.2)

> 本版整合了 V3.0 / V3.1 与前几轮评审意见,并纳入运维提出的三项生产要求。
> 标记 **【待核对】** 的内容表示尚未在官方文档或实测中确认,编码前必须验证。
> 2026-10-19 报告能力修订:用户明确授权的目标内允许自动端口发现、受限服务识别和只读漏洞检查;不要求开放端口逐项再审批。端口范围支持常见、自定义、已登记和全端口(二次确认),单任务最多 65535 个 TCP 端口,有界并发不超过 64。排除端口和隔离端口不产生任何连接。具体口径见 `report-capability-plan.md`。
> 2026-10-20 补充并替代 2026-10-19 的资产可达性约定:新增/编辑表单可测试当前填写的单个数字 IP,不保存测试结果;Server 启动后立即对清册中已登记的主机发送一次 ICMP echo,之后每轮完成后等待 60 秒再开始下一轮。每次只探测清册中的数字 IP,超时 2.5 秒;无响应仅表示未收到 ICMP 响应,不等于主机离线,也不得跳过 TCP 检测。清册自动刷新状态,不要求用户手动重测。修改资产 IP 会撤销原授权范围并清除旧可达性结果。

---

## 0. 修订摘要(相对 V3.1)

| 类别 | 主要调整 |
|---|---|
| 数据模型 | 指纹只取稳定字段;`FIXED` 增加严格判定条件;补充资产、端口范围、端口隔离、审计、节点、规则包等缺失表 |
| 围栏 | 端口纳入显式授权与网络白名单;基础设施白名单精确到 IP:端口;增加失联自终止与本地硬截止时间 |
| 调度 | 任务按目标分块,块间检查时间窗;不再依赖中途强杀进程 |
| 规则包 | 增加防回滚、私钥保管与轮换要求 |
| Harbor | 默认推荐复用 Harbor 内置 Trivy,自研扫描作为备选;补充容量测算与待核实项 |
| 路线图 | 便携版骨架前移到 MVP;工期改为"待 PoC 修正的估算" |

---

## 1. 目标、范围与原则

### 1.1 需求

- 多端可用(Web 控制台、CLI、便携离线版)。
- 可定时执行,且遵守允许扫描的时间窗。
- 支持在线与离线两种运行方式。
- 支持 AI 辅助研判(后期阶段,见第 11 章)。
- 以成熟开源引擎为内核,逐步定制成公司专属产品。

### 1.2 运维提出的三项硬性要求

1. **漏洞扫描范围必须明确输入并严格遵守**:仅扫描用户明确输入并授权的目标,允许按选定端口策略自动发现服务并执行只读检查;不得发现或扫描其他主机、相邻网段或 CIDR。
2. **目标服务器可能部署 nginx 四层(stream)代理**,已知转发端口必须排除。TCP 连接探测本身也可能触发上游连接,不确定配置时应先向运维确认。
3. **公司 Harbor 每天上传大量镜像**,Trivy 扫描耗时可能很长,必须有可控的吞吐方案。

### 1.3 架构原则

1. **引擎与规则库分离**:引擎低频升级,规则和漏洞库高频热更新,更新不重启容器。
2. **三权分立**:控制面(唯一连库)、更新器(唯一写规则盘)、执行器(处理不可信目标,零数据库凭据)。
3. **默认安全**:不扫描未输入目标,排除与隔离优先;攻击、凭据尝试和默认口令模板不启用。
4. **同源构建**:一套 Go 代码,既能部署为集群,也能编译为单进程便携版。

### 1.4 非目标(MVP 不做)

SAST、密钥扫描、重型 DAST 爬虫、AI 自动研判、任何自动利用类能力。

---

## 2. 路线图

> 工期为估算,假设 3–5 人团队,以 PoC 结果为准重新评估。

| 阶段 | 估算周期 | 内容 | 退出标准 |
|---|---|---|---|
| **Phase 0:PoC** | 约 2 周 | 完成第 12 章的 6 项验证 | 6 项 PoC 全部达到验收标准 |
| **Phase 1:MVP** | 约 2–3 个月 | 资产与授权范围、Nuclei + Trivy、归一化去重入库、漏洞生命周期、时间窗调度、规则包与离线导入、Server/Updater/Worker 三权分立;**存储抽象层与"嵌入式单进程"骨架** | 可在真实内网资产和一批 Harbor 样本上稳定运行 |
| **Phase 2:扩展** | 约 2 个月 | 便携版打包与跨平台发布、ZAP sidecar、按需接入 Gitleaks 和 Semgrep(仅自研规则)、报表与看板 | 便携版在目标终端通过 EDR 与签名验证 |
| **Phase 3:智能** | 约 2 个月 | AI 研判与修复建议、工单闭环 | AI 在评测集上显著降低误报,数据外发策略已审批 |

---

## 3. 组件选型与许可证

### 3.1 选型决定

| 类别 | 选择 | 说明 |
|---|---|---|
| 扫描引擎 | Nuclei、Trivy(MVP);ZAP、Semgrep、Gitleaks(后期) | 均以子进程方式调用,统一输出归一化 JSON |
| 控制面 | Go + PostgreSQL | 任务队列使用 `SELECT ... FOR UPDATE SKIP LOCKED`,中心端不引入 Redis |
| 离线版存储 | SQLite(纯 Go 驱动) | 通过 `Repository` 接口与 PostgreSQL 共用一套业务代码 |
| 前端 | 静态单页应用,可 `go:embed` | Next.js、Vue、React 均可,按团队熟悉程度选;离线版不得依赖 CDN 与外部字体 |
| 资产接入 | 标准 CSV/JSON 导入 + 通用 Webhook API | 不集成 ScopeSentry |

### 3.2 明确不采用

- **ARTEX 及其分支**:涉及真实攻击事件,上游已闭源,副本来源不明,AGPL-3.0。
- **ScopeSentry**:技术栈异构(Python + MongoDB + Redis),与自研控制面功能重叠;其 README 声明公司和营利实体使用、分发或修改前需取得商业授权(此信息来自一个 fork 页面,需核对上游 LICENSE)。除非法务确认并取得授权,不部署、不依赖。

### 3.3 许可证核查表

> 本表**不是法律意见**。仅 Semgrep 规则库一行已在官方文档中核实,其余请法务对照各仓库最新 LICENSE 逐项确认。

| 组件 | 许可证(待法务确认) | 核实状态 | 备注 |
|---|---|---|---|
| Nuclei 引擎、nuclei-templates | MIT | 待核对 | |
| Trivy 引擎 | Apache-2.0 | 待核对 | |
| trivy-db / trivy-java-db | 含多源数据 | 待核对 | 对外分发前核查上游公告源条款 |
| OWASP ZAP | Apache-2.0 | 待核对 | 第三方插件许可证需逐个筛选 |
| Semgrep 引擎 | LGPL-2.1 | 已核实 | |
| Semgrep 官方规则库 | Semgrep Rules License v1.0 | 已核实 | 仅限内部业务使用,不得分发或以服务形式提供给他人;后期只用自研规则 |

---

## 4. 总体架构

### 4.1 组件与权限

| 组件 | 职责 | 数据库凭据 | 规则目录 | 网络 |
|---|---|---|---|---|
| `sec-server` | Web UI、任务调度、节点 API、结果入库、租约登记 | **唯一持有** | 无 | 控制网络 + 执行网络 |
| `sec-updater` | 拉取并验签规则包、切换 `CURRENT`、回收旧版本 | 无 | **读写** | 执行网络 |
| `sec-worker` | 领取任务、执行扫描、回传结果 | 无 | **只读**(+ 自己的私有可写运行目录) | 执行网络 |
| PostgreSQL | 业务存储、任务队列 | — | — | 仅控制网络 |

### 4.2 通信与凭据

- Web UI 与节点 API 使用**两个独立监听端口**。节点 API 不发布到宿主机。
- 节点与 Server 通信必须使用 TLS;多主机部署时使用 mTLS 或每节点独立令牌(可吊销)。
- 令牌通过 Docker secrets 或文件挂载传入,不放在环境变量里。
- Worker 横向扩容时,每个副本拥有独立令牌和独立私有 runtime 目录(用脚本生成,避免手工复制)。

节点材料分发采用角色最小权限包。完整离线材料只能留在受信部署机；Server 包含 CA 证书、Server 证书/私钥和节点令牌注册表，Worker/Updater 包只包含 CA 证书、对应节点的客户端证书/私钥和令牌。`sec-node-provision` 在拆包前重新验证完整材料，使用版本化 manifest 和目录级原子发布；传输后的 `--verify-dir` 按角色执行精确文件集、证书用途、节点身份和 owner-only 权限校验。`sec-node-deploy` 默认只生成计划，显式执行时才允许对用户指定的数字 IP 通过固定 known-hosts 的 SSH/SCP 完成暂存、远端预检、首次目录发布和固定服务重启；显式 `--rotate-existing` 才能替换现有目录，过程先保留唯一回滚目录，重启失败时按固定步骤恢复旧目录并重启服务，成功后才删除回滚目录。不做主机发现，不接受域名/CIDR，不自动登记节点或变更令牌。

### 4.3 进程权限

- Worker 入口为 supervisor(root,仅用于设置网络围栏),设置完成后以 `uid=10001`、无任何 capabilities 的身份拉起 `nuclei` / `trivy`。
- 引擎的 HOME、配置、缓存、恢复文件全部指向该 Worker 的 `/runtime` 下,保证规则目录只读时引擎仍能正常运行。

---

## 5. 规则库与引擎管理

### 5.1 引擎版本与内容版本分离

- 引擎镜像或二进制:固定版本号,按季度评估升级,不使用 `latest`。
- 内容包(漏洞库 + 模板):按日或按周更新,独立版本号。
- 引擎自带的联网更新全部关闭,统一由 Updater 控制。

### 5.2 三段式发布流水线

1. **Staging**:拉取上游内容,生成与上一版本的差异清单,按协议类型和标签清理高风险模板,执行 `nuclei -validate`。
2. **Canary**:在固定内部靶场上做冒烟扫描,对比耗时、退出码、基准漏洞检出数。
3. **Stable**:生成 `manifest.json` 并签名,推送到内网制品库。**上游变更不自动进入 Stable,需要人工审核差异后晋级。**

### 5.3 内容包目录与 `CURRENT` 指针

使用纯文本 `CURRENT` 指针文件(而非符号链接),在 Linux、macOS、Windows 上行为一致,并避开 bind mount 提前解析软链接的问题。

```text
/var/lib/sec-agent/vuln-data/          # 本地 SSD,不使用 NFS
├── CURRENT                            # 一行文本:当前版本号
├── staging/                           # 下载与验签临时区
├── .trash/                            # 两阶段删除隔离区
└── releases/
    └── 20261016.01/
        ├── manifest.json
        ├── manifest.json.sig
        ├── trivy-db/                  # trivy.db + metadata.json (+ java-db 或占位库)
        └── nuclei-templates/
            ├── official/
            └── custom/                # 公司自研模板
```

切换方式:写临时文件 → `fsync` → `rename` 覆盖 `CURRENT`。Windows 上 rename 覆盖可能因文件被占用失败,需要带重试。

### 5.4 manifest 规范

```json
{
  "bundle_version": "20261016.01",
  "channel": "stable",
  "created_at": "2026-10-16T02:00:00Z",
  "bundle_type": "core",
  "engine_compatibility": {
    "trivy": { "min": "0.76.0", "max": "0.76.0",
               "db_schema": 2, "java_db_schema": 1 },
    "nuclei": { "min": "3.11.1", "max": "3.11.1" }
  },
  "files": { "<相对路径>": "sha256:<哈希>" }
}
```

> 当前锁定版本的范围由 CI 和本地引擎回归实测后填入。没有兼容矩阵的历史包可以只读展示,但不能普通激活或交给 Worker 执行。

### 5.5 签名与防回滚

- 使用 Ed25519 对 `manifest.json` 原始字节签名,签名文件为同目录下的 `manifest.json.sig`;下载包的 `SHA256SUMS` 也覆盖该签名文件。
- 当前漏洞库准备工作流只允许在 `main` 运行,使用 GitHub Environment `vulnerability-data-signing` 中的 `BUNDLE_SIGNING_PRIVATE_KEY_PEM` 私钥和 `BUNDLE_SIGNING_PUBLIC_KEY_PEM` 公钥。Environment 应限制可部署分支并配置审批保护;工作流在临时目录中使用密钥,校验密钥类型及公私钥匹配,验签成功后才打包。
- Updater 通过可重复的 `--trusted-rule-public-key` 从规则根目录外的普通 PEM 文件加载 1–3 把受信 Ed25519 公钥,对 manifest 原始字节和独立的 64 字节 `manifest.json.sig` 验签后再校验内容。密钥轮换时同时配置退役与下一把公钥,任一把验签通过即可;重复密钥、超过上限、缺少受信公钥或有效签名时拒绝执行。已安装历史无签名版本可只读展示,`signatureVerified` 为 false。Worker 当前仍只复核固定版本的文件完整性,不因签名文件存在就声明验签成功。
- `--prepare-engines` 是显式的本机数据准备操作,可通过同一 Manager 实例刚完成准备时登记的一次性记录激活本地生成版本;记录绑定规则根、版本和 manifest 哈希,失败/重启不能继承,外部导入不能取得该记录。该入口不表示本地包经过签名认证,也不向普通激活开放跳过验签的选项。
- 网页 multipart 导入继续限制为 256 MiB,避免把大包写入 Server 的 SQLite BLOB 并通过节点 API 复制。已签名的大包由 Updater 通过本地文件导入或 HTTPS Fetch 流式落到私有临时文件,上限 2 GiB,然后复用同一 manifest 签名、文件哈希、路径和防回滚校验;失败或取消不切换 `CURRENT`。
- 定期轮换签名密钥;更换密钥时,先把退役与下一把公钥同时配置到 Updater,确认新包已切换后再移除旧信任。Updater 只在启动时加载外部公钥并复制到进程内,不会从规则包取得信任;最多保留 3 把重叠公钥,不能直接删除仍用于回滚的旧信任。规则包激活前还必须通过清单中的引擎版本范围和 Trivy 数据库 schema 校验;不兼容包不能激活。
- **拒绝版本号低于当前的包**,除非通过显式的"回滚"操作并留审计记录。

### 5.6 版本租约与垃圾回收

**租约(Server 侧登记)**
1. Worker 读取本地 `CURRENT`,领取任务时上报 `local_rule_version`。
2. Server 记录 `pinned_rule_version`、`worker_node_id`、`lease_expires_at`。
3. Worker 每 60 秒续约,并把真实版本目录的绝对路径传给引擎子进程。
4. **失联自终止**:Worker 连续续约失败超过租约时长,必须主动终止扫描,避免任务被重新分配后出现重复扫描,或版本目录被回收。

**回收规则(两阶段、带宽限期)**
一个旧版本同时满足以下条件才可回收:
1. 不是 `CURRENT`,且不是最近一个备用回滚版本。
2. 退役时间超过宽限期(默认 2 小时)。新任务只会绑定 `CURRENT`,退役后不会再产生新租约。
3. Updater 向 Server 查询:**本节点上**没有任何 `RUNNING` 任务绑定该版本(多主机部署时按节点查询)。

满足后先 `rename` 到 `.trash/`,再次复查,最后删除。

**首次启动**:没有 `CURRENT` 时,Worker 上报 `WAITING_FOR_RULES` 并退避等待,不报错退出。

### 5.6.1 Trivy 只读库与可写缓存

- 可写缓存目录:`/runtime/trivy-cache-v<引擎版本>/`(缓存键含引擎版本)。
- 每个内容版本**只复制一次**漏洞库到该缓存的 `db/`(跨挂载点无法使用硬链接),并写 `.synced_version` 标记。
- 轻量包中预置合法的 Java 库占位,避免离线生成 SBOM 时报错【待核对:新版本行为是否仍如此】。

---

## 6. 运维三项要求的落地方案

### 6.1 范围严格锁死

**输入层**
- 漏洞扫描接受用户明确输入并授权的目标;自动流程由 Server 将目标和端口策略固定为精确数字 IP 与端口集合,只对范围内开放且未排除的端口执行只读检查。
- 单台主机端口探测由 Server 根据资产 ID 固定数字 IP,只对该 IP 执行常见、自定义、已登记或全端口策略;全端口必须二次确认并审计。单任务最多 65535 个 TCP 端口,Worker 最多并发连接 64 个端口。系统、资产、任务排除取并集,隔离端口同样跳过。独立 TCP 探测只记录开放端口;自动扫描可继续受限协议识别和只读漏洞检测,不尝试登录。
- 去掉相邻网段发现、ARP 探测、子域名泛解析等一切自动扩展模块。
- 当前资产输入只接受数字 IP,不接受域名或 CIDR。Worker 不展开网段、不解析域名;漏洞扫描任务只拿已校验的"IP:端口"清单,端口探测任务只拿 Server 绑定资产后的单个数字 IP 和固定端口清单。

**引擎层**
- 重定向只允许同主机(`-fhr`)。
- **不得使用 `-restrict-local-network-access`**:它会阻止连接私有网络,导致内网目标本身被拦截。
- 内网扫描使用 `-ni` 关闭 OAST,或自建内网 interactsh 并用 `-iserver` 指向它(见 6.1.1)。

**网络层(执行时强制)**
- **每个 Worker 同一时刻只跑一个任务**,横向扩容靠增加副本,避免同一网络命名空间内多个任务的规则互相覆盖。
- supervisor 先设置出站默认 `DROP`,仅放行:回环、Server 节点 API(IP:端口)、内网 DNS、Harbor、制品库(均为**精确 IP:端口**,不放行整个网段)、本任务目标。端口探测任务的目标只能是 Server 解析的那一台数字 IP,端口只能是经过 Server 校验的清单。
- 规则生效后降权为 `uid=10001` 且清空 capabilities 再拉起引擎,被攻陷的引擎无法修改规则。
- 任务进程及其后代加入专用 cgroup v2;取消、硬截止时间或租约失联时使用内核 `cgroup.kill` 清理整个任务树,不得退化为仅杀单个 PID。
- 记录被 `DROP` 的数据包计数或日志,出现范围外连接尝试时告警。

**便携版(无防火墙权限)**:在应用层做范围校验,直接把具体 IP 传给引擎,并配合同主机重定向限制;范围检查与端口清单校验必须在 Go 层强制执行。

**事后对账**:比对任务实际连接的目标与授权清单,范围外的发现项丢弃并告警。

#### 6.1.1 关于 OAST

`-ni` 会同时排除依赖 OAST 的模板,盲注、盲 SSRF 类检测的覆盖率会下降。若覆盖率重要,在内网自建 interactsh,否则接受这一取舍并在产品中注明。

### 6.2 Nginx 四层代理防穿透

**主控手段:显式授权**
1. **授权目标和端口策略**:范围内自动发现的开放端口可进入受限只读检查,无需逐端口再审批;必须应用排除并在执行前复核。旧端口申请记录继续保留为行政台账。
2. **探测有界且排除优先**:仅连接已输入的单台数字 IP,按强度限制速率、并发与超时,每端口服务识别最多 3 次;独立探测仅 TCP connect,自动流程可读取有限协议响应。疑似转发写隔离记录,本任务停止后续 Web 检查,后续任务跳过直到人工解除。
3. **端口分类**:`WEB`(可跑 Web 模板)、`NON_WEB`(仅做协议指纹)、`EXCLUDED_PROXY`(已知四层转发端口,永久跳过)。
4. **隔离记录持久化**:扫描中被判定为"疑似四层转发"的端口,写入 `port_quarantine` 表,后续任务一律跳过,直到人工复核解除。
5. **请求预算**:每个"主机:端口"设置请求总数与速率上限,不只依赖出错熔断。
6. **指纹先行**:先识别服务类型再选对应模板,不对每个端口跑全部模板【待核对:Nuclei 自动按技术指纹选模板的参数】。
7. **熔断**:`-mhe` 在连续出错后跳过该主机(默认阈值为 30,可调小)。

**辅助手段**:时延探针只对 `WEB` 类端口启用,阈值可配置,且不作为唯一判断依据(慢启动应用会被误判)。

### 6.3 Harbor 大量镜像

**默认推荐:复用 Harbor 内置 Trivy(模式 A)**
- Harbor 自带 Trivy 作为默认扫描器,支持推送即扫和定时扫描全部镜像,并支持扫描完成事件的 Webhook。
- 平台通过 Webhook 与 API 拉取扫描报告,负责聚合、去重、生命周期、SLA 与 AI 研判。
- **待核对**:Webhook 事件名、报告 API 路径、仓库名含斜杠时的编码方式、SBOM 能力,均以所用 Harbor 版本的 Swagger 文档为准。
- **治理缺口**:Harbor 内置 Trivy 的漏洞库更新来源(在线或内网镜像)不在本平台的规则发布流水线内,需要单独明确。

**备选:自建 Worker 扫描(模式 B)**,适用于需要统一纳管多镜像源、统一规则版本、定制离线库的场景。

| 手段 | 说明 |
|---|---|
| 摘要去重 | 去重键 = `平台摘要 + 规则版本 + 引擎版本`;多架构镜像按各平台摘要分别处理 |
| 层缓存 | 持久化 Trivy 层缓存,仅分析新增层;缓存键含引擎版本;每个 Worker 私有缓存,命中率随 Worker 数下降,可按项目或基础镜像做粘性分配 |
| 精简扫描 | 先只做漏洞扫描(`--scanners vuln`),生产或高风险项目再加深度检查【待核对:参数与提速幅度需实测】 |
| SBOM 复扫 | 首扫生成 CycloneDX SBOM,压缩后存对象存储(数据库只存路径和哈希);规则更新后用 SBOM 本地复扫,不再拉镜像 |
| 队列 | 优先级:新推送 > 每日重扫;限制并发保护 Harbor;设置超时与重试 |

**容量测算(必做)**:取一天真实镜像样本,测单镜像耗时的中位数与 P95 及并发扩展曲线,再用 `每日镜像数 × 平均耗时 ÷ 并发数` 估算所需 Worker 数。

---

## 7. 数据模型

> 使用与 SQLite 兼容的类型(JSON 以 TEXT 存储)。以下为核心表,字段可在详细设计时扩展。

```sql
-- 组织与权限
CREATE TABLE users (
  id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
  role TEXT NOT NULL,                 -- admin / security_engineer / ops_approver / viewer
  is_active BOOLEAN DEFAULT TRUE
);

-- 资产与业务组(看板的"TOP5 风险业务组"依赖于此)
CREATE TABLE assets (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,                 -- host / image_repo
  address TEXT NOT NULL,              -- IP、域名(已解析并固定的 IP 另存)或镜像仓库
  resolved_ip TEXT,
  business_group TEXT, owner TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 资产的登记端口与分类(自动发现可补充;排除优先)
CREATE TABLE asset_ports (
  asset_id TEXT NOT NULL REFERENCES assets(id),
  port INTEGER NOT NULL,
  kind TEXT NOT NULL,                 -- WEB / NON_WEB / EXCLUDED_PROXY
  source TEXT,                        -- 台账导入 / 人工登记
  PRIMARY KEY (asset_id, port)
);

-- 被判定为疑似四层转发的端口(后续任务跳过,人工复核后解除)
CREATE TABLE port_quarantine (
  asset_id TEXT NOT NULL, port INTEGER NOT NULL,
  reason TEXT NOT NULL, detected_at TIMESTAMP NOT NULL,
  status TEXT NOT NULL DEFAULT 'ACTIVE',   -- ACTIVE / RELEASED
  reviewed_by TEXT, reviewed_at TIMESTAMP,
  PRIMARY KEY (asset_id, port)
);

-- 扫描授权范围与审批
CREATE TABLE authorized_scopes (
  id TEXT PRIMARY KEY,
  cidr_or_host TEXT NOT NULL,
  max_targets INTEGER NOT NULL,       -- CIDR 规模上限
  time_windows TEXT NOT NULL,         -- JSON:星期、起止时间、时区;明确跨午夜语义
  approved_by TEXT NOT NULL, approval_ticket TEXT NOT NULL,
  expires_at TIMESTAMP,               -- 授权到期
  is_active BOOLEAN DEFAULT TRUE
);

-- 节点与令牌
CREATE TABLE nodes (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL,   -- worker / updater
  host_id TEXT NOT NULL,                     -- 多主机部署时按主机回收规则版本
  token_hash TEXT NOT NULL, revoked_at TIMESTAMP,
  last_heartbeat TIMESTAMP
);

-- 规则包版本
CREATE TABLE rule_bundles (
  version TEXT PRIMARY KEY, channel TEXT NOT NULL,
  manifest_sha256 TEXT NOT NULL, published_at TIMESTAMP NOT NULL
);

-- 扫描任务与分块
CREATE TABLE scan_tasks (
  id TEXT PRIMARY KEY,
  scope_id TEXT NOT NULL REFERENCES authorized_scopes(id),
  engines TEXT NOT NULL,              -- JSON 数组
  status TEXT NOT NULL DEFAULT 'PENDING',
  -- PENDING / WAITING_WINDOW / RUNNING / PAUSED_WINDOW / COMPLETED / FAILED / CANCELED
  archived_at TIMESTAMP,               -- 归档后从默认任务清册隐藏,可恢复
  hard_deadline TIMESTAMP,            -- 下发给 Worker 的本地强制截止时间
  created_by TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE scan_task_chunks (
  id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES scan_tasks(id),
  targets TEXT NOT NULL,              -- JSON:已校验的"IP:端口"清单
  status TEXT NOT NULL DEFAULT 'PENDING',
  worker_node_id TEXT, pinned_rule_version TEXT,
  lease_expires_at TIMESTAMP,
  completed_fully BOOLEAN DEFAULT FALSE,     -- 是否完整完成(无中断、无熔断跳过、无超时)
  started_at TIMESTAMP, finished_at TIMESTAMP
);
CREATE INDEX idx_chunks_poll ON scan_task_chunks(status, lease_expires_at);

-- 发现项(指纹只含稳定字段)
CREATE TABLE security_findings (
  id TEXT PRIMARY KEY,
  asset_id TEXT NOT NULL REFERENCES assets(id),
  fingerprint_hash TEXT NOT NULL,
  -- Nuclei: sha256(资产 | 端口 | 引擎 | 模板ID | 规范化匹配路径)
  -- Trivy : sha256(镜像摘要或主机 | 软件包名 | 已安装版本 | 漏洞ID)
  -- 请求/响应、时间戳、横幅等易变证据不参与哈希
  engine_name TEXT NOT NULL, rule_id TEXT NOT NULL,
  severity TEXT NOT NULL, title TEXT NOT NULL, location TEXT NOT NULL,
  evidence_json TEXT NOT NULL,        -- 证据另存,可随扫描更新
  lifecycle_status TEXT NOT NULL DEFAULT 'OPEN',
  accepted_until TIMESTAMP,           -- ACCEPTED_RISK 到期复审
  sla_deadline TIMESTAMP,
  first_seen_task_id TEXT NOT NULL, last_seen_task_id TEXT NOT NULL,
  first_seen_at TIMESTAMP, last_seen_at TIMESTAMP, resolved_at TIMESTAMP,
  UNIQUE (asset_id, fingerprint_hash)
);

-- 状态流转历史
CREATE TABLE finding_events (
  id TEXT PRIMARY KEY, finding_id TEXT NOT NULL,
  from_status TEXT, to_status TEXT NOT NULL,
  actor TEXT, reason TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 镜像摘要与 SBOM 索引
CREATE TABLE artifact_sboms (
  manifest_digest TEXT NOT NULL, rule_version TEXT NOT NULL, engine_version TEXT NOT NULL,
  repo_name TEXT NOT NULL, sbom_uri TEXT NOT NULL, sbom_sha256 TEXT NOT NULL,
  scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (manifest_digest, rule_version, engine_version)
);

-- 审计日志(谁批准了什么、谁发起了什么、AI 做了什么)
CREATE TABLE audit_logs (
  id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL,
  object_type TEXT, object_id TEXT, detail TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 7.1 漏洞生命周期规则

状态:`OPEN`(新增)、`REOPENED`(复现)、`IN_PROGRESS`(修复中)、`FIXED`(已修复)、`FALSE_POSITIVE`(误报)、`ACCEPTED_RISK`(接受风险)。

**转为 `FIXED` 必须同时满足:**
1. 对该资产的相关范围,本次扫描**完整完成**(`completed_fully = true`,没有中断、熔断跳过、超时)。
2. 检出该问题的规则在本次规则版本中**仍然存在且确实执行过**(模板被删除或被排除,不能算修复)。
3. 连续未检出次数达到配置阈值(默认 1 次,可调整)。

否则保持 `OPEN`,并标记"本次未验证"。

其他规则:
- 已 `FIXED` 的问题再次检出 → `REOPENED`。
- `FALSE_POSITIVE` 按"资产 + 指纹"静默;规则级别的屏蔽另行配置。
- `ACCEPTED_RISK` 到期后自动回到 `OPEN` 并通知复审。

---

## 8. 调度与时间窗

1. **准入**:任务创建时校验授权范围、目标在授权清单内、端口已登记,不在允许时间窗则置 `WAITING_WINDOW`。
2. **分块**:任务按目标拆成多个块,Worker 每次领取一个块。**块与块之间检查时间窗**,到点自然暂停(`PAUSED_WINDOW`),次日继续,不依赖中途强杀进程。
3. **硬截止**:每个任务块下发 `hard_deadline`(时间窗结束与最大运行时长取较早者),由 Worker **本地**强制结束,不依赖 Server 心跳,Server 不可达时同样生效。
4. **时区**:时间窗必须带时区,并明确跨午夜(如 23:00–05:00)的语义。
5. **定时**:Server 内置 cron 调度,到点生成任务,遵守上述准入规则。
6. **任务清理**:终态任务可归档并恢复;归档任务不出现在默认任务清册,但扫描记录仍保留。管理员仅可彻底删除已结束且没有关联发现项的任务;删除动作留审计日志,已生成的冻结报告快照不随任务删除。
7. **执行进度**:Worker 可在现有心跳中上报 `tcp_probe`、`service_identification`、`http_scan`、`ssh_collection`、`trivy_scan`、`application_scan` 或单引擎 `engine_scan` 的完成数/总数;Server 仅接受当前运行任务所属 Worker 的单调计数。TCP 总数必须等于 Server 冻结下发的端口数;自动任务的服务识别/HTTP 总数不得超过该端口数,SSH/Trivy 为单步,应用分析受有界输入数限制。进度单独存储并作为只读 UI 遥测,不改变授权范围、扫描结果或任务状态。UI 按阶段权重显示可解释的完成比例,不得按耗时估算百分比;旧 Worker 未上报进度时 UI 显示不确定状态。

---

## 9. 便携离线版

**形态**:单个 Go 主程序,内嵌静态 Web UI,内部以进程内方式串联 Server、Updater、Worker,存储使用 SQLite,仅监听 `127.0.0.1`。

```text
sec-portable/
├── sec-platform(.exe)
├── bin/            # 随包附带的 nuclei、trivy(对应平台)
├── vuln-data/      # 与集群版相同的目录结构
│   ├── CURRENT
│   └── releases/
└── runtime/
    ├── local_data.db
    └── trivy-cache/
```

**要求与风险**
- 范围围栏在应用层强制执行(见 6.1)。
- 离线规则包导入:内置验签、防回滚、原子切换 `CURRENT`。
- **杀毒软件与企业 EDR** 常会误判扫描器二进制和 POC 模板,必须在目标环境尽早测试。
- Windows 与 macOS 需要代码签名与公证,否则分发时会被系统拦截。
- Windows 上 rename 覆盖正在被读取的文件可能失败,需要重试。

---

## 10. 部署契约(Docker Compose)

仓库提供 `deploy/Dockerfile` 的 Server、Worker、Updater 三个 BuildKit
目标，以及 `deploy/compose.production.yaml` 的生产部署契约。Compose
不包含 `build:`，所有服务镜像必须由发布流程生成并固定为
`@sha256:...`；凭据、证书、令牌、DSN 和规则公钥只能通过
`deploy/secrets/` 的 owner-managed 文件挂载。`deploy/README.md` 记录镜像
构建、秘密文件和门禁顺序。该文件可以作为真实部署输入，但不能替代
隔离 Linux 的 namespace、cgroup、DROP 计数和范围外抓包验收。

启动前先完成静态门禁和秘密文件预检；实际启动由部署环境执行：

```text
set -a; . ./deploy/production.env; set +a
DEPLOY_COMPOSE_FILE=deploy/compose.production.yaml make verify-deploy
docker compose --env-file deploy/production.env \\
  -f deploy/compose.production.yaml up -d
```

> 二期的 ZAP sidecar 通过独立 profile 启用,且必须强制设置 API Key。

部署文件在进入隔离 Linux 验收前必须通过仓库的静态安全门禁：
`DEPLOY_COMPOSE_FILE=/path/to/compose.yaml make verify-deploy`。门禁使用
`docker compose config --format json` 规范化候选文件，检查服务角色、显式
命名网络、禁止 host namespace/privileged/危险 capabilities、secret 文件
引用、Server 回环端口、Worker/Updater/PostgreSQL 端口发布，以及 Worker
规则目录只读和私有 runtime 可写约束；每个服务还必须使用审批过的
`@sha256` 镜像，不能直接使用未固定的 tag 或 `build:` 上下文。它不替代实际 namespace、nftables、
cgroup、DROP 计数和范围外抓包验收；镜像 digest、证书 SAN、秘密文件和
Worker cgroup 挂载仍必须由部署环境按实际节点值复核。

---

## 11. 安全、合规与 AI

- **授权与审计**:每个授权范围需要审批人与工单号,带到期时间;所有任务创建、审批、令牌签发与吊销、AI 调用均写入审计日志。
- **RBAC**:至少区分管理员、安全工程师、运维审批人、只读用户。
- **攻击能力不提供**:不实现利用、写入、暴力破解、口令猜测或默认口令登录尝试;弱口令第一阶段显示未启用。
- **AI(Phase 3)**:
  - 用于误报研判、漏洞解读与修复建议、辅助生成模板,不做自主攻击。
  - 先建立评测集,量化对误报率的实际改善。
  - 明确哪些数据允许发送到云端模型,敏感场景强制使用本地模型;脱敏规则需先审批再实现。
- **规则与模板供应链**:上游更新经 Staging → Canary → Stable,人工审核差异后才晋级。

---

## 12. 立项前 PoC(约 2 周)

| # | 验证内容 | 验收标准 |
|---|---|---|
| 1 | **围栏与并发隔离**:supervisor 以 root 设置出站默认 DROP,仅放行精确 IP:端口,将任务树放入 cgroup v2 后再降权为 `uid=10001` 拉起引擎 | 引擎无法访问范围外地址;无法修改防火墙规则;DROP 计数能触发告警;取消或失联时 cgroup 后代全部终止 |
| 2 | **租约与 GC 压测**:长任务期间连续发布多个新版本并触发回收 | 被租约引用的版本不被回收;Worker 与 Server 失联后自终止;Windows 与 Linux 下 `CURRENT` 切换零报错 |
| 3 | **Trivy 只读库 + 私有可写缓存** | 无只读文件系统报错;无任何联网请求;第二个共享基础层的镜像命中缓存且耗时明显缩短;验证 Java 库占位行为 |
| 4 | **Nuclei 零外联**:全量模板 + 同主机重定向限制 + OAST 处理方案,抓包 | 抓包无任何公网 DNS 或 TCP 连接;内网靶机漏洞正常检出;引擎在只读规则目录下运行无写入失败 |
| 5 | **指纹稳定性与 FIXED 判定**:对同一靶机重复扫描,并制造中断和熔断 | 不重复入库;中断、熔断、超时不会误标 `FIXED` |
| 6 | **时间窗中止与恢复**:分块执行,到点本地强制停止并次日续跑 | 到点后 Worker 本地停止;恢复后结果完整,无重复或丢失 |

另有一项与 PoC 并行的准备工作:**取一天的 Harbor 镜像样本做耗时与吞吐实测**(见 6.3)。

---

## 13. 待决策与待核对清单

### 需要拍板

1. **ScopeSentry 去留**:法务确认授权条款前不部署、不依赖。
2. **Harbor 模式**:模式 A(复用 Harbor 内置 Trivy)或模式 B(自建 Worker 扫描),依据样本实测与统一规则的需求决定。
3. **OAST 策略**:关闭(`-ni`)或自建 interactsh。
4. **团队规模与工期**:确认人数后重新评估 Phase 1 周期。
5. **私钥保管与轮换方案**。

### 编码前必须核对

| 项目 | 状态 |
|---|---|
| Nuclei:`-code`(默认关闭)、`-ept`、`-etags`、`-validate`、`-fhr`、`-ni`、`-iserver`、`-mhe`(默认 30) | 已在官方 README 中确认 |
| Nuclei:`-lna`(会阻止私网连接,**不要使用**) | 已确认 |
| ZAP:`-silent` | 已在官方文档中确认 |
| Nuclei:`-rl`、`-c`、`-duc`;`-etags` 中的 `brute-force` 等标签名是否存在于所用模板库 | 待核对 |
| Trivy:`--skip-db-update`、`--skip-java-db-update` | 参数存在已有间接依据,仍需在锁定版本上跑 `--help` 确认 |
| Trivy:`--skip-check-update`、`--offline-scan`、`--scanners` | 待核对(CI 中自动校验) |
| Trivy 离线时对 Java 库的依赖行为(旧 issue 显示跳过更新而本地无库会报错) | 待实测 |
| Harbor Webhook 事件名、API 路径、SBOM 能力 | 待核对所用 Harbor 版本 |
| Nuclei 按技术指纹自动选模板的参数 | 待核对 |
| 各开源组件许可证(Semgrep 规则库除外) | 待法务核对 |

### 2026-10-19 报告与资产画像数据扩展

资产画像、服务、登录入口、可达性、策略、知识库、任务观察和报告数据采用独立表及 TEXT JSON,与 SQLite 可移植结构一致。PostgreSQL 新增迁移 `0004_report_inventory.sql` 和后续资产目录、任务投影、发现项投影、规则目录、规则作业、定时任务、通知与产品目录迁移,不改已应用的迁移。SQLite 仍是默认便携模式；Server 可通过显式 `--storage postgres --postgres-dsn-file` 选择 PostgreSQL,并复用账号、资产、授权、核心任务队列、任务安全投影、发现项生命周期、报告作业、规则作业、定时任务、通知、系统设置、扫描策略、扫描方案、自定义规则和知识库适配。仍未实现的部分发现项处置和系统管理能力必须返回不可用,不得回退读取 SQLite。

发现项保留检测方式、置信度、CVSS、分类、外部编号和中文内容;版本匹配明确标记未原理验证。知识库只接受公开来源整理的规范 JSON,不自动接入 CNNVD/CNVD。报告在 Server 冻结快照后异步输出 HTML、Excel、Word、漏洞明细 CSV 和完整 JSON;生成过程不连接目标。登录入口独立计数,弱口令未启用不显示零项。详见 `product/report-usage.md` 与 `product/report-checklist.md`。

### 2026-10-20 SSH 指定部署目录应用采集

自动综合扫描支持 Worker 本地 SSH profile 中明确配置的应用目录，每台主机最多 8 个应用别名。目录必须是具体的绝对部署路径，不接受根目录、宽泛的系统父目录、伪文件系统或网络挂载入口；每项显式选择 Java 归档或 Go ELF 产物。仅当相同数字 IP 的 SSH 端口属于本次有效范围且探测开放时连接，不扩展主机、端口或目录。未配置应用时保持原有系统包流程。

采集脚本不执行目标应用、不登录容器、不安装软件。通过目录句柄和禁止符号链接的方式读取指定目录，限制深度、条目数、文件数及总大小；超限或快照变动则失败。每个选中文件使用独立输入目录与哈希清单，回传后校验清单、类型及大小，Go ELF 还需本地读取构建信息确认。Java 归档有解压预算约束。每项输入顺序调用本地 Trivy，只在返回相应语言类型的实际分析结果时记为已分析，零漏洞可以是成功结果；没有识别结果不能当作已分析。

任务保存固定枚举 `applicationScanStatus` 和每个别名的 `selectedCount` / `analyzedCount`，不保存远端部署路径。任何配置内的采集或分析失败都使该次应用阶段未完成并让任务失败；Worker、Server 保留覆盖计数和系统包阶段状态，失败任务不插入部分发现项。SSH 端口不在授权范围时明确标为未采集，HTTP 阶段可以按其原范围完成。旧 Worker 无应用字段的报告仍可读取，界面明确表示没有应用覆盖记录。Trivy 指纹继续以主机、包、安装版本、漏洞编号等稳定字段计算，不使用临时路径或应用别名。

该能力是指定产物的依赖版本分析，不涵盖任意安装路径、全部文件系统、主机配置审计或漏洞利用验证。详见 `ssh-collection.md` 与 `linux-server-scan.md`；本轮先做隔离单元测试，真实 SSH 与引擎验收另行执行。

### 2026-10-21 SSH 运行态服务只读画像

自动综合扫描的 SSH 系统采集在同一已登记且授权的数字 IP 上增加有界运行态线索：只读取 rootfs 中的 systemd `*.service` 单元名、`/etc/init.d` 脚本名和 `/proc/<pid>/comm` 进程名，归一化为最多 256 个 `name/manager/state` 条目。服务单元和 init 脚本标为 `installed`，进程名标为 `running`；不会读取 PID、命令行、参数、环境变量或服务文件内容，也不会连接新的主机或端口。Worker 对归档路径、JSON schema、枚举值、名称字符集、重复项和大小执行失败即关闭校验，结果复用现有 `asset_profiles` JSON，不新增表或迁移。该画像用于资产详情和报告提示，不等同于服务已启动、配置审计或漏洞验证。

### 2026-10-21 节点 mTLS、轮换与首阶段生命周期

独立节点监听继续强制 TLS 1.3 和每节点 Bearer 令牌；Server 可额外加载 owner 配置的客户端 CA，启用客户端证书校验。Worker/Updater 可分别配置服务端 CA 和客户端证书/私钥，私钥保持 owner-only 文件约束。Server 收到 `SIGHUP` 时原子重载节点证书、客户端 CA 和节点令牌注册表，替换文件解析失败保留上一份有效配置；客户端证书轮换通过重启对应节点完成。

节点生命周期首阶段已经落到 SQLite 与 PostgreSQL：管理员可登记预期节点、吊销节点；心跳会把已登记节点置为 `ONLINE`，超过十秒未上报则置为 `OFFLINE` 并生成一次离线事件，恢复心跳生成 `RECOVERED` 事件；离线事件进入平台内通知，登记/吊销动作进入审计。启用节点令牌注册表时，吊销状态在 Bearer 身份校验后拒绝所有 Worker/Updater 协议请求；未配置令牌注册表的本地兼容模式仍不提供可验证的节点身份。

节点令牌可由管理员在清册为已登记节点显式签发一次：Server 原子更新 owner-only 注册表并写入不含明文的审计记录，令牌只在签发响应中返回一次。对已有令牌的节点，管理员可显式执行轮换：Server 在同一锁内原子替换注册表、立即使旧令牌失效，写入 `rotate_node_credential` 审计动作，并只在响应中返回新令牌；审计和日志不保存明文。运维仍需把新令牌写入节点 owner-only 文件并发送 SIGHUP。自动签发证书、节点远程部署编排和客户端自动注册仍属于后续部署工作。节点清册提供管理员登记、生命周期状态/事件查看、签发/轮换令牌和吊销操作；节点注册接口只记录由管理员明确提交的节点元数据，不会自动发现主机或扩大扫描范围。

### 2026-10-21 一次性 Worker 生命周期监督

Linux fenced Worker 由可信 `sec-fence-launcher` 创建一次性 network namespace，并在一个任务结束后退出。`sec-worker-supervisor` 作为外部进程监督器，启动前校验 launcher 与 Worker 为绝对、规范、不可被 group/other 写入的普通可执行文件；Worker 参数必须位于显式 `--` 之后，监督器拒绝覆盖 `--fence`、`--once` 和父 namespace fd 等边界参数。监督器不使用 shell、不读取数据库或凭据；成功任务按固定延迟重新拉起，连续失败按有界指数退避，收到终止信号后取消当前周期且不重启。secret、证书、令牌下发、远程部署和自动证书签发仍由受信服务管理器/部署系统负责。

### 2026-10-21 围栏 DROP 计数回报

fenced Worker 子进程在围栏成功且计数读取完成后，将 `fenceStatus=ENFORCED` 与非负 `dropCount` 作为任务回报元数据发送；Server 只接受这两个受限字段，计数超过 JSON 安全整数范围或状态不匹配时拒绝回报。SQLite 任务详情与 PostgreSQL 任务安全投影保存最后一次任务计数；计数大于零时写入不含目标地址、请求/响应或凭据的 `fence_drop_observed` 审计事件，任务日志、详情和平台通知中心只显示静态脱敏告警。该链路不新增迁移，也不改变授权范围；真实范围外发包抓包、部署告警和 Compose 网络约束仍需隔离部署验收。
