# Worker 本机 SSH 采集

自动综合扫描可选用 SSH 对单台已登记 Linux 主机做一次性系统包采集。Server、API、SQLite 和扫描日志都不接收 SSH 密钥、Agent 内容或原始认证输出。Worker 使用系统 OpenSSH 客户端，将固定采集脚本通过 SSH 标准输入传到目标；脚本把发行版标识和系统包数据库整理成短期快照，快照经 SSH 输出到 Worker 后，目标机临时目录会被删除。不会安装常驻服务、修改软件包或启动目标程序。

除系统包数据库外，可在 Worker 本地 profile 明确配置最多 8 个应用部署目录，临时采集其中启用的 Java 归档与 Go ELF；每个文件由 Trivy 独立分析，使用本地固定版本漏洞库。系统包管理器安装的 Nginx、Tomcat、Kafka、RabbitMQ、MySQL、PostgreSQL、ZooKeeper、Nacos 等组件可能随发行版包数据库被识别；直接部署的 Java/Go 应用通过下述 `apps` 配置选择。其他源码安装、容器镜像和容器挂载卷需要按 [Linux 输入指南](linux-server-scan.md) 提供明确的离线输入。银河麒麟目前会显示“发行版尚未适配漏洞源”，不会借用 CentOS/RHEL 结果代替。CentOS 7 的结果仍受 Trivy 上游公告映射与发行版维护状态限制。

## Worker 配置

在运行 Worker 的电脑创建仅本机可读的目录和 JSON 文件。例子中的文档保留地址仅用于演示；替换为已登记的服务器 IP、SSH 端口和只读账号。配置文件不上传到 Server。

```json
{
  "knownHostsFile": "known_hosts",
  "targets": [
    {
      "ip": "192.0.2.10",
      "sshPort": 22,
      "user": "scanner_ro",
      "auth": "agent",
      "apps": [
        {"alias": "orders", "directory": "/opt/example-orders", "includeJava": true, "includeGo": false},
        {"alias": "gateway", "directory": "/srv/example-gateway", "includeJava": false, "includeGo": true}
      ]
    },
    {
      "ip": "192.0.2.11",
      "sshPort": 2222,
      "user": "scanner_ro",
      "auth": "private-key",
      "privateKeyFile": "keys/scan_ed25519"
    }
  ]
}
```

也可以在平台“资产列表 → SSH 采集配置”（或资产详情的“生成 SSH 采集配置”）中选择已登记主机、填写 SSH 端口、只读账号、认证方式、Worker 上的私钥文件路径和应用目录，生成上面格式的 `ssh-config.json` 后复制或下载。生成和校验只在浏览器内完成，不会上传到 Server；页面不提供密码或私钥内容输入框，校验规则与 Worker 加载时一致，并列出需要核对指纹的 `ssh-keyscan` 命令。资产列表的“最近扫描”会显示最近一次自动综合扫描的 SSH 采集状态（如未配置、认证失败、主机指纹不匹配）。

`knownHostsFile` 和 `privateKeyFile` 的相对路径以 JSON 所在目录为基准。每条配置必须使用唯一的数字 IP；不支持主机名、密码或未知 JSON 字段。私钥在 Unix 上权限必须限制为仅本人可读；Windows 请使用 ACL 限定访问者。加密私钥可先加入 SSH Agent，再使用 `auth: "agent"`。

首次连接前，运维应通过可信渠道核对服务器主机公钥指纹，再将相应公钥写入 `known_hosts`。例如 `ssh-keyscan -p 22 192.0.2.10` 只能取得待核对的公钥，不能单独证明它可信。Worker 固定启用 `StrictHostKeyChecking=yes`，禁用密码认证、代理转发、跳板机、系统级 SSH 配置和远端主机密钥自动更新；主机指纹不匹配时拒绝采集。

系统用户需要能读取 `/etc/os-release` 和受支持的 dpkg/apk/rpm 数据库；采集脚本不自动使用 sudo。目标机系统包采集需要 Python 3；RPM SQLite 数据库一致性备份及应用目录采集需要 Python 3.7+。Worker 需要系统 OpenSSH 客户端、当前规则包同时包含 Nuclei 与 Trivy，以及可用的 Trivy 漏洞库。

本地开发可在启动命令前设置：

```bash
SCANNER_SSH_CONFIG=runtime/ssh/ssh-config.json make dev
```

独立启动 Worker 时传入：

```text
sec-worker --ssh-config runtime/ssh/ssh-config.json
```

Windows 使用 `sec-worker.exe --ssh-config runtime\ssh\ssh-config.json`；确认 Windows OpenSSH Client 已安装。若使用 Agent，在同一用户会话中启动/解锁 Agent 并加入密钥后再启动 Worker。

## 创建任务

在任务中心选择“自动综合扫描”，选择一台或多台已登记主机（每台各建一个任务），填写经过运维批准的端口范围和排除项，并确认授权。SSH 端口必须包含在本次范围里且实际可连接，Worker 才会使用对应 IP 的本机 profile；超出范围不会尝试 SSH。HTTP(S) 服务检查只访问这次范围内探测开放的端口。

完成后任务详情显示系统包采集状态。报告仅把 Trivy 实际发现列为漏洞；未提供 profile、SSH 端口未开放、认证失败、主机指纹不匹配、目标没有 Python 3、规则库不可用或发行版不支持时都会明确写为未采集/未完成，不会当成“无漏洞”。原始 SSH 输出和密钥不会存进任务状态。Worker 在收到快照后会删除自己的临时输入；目标端脚本正常结束后会删除临时快照。

若 Worker 被强制断电或目标端进程遭到强制终止，无法承诺运行中的临时文件立即清除；应联系运维检查 `/tmp/secscan-*` 临时目录。任务超时会停止本地 SSH 子进程，不会跳过硬截止时间继续分析。

## 指定部署目录应用

`apps` 仅保存在 Worker 本地。`alias` 使用 1–64 个字母、数字、下划线或连字符，首字符为字母或数字，同 profile 内唯一。每项必须启用 `includeJava` 或 `includeGo`。`directory` 是不超过 512 字节的干净绝对 POSIX 路径；拒绝 `.`、`..`、重复分隔符、控制字符、根目录、`/opt`、`/srv`、`/home`、`/usr/local`、`/var/lib` 等宽泛父目录，以及 `/proc`、`/sys`、`/dev`、`/run`、`/tmp`、`/net`、`/mnt`、`/media` 和其子目录。请指定应用的具体部署目录。路径经过 Go 和远端 Python 双重校验，以有界 base64url JSON 传输，原始目录不进入 SSH 远端命令参数。

系统包流程后，应用采集向相同数字 IP 和 SSH 端口建立第二次有界连接。仅选启用的 JAR/WAR/EAR/PAR 或 ELF 候选；Go ELF 必须通过 Worker 的 Go build info 校验，其他原生 ELF 明确失败。不会运行应用，不收集依赖 lock 文件、配置、容器或其他主机。没有 `apps` 的旧 profile 保持原系统包行为，不增加 SSH 连接。

目录递归最多 3 层，全部应用合计最多检查 4096 个目录项；每应用最多 16 个产物，全部应用最多 32 个。单文件最多 512 MiB，解包总量最多 2 GiB。任一级符号链接、特殊文件、跨文件系统、文件变化、无启用类型的产物或超过限制均使采集失败，不会静默截断。使用目录描述符及 `O_NOFOLLOW` 读取，采集文件权限为私有且不可执行。Worker 在分析前还检查 Java ZIP 的完整性、最多 4096 个归档项、总展开不超过 2 GiB；嵌套 Java/ZIP 归档最多 3 层，单个嵌套归档最多 64 MiB。超限应用应拆分为明确的小目录。

本批以根文件系统的设备号为边界：部署在独立挂载的 `/opt` 等目录也会拒绝，应使用明确的离线输入流程。设备号检查无法区分同设备 bind mount，不是针对拥有目标主机挂载管理权限者的隔离机制。Java ZIP64、分卷或中央目录超过 4 MiB 的归档也暂不支持。

每个产物有独立的 `artifact` 输入与恰好一个 SHA-256 文件清单；Worker 只接收配置别名、连续序号和单个产物，拒绝额外文件、缺清单、重复项、软硬链接及哈希不符。Trivy 扫描前后强制核对清单。每文件必须有对应 `lang-pkgs` 的 `jar` 或 `gobinary` 分析结果和非空 Target，零漏洞的合格结果可以完成；空 Results、类型不符、缺 Java 索引或任何文件执行失败均使整个任务失败。失败回报保留系统包与各应用计数，不入库部分漏洞。

任务详情显示应用总状态，以及每个别名的选中数和已分析数。SSH 端口不在本次范围内时不连接，显示“未采集”；端口在范围内但未开放、采集或分析失败时，配置了应用的任务失败。发现项使用稳定的服务器 IP:SSH端口作为目标，去重仍使用主机、包名、安装版本与漏洞 ID，不包含临时目录或应用别名。原始远端路径及 SSH 输出不会进入回报。完成只代表本次选择产物得到分析，不代表完整产品或业务安全覆盖。

隔离回归（仅使用临时文件、合成包和 fake 执行器，不访问目标）:

```bash
go test -race -count=1 ./internal/sshcollect ./internal/executor ./internal/taskflow ./internal/repo
python3 -m unittest discover -s scripts -p test_collect_linux_inputs.py
```
