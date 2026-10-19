# Worker 本机 SSH 采集

自动综合扫描可选用 SSH 对单台已登记 Linux 主机做一次性系统包采集。Server、API、SQLite 和扫描日志都不接收 SSH 密钥、Agent 内容或原始认证输出。Worker 使用系统 OpenSSH 客户端，将固定采集脚本通过 SSH 标准输入传到目标；脚本把发行版标识和系统包数据库整理成短期快照，快照经 SSH 输出到 Worker 后，目标机临时目录会被删除。不会安装常驻服务、修改软件包或启动目标程序。

当前只采集系统包数据库，Trivy 使用 Worker 上对应版本的离线漏洞库分析。系统包管理器安装的 Nginx、Tomcat、Kafka、RabbitMQ、MySQL、PostgreSQL、ZooKeeper、Nacos 等组件可能随发行版包数据库被识别；源码安装、独立压缩包、直接部署的 JAR/Go 文件、容器镜像和容器挂载卷不在这条 SSH 采集路径中，需要按 [Linux 输入指南](linux-server-scan.md) 提供明确的离线输入。银河麒麟目前会显示“发行版尚未适配漏洞源”，不会借用 CentOS/RHEL 结果代替。CentOS 7 的结果仍受 Trivy 上游公告映射与发行版维护状态限制。

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
      "auth": "agent"
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

`knownHostsFile` 和 `privateKeyFile` 的相对路径以 JSON 所在目录为基准。每条配置必须使用唯一的数字 IP；不支持主机名、密码或未知 JSON 字段。私钥在 Unix 上权限必须限制为仅本人可读；Windows 请使用 ACL 限定访问者。加密私钥可先加入 SSH Agent，再使用 `auth: "agent"`。

首次连接前，运维应通过可信渠道核对服务器主机公钥指纹，再将相应公钥写入 `known_hosts`。例如 `ssh-keyscan -p 22 192.0.2.10` 只能取得待核对的公钥，不能单独证明它可信。Worker 固定启用 `StrictHostKeyChecking=yes`，禁用密码认证、代理转发、跳板机、系统级 SSH 配置和远端主机密钥自动更新；主机指纹不匹配时拒绝采集。

系统用户需要能读取 `/etc/os-release` 和受支持的 dpkg/apk/rpm 数据库；采集脚本不自动使用 sudo。目标机需要 Python 3；RPM SQLite 数据库一致性备份需要 Python 3.7+。Worker 需要系统 OpenSSH 客户端、当前规则包同时包含 Nuclei 与 Trivy，以及可用的 Trivy 漏洞库。

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

在任务中心选择“自动综合扫描”，选择单台已登记主机，填写经过运维批准的端口范围和排除项，并确认授权。SSH 端口必须包含在本次范围里且实际可连接，Worker 才会使用对应 IP 的本机 profile；超出范围不会尝试 SSH。HTTP(S) 服务检查只访问这次范围内探测开放的端口。

完成后任务详情显示系统包采集状态。报告仅把 Trivy 实际发现列为漏洞；未提供 profile、SSH 端口未开放、认证失败、主机指纹不匹配、目标没有 Python 3、规则库不可用或发行版不支持时都会明确写为未采集/未完成，不会当成“无漏洞”。原始 SSH 输出和密钥不会存进任务状态。Worker 在收到快照后会删除自己的临时输入；目标端脚本正常结束后会删除临时快照。

若 Worker 被强制断电或目标端进程遭到强制终止，无法承诺运行中的临时文件立即清除；应联系运维检查 `/tmp/secscan-*` 临时目录。任务超时会停止本地 SSH 子进程，不会跳过硬截止时间继续分析。
