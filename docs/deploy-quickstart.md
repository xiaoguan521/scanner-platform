# 一键部署（傻瓜版）

本文只讲最省事的做法：标准版装在一台内网 Linux 服务器上（systemd），便携版直接双击运行。手工步骤和生产集群部署见 [deploy/README.md](../deploy/README.md)。所有脚本只下载、安装和管理程序，**不会扫描任何目标**；扫描只对你在网页上登记并审批过的主机进行。

## 第 1 步：在能上网的机器上下载（云服务器或你的电脑）

需要 [GitHub CLI](https://cli.github.com/)，先登录一次：

```bash
gh auth login
```

在仓库目录下运行（或从发布包的 `tools/fetch_release.sh` 运行，加 `--repo <owner>/<name>`）：

```bash
./scripts/deploy/fetch_release.sh
```

默认下载标准版 `linux-amd64` 和漏洞库（约 1.2 GB），校验 SHA-256 后整理到 `scanner-release-standard-linux-amd64-<日期>/`。常用变化：

| 需求 | 命令 |
|---|---|
| 内网服务器是 ARM | `./scripts/deploy/fetch_release.sh --platform linux-arm64` |
| 便携版（Windows） | `./scripts/deploy/fetch_release.sh --edition portable --platform windows-amd64` |
| 便携版（Mac，Apple 芯片） | `./scripts/deploy/fetch_release.sh --edition portable --platform darwin-arm64` |
| 构建已过期（产物只保留 14 天） | 加 `--refresh`，脚本会先重新运行工作流 |
| 暂不要漏洞库 | 加 `--no-data` |

## 第 2 步（标准版）：拷到内网服务器，一条命令安装

```bash
scp -r scanner-release-standard-linux-amd64-<日期> <用户>@<内网服务器IP>:~/
```

在内网服务器上：

```bash
cd ~/scanner-release-standard-linux-amd64-<日期>
```

```bash
sudo ./install.sh
```

安装脚本会：校验发布包；创建服务用户 `secscan`；安装到 `/opt/scanner-platform`；导入同目录的漏洞库和签名公钥；生成只写在 `secrets/`（权限 600）的节点令牌；询问并创建管理员；配置并启动 `sec-server`、`sec-worker`、`sec-updater` 三个 systemd 服务；最后显示状态。再次运行就是升级，数据库、配置、令牌和漏洞库都会保留。

然后在**你自己的电脑**上打开网页（网页只监听服务器本机）：

```bash
ssh -L 8080:127.0.0.1:8080 <用户>@<内网服务器IP>
```

浏览器打开 `http://127.0.0.1:8080/`。服务器上运行 `scanctl tunnel` 会直接显示这条命令。

### 日常管理：scanctl

| 命令 | 作用 |
|---|---|
| `sudo scanctl status` | 服务、网页、漏洞库、引擎、SSH 采集状态 |
| `sudo scanctl logs` / `sudo scanctl logs -f` | 查看 / 跟踪日志 |
| `sudo scanctl restart` | 重启全部服务 |
| `sudo scanctl update-data <vulnerability-data>` | 更新漏洞库（目录、.zip 或 .tar.gz，自动校验并保留上一版） |
| `sudo scanctl prepare-data` | 服务器能上网时，直接在本机下载漏洞库 |
| `sudo scanctl ssh-config ssh-config.json --known-hosts known_hosts --key scan_ed25519` | 安装网页“资产列表 → SSH 采集配置”下载的配置；Worker 拒绝时自动恢复上一份 |
| `sudo scanctl add-rule-key bundle-public-key.pem` | 添加规则包签名公钥 |
| `sudo scanctl backup` | 停服备份数据库、报告、配置和令牌到 `/var/backups/scanner-platform` |

`known_hosts` 里的主机指纹必须先和运维核对，不能直接信任 `ssh-keyscan` 的结果。

## 第 2 步（便携版）：双击运行

`fetch_release.sh --edition portable` 已经把漏洞库放进 `sec-portable/vuln-data/`。把 `sec-portable` 文件夹拷到要用的电脑，双击：

| 系统 | 启动 | 联网准备漏洞库（没下载数据包时） |
|---|---|---|
| Windows | `start-windows.bat` | `prepare-data-windows.bat` |
| macOS | `start-macos.command`（第一次右键 → 打开） | `prepare-data-macos.command` |
| Linux | `./start-linux.sh` | `./prepare-data-linux.sh` |

浏览器会自动打开 `http://127.0.0.1:8080/`。Windows 出现 SmartScreen 时点“更多信息 → 仍要运行”（程序还没有代码签名）。杀毒软件 / EDR 可能误报 `bin/` 里的 nuclei、trivy，需要安全团队加白。数据都在 `sec-portable/runtime/`，备份时关闭程序后复制整个文件夹。

## 第 3 步：第一次扫描（两个版本相同）

1. 系统 → 用户与角色：新建一个“运维审批”角色的账号（平台不允许审批自己的申请）。
2. 资产 → 资产列表：登记测试主机的数字 IP。
3. 系统 → 授权范围：申请扫描授权；换审批账号登录后批准。
4. 系统 → 节点与规则库：确认 Worker、Updater 在线，规则版本正确。
5. 扫描任务 → 创建扫描任务：自动综合扫描，先用“快速检测”和常用端口。
6. 在任务详情、漏洞列表查看结果，在报告中心生成报告。

出问题时：标准版运行 `sudo scanctl status` 和 `sudo scanctl logs`；便携版看 `sec-portable/runtime/logs/portable.log`。
