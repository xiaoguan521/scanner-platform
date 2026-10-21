# OrbStack Linux 系统与中间件靶场

这是供本项目本机验证使用的自建 Debian 靶机镜像。镜像安装 Debian 系统包、Apache、Tomcat、MariaDB、PostgreSQL、Redis、OpenSSH 和 Python 3：平台通过本机 SSH 采集系统包清单并交给 Trivy 分析；对外开放的 HTTP 与 SSH 端口则用于服务版本识别和只读 HTTP 基线检查。

验证步骤和结果判定见[OrbStack 靶场功能验证方案](verification-plan.md)。

只有 SSH 和 Apache 会启动。Compose 只把这两个端口绑定在宿主机 `127.0.0.1`；OrbStack 的 **Expose ports to LAN** 也请保持关闭。数据库、Redis 和 Tomcat 包会进入系统包清单，但本配置不会启动或映射它们的服务端口。

## 启动

从仓库根目录执行。SSH 私钥和配置都放在已被 Git 忽略的 `runtime/` 目录中；不要把私钥提交到仓库。

```bash
mkdir -p runtime/ssh
chmod 700 runtime/ssh
ssh-keygen -q -t ed25519 -N '' -f runtime/ssh/orbstack-target
chmod 600 runtime/ssh/orbstack-target
docker compose -f lab/orbstack-target/compose.yaml up --build -d
```

确认 HTTP 服务启动：

```bash
curl --fail http://127.0.0.1:18080/
```

## 固定 SSH 主机指纹

先查看容器内 SSH 主机公钥指纹，再取得宿主机看到的候选公钥指纹；两者一致后，才把候选项保存为 Worker 的 `known_hosts`。容器重建会重新生成主机密钥，需要重新核对。

```bash
docker compose -f lab/orbstack-target/compose.yaml exec -T linux-server \
  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
ssh-keyscan -T 5 -t ed25519 -p 12222 127.0.0.1 > runtime/ssh/known_hosts.candidate
awk 'NF >= 3 { print $2, $3 }' runtime/ssh/known_hosts.candidate \
  > runtime/ssh/scanned-host.pub
ssh-keygen -lf runtime/ssh/scanned-host.pub
```

核对两条输出中的指纹；相同后执行：

```bash
mv runtime/ssh/known_hosts.candidate runtime/ssh/known_hosts
```

`ssh-keyscan` 只负责取得候选公钥，不能代替指纹核对。

## 配置 Worker

在 `runtime/ssh/ssh-config.json` 写入：

```json
{
  "knownHostsFile": "known_hosts",
  "targets": [
    {
      "ip": "127.0.0.1",
      "sshPort": 12222,
      "user": "scanner_ro",
      "auth": "private-key",
      "privateKeyFile": "orbstack-target"
    }
  ]
}
```

若 Worker 已经运行，停止后从仓库根目录用此配置启动：

```bash
SCANNER_SSH_CONFIG=runtime/ssh/ssh-config.json make dev
```

## 在平台中验证

1. 只登记数字 IP `127.0.0.1`，授权 TCP 端口 `12222` 和 `18080`。
2. 创建“自动综合扫描”任务，端口范围选“自定义”，只填写 `12222,18080`。常见端口预设不包含 SSH 映射端口 `12222`。SSH 端口必须在本次授权范围内且探测为开放，Worker 才会采集 Debian 的系统包清单。
3. 查看任务里的 SSH 系统采集状态、Trivy 软件包发现项，以及 Apache HTTP 服务版本和只读基线结果。

Trivy 结果由构建时 Debian 软件包版本和 Worker 本地漏洞库决定；此配置不会保证每次都产生 CVE 发现。当前 Nuclei 仅运行只读 HTTP 基线，知识库的 CVE 匹配属于版本推断；平台尚未实现通用的漏洞原理验证，也不会执行利用、爆破或口令尝试。需要验证具体 CVE 原理时，应另行确定平台已支持的只读验证规则和对应隔离靶机。

完成后停止并移除靶机：

```bash
docker compose -f lab/orbstack-target/compose.yaml down
```

## 启动 PostgreSQL 验证库

`compose-postgres.yaml` 是与 Linux 靶机分开的本地 PostgreSQL 夹具，只把端口绑定到宿主机回环地址，不写入初始业务数据。密码必须由调用者提供，仓库不保存 `.env`、DSN 或数据库卷内容：

```bash
export SCANNER_POSTGRES_PASSWORD="$(openssl rand -hex 24)"
docker compose -f lab/orbstack-target/compose-postgres.yaml up -d
docker compose -f lab/orbstack-target/compose-postgres.yaml ps
```

等待 `postgres` 的健康状态为 `healthy` 后，创建 owner-only DSN 文件并执行嵌入式迁移：

```bash
mkdir -p runtime/postgres
umask 077
printf 'postgres://scanner:%s@127.0.0.1:15432/scanner_platform?sslmode=disable\n' "$SCANNER_POSTGRES_PASSWORD" > runtime/postgres/dsn
POSTGRES_DSN_FILE="$PWD/runtime/postgres/dsn" make migrate-postgres
```

迁移命令只创建/更新 schema journal，不创建用户、资产、规则或测试结果。验证完成后可以删除夹具和卷：

```bash
docker compose -f lab/orbstack-target/compose-postgres.yaml down -v
rm -f runtime/postgres/dsn
unset SCANNER_POSTGRES_PASSWORD
```
