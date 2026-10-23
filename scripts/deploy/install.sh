#!/usr/bin/env bash
# 一键安装 / 升级标准版（Linux + systemd）。不扫描任何目标。
#
# 最简单的用法：解压发布包后，在包目录里运行
#   sudo ./install.sh
# 会自动使用同目录（或上一级目录）里的 vulnerability-data 和 bundle-public-key.pem。
# 再次运行即为升级：保留数据库、配置、令牌和漏洞库，只替换程序文件。
set -euo pipefail

PREFIX=/opt/scanner-platform
SERVICE_USER=secscan
LISTEN=""
PACKAGE=""
DATA=""
ADMIN=""
PASSWORD_FILE=""
RULE_KEYS=()
ASSUME_YES=0

say() { printf '%s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }
die() { printf '\n错误：%s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
用法：sudo ./install.sh [选项]

  --package <路径>          发布包 .tar.gz 或已解压目录（默认：本脚本所在目录）
  --data <路径>             漏洞库：vulnerability-data 目录、.zip 或 .tar.gz（默认自动查找）
  --rule-public-key <文件>  规则包签名公钥 PEM，可重复（默认自动查找 bundle-public-key.pem）
  --prefix <目录>           安装目录（默认 /opt/scanner-platform）
  --listen <地址>           网页地址，只能是回环地址（默认 127.0.0.1:8080）
  --admin <用户名>          首次安装时创建的管理员（默认交互询问，留空则在网页上创建）
  --admin-password-file <文件>  非交互创建管理员时使用的仅本人可读密码文件
  -y, --yes                 不询问确认
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --package) PACKAGE="${2:-}"; shift 2 ;;
    --data) DATA="${2:-}"; shift 2 ;;
    --rule-public-key) RULE_KEYS+=("${2:-}"); shift 2 ;;
    --prefix) PREFIX="${2:-}"; shift 2 ;;
    --listen) LISTEN="${2:-}"; shift 2 ;;
    --admin) ADMIN="${2:-}"; shift 2 ;;
    --admin-password-file) PASSWORD_FILE="${2:-}"; shift 2 ;;
    -y|--yes) ASSUME_YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "未知参数：$1" ;;
  esac
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

step "检查运行环境"
[[ "$(uname -s)" == Linux ]] || die "标准版安装脚本只支持 Linux；Windows/macOS 请使用便携版"
[[ $EUID -eq 0 ]] || die "请用 sudo 运行：sudo ./install.sh"
for tool in systemctl tar sha256sum curl openssl runuser; do
  command -v "$tool" >/dev/null || die "缺少命令 $tool"
done
case "$PREFIX" in /*) ;; *) die "--prefix 必须是绝对路径" ;; esac
if [[ -n "$LISTEN" ]]; then
  [[ "$LISTEN" =~ ^(127\.[0-9]+\.[0-9]+\.[0-9]+|\[::1\]):[0-9]+$ ]] || die "--listen 只能是回环地址，例如 127.0.0.1:8080"
fi
say "安装目录：$PREFIX，服务用户：$SERVICE_USER"

# --- locate the package -------------------------------------------------
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
if [[ -z "$PACKAGE" ]]; then
  if [[ -x "$HERE/sec-server" ]]; then
    PACKAGE="$HERE"
  else
    PACKAGE="$(ls "$HERE"/scanner-platform-linux-*.tar.gz 2>/dev/null | head -n 1 || true)"
  fi
fi
[[ -n "$PACKAGE" && -e "$PACKAGE" ]] || die "找不到发布包；用 --package 指定 scanner-platform-linux-*.tar.gz"
step "准备发布包：$PACKAGE"
if [[ -f "$PACKAGE" ]]; then
  if [[ -f "$PACKAGE.sha256" ]]; then
    (cd "$(dirname "$PACKAGE")" && sha256sum --quiet -c "$(basename "$PACKAGE").sha256") || die "发布包 SHA-256 校验失败"
    say "SHA-256 校验通过"
  else
    say "提示：没有找到 $(basename "$PACKAGE").sha256，跳过校验"
  fi
  mkdir -p "$WORK/package"
  tar -xzf "$PACKAGE" -C "$WORK/package"
  SRC="$WORK/package"
else
  SRC="$(cd "$PACKAGE" && pwd)"
fi
if [[ "$(cd "$SRC" && pwd -P)" == "$(mkdir -p "$PREFIX" && cd "$PREFIX" && pwd -P)" ]]; then
  die "发布包不能直接解压在安装目录 $PREFIX；请解压到其他目录（例如 ~/scanner-release）后再运行"
fi
for item in sec-server sec-worker sec-updater web/dist/index.html bin; do
  [[ -e "$SRC/$item" ]] || die "发布包缺少 $item，请确认下载的是 Linux 的 package-linux-* 包"
done
arch="$(uname -m)"
if file "$SRC/sec-server" 2>/dev/null | grep -q 'ELF'; then
  case "$arch" in
    x86_64) file "$SRC/sec-server" | grep -q 'x86-64' || die "这台机器是 x86_64，请下载 package-linux-amd64" ;;
    aarch64|arm64) file "$SRC/sec-server" | grep -q 'aarch64' || die "这台机器是 ARM64，请下载 package-linux-arm64" ;;
  esac
fi

# Data and signing key next to the package or this script, if not given.
search_dirs=("$HERE" "$(dirname "$HERE")")
[[ -f "$PACKAGE" ]] && search_dirs+=("$(dirname "$PACKAGE")")
if [[ -z "$DATA" ]]; then
  for dir in "${search_dirs[@]}"; do
    for candidate in "$dir/vulnerability-data" "$dir/vulnerability-data.zip" "$dir/vulnerability-data.tar.gz"; do
      if [[ -e "$candidate" ]]; then DATA="$candidate"; break 2; fi
    done
  done
fi
if [[ ${#RULE_KEYS[@]} -eq 0 ]]; then
  for dir in "${search_dirs[@]}"; do
    if [[ -f "$dir/bundle-public-key.pem" ]]; then RULE_KEYS+=("$dir/bundle-public-key.pem"); break; fi
  done
fi

UPGRADE=0
[[ -f "$PREFIX/runtime/platform.db" ]] && UPGRADE=1
step "安装计划"
if [[ $UPGRADE -eq 1 ]]; then say "检测到已有安装：升级程序文件，保留数据库、配置、令牌和漏洞库"; else say "全新安装"; fi
[[ -n "$DATA" ]] && say "漏洞库：$DATA" || say "漏洞库：未提供（安装后可运行 scanctl update-data 或 scanctl prepare-data）"
[[ ${#RULE_KEYS[@]} -gt 0 ]] && say "规则签名公钥：${RULE_KEYS[*]}" || true
if [[ $ASSUME_YES -eq 0 && -t 0 ]]; then
  read -r -p "继续安装？[Y/n] " answer
  [[ -z "$answer" || "$answer" =~ ^[Yy] ]] || die "已取消"
fi

# --- install --------------------------------------------------------------
step "创建服务用户和目录"
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$PREFIX" --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
  say "已创建用户 $SERVICE_USER"
fi
install -d -m 755 "$PREFIX"
for unit in sec-worker sec-updater sec-server; do
  systemctl stop "$unit" 2>/dev/null || true
done

step "安装程序文件"
for item in sec-server sec-worker sec-updater sec-portable sec-node-provision sec-node-deploy sec-fence-launcher sec-worker-supervisor web bin tools docs README.md; do
  [[ -e "$SRC/$item" ]] || continue
  rm -rf "${PREFIX:?}/${item:?}"
  cp -a "$SRC/$item" "$PREFIX/$item"
  # Program files belong to root so the service account cannot modify them.
  chown -R root:root "$PREFIX/$item"
done
install -d -m 755 "$PREFIX/libexec"
install -m 755 "$HERE/libexec/scanner-run" "$PREFIX/libexec/scanner-run" 2>/dev/null || install -m 755 "$SRC/libexec/scanner-run" "$PREFIX/libexec/scanner-run"
install -m 755 "$HERE/tools/scanctl" /usr/local/bin/scanctl 2>/dev/null || install -m 755 "$SRC/tools/scanctl" /usr/local/bin/scanctl
chown -R root:root "$PREFIX/libexec"

for dir in runtime runtime/inputs runtime/worker runtime/reports runtime/engine-data/trivy; do
  install -d -m 700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$PREFIX/$dir"
done
install -d -m 750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$PREFIX/config" "$PREFIX/config/trusted-rule-keys" "$PREFIX/config/keys"
install -d -m 700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$PREFIX/secrets"
install -d -m 755 -o "$SERVICE_USER" -g "$SERVICE_USER" "$PREFIX/vuln-data"

if [[ -n "$LISTEN" || ! -f "$PREFIX/config/scanner.conf" ]]; then
  printf 'LISTEN=%s\n' "${LISTEN:-127.0.0.1:8080}" > "$PREFIX/config/scanner.conf"
  chown root:"$SERVICE_USER" "$PREFIX/config/scanner.conf"
  chmod 644 "$PREFIX/config/scanner.conf"
fi
for key in ${RULE_KEYS[@]+"${RULE_KEYS[@]}"}; do
  [[ -f "$key" ]] || die "找不到公钥 $key"
  grep -q 'BEGIN PUBLIC KEY' "$key" || die "$key 不是 PUBLIC KEY PEM"
  install -m 640 -o "$SERVICE_USER" -g "$SERVICE_USER" "$key" "$PREFIX/config/trusted-rule-keys/$(basename "$key")"
done

step "生成节点令牌（只写入 $PREFIX/secrets，权限 600）"
if [[ -f "$PREFIX/secrets/node-tokens" && -f "$PREFIX/secrets/worker.token" && -f "$PREFIX/secrets/updater.token" ]]; then
  say "已存在，保留原令牌"
else
  (
    umask 077
    worker_token="$(openssl rand -hex 32)"
    updater_token="$(openssl rand -hex 32)"
    printf 'worker-local=%s\nupdater-local=%s\n' "$worker_token" "$updater_token" > "$PREFIX/secrets/node-tokens"
    printf '%s\n' "$worker_token" > "$PREFIX/secrets/worker.token"
    printf '%s\n' "$updater_token" > "$PREFIX/secrets/updater.token"
  )
  say "已生成"
fi
chown "$SERVICE_USER:$SERVICE_USER" "$PREFIX"/secrets/*
chmod 600 "$PREFIX"/secrets/*

if [[ -n "$DATA" ]]; then
  step "安装漏洞库"
  SCANNER_PREFIX="$PREFIX" SCANNER_USER="$SERVICE_USER" /usr/local/bin/scanctl update-data "$DATA" --no-restart
fi
chown -R "$SERVICE_USER:$SERVICE_USER" "$PREFIX/runtime" "$PREFIX/vuln-data"

if [[ $UPGRADE -eq 0 ]]; then
  step "创建管理员"
  if [[ -z "$ADMIN" && -t 0 && $ASSUME_YES -eq 0 ]]; then
    read -r -p "管理员用户名（直接回车则稍后在网页上创建）：" ADMIN
  fi
  if [[ -n "$ADMIN" ]]; then
    init=(./sec-server --db runtime/platform.db --init-admin "$ADMIN")
    if [[ -n "$PASSWORD_FILE" ]]; then
      [[ -f "$PASSWORD_FILE" ]] || die "找不到密码文件 $PASSWORD_FILE"
      install -m 600 -o "$SERVICE_USER" -g "$SERVICE_USER" "$PASSWORD_FILE" "$WORK/admin-password"
      init+=(--password-file "$WORK/admin-password")
      chmod 711 "$WORK"
    else
      say "请输入管理员密码（12–72 字节，输入时不显示）："
    fi
    (cd "$PREFIX" && runuser -u "$SERVICE_USER" -- "${init[@]}") || die "创建管理员失败"
  else
    say "跳过：第一次打开网页时会提示创建管理员"
  fi
fi

step "配置并启动 systemd 服务"
write_unit() {
  local name="$1" component="$2" description="$3" after="$4"
  cat > "/etc/systemd/system/$name.service" <<UNIT
[Unit]
Description=$description
After=$after
${5:-}

[Service]
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$PREFIX
ExecStart=$PREFIX/libexec/scanner-run $component
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT
}
write_unit sec-server server "Scanner Platform Server" network-online.target "Wants=network-online.target"
write_unit sec-worker worker "Scanner Platform Worker" sec-server.service "Requires=sec-server.service"
write_unit sec-updater updater "Scanner Platform Updater" sec-server.service "Requires=sec-server.service"
systemctl daemon-reload
systemctl enable sec-server sec-worker sec-updater >/dev/null
SCANNER_PREFIX="$PREFIX" SCANNER_USER="$SERVICE_USER" /usr/local/bin/scanctl start

step "检查"
sleep 3
SCANNER_PREFIX="$PREFIX" SCANNER_USER="$SERVICE_USER" /usr/local/bin/scanctl status || true

PORT="$(sed -n 's/^LISTEN=//p' "$PREFIX/config/scanner.conf" | tail -n 1)"
PORT="${PORT##*:}"
cat <<DONE

安装完成。

  查看状态：  sudo scanctl status
  查看日志：  sudo scanctl logs
  打开网页：  在你的电脑上运行 scanctl tunnel 显示的 ssh 命令，然后浏览器打开 http://127.0.0.1:${PORT}/
DONE
[[ ! -f "$PREFIX/vuln-data/CURRENT" ]] && say "  漏洞库：    还没有，运行 sudo scanctl update-data <vulnerability-data> 或 sudo scanctl prepare-data"
say "  首次使用：  建一个「运维审批」角色的账号（不能审批自己的申请），再登记资产、申请并审批授权、创建扫描。"
exit 0
