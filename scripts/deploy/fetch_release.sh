#!/usr/bin/env bash
# 在能上网的机器（云服务器或你的电脑）上一键下载发布包和漏洞库，整理成一个
# 可以直接拷到内网的文件夹。只下载 GitHub Actions 产物，不扫描任何目标。
#
#   ./fetch_release.sh                      # 标准版 linux-amd64 + 漏洞库
#   ./fetch_release.sh --edition portable --platform windows-amd64
#   ./fetch_release.sh --refresh            # 先重新运行工作流再下载最新产物
#
# 需要已登录的 GitHub CLI（gh auth login），以及 sha256sum 或 shasum。
set -euo pipefail

EDITION=standard
PLATFORM=linux-amd64
OUTPUT=""
WITH_DATA=1
REFRESH=0
REPO=""

say() { printf '%s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }
die() { printf '\n错误：%s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
用法：./fetch_release.sh [选项]

  --edition standard|portable   标准版（默认）或便携版
  --platform <系统-架构>         linux-amd64（默认）、linux-arm64、windows-amd64、darwin-arm64、darwin-amd64
  --output <目录>               输出目录（默认 ./scanner-release-<版本>-<平台>）
  --no-data                     不下载漏洞库（约 1.2 GB）
  --refresh                     先触发工作流重新构建，等待完成后再下载
  --repo <owner/name>           仓库（默认：当前目录所在的 GitHub 仓库）
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --edition) EDITION="${2:-}"; shift 2 ;;
    --platform) PLATFORM="${2:-}"; shift 2 ;;
    --output) OUTPUT="${2:-}"; shift 2 ;;
    --no-data) WITH_DATA=0; shift ;;
    --refresh) REFRESH=1; shift ;;
    --repo) REPO="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "未知参数：$1" ;;
  esac
done

case "$EDITION" in standard|portable) ;; *) die "--edition 只能是 standard 或 portable" ;; esac
case "$PLATFORM" in linux-amd64|linux-arm64|windows-amd64|darwin-arm64|darwin-amd64) ;; *) die "不支持的平台 $PLATFORM" ;; esac
[[ "$EDITION" == standard && "$PLATFORM" != linux-* ]] && die "标准版只支持 Linux；Windows/macOS 请用 --edition portable"
command -v gh >/dev/null || die "需要 GitHub CLI：https://cli.github.com/ ，安装后运行 gh auth login"
gh auth status >/dev/null 2>&1 || die "GitHub CLI 未登录，请先运行 gh auth login"
if command -v sha256sum >/dev/null; then SHA=(sha256sum); else SHA=(shasum -a 256); fi
repo_args=()
[[ -n "$REPO" ]] && repo_args=(--repo "$REPO")

if [[ "$EDITION" == standard ]]; then
  WORKFLOW="Build & Release Artifacts"; ARTIFACT="package-$PLATFORM"; ARCHIVE_PREFIX="scanner-platform-$PLATFORM"
else
  WORKFLOW="Build Portable Edition"; ARTIFACT="portable-$PLATFORM"; ARCHIVE_PREFIX="scanner-platform-portable-$PLATFORM"
fi
DATA_WORKFLOW="Build Offline Vulnerability Data"

# Newest successful run of a workflow on main, optionally after a fresh run.
latest_run() {
  local workflow="$1"
  if [[ $REFRESH -eq 1 ]]; then
    step "触发工作流：$workflow"
    gh workflow run "$workflow" --ref main "${repo_args[@]+"${repo_args[@]}"}" >/dev/null
    sleep 8
    local id
    id="$(gh run list --workflow "$workflow" --branch main --limit 1 --json databaseId --jq '.[0].databaseId' "${repo_args[@]+"${repo_args[@]}"}")"
    say "等待运行 $id 完成（漏洞库约 10 分钟，程序包约 5–10 分钟）..."
    gh run watch "$id" --exit-status "${repo_args[@]+"${repo_args[@]}"}" >/dev/null || die "工作流运行失败：gh run view $id --log-failed"
  fi
  gh run list --workflow "$workflow" --branch main --status success --limit 1 --json databaseId --jq '.[0].databaseId' "${repo_args[@]+"${repo_args[@]}"}"
}

# gh run download with retries: large artifacts often break on unstable networks.
download() {
  local run="$1" name="$2" dir="$3" attempt
  for attempt in 1 2 3; do
    rm -rf "$dir"
    if gh run download "$run" -n "$name" -D "$dir" "${repo_args[@]+"${repo_args[@]}"}"; then
      return 0
    fi
    if gh api "repos/{owner}/{repo}/actions/runs/$run/artifacts" --jq ".artifacts[] | select(.name==\"$name\") | .expired" "${repo_args[@]+"${repo_args[@]}"}" 2>/dev/null | grep -q true; then
      die "产物 $name 已过期（只保留 14 天），请加 --refresh 重新构建"
    fi
    [[ $attempt -lt 3 ]] && say "下载中断（网络不稳定），第 $attempt 次失败，10 秒后重试..." && sleep 10
  done
  die "下载 $name 连续 3 次失败，请检查网络后重试（也可以在 GitHub 网页的运行页面 Artifacts 处手动下载）"
}

step "查找最新的成功构建"
RUN="$(latest_run "$WORKFLOW")"
[[ -n "$RUN" && "$RUN" != null ]] && say "$WORKFLOW：运行 $RUN" || die "没有找到成功的「$WORKFLOW」运行；用 --refresh 触发一次"
DATA_RUN=""
if [[ $WITH_DATA -eq 1 ]]; then
  DATA_RUN="$(latest_run "$DATA_WORKFLOW")"
  [[ -n "$DATA_RUN" && "$DATA_RUN" != null ]] && say "$DATA_WORKFLOW：运行 $DATA_RUN" || die "没有找到成功的漏洞库构建；用 --refresh 触发，或加 --no-data 跳过"
fi

OUTPUT="${OUTPUT:-./scanner-release-$EDITION-$PLATFORM-$(date +%Y%m%d)}"
[[ -e "$OUTPUT" ]] && die "$OUTPUT 已存在；换一个 --output 目录"
mkdir -p "$OUTPUT"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

step "下载程序包 $ARTIFACT"
download "$RUN" "$ARTIFACT" "$WORK/package"
archive="$(find "$WORK/package" -maxdepth 1 -name "$ARCHIVE_PREFIX.*" ! -name '*.sha256' | head -n 1)"
[[ -n "$archive" ]] || die "产物中没有 $ARCHIVE_PREFIX 压缩包"
(cd "$WORK/package" && "${SHA[@]}" -c "$(basename "$archive").sha256" >/dev/null) || die "程序包 SHA-256 校验失败"
mv "$archive" "$archive.sha256" "$OUTPUT/"
say "程序包校验通过：$(basename "$archive")"

if [[ "$EDITION" == standard ]]; then
  # The installer sits inside the package; copy it beside the archive so the
  # intranet side can run it directly.
  mkdir -p "$WORK/installer"
  tar -xzf "$OUTPUT/$(basename "$archive")" -C "$WORK/installer" ./install.sh ./libexec/scanner-run ./tools/scanctl 2>/dev/null \
    || die "这个程序包里没有 install.sh（构建早于安装脚本）；用 --refresh 重新构建"
  cp "$WORK/installer/install.sh" "$OUTPUT/"
  mkdir -p "$OUTPUT/libexec" "$OUTPUT/tools"
  cp "$WORK/installer/libexec/scanner-run" "$OUTPUT/libexec/"
  cp "$WORK/installer/tools/scanctl" "$OUTPUT/tools/"
fi

if [[ $WITH_DATA -eq 1 ]]; then
  step "下载漏洞库（约 1.2 GB，请耐心等待）"
  download "$DATA_RUN" vulnerability-data "$OUTPUT/vulnerability-data"
  (cd "$OUTPUT/vulnerability-data" && "${SHA[@]}" -c SHA256SUMS >/dev/null) || die "漏洞库 SHA-256 校验失败"
  say "漏洞库校验通过：版本 $(tr -d '[:space:]' < "$OUTPUT/vulnerability-data/vuln-data/CURRENT")"
  if gh variable get BUNDLE_SIGNING_PUBLIC_KEY_PEM --env vulnerability-data-signing "${repo_args[@]+"${repo_args[@]}"}" > "$OUTPUT/bundle-public-key.pem" 2>/dev/null \
    && grep -q 'BEGIN PUBLIC KEY' "$OUTPUT/bundle-public-key.pem"; then
    say "已保存规则签名公钥 bundle-public-key.pem（只有公钥）"
  else
    rm -f "$OUTPUT/bundle-public-key.pem"
    say "提示：没能读取签名公钥（需要仓库变量读取权限），不影响安装"
  fi
fi

if [[ "$EDITION" == portable ]]; then
  step "解压便携版并放入漏洞库"
  case "$archive" in
    *.zip)
      if command -v unzip >/dev/null; then unzip -q "$OUTPUT/$(basename "$archive")" -d "$OUTPUT"
      else python3 -m zipfile -e "$OUTPUT/$(basename "$archive")" "$OUTPUT"; fi ;;
    *) tar -xzf "$OUTPUT/$(basename "$archive")" -C "$OUTPUT" ;;
  esac
  [[ -d "$OUTPUT/sec-portable" ]] || die "解压后没有 sec-portable/ 目录"
  if [[ $WITH_DATA -eq 1 ]]; then
    cp -a "$OUTPUT/vulnerability-data/vuln-data/." "$OUTPUT/sec-portable/vuln-data/"
    [[ -f "$OUTPUT/bundle-public-key.pem" ]] && cp "$OUTPUT/bundle-public-key.pem" "$OUTPUT/sec-portable/config/trusted-rule-keys/"
    rm -rf "$OUTPUT/vulnerability-data"
  fi
fi

step "完成：$OUTPUT"
if [[ "$EDITION" == standard ]]; then
  cat <<NEXT
把整个文件夹拷到内网 Linux 服务器（例如：scp -r $OUTPUT <用户>@<内网服务器IP>:~/ ），然后在服务器上：
  cd ~/$(basename "$OUTPUT")
  sudo ./install.sh
NEXT
else
  say "便携版已就绪：$OUTPUT/sec-portable/"
  [[ $WITH_DATA -eq 1 ]] && say "漏洞库已放入 sec-portable/vuln-data。" || say "未下载漏洞库：联网时运行 sec-portable 文件夹里的 prepare-data 脚本。"
  say "把 sec-portable 文件夹拷到要用的电脑上，双击里面的启动脚本（Windows：start-windows.bat，macOS：start-macos.command，Linux：start-linux.sh）。"
fi
