#!/bin/bash
# Double-click (macOS) or run to start sec-portable; the browser opens the web console.
cd "$(dirname "$0")" || exit 1
# Downloaded copies are quarantined by macOS; clear it for this folder only.
if [[ "$(uname -s)" == Darwin ]]; then
  xattr -dr com.apple.quarantine . 2>/dev/null || true
fi
chmod +x ./sec-portable ./bin/* 2>/dev/null || true
echo "正在启动 sec-portable，按 Ctrl+C 退出。"
./sec-portable "$@"
status=$?
if [[ $status -ne 0 ]]; then
  echo
  echo "启动失败（退出码 $status），请查看上面的错误信息，或 runtime/logs/portable.log"
  read -r -n 1 -p "按任意键关闭..."
fi
exit $status
