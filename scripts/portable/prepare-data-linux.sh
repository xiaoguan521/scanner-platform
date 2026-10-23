#!/bin/bash
# Downloads and activates vulnerability data on a computer with internet access. Never scans.
cd "$(dirname "$0")" || exit 1
if [[ "$(uname -s)" == Darwin ]]; then
  xattr -dr com.apple.quarantine . 2>/dev/null || true
fi
chmod +x ./sec-portable ./bin/* 2>/dev/null || true
echo "正在联网准备漏洞库（约 1 GB，不扫描任何目标）..."
if ./sec-portable prepare --with-java-db; then
  echo "完成，现在可以启动 sec-portable。"
else
  echo "准备失败：请确认能访问互联网，并且没有正在运行的 sec-portable。"
fi
read -r -n 1 -p "按任意键关闭..."
