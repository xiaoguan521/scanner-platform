@echo off
rem Double-click to start sec-portable; the browser opens the web console.
chcp 65001 >nul
cd /d "%~dp0"
echo 正在启动 sec-portable，关闭本窗口或按 Ctrl+C 即退出。
"%~dp0sec-portable.exe" %*
if errorlevel 1 (
  echo.
  echo 启动失败，请查看上面的错误信息，或 runtime\logs\portable.log
  pause
)
