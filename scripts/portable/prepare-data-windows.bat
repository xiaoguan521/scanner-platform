@echo off
rem Downloads and activates vulnerability data on a computer with internet access. Never scans.
chcp 65001 >nul
cd /d "%~dp0"
echo 正在联网准备漏洞库（约 1 GB，不扫描任何目标）...
"%~dp0sec-portable.exe" prepare --with-java-db
if errorlevel 1 (
  echo 准备失败：请确认能访问互联网，并且没有正在运行的 sec-portable。
) else (
  echo 完成，现在可以双击 start-windows.bat 启动。
)
pause
