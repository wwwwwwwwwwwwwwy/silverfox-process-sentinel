@echo off
chcp 936 >nul
title 停止银狐进程监视器
cd /d "%~dp0"

setlocal enabledelayedexpansion
set "PORT="
set "TOKEN="
if exist "%~dp0runtime_port.txt" set /p PORT=<"%~dp0runtime_port.txt"
if exist "%~dp0runtime_token.txt" set /p TOKEN=<"%~dp0runtime_token.txt"

if not defined TOKEN (
  echo.
  echo  [提示] 未找到会话令牌文件（runtime_token.txt），监视器可能未在运行。
  echo  若界面窗口仍开着，直接关闭窗口即可。
  echo.
  timeout /t 3 >nul
  exit /b 0
)

if defined PORT (
  curl -s -m 2 -X POST -H "X-Yinhu-Token: !TOKEN!" -H "Content-Type: application/json" -d "{}" "http://127.0.0.1:!PORT!/api/shutdown" >nul 2>nul
  echo  已向端口 !PORT! 发送退出指令。
) else (
  echo  端口文件缺失，扫描默认端口段 8787-8816…
  for /l %%p in (8787,1,8816) do (
    curl -s -m 1 -X POST -H "X-Yinhu-Token: !TOKEN!" -H "Content-Type: application/json" -d "{}" "http://127.0.0.1:%%p/api/shutdown" >nul 2>nul
  )
  echo  已扫描默认端口段。
)

echo.
echo  已发送退出指令。若窗口仍未关闭，直接点右上角关闭即可。
timeout /t 2 >nul
exit /b 0
