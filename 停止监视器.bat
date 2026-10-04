@echo off
chcp 65001 >nul
title SilverFox Process Sentinel - stop
cd /d "%~dp0"

rem Runtime data lives in the per-user data directory, NOT next to the
rem program (the program folder can be locked down to admins-only).
set "DATA=%LOCALAPPDATA%\SilverFoxSentinel"
if not exist "%DATA%\runtime_port.txt" if exist "%~dp0runtime_port.txt" set "DATA=%~dp0"

setlocal enabledelayedexpansion
set "PORT="
set "TOKEN="
if exist "%DATA%\runtime_port.txt" set /p PORT=<"%DATA%\runtime_port.txt"
if exist "%DATA%\runtime_token.txt" set /p TOKEN=<"%DATA%\runtime_token.txt"

if not defined TOKEN (
  echo.
  echo  [INFO] runtime_token.txt not found - the monitor is probably not running.
  echo  Looked in: %DATA%
  echo  If the window is still open, just close it.
  echo.
  timeout /t 3 >nul
  exit /b 0
)

if defined PORT (
  curl -s -m 2 -X POST -H "X-Yinhu-Token: !TOKEN!" -H "Content-Type: application/json" -d "{}" "http://127.0.0.1:!PORT!/api/shutdown" >nul 2>nul
  echo  Shutdown request sent to port !PORT!.
) else (
  echo  Port file missing - scanning the default range 8787-8816...
  for /l %%p in (8787,1,8816) do (
    curl -s -m 1 -X POST -H "X-Yinhu-Token: !TOKEN!" -H "Content-Type: application/json" -d "{}" "http://127.0.0.1:%%p/api/shutdown" >nul 2>nul
  )
  echo  Default port range scanned.
)

echo.
echo  Done. If the window is still open, just close it.
timeout /t 2 >nul
exit /b 0
