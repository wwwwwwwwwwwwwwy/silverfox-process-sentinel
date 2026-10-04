@echo off
chcp 65001 >nul
title SilverFox Process Sentinel - debug mode
cd /d "%~dp0"

rem Keep this file ASCII-only (see the main launcher for the reason).

set "CFGPY="
if exist "%~dp0python_path.txt" set /p CFGPY=<"%~dp0python_path.txt"

setlocal enabledelayedexpansion
set "PYEXE="

if defined CFGPY if exist "!CFGPY!" (
  "!CFGPY!" -c "import psutil" >nul 2>nul
  if not errorlevel 1 set "PYEXE=!CFGPY!"
)

if not defined PYEXE if exist "%~dp0runtime\python.exe" (
  "%~dp0runtime\python.exe" -c "import psutil" >nul 2>nul
  if not errorlevel 1 set "PYEXE=%~dp0runtime\python.exe"
)

if not defined PYEXE (
  for %%v in (3.14 3.13 3.12 3.11 3) do (
    if not defined PYEXE (
      for /f "delims=" %%i in ('py -%%v -c "import sys;print(sys.executable)" 2^>nul') do (
        if not defined PYEXE (
          set "CAND=%%i"
          if exist "!CAND!" (
            "!CAND!" -c "import psutil" >nul 2>nul
            if not errorlevel 1 set "PYEXE=!CAND!"
          )
        )
      )
    )
  )
)

if not defined PYEXE (
  for /f "delims=" %%i in ('where python.exe 2^>nul') do (
    if not defined PYEXE (
      "%%i" -c "import psutil" >nul 2>nul
      if not errorlevel 1 set "PYEXE=%%i"
    )
  )
)

if not defined PYEXE (
  echo.
  echo  [ERROR] No Python 3.11+ with psutil was found.
  echo  Install Python 3.11+ and run:  pip install psutil
  echo  Or create python_path.txt here with the full interpreter path.
  echo.
  pause
  exit /b 1
)

echo ============================================================
echo  Interpreter : !PYEXE!
echo  Starting... the window opens after the first scan.
echo  Close this console window to stop the monitor.
echo ============================================================
echo.
"!PYEXE!" "%~dp0app\main.py"
echo.
echo Monitor exited. Press any key to close.
pause >nul
