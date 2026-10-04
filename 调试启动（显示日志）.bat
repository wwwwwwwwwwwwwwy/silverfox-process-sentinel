@echo off
chcp 936 >nul
title 银狐进程监视器 - 调试模式（显示日志）
cd /d "%~dp0"
setlocal enabledelayedexpansion

set "PYEXE="

if exist "%~dp0python_path.txt" (
  set "CFGPY="
  set /p CFGPY=<"%~dp0python_path.txt"
  if defined CFGPY if exist "!CFGPY!" (
    "!CFGPY!" -c "import psutil" >nul 2>nul
    if not errorlevel 1 set "PYEXE=!CFGPY!"
  )
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
  echo  [错误] 没有找到「已安装 psutil 的 Python 3.11+」。
  echo  请安装 Python 3.11+ 并执行：  pip install psutil
  echo  或在本目录建 python_path.txt 写明解释器完整路径。
  echo.
  pause
  exit /b 1
)

echo ============================================================
echo  使用解释器 : !PYEXE!
echo  启动中，请稍候……界面会在首次扫描完成后自动打开
echo  关闭本窗口即停止监视器
echo ============================================================
echo.
"!PYEXE!" "%~dp0app\main.py"
echo.
echo 监视器已退出。按任意键关闭窗口。
pause >nul
