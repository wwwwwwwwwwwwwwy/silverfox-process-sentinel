@echo off
chcp 936 >nul
title 银狐进程监视器
cd /d "%~dp0"
setlocal enabledelayedexpansion

rem ============================================================
rem  启动银狐进程监视器
rem  需要 Python 3.11+，并且**该解释器**已安装 psutil
rem
rem  解释器查找顺序：
rem    1. python_path.txt 里指定的路径（用 venv/conda 时写这里）
rem    2. 项目内 runtime\pythonw.exe
rem    3. Windows 官方 py 启动器（3.14 → 3.11 → 任意 3.x）
rem    4. 系统 PATH 里的 pythonw
rem  每个候选都会先验证 `import psutil` 是否成功。
rem ============================================================

if not exist "%~dp0app\main.py" (
  echo.
  echo  [错误] 未找到 app\main.py，项目文件不完整。
  echo  请保持本 bat 与 app 目录在同一文件夹内。
  echo.
  pause
  exit /b 1
)

set "PYEXE="

rem 候选 1：python_path.txt 显式指定
if exist "%~dp0python_path.txt" (
  set "CFGPY="
  set /p CFGPY=<"%~dp0python_path.txt"
  if defined CFGPY (
    if exist "!CFGPY!" (
      "!CFGPY!" -c "import psutil" >nul 2>nul
      if not errorlevel 1 set "PYEXE=!CFGPY!"
    )
  )
)

rem 候选 2：项目内随附的解释器
if not defined PYEXE if exist "%~dp0runtime\pythonw.exe" (
  "%~dp0runtime\pythonw.exe" -c "import psutil" >nul 2>nul
  if not errorlevel 1 set "PYEXE=%~dp0runtime\pythonw.exe"
)

rem 候选 3：官方 py 启动器，按版本从新到旧
if not defined PYEXE (
  for %%v in (3.14 3.13 3.12 3.11 3) do (
    if not defined PYEXE (
      for /f "delims=" %%i in ('py -%%v -c "import sys;print(sys.executable)" 2^>nul') do (
        if not defined PYEXE (
          set "CAND=%%~dpipythonw.exe"
          if exist "!CAND!" (
            "!CAND!" -c "import psutil" >nul 2>nul
            if not errorlevel 1 set "PYEXE=!CAND!"
          )
        )
      )
    )
  )
)

rem 候选 4：PATH 里的 pythonw
if not defined PYEXE (
  for /f "delims=" %%i in ('where pythonw.exe 2^>nul') do (
    if not defined PYEXE (
      "%%i" -c "import psutil" >nul 2>nul
      if not errorlevel 1 set "PYEXE=%%i"
    )
  )
)

if not defined PYEXE (
  echo.
  echo  [错误] 没有找到「已安装 psutil 的 Python 3.11+」。
  echo.
  echo  办法一：给系统 Python 装上 psutil
  echo      安装 Python 3.11+（https://www.python.org/downloads/）
  echo      安装时勾选 "Add Python to PATH"，然后执行：
  echo          pip install psutil
  echo.
  echo  办法二：用 venv / conda 的话，在项目根目录建一个 python_path.txt，
  echo          里面写解释器的完整路径，例如：
  echo          D:\myenv\Scripts\pythonw.exe
  echo.
  echo  提示：本机若装了多个 Python，请确认 psutil 装在了你要用的那个上。
  echo.
  pause
  exit /b 1
)

start "" "!PYEXE!" "%~dp0app\main.py"
exit /b 0
