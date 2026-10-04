@echo off
chcp 65001 >nul
title SilverFox Process Sentinel
cd /d "%~dp0"

rem ============================================================
rem  SilverFox Process Sentinel - launcher
rem  Requires Python 3.11+ with psutil installed.
rem
rem  Interpreter lookup order:
rem    1. python_path.txt  (explicit path; use this for venv/conda)
rem    2. runtime\pythonw.exe  (bundled portable Python)
rem    3. Windows "py" launcher (3.14 -> 3.11 -> any 3.x)
rem    4. pythonw on PATH
rem  Every candidate is verified with `import psutil` before use.
rem
rem  NOTE: keep this file ASCII-only. cmd.exe reads .bat using the
rem  console codepage; non-ASCII text would break on some systems.
rem ============================================================

if not exist "%~dp0app\main.py" (
  echo.
  echo  [ERROR] app\main.py not found - the project files are incomplete.
  echo  Keep this .bat in the same folder as the "app" directory.
  echo.
  pause
  exit /b 1
)

rem Read the config BEFORE setlocal enabledelayedexpansion:
rem delayed expansion would eat "!" characters inside the path.
set "CFGPY="
if exist "%~dp0python_path.txt" set /p CFGPY=<"%~dp0python_path.txt"

setlocal enabledelayedexpansion
set "PYEXE="

rem --- candidate 1: explicit path from python_path.txt ---
if defined CFGPY (
  if exist "!CFGPY!" (
    "!CFGPY!" -c "import psutil" >nul 2>nul
    if not errorlevel 1 set "PYEXE=!CFGPY!"
  )
)

rem --- candidate 2: bundled interpreter ---
if not defined PYEXE if exist "%~dp0runtime\pythonw.exe" (
  "%~dp0runtime\pythonw.exe" -c "import psutil" >nul 2>nul
  if not errorlevel 1 set "PYEXE=%~dp0runtime\pythonw.exe"
)

rem --- candidate 3: Windows py launcher ---
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

rem --- candidate 4: pythonw on PATH ---
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
  echo  [ERROR] No Python 3.11+ with psutil was found.
  echo.
  echo  Option 1 - install psutil into your system Python:
  echo      https://www.python.org/downloads/   ^(check "Add Python to PATH"^)
  echo      pip install psutil
  echo.
  echo  Option 2 - using venv / conda? Create python_path.txt in this
  echo      folder containing the full path to the interpreter, e.g.
  echo      D:\myenv\Scripts\pythonw.exe
  echo.
  echo  Tip: if several Pythons are installed, make sure psutil is
  echo       installed for the one you intend to use.
  echo.
  pause
  exit /b 1
)

rem Show the interpreter actually used - if it was swapped for something
rem unfamiliar, you will see it here.
echo  Interpreter: !PYEXE!
start "" "!PYEXE!" "%~dp0app\main.py"
exit /b 0
