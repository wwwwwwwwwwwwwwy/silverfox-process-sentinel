@echo off
rem ============================================================================
rem  银狐进程监视器 - 本机副本管理 / 更新
rem
rem  NOTE: keep this file ASCII-only. cmd.exe reads .bat using the console
rem        codepage; non-ASCII bytes get mangled and the script silently fails.
rem
rem  What it does:
rem    1. lists every copy of the tool on this machine, with version + fingerprint
rem    2. reports junk left by the packed exe (_MEI* folders) and stale copies
rem    3. optionally cleans them, or overwrites an older copy with a newer one
rem
rem  It NEVER touches: %LOCALAPPDATA%\SilverFoxSentinel (whitelist, baseline,
rem  reports) and python_path.txt / the 备份 folder inside a copy.
rem ============================================================================
setlocal
cd /d "%~dp0"

set "PYEXE="
if exist "%~dp0python_path.txt" set /p CFGPY=<"%~dp0python_path.txt"
if defined CFGPY if exist "%CFGPY%" set "PYEXE=%CFGPY%"
if not defined PYEXE if exist "%~dp0runtime\pythonw.exe" (
  "%~dp0runtime\pythonw.exe" -c "import psutil" >nul 2>nul
  if not errorlevel 1 set "PYEXE=%~dp0runtime\pythonw.exe"
)
if not defined PYEXE for /f "delims=" %%i in ('where python.exe 2^>nul') do (
  if not defined PYEXE set "PYEXE=%%i"
)
if not defined PYEXE (
  echo [ERROR] Python not found. Put its full path into python_path.txt
  echo         next to this .bat file, e.g.  D:\myenv\Scripts\python.exe
  echo.
  pause
  exit /b 1
)

echo.
echo ==========================================================================
echo   Scan only - nothing will be changed.
echo ==========================================================================
"%PYEXE%" "%~dp0本机副本管理.py"
if errorlevel 1 goto done

echo.
echo --------------------------------------------------------------------------
echo   Next steps (copy a line and run it in this folder if you need to):
echo.
echo     Clean junk (packed-exe leftovers, stale packed exe, Temp copies):
echo         "%PYEXE%" "%~dp0本机副本管理.py" --clean
echo.
echo     Overwrite an older copy with a newer one:
echo         "%PYEXE%" "%~dp0本机副本管理.py" --update "D:\path\to\newer\copy"
echo.
echo   Both ask for confirmation before deleting anything.
echo --------------------------------------------------------------------------

:done
echo.
pause
endlocal
