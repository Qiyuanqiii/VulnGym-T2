@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
if not exist "runtime\python\python.exe" (
  echo Portable Python is missing. Extract the entire submission ZIP first.
  exit /b 1
)
"runtime\python\python.exe" -X utf8 -B "launch_workbench.py" --read-only %*
endlocal
