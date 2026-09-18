@echo off
setlocal
call "%~dp0start.cmd" --network-mode direct %*
exit /b %errorlevel%
