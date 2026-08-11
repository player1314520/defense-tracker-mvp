@echo off
chcp 65001 >nul
cd /d "%~dp0\.."
echo.
echo  正在打包防务数据追踪系统...
echo.
py scripts\build_app.py
pause
