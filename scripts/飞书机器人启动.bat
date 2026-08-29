@echo off
chcp 65001 >nul
cd /d "%~dp0\.."

if defined NGROK_DOMAIN goto ngrok_domain_ready
echo  [!] NGROK_DOMAIN is required. Example:
echo      set "NGROK_DOMAIN=your-ngrok-domain.example"
exit /b 1

:ngrok_domain_ready
echo.
echo  ╔════════════════════════════════════════════════╗
echo  ║     防务追踪系统  飞书机器人模式               ║
echo  ╚════════════════════════════════════════════════╝
echo.

:: ── 检查配置 ─────────────────────────────────────────────
if not defined FEISHU_APP_ID (
    echo  [!] 请先设置飞书应用凭证：
    echo.
    set /p FEISHU_APP_ID=  输入 App ID    :
    set /p FEISHU_APP_SECRET=  输入 App Secret:
    echo.
)

echo.
echo  启动安全守护程序；ngrok 必须位于本机 PATH 的绝对目录中。
echo  按 Ctrl+C 可同时停止追踪系统和 ngrok。
py -3 scripts\auto_start.py
set "SUPERVISOR_EXIT=%ERRORLEVEL%"
if not "%SUPERVISOR_EXIT%"=="0" echo  [!] 守护程序退出码：%SUPERVISOR_EXIT%
pause
exit /b %SUPERVISOR_EXIT%
