@echo off
chcp 65001 >nul
cd /d "%~dp0\.."

if not defined NGROK_EXE set "NGROK_EXE=ngrok"
if defined NGROK_DOMAIN goto ngrok_domain_ready
echo  [!] NGROK_DOMAIN is required. Example:
echo      set "NGROK_DOMAIN=your-ngrok-domain.example"
exit /b 1

:ngrok_domain_ready
set "WEBHOOK_URL=https://%NGROK_DOMAIN%/api/feishu/webhook"

echo.
echo  ╔════════════════════════════════════════════════╗
echo  ║     防务追踪系统  飞书机器人模式               ║
echo  ╚════════════════════════════════════════════════╝
echo.

:: ── 检查配置 ─────────────────────────────────────────────
if "%FEISHU_APP_ID%"=="" (
    echo  [!] 请先设置飞书应用凭证：
    echo.
    set /p FEISHU_APP_ID=  输入 App ID    :
    set /p FEISHU_APP_SECRET=  输入 App Secret:
    echo.
)

:: ── 检查系统是否已在运行 ──────────────────────────────────
netstat -ano | findstr ":5000" | findstr "LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo  [1/2] 追踪系统已在运行，跳过启动...
    goto start_ngrok
)

:: ── 启动追踪系统 ──────────────────────────────────────────
echo  [1/2] 启动防务追踪系统（后台）...
start /min "DefenseTracker" py app.py
timeout /t 4 /nobreak >nul

:start_ngrok
:: ── 启动 ngrok 固定域名 ────────────────────────────────────
echo  [2/2] 启动 ngrok 固定隧道...
if exist "%NGROK_EXE%" goto ngrok_ready
where "%NGROK_EXE%" >nul 2>&1
if errorlevel 1 (
    echo.
    echo  [!] 未找到 ngrok，请设置 NGROK_EXE 或将 ngrok 加入 PATH：%NGROK_EXE%
    pause
    exit /b 1
)

:ngrok_ready
start "ngrok" "%NGROK_EXE%" http --domain=%NGROK_DOMAIN% 5000

echo.
echo  ========================================
echo   系统已启动！
echo  ========================================
echo.
echo   固定 Webhook 地址（永不变化）：
echo   %WEBHOOK_URL%
echo.
echo   飞书开放平台设置：
echo   事件订阅 URL  → %WEBHOOK_URL%
echo   订阅事件      → im.message.receive_v1
echo.
echo   使用方法：
echo   将机器人加入群聊或私聊
echo   发送文章链接或正文，机器人自动回复要讯
echo  ========================================
echo.
pause
