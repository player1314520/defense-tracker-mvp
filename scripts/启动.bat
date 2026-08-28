@echo off
chcp 65001 >nul
echo.
echo  ╔══════════════════════════════════════╗
echo  ║  🛡️  防务数据追踪系统               ║
echo  ║  正在启动，请稍候...                ║
echo  ╚══════════════════════════════════════╝
echo.
echo  提示：设置AI分析功能，请配置环境变量：
echo    set AI_API_KEY=你的API密钥
echo    set AI_BASE_URL=https://api.deepseek.com
echo    set AI_MODEL=deepseek-chat
echo  或在网页中点击 🤖AI分析 标签页 → ⚙️配置AI
echo.
cd /d "%~dp0\.."
py app.py
pause
