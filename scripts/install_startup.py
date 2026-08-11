"""
安装开机自启动 - 在 Windows 启动文件夹中创建 VBS 启动脚本
运行一次即可，重启电脑后追踪系统将自动启动
"""

import os
import sys


def get_startup_folder():
    """获取 Windows 启动文件夹路径"""
    # 通过环境变量拼接
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        return os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    # 备用方案
    return os.path.expanduser(
        r"~\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    )


def main():
    # 项目根目录
    project_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(project_dir)  # scripts/ -> 项目根
    ngrok_domain = os.environ.get("NGROK_DOMAIN", "").strip()

    auto_start_script = os.path.join(project_dir, "scripts", "auto_start.py")
    if not os.path.isfile(auto_start_script):
        print(f"[错误] 找不到守护脚本: {auto_start_script}")
        sys.exit(1)

    startup_folder = get_startup_folder()
    if not os.path.isdir(startup_folder):
        print(f"[错误] 启动文件夹不存在: {startup_folder}")
        sys.exit(1)

    vbs_name = "追踪系统_AutoStart.vbs"
    vbs_path = os.path.join(startup_folder, vbs_name)

    # VBS 内容：静默启动 pythonw 运行守护脚本（无黑窗口）
    # 使用 pythonw 避免控制台窗口
    pythonw_path = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    if not os.path.isfile(pythonw_path):
        # 如果找不到 pythonw，回退到 python
        pythonw_path = sys.executable
        print(f"[警告] 未找到 pythonw.exe，将使用 {pythonw_path} (可能会显示窗口)")

    # VBS 脚本内容
    vbs_content = f'''Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "{project_dir}"
WshShell.Run """{pythonw_path}"" scripts/auto_start.py", 0, False
'''

    # 写入 VBS 文件
    with open(vbs_path, "w", encoding="utf-8") as f:
        f.write(vbs_content)

    print("=" * 55)
    print("  追踪系统 - 开机自启动安装成功!")
    print("=" * 55)
    print()
    print(f"  VBS 文件:    {vbs_path}")
    print(f"  守护脚本:    {auto_start_script}")
    print(f"  Python:      {pythonw_path}")
    print(f"  项目目录:    {project_dir}")
    print()
    print("  启动后将自动运行:")
    print("    1. app.py   (Flask 服务, 端口 5000)")
    print("    2. ngrok    (隧道)")
    print()
    print("  飞书 Webhook 地址:")
    if ngrok_domain:
        print(f"    https://{ngrok_domain}/api/feishu/webhook")
    else:
        print("    未配置；请设置 NGROK_DOMAIN=your-ngrok-domain.example")
    print()
    print("  下次重启电脑即可生效!")
    print("  也可以现在双击 scripts/auto_start.py 手动测试。")
    print("=" * 55)


if __name__ == "__main__":
    main()
