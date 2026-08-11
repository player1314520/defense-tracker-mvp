"""
卸载开机自启动 - 删除 Windows 启动文件夹中的 VBS 文件
"""

import os
import sys


def get_startup_folder():
    """获取 Windows 启动文件夹路径"""
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        return os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    return os.path.expanduser(
        r"~\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    )


def main():
    startup_folder = get_startup_folder()
    vbs_name = "追踪系统_AutoStart.vbs"
    vbs_path = os.path.join(startup_folder, vbs_name)

    if os.path.isfile(vbs_path):
        os.remove(vbs_path)
        print("=" * 50)
        print("  追踪系统 - 开机自启动已卸载!")
        print("=" * 50)
        print()
        print(f"  已删除: {vbs_path}")
        print()
        print("  下次开机将不再自动启动追踪系统。")
        print("=" * 50)
    else:
        print("=" * 50)
        print("  未找到自启动文件，可能尚未安装。")
        print("=" * 50)
        print()
        print(f"  查找路径: {vbs_path}")
        print()


if __name__ == "__main__":
    main()
