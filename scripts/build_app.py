# -*- coding: utf-8 -*-
"""Secret-free PyInstaller entrypoint for the DefenseTracker desktop client.

The script performs packaging only. Dependency installation belongs exclusively
to Prepare-BuildEnv.ps1 and release promotion belongs to Build-AndShip.ps1.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


BASE = Path(__file__).resolve().parents[1]
BUILD_ROOT = BASE / "build"
STAGING_ROOT = BUILD_ROOT / "release-staging"
WORK_ROOT = BUILD_ROOT / "pyinstaller"
SPEC_ROOT = BUILD_ROOT / "pyinstaller-spec"
EXPECTED_VENV = (BASE / ".venv-build").resolve()


def _assert_isolated_toolchain() -> None:
    prefix = Path(sys.prefix).resolve()
    if prefix != EXPECTED_VENV:
        raise SystemExit(
            "Refusing to build outside the isolated .venv-build toolchain. "
            "Run scripts/Prepare-BuildEnv.ps1 first."
        )


def _reset_staging() -> None:
    BUILD_ROOT.mkdir(parents=True, exist_ok=True)
    resolved = STAGING_ROOT.resolve()
    if resolved.parent != BUILD_ROOT.resolve():
        raise SystemExit(f"Unexpected staging path: {resolved}")
    if resolved.exists():
        shutil.rmtree(resolved)
    resolved.mkdir(parents=True)
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    SPEC_ROOT.mkdir(parents=True, exist_ok=True)


def _pyinstaller_args() -> list[str]:
    args = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name",
        "DefenseTracker",
        "--windowed",
        "--noconfirm",
        "--clean",
        "--distpath",
        str(STAGING_ROOT),
        "--workpath",
        str(WORK_ROOT),
        "--specpath",
        str(SPEC_ROOT),
        "--add-data",
        f"{BASE / 'templates'}{os.pathsep}templates",
        "--add-data",
        f"{BASE / 'static'}{os.pathsep}static",
        "--collect-submodules",
        "webview",
        "--collect-submodules",
        "apscheduler",
        "--collect-data",
        "reportlab",
    ]
    icon = BASE / "app_icon.ico"
    if icon.is_file():
        args.extend(["--icon", str(icon)])

    hidden_imports = (
        "feedparser",
        "feedparser.mixin",
        "apscheduler.schedulers.background",
        "apscheduler.executors.pool",
        "apscheduler.jobstores.base",
        "apscheduler.triggers.interval",
        "bs4.builder._htmlparser",
        "requests",
        "webview",
        "webview.platforms.winforms",
        "webview.platforms.edgechromium",
        "docx",
        "openpyxl",
        "openpyxl.styles",
        "openpyxl.utils",
        "pdfplumber",
        "cryptography",
        "cryptography.fernet",
        "report_agent",
        "consulting_agent",
        "search_adapters",
        "quality",
        "state",
        "v9.api",
        "v9.crypto",
        "v9.repository",
        "v9.service",
    "v9.situation",
    "v9.alerts",
    "v9.workflow",
    "v9.orchestration",
    )
    for module in hidden_imports:
        args.extend(["--hidden-import", module])

    excluded_modules = (
        "torch",
        "torchvision",
        "torchaudio",
        "scipy",
        "pandas",
        "matplotlib",
        "numba",
        "llvmlite",
        "onnxruntime",
        "pyarrow",
        "sqlalchemy",
        "IPython",
        "jupyter",
        "notebook",
        "sklearn",
        "cv2",
        "tkinter",
        "PySide2",
        "PySide6",
        "PyQt5",
        "PyQt6",
        "tensorboard",
    )
    for module in excluded_modules:
        args.extend(["--exclude-module", module])

    args.append(str(BASE / "launcher.py"))
    return args


def main() -> int:
    _assert_isolated_toolchain()
    _reset_staging()
    print(f"[BUILD] Isolated Python: {sys.executable}")
    print(f"[BUILD] Staging only: {STAGING_ROOT}")
    result = subprocess.run(_pyinstaller_args(), cwd=BASE, check=False)
    if result.returncode:
        return result.returncode
    expected = STAGING_ROOT / "DefenseTracker" / "DefenseTracker.exe"
    if not expected.is_file() or expected.stat().st_size == 0:
        print(f"[BUILD] Expected executable missing: {expected}", file=sys.stderr)
        return 2
    print(f"[BUILD] Staged executable: {expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
