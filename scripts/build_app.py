# -*- coding: utf-8 -*-
"""Secret-free PyInstaller entrypoint for the DefenseTracker desktop client.

The script performs packaging only. Dependency installation belongs exclusively
to Prepare-BuildEnv.ps1 and release promotion belongs to Build-AndShip.ps1.
"""
from __future__ import annotations

import os
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from product_version import PRODUCT_VERSION  # noqa: E402
from scripts.generate_windows_version_info import render_version_info  # noqa: E402


BUILD_ROOT = Path(os.environ.get("DEFENSE_TRACKER_BUILD_OUTPUT_ROOT", BASE / "build")).resolve()
STAGING_ROOT = BUILD_ROOT / "release-staging"
WORK_ROOT = BUILD_ROOT / "pyinstaller"
SPEC_ROOT = BUILD_ROOT / "pyinstaller-spec"
EXPECTED_VENV = Path(
    os.environ.get("DEFENSE_TRACKER_BUILD_TOOLCHAIN_ROOT", BASE / ".venv-build")
).resolve()
VERSION_INFO_FILE = BUILD_ROOT / "windows-version-info.txt"
BUILD_METADATA_FILE = BUILD_ROOT / "build-metadata.json"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _assert_isolated_toolchain() -> None:
    prefix = Path(sys.prefix).resolve()
    if prefix != EXPECTED_VENV:
        raise SystemExit(
            "Refusing to build outside the isolated .venv-build toolchain. "
            "Run scripts/Prepare-BuildEnv.ps1 first."
        )


def _required_build_value(name: str, *, pattern: re.Pattern[str] | None = None) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"Missing required build metadata: {name}")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise SystemExit(f"Invalid required build metadata: {name}")
    return value


def _write_generated_metadata() -> None:
    publisher = _required_build_value("DEFENSE_TRACKER_PUBLISHER")
    commit = _required_build_value("DEFENSE_TRACKER_EXPECTED_RELEASE_SHA", pattern=SHA_RE)
    source_tree = _required_build_value("DEFENSE_TRACKER_SOURCE_TREE", pattern=SHA_RE)
    source_date_epoch = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if not source_date_epoch.isdigit():
        raise SystemExit("SOURCE_DATE_EPOCH must be an integer Git commit timestamp")
    source_date_epoch_utc = datetime.fromtimestamp(
        int(source_date_epoch), tz=timezone.utc
    ).isoformat().replace(
        "+00:00", "Z"
    )
    VERSION_INFO_FILE.write_text(
        render_version_info(PRODUCT_VERSION, publisher), encoding="utf-8", newline="\n"
    )
    BUILD_METADATA_FILE.write_text(
        json.dumps(
            {
                "schema": 2,
                "commit": commit,
                "source_tree": source_tree,
                "source_date_epoch_utc": source_date_epoch_utc,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
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
    _write_generated_metadata()


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
        "--version-file",
        str(VERSION_INFO_FILE),
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
        "--add-data",
        f"{BASE / 'version.json'}{os.pathsep}.",
        "--add-data",
        f"{BUILD_METADATA_FILE}{os.pathsep}.",
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
        "protected_secrets",
        "wechat_runtime",
        "product_version",
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
