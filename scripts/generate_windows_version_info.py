# -*- coding: utf-8 -*-
"""Generate the PyInstaller VersionInfo resource from version.json."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from product_version import ProductVersion, load_product_version  # noqa: E402


def _validated_publisher(value: str) -> str:
    publisher = value.strip()
    if not publisher or len(publisher) > 160:
        raise ValueError("Publisher must be a non-empty legal name of at most 160 characters")
    if any(ord(char) < 32 for char in publisher):
        raise ValueError("Publisher contains a control character")
    return publisher


def render_version_info(version: ProductVersion, publisher: str) -> str:
    publisher = _validated_publisher(publisher)
    file_version = version.windows_file_version_tuple
    product_version = (*file_version[:3], 0)
    copyright_text = f"Copyright (c) 2026 {publisher}"
    strings = {
        "CompanyName": publisher,
        "FileDescription": f"{version.product_name} {version.display_version}",
        "FileVersion": version.windows_file_version,
        "InternalName": version.product_name,
        "LegalCopyright": copyright_text,
        "OriginalFilename": f"{version.product_name}.exe",
        "ProductName": version.product_name,
        "ProductVersion": version.semantic_version,
    }
    string_entries = ",\n".join(
        f"StringStruct({key!r}, {value!r})" for key, value in strings.items()
    )
    return f"""# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={file_version!r},
    prodvers={product_version!r},
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable('040904B0', [
        {string_entries}
      ])
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--publisher", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version-file", type=Path, default=PROJECT_ROOT / "version.json")
    args = parser.parse_args()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    version = load_product_version(args.version_file)
    output.write_text(
        render_version_info(version, args.publisher),
        encoding="utf-8",
        newline="\n",
    )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
