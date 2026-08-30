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


UNSIGNED_DEVELOPMENT_COMPANY_NAME = (
    "DefenseTracker Community Edition (Unsigned Development Build)"
)


def _validated_company_name(value: str) -> str:
    company_name = value.strip()
    if not company_name or len(company_name) > 160:
        raise ValueError("CompanyName must be non-empty and at most 160 characters")
    if any(ord(char) < 32 for char in company_name):
        raise ValueError("CompanyName contains a control character")
    return company_name


def render_version_info(
    version: ProductVersion,
    company_name: str,
    *,
    unsigned_development: bool = False,
) -> str:
    company_name = _validated_company_name(company_name)
    if unsigned_development:
        if company_name != UNSIGNED_DEVELOPMENT_COMPANY_NAME:
            raise ValueError(
                "Unsigned development builds must use the fixed non-identity CompanyName"
            )
        copyright_text = (
            "Unsigned development build; no publisher identity asserted"
        )
    else:
        if company_name == UNSIGNED_DEVELOPMENT_COMPANY_NAME:
            raise ValueError(
                "The unsigned development CompanyName cannot be used for signed builds"
            )
        copyright_text = f"Copyright (c) 2026 {company_name}"
    file_version = version.windows_file_version_tuple
    product_version = (*file_version[:3], 0)
    strings = {
        "CompanyName": company_name,
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
    identity = parser.add_mutually_exclusive_group(required=True)
    identity.add_argument("--company-name")
    identity.add_argument("--publisher")
    parser.add_argument("--unsigned-development", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version-file", type=Path, default=PROJECT_ROOT / "version.json")
    args = parser.parse_args()
    if args.unsigned_development and args.publisher is not None:
        parser.error("--publisher cannot be used for an unsigned development build")
    company_name = args.company_name or args.publisher
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    version = load_product_version(args.version_file)
    output.write_text(
        render_version_info(
            version,
            company_name,
            unsigned_development=args.unsigned_development,
        ),
        encoding="utf-8",
        newline="\n",
    )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
