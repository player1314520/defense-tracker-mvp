# -*- coding: utf-8 -*-
"""Generate the exact unsigned onedir inventory used for legal review."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

if __package__:
    from .authenticode_digest import inspect_authenticode_image
else:
    from authenticode_digest import inspect_authenticode_image


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def generate(root: Path, destination: Path) -> dict[str, object]:
    root = root.resolve()
    destination = destination.resolve()
    if not root.is_dir():
        raise ValueError("Component inventory root is not a directory")
    files: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda value: value.as_posix().lower()):
        if path.is_symlink():
            raise ValueError("Component inventory does not allow symbolic links")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        entry: dict[str, object] = {
            "path": relative,
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        if relative == "DefenseTracker.exe":
            inspected = inspect_authenticode_image(path, require_state="unsigned")
            entry["authenticode_neutral_sha256"] = inspected.normalized_sha256
        files.append(entry)
    if not files or not any(item["path"] == "DefenseTracker.exe" for item in files):
        raise ValueError("Component inventory is missing DefenseTracker.exe")
    payload: dict[str, object] = {"schema": 2, "files": files}
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temporary, destination)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    generate(args.root, args.destination)
    print("component-inventory: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
