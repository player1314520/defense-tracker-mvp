# -*- coding: utf-8 -*-
"""Create a sanitized source release zip for this project.

The output intentionally excludes local secrets, Git history, build outputs,
agent worktrees, caches, and generated runtime files.
"""

from __future__ import annotations

import argparse
import subprocess
import zipfile
from pathlib import Path


EXCLUDED_DIRS = {
    ".git",
    ".claude",
    ".codex",
    ".vscode",
    ".idea",
    ".pytest_cache",
    "__pycache__",
    "build",
    "dist",
    "data",
    "ssl",
    "素材库",
    "归档",
    "archive",
}

EXCLUDED_NAMES = {
    ".access_token",
    ".ai_config.json",
    ".ai_config.key",
    ".feishu_config.json",
    ".supabase_config.json",
    ".supabase_v9_config.json",
    ".search_config.json",
    ".email_config.json",
    ".v9_local_master.key",
    ".env",
    "sessions.json",
    "test_output.docx",
}

EXCLUDED_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".log",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".ico",
    ".spec",
    ".key",
}


def should_include(path: Path, root: Path) -> bool:
    rel = path.relative_to(root)
    if any(part in EXCLUDED_DIRS for part in rel.parts):
        return False
    if path.name in EXCLUDED_NAMES or path.name.startswith(".env."):
        return False
    if path.suffix.lower() in EXCLUDED_SUFFIXES:
        return False
    if path.suffix.lower() == ".zip":
        return False
    return True


def make_release_zip(root: Path, output: Path) -> int:
    root = root.resolve()
    output = output.resolve()
    count = 0
    tracked = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8").split("\0")
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for relative in sorted(item for item in tracked if item):
            path = root / relative
            if not path.is_file():
                continue
            if path == output or not should_include(path, root):
                continue
            zf.write(path, path.relative_to(root.parent))
            count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a clean project release zip.")
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output zip path. Defaults to ../<project>_clean.zip",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    output = args.output or (root.parent / f"{root.name}_clean.zip")
    count = make_release_zip(root, output)
    print(f"Wrote {output} with {count} files")


if __name__ == "__main__":
    main()
