#!/usr/bin/env python3
"""Materialize a secret-free Portal Docker context from one Git commit.

The context is intentionally generated from ``git show HEAD:<path>`` instead
of the working tree. Uncommitted source, ignored assets and local configuration
therefore cannot enter the Docker build context by accident.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BUILD_ROOT = PROJECT_ROOT / "build"
CONTEXT_ROOT = BUILD_ROOT / "mvp-portal-context"
EXACT_FILES = {
    "product_version.py",
    "version.json",
    "v9_cloud.py",
    "feishu_webhook_security.py",
    "deploy/requirements.cloud.txt",
    "deploy/mvp/portal.Dockerfile",
    "deploy/mvp/portal-entrypoint.sh",
}
TREE_PREFIXES = ("v9/", "web/v9-portal/")
FORBIDDEN_PARTS = {
    ".git",
    ".env",
    ".access_token",
    ".ai_config.json",
    ".ai_config.key",
    ".feishu_config.json",
    ".supabase_v9_config.json",
    ".v9_local_master.key",
    "素材库",
    "归档",
    "tests",
}
FORBIDDEN_SUFFIXES = {".key", ".pem", ".pfx", ".p12", ".kdbx", ".sqlite", ".db"}
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(
        rb"(?<![A-Za-z0-9_-])(?:sk-(?:proj-)?|ghp_)[A-Za-z0-9_-]{16,}"
        rb"(?![A-Za-z0-9_-])",
        re.IGNORECASE,
    ),
    re.compile(
        rb"(?<![A-Za-z0-9_-])sb_secret_[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])",
        re.IGNORECASE,
    ),
)


def _git(*args: str, binary: bool = False) -> bytes | str:
    result = subprocess.run(
        ["git", "-C", str(PROJECT_ROOT), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout if binary else result.stdout.decode("utf-8").strip()


def _included(path: str) -> bool:
    return path in EXACT_FILES or path.startswith(TREE_PREFIXES)


def _tracked_files() -> list[str]:
    names = str(
        _git(
            "ls-tree",
            "-r",
            "--name-only",
            "HEAD",
            "--",
            "v9_cloud.py",
            "feishu_webhook_security.py",
            "product_version.py",
            "version.json",
            "v9",
            "web/v9-portal",
            "deploy/requirements.cloud.txt",
            "deploy/mvp/portal.Dockerfile",
            "deploy/mvp/portal-entrypoint.sh",
        )
    ).splitlines()
    files = sorted(name.strip().replace("\\", "/") for name in names if name.strip())
    unexpected = [path for path in files if not _included(path)]
    if unexpected:
        raise SystemExit(f"unexpected path in Portal allowlist: {unexpected[0]}")
    missing = sorted(EXACT_FILES.difference(files))
    if missing:
        raise SystemExit(f"required committed Portal file is missing: {missing[0]}")
    if not any(path.startswith("v9/") for path in files):
        raise SystemExit("committed v9 package is empty")
    if not any(path.startswith("web/v9-portal/") for path in files):
        raise SystemExit("committed Portal assets are empty")
    for path in files:
        parts = set(Path(path).parts)
        path_object = Path(path)
        if (
            parts.intersection(FORBIDDEN_PARTS)
            or path_object.name.lower().startswith(".env")
            or path_object.suffix.lower() in FORBIDDEN_SUFFIXES
        ):
            raise SystemExit(f"forbidden path in Portal context: {path}")
        mode = str(_git("ls-tree", "HEAD", "--", path)).split(maxsplit=1)[0]
        if mode == "120000":
            raise SystemExit(f"symlinks are not allowed in Portal context: {path}")
    return files


def _assert_clean(files: list[str]) -> None:
    status = str(
        _git("status", "--porcelain", "--untracked-files=all", "--", *files)
    )
    if status:
        raise SystemExit(
            "Portal release inputs differ from HEAD; commit them before building"
        )


def _safe_reset_context() -> None:
    expected = (BUILD_ROOT / "mvp-portal-context").resolve()
    actual = CONTEXT_ROOT.resolve()
    if actual != expected or actual.parent != BUILD_ROOT.resolve():
        raise SystemExit(f"refusing to reset unexpected context path: {actual}")
    if actual.exists():
        item_count = sum(1 for _ in actual.rglob("*"))
        print(f"[CONTEXT] Replacing generated context ({item_count} existing items).")
        shutil.rmtree(actual)
    actual.mkdir(parents=True, mode=0o700)


def prepare(*, check_only: bool) -> dict[str, object]:
    commit = str(_git("rev-parse", "HEAD"))
    if len(commit) != 40:
        raise SystemExit("unable to resolve a full Git commit SHA")
    files = _tracked_files()
    _assert_clean(files)
    source_tree = str(_git("rev-parse", f"{commit}^{{tree}}"))
    commit_epoch = int(str(_git("show", "-s", "--format=%ct", commit)))
    metadata: dict[str, object] = {
        "schema": 2,
        "commit": commit,
        "source_tree": source_tree,
        "source_date_epoch_utc": datetime.fromtimestamp(commit_epoch, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "context_files": [],
    }
    if check_only:
        return metadata | {"context_files": files}

    _safe_reset_context()
    file_entries: list[dict[str, object]] = []
    for relative in files:
        payload = bytes(_git("show", f"HEAD:{relative}", binary=True))
        if any(pattern.search(payload) for pattern in SECRET_PATTERNS):
            raise SystemExit(f"high-confidence secret content in Portal input: {relative}")
        destination = CONTEXT_ROOT / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        file_entries.append(
            {
                "path": relative,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    metadata["context_files"] = file_entries
    (CONTEXT_ROOT / "build-metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"[CONTEXT] Git SHA: {commit}")
    print(f"[CONTEXT] Files: {len(file_entries)}")
    print(f"[CONTEXT] Output: {CONTEXT_ROOT}")
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="validate the committed allowlist without writing build output",
    )
    args = parser.parse_args()
    prepare(check_only=args.check_only)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
