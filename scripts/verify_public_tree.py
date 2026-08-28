#!/usr/bin/env python3
"""Fail closed when a public Git snapshot contains known private material."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


FORBIDDEN_PATHS = {
    "AGENTS.md",
    "CLAUDE.md",
    "SUMMARY.md",
    "docs/TASKS.md",
    "docs/V9_IMPLEMENTATION_STATUS.md",
    "docs/V9_SUPABASE_STAGING.md",
    "docs/refactor-app-split.md",
    "docs/refactor-frontend-split.md",
    "docs/六代机外媒交叉素材.md",
    "docs/升级路线图.md",
    "scripts/generate_daily_brief_docx_20260611.py",
}
FORBIDDEN_PREFIXES = (
    "docs/release-evidence/",
    "docs/2026-",
)
FORBIDDEN_RUNTIME_NAMES = {
    ".access_token",
    ".brief_evidence.key",
    ".ai_config.json",
    ".ai_config.key",
    ".email_config.json",
    ".email_config.key",
    ".feishu_config.json",
    ".supabase_config.json",
    ".supabase_v9_config.json",
    ".v9_local_master.key",
}
FORBIDDEN_ARTIFACT_SUFFIXES = {
    ".7z",
    ".db",
    ".dll",
    ".docx",
    ".exe",
    ".p12",
    ".pdf",
    ".pfx",
    ".rar",
    ".sqlite",
    ".sqlite3",
    ".xlsx",
    ".zip",
}
EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63})"
)
ALLOWED_EMAIL_DOMAINS = {
    "example.com",
    "example.invalid",
    "example.test",
    "users.noreply.github.com",
}
ALLOWED_EMAIL_ADDRESSES = {
    "noreply@github.com",
}
CONTENT_RULES = {
    "local Windows path": re.compile(
        r"[A-Za-z]:[\\/](?:Users|HuaweiMoveData)[\\/]", re.IGNORECASE
    ),
    # The public maintainer handle is explicitly approved for community metadata.
    # Continue rejecting the same legacy numeric marker when it appears outside
    # that exact public handle (for example in copied account material).
    "unapproved legacy user marker": re.compile(
        r"(?<!player)131" + "4520", re.IGNORECASE
    ),
    "retired tunnel hostname": re.compile(
        "unclean-kasandra-" + "nonartistically\\.ngrok-free\\.dev",
        re.IGNORECASE,
    ),
}


def tracked_files(root: Path) -> list[str]:
    completed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    return sorted(
        item.decode("utf-8")
        for item in completed.stdout.split(b"\0")
        if item
    )


def audit(root: Path) -> list[str]:
    issues: list[str] = []
    for relative in tracked_files(root):
        normalized = relative.replace("\\", "/")
        name = Path(normalized).name
        if normalized in FORBIDDEN_PATHS or normalized.startswith(FORBIDDEN_PREFIXES):
            issues.append(f"forbidden public path: {normalized}")
            continue
        if name in FORBIDDEN_RUNTIME_NAMES or (
            name.startswith(".env") and not name.endswith(".example")
        ):
            issues.append(f"runtime secret filename: {normalized}")
            continue
        if name.endswith((".key", ".pem", ".p12", ".pfx")):
            issues.append(f"private-key filename: {normalized}")
            continue
        if Path(name).suffix.lower() in FORBIDDEN_ARTIFACT_SUFFIXES:
            issues.append(f"generated or binary artifact: {normalized}")
            continue

        path = root / Path(normalized)
        try:
            raw = path.read_bytes()
        except OSError as exc:
            issues.append(f"unreadable tracked file: {normalized} ({exc.__class__.__name__})")
            continue
        if b"\0" in raw:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for match in EMAIL_PATTERN.finditer(text):
            address = match.group(0).lower()
            domain = match.group(1).lower()
            reserved = domain.endswith((".example", ".invalid", ".test"))
            if (
                address not in ALLOWED_EMAIL_ADDRESSES
                and domain not in ALLOWED_EMAIL_DOMAINS
                and not reserved
            ):
                line = text.count("\n", 0, match.start()) + 1
                issues.append(f"non-placeholder email: {normalized}:{line}")
        for label, pattern in CONTENT_RULES.items():
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                issues.append(f"{label}: {normalized}:{line}")
    return issues


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    issues = audit(root)
    if issues:
        print("public tree verification failed", file=sys.stderr)
        for issue in issues:
            print(f"- {issue}", file=sys.stderr)
        return 1
    print(f"public tree verification passed ({len(tracked_files(root))} tracked files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
