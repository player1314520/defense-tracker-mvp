# -*- coding: utf-8 -*-
"""Bind post-package Windows verification evidence into the stable manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERIFIED_GATES = [
    "staged-authenticated-workspace",
    "installer-install-start-uninstall",
    "portable-authenticated-workspace",
    "legacy-migration-non-overwrite",
    "authenticode-chain-and-timestamp",
    "defender",
    "privacy-artifact-rescan",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_utc(value: str) -> datetime:
    if not value.endswith("Z"):
        raise ValueError("completed_at_utc must end in Z")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def finalize(
    root: Path,
    *,
    expected_commit: str,
    completed_at_utc: str,
    portable_exe_sha256: str,
) -> None:
    root = root.resolve()
    if SHA_RE.fullmatch(expected_commit) is None:
        raise ValueError("expected commit must be a full lowercase Git SHA")
    if SHA256_RE.fullmatch(portable_exe_sha256) is None:
        raise ValueError("portable EXE SHA-256 is invalid")
    completed = _parse_utc(completed_at_utc)
    manifest_path = root / "release-manifest.json"
    sums_path = root / "SHA256SUMS.txt"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    if manifest.get("schema") != 2 or manifest.get("kind") != "stable-release":
        raise ValueError("release manifest contract mismatch")
    if manifest.get("release", {}).get("commit") != expected_commit:
        raise ValueError("release manifest commit mismatch")
    if "verification" in manifest:
        raise ValueError("release verification evidence is immutable once written")
    build_verified = _parse_utc(str(manifest.get("build", {}).get("verified_at_utc", "")))
    if completed < build_verified:
        raise ValueError("release verification completion predates build verification")

    manifest["verification"] = {
        "schema": 1,
        "completed_at_utc": completed_at_utc,
        "portable_exe_sha256": portable_exe_sha256,
        "gates": VERIFIED_GATES,
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    manifest_hash = sha256_file(manifest_path)
    lines = sums_path.read_text(encoding="utf-8-sig").splitlines()
    replaced = False
    rewritten: list[str] = []
    for line in lines:
        _digest, separator, name = line.partition("  ")
        if separator != "  ":
            raise ValueError("SHA256SUMS is malformed")
        if name == manifest_path.name:
            line = f"{manifest_hash}  {name}"
            replaced = True
        rewritten.append(line)
    if not replaced:
        raise ValueError("SHA256SUMS does not bind release-manifest.json")
    sums_path.write_text("\n".join(rewritten) + "\n", encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--completed-at-utc", required=True)
    parser.add_argument("--portable-exe-sha256", required=True)
    args = parser.parse_args()
    finalize(
        args.root,
        expected_commit=args.expected_commit,
        completed_at_utc=args.completed_at_utc,
        portable_exe_sha256=args.portable_exe_sha256,
    )
    print("release-assets-finalized: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
