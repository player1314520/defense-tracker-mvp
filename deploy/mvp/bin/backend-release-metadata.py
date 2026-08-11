#!/usr/bin/env python3
"""Derive fail-closed backend release metadata from one exact Git commit."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


SHA_RE = re.compile(r"[0-9a-f]{40}")
DIGEST_RE = re.compile(r"[0-9a-f]{64}")
WIRE_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
MIGRATION_RE = re.compile(r"supabase/migrations/[0-9]{12}_[a-z0-9_]+[.]sql")
COMPATIBILITY_PATH = "deploy/mvp/backend-compatibility.json"
SOURCE_PREFIXES = (
    "supabase/migrations/",
    "supabase/functions/access-applications/",
    "supabase/functions/invite-member/",
)
REQUIRED_FUNCTIONS = (
    "supabase/functions/access-applications/index.ts",
    "supabase/functions/invite-member/index.ts",
)
COMPATIBILITY_KEYS = {"schema", "wire_compatibility", "migration_policy"}


class MetadataError(RuntimeError):
    pass


def git(repo: Path, *arguments: str) -> bytes:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), *arguments], stderr=subprocess.PIPE
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = ""
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            detail = exc.stderr.decode("utf-8", errors="replace").strip()
        raise MetadataError(detail or "unable to read the requested Git commit") from exc


def commit_bytes(repo: Path, git_sha: str, path: str) -> bytes:
    return git(repo, "show", f"{git_sha}:{path}")


def compute_metadata(repo: Path, git_sha: str) -> dict[str, object]:
    if SHA_RE.fullmatch(git_sha) is None:
        raise MetadataError("release SHA must be 40 lowercase hexadecimal characters")
    resolved = git(repo, "rev-parse", "--verify", f"{git_sha}^{{commit}}")
    if resolved.decode("ascii").strip() != git_sha:
        raise MetadataError("release SHA does not resolve to the exact requested commit")

    raw_paths = git(
        repo,
        "ls-tree",
        "-r",
        "--name-only",
        git_sha,
        "--",
        "supabase/migrations",
        "supabase/functions/access-applications",
        "supabase/functions/invite-member",
        COMPATIBILITY_PATH,
    )
    paths = sorted(
        path
        for path in raw_paths.decode("utf-8").splitlines()
        if path == COMPATIBILITY_PATH
        or any(path.startswith(prefix) for prefix in SOURCE_PREFIXES)
    )
    if COMPATIBILITY_PATH not in paths:
        raise MetadataError("backend compatibility declaration is missing")
    for required in REQUIRED_FUNCTIONS:
        if required not in paths:
            raise MetadataError(f"required Edge Function entrypoint is missing: {required}")
    migrations = [path for path in paths if path.startswith("supabase/migrations/")]
    if not migrations:
        raise MetadataError("at least one committed Supabase migration is required")
    invalid_migrations = [path for path in migrations if MIGRATION_RE.fullmatch(path) is None]
    if invalid_migrations:
        raise MetadataError(f"invalid migration filename: {invalid_migrations[0]}")

    try:
        compatibility = json.loads(
            commit_bytes(repo, git_sha, COMPATIBILITY_PATH).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MetadataError("backend compatibility declaration is invalid JSON") from exc
    if not isinstance(compatibility, dict) or set(compatibility) != COMPATIBILITY_KEYS:
        raise MetadataError("backend compatibility declaration has unexpected fields")
    if compatibility.get("schema") != 1:
        raise MetadataError("backend compatibility schema must be 1")
    wire = compatibility.get("wire_compatibility")
    if not isinstance(wire, str) or WIRE_RE.fullmatch(wire) is None:
        raise MetadataError("backend wire compatibility identifier is invalid")
    policy = compatibility.get("migration_policy")
    if policy != "expand-contract":
        raise MetadataError("backend migration policy must be expand-contract")

    manifest = hashlib.sha256()
    for path in paths:
        blob_digest = hashlib.sha256(commit_bytes(repo, git_sha, path)).hexdigest()
        manifest.update(f"{blob_digest}  {path}\n".encode("utf-8"))
    source_manifest = manifest.hexdigest()
    if DIGEST_RE.fullmatch(source_manifest) is None:  # pragma: no cover
        raise MetadataError("unable to derive source manifest")
    return {
        "schema": 1,
        "release_sha": git_sha,
        "source_manifest_sha256": source_manifest,
        "wire_compatibility": wire,
        "migration_policy": policy,
        "source_file_count": len(paths),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--git-sha", required=True)
    parser.add_argument(
        "--field",
        choices=(
            "release_sha",
            "source_manifest_sha256",
            "wire_compatibility",
            "migration_policy",
            "source_file_count",
        ),
    )
    arguments = parser.parse_args()
    try:
        metadata = compute_metadata(arguments.repo.resolve(), arguments.git_sha)
    except MetadataError as exc:
        print(str(exc), file=sys.stderr)
        return 65
    if arguments.field:
        print(metadata[arguments.field])
    else:
        print(json.dumps(metadata, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
