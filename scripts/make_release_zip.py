# -*- coding: utf-8 -*-
"""Create a sanitized source release zip from an exact reviewed Git commit.

The output intentionally excludes local secrets, Git history, build outputs,
agent worktrees, caches, generated runtime files, and all index/worktree edits.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path, PureWindowsPath


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

REQUIRED_RELEASE_FILES = frozenset(
    {
        "feishu_bot.py",
        "pinned_http.py",
        "protected_secrets.py",
        "wechat_runtime.py",
        "templates/index.html",
        "static/css/credential-notice.css",
        "static/js/credential-notice.js",
    }
)

_WINDOWS_FORBIDDEN_CHARS = frozenset('<>:"|?*')
_WINDOWS_RESERVED_NAMES = frozenset(
    {"con", "prn", "aux", "nul", "conin$", "conout$"}
    | {f"com{number}" for number in range(1, 10)}
    | {f"lpt{number}" for number in range(1, 10)}
)
_FULL_COMMIT_SHA = re.compile(r"\A[0-9a-fA-F]{40}\Z")
_CLI_OUTPUT_ROOTS = (
    Path("build/release-evidence"),
    Path("dist/releases"),
)


def _path_exists(path: Path) -> bool:
    return os.path.lexists(path)


def _is_link_or_reparse(path: Path) -> bool:
    metadata = path.lstat()
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _require_new_regular_output(output: Path) -> None:
    if _path_exists(output):
        raise RuntimeError(f"Source release refuses an existing output: {output}")
    parent = output.parent
    if not _path_exists(parent) or _is_link_or_reparse(parent) or not parent.is_dir():
        raise RuntimeError(
            "Source release output parent must be an existing regular directory: "
            + str(parent)
        )


def validate_cli_output(root: Path, output: Path) -> Path:
    """Resolve CLI output only inside ignored evidence/release directories."""

    root = root.resolve(strict=True)
    raw_output = output if output.is_absolute() else root / output
    candidate = Path(os.path.abspath(raw_output))
    if candidate.suffix.lower() != ".zip" or candidate.name in {"", ".", ".."}:
        raise RuntimeError("Source release CLI output must be a named .zip file")
    allowed_roots = tuple(root / relative for relative in _CLI_OUTPUT_ROOTS)
    if not any(candidate.is_relative_to(allowed) for allowed in allowed_roots):
        raise RuntimeError(
            "Source release CLI output must remain under build/release-evidence "
            "or dist/releases"
        )

    relative_parent = candidate.parent.relative_to(root)
    current = root
    for component in relative_parent.parts:
        current = current / component
        if _path_exists(current):
            if _is_link_or_reparse(current) or not current.is_dir():
                raise RuntimeError(
                    "Source release CLI output path contains a link or non-directory: "
                    + str(current)
                )
        else:
            current.mkdir()
    _require_new_regular_output(candidate)
    return candidate


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


def _controlled_git_env() -> dict[str, str]:
    env = dict(os.environ)
    for key in list(env):
        normalized = key.upper()
        if normalized.startswith("GIT_"):
            env.pop(key, None)
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    return env


def validate_git_release_path(relative: str) -> str:
    parts = relative.split("/")
    unsafe_windows_component = any(
        part.endswith((".", " "))
        or any(
            character in _WINDOWS_FORBIDDEN_CHARS or ord(character) < 32
            for character in part
        )
        or part.split(".", 1)[0].casefold() in _WINDOWS_RESERVED_NAMES
        for part in parts
    )
    if (
        not relative
        or "\\" in relative
        or relative.startswith("/")
        or PureWindowsPath(relative).drive
        or any(part in {"", ".", ".."} for part in parts)
        or unsafe_windows_component
    ):
        raise RuntimeError(f"Source release refused unsafe Git path: {relative!r}")
    return relative


def validate_expected_commit(root: Path, expected_sha: str) -> str:
    if not isinstance(expected_sha, str) or not _FULL_COMMIT_SHA.fullmatch(
        expected_sha
    ):
        raise RuntimeError(
            "Source release requires --expected-sha as a full 40-hex commit ID"
        )
    expected_sha = expected_sha.lower()
    try:
        object_type = subprocess.run(
            ["git", "-C", str(root), "cat-file", "-t", expected_sha],
            check=True,
            capture_output=True,
            env=_controlled_git_env(),
        ).stdout.decode("ascii").strip()
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"Source release expected commit does not exist: {expected_sha}"
        ) from exc
    if object_type != "commit":
        raise RuntimeError(
            "Source release expected object is not a commit: "
            f"{expected_sha} ({object_type or 'unknown'})"
        )
    canonical_sha = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", f"{expected_sha}^{{commit}}"],
        check=True,
        capture_output=True,
        env=_controlled_git_env(),
    ).stdout.decode("ascii").strip()
    if _FULL_COMMIT_SHA.fullmatch(canonical_sha) is None or canonical_sha != expected_sha:
        raise RuntimeError("Source release could not resolve the exact commit ID")
    return canonical_sha


def _git_commit_entries(
    root: Path,
    expected_sha: str,
) -> list[tuple[str, str, str]]:
    try:
        raw_records = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "ls-tree",
                "-r",
                "--full-tree",
                "-z",
                expected_sha,
            ],
            check=True,
            capture_output=True,
            env=_controlled_git_env(),
        ).stdout
        records = raw_records.decode("utf-8").split("\0")
    except UnicodeDecodeError as exc:
        raise RuntimeError("Source release refused a non-UTF-8 Git path") from exc
    tracked = []
    invalid = []
    for record in records:
        if not record:
            continue
        try:
            metadata, relative = record.split("\t", 1)
            mode, object_type, object_id = metadata.split()
        except ValueError as exc:
            raise RuntimeError("Source release refused malformed Git tree data") from exc
        relative = validate_git_release_path(relative)
        if mode not in {"100644", "100755"} or object_type != "blob":
            invalid.append(f"{relative} ({mode}, {object_type})")
        tracked.append((relative, object_id, mode))
    if invalid:
        raise RuntimeError(
            "Source release refused non-regular Git commit entries: "
            + ", ".join(sorted(invalid))
        )
    return tracked


def _git_commit_timestamp(root: Path, expected_sha: str) -> tuple[int, ...]:
    raw_timestamp = subprocess.run(
        ["git", "-C", str(root), "show", "-s", "--format=%ct", expected_sha],
        check=True,
        capture_output=True,
        env=_controlled_git_env(),
    ).stdout.decode("ascii").strip()
    try:
        timestamp = int(raw_timestamp)
        date_time = time.gmtime(timestamp)[:6]
    except (ValueError, OverflowError, OSError) as exc:
        raise RuntimeError("Source release refused an invalid commit timestamp") from exc
    year, month, day, hour, minute, second = date_time
    if not 1980 <= year <= 2107:
        raise RuntimeError(
            "Source release commit timestamp is outside the ZIP format range"
        )
    return year, month, day, hour, minute, second - (second % 2)


def _git_blob(root: Path, object_id: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), "cat-file", "blob", object_id],
        check=True,
        capture_output=True,
        env=_controlled_git_env(),
    ).stdout


def validate_required_release_files(
    root: Path,
    tracked: list[str] | set[str] | frozenset[str],
) -> None:
    normalized = {item.replace("\\", "/") for item in tracked if item}
    unavailable = sorted(
        relative
        for relative in REQUIRED_RELEASE_FILES
        if relative not in normalized
        or not should_include(root / relative, root)
    )
    if unavailable:
        raise RuntimeError(
            "Source release refused because required runtime files are missing from "
            "the expected commit or excluded: "
            + ", ".join(unavailable)
        )


def prepare_release_entries(
    root: Path,
    entries: list[tuple[str, str, str]],
    *,
    archive_root: str | None = None,
) -> list[tuple[str, str, str, str]]:
    archive_root = validate_git_release_path(archive_root or root.name)
    prepared = []
    exact_members = set()
    windows_members = set()
    for relative, object_id, mode in sorted(entries):
        relative = validate_git_release_path(relative)
        path = root / relative
        if not should_include(path, root):
            continue
        member = f"{archive_root}/{relative}"
        windows_member = member.casefold()
        if member in exact_members or windows_member in windows_members:
            raise RuntimeError(
                "Source release refused duplicate archive member: " + member
            )
        exact_members.add(member)
        windows_members.add(windows_member)
        prepared.append((relative, object_id, mode, member))
    return prepared


def make_release_zip(root: Path, output: Path, *, expected_sha: str) -> int:
    root = root.resolve()
    output_input = Path(output)
    output_parent = output_input.parent.resolve()
    output = output_parent / output_input.name
    _require_new_regular_output(output)
    expected_sha = validate_expected_commit(root, expected_sha)
    entries = _git_commit_entries(root, expected_sha)
    tracked = [relative for relative, _object_id, _mode in entries]
    validate_required_release_files(root, tracked)
    prepared = prepare_release_entries(
        root,
        entries,
        archive_root=f"DefenseTracker-source-{expected_sha}",
    )
    archive_timestamp = _git_commit_timestamp(root, expected_sha)
    try:
        output_relative = output.relative_to(root).as_posix()
    except ValueError:
        output_relative = None
    if output_relative in tracked:
        raise RuntimeError(
            "Source release refused output path overlapping a tracked source file: "
            + output_relative
        )

    descriptor, temporary_name = tempfile.mkstemp(
        dir=output_parent,
        prefix=f".{output.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary_name)
    temporary_stream = os.fdopen(descriptor, "w+b")
    try:
        with temporary_stream as stream:
            with zipfile.ZipFile(
                stream,
                "w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            ) as zf:
                for _relative, object_id, mode, archive_path in prepared:
                    info = zipfile.ZipInfo(archive_path, date_time=archive_timestamp)
                    info.create_system = 3
                    info.external_attr = (
                        (0o100755 if mode == "100755" else 0o100644) << 16
                    )
                    info.compress_type = zipfile.ZIP_DEFLATED
                    zf.writestr(info, _git_blob(root, object_id), compresslevel=9)
        try:
            os.link(temporary_path, output)
        except FileExistsError as exc:
            raise RuntimeError(
                f"Source release refuses an existing output: {output}"
            ) from exc
        temporary_path.unlink()
    except BaseException:
        if not temporary_stream.closed:
            temporary_stream.close()
        temporary_path.unlink(missing_ok=True)
        raise
    return len(prepared)


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a clean project release zip.")
    parser.add_argument(
        "--expected-sha",
        required=True,
        help="Exact reviewed 40-hex Git commit to archive.",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    if _FULL_COMMIT_SHA.fullmatch(args.expected_sha) is None:
        parser.error("--expected-sha must be a full 40-hex commit ID")
    expected_sha = validate_expected_commit(root, args.expected_sha)
    output = validate_cli_output(
        root,
        Path("build/release-evidence/source-zips")
        / f"DefenseTracker-source-{expected_sha}.zip",
    )
    count = make_release_zip(root, output, expected_sha=expected_sha)
    print(f"Wrote {output} with {count} files from {expected_sha}")


if __name__ == "__main__":
    main()
