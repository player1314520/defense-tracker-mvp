#!/usr/bin/env python3
"""Strict, crash-safe host release state for the V9 Portal and backend.

Each subsystem has one authoritative JSON document.  A commit writes and
fsyncs a same-directory temporary file, atomically replaces the document, and
fsyncs the containing directory.  Prior generations remain embedded in the
new document so a successful commit never discards earlier release evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from typing import Any, Callable


PORTAL_STATE_NAME = "portal-state.json"
BACKEND_STATE_NAME = "backend-state.json"
PORTAL_MIGRATION_MARKER_NAME = "portal-state.migrated.json"
BACKEND_MIGRATION_MARKER_NAME = "backend-state.migrated.json"
PORTAL_INTENT_NAME = "portal-switch-intent.json"
SCHEMA = 1
MAX_STATE_BYTES = 16 * 1024 * 1024

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}@sha256:[0-9a-f]{64}$"
)
WIRE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

PORTAL_FIELDS = {
    "image",
    "release_sha",
    "wire_compatibility",
    "source_manifest_sha256",
}
BACKEND_FIELDS = {
    "release_sha",
    "source_manifest_sha256",
    "wire_compatibility",
    "migration_policy",
    "function_digest",
    "supabase_upstream_sha",
}

MIGRATION_MARKER_FIELDS = {
    "schema",
    "kind",
    "state_file",
    "state_sha256",
    "established",
}
PORTAL_INTENT_FIELDS = {
    "schema",
    "kind",
    "operation",
    "base_generation",
    "from_release",
    "to_release",
}


class StateError(RuntimeError):
    """Release state is missing, unsafe, incomplete, or malformed."""


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def _enforce_posix_permissions() -> bool:
    return os.name == "posix"


def _reject_symlink_components(path: Path) -> None:
    probe = Path(path.anchor)
    for part in path.parts[1:]:
        probe /= part
        try:
            metadata = probe.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise StateError(f"release state path contains a symbolic link: {probe}")


def _normal_state_path(value: os.PathLike[str] | str) -> Path:
    raw = os.fspath(value)
    path = Path(raw)
    if not path.is_absolute():
        raise StateError("release state path must be absolute")
    normalized = Path(os.path.normpath(raw))
    if normalized != path:
        raise StateError("release state path must be normalized")
    if path.parent == path:
        raise StateError("release state path is too broad")
    if len(raw) > 4096:
        raise StateError("release state path is too long")
    if os.name == "posix" and raw in {
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/home",
        "/opt",
        "/root",
        "/run",
        "/srv",
        "/tmp",
        "/usr",
        "/var",
    }:
        raise StateError("release state path is too broad")
    _reject_symlink_components(path)
    return path


def _validate_owner(path: Path) -> None:
    if _enforce_posix_permissions() and hasattr(os, "geteuid"):
        if path.lstat().st_uid != os.geteuid():
            raise StateError(f"release state path is not owned by the current user: {path}")


def assert_secure_state_dir(value: os.PathLike[str] | str) -> Path:
    path = _normal_state_path(value)
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise StateError("release state directory is missing") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise StateError("release state directory must not be a symbolic link")
    if not stat.S_ISDIR(metadata.st_mode):
        raise StateError("release state path must be a directory")
    _validate_owner(path)
    if _enforce_posix_permissions() and _mode(path) != 0o700:
        raise StateError("release state directory permissions must be 0700")
    return path


def prepare_state_dir(value: os.PathLike[str] | str) -> Path:
    path = _normal_state_path(value)
    if not path.exists():
        missing: list[Path] = []
        cursor = path
        while not cursor.exists():
            missing.append(cursor)
            cursor = cursor.parent
        _reject_symlink_components(cursor)
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
            if _enforce_posix_permissions():
                directory.chmod(0o700)
    return assert_secure_state_dir(path)


def assert_secure_regular_file(
    path: Path,
    *,
    expected_mode: int = 0o600,
    enforce_posix_permissions: bool | None = None,
    observed_mode: int | None = None,
) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise StateError(f"release state file is missing: {path.name}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise StateError(f"release state file must not be a symbolic link: {path.name}")
    if not stat.S_ISREG(metadata.st_mode):
        raise StateError(f"release state file is not regular: {path.name}")
    if enforce_posix_permissions is None:
        enforce_posix_permissions = _enforce_posix_permissions()
    if enforce_posix_permissions:
        actual_mode = _mode(path) if observed_mode is None else observed_mode
        if actual_mode != expected_mode:
            raise StateError(
                f"release state file permissions must be {expected_mode:04o}: {path.name}"
            )
        _validate_owner(path)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StateError(f"release state contains duplicate key: {key}")
        result[key] = value
    return result


def _require_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise StateError(f"{label} schema is invalid")
    return value


def _require_generation(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StateError(f"{label} generation is invalid")
    return value


def _validate_portal_release(value: Any, label: str) -> dict[str, str]:
    release = _require_keys(value, PORTAL_FIELDS, label)
    if not isinstance(release["image"], str) or not IMAGE_RE.fullmatch(release["image"]):
        raise StateError(f"{label} image is invalid")
    if "/../" in release["image"] or "//" in release["image"]:
        raise StateError(f"{label} image is invalid")
    if not isinstance(release["release_sha"], str) or not SHA40_RE.fullmatch(
        release["release_sha"]
    ):
        raise StateError(f"{label} release SHA is invalid")
    if not isinstance(release["wire_compatibility"], str) or not WIRE_RE.fullmatch(
        release["wire_compatibility"]
    ):
        raise StateError(f"{label} wire compatibility is invalid")
    if not isinstance(release["source_manifest_sha256"], str) or not SHA256_RE.fullmatch(
        release["source_manifest_sha256"]
    ):
        raise StateError(f"{label} source manifest is invalid")
    return dict(release)


def _validate_backend_release(value: Any, label: str) -> dict[str, str]:
    release = _require_keys(value, BACKEND_FIELDS, label)
    for field in ("release_sha", "supabase_upstream_sha"):
        if not isinstance(release[field], str) or not SHA40_RE.fullmatch(release[field]):
            raise StateError(f"{label} {field} is invalid")
    for field in ("source_manifest_sha256", "function_digest"):
        if not isinstance(release[field], str) or not SHA256_RE.fullmatch(release[field]):
            raise StateError(f"{label} {field} is invalid")
    if not isinstance(release["wire_compatibility"], str) or not WIRE_RE.fullmatch(
        release["wire_compatibility"]
    ):
        raise StateError(f"{label} wire compatibility is invalid")
    if release["migration_policy"] != "expand-contract":
        raise StateError(f"{label} migration policy is invalid")
    return dict(release)


def _validate_portal_state(value: Any) -> dict[str, Any]:
    state = _require_keys(
        value,
        {"schema", "kind", "generation", "current", "previous", "history"},
        "Portal state",
    )
    if state["schema"] != SCHEMA or state["kind"] != "portal-release-state":
        raise StateError("Portal state identity is invalid")
    generation = _require_generation(state["generation"], "Portal state")
    current = _validate_portal_release(state["current"], "Portal current")
    previous = state["previous"]
    if previous is not None:
        previous = _validate_portal_release(previous, "Portal previous")
        if previous == current:
            raise StateError("Portal current and previous releases must differ")
    history = state["history"]
    if not isinstance(history, list) or len(history) != generation - 1:
        raise StateError("Portal history does not cover every prior generation")
    clean_history: list[dict[str, Any]] = []
    for expected_generation, item in enumerate(history, start=1):
        entry = _require_keys(item, {"generation", "current", "previous"}, "Portal history")
        if _require_generation(entry["generation"], "Portal history") != expected_generation:
            raise StateError("Portal history generations are not contiguous")
        entry_previous = entry["previous"]
        if entry_previous is not None:
            entry_previous = _validate_portal_release(
                entry_previous, "Portal historical previous"
            )
        clean_history.append(
            {
                "generation": expected_generation,
                "current": _validate_portal_release(
                    entry["current"], "Portal historical current"
                ),
                "previous": entry_previous,
            }
        )
    for prior, following in zip(clean_history, clean_history[1:]):
        if following["previous"] != prior["current"]:
            raise StateError("Portal history transition is inconsistent")
    if clean_history and previous != clean_history[-1]["current"]:
        raise StateError("Portal active generation is inconsistent with its history")
    return {
        "schema": SCHEMA,
        "kind": "portal-release-state",
        "generation": generation,
        "current": current,
        "previous": previous,
        "history": clean_history,
    }


def _validate_backend_state(value: Any) -> dict[str, Any]:
    state = _require_keys(
        value,
        {"schema", "kind", "generation", "active", "history"},
        "backend state",
    )
    if state["schema"] != SCHEMA or state["kind"] != "backend-release-state":
        raise StateError("backend state identity is invalid")
    generation = _require_generation(state["generation"], "backend state")
    active = _validate_backend_release(state["active"], "backend active")
    history = state["history"]
    if not isinstance(history, list) or len(history) != generation - 1:
        raise StateError("backend history does not cover every prior generation")
    clean_history: list[dict[str, Any]] = []
    for expected_generation, item in enumerate(history, start=1):
        entry = _require_keys(item, {"generation", "active"}, "backend history")
        if _require_generation(entry["generation"], "backend history") != expected_generation:
            raise StateError("backend history generations are not contiguous")
        clean_history.append(
            {
                "generation": expected_generation,
                "active": _validate_backend_release(
                    entry["active"], "historical backend active"
                ),
            }
        )
    return {
        "schema": SCHEMA,
        "kind": "backend-release-state",
        "generation": generation,
        "active": active,
        "history": clean_history,
    }


def _validate_migration_marker(
    value: Any, *, expected_kind: str, expected_state_file: str
) -> dict[str, Any]:
    marker = _require_keys(value, MIGRATION_MARKER_FIELDS, "migration marker")
    if marker["schema"] != SCHEMA or marker["kind"] != expected_kind:
        raise StateError("migration marker identity is invalid")
    if marker["state_file"] != expected_state_file:
        raise StateError("migration marker state file is invalid")
    if not isinstance(marker["state_sha256"], str) or not SHA256_RE.fullmatch(
        marker["state_sha256"]
    ):
        raise StateError("migration marker state digest is invalid")
    if not isinstance(marker["established"], bool):
        raise StateError("migration marker establishment state is invalid")
    return dict(marker)


def _validate_portal_intent(value: Any) -> dict[str, Any]:
    intent = _require_keys(value, PORTAL_INTENT_FIELDS, "Portal switch intent")
    if intent["schema"] != SCHEMA or intent["kind"] != "portal-switch-intent":
        raise StateError("Portal switch intent identity is invalid")
    if intent["operation"] not in {"promote", "rollback"}:
        raise StateError("Portal switch intent operation is invalid")
    base_generation = intent["base_generation"]
    if (
        isinstance(base_generation, bool)
        or not isinstance(base_generation, int)
        or base_generation < 0
    ):
        raise StateError("Portal switch intent generation is invalid")
    from_release = intent["from_release"]
    if from_release is not None:
        from_release = _validate_portal_release(from_release, "Portal intent source")
    to_release = _validate_portal_release(intent["to_release"], "Portal intent target")
    if from_release == to_release:
        raise StateError("Portal switch intent source and target must differ")
    if base_generation == 0 and from_release is not None:
        raise StateError("initial Portal switch intent must not have a source release")
    if base_generation > 0 and from_release is None:
        raise StateError("existing Portal switch intent must have a source release")
    return {
        "schema": SCHEMA,
        "kind": "portal-switch-intent",
        "operation": intent["operation"],
        "base_generation": base_generation,
        "from_release": from_release,
        "to_release": to_release,
    }


def _load_document(
    state_dir: os.PathLike[str] | str,
    filename: str,
    validator: Callable[[Any], dict[str, Any]],
) -> dict[str, Any]:
    directory = assert_secure_state_dir(state_dir)
    target = directory / filename
    assert_secure_regular_file(target)
    size = target.lstat().st_size
    if size < 2 or size > MAX_STATE_BYTES:
        raise StateError(f"release state file size is invalid: {filename}")
    try:
        with target.open("r", encoding="utf-8", newline="") as handle:
            value = json.load(handle, object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StateError(f"release state JSON is invalid: {filename}") from exc
    return validator(value)


def _document_payload(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _document_sha256(value: dict[str, Any]) -> str:
    return hashlib.sha256(_document_payload(value)).hexdigest()


def _lineage_origin(filename: str, state: dict[str, Any]) -> dict[str, Any]:
    if filename == PORTAL_STATE_NAME:
        if state["generation"] == 1:
            return state
        first = state["history"][0]
        return {
            "schema": SCHEMA,
            "kind": "portal-release-state",
            "generation": 1,
            "current": first["current"],
            "previous": first["previous"],
            "history": [],
        }
    if filename == BACKEND_STATE_NAME:
        if state["generation"] == 1:
            return state
        first = state["history"][0]
        return {
            "schema": SCHEMA,
            "kind": "backend-release-state",
            "generation": 1,
            "active": first["active"],
            "history": [],
        }
    raise AssertionError(f"no lineage origin is defined for {filename}")


def _lineage_sha256(filename: str, state: dict[str, Any]) -> str:
    return _document_sha256(_lineage_origin(filename, state))


def _marker_spec(filename: str) -> tuple[str, str]:
    if filename == PORTAL_STATE_NAME:
        return PORTAL_MIGRATION_MARKER_NAME, "portal-state-migration-marker"
    if filename == BACKEND_STATE_NAME:
        return BACKEND_MIGRATION_MARKER_NAME, "backend-state-migration-marker"
    raise AssertionError(f"no migration marker is defined for {filename}")


def _load_migration_marker(directory: Path, filename: str) -> dict[str, Any] | None:
    marker_name, marker_kind = _marker_spec(filename)
    target = directory / marker_name
    if not target.exists() and not target.is_symlink():
        return None
    return _load_document(
        directory,
        marker_name,
        lambda value: _validate_migration_marker(
            value,
            expected_kind=marker_kind,
            expected_state_file=filename,
        ),
    )


def _verify_state_marker(
    directory: Path, filename: str, state: dict[str, Any]
) -> None:
    marker = _load_migration_marker(directory, filename)
    if marker is not None:
        if not marker["established"]:
            raise StateError(f"release state lineage is not established: {filename}")
        if marker["state_sha256"] != _lineage_sha256(filename, state):
            raise StateError(f"release state does not match its durable marker: {filename}")


def load_portal_state(state_dir: os.PathLike[str] | str) -> dict[str, Any]:
    directory = assert_secure_state_dir(state_dir)
    state = _load_document(directory, PORTAL_STATE_NAME, _validate_portal_state)
    _verify_state_marker(directory, PORTAL_STATE_NAME, state)
    return state


def load_backend_state(state_dir: os.PathLike[str] | str) -> dict[str, Any]:
    directory = assert_secure_state_dir(state_dir)
    state = _load_document(directory, BACKEND_STATE_NAME, _validate_backend_state)
    _verify_state_marker(directory, BACKEND_STATE_NAME, state)
    return state


def _fsync_directory(directory: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write_document(directory: Path, filename: str, value: dict[str, Any]) -> None:
    directory = assert_secure_state_dir(directory)
    target = directory / filename
    if target.exists() or target.is_symlink():
        assert_secure_regular_file(target)
    payload = _document_payload(value)
    if len(payload) > MAX_STATE_BYTES:
        raise StateError("release state history exceeds the supported document size")
    temporary = directory / f".{filename}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            temporary.chmod(0o600)
        assert_secure_regular_file(temporary)
        os.replace(temporary, target)
        _fsync_directory(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _write_marker_for_state(
    directory: Path,
    filename: str,
    value: dict[str, Any],
    *,
    established: bool,
) -> None:
    marker_name, marker_kind = _marker_spec(filename)
    marker = {
        "schema": SCHEMA,
        "kind": marker_kind,
        "state_file": filename,
        "state_sha256": _lineage_sha256(filename, value),
        "established": established,
    }
    clean_marker = _validate_migration_marker(
        marker,
        expected_kind=marker_kind,
        expected_state_file=filename,
    )
    _atomic_write_document(directory, marker_name, clean_marker)


def _write_state_with_marker(
    directory: Path, filename: str, value: dict[str, Any]
) -> None:
    marker_name, _ = _marker_spec(filename)
    marker_target = directory / marker_name
    if marker_target.exists() or marker_target.is_symlink():
        marker = _load_migration_marker(directory, filename)
        if (
            marker is None
            or not marker["established"]
            or marker["state_sha256"] != _lineage_sha256(filename, value)
        ):
            raise StateError(f"release state lineage differs from its durable marker: {filename}")
        # The lineage marker is immutable.  Established generations therefore
        # require one atomic document replacement rather than a two-file commit.
        _atomic_write_document(directory, filename, value)
    else:
        # The first marker is a durable tombstone.  It must reach disk before
        # the first authoritative state so retained legacy fields can never be
        # resurrected after an interrupted migration.
        _write_marker_for_state(directory, filename, value, established=False)
        _atomic_write_document(directory, filename, value)
        _write_marker_for_state(directory, filename, value, established=True)


def _remove_secure_file(directory: Path, filename: str) -> None:
    target = directory / filename
    assert_secure_regular_file(target)
    target.unlink()
    _fsync_directory(directory)


def _optional_load(
    state_dir: Path,
    filename: str,
    loader: Callable[[Path], dict[str, Any]],
) -> dict[str, Any] | None:
    target = state_dir / filename
    if not target.exists() and not target.is_symlink():
        marker_name, _ = _marker_spec(filename)
        marker = state_dir / marker_name
        if marker.exists() or marker.is_symlink():
            _load_migration_marker(state_dir, filename)
            raise StateError(
                f"durable migration marker exists but release state is missing: {filename}"
            )
        return None
    return loader(state_dir)


def promote_portal(
    state_dir: os.PathLike[str] | str, release: dict[str, str]
) -> dict[str, Any]:
    directory = assert_secure_state_dir(state_dir)
    clean_release = _validate_portal_release(release, "Portal candidate")
    old = _optional_load(directory, PORTAL_STATE_NAME, load_portal_state)
    if old is None:
        new = {
            "schema": SCHEMA,
            "kind": "portal-release-state",
            "generation": 1,
            "current": clean_release,
            "previous": None,
            "history": [],
        }
    elif old["current"] == clean_release:
        return old
    else:
        new = {
            "schema": SCHEMA,
            "kind": "portal-release-state",
            "generation": old["generation"] + 1,
            "current": clean_release,
            "previous": old["current"],
            "history": old["history"]
            + [
                {
                    "generation": old["generation"],
                    "current": old["current"],
                    "previous": old["previous"],
                }
            ],
        }
    clean = _validate_portal_state(new)
    _write_state_with_marker(directory, PORTAL_STATE_NAME, clean)
    return clean


def rollback_portal(state_dir: os.PathLike[str] | str) -> dict[str, Any]:
    directory = assert_secure_state_dir(state_dir)
    old = load_portal_state(directory)
    if old["previous"] is None:
        raise StateError("Portal rollback state has no previous release")
    new = {
        "schema": SCHEMA,
        "kind": "portal-release-state",
        "generation": old["generation"] + 1,
        "current": old["previous"],
        "previous": old["current"],
        "history": old["history"]
        + [
            {
                "generation": old["generation"],
                "current": old["current"],
                "previous": old["previous"],
            }
        ],
    }
    clean = _validate_portal_state(new)
    _write_state_with_marker(directory, PORTAL_STATE_NAME, clean)
    return clean


def commit_backend(
    state_dir: os.PathLike[str] | str, release: dict[str, str]
) -> dict[str, Any]:
    directory = assert_secure_state_dir(state_dir)
    clean_release = _validate_backend_release(release, "backend candidate")
    old = _optional_load(directory, BACKEND_STATE_NAME, load_backend_state)
    if old is None:
        new = {
            "schema": SCHEMA,
            "kind": "backend-release-state",
            "generation": 1,
            "active": clean_release,
            "history": [],
        }
    elif old["active"] == clean_release:
        return old
    else:
        new = {
            "schema": SCHEMA,
            "kind": "backend-release-state",
            "generation": old["generation"] + 1,
            "active": clean_release,
            "history": old["history"]
            + [{"generation": old["generation"], "active": old["active"]}],
        }
    clean = _validate_backend_state(new)
    _write_state_with_marker(directory, BACKEND_STATE_NAME, clean)
    return clean


def load_portal_intent(state_dir: os.PathLike[str] | str) -> dict[str, Any]:
    return _load_document(state_dir, PORTAL_INTENT_NAME, _validate_portal_intent)


def _optional_portal_intent(directory: Path) -> dict[str, Any] | None:
    target = directory / PORTAL_INTENT_NAME
    if not target.exists() and not target.is_symlink():
        return None
    return load_portal_intent(directory)


def assert_portal_intent_clear(state_dir: os.PathLike[str] | str) -> None:
    directory = assert_secure_state_dir(state_dir)
    intent = _optional_portal_intent(directory)
    if intent is None:
        return
    state_target = directory / PORTAL_STATE_NAME
    state = None
    if state_target.exists() or state_target.is_symlink():
        try:
            state = load_portal_state(directory)
        except StateError as exc:
            raise StateError(
                "unresolved Portal switch intent has an incomplete state commit; "
                "run the audited recovery wrapper"
            ) from exc
    if state is not None and _committed_portal_intent_matches(state, intent):
        # The state commit completed and only journal cleanup was interrupted.
        _remove_secure_file(directory, PORTAL_INTENT_NAME)
        return
    raise StateError(
        "unresolved Portal switch intent; run the audited recovery wrapper"
    )


def _committed_portal_intent_matches(
    state: dict[str, Any], intent: dict[str, Any]
) -> bool:
    if intent["base_generation"] == 0 or intent["from_release"] is None:
        return False
    if (
        state["generation"] != intent["base_generation"] + 1
        or state["current"] != intent["to_release"]
        or state["previous"] != intent["from_release"]
        or not state["history"]
    ):
        return False
    prior = state["history"][-1]
    if (
        prior["generation"] != intent["base_generation"]
        or prior["current"] != intent["from_release"]
    ):
        return False
    return intent["operation"] != "rollback" or prior["previous"] == intent["to_release"]


def begin_portal_intent(
    state_dir: os.PathLike[str] | str,
    operation: str,
    target_release: dict[str, str],
) -> dict[str, Any]:
    directory = assert_secure_state_dir(state_dir)
    assert_portal_intent_clear(directory)
    target = _validate_portal_release(target_release, "Portal intent target")
    state = _optional_load(directory, PORTAL_STATE_NAME, load_portal_state)
    if state is None:
        if operation != "promote":
            raise StateError("Portal rollback requires an existing release state")
        base_generation = 0
        source = None
    else:
        base_generation = state["generation"]
        source = state["current"]
        if operation == "rollback":
            if state["previous"] is None or target != state["previous"]:
                raise StateError("Portal rollback intent target is not the retained previous release")
        elif operation != "promote":
            raise StateError("Portal switch intent operation is invalid")
    if source == target:
        raise StateError("Portal switch intent target is already current")
    intent = _validate_portal_intent(
        {
            "schema": SCHEMA,
            "kind": "portal-switch-intent",
            "operation": operation,
            "base_generation": base_generation,
            "from_release": source,
            "to_release": target,
        }
    )
    _atomic_write_document(directory, PORTAL_INTENT_NAME, intent)
    return intent


def complete_portal_intent(
    state_dir: os.PathLike[str] | str, observed_image: str
) -> dict[str, Any]:
    directory = assert_secure_state_dir(state_dir)
    intent = load_portal_intent(directory)
    if observed_image != intent["to_release"]["image"]:
        raise StateError("running Portal image does not match the switch intent target")
    if intent["base_generation"] == 0:
        return _complete_initial_portal_intent(directory, intent)
    state = _optional_load(directory, PORTAL_STATE_NAME, load_portal_state)
    expected_source = intent["from_release"]
    if state is not None and _committed_portal_intent_matches(state, intent):
        # The generation was durably committed and only intent cleanup was
        # interrupted.  Re-running recovery is deliberately idempotent.
        _remove_secure_file(directory, PORTAL_INTENT_NAME)
        return state
    if expected_source is None:
        if state is not None or intent["base_generation"] != 0:
            raise StateError("Portal state changed after the initial switch intent")
    elif (
        state is None
        or state["generation"] != intent["base_generation"]
        or state["current"] != expected_source
    ):
        raise StateError("Portal state changed after the switch intent was recorded")

    if intent["operation"] == "promote":
        committed = promote_portal(directory, intent["to_release"])
    else:
        committed = rollback_portal(directory)
    if (
        committed["generation"] != intent["base_generation"] + 1
        or committed["current"] != intent["to_release"]
    ):
        raise StateError("Portal switch intent committed an unexpected generation")
    _remove_secure_file(directory, PORTAL_INTENT_NAME)
    return committed


def _initial_portal_state(release: dict[str, str]) -> dict[str, Any]:
    return _validate_portal_state(
        {
            "schema": SCHEMA,
            "kind": "portal-release-state",
            "generation": 1,
            "current": release,
            "previous": None,
            "history": [],
        }
    )


def _complete_initial_portal_intent(
    directory: Path, intent: dict[str, Any]
) -> dict[str, Any]:
    if intent["from_release"] is not None:
        raise StateError("initial Portal intent unexpectedly has a source release")
    expected = _initial_portal_state(intent["to_release"])
    state_target = directory / PORTAL_STATE_NAME
    marker_target = directory / PORTAL_MIGRATION_MARKER_NAME
    state_exists = state_target.exists() or state_target.is_symlink()
    marker_exists = marker_target.exists() or marker_target.is_symlink()
    if marker_exists:
        marker = _load_migration_marker(directory, PORTAL_STATE_NAME)
        if marker is None or marker["state_sha256"] != _lineage_sha256(
            PORTAL_STATE_NAME, expected
        ):
            raise StateError("initial Portal marker differs from the switch intent")
        if marker["established"]:
            if not state_exists or load_portal_state(directory) != expected:
                raise StateError("established initial Portal state is missing or unexpected")
        else:
            if state_exists:
                raw_state = _load_document(
                    directory, PORTAL_STATE_NAME, _validate_portal_state
                )
                if raw_state != expected:
                    raise StateError("partial initial Portal state differs from the intent")
            else:
                _atomic_write_document(directory, PORTAL_STATE_NAME, expected)
            _write_marker_for_state(
                directory, PORTAL_STATE_NAME, expected, established=True
            )
    else:
        if state_exists:
            raise StateError("initial Portal state exists without its durable marker")
        _write_state_with_marker(directory, PORTAL_STATE_NAME, expected)
    _remove_secure_file(directory, PORTAL_INTENT_NAME)
    return expected


def abort_portal_intent(
    state_dir: os.PathLike[str] | str, observed_image: str
) -> None:
    directory = assert_secure_state_dir(state_dir)
    intent = load_portal_intent(directory)
    expected_source = intent["from_release"]
    expected_image = "none" if expected_source is None else expected_source["image"]
    if observed_image != expected_image:
        raise StateError("running Portal image does not match the pre-switch release")
    if expected_source is None:
        if intent["base_generation"] != 0:
            raise StateError("initial Portal intent generation is invalid")
        expected = _initial_portal_state(intent["to_release"])
        state_target = directory / PORTAL_STATE_NAME
        marker_target = directory / PORTAL_MIGRATION_MARKER_NAME
        state_exists = state_target.exists() or state_target.is_symlink()
        marker_exists = marker_target.exists() or marker_target.is_symlink()
        if marker_exists:
            marker = _load_migration_marker(directory, PORTAL_STATE_NAME)
            if (
                marker is None
                or marker["established"]
                or marker["state_sha256"]
                != _lineage_sha256(PORTAL_STATE_NAME, expected)
            ):
                raise StateError("initial Portal marker cannot be safely aborted")
            if state_exists:
                raw_state = _load_document(
                    directory, PORTAL_STATE_NAME, _validate_portal_state
                )
                if raw_state != expected:
                    raise StateError("partial initial Portal state differs from the intent")
                _remove_secure_file(directory, PORTAL_STATE_NAME)
            _remove_secure_file(directory, PORTAL_MIGRATION_MARKER_NAME)
        elif state_exists:
            raise StateError("initial Portal state exists without its durable marker")
        unchanged = True
    else:
        state = _optional_load(directory, PORTAL_STATE_NAME, load_portal_state)
        unchanged = (
            state is not None
            and state["generation"] == intent["base_generation"]
            and state["current"] == expected_source
        )
    if not unchanged:
        raise StateError("Portal state changed after the switch intent was recorded")
    _remove_secure_file(directory, PORTAL_INTENT_NAME)


def _read_legacy_value(path: Path) -> str:
    assert_secure_regular_file(path)
    if path.lstat().st_size > 4096:
        raise StateError(f"legacy release state value is too large: {path.name}")
    try:
        value = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise StateError(f"legacy release state is unreadable: {path.name}") from exc
    if value.endswith("\r\n"):
        value = value[:-2]
    elif value.endswith("\n"):
        value = value[:-1]
    if not value or value != value.strip() or "\n" in value or "\r" in value:
        raise StateError(f"legacy release state is invalid: {path.name}")
    return value


def _legacy_group(directory: Path, names: list[str], label: str) -> dict[str, str] | None:
    present = [name for name in names if (directory / name).exists() or (directory / name).is_symlink()]
    if not present:
        return None
    if len(present) != len(names):
        raise StateError(f"legacy {label} release state is incomplete")
    return {name: _read_legacy_value(directory / name) for name in names}


def migrate_legacy_portal(state_dir: os.PathLike[str] | str) -> bool:
    directory = assert_secure_state_dir(state_dir)
    state_target = directory / PORTAL_STATE_NAME
    marker_target = directory / PORTAL_MIGRATION_MARKER_NAME
    state_exists = state_target.exists() or state_target.is_symlink()
    marker_exists = marker_target.exists() or marker_target.is_symlink()
    if state_exists:
        state = _load_document(directory, PORTAL_STATE_NAME, _validate_portal_state)
        if marker_exists:
            marker = _load_migration_marker(directory, PORTAL_STATE_NAME)
            if marker is None or marker["state_sha256"] != _lineage_sha256(
                PORTAL_STATE_NAME, state
            ):
                raise StateError("Portal state differs from its durable marker")
            if not marker["established"]:
                _write_marker_for_state(
                    directory, PORTAL_STATE_NAME, state, established=True
                )
        else:
            _write_marker_for_state(
                directory, PORTAL_STATE_NAME, state, established=True
            )
        return False
    current_names = ["current.image", "current.sha", "current.wire", "current.manifest"]
    previous_names = ["previous.image", "previous.sha", "previous.wire", "previous.manifest"]
    current = _legacy_group(directory, current_names, "Portal current")
    previous = _legacy_group(directory, previous_names, "Portal previous")
    if current is None and previous is None:
        if marker_exists:
            _load_migration_marker(directory, PORTAL_STATE_NAME)
            raise StateError(
                "durable Portal migration marker exists but Portal state is missing"
            )
        return False
    if current is None:
        raise StateError("legacy Portal release state is incomplete")

    def portal_from(group: dict[str, str], prefix: str) -> dict[str, str]:
        return {
            "image": group[f"{prefix}.image"],
            "release_sha": group[f"{prefix}.sha"],
            "wire_compatibility": group[f"{prefix}.wire"],
            "source_manifest_sha256": group[f"{prefix}.manifest"],
        }

    state = {
        "schema": SCHEMA,
        "kind": "portal-release-state",
        "generation": 1,
        "current": portal_from(current, "current"),
        "previous": portal_from(previous, "previous") if previous is not None else None,
        "history": [],
    }
    clean = _validate_portal_state(state)
    if marker_exists:
        marker = _load_migration_marker(directory, PORTAL_STATE_NAME)
        if (
            marker is None
            or marker["established"]
            or marker["state_sha256"] != _lineage_sha256(PORTAL_STATE_NAME, clean)
        ):
            raise StateError("retained Portal legacy state differs from its durable marker")
        _atomic_write_document(directory, PORTAL_STATE_NAME, clean)
        _write_marker_for_state(
            directory, PORTAL_STATE_NAME, clean, established=True
        )
    else:
        _write_state_with_marker(directory, PORTAL_STATE_NAME, clean)
    return True


def migrate_legacy_backend(state_dir: os.PathLike[str] | str) -> bool:
    directory = assert_secure_state_dir(state_dir)
    state_target = directory / BACKEND_STATE_NAME
    marker_target = directory / BACKEND_MIGRATION_MARKER_NAME
    state_exists = state_target.exists() or state_target.is_symlink()
    marker_exists = marker_target.exists() or marker_target.is_symlink()
    if state_exists:
        state = _load_document(directory, BACKEND_STATE_NAME, _validate_backend_state)
        if marker_exists:
            marker = _load_migration_marker(directory, BACKEND_STATE_NAME)
            if marker is None or marker["state_sha256"] != _lineage_sha256(
                BACKEND_STATE_NAME, state
            ):
                raise StateError("backend state differs from its durable marker")
            if not marker["established"]:
                _write_marker_for_state(
                    directory, BACKEND_STATE_NAME, state, established=True
                )
        else:
            _write_marker_for_state(
                directory, BACKEND_STATE_NAME, state, established=True
            )
        return False
    names = [
        "backend.sha",
        "backend.manifest",
        "backend.wire",
        "backend.policy",
        "backend.functions",
        "backend.upstream",
    ]
    legacy = _legacy_group(directory, names, "backend")
    if legacy is None:
        if marker_exists:
            _load_migration_marker(directory, BACKEND_STATE_NAME)
            raise StateError(
                "durable backend migration marker exists but backend state is missing"
            )
        return False
    release = {
        "release_sha": legacy["backend.sha"],
        "source_manifest_sha256": legacy["backend.manifest"],
        "wire_compatibility": legacy["backend.wire"],
        "migration_policy": legacy["backend.policy"],
        "function_digest": legacy["backend.functions"],
        "supabase_upstream_sha": legacy["backend.upstream"],
    }
    state = {
        "schema": SCHEMA,
        "kind": "backend-release-state",
        "generation": 1,
        "active": release,
        "history": [],
    }
    clean = _validate_backend_state(state)
    if marker_exists:
        marker = _load_migration_marker(directory, BACKEND_STATE_NAME)
        if (
            marker is None
            or marker["established"]
            or marker["state_sha256"] != _lineage_sha256(BACKEND_STATE_NAME, clean)
        ):
            raise StateError("retained backend legacy state differs from its durable marker")
        _atomic_write_document(directory, BACKEND_STATE_NAME, clean)
        _write_marker_for_state(
            directory, BACKEND_STATE_NAME, clean, established=True
        )
    else:
        _write_state_with_marker(directory, BACKEND_STATE_NAME, clean)
    return True


def _get_field(value: dict[str, Any], dotted: str) -> str:
    current: Any = value
    for component in dotted.split("."):
        if not isinstance(current, dict) or component not in current:
            raise StateError(f"release state field is unavailable: {dotted}")
        current = current[component]
    if not isinstance(current, (str, int)) or isinstance(current, bool):
        raise StateError(f"release state field is not scalar: {dotted}")
    return str(current)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("state_dir", type=Path)
    check_dir = commands.add_parser("check-dir")
    check_dir.add_argument("state_dir", type=Path)
    migrate = commands.add_parser("migrate")
    migrate.add_argument("kind", choices=("portal", "backend"))
    migrate.add_argument("state_dir", type=Path)
    exists = commands.add_parser("exists")
    exists.add_argument("kind", choices=("portal", "backend"))
    exists.add_argument("state_dir", type=Path)
    get = commands.add_parser("get")
    get.add_argument("kind", choices=("portal", "backend"))
    get.add_argument("state_dir", type=Path)
    get.add_argument("field")
    promote = commands.add_parser("portal-promote")
    promote.add_argument("state_dir", type=Path)
    promote.add_argument("image")
    promote.add_argument("release_sha")
    promote.add_argument("wire_compatibility")
    promote.add_argument("source_manifest_sha256")
    rollback = commands.add_parser("portal-rollback")
    rollback.add_argument("state_dir", type=Path)
    intent_check = commands.add_parser("portal-intent-check")
    intent_check.add_argument("state_dir", type=Path)
    intent_get = commands.add_parser("portal-intent-get")
    intent_get.add_argument("state_dir", type=Path)
    intent_get.add_argument("field")
    intent_begin = commands.add_parser("portal-intent-begin")
    intent_begin.add_argument("state_dir", type=Path)
    intent_begin.add_argument("operation", choices=("promote", "rollback"))
    intent_begin.add_argument("image")
    intent_begin.add_argument("release_sha")
    intent_begin.add_argument("wire_compatibility")
    intent_begin.add_argument("source_manifest_sha256")
    intent_complete = commands.add_parser("portal-intent-complete")
    intent_complete.add_argument("state_dir", type=Path)
    intent_complete.add_argument("observed_image")
    intent_abort = commands.add_parser("portal-intent-abort")
    intent_abort.add_argument("state_dir", type=Path)
    intent_abort.add_argument("observed_image")
    backend = commands.add_parser("backend-commit")
    backend.add_argument("state_dir", type=Path)
    backend.add_argument("release_sha")
    backend.add_argument("source_manifest_sha256")
    backend.add_argument("wire_compatibility")
    backend.add_argument("migration_policy")
    backend.add_argument("function_digest")
    backend.add_argument("supabase_upstream_sha")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "prepare":
        prepare_state_dir(args.state_dir)
        return 0
    if args.command == "check-dir":
        assert_secure_state_dir(args.state_dir)
        return 0
    if args.command == "migrate":
        migrated = (
            migrate_legacy_portal(args.state_dir)
            if args.kind == "portal"
            else migrate_legacy_backend(args.state_dir)
        )
        print("migrated" if migrated else "not-needed")
        return 0
    if args.command in {"exists", "get"}:
        filename = PORTAL_STATE_NAME if args.kind == "portal" else BACKEND_STATE_NAME
        directory = assert_secure_state_dir(args.state_dir)
        target = directory / filename
        if not target.exists() and not target.is_symlink():
            return 1
        state = (
            load_portal_state(directory)
            if args.kind == "portal"
            else load_backend_state(directory)
        )
        if args.command == "get":
            print(_get_field(state, args.field))
        return 0
    if args.command == "portal-promote":
        promote_portal(
            args.state_dir,
            {
                "image": args.image,
                "release_sha": args.release_sha,
                "wire_compatibility": args.wire_compatibility,
                "source_manifest_sha256": args.source_manifest_sha256,
            },
        )
        return 0
    if args.command == "portal-rollback":
        rollback_portal(args.state_dir)
        return 0
    if args.command == "portal-intent-check":
        assert_portal_intent_clear(args.state_dir)
        return 0
    if args.command == "portal-intent-get":
        print(_get_field(load_portal_intent(args.state_dir), args.field))
        return 0
    if args.command == "portal-intent-begin":
        begin_portal_intent(
            args.state_dir,
            args.operation,
            {
                "image": args.image,
                "release_sha": args.release_sha,
                "wire_compatibility": args.wire_compatibility,
                "source_manifest_sha256": args.source_manifest_sha256,
            },
        )
        return 0
    if args.command == "portal-intent-complete":
        complete_portal_intent(args.state_dir, args.observed_image)
        return 0
    if args.command == "portal-intent-abort":
        abort_portal_intent(args.state_dir, args.observed_image)
        return 0
    if args.command == "backend-commit":
        commit_backend(
            args.state_dir,
            {
                "release_sha": args.release_sha,
                "source_manifest_sha256": args.source_manifest_sha256,
                "wire_compatibility": args.wire_compatibility,
                "migration_policy": args.migration_policy,
                "function_digest": args.function_digest,
                "supabase_upstream_sha": args.supabase_upstream_sha,
            },
        )
        return 0
    raise AssertionError("unreachable")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except StateError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(65) from exc
