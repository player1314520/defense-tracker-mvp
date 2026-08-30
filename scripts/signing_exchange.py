# -*- coding: utf-8 -*-
"""Create and verify credentialless Authenticode exchange bundles.

The release build and finalization jobs use this module only with already
decrypted local directories.  A signing job does not need this repository: it
can validate the public canonical request, sign the single requested PE, and
return the bundle with a canonical receipt.

This module proves byte identity and Authenticode-normalized PE identity.  It
does not verify certificate trust, Publisher policy, or RFC 3161 timestamp
trust; the credentialless Windows consumer must run SignTool and the pinned
certificate-policy checks after this structural gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Literal
from urllib.parse import urlsplit

try:
    from scripts.authenticode_digest import inspect_authenticode_image
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    from authenticode_digest import inspect_authenticode_image  # type: ignore[no-redef]


REQUEST_SCHEMA = 2
REQUEST_KIND = "defense-tracker-authenticode-signing-request"
RECEIPT_KIND = "defense-tracker-authenticode-signing-receipt"
SUBJECT_KINDS = {"application", "installer"}
SIGNING_PROVIDERS = {"AzureArtifactSigning", "DigiCertKeyLocker"}
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SEMVER_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
)
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_FILES = 200_000
MAX_FILE_BYTES = 64 * 1024 * 1024 * 1024
MAX_POSITIVE_ID = 9_223_372_036_854_775_807

REQUEST_KEYS = {
    "schema",
    "kind",
    "subject_kind",
    "release",
    "provenance",
    "materials",
    "target",
    "payload_files",
    "created_at_utc",
}
RELEASE_KEYS = {"commit", "source_tree", "version", "publisher"}
PROVENANCE_KEYS = {"repository", "workflow_ref", "run_id", "run_attempt", "job"}
TARGET_KEYS = {
    "path",
    "bytes",
    "sha256",
    "authenticode_normalized_sha256",
    "signature_state",
}
FILE_KEYS = {"path", "bytes", "sha256"}
MATERIAL_KEYS = {"name", "sha256"}
MATERIAL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
RECEIPT_KEYS = {
    "schema",
    "kind",
    "subject_kind",
    "request_sha256",
    "release_commit",
    "target_path",
    "unsigned_sha256",
    "signed_sha256",
    "signed_bytes",
    "signature",
    "provenance",
    "completed_at_utc",
}
SIGNATURE_KEYS = {
    "provider",
    "publisher",
    "signer_subject",
    "signer_spki_sha256",
    "signer_issuer_subject",
    "signer_root_sha256",
    "timestamp_url",
    "timestamp_certificate_subject",
    "timestamp_verified_at_utc",
    "publisher_policy",
}
PUBLISHER_POLICY_KEYS = {
    "sha256",
    "leaf_spki_policy",
    "durable_identity_eku",
    "azure_endpoint",
    "azure_account_name",
    "azure_certificate_profile_name",
    "azure_metadata_sha256",
    "digicert_sm_host",
    "digicert_key_alias",
}
RESERVED_METADATA = {"signing-request.json", "signing-receipt.json"}
WINDOWS_DEVICE_NAMES = {
    "aux",
    "clock$",
    "con",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}


def canonical_json_bytes(value: object) -> bytes:
    """Return the only accepted byte representation for exchange JSON."""

    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("Exchange JSON is not canonicalizable") from exc
    return (rendered + "\n").encode("utf-8")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _pairs_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Exchange JSON contains duplicate key: {key}")
        result[key] = value
    return result


def load_canonical_json(path: Path, *, label: str) -> tuple[dict[str, object], bytes]:
    if _is_reparse(path) or path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-reparse file")
    payload = _read_stable(path, label=label, max_bytes=MAX_JSON_BYTES)
    if payload.startswith(b"\xef\xbb\xbf"):
        raise ValueError(f"{label} must not contain a UTF-8 BOM")
    try:
        parsed = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"Non-finite JSON number is forbidden: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{label} is not strict canonical JSON") from exc
    if not isinstance(parsed, dict) or canonical_json_bytes(parsed) != payload:
        raise ValueError(f"{label} bytes are not canonical")
    return parsed, payload


def write_canonical_json(path: Path, value: object) -> None:
    destination = path.resolve(strict=False)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json_bytes(value)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=destination.name + ".", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _is_reparse(path: Path) -> bool:
    try:
        result = path.lstat()
    except OSError:
        return False
    attributes = getattr(result, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _stat_identity(result: os.stat_result) -> tuple[int, int, int, int]:
    return (
        result.st_dev,
        result.st_ino,
        result.st_size,
        result.st_mtime_ns,
    )


def _read_stable(path: Path, *, label: str, max_bytes: int = MAX_FILE_BYTES) -> bytes:
    try:
        before_path = path.lstat()
        if (
            _is_reparse(path)
            or stat.S_ISLNK(before_path.st_mode)
            or not stat.S_ISREG(before_path.st_mode)
            or before_path.st_size < 0
            or before_path.st_size > max_bytes
        ):
            raise ValueError(f"{label} is not an allowed regular file")
        with path.open("rb") as stream:
            before_fd = os.fstat(stream.fileno())
            payload = stream.read(before_fd.st_size + 1)
            after_fd = os.fstat(stream.fileno())
        after_path = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} could not be read safely") from exc
    if len(payload) > max_bytes:
        raise ValueError(f"{label} exceeds the maximum size")
    identities = {
        _stat_identity(before_path),
        _stat_identity(before_fd),
        _stat_identity(after_fd),
        _stat_identity(after_path),
    }
    if len(identities) != 1 or len(payload) != before_path.st_size:
        raise ValueError(f"{label} changed while it was being read")
    return payload


def sha256_file(path: Path, *, label: str) -> tuple[int, str]:
    digest = hashlib.sha256()
    try:
        before_path = path.lstat()
        if (
            _is_reparse(path)
            or stat.S_ISLNK(before_path.st_mode)
            or not stat.S_ISREG(before_path.st_mode)
            or before_path.st_size < 0
            or before_path.st_size > MAX_FILE_BYTES
        ):
            raise ValueError(f"{label} is not an allowed regular file")
        with path.open("rb") as stream:
            before_fd = os.fstat(stream.fileno())
            total = 0
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                total += len(block)
                if total > MAX_FILE_BYTES:
                    raise ValueError(f"{label} exceeds the maximum size")
                digest.update(block)
            after_fd = os.fstat(stream.fileno())
        after_path = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} could not be hashed safely") from exc
    identities = {
        _stat_identity(before_path),
        _stat_identity(before_fd),
        _stat_identity(after_fd),
        _stat_identity(after_path),
    }
    if len(identities) != 1 or total != before_path.st_size:
        raise ValueError(f"{label} changed while it was being hashed")
    return total, digest.hexdigest()


def _safe_relative_path(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
        or value in {".", ".."}
        or value.startswith("/")
        or value.endswith("/")
        or "//" in value
        or re.match(r"^[A-Za-z]:", value) is not None
    ):
        raise ValueError(f"{label} is not a safe POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{label} is not a safe POSIX relative path")
    if value != path.as_posix() or any(
        re.search(r'[:*?"<>|]', part) is not None
        or part.endswith((" ", "."))
        or part.split(".", 1)[0].casefold() in WINDOWS_DEVICE_NAMES
        for part in path.parts
    ):
        raise ValueError(f"{label} is not a portable relative path")
    return value


def resolve_path_within(
    root: Path,
    relative: object,
    *,
    label: str,
    kind: Literal["file", "directory", "output"] = "file",
) -> Path:
    """Resolve one strict POSIX relative path beneath an already chosen root.

    The relative value is validated before it reaches any host path API.  Every
    existing component is then checked again after resolution so a symlink or
    Windows reparse point cannot redirect the operation outside ``root``.
    """

    normalized = _safe_relative_path(relative, label=label)
    root_resolved = root.resolve(strict=True)
    if _is_reparse(root_resolved) or root_resolved.is_symlink() or not root_resolved.is_dir():
        raise ValueError(f"{label} root must be a regular non-reparse directory")
    candidate = root_resolved.joinpath(*PurePosixPath(normalized).parts)
    try:
        if kind == "output":
            parent = candidate.parent.resolve(strict=True)
            parent.relative_to(root_resolved)
            resolved = parent / candidate.name
        else:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root_resolved)
    except (OSError, ValueError) as exc:
        raise ValueError(f"{label} escapes or is absent from its allowed root") from exc
    current = root_resolved
    parts = PurePosixPath(normalized).parts
    checked_parts = parts[:-1] if kind == "output" else parts
    for part in checked_parts:
        current = current / part
        if _is_reparse(current) or current.is_symlink():
            raise ValueError(f"{label} traverses a reparse point")
    if kind == "file" and (resolved != candidate or not candidate.is_file()):
        raise ValueError(f"{label} is not a regular file")
    if kind == "directory" and (resolved != candidate or not candidate.is_dir()):
        raise ValueError(f"{label} is not a regular directory")
    if kind == "output" and candidate.exists():
        if _is_reparse(candidate) or candidate.is_symlink() or not candidate.is_file():
            raise ValueError(f"{label} is not a regular output file")
        if candidate.resolve(strict=True) != candidate:
            raise ValueError(f"{label} does not resolve to its exact allowed path")
    return resolved


def _resolve_bundle_file(root: Path, relative: str, *, label: str) -> Path:
    return resolve_path_within(root, relative, label=label, kind="file")


def _snapshot_payload(root: Path) -> list[dict[str, object]]:
    root_resolved = root.resolve(strict=True)
    if _is_reparse(root_resolved) or root_resolved.is_symlink() or not root_resolved.is_dir():
        raise ValueError("Bundle root must be a regular non-reparse directory")
    entries: list[dict[str, object]] = []
    identities_before: dict[str, tuple[int, int, int, int]] = {}
    casefold_paths: set[str] = set()
    for directory, directory_names, file_names in os.walk(root_resolved, followlinks=False):
        directory_path = Path(directory)
        if _is_reparse(directory_path) or directory_path.is_symlink():
            raise ValueError("Bundle contains a reparse directory")
        for name in list(directory_names):
            child = directory_path / name
            if _is_reparse(child) or child.is_symlink():
                raise ValueError("Bundle contains a reparse directory")
        for name in file_names:
            path = directory_path / name
            relative = path.relative_to(root_resolved).as_posix()
            _safe_relative_path(relative, label="bundle file path")
            folded = relative.casefold()
            if folded in casefold_paths:
                raise ValueError("Bundle contains case-insensitive duplicate paths")
            casefold_paths.add(folded)
            if relative in RESERVED_METADATA:
                continue
            before = path.lstat()
            identities_before[relative] = _stat_identity(before)
            size, digest = sha256_file(path, label=f"bundle file {relative}")
            entries.append({"path": relative, "bytes": size, "sha256": digest})
            if len(entries) > MAX_FILES:
                raise ValueError("Bundle contains too many files")
    entries.sort(key=lambda item: str(item["path"]))
    actual_names = {
        path.relative_to(root_resolved).as_posix()
        for path in root_resolved.rglob("*")
        if path.is_file() and path.relative_to(root_resolved).as_posix() not in RESERVED_METADATA
    }
    if actual_names != set(identities_before):
        raise ValueError("Bundle file set changed while it was inventoried")
    for relative, identity in identities_before.items():
        path = _resolve_bundle_file(root_resolved, relative, label="bundle inventory path")
        if _stat_identity(path.lstat()) != identity:
            raise ValueError("Bundle file changed while it was inventoried")
    return entries


def _require_exact_keys(value: object, expected: set[str], *, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{label} has missing or unexpected fields")
    return value


def _positive_integer(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_POSITIVE_ID:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _nonempty_text(value: object, *, label: str, maximum: int = 2048) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > maximum
        or re.search(r"[\x00-\x1f\x7f]", value) is not None
    ):
        raise ValueError(f"{label} is missing or unsafe")
    return value


def _parse_utc(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} must be an explicit UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{label} must be UTC")
    return parsed


def utc_now_text() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _validate_provenance(value: object, *, label: str) -> dict[str, object]:
    provenance = _require_exact_keys(value, PROVENANCE_KEYS, label=label)
    repository = _nonempty_text(provenance["repository"], label=f"{label}.repository")
    if REPOSITORY_RE.fullmatch(repository) is None:
        raise ValueError(f"{label}.repository is malformed")
    _nonempty_text(provenance["workflow_ref"], label=f"{label}.workflow_ref")
    _positive_integer(provenance["run_id"], label=f"{label}.run_id")
    _positive_integer(provenance["run_attempt"], label=f"{label}.run_attempt")
    _nonempty_text(provenance["job"], label=f"{label}.job", maximum=128)
    return provenance


def _validate_request(value: object) -> dict[str, object]:
    request = _require_exact_keys(value, REQUEST_KEYS, label="signing request")
    if request["schema"] != REQUEST_SCHEMA or request["kind"] != REQUEST_KIND:
        raise ValueError("Signing request schema or kind is unsupported")
    subject = request["subject_kind"]
    if subject not in SUBJECT_KINDS:
        raise ValueError("Signing request subject_kind is unsupported")
    release = _require_exact_keys(request["release"], RELEASE_KEYS, label="request.release")
    if not isinstance(release["commit"], str) or SHA1_RE.fullmatch(release["commit"]) is None:
        raise ValueError("request.release.commit is malformed")
    if not isinstance(release["source_tree"], str) or SHA1_RE.fullmatch(release["source_tree"]) is None:
        raise ValueError("request.release.source_tree is malformed")
    if not isinstance(release["version"], str) or SEMVER_RE.fullmatch(release["version"]) is None:
        raise ValueError("request.release.version is malformed")
    _nonempty_text(release["publisher"], label="request.release.publisher", maximum=512)
    _validate_provenance(request["provenance"], label="request.provenance")
    materials = request["materials"]
    if not isinstance(materials, list) or not materials or len(materials) > 128:
        raise ValueError("Signing request materials is empty or oversized")
    previous_material = ""
    for index, entry_value in enumerate(materials):
        entry = _require_exact_keys(
            entry_value, MATERIAL_KEYS, label=f"materials[{index}]"
        )
        name = entry["name"]
        digest = entry["sha256"]
        if (
            not isinstance(name, str)
            or MATERIAL_NAME_RE.fullmatch(name) is None
            or name <= previous_material
        ):
            raise ValueError("Signing request material names must be safe, unique and sorted")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise ValueError(f"materials[{index}].sha256 is malformed")
        previous_material = name
    target = _require_exact_keys(request["target"], TARGET_KEYS, label="request.target")
    target_path = _safe_relative_path(target["path"], label="request.target.path")
    if subject == "application" and target_path != "payload/DefenseTracker/DefenseTracker.exe":
        raise ValueError("Application signing target path is not the fixed release executable")
    installer_name = f"DefenseTracker-Setup-v{release['version']}-windows-x64.exe"
    if subject == "installer" and target_path != f"payload/{installer_name}":
        raise ValueError("Installer signing target path is not the fixed release installer")
    _positive_integer(target["bytes"], label="request.target.bytes")
    for field in ("sha256", "authenticode_normalized_sha256"):
        if not isinstance(target[field], str) or SHA256_RE.fullmatch(target[field]) is None:
            raise ValueError(f"request.target.{field} is malformed")
    if target["signature_state"] != "unsigned":
        raise ValueError("Signing request target must be unsigned")
    files = request["payload_files"]
    if not isinstance(files, list) or not files or len(files) > MAX_FILES:
        raise ValueError("Signing request payload_files is empty or oversized")
    previous = ""
    casefold_paths: set[str] = set()
    target_count = 0
    for index, entry_value in enumerate(files):
        entry = _require_exact_keys(entry_value, FILE_KEYS, label=f"payload_files[{index}]")
        path = _safe_relative_path(entry["path"], label=f"payload_files[{index}].path")
        folded = path.casefold()
        if path in RESERVED_METADATA or path <= previous or folded in casefold_paths:
            raise ValueError("Signing request payload file paths must be unique and sorted")
        casefold_paths.add(folded)
        previous = path
        size = _positive_integer(entry["bytes"], label=f"payload_files[{index}].bytes")
        digest = entry["sha256"]
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise ValueError(f"payload_files[{index}].sha256 is malformed")
        if path == target_path:
            target_count += 1
            if size != target["bytes"] or digest != target["sha256"]:
                raise ValueError("Signing target differs from its payload inventory entry")
    if target_count != 1:
        raise ValueError("Signing target must occur exactly once in payload_files")
    _parse_utc(request["created_at_utc"], label="request.created_at_utc")
    return request


def _validate_receipt(value: object) -> dict[str, object]:
    receipt = _require_exact_keys(value, RECEIPT_KEYS, label="signing receipt")
    if receipt["schema"] != REQUEST_SCHEMA or receipt["kind"] != RECEIPT_KIND:
        raise ValueError("Signing receipt schema or kind is unsupported")
    if receipt["subject_kind"] not in SUBJECT_KINDS:
        raise ValueError("Signing receipt subject_kind is unsupported")
    for field in ("request_sha256", "unsigned_sha256", "signed_sha256"):
        if not isinstance(receipt[field], str) or SHA256_RE.fullmatch(receipt[field]) is None:
            raise ValueError(f"signing receipt {field} is malformed")
    if not isinstance(receipt["release_commit"], str) or SHA1_RE.fullmatch(receipt["release_commit"]) is None:
        raise ValueError("signing receipt release_commit is malformed")
    _safe_relative_path(receipt["target_path"], label="signing receipt target_path")
    _positive_integer(receipt["signed_bytes"], label="signing receipt signed_bytes")
    signature = _require_exact_keys(receipt["signature"], SIGNATURE_KEYS, label="receipt.signature")
    if signature["provider"] not in SIGNING_PROVIDERS:
        raise ValueError("receipt.signature.provider is unsupported")
    for field in (
        "publisher",
        "signer_subject",
        "signer_issuer_subject",
        "timestamp_url",
        "timestamp_certificate_subject",
    ):
        _nonempty_text(signature[field], label=f"receipt.signature.{field}", maximum=2048)
    for field in ("signer_spki_sha256", "signer_root_sha256"):
        if not isinstance(signature[field], str) or SHA256_RE.fullmatch(signature[field]) is None:
            raise ValueError(f"receipt.signature.{field} is malformed")
    policy = _require_exact_keys(
        signature["publisher_policy"],
        PUBLISHER_POLICY_KEYS,
        label="receipt.signature.publisher_policy",
    )
    if not isinstance(policy["sha256"], str) or SHA256_RE.fullmatch(policy["sha256"]) is None:
        raise ValueError("receipt signature Publisher policy SHA-256 is malformed")
    if policy["leaf_spki_policy"] not in {"record-only", "required-pin"}:
        raise ValueError("receipt signature leaf SPKI policy is unsupported")
    azure_fields = (
        "durable_identity_eku",
        "azure_endpoint",
        "azure_account_name",
        "azure_certificate_profile_name",
        "azure_metadata_sha256",
    )
    digicert_fields = ("digicert_sm_host", "digicert_key_alias")
    if signature["provider"] == "AzureArtifactSigning":
        if policy["leaf_spki_policy"] != "record-only":
            raise ValueError("Azure Artifact Signing must use record-only leaf SPKI policy")
        for field in azure_fields[:-1]:
            _nonempty_text(policy[field], label=f"receipt.signature.publisher_policy.{field}")
        if (
            not isinstance(policy["azure_metadata_sha256"], str)
            or SHA256_RE.fullmatch(policy["azure_metadata_sha256"]) is None
        ):
            raise ValueError("Azure metadata SHA-256 is malformed")
        if any(policy[field] is not None for field in digicert_fields):
            raise ValueError("Azure receipt must not contain DigiCert identity")
        endpoint = urlsplit(str(policy["azure_endpoint"]))
        if (
            endpoint.scheme != "https"
            or not endpoint.hostname
            or endpoint.username is not None
            or endpoint.password is not None
            or endpoint.query
            or endpoint.fragment
        ):
            raise ValueError("Azure endpoint must be a credential-free HTTPS URL")
        if not re.fullmatch(
            r"1\.3\.6\.1\.4\.1\.311\.97\.(?:[0-9]+\.)+[0-9]+",
            str(policy["durable_identity_eku"]),
        ):
            raise ValueError("Azure durable identity EKU is malformed")
    elif (
        policy["leaf_spki_policy"] != "required-pin"
        or any(policy[field] is not None for field in azure_fields)
    ):
        raise ValueError("DigiCert receipt must use required-pin policy without Azure identity")
    else:
        for field in digicert_fields:
            _nonempty_text(
                policy[field],
                label=f"receipt.signature.publisher_policy.{field}",
            )
        if not re.fullmatch(
            r"https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?",
            str(policy["digicert_sm_host"]),
        ):
            raise ValueError("DigiCert SM host is malformed")
    timestamp_verified = _parse_utc(
        signature["timestamp_verified_at_utc"],
        label="receipt.signature.timestamp_verified_at_utc",
    )
    completed = _parse_utc(receipt["completed_at_utc"], label="receipt.completed_at_utc")
    if timestamp_verified > completed:
        raise ValueError("Signing receipt completes before timestamp verification")
    _validate_provenance(receipt["provenance"], label="receipt.provenance")
    return receipt


def create_request(
    *,
    subject_kind: Literal["application", "installer"],
    bundle_root: Path,
    target_path: str,
    release_commit: str,
    source_tree: str,
    version: str,
    publisher: str,
    repository: str,
    workflow_ref: str,
    run_id: int,
    run_attempt: int,
    job: str,
    materials: dict[str, Path | str],
    created_at_utc: str,
) -> dict[str, object]:
    payload_files = _snapshot_payload(bundle_root)
    target = _resolve_bundle_file(bundle_root, target_path, label="signing target")
    inspected = inspect_authenticode_image(target, require_state="unsigned")
    target_entry = next(
        (entry for entry in payload_files if entry["path"] == target_path), None
    )
    if target_entry is None:
        raise ValueError("Signing target is absent from the payload inventory")
    request: dict[str, object] = {
        "schema": REQUEST_SCHEMA,
        "kind": REQUEST_KIND,
        "subject_kind": subject_kind,
        "release": {
            "commit": release_commit,
            "source_tree": source_tree,
            "version": version,
            "publisher": publisher,
        },
        "provenance": {
            "repository": repository,
            "workflow_ref": workflow_ref,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "job": job,
        },
        "materials": [
            {
                "name": name,
                "sha256": (
                    path
                    if isinstance(path, str)
                    else sha256_file(path, label=f"release material {name}")[1]
                ),
            }
            for name, path in sorted(materials.items())
        ],
        "target": {
            "path": target_path,
            "bytes": inspected.bytes,
            "sha256": inspected.file_sha256,
            "authenticode_normalized_sha256": inspected.normalized_sha256,
            "signature_state": inspected.signature_state,
        },
        "payload_files": payload_files,
        "created_at_utc": created_at_utc,
    }
    return _validate_request(request)


def verify_signed_return(
    *,
    bundle_root: Path,
    request_path: Path,
    receipt_path: Path,
    expected_request_sha256: str,
    expected_subject_kind: str,
    expected_release_commit: str,
    expected_publisher: str,
    expected_repository: str,
    expected_workflow_ref: str,
    expected_run_id: int,
    expected_run_attempt: int,
    expected_job: str,
) -> dict[str, object]:
    request_value, request_bytes = load_canonical_json(
        request_path, label="signing request"
    )
    request = _validate_request(request_value)
    receipt_value, receipt_bytes = load_canonical_json(
        receipt_path, label="signing receipt"
    )
    receipt = _validate_receipt(receipt_value)
    request_sha256 = sha256_bytes(request_bytes)
    if not SHA256_RE.fullmatch(expected_request_sha256) or request_sha256 != expected_request_sha256:
        raise ValueError("Signing request differs from its expected SHA-256")
    release = request["release"]
    target = request["target"]
    assert isinstance(release, dict) and isinstance(target, dict)
    expected = {
        "subject_kind": expected_subject_kind,
        "request_sha256": request_sha256,
        "release_commit": expected_release_commit,
        "target_path": target["path"],
        "unsigned_sha256": target["sha256"],
    }
    for field, expected_value in expected.items():
        if receipt[field] != expected_value:
            raise ValueError(f"Signing receipt {field} differs from the reviewed request")
    if request["subject_kind"] != expected_subject_kind:
        raise ValueError("Signing request subject_kind differs from the expected stage")
    if release["commit"] != expected_release_commit or release["publisher"] != expected_publisher:
        raise ValueError("Signing request release identity differs from expected policy")
    signature = receipt["signature"]
    provenance = receipt["provenance"]
    assert isinstance(signature, dict) and isinstance(provenance, dict)
    if signature["publisher"] != expected_publisher:
        raise ValueError("Signing receipt Publisher differs from expected policy")
    provenance_expectations = {
        "repository": expected_repository,
        "workflow_ref": expected_workflow_ref,
        "run_id": expected_run_id,
        "run_attempt": expected_run_attempt,
        "job": expected_job,
    }
    for field, expected_value in provenance_expectations.items():
        if provenance[field] != expected_value:
            raise ValueError(f"Signing receipt provenance {field} differs from expected")

    payload_files = request["payload_files"]
    assert isinstance(payload_files, list)
    target_path = str(target["path"])
    actual_paths: set[str] = set()
    target_actual: Path | None = None
    identities: dict[str, tuple[int, int, int, int]] = {}
    for entry_value in payload_files:
        assert isinstance(entry_value, dict)
        relative = str(entry_value["path"])
        path = _resolve_bundle_file(bundle_root, relative, label="returned payload file")
        identities[relative] = _stat_identity(path.lstat())
        actual_paths.add(relative)
        if relative == target_path:
            target_actual = path
            continue
        size, digest = sha256_file(path, label=f"returned payload file {relative}")
        if size != entry_value["bytes"] or digest != entry_value["sha256"]:
            raise ValueError(f"Non-target payload changed during signing: {relative}")
    if target_actual is None:
        raise ValueError("Returned signing target is absent")
    inspected = inspect_authenticode_image(
        target_actual,
        require_state="signed",
        expected_unsigned_size=int(target["bytes"]),
        expected_normalized_sha256=str(target["authenticode_normalized_sha256"]),
    )
    if (
        inspected.file_sha256 != receipt["signed_sha256"]
        or inspected.bytes != receipt["signed_bytes"]
    ):
        raise ValueError("Signed target differs from its canonical receipt")
    allowed = actual_paths | RESERVED_METADATA
    discovered: set[str] = set()
    root_resolved = bundle_root.resolve(strict=True)
    for path in root_resolved.rglob("*"):
        if _is_reparse(path) or path.is_symlink():
            raise ValueError("Returned bundle contains a reparse point")
        if path.is_file():
            discovered.add(path.relative_to(root_resolved).as_posix())
    if discovered != allowed:
        raise ValueError("Returned bundle contains an extra or missing file")
    for relative, identity in identities.items():
        path = _resolve_bundle_file(bundle_root, relative, label="returned payload file")
        if _stat_identity(path.lstat()) != identity:
            raise ValueError("Returned bundle changed during verification")
    # Re-read both canonical metadata files after payload validation to close a
    # request/receipt swap between the first and last security check.
    _, request_after = load_canonical_json(request_path, label="signing request")
    _, receipt_after = load_canonical_json(receipt_path, label="signing receipt")
    if request_after != request_bytes or receipt_after != receipt_bytes:
        raise ValueError("Signing exchange metadata changed during verification")
    return {
        "schema": REQUEST_SCHEMA,
        "kind": "defense-tracker-authenticode-signed-return-verification",
        "subject_kind": expected_subject_kind,
        "release_commit": expected_release_commit,
        "request_sha256": request_sha256,
        "receipt_sha256": sha256_bytes(receipt_bytes),
        "target_path": target_path,
        "unsigned_sha256": target["sha256"],
        "signed_sha256": inspected.file_sha256,
        "signed_bytes": inspected.bytes,
        "authenticode_normalized_sha256": inspected.normalized_sha256,
        "signature": signature,
        "receipt_provenance": provenance,
    }


def verify_unsigned_request(
    *,
    bundle_root: Path,
    request_path: Path,
    expected_request_sha256: str,
    expected_subject_kind: str,
    expected_release_commit: str,
    expected_publisher: str,
    expected_repository: str,
    expected_workflow_ref: str,
    expected_run_id: int,
    expected_run_attempt: int,
    expected_job: str,
    materials: dict[str, Path | str],
) -> dict[str, object]:
    """Verify the exact unsigned request before entering a signing Environment."""

    request_value, request_bytes = load_canonical_json(
        request_path, label="signing request"
    )
    request = _validate_request(request_value)
    request_sha256 = sha256_bytes(request_bytes)
    if not SHA256_RE.fullmatch(expected_request_sha256) or request_sha256 != expected_request_sha256:
        raise ValueError("Signing request differs from its expected SHA-256")
    release = request["release"]
    provenance = request["provenance"]
    target = request["target"]
    assert isinstance(release, dict) and isinstance(provenance, dict) and isinstance(target, dict)
    if (
        request["subject_kind"] != expected_subject_kind
        or release["commit"] != expected_release_commit
        or release["publisher"] != expected_publisher
    ):
        raise ValueError("Signing request release identity differs from expected policy")
    provenance_expectations = {
        "repository": expected_repository,
        "workflow_ref": expected_workflow_ref,
        "run_id": expected_run_id,
        "run_attempt": expected_run_attempt,
        "job": expected_job,
    }
    for field, expected_value in provenance_expectations.items():
        if provenance[field] != expected_value:
            raise ValueError(f"Signing request provenance {field} differs from expected")
    expected_materials = [
        {
            "name": name,
            "sha256": (
                path
                if isinstance(path, str)
                else sha256_file(path, label=f"release material {name}")[1]
            ),
        }
        for name, path in sorted(materials.items())
    ]
    if request["materials"] != expected_materials:
        raise ValueError("Signing request release materials differ from the exact inputs")

    payload_files = request["payload_files"]
    assert isinstance(payload_files, list)
    identities: dict[str, tuple[int, int, int, int]] = {}
    target_actual: Path | None = None
    expected_paths: set[str] = set()
    for entry_value in payload_files:
        assert isinstance(entry_value, dict)
        relative = str(entry_value["path"])
        path = _resolve_bundle_file(bundle_root, relative, label="unsigned payload file")
        expected_paths.add(relative)
        identities[relative] = _stat_identity(path.lstat())
        size, digest = sha256_file(path, label=f"unsigned payload file {relative}")
        if size != entry_value["bytes"] or digest != entry_value["sha256"]:
            raise ValueError(f"Unsigned payload differs from its request: {relative}")
        if relative == target["path"]:
            target_actual = path
    if target_actual is None:
        raise ValueError("Unsigned signing target is absent")
    inspected = inspect_authenticode_image(target_actual, require_state="unsigned")
    if (
        inspected.bytes != target["bytes"]
        or inspected.file_sha256 != target["sha256"]
        or inspected.normalized_sha256 != target["authenticode_normalized_sha256"]
    ):
        raise ValueError("Unsigned target differs from its request identity")
    root_resolved = bundle_root.resolve(strict=True)
    discovered: set[str] = set()
    for path in root_resolved.rglob("*"):
        if _is_reparse(path) or path.is_symlink():
            raise ValueError("Unsigned bundle contains a reparse point")
        if path.is_file():
            discovered.add(path.relative_to(root_resolved).as_posix())
    if discovered != expected_paths | {"signing-request.json"}:
        raise ValueError("Unsigned bundle contains an extra or missing file")
    for relative, identity in identities.items():
        path = _resolve_bundle_file(bundle_root, relative, label="unsigned payload file")
        if _stat_identity(path.lstat()) != identity:
            raise ValueError("Unsigned bundle changed during verification")
    _, request_after = load_canonical_json(request_path, label="signing request")
    if request_after != request_bytes:
        raise ValueError("Signing request changed during verification")
    return {
        "schema": REQUEST_SCHEMA,
        "kind": "defense-tracker-authenticode-unsigned-request-verification",
        "subject_kind": expected_subject_kind,
        "release_commit": expected_release_commit,
        "request_sha256": request_sha256,
        "target_path": target["path"],
        "unsigned_sha256": inspected.file_sha256,
        "unsigned_bytes": inspected.bytes,
        "authenticode_normalized_sha256": inspected.normalized_sha256,
        "materials": expected_materials,
        "request_provenance": provenance,
    }


def _add_provenance_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--run-attempt", required=True, type=int)
    parser.add_argument("--job", required=True)


def _parse_materials(
    values: list[str],
    digest_values: list[str] | None = None,
    *,
    path_root: Path,
) -> dict[str, Path | str]:
    materials: dict[str, Path | str] = {}
    material_paths: set[str] = set()
    for value in values:
        name, separator, raw_path = value.partition("=")
        if (
            not separator
            or MATERIAL_NAME_RE.fullmatch(name) is None
            or name in materials
            or not raw_path
        ):
            raise ValueError("Each --material must be a unique safe name=path pair")
        normalized = _safe_relative_path(raw_path, label=f"Release material {name}")
        folded = normalized.casefold()
        if folded in material_paths:
            raise ValueError("Release material paths must be case-insensitively unique")
        material_paths.add(folded)
        path = resolve_path_within(
            path_root,
            normalized,
            label=f"Release material {name}",
            kind="file",
        )
        materials[name] = path
    for value in digest_values or []:
        name, separator, digest = value.partition("=")
        if (
            not separator
            or MATERIAL_NAME_RE.fullmatch(name) is None
            or name in materials
            or SHA256_RE.fullmatch(digest) is None
        ):
            raise ValueError(
                "Each --material-sha256 must be a unique safe name=lowercase-sha256 pair"
            )
        materials[name] = digest
    if not materials:
        raise ValueError("At least one --material is required")
    return materials


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create-request")
    create.add_argument("--subject-kind", choices=sorted(SUBJECT_KINDS), required=True)
    create.add_argument("--bundle-root", required=True)
    create.add_argument("--target", required=True)
    create.add_argument("--release-commit", required=True)
    create.add_argument("--source-tree", required=True)
    create.add_argument("--version", required=True)
    create.add_argument("--publisher", required=True)
    _add_provenance_arguments(create)
    create.add_argument("--material", action="append", default=[])
    create.add_argument("--material-sha256", action="append", default=[])
    create.add_argument("--created-at-utc", default=None)
    create.add_argument("--output", required=True)

    verify = subparsers.add_parser("verify-return")
    verify.add_argument("--bundle-root", required=True)
    verify.add_argument("--request", required=True)
    verify.add_argument("--receipt", required=True)
    verify.add_argument("--expected-request-sha256", required=True)
    verify.add_argument("--expected-subject-kind", choices=sorted(SUBJECT_KINDS), required=True)
    verify.add_argument("--expected-release-commit", required=True)
    verify.add_argument("--expected-publisher", required=True)
    verify.add_argument("--expected-repository", required=True)
    verify.add_argument("--expected-workflow-ref", required=True)
    verify.add_argument("--expected-run-id", required=True, type=int)
    verify.add_argument("--expected-run-attempt", required=True, type=int)
    verify.add_argument("--expected-job", required=True)
    verify.add_argument("--output", required=True)

    verify_request = subparsers.add_parser("verify-request")
    verify_request.add_argument("--bundle-root", required=True)
    verify_request.add_argument("--request", required=True)
    verify_request.add_argument("--expected-request-sha256", required=True)
    verify_request.add_argument(
        "--expected-subject-kind", choices=sorted(SUBJECT_KINDS), required=True
    )
    verify_request.add_argument("--expected-release-commit", required=True)
    verify_request.add_argument("--expected-publisher", required=True)
    verify_request.add_argument("--expected-repository", required=True)
    verify_request.add_argument("--expected-workflow-ref", required=True)
    verify_request.add_argument("--expected-run-id", required=True, type=int)
    verify_request.add_argument("--expected-run-attempt", required=True, type=int)
    verify_request.add_argument("--expected-job", required=True)
    verify_request.add_argument("--material", action="append", default=[])
    verify_request.add_argument("--material-sha256", action="append", default=[])
    verify_request.add_argument("--output", required=True)

    args = parser.parse_args()
    cli_root = Path.cwd().resolve(strict=True)
    bundle_root = resolve_path_within(
        cli_root,
        args.bundle_root,
        label="--bundle-root",
        kind="directory",
    )
    output = resolve_path_within(
        cli_root,
        args.output,
        label="--output",
        kind="output",
    )
    if args.command == "create-request":
        root = bundle_root
        expected_output = root / "signing-request.json"
        if output != expected_output:
            raise ValueError("Signing request must use the fixed bundle filename")
        if output.exists() or (root / "signing-receipt.json").exists():
            raise ValueError("Signing bundle metadata already exists")
        request = create_request(
            subject_kind=args.subject_kind,
            bundle_root=root,
            target_path=args.target,
            release_commit=args.release_commit,
            source_tree=args.source_tree,
            version=args.version,
            publisher=args.publisher,
            repository=args.repository,
            workflow_ref=args.workflow_ref,
            run_id=args.run_id,
            run_attempt=args.run_attempt,
            job=args.job,
            materials=_parse_materials(
                args.material,
                args.material_sha256,
                path_root=cli_root,
            ),
            created_at_utc=args.created_at_utc or utc_now_text(),
        )
        write_canonical_json(output, request)
        print(f"signing-request-sha256={sha256_bytes(canonical_json_bytes(request))}")
        return 0

    request_path = resolve_path_within(
        cli_root,
        args.request,
        label="--request",
        kind="file",
    )
    if request_path != bundle_root / "signing-request.json":
        raise ValueError("Signing request path must use the fixed bundle filename")
    if args.command == "verify-request":
        result = verify_unsigned_request(
            bundle_root=bundle_root,
            request_path=request_path,
            expected_request_sha256=args.expected_request_sha256,
            expected_subject_kind=args.expected_subject_kind,
            expected_release_commit=args.expected_release_commit,
            expected_publisher=args.expected_publisher,
            expected_repository=args.expected_repository,
            expected_workflow_ref=args.expected_workflow_ref,
            expected_run_id=args.expected_run_id,
            expected_run_attempt=args.expected_run_attempt,
            expected_job=args.expected_job,
            materials=_parse_materials(
                args.material,
                args.material_sha256,
                path_root=cli_root,
            ),
        )
        write_canonical_json(output, result)
        print("unsigned-request-verification: PASS")
        return 0
    receipt_path = resolve_path_within(
        cli_root,
        args.receipt,
        label="--receipt",
        kind="file",
    )
    if receipt_path != bundle_root / "signing-receipt.json":
        raise ValueError("Signing receipt path must use the fixed bundle filename")
    result = verify_signed_return(
        bundle_root=bundle_root,
        request_path=request_path,
        receipt_path=receipt_path,
        expected_request_sha256=args.expected_request_sha256,
        expected_subject_kind=args.expected_subject_kind,
        expected_release_commit=args.expected_release_commit,
        expected_publisher=args.expected_publisher,
        expected_repository=args.expected_repository,
        expected_workflow_ref=args.expected_workflow_ref,
        expected_run_id=args.expected_run_id,
        expected_run_attempt=args.expected_run_attempt,
        expected_job=args.expected_job,
    )
    write_canonical_json(output, result)
    print("signed-return-verification: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
