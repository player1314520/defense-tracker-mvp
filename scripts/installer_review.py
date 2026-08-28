# -*- coding: utf-8 -*-
"""Offline trust gate for an independently reviewed Windows installer.

The build job may generate an installer review request, but it cannot approve
that request.  Approval is an exact-byte Ed25519 signature made by a key in the
independent installer-review registry.  The same reviewed, unsigned installer
is then bound to its signed form with an Authenticode-neutral PE digest and a
complete inventory of the extracted payload.

Security boundary:

* this module does not validate the Authenticode certificate chain, Publisher,
  or timestamp; the Windows signing gate must do that separately;
* distinct reviewer key IDs cannot prove that distinct natural people control
  the keys; organizational key custody remains a process control;
* a static extractor inventory cannot prove installer runtime behavior, so the
  reviewed ``.iss`` file and lifecycle smoke tests remain mandatory.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import unicodedata
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from packaging.licenses import InvalidLicenseExpression, canonicalize_license_expression

try:  # Direct script execution and namespace-package imports both matter here.
    from scripts.authenticode_digest import (
        AuthenticodeImageDigest,
        inspect_authenticode_image,
    )
except ModuleNotFoundError:  # pragma: no cover - exercised by PowerShell entrypoint
    from authenticode_digest import (  # type: ignore[no-redef]
        AuthenticodeImageDigest,
        inspect_authenticode_image,
    )


INSTALLER_REVIEW_SCOPE = "installer-release-review"
REQUEST_KIND = "defensetracker-installer-review-request"
APPROVAL_KIND = "defensetracker-installer-review-approval"
PE_DIGEST_ALGORITHM = "sha256-authenticode-neutral-pe-v1"

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SEMVER_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
)
KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
REVIEW_REFERENCE_RE = re.compile(r"^installer-review:[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
UTC_SECONDS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

_REQUEST_KEYS = {
    "schema",
    "kind",
    "release_commit",
    "source_tree",
    "version",
    "publisher",
    "recipe",
    "bootstrap_license",
    "unsigned_installer",
    "payload_inventory_sha256",
    "payload_inventory",
}
_RECIPE_KEYS = {
    "iss_sha256",
    "iscc_sha256",
    "iscc_version",
    "seven_zip_sha256",
    "seven_zip_version",
    "signed_application_inventory_sha256",
}
_UNSIGNED_INSTALLER_KEYS = {
    "algorithm",
    "bytes",
    "sha256",
    "normalized_sha256",
    "signature_state",
    "certificate_table_offset",
    "certificate_table_bytes",
}
_BOOTSTRAP_LICENSE_KEYS = {
    "license_declared",
    "license_concluded",
    "copyright_text",
    "license_text",
    "license_text_sha256",
}
_INVENTORY_KEYS = {"schema", "files"}
_INVENTORY_FILE_KEYS = {"path", "bytes", "sha256"}
_APPROVAL_KEYS = {
    "schema",
    "kind",
    "request_sha256",
    "request_base64",
    "decision",
    "scope",
    "reviewer_key_id",
    "reviewer_organization",
    "review_reference",
    "reviewed_at_utc",
}
_REGISTRY_KEYS = {"schema", "status", "scope", "reviewers"}
_REVIEWER_KEYS = {
    "key_id",
    "organization",
    "public_key_base64",
    "public_key_sha256",
    "allowed_publishers",
    "scope",
}
_MAX_JSON_BYTES = 64 * 1024 * 1024
_MAX_PAYLOAD_FILES = 200_000
_MAX_FILE_BYTES = 64 * 1024 * 1024 * 1024


@dataclass(frozen=True)
class InstallerBinding:
    """Redaction-safe evidence produced immediately around signing."""

    phase: Literal["pre-sign", "post-sign"]
    installer_sha256: str
    installer_bytes: int
    unsigned_installer_bytes: int
    normalized_sha256: str
    signature_state: Literal["unsigned", "signed"]
    payload_inventory_sha256: str
    payload_file_count: int

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": 1,
            "phase": self.phase,
            "installer_sha256": self.installer_sha256,
            "installer_bytes": self.installer_bytes,
            "unsigned_installer_bytes": self.unsigned_installer_bytes,
            "normalized_sha256": self.normalized_sha256,
            "signature_state": self.signature_state,
            "payload_inventory_sha256": self.payload_inventory_sha256,
            "payload_file_count": self.payload_file_count,
        }


@dataclass(frozen=True)
class InstallerReview:
    """A verified independent approval and its exact canonical request."""

    request_bytes: bytes
    request_sha256: str
    evidence_sha256: str
    signature_sha256: str
    reviewer_registry_sha256: str
    reviewer_key_id: str
    reviewer_organization: str
    review_reference: str
    reviewed_at_utc: str
    pre_sign_binding: InstallerBinding | None = None

    @property
    def request(self) -> dict[str, object]:
        parsed = _strict_json_loads(self.request_bytes, "installer review request")
        if not isinstance(parsed, dict):  # Defense in depth for a forged dataclass.
            raise ValueError("Installer review request must be an object")
        return parsed


def canonical_json_bytes(value: object) -> bytes:
    """Serialize signed material without whitespace or numeric ambiguity."""

    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("Signed JSON material is not canonicalizable") from exc
    return (rendered + "\n").encode("utf-8")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path, *, label: str = "file") -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular file")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
            after = os.fstat(stream.fileno())
    except OSError as exc:
        raise ValueError(f"{label} could not be read") from exc
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ino != after.st_ino
    ):
        raise ValueError(f"{label} changed while it was being hashed")
    return digest.hexdigest()


def _strict_json_loads(payload: bytes, label: str) -> object:
    if not payload or len(payload) > _MAX_JSON_BYTES:
        raise ValueError(f"{label} has an invalid size")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not UTF-8 JSON") from exc

    def reject_constant(value: str) -> object:
        raise ValueError(f"{label} contains a non-finite number: {value}")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains a duplicate key")
            result[key] = value
        return result

    try:
        return json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON") from exc


def _read_json_object(path: Path, label: str, *, canonical: bool) -> tuple[dict[str, object], bytes]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular file")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"{label} could not be read") from exc
    parsed = _strict_json_loads(payload, label)
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} must be an object")
    if canonical and payload != canonical_json_bytes(parsed):
        raise ValueError(f"{label} is not canonical JSON")
    return parsed, payload


def _require_exact_keys(value: dict[str, object], keys: set[str], label: str) -> None:
    if set(value) != keys:
        raise ValueError(f"{label} fields differ from schema")


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _require_git_id(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA1_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase 40-character Git object ID")
    return value


def _require_safe_text(value: object, label: str, *, maximum: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _validate_inventory_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 500:
        raise ValueError("Payload inventory path is invalid")
    if value != unicodedata.normalize("NFC", value):
        raise ValueError("Payload inventory path is not Unicode-normalized")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value.startswith("/")
        or "\\" in value
        or ":" in value
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(part.endswith((" ", ".")) for part in path.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("Payload inventory path is unsafe")
    return value


def build_payload_inventory(root: Path) -> dict[str, object]:
    """Hash every regular extracted payload file using relative POSIX names."""

    if root.is_symlink() or not root.is_dir():
        raise ValueError("Extracted payload root must be a regular directory")
    files: list[dict[str, object]] = []
    seen_casefolded: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("Extracted payload must not contain symbolic links")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("Extracted payload contains a non-regular entry")
        relative = _validate_inventory_path(path.relative_to(root).as_posix())
        folded = relative.casefold()
        if folded in seen_casefolded:
            raise ValueError("Extracted payload contains a case-colliding path")
        seen_casefolded.add(folded)
        size = path.stat().st_size
        if size < 0 or size > _MAX_FILE_BYTES:
            raise ValueError("Extracted payload file size is outside policy")
        files.append(
            {
                "path": relative,
                "bytes": size,
                "sha256": sha256_file(path, label="payload file"),
            }
        )
        if len(files) > _MAX_PAYLOAD_FILES:
            raise ValueError("Extracted payload contains too many files")
    if not files:
        raise ValueError("Extracted payload inventory is empty")
    files.sort(key=lambda item: (str(item["path"]).casefold(), str(item["path"])))
    inventory: dict[str, object] = {"schema": 1, "files": files}
    _validate_payload_inventory(inventory)
    return inventory


def _validate_payload_inventory(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("Payload inventory must be an object")
    _require_exact_keys(value, _INVENTORY_KEYS, "payload inventory")
    if value.get("schema") != 1 or not isinstance(value.get("files"), list):
        raise ValueError("Payload inventory schema is invalid")
    rows = value["files"]
    if not rows or len(rows) > _MAX_PAYLOAD_FILES:
        raise ValueError("Payload inventory file count is invalid")
    seen: set[str] = set()
    previous: tuple[str, str] | None = None
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Payload inventory entry must be an object")
        _require_exact_keys(row, _INVENTORY_FILE_KEYS, "payload inventory entry")
        relative = _validate_inventory_path(row.get("path"))
        folded = relative.casefold()
        if folded in seen:
            raise ValueError("Payload inventory contains a duplicate path")
        seen.add(folded)
        order_key = (folded, relative)
        if previous is not None and order_key <= previous:
            raise ValueError("Payload inventory is not deterministically ordered")
        previous = order_key
        size = row.get("bytes")
        if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= _MAX_FILE_BYTES:
            raise ValueError("Payload inventory file size is invalid")
        _require_sha256(row.get("sha256"), "payload inventory file hash")
    return value


def _identity_record(identity: AuthenticodeImageDigest) -> dict[str, object]:
    return {
        "algorithm": identity.algorithm,
        "bytes": identity.bytes,
        "sha256": identity.file_sha256,
        "normalized_sha256": identity.normalized_sha256,
        "signature_state": identity.signature_state,
        "certificate_table_offset": identity.certificate_table_offset,
        "certificate_table_bytes": identity.certificate_table_bytes,
    }


def _bootstrap_license_record(
    *,
    license_declared: str,
    license_concluded: str,
    copyright_text: str,
    license_text_path: Path,
) -> dict[str, object]:
    if license_text_path.is_symlink() or not license_text_path.is_file():
        raise ValueError("Installer bootstrap license text must be a regular file")
    try:
        license_text_bytes = license_text_path.read_bytes()
        license_text = license_text_bytes.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError("Installer bootstrap license text must be UTF-8") from exc
    if license_text.encode("utf-8") != license_text_bytes:
        raise ValueError("Installer bootstrap license text encoding is not canonical UTF-8")
    record: dict[str, object] = {
        "license_declared": license_declared,
        "license_concluded": license_concluded,
        "copyright_text": copyright_text,
        "license_text": license_text,
        "license_text_sha256": sha256_bytes(license_text_bytes),
    }
    # Reuse the complete request validator by validating these fields below in
    # the caller; this helper intentionally performs only lossless file loading.
    return record


def _validate_request(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("Installer review request must be an object")
    _require_exact_keys(value, _REQUEST_KEYS, "installer review request")
    if value.get("schema") != 1 or value.get("kind") != REQUEST_KIND:
        raise ValueError("Installer review request schema is invalid")
    _require_git_id(value.get("release_commit"), "release_commit")
    _require_git_id(value.get("source_tree"), "source_tree")
    version = value.get("version")
    if not isinstance(version, str) or SEMVER_RE.fullmatch(version) is None:
        raise ValueError("Installer review version is not a stable semantic version")
    _require_safe_text(value.get("publisher"), "publisher")

    recipe = value.get("recipe")
    if not isinstance(recipe, dict):
        raise ValueError("Installer review recipe must be an object")
    _require_exact_keys(recipe, _RECIPE_KEYS, "installer review recipe")
    for field in (
        "iss_sha256",
        "iscc_sha256",
        "seven_zip_sha256",
        "signed_application_inventory_sha256",
    ):
        _require_sha256(recipe.get(field), f"recipe.{field}")
    _require_safe_text(recipe.get("iscc_version"), "recipe.iscc_version")
    _require_safe_text(recipe.get("seven_zip_version"), "recipe.seven_zip_version")

    bootstrap_license = value.get("bootstrap_license")
    if not isinstance(bootstrap_license, dict):
        raise ValueError("Installer bootstrap license review must be an object")
    _require_exact_keys(
        bootstrap_license,
        _BOOTSTRAP_LICENSE_KEYS,
        "installer bootstrap license review",
    )
    for field in ("license_declared", "license_concluded"):
        expression = bootstrap_license.get(field)
        if not isinstance(expression, str):
            raise ValueError("Installer bootstrap license expression is invalid")
        if expression in {"NOASSERTION", "NONE"}:
            raise ValueError(
                "Installer bootstrap license expression must be canonical and resolved"
            )
        try:
            canonical = canonicalize_license_expression(expression)
        except InvalidLicenseExpression as exc:
            raise ValueError("Installer bootstrap license expression is invalid") from exc
        if expression != canonical or canonical in {"NOASSERTION", "NONE"}:
            raise ValueError(
                "Installer bootstrap license expression must be canonical and resolved"
            )
    _require_safe_text(
        bootstrap_license.get("copyright_text"),
        "installer bootstrap copyright",
        maximum=1000,
    )
    license_text = bootstrap_license.get("license_text")
    if (
        not isinstance(license_text, str)
        or not license_text.strip()
        or len(license_text.encode("utf-8")) > 1024 * 1024
        or any(
            ord(character) < 32 and character not in "\r\n\t"
            for character in license_text
        )
    ):
        raise ValueError("Installer bootstrap license text is invalid")
    license_text_sha256 = _require_sha256(
        bootstrap_license.get("license_text_sha256"),
        "installer bootstrap license text SHA-256",
    )
    if license_text_sha256 != sha256_bytes(license_text.encode("utf-8")):
        raise ValueError("Installer bootstrap license text hash does not match the text")

    unsigned = value.get("unsigned_installer")
    if not isinstance(unsigned, dict):
        raise ValueError("Unsigned installer identity must be an object")
    _require_exact_keys(unsigned, _UNSIGNED_INSTALLER_KEYS, "unsigned installer identity")
    size = unsigned.get("bytes")
    if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= _MAX_FILE_BYTES:
        raise ValueError("Unsigned installer size is invalid")
    if (
        unsigned.get("algorithm") != PE_DIGEST_ALGORITHM
        or unsigned.get("signature_state") != "unsigned"
        or unsigned.get("certificate_table_offset") != 0
        or unsigned.get("certificate_table_bytes") != 0
    ):
        raise ValueError("Unsigned installer is not a strict unsigned PE identity")
    _require_sha256(unsigned.get("sha256"), "unsigned installer SHA-256")
    _require_sha256(
        unsigned.get("normalized_sha256"), "unsigned installer normalized SHA-256"
    )

    inventory = _validate_payload_inventory(value.get("payload_inventory"))
    inventory_sha256 = _require_sha256(
        value.get("payload_inventory_sha256"), "payload inventory SHA-256"
    )
    if inventory_sha256 != sha256_bytes(canonical_json_bytes(inventory)):
        raise ValueError("Payload inventory hash does not match its exact contents")
    return value


def generate_installer_review_request(
    *,
    unsigned_installer: Path,
    extracted_payload_root: Path,
    signed_application_inventory: Path,
    iss_path: Path,
    iscc_path: Path,
    iscc_version: str,
    seven_zip_path: Path,
    seven_zip_version: str,
    bootstrap_license_declared: str,
    bootstrap_license_concluded: str,
    bootstrap_copyright_text: str,
    bootstrap_license_text_path: Path,
    release_commit: str,
    source_tree: str,
    version: str,
    publisher: str,
) -> dict[str, object]:
    """Create the canonical request that an independent reviewer will inspect."""

    identity = inspect_authenticode_image(unsigned_installer, require_state="unsigned")
    inventory = build_payload_inventory(extracted_payload_root)
    bootstrap_license = _bootstrap_license_record(
        license_declared=bootstrap_license_declared,
        license_concluded=bootstrap_license_concluded,
        copyright_text=bootstrap_copyright_text,
        license_text_path=bootstrap_license_text_path,
    )
    request: dict[str, object] = {
        "schema": 1,
        "kind": REQUEST_KIND,
        "release_commit": release_commit,
        "source_tree": source_tree,
        "version": version,
        "publisher": publisher,
        "recipe": {
            "iss_sha256": sha256_file(iss_path, label="Inno Setup recipe"),
            "iscc_sha256": sha256_file(iscc_path, label="ISCC tool"),
            "iscc_version": iscc_version,
            "seven_zip_sha256": sha256_file(seven_zip_path, label="7-Zip tool"),
            "seven_zip_version": seven_zip_version,
            "signed_application_inventory_sha256": sha256_file(
                signed_application_inventory,
                label="signed application inventory",
            ),
        },
        "bootstrap_license": bootstrap_license,
        "unsigned_installer": _identity_record(identity),
        "payload_inventory_sha256": sha256_bytes(canonical_json_bytes(inventory)),
        "payload_inventory": inventory,
    }
    return _validate_request(request)


def write_canonical_json(path: Path, value: object) -> None:
    payload = canonical_json_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        temporary.write_bytes(payload)
        os.replace(temporary, path)
    except OSError as exc:
        raise ValueError("Canonical JSON output could not be written") from exc


def _load_signature(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Installer review signature must be a regular file")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ValueError("Installer review signature could not be read") from exc
    if payload.endswith(b"\r\n"):
        payload = payload[:-2]
    elif payload.endswith(b"\n"):
        payload = payload[:-1]
    if not payload or b"\r" in payload or b"\n" in payload or b" " in payload or b"\t" in payload:
        raise ValueError("Installer review signature encoding is invalid")
    try:
        signature = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Installer review signature encoding is invalid") from exc
    if len(signature) != 64:
        raise ValueError("Installer review signature length is invalid")
    return signature


def _load_active_reviewer(
    registry_path: Path,
    *,
    reviewer_key_id: str,
    publisher: str,
    application_reviewer_key_id: str,
) -> tuple[dict[str, object], str]:
    registry, registry_bytes = _read_json_object(
        registry_path, "installer reviewer registry", canonical=False
    )
    _require_exact_keys(registry, _REGISTRY_KEYS, "installer reviewer registry")
    if (
        registry.get("schema") != 1
        or registry.get("status") != "active"
        or registry.get("scope") != INSTALLER_REVIEW_SCOPE
        or not isinstance(registry.get("reviewers"), list)
    ):
        raise ValueError("Installer reviewer registry is inactive or malformed")
    _require_safe_text(application_reviewer_key_id, "application reviewer key ID")
    if reviewer_key_id == application_reviewer_key_id:
        raise ValueError("Application and installer reviews must use different key IDs")

    matches: list[dict[str, object]] = []
    seen_key_ids: set[str] = set()
    seen_public_keys: set[str] = set()
    for item in registry["reviewers"]:
        if not isinstance(item, dict):
            raise ValueError("Installer reviewer registration must be an object")
        _require_exact_keys(item, _REVIEWER_KEYS, "installer reviewer registration")
        key_id = item.get("key_id")
        if not isinstance(key_id, str) or KEY_ID_RE.fullmatch(key_id) is None:
            raise ValueError("Installer reviewer key ID is invalid")
        if key_id in seen_key_ids:
            raise ValueError("Installer reviewer registry contains a duplicate key ID")
        seen_key_ids.add(key_id)
        _require_safe_text(item.get("organization"), "reviewer organization")
        if item.get("scope") != INSTALLER_REVIEW_SCOPE:
            raise ValueError("Installer reviewer has the wrong scope")
        public_key_sha256 = _require_sha256(
            item.get("public_key_sha256"), "reviewer public-key SHA-256"
        )
        if public_key_sha256 in seen_public_keys:
            raise ValueError("Installer reviewer registry reuses a public key")
        seen_public_keys.add(public_key_sha256)
        publishers = item.get("allowed_publishers")
        if (
            not isinstance(publishers, list)
            or not publishers
            or len(publishers) > 100
            or any(not isinstance(value, str) for value in publishers)
        ):
            raise ValueError("Installer reviewer Publisher allowlist is invalid")
        checked_publishers = [
            _require_safe_text(value, "allowed Publisher") for value in publishers
        ]
        if len(set(checked_publishers)) != len(checked_publishers):
            raise ValueError("Installer reviewer Publisher allowlist has duplicates")
        if key_id == reviewer_key_id:
            matches.append(item)
    if len(matches) != 1:
        raise ValueError("Installer reviewer key is not uniquely registered")
    reviewer = matches[0]
    if publisher not in reviewer["allowed_publishers"]:
        raise ValueError("Installer reviewer is not authorized for this Publisher")
    return reviewer, sha256_bytes(registry_bytes)


def load_installer_review(
    evidence_path: Path,
    signature_path: Path,
    reviewer_registry: Path,
    *,
    expected_evidence_sha256: str,
    application_reviewer_key_id: str,
    expected_commit: str,
    expected_source_tree: str,
    expected_version: str,
    expected_publisher: str,
) -> InstallerReview:
    """Authenticate one exact approved request against the protected registry."""

    expected_evidence_sha256 = _require_sha256(
        expected_evidence_sha256, "expected installer review evidence SHA-256"
    )
    evidence, evidence_bytes = _read_json_object(
        evidence_path, "installer review evidence", canonical=True
    )
    actual_evidence_sha256 = sha256_bytes(evidence_bytes)
    if actual_evidence_sha256 != expected_evidence_sha256:
        raise ValueError("Installer review evidence SHA-256 differs from the trusted value")
    _require_exact_keys(evidence, _APPROVAL_KEYS, "installer review evidence")
    if (
        evidence.get("schema") != 1
        or evidence.get("kind") != APPROVAL_KIND
        or evidence.get("decision") != "approved"
        or evidence.get("scope") != INSTALLER_REVIEW_SCOPE
    ):
        raise ValueError("Installer review evidence is not an approval for this scope")
    reviewer_key_id = evidence.get("reviewer_key_id")
    if not isinstance(reviewer_key_id, str) or KEY_ID_RE.fullmatch(reviewer_key_id) is None:
        raise ValueError("Installer reviewer key ID is invalid")
    reviewer_organization = _require_safe_text(
        evidence.get("reviewer_organization"), "reviewer organization"
    )
    review_reference = evidence.get("review_reference")
    if (
        not isinstance(review_reference, str)
        or REVIEW_REFERENCE_RE.fullmatch(review_reference) is None
    ):
        raise ValueError("Installer review reference is invalid")
    reviewed_at = evidence.get("reviewed_at_utc")
    if not isinstance(reviewed_at, str) or UTC_SECONDS_RE.fullmatch(reviewed_at) is None:
        raise ValueError("Installer review timestamp is not canonical UTC seconds")
    try:
        datetime.strptime(reviewed_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ValueError("Installer review timestamp is invalid") from exc

    request_sha256 = _require_sha256(
        evidence.get("request_sha256"), "installer review request SHA-256"
    )
    request_base64 = evidence.get("request_base64")
    if not isinstance(request_base64, str) or not request_base64:
        raise ValueError("Installer review request bytes are missing")
    try:
        request_bytes = base64.b64decode(request_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Installer review request bytes are not valid base64") from exc
    if sha256_bytes(request_bytes) != request_sha256:
        raise ValueError("Installer review request hash does not match its exact bytes")
    parsed_request = _strict_json_loads(request_bytes, "installer review request")
    if not isinstance(parsed_request, dict) or request_bytes != canonical_json_bytes(parsed_request):
        raise ValueError("Installer review request is not canonical JSON")
    request = _validate_request(parsed_request)

    expected_commit = _require_git_id(expected_commit, "expected release commit")
    expected_source_tree = _require_git_id(expected_source_tree, "expected source tree")
    if not isinstance(expected_version, str) or SEMVER_RE.fullmatch(expected_version) is None:
        raise ValueError("Expected version is invalid")
    expected_publisher = _require_safe_text(expected_publisher, "expected Publisher")
    if (
        request["release_commit"] != expected_commit
        or request["source_tree"] != expected_source_tree
        or request["version"] != expected_version
        or request["publisher"] != expected_publisher
    ):
        raise ValueError("Installer review request does not bind the expected release")

    reviewer, registry_sha256 = _load_active_reviewer(
        reviewer_registry,
        reviewer_key_id=reviewer_key_id,
        publisher=expected_publisher,
        application_reviewer_key_id=application_reviewer_key_id,
    )
    if reviewer.get("organization") != reviewer_organization:
        raise ValueError("Installer reviewer organization differs from the registry")
    try:
        public_key = base64.b64decode(
            str(reviewer.get("public_key_base64", "")), validate=True
        )
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Installer reviewer public key is invalid") from exc
    if (
        len(public_key) != 32
        or sha256_bytes(public_key) != reviewer.get("public_key_sha256")
    ):
        raise ValueError("Installer reviewer public key does not match its registry hash")
    signature = _load_signature(signature_path)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, evidence_bytes)
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("Installer review evidence signature is invalid") from exc

    return InstallerReview(
        request_bytes=request_bytes,
        request_sha256=request_sha256,
        evidence_sha256=actual_evidence_sha256,
        signature_sha256=sha256_bytes(signature),
        reviewer_registry_sha256=registry_sha256,
        reviewer_key_id=reviewer_key_id,
        reviewer_organization=reviewer_organization,
        review_reference=review_reference,
        reviewed_at_utc=reviewed_at,
    )


def _compare_identity(expected: dict[str, object], actual: AuthenticodeImageDigest) -> None:
    if _identity_record(actual) != expected:
        raise ValueError("Unsigned installer bytes differ from the reviewed request")


def _compare_payload(expected: object, root: Path) -> dict[str, object]:
    expected_inventory = _validate_payload_inventory(expected)
    actual_inventory = build_payload_inventory(root)
    if actual_inventory != expected_inventory:
        raise ValueError("Extracted installer payload differs from the reviewed inventory")
    return actual_inventory


def _binding(
    phase: Literal["pre-sign", "post-sign"],
    identity: AuthenticodeImageDigest,
    inventory: dict[str, object],
) -> InstallerBinding:
    rows = inventory["files"]
    assert isinstance(rows, list)  # validated by _validate_payload_inventory
    return InstallerBinding(
        phase=phase,
        installer_sha256=identity.file_sha256,
        installer_bytes=identity.bytes,
        unsigned_installer_bytes=identity.unsigned_bytes,
        normalized_sha256=identity.normalized_sha256,
        signature_state=identity.signature_state,
        payload_inventory_sha256=sha256_bytes(canonical_json_bytes(inventory)),
        payload_file_count=len(rows),
    )


def verify_installer_before_sign(
    *,
    evidence_path: Path,
    signature_path: Path,
    reviewer_registry: Path,
    expected_evidence_sha256: str,
    application_reviewer_key_id: str,
    unsigned_installer: Path,
    extracted_payload_root: Path,
    signed_application_inventory: Path,
    iss_path: Path,
    iscc_path: Path,
    iscc_version: str,
    seven_zip_path: Path,
    seven_zip_version: str,
    bootstrap_license_declared: str,
    bootstrap_license_concluded: str,
    bootstrap_copyright_text: str,
    bootstrap_license_text_path: Path,
    expected_commit: str,
    expected_source_tree: str,
    expected_version: str,
    expected_publisher: str,
) -> InstallerReview:
    """Verify the exact reviewed candidate immediately before signing."""

    review = load_installer_review(
        evidence_path,
        signature_path,
        reviewer_registry,
        expected_evidence_sha256=expected_evidence_sha256,
        application_reviewer_key_id=application_reviewer_key_id,
        expected_commit=expected_commit,
        expected_source_tree=expected_source_tree,
        expected_version=expected_version,
        expected_publisher=expected_publisher,
    )
    request = review.request
    recipe = request["recipe"]
    assert isinstance(recipe, dict)
    actual_recipe = {
        "iss_sha256": sha256_file(iss_path, label="Inno Setup recipe"),
        "iscc_sha256": sha256_file(iscc_path, label="ISCC tool"),
        "iscc_version": _require_safe_text(iscc_version, "ISCC version"),
        "seven_zip_sha256": sha256_file(seven_zip_path, label="7-Zip tool"),
        "seven_zip_version": _require_safe_text(seven_zip_version, "7-Zip version"),
        "signed_application_inventory_sha256": sha256_file(
            signed_application_inventory, label="signed application inventory"
        ),
    }
    if actual_recipe != recipe:
        raise ValueError("Installer build recipe differs from the reviewed request")
    actual_bootstrap_license = _bootstrap_license_record(
        license_declared=bootstrap_license_declared,
        license_concluded=bootstrap_license_concluded,
        copyright_text=bootstrap_copyright_text,
        license_text_path=bootstrap_license_text_path,
    )
    if actual_bootstrap_license != request["bootstrap_license"]:
        raise ValueError("Installer bootstrap license differs from the reviewed request")

    unsigned_identity = inspect_authenticode_image(
        unsigned_installer, require_state="unsigned"
    )
    expected_identity = request["unsigned_installer"]
    assert isinstance(expected_identity, dict)
    _compare_identity(expected_identity, unsigned_identity)
    inventory = _compare_payload(request["payload_inventory"], extracted_payload_root)
    binding = _binding("pre-sign", unsigned_identity, inventory)
    if binding.payload_inventory_sha256 != request["payload_inventory_sha256"]:
        raise ValueError("Pre-sign payload hash differs from the reviewed request")
    return replace(review, pre_sign_binding=binding)


def verify_installer_after_sign(
    review: InstallerReview,
    *,
    signed_installer: Path,
    extracted_payload_root: Path,
) -> InstallerBinding:
    """Bind the signed PE and its re-extracted payload to the approved request."""

    if not isinstance(review, InstallerReview) or review.pre_sign_binding is None:
        raise ValueError("Post-sign verification requires a verified pre-sign review")
    request = review.request
    _validate_request(request)
    unsigned = request["unsigned_installer"]
    assert isinstance(unsigned, dict)
    signed_identity = inspect_authenticode_image(
        signed_installer,
        require_state="signed",
        expected_unsigned_size=int(unsigned["bytes"]),
        expected_normalized_sha256=str(unsigned["normalized_sha256"]),
    )
    inventory = _compare_payload(request["payload_inventory"], extracted_payload_root)
    binding = _binding("post-sign", signed_identity, inventory)
    if (
        binding.unsigned_installer_bytes != review.pre_sign_binding.unsigned_installer_bytes
        or binding.normalized_sha256 != review.pre_sign_binding.normalized_sha256
        or binding.payload_inventory_sha256
        != review.pre_sign_binding.payload_inventory_sha256
    ):
        raise ValueError("Signed installer binding differs from the verified unsigned candidate")
    return binding


def _add_review_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--reviewer-registry", type=Path, required=True)
    parser.add_argument("--expected-evidence-sha256", required=True)
    parser.add_argument("--application-reviewer-key-id", required=True)
    parser.add_argument("--unsigned-installer", type=Path, required=True)
    parser.add_argument("--payload-root", type=Path, required=True)
    parser.add_argument("--signed-application-inventory", type=Path, required=True)
    parser.add_argument("--iss", type=Path, required=True)
    parser.add_argument("--iscc", type=Path, required=True)
    parser.add_argument("--iscc-version", required=True)
    parser.add_argument("--seven-zip", type=Path, required=True)
    parser.add_argument("--seven-zip-version", required=True)
    parser.add_argument("--bootstrap-license-declared", required=True)
    parser.add_argument("--bootstrap-license-concluded", required=True)
    parser.add_argument("--bootstrap-copyright-text", required=True)
    parser.add_argument("--bootstrap-license-text", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--publisher", required=True)
    parser.add_argument("--output", type=Path)


def _review_from_args(args: argparse.Namespace) -> InstallerReview:
    return verify_installer_before_sign(
        evidence_path=args.evidence,
        signature_path=args.signature,
        reviewer_registry=args.reviewer_registry,
        expected_evidence_sha256=args.expected_evidence_sha256,
        application_reviewer_key_id=args.application_reviewer_key_id,
        unsigned_installer=args.unsigned_installer,
        extracted_payload_root=args.payload_root,
        signed_application_inventory=args.signed_application_inventory,
        iss_path=args.iss,
        iscc_path=args.iscc,
        iscc_version=args.iscc_version,
        seven_zip_path=args.seven_zip,
        seven_zip_version=args.seven_zip_version,
        bootstrap_license_declared=args.bootstrap_license_declared,
        bootstrap_license_concluded=args.bootstrap_license_concluded,
        bootstrap_copyright_text=args.bootstrap_copyright_text,
        bootstrap_license_text_path=args.bootstrap_license_text,
        expected_commit=args.commit,
        expected_source_tree=args.source_tree,
        expected_version=args.version,
        expected_publisher=args.publisher,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="phase", required=True)
    pre = subparsers.add_parser("pre-sign")
    _add_review_arguments(pre)
    post = subparsers.add_parser("post-sign")
    _add_review_arguments(post)
    post.add_argument("--signed-installer", type=Path, required=True)
    args = parser.parse_args()

    review = _review_from_args(args)
    if args.phase == "pre-sign":
        assert review.pre_sign_binding is not None
        binding = review.pre_sign_binding
    else:
        binding = verify_installer_after_sign(
            review,
            signed_installer=args.signed_installer,
            extracted_payload_root=args.payload_root,
        )
    if args.output is not None:
        write_canonical_json(args.output, binding.as_dict())
    print(f"installer-review-{args.phase}: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
