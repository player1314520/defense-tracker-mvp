# -*- coding: utf-8 -*-
"""Bind a protected GitHub Environment approval to a Windows installer.

The preparation job generates an exact canonical installer review request.  A
separate job may consume it only after GitHub admits that job to the protected
``v9-installer-signing-review`` Environment.  The resulting approval context
binds the request to the repository, workflow, release commit and exact Actions
run/attempt.  The same reviewed, unsigned installer is then bound to its signed
form with an Authenticode-neutral PE digest and a complete inventory of the
extracted payload.

Security boundary:

* this module does not validate the Authenticode certificate chain, Publisher,
  or timestamp; the Windows signing gate must do that separately;
* this context records the single-maintainer Environment review model; it does
  not identify the human approver and must be paired with GitHub's deployment
  protection and audit logs;
* a static extractor inventory cannot prove installer runtime behavior, so the
  reviewed ``.iss`` file and lifecycle smoke tests remain mandatory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import unicodedata
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Literal

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

try:  # Direct script execution and namespace-package imports both matter here.
    from scripts.github_environment_approval import load_approval_context
except ModuleNotFoundError:  # pragma: no cover - exercised by PowerShell entrypoint
    from github_environment_approval import load_approval_context  # type: ignore[no-redef]


INSTALLER_REVIEW_SCOPE = "installer-release-review"
REQUEST_KIND = "defensetracker-installer-review-request"
APPROVAL_SUBJECT_KIND = "installer-review-request"
APPROVAL_ENVIRONMENT = "v9-installer-signing-review"
APPROVAL_JOB = "finalize-signed-candidate"
PE_DIGEST_ALGORITHM = "sha256-authenticode-neutral-pe-v1"

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SEMVER_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
)

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
_MAX_JSON_BYTES = 64 * 1024 * 1024
_MAX_PAYLOAD_FILES = 200_000
_MAX_FILE_BYTES = 64 * 1024 * 1024 * 1024
_MAX_POSITIVE_ID = 9_223_372_036_854_775_807


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
    """A protected-Environment approval and its exact canonical request."""

    request_bytes: bytes
    request_sha256: str
    approval_context_sha256: str
    approval_environment: str
    approval_repository: str
    approval_workflow_ref: str
    approval_run_id: int
    approval_run_attempt: int
    review_model: str
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


def _require_positive_id(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > _MAX_POSITIVE_ID
    ):
        raise ValueError(f"{label} must be a positive 64-bit integer")
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
    """Create the canonical request admitted through the protected Environment."""

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


def load_installer_review(
    request_path: Path,
    approval_context_path: Path,
    *,
    expected_repository: str,
    expected_workflow_ref: str,
    expected_run_id: int,
    expected_run_attempt: int,
    expected_commit: str,
    expected_source_tree: str,
    expected_version: str,
    expected_publisher: str,
) -> InstallerReview:
    """Bind one exact request to the protected Environment job that consumes it."""

    request, request_bytes = _read_json_object(
        request_path, "installer review request", canonical=True
    )
    request = _validate_request(request)
    request_sha256 = sha256_bytes(request_bytes)

    expected_commit = _require_git_id(expected_commit, "expected release commit")
    expected_source_tree = _require_git_id(expected_source_tree, "expected source tree")
    expected_run_id = _require_positive_id(expected_run_id, "expected run ID")
    expected_run_attempt = _require_positive_id(
        expected_run_attempt, "expected run attempt"
    )
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

    approval_context_sha256_before = sha256_file(
        approval_context_path, label="installer approval context"
    )
    approval = load_approval_context(
        approval_context_path,
        expected_environment=APPROVAL_ENVIRONMENT,
        expected_repository=expected_repository,
        expected_workflow_ref=expected_workflow_ref,
        expected_release_commit=expected_commit,
        expected_run_id=expected_run_id,
        expected_run_attempt=expected_run_attempt,
        expected_job=APPROVAL_JOB,
        expected_subject_kind=APPROVAL_SUBJECT_KIND,
        expected_subject_sha256=request_sha256,
    )
    approval_context_sha256_after = sha256_file(
        approval_context_path, label="installer approval context"
    )
    if approval_context_sha256_before != approval_context_sha256_after:
        raise ValueError("Installer approval context changed while it was verified")

    return InstallerReview(
        request_bytes=request_bytes,
        request_sha256=request_sha256,
        approval_context_sha256=approval_context_sha256_after,
        approval_environment=approval.environment,
        approval_repository=approval.repository,
        approval_workflow_ref=approval.workflow_ref,
        approval_run_id=approval.run_id,
        approval_run_attempt=approval.run_attempt,
        review_model=approval.review_model,
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
    request_path: Path,
    approval_context_path: Path,
    expected_repository: str,
    expected_workflow_ref: str,
    expected_run_id: int,
    expected_run_attempt: int,
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
        request_path,
        approval_context_path,
        expected_repository=expected_repository,
        expected_workflow_ref=expected_workflow_ref,
        expected_run_id=expected_run_id,
        expected_run_attempt=expected_run_attempt,
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
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--approval-context", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
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
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-publisher", required=True)
    parser.add_argument("--output", type=Path)


def _review_from_args(args: argparse.Namespace) -> InstallerReview:
    return verify_installer_before_sign(
        request_path=args.request,
        approval_context_path=args.approval_context,
        expected_repository=args.repository,
        expected_workflow_ref=args.workflow_ref,
        expected_run_id=args.run_id,
        expected_run_attempt=args.run_attempt,
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
        expected_commit=args.release_sha,
        expected_source_tree=args.expected_tree,
        expected_version=args.expected_version,
        expected_publisher=args.expected_publisher,
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
