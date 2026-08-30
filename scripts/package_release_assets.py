# -*- coding: utf-8 -*-
"""Create the fixed DefenseTracker release asset set without publishing it."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from packaging.licenses import InvalidLicenseExpression, canonicalize_license_expression


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from product_version import PRODUCT_VERSION  # noqa: E402
from scripts.authenticode_digest import inspect_authenticode_image  # noqa: E402
from scripts.installer_review import (  # noqa: E402
    _read_json_object as read_installer_review_json,
    _validate_request as validate_installer_review_request,
    build_payload_inventory,
    canonical_json_bytes as installer_review_canonical_bytes,
)
from scripts.signing_exchange import (  # noqa: E402
    _safe_relative_path as safe_relative_path,
    _validate_receipt as validate_signing_receipt,
    _validate_request as validate_signing_request,
    load_canonical_json as load_signing_exchange_json,
    resolve_path_within,
)


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s]+)$")
REVIEW_REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/\-]{2,127}$")
EXPECTED_REPOSITORY = "player1314520/defense-tracker-mvp"
SIGNED_CANDIDATE_WORKFLOW_REF = (
    f"{EXPECTED_REPOSITORY}/.github/workflows/v9-signed-candidate.yml@refs/heads/main"
)


def parse_utc(value: str, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{field} must be an ISO-8601 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo != timezone.utc:
        parsed = parsed.astimezone(timezone.utc)
    return parsed


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_signing_exchange_paths(
    raw_paths: dict[str, object],
    *,
    cli_root: Path,
) -> dict[str, Path]:
    """Resolve CLI exchange members only after strict relative-path validation."""

    resolved: dict[str, Path] = {}
    casefold_paths: set[str] = set()
    for name, value in raw_paths.items():
        normalized = safe_relative_path(
            value,
            label=f"--{name.replace('_', '-')}",
        )
        folded = normalized.casefold()
        if folded in casefold_paths:
            raise ValueError(
                "Signing exchange CLI paths must be case-insensitively unique"
            )
        casefold_paths.add(folded)
        exchange_path = resolve_path_within(
            cli_root,
            normalized,
            label=f"--{name.replace('_', '-')}",
            kind="file",
        )
        resolved[name] = exchange_path
    return resolved


def _positive_github_id(value: object, *, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a positive integer")
    try:
        parsed = int(str(value), 10)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a positive integer") from exc
    if parsed < 1 or parsed > 9_223_372_036_854_775_807:
        raise ValueError(f"{field} must be a positive integer")
    return parsed


def _github_release_binding(args: argparse.Namespace) -> tuple[str, str, int, int]:
    repository = str(
        getattr(args, "github_repository", None)
        or os.environ.get("GITHUB_REPOSITORY", "")
    )
    workflow_ref = str(
        getattr(args, "github_workflow_ref", None)
        or os.environ.get("GITHUB_WORKFLOW_REF", "")
    )
    run_id = _positive_github_id(
        getattr(args, "github_run_id", None) or os.environ.get("GITHUB_RUN_ID", ""),
        field="GITHUB_RUN_ID",
    )
    run_attempt = _positive_github_id(
        getattr(args, "github_run_attempt", None)
        or os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        field="GITHUB_RUN_ATTEMPT",
    )
    if repository != EXPECTED_REPOSITORY:
        raise ValueError("GITHUB_REPOSITORY is not the public release repository")
    if workflow_ref != SIGNED_CANDIDATE_WORKFLOW_REF:
        raise ValueError("GITHUB_WORKFLOW_REF is not the protected candidate workflow")
    return repository, workflow_ref, run_id, run_attempt


def load_signing_exchange_evidence(
    request_path: Path,
    receipt_path: Path,
    *,
    subject_kind: str,
    commit: str,
    publisher: str,
    provider: str,
) -> dict[str, object]:
    request_value, request_bytes = load_signing_exchange_json(
        request_path, label=f"{subject_kind} signing request"
    )
    receipt_value, receipt_bytes = load_signing_exchange_json(
        receipt_path, label=f"{subject_kind} signing receipt"
    )
    request = validate_signing_request(request_value)
    receipt = validate_signing_receipt(receipt_value)
    request_sha256 = hashlib.sha256(request_bytes).hexdigest()
    release = request["release"]
    target = request["target"]
    signature = receipt["signature"]
    assert isinstance(release, dict)
    assert isinstance(target, dict)
    assert isinstance(signature, dict)
    expected = {
        "subject_kind": subject_kind,
        "request_sha256": request_sha256,
        "release_commit": commit,
        "target_path": target["path"],
        "unsigned_sha256": target["sha256"],
    }
    if (
        request["subject_kind"] != subject_kind
        or release["commit"] != commit
        or release["publisher"] != publisher
        or signature["provider"] != provider
        or signature["publisher"] != publisher
        or any(receipt[field] != value for field, value in expected.items())
    ):
        raise ValueError(f"{subject_kind} signing exchange identity is inconsistent")
    if request_path.read_bytes() != request_bytes or receipt_path.read_bytes() != receipt_bytes:
        raise ValueError(f"{subject_kind} signing exchange changed during packaging")
    return {
        "request_schema": request["schema"],
        "request_sha256": request_sha256,
        "request_base64": base64.b64encode(request_bytes).decode("ascii"),
        "request_provenance": request["provenance"],
        "receipt_schema": receipt["schema"],
        "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "receipt_base64": base64.b64encode(receipt_bytes).decode("ascii"),
        "receipt_provenance": receipt["provenance"],
        "completed_at_utc": receipt["completed_at_utc"],
        "signature": signature,
        "unsigned_sha256": receipt["unsigned_sha256"],
        "signed_sha256": receipt["signed_sha256"],
        "signed_bytes": receipt["signed_bytes"],
        "target": target,
    }


def file_entry(path: Path, *, relative_to: Path | None = None) -> dict[str, object]:
    relative = path.name if relative_to is None else path.relative_to(relative_to).as_posix()
    return {"path": relative, "bytes": path.stat().st_size, "sha256": sha256_file(path)}


def list_files(root: Path, *, exclude: set[str] | None = None) -> list[dict[str, object]]:
    excluded = exclude or set()
    return [
        file_entry(path, relative_to=root)
        for path in sorted(root.rglob("*"), key=lambda value: value.as_posix().lower())
        if path.is_file() and path.relative_to(root).as_posix() not in excluded
    ]


def _zip_datetime(epoch: int) -> tuple[int, int, int, int, int, int]:
    value = datetime.fromtimestamp(epoch, tz=timezone.utc)
    if value.year < 1980:
        value = datetime(1980, 1, 1, tzinfo=timezone.utc)
    return (value.year, value.month, value.day, value.hour, value.minute, value.second)


def write_portable_zip(application_root: Path, destination: Path, *, epoch: int) -> None:
    with zipfile.ZipFile(
        destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for source in sorted(
            application_root.rglob("*"), key=lambda value: value.as_posix().lower()
        ):
            if not source.is_file():
                continue
            relative = PurePosixPath("DefenseTracker") / PurePosixPath(
                source.relative_to(application_root).as_posix()
            )
            info = zipfile.ZipInfo(relative.as_posix(), date_time=_zip_datetime(epoch))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            with source.open("rb") as stream:
                archive.writestr(info, stream.read(), compress_type=zipfile.ZIP_DEFLATED)


def _spdx_id(name: str) -> str:
    return "SPDXRef-Package-" + re.sub(r"[^A-Za-z0-9.-]", "-", name)


def parse_packages(path: Path) -> list[tuple[str, str]]:
    packages: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = PACKAGE_RE.fullmatch(line.strip())
        if match:
            packages[match.group(1).lower()] = match.group(2)
    if not packages:
        raise ValueError("Installed package inventory is empty")
    return sorted(packages.items())


def load_toolchain_evidence(path: Path, *, signing_provider: str) -> dict[str, object]:
    evidence = json.loads(path.read_text(encoding="utf-8-sig"))
    required = {"python", "signtool", "iscc", "seven_zip", "defender"}
    missing = required.difference(evidence)
    if missing:
        raise ValueError(f"Signed toolchain evidence is incomplete: {sorted(missing)}")
    for name in sorted(required):
        item = evidence[name]
        if not isinstance(item, dict):
            raise ValueError(f"Toolchain evidence is malformed for {name}")
        actual = item.get("sha256")
        expected = item.get("expected_sha256")
        version = item.get("version")
        if (
            not isinstance(actual, str)
            or SHA256_RE.fullmatch(actual) is None
            or actual != expected
            or item.get("hash_verified") is not True
            or not isinstance(version, str)
            or not version.strip()
        ):
            raise ValueError(f"Toolchain evidence is not hash-verified for {name}")
    return {name: evidence[name] for name in sorted(required)}


def load_compliance_evidence(
    path: Path,
    *,
    application_signing_request_path: Path,
    expected_application_signing_request_sha256: str,
    component_inventory_file: Path,
    application_root: Path,
    expected_sha256: str,
    commit: str,
    source_tree: str,
    publisher: str,
    packages_file: Path,
    notices: Path,
    runtime_lock_sha256: str,
    build_lock_sha256: str,
    verified_at_utc: str,
    expected_repository: str,
    expected_workflow_ref: str,
    expected_run_id: int,
    expected_run_attempt: int,
) -> tuple[
    dict[str, dict[str, str]],
    dict[str, dict[str, object]],
    dict[str, object],
]:
    if SHA256_RE.fullmatch(expected_sha256) is None:
        raise ValueError("Expected compliance evidence SHA-256 is invalid")
    actual_sha256 = sha256_file(path)
    if actual_sha256 != expected_sha256:
        raise ValueError("Compliance evidence SHA-256 does not match the trusted value")
    evidence_bytes = path.read_bytes()
    if hashlib.sha256(evidence_bytes).hexdigest() != actual_sha256:
        raise ValueError("Compliance evidence changed while it was verified")
    evidence = json.loads(evidence_bytes.decode("utf-8-sig"))
    required_keys = {
        "schema",
        "release_commit",
        "source_tree",
        "publisher",
        "reviewed_at_utc",
        "review_reference",
        "license_review",
        "sbom_scope",
        "stable_release_eligible",
        "runtime_lock_sha256",
        "build_lock_sha256",
        "packages_inventory_sha256",
        "third_party_notices_sha256",
        "component_inventory_sha256",
        "components",
        "packages",
    }
    if not isinstance(evidence, dict) or set(evidence) != required_keys:
        raise ValueError("Compliance evidence keys differ from the schema")
    request_value, request_bytes = load_signing_exchange_json(
        application_signing_request_path,
        label="application signing request",
    )
    request = validate_signing_request(request_value)
    request_sha256 = hashlib.sha256(request_bytes).hexdigest()
    request_release = request["release"]
    request_provenance = request["provenance"]
    if not isinstance(request_release, dict) or not isinstance(request_provenance, dict):
        raise ValueError("Application signing request identity is malformed")
    if (
        SHA256_RE.fullmatch(expected_application_signing_request_sha256) is None
        or request_sha256 != expected_application_signing_request_sha256
        or request.get("subject_kind") != "application"
        or request_release.get("commit") != commit
        or request_release.get("source_tree") != source_tree
        or request_release.get("version") != PRODUCT_VERSION.semantic_version
        or request_release.get("publisher") != publisher
        or request_provenance.get("repository") != expected_repository
        or request_provenance.get("workflow_ref") != expected_workflow_ref
        or request_provenance.get("run_id") != expected_run_id
        or request_provenance.get("run_attempt") != expected_run_attempt
        or request_provenance.get("job") != "prepare-unsigned-application"
    ):
        raise ValueError("Application signing request differs from the dispatch contract")
    request_materials = {
        str(item["name"]): str(item["sha256"])
        for item in request["materials"]
        if isinstance(item, dict)
    }
    required_request_materials = {
        "runtime-lock": runtime_lock_sha256,
        "build-lock": build_lock_sha256,
        "installed-packages": sha256_file(packages_file),
        "component-inventory": sha256_file(component_inventory_file),
    }
    if any(
        request_materials.get(name) != digest
        for name, digest in required_request_materials.items()
    ):
        raise ValueError("Application signing request materials differ from reviewed inputs")

    if (
        evidence.get("schema") != 2
        or evidence.get("release_commit") != commit
        or evidence.get("source_tree") != source_tree
        or evidence.get("publisher") != publisher
        or evidence.get("license_review") != "approved"
        or evidence.get("sbom_scope") != "final-shipped-bytes"
        or evidence.get("stable_release_eligible") is not True
        or evidence.get("runtime_lock_sha256") != runtime_lock_sha256
        or evidence.get("build_lock_sha256") != build_lock_sha256
        or evidence.get("packages_inventory_sha256") != sha256_file(packages_file)
        or evidence.get("third_party_notices_sha256") != sha256_file(notices)
        or evidence.get("component_inventory_sha256")
        != sha256_file(component_inventory_file)
    ):
        raise ValueError("Compliance evidence does not bind the exact release inputs")
    reviewed = parse_utc(str(evidence.get("reviewed_at_utc", "")), field="reviewed_at_utc")
    verified = parse_utc(verified_at_utc, field="verified_at_utc")
    requested = parse_utc(
        str(request.get("created_at_utc", "")),
        field="application_signing_request.created_at_utc",
    )
    if not requested <= reviewed <= verified:
        raise ValueError("Build request, compliance review and verification timestamps are not ordered")
    review_reference = str(evidence.get("review_reference", ""))
    if REVIEW_REFERENCE_RE.fullmatch(review_reference) is None:
        raise ValueError("Compliance review reference is invalid")

    package_rows = evidence.get("packages")
    if not isinstance(package_rows, list):
        raise ValueError("Compliance package review must be a list")
    expected_packages = dict(parse_packages(packages_file))
    reviewed_packages: dict[str, dict[str, str]] = {}
    required_package_keys = {
        "name",
        "version",
        "license_declared",
        "license_concluded",
        "download_location",
        "copyright_text",
    }
    for row in package_rows:
        if not isinstance(row, dict) or set(row) != required_package_keys:
            raise ValueError("Compliance package entry differs from the schema")
        name = str(row["name"]).lower()
        values = {key: str(row[key]) for key in required_package_keys if key != "name"}
        if name in reviewed_packages or expected_packages.get(name) != values["version"]:
            raise ValueError("Compliance package inventory differs from the installed set")
        for field in ("license_declared", "license_concluded"):
            try:
                canonical = canonicalize_license_expression(values[field])
            except InvalidLicenseExpression as exc:
                raise ValueError("Compliance package license is invalid") from exc
            if canonical in {"NOASSERTION", "NONE"}:
                raise ValueError("Compliance package license is unresolved")
            values[field] = canonical
        if values["download_location"] != "NONE":
            download = urlsplit(values["download_location"])
            if (
                download.scheme != "https"
                or not download.hostname
                or download.username is not None
                or download.password is not None
                or download.query
                or download.fragment
                or len(values["download_location"]) > 500
            ):
                raise ValueError("Compliance package download location is invalid")
        if (
            not values["copyright_text"].strip()
            or values["copyright_text"] == "NOASSERTION"
            or len(values["copyright_text"]) > 500
            or any(ord(character) < 32 for character in values["copyright_text"])
        ):
            raise ValueError("Compliance package copyright text is unresolved or invalid")
        reviewed_packages[name] = values
    if set(reviewed_packages) != set(expected_packages):
        raise ValueError("Compliance package review is incomplete")

    inventory = json.loads(component_inventory_file.read_text(encoding="utf-8-sig"))
    if (
        not isinstance(inventory, dict)
        or set(inventory) != {"schema", "files"}
        or inventory.get("schema") != 2
        or not isinstance(inventory.get("files"), list)
    ):
        raise ValueError("Unsigned component inventory is malformed")
    inventory_by_path: dict[str, dict[str, object]] = {}
    inventory_casefold_paths: set[str] = set()
    for item in inventory["files"]:
        relative = item.get("path") if isinstance(item, dict) else None
        expected_keys = {"path", "bytes", "sha256"}
        if relative == "DefenseTracker.exe":
            expected_keys.add("authenticode_neutral_sha256")
        if (
            not isinstance(item, dict)
            or set(item) != expected_keys
            or not isinstance(relative, str)
            or not isinstance(item.get("bytes"), int)
            or item["bytes"] < 0
            or SHA256_RE.fullmatch(str(item.get("sha256", ""))) is None
            or (
                relative == "DefenseTracker.exe"
                and SHA256_RE.fullmatch(
                    str(item.get("authenticode_neutral_sha256", ""))
                )
                is None
            )
            or relative in inventory_by_path
        ):
            raise ValueError("Unsigned component inventory entry is malformed")
        relative = safe_relative_path(relative, label="component inventory path")
        folded_relative = relative.casefold()
        if folded_relative in inventory_casefold_paths:
            raise ValueError("Unsigned component inventory contains case-insensitive duplicates")
        inventory_casefold_paths.add(folded_relative)
        inventory_by_path[relative] = item
    component_rows = evidence.get("components")
    if not isinstance(component_rows, list):
        raise ValueError("Compliance component review must be a list")
    component_review_keys = {
        "license_declared",
        "license_concluded",
        "copyright_text",
    }
    reviewed_components: dict[str, dict[str, object]] = {}
    reviewed_casefold_paths: set[str] = set()
    for row in component_rows:
        if not isinstance(row, dict):
            raise ValueError("Compliance component entry differs from the schema")
        relative_value = row.get("path")
        if not isinstance(relative_value, str):
            raise ValueError("Compliance component entry differs from the schema")
        relative = safe_relative_path(relative_value, label="compliance component path")
        folded_relative = relative.casefold()
        if relative in reviewed_components or folded_relative in reviewed_casefold_paths:
            raise ValueError("Compliance component path is invalid")
        reviewed_casefold_paths.add(folded_relative)
        expected_item = inventory_by_path.get(relative)
        if (
            expected_item is None
            or set(row) != set(expected_item).union(component_review_keys)
            or any(row.get(key) != value for key, value in expected_item.items())
        ):
            raise ValueError("Compliance component review differs from unsigned bytes")
        normalized = dict(row)
        for field in ("license_declared", "license_concluded"):
            try:
                canonical = canonicalize_license_expression(str(row[field]))
            except InvalidLicenseExpression as exc:
                raise ValueError("Compliance component license is invalid") from exc
            if canonical in {"NOASSERTION", "NONE"}:
                raise ValueError("Compliance component license is unresolved")
            normalized[field] = canonical
        copyright_text = str(row["copyright_text"])
        if (
            not copyright_text.strip()
            or copyright_text == "NOASSERTION"
            or len(copyright_text) > 500
            or any(ord(character) < 32 for character in copyright_text)
        ):
            raise ValueError("Compliance component copyright is unresolved or invalid")
        normalized["copyright_text"] = copyright_text
        reviewed_components[relative] = normalized
    if set(reviewed_components) != set(inventory_by_path):
        raise ValueError("Compliance component review is incomplete")

    current_files = {
        item["path"]: item
        for item in list_files(application_root, exclude={"release-manifest.json"})
    }
    if set(current_files) != set(inventory_by_path):
        raise ValueError("Signed application component set differs from legal review")
    for relative, unsigned_item in inventory_by_path.items():
        if relative == "DefenseTracker.exe":
            current = current_files[relative]
            executable = application_root / "DefenseTracker.exe"
            try:
                if (
                    current["bytes"] == unsigned_item["bytes"]
                    and current["sha256"] == unsigned_item["sha256"]
                ):
                    inspect_authenticode_image(
                        executable,
                        require_state="unsigned",
                        expected_unsigned_size=int(unsigned_item["bytes"]),
                        expected_normalized_sha256=str(
                            unsigned_item["authenticode_neutral_sha256"]
                        ),
                    )
                else:
                    inspect_authenticode_image(
                        executable,
                        require_state="signed",
                        expected_unsigned_size=int(unsigned_item["bytes"]),
                        expected_normalized_sha256=str(
                            unsigned_item["authenticode_neutral_sha256"]
                        ),
                    )
            except ValueError as exc:
                raise ValueError(
                    "DefenseTracker.exe changed outside Authenticode fields"
                ) from exc
            continue
        current = current_files[relative]
        if (
            current["bytes"] != unsigned_item["bytes"]
            or current["sha256"] != unsigned_item["sha256"]
        ):
            raise ValueError("A non-signature component changed after legal review")
    compliance = {
        "sbom_scope": "final-shipped-bytes",
        "license_review": "approved",
        "stable_release_eligible": True,
        "evidence_schema": 2,
        "evidence_sha256": actual_sha256,
        "reviewed_at_utc": evidence["reviewed_at_utc"],
        "review_reference": review_reference,
        "component_inventory_sha256": evidence["component_inventory_sha256"],
        "evidence_base64": base64.b64encode(evidence_bytes).decode("ascii"),
        "application_signing_request_schema": 2,
        "application_signing_request_sha256": request_sha256,
        "application_signing_request_base64": base64.b64encode(request_bytes).decode(
            "ascii"
        ),
        "application_signing_request_repository": request_provenance["repository"],
        "application_signing_request_workflow_ref": request_provenance["workflow_ref"],
        "application_signing_request_run_id": request_provenance["run_id"],
        "application_signing_request_run_attempt": request_provenance["run_attempt"],
        "application_signing_request_job": request_provenance["job"],
    }
    return reviewed_packages, reviewed_components, compliance


def load_installer_compliance(
    *,
    request_path: Path,
    signed_installer: Path,
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
    commit: str,
    source_tree: str,
    publisher: str,
) -> dict[str, object]:
    """Verify the immutable installer review request without an approval loop."""

    request, request_bytes = read_installer_review_json(
        request_path, "installer review request", canonical=True
    )
    request = validate_installer_review_request(request)
    request_sha256 = hashlib.sha256(request_bytes).hexdigest()
    if (
        request["release_commit"] != commit
        or request["source_tree"] != source_tree
        or request["version"] != PRODUCT_VERSION.semantic_version
        or request["publisher"] != publisher
    ):
        raise ValueError("Installer review request does not bind the exact release")
    recipe = request["recipe"]
    unsigned = request["unsigned_installer"]
    payload = request["payload_inventory"]
    bootstrap = request["bootstrap_license"]
    assert isinstance(recipe, dict)
    assert isinstance(unsigned, dict)
    assert isinstance(payload, dict)
    assert isinstance(bootstrap, dict)
    expected_recipe = {
        "iss_sha256": sha256_file(iss_path),
        "iscc_sha256": sha256_file(iscc_path),
        "iscc_version": iscc_version,
        "seven_zip_sha256": sha256_file(seven_zip_path),
        "seven_zip_version": seven_zip_version,
        "signed_application_inventory_sha256": sha256_file(
            signed_application_inventory
        ),
    }
    if recipe != expected_recipe:
        raise ValueError("Installer build recipe differs from its immutable review request")
    license_text = bootstrap_license_text_path.read_text(encoding="utf-8")
    if (
        bootstrap["license_declared"] != bootstrap_license_declared
        or bootstrap["license_concluded"] != bootstrap_license_concluded
        or bootstrap["copyright_text"] != bootstrap_copyright_text
        or bootstrap["license_text"] != license_text
        or bootstrap["license_text_sha256"]
        != hashlib.sha256(license_text.encode("utf-8")).hexdigest()
    ):
        raise ValueError("Installer bootstrap license differs from reviewed bytes")
    actual_payload = build_payload_inventory(extracted_payload_root)
    if (
        actual_payload != payload
        or hashlib.sha256(installer_review_canonical_bytes(actual_payload)).hexdigest()
        != request["payload_inventory_sha256"]
    ):
        raise ValueError("Signed installer payload differs from reviewed inventory")
    signed_identity = inspect_authenticode_image(
        signed_installer,
        require_state="signed",
        expected_unsigned_size=int(unsigned["bytes"]),
        expected_normalized_sha256=str(unsigned["normalized_sha256"]),
    )
    payload_files = payload.get("files")
    if not isinstance(payload_files, list):  # pragma: no cover - validated upstream
        raise ValueError("Installer payload inventory is malformed")
    if request_path.read_bytes() != request_bytes:
        raise ValueError("Installer review request changed during verification")
    return {
        "schema": 2,
        "scope": "installer-release-review",
        "stable_release_eligible": True,
        "request_sha256": request_sha256,
        "payload_inventory_sha256": request["payload_inventory_sha256"],
        "payload_file_count": len(payload_files),
        "unsigned_installer_sha256": unsigned["sha256"],
        "unsigned_installer_bytes": unsigned["bytes"],
        "authenticode_normalized_sha256": unsigned["normalized_sha256"],
        "signed_installer_sha256": signed_identity.file_sha256,
        "signed_installer_bytes": signed_identity.bytes,
        "bootstrap_license": bootstrap,
        "request_base64": base64.b64encode(request_bytes).decode("ascii"),
    }


def write_spdx(
    destination: Path,
    *,
    commit: str,
    epoch: int,
    publisher: str,
    packages_file: Path,
    application_root: Path,
    installer_asset: Path,
    portable_asset: Path,
    package_licenses: dict[str, dict[str, str]] | None = None,
    component_licenses: dict[str, dict[str, object]] | None = None,
    installer_review: dict[str, object] | None = None,
) -> None:
    created = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    root_id = "SPDXRef-Package-DefenseTracker"
    packages: list[dict[str, object]] = [
        {
            "SPDXID": root_id,
            "name": PRODUCT_VERSION.product_name,
            "versionInfo": PRODUCT_VERSION.semantic_version,
            "downloadLocation": "https://github.com/player1314520/defense-tracker-mvp",
            "filesAnalyzed": False,
            "licenseConcluded": "AGPL-3.0-only",
            "licenseDeclared": "AGPL-3.0-only",
            "copyrightText": f"Copyright (c) 2026 {publisher}",
            "supplier": f"Organization: {publisher}",
        }
    ]
    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_id,
        }
    ]
    files: list[dict[str, object]] = []
    for name, version in parse_packages(packages_file):
        package_id = _spdx_id(name)
        license_evidence = (package_licenses or {}).get(name)
        packages.append(
            {
                "SPDXID": package_id,
                "name": name,
                "versionInfo": version,
                "downloadLocation": (
                    license_evidence["download_location"]
                    if license_evidence is not None
                    else "NOASSERTION"
                ),
                "filesAnalyzed": False,
                "licenseConcluded": (
                    license_evidence["license_concluded"]
                    if license_evidence is not None
                    else "NOASSERTION"
                ),
                "licenseDeclared": (
                    license_evidence["license_declared"]
                    if license_evidence is not None
                    else "NOASSERTION"
                ),
                "copyrightText": (
                    license_evidence["copyright_text"]
                    if license_evidence is not None
                    else "NOASSERTION"
                ),
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:pypi/{name}@{version}",
                    }
                ],
            }
        )
        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package_id,
            }
        )
    concluded_licenses = {"AGPL-3.0-only"}
    if package_licenses:
        concluded_licenses.update(
            item["license_concluded"] for item in package_licenses.values()
        )
    if component_licenses:
        concluded_licenses.update(
            str(item["license_concluded"]) for item in component_licenses.values()
        )
    portable_license = " AND ".join(
        f"({license_expression})" for license_expression in sorted(concluded_licenses)
    )
    extracted_licenses: list[dict[str, str]] = []
    installer_declared_license = portable_license
    installer_concluded_license = portable_license
    if installer_review is not None:
        bootstrap = installer_review.get("bootstrap_license")
        if not isinstance(bootstrap, dict):
            raise ValueError("Installer review lacks bootstrap license evidence")
        declared = str(bootstrap.get("license_declared", ""))
        concluded = str(bootstrap.get("license_concluded", ""))
        text = str(bootstrap.get("license_text", ""))
        if (
            not declared.startswith("LicenseRef-")
            or concluded != declared
            or not text.strip()
        ):
            raise ValueError("Installer bootstrap license must use one resolved LicenseRef")
        installer_declared_license = f"({portable_license}) AND ({declared})"
        installer_concluded_license = f"({portable_license}) AND ({concluded})"
        extracted_licenses.append(
            {
                "licenseId": declared,
                "extractedText": text,
                "name": "Inno Setup bootstrap/runtime license",
            }
        )
    for artifact_name, artifact_path, artifact_id, declared_license, concluded_license in (
        (
            "DefenseTracker Windows Installer",
            installer_asset,
            "SPDXRef-Package-DefenseTracker-Windows-Installer",
            installer_declared_license,
            installer_concluded_license,
        ),
        (
            "DefenseTracker Windows Portable",
            portable_asset,
            "SPDXRef-Package-DefenseTracker-Windows-Portable",
            portable_license,
            portable_license,
        ),
    ):
        packages.append(
            {
                "SPDXID": artifact_id,
                "name": artifact_name,
                "versionInfo": PRODUCT_VERSION.semantic_version,
                "downloadLocation": (
                    "https://github.com/player1314520/defense-tracker-mvp/"
                    f"releases/download/{PRODUCT_VERSION.release_tag}/{artifact_path.name}"
                ),
                "filesAnalyzed": False,
                "licenseConcluded": concluded_license,
                "licenseDeclared": declared_license,
                "copyrightText": (
                    f"Copyright (c) 2026 {publisher}; third-party notices apply"
                ),
                "supplier": f"Organization: {publisher}",
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": sha256_file(artifact_path)}
                ],
            }
        )
        relationships.extend(
            [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": artifact_id,
                },
                {
                    "spdxElementId": artifact_id,
                    "relationshipType": "GENERATED_FROM",
                    "relatedSpdxElement": root_id,
                },
            ]
        )
    effective_component_licenses = dict(component_licenses or {})
    generated_manifest = application_root / "release-manifest.json"
    if component_licenses and generated_manifest.is_file():
        effective_component_licenses["release-manifest.json"] = {
            "license_declared": "AGPL-3.0-only",
            "license_concluded": "AGPL-3.0-only",
            "copyright_text": f"Copyright (c) 2026 {publisher}",
        }
    for relative, evidence in sorted(effective_component_licenses.items()):
        source = resolve_path_within(
            application_root,
            relative,
            label="SBOM component path",
            kind="file",
        )
        file_id = "SPDXRef-File-" + hashlib.sha256(relative.encode()).hexdigest()[:24]
        files.append(
            {
                "SPDXID": file_id,
                "fileName": f"./DefenseTracker/{relative}",
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": sha256_file(source)}
                ],
                "licenseConcluded": evidence["license_concluded"],
                "licenseInfoInFiles": [evidence["license_declared"]],
                "copyrightText": evidence["copyright_text"],
            }
        )
        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": file_id,
            }
        )
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{PRODUCT_VERSION.product_name}-{PRODUCT_VERSION.release_tag}",
        "documentNamespace": (
            "https://github.com/player1314520/defense-tracker-mvp/"
            f"releases/tag/{PRODUCT_VERSION.release_tag}/spdx/{commit}"
        ),
        "creationInfo": {
            "created": created,
            "creators": ["Tool: DefenseTracker scripts/package_release_assets.py"],
        },
        "packages": packages,
        "files": files,
        "relationships": relationships,
    }
    if extracted_licenses:
        document["hasExtractedLicensingInfos"] = extracted_licenses
    destination.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def package_assets(args: argparse.Namespace) -> dict[str, object]:
    application_root = args.application_root.resolve()
    installer = args.installer.resolve()
    output_dir = args.output_dir.resolve()
    notices = args.third_party_notices.resolve()
    packages_file = args.packages_file.resolve()
    toolchain_evidence_file = args.toolchain_evidence.resolve()
    if SHA_RE.fullmatch(args.commit) is None or SHA_RE.fullmatch(args.source_tree) is None:
        raise ValueError("Commit and source tree must be full lowercase Git object IDs")
    if not args.publisher.strip():
        raise ValueError("Publisher is required")
    for required in (
        application_root,
        installer,
        notices,
        packages_file,
        toolchain_evidence_file,
    ):
        if not required.exists():
            raise FileNotFoundError(required)
    toolchain_evidence = load_toolchain_evidence(
        toolchain_evidence_file, signing_provider=args.signing_provider
    )
    raw_exchange_paths = {
        "application_request": getattr(args, "application_signing_request", None),
        "application_receipt": getattr(args, "application_signing_receipt", None),
        "installer_request": getattr(args, "installer_signing_request", None),
        "installer_receipt": getattr(args, "installer_signing_receipt", None),
        "publisher_policy": getattr(args, "publisher_policy", None),
    }
    supplied_exchange_count = sum(value is not None for value in raw_exchange_paths.values())
    if supplied_exchange_count not in {0, len(raw_exchange_paths)}:
        raise ValueError("Signing exchange inputs must be supplied as one complete set")
    exchange_paths: dict[str, Path] = {}
    application_exchange: dict[str, object] | None = None
    installer_exchange: dict[str, object] | None = None
    application_signature: dict[str, object] | None = None
    installer_signature: dict[str, object] | None = None
    publisher_policy_sha256: str | None = None
    if supplied_exchange_count:
        exchange_paths = resolve_signing_exchange_paths(
            raw_exchange_paths,
            cli_root=Path.cwd(),
        )
        for exchange_path in exchange_paths.values():
            if not exchange_path.is_file():
                raise FileNotFoundError(exchange_path)
        application_exchange = load_signing_exchange_evidence(
            exchange_paths["application_request"],
            exchange_paths["application_receipt"],
            subject_kind="application",
            commit=args.commit,
            publisher=args.publisher,
            provider=args.signing_provider,
        )
        installer_exchange = load_signing_exchange_evidence(
            exchange_paths["installer_request"],
            exchange_paths["installer_receipt"],
            subject_kind="installer",
            commit=args.commit,
            publisher=args.publisher,
            provider=args.signing_provider,
        )
        publisher_policy_sha256 = sha256_file(exchange_paths["publisher_policy"])
        publisher_policy = json.loads(
            exchange_paths["publisher_policy"].read_text(encoding="utf-8-sig")
        )
        if (
            not isinstance(publisher_policy, dict)
            or publisher_policy.get("status") != "approved"
            or publisher_policy.get("publisher") != args.publisher
            or publisher_policy.get("active_provider") != args.signing_provider
        ):
            raise ValueError("Committed Publisher policy is not approved for this release")
        application_signature = application_exchange["signature"]
        installer_signature = installer_exchange["signature"]
        assert isinstance(application_signature, dict)
        assert isinstance(installer_signature, dict)
        for signature in (application_signature, installer_signature):
            policy_evidence = signature["publisher_policy"]
            assert isinstance(policy_evidence, dict)
            if policy_evidence["sha256"] != publisher_policy_sha256:
                raise ValueError("Signing receipt Publisher policy digest differs")
        if args.signing_provider == "DigiCertKeyLocker":
            for field in (
                "signer_subject",
                "signer_spki_sha256",
                "signer_issuer_subject",
                "signer_root_sha256",
            ):
                if application_signature[field] != installer_signature[field]:
                    raise ValueError("DigiCert signer identity differs across stages")
    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise ValueError("Release asset output directory must be empty")

    epoch = int(args.source_date_epoch)
    source_date_epoch_utc = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    build_started_raw = getattr(args, "build_started_utc", source_date_epoch_utc)
    build_finished_raw = getattr(args, "build_finished_utc", build_started_raw)
    verified_raw = getattr(args, "verified_at_utc", build_finished_raw)
    build_started = parse_utc(build_started_raw, field="build_started_utc")
    build_finished = parse_utc(build_finished_raw, field="build_finished_utc")
    verified_at = parse_utc(verified_raw, field="verified_at_utc")
    if build_finished < build_started:
        raise ValueError("build_finished_utc predates build_started_utc")
    if verified_at < build_finished:
        raise ValueError("verified_at_utc predates build_finished_utc")
    compliance_evidence_arg = getattr(args, "compliance_evidence", None)
    compliance_evidence_sha256 = str(
        getattr(args, "compliance_evidence_sha256", "") or ""
    )
    package_licenses: dict[str, dict[str, str]] = {}
    component_licenses: dict[str, dict[str, object]] = {}
    compliance: dict[str, object] = {
        "sbom_scope": "build-environment-package-inventory-only",
        "license_review": "incomplete",
        "stable_release_eligible": False,
    }
    if compliance_evidence_arg is not None:
        if application_exchange is None or installer_exchange is None:
            raise ValueError("Stable compliance packaging requires both signing exchanges")
        compliance_evidence_path = Path(compliance_evidence_arg).resolve()
        inventory_arg = getattr(args, "component_inventory", None)
        if inventory_arg is None:
            raise ValueError("Compliance component inventory is incomplete")
        component_inventory_path = Path(inventory_arg).resolve()
        for required_compliance_file in (
            compliance_evidence_path,
            component_inventory_path,
        ):
            if not required_compliance_file.is_file():
                raise FileNotFoundError(required_compliance_file)
        request_provenance = application_exchange["request_provenance"]
        assert isinstance(request_provenance, dict)
        package_licenses, component_licenses, compliance = load_compliance_evidence(
            compliance_evidence_path,
            application_signing_request_path=exchange_paths["application_request"],
            expected_application_signing_request_sha256=str(
                application_exchange["request_sha256"]
            ),
            component_inventory_file=component_inventory_path,
            application_root=application_root,
            expected_sha256=compliance_evidence_sha256,
            commit=args.commit,
            source_tree=args.source_tree,
            publisher=args.publisher,
            packages_file=packages_file,
            notices=notices,
            runtime_lock_sha256=args.runtime_lock_sha256,
            build_lock_sha256=args.build_lock_sha256,
            verified_at_utc=verified_raw,
            expected_repository=str(request_provenance["repository"]),
            expected_workflow_ref=str(request_provenance["workflow_ref"]),
            expected_run_id=int(request_provenance["run_id"]),
            expected_run_attempt=int(request_provenance["run_attempt"]),
        )
    elif compliance_evidence_sha256:
        raise ValueError("Compliance evidence path is missing")
    installer_review_request_arg = getattr(args, "installer_review_request", None)
    installer_review: dict[str, object] = {
        "scope": "installer-release-review",
        "stable_release_eligible": False,
    }
    if compliance.get("stable_release_eligible") is True:
        installer_inputs = {
            "request_path": installer_review_request_arg,
            "extracted_payload_root": getattr(args, "installer_payload_root", None),
            "signed_application_inventory": getattr(
                args, "signed_application_inventory", None
            ),
            "iss_path": getattr(args, "iss", None),
            "iscc_path": getattr(args, "iscc", None),
            "iscc_version": getattr(args, "iscc_version", None),
            "seven_zip_path": getattr(args, "seven_zip", None),
            "seven_zip_version": getattr(args, "seven_zip_version", None),
            "bootstrap_license_declared": getattr(
                args, "bootstrap_license_declared", None
            ),
            "bootstrap_license_concluded": getattr(
                args, "bootstrap_license_concluded", None
            ),
            "bootstrap_copyright_text": getattr(
                args, "bootstrap_copyright_text", None
            ),
            "bootstrap_license_text_path": getattr(
                args, "bootstrap_license_text", None
            ),
        }
        if any(value is None or value == "" for value in installer_inputs.values()):
            raise ValueError("Independent installer review inputs are incomplete")
        path_fields = {
            "request_path",
            "extracted_payload_root",
            "signed_application_inventory",
            "iss_path",
            "iscc_path",
            "seven_zip_path",
            "bootstrap_license_text_path",
        }
        for field in path_fields:
            installer_inputs[field] = Path(installer_inputs[field]).resolve()
        installer_review = load_installer_compliance(
            **installer_inputs,
            signed_installer=installer,
            commit=args.commit,
            source_tree=args.source_tree,
            publisher=args.publisher,
        )
    elif installer_review_request_arg is not None:
        raise ValueError("Installer review cannot replace application compliance review")

    signatures: dict[str, object] = {}
    if compliance.get("stable_release_eligible") is True:
        if (
            application_exchange is None
            or installer_exchange is None
            or application_signature is None
            or installer_signature is None
            or publisher_policy_sha256 is None
        ):
            raise ValueError("Stable signatures require canonical exchange evidence")
        reviewed_executable = component_licenses.get("DefenseTracker.exe")
        if not isinstance(reviewed_executable, dict):
            raise ValueError("Application review does not bind DefenseTracker.exe")
        application_identity = inspect_authenticode_image(
            application_root / "DefenseTracker.exe",
            require_state="signed",
            expected_unsigned_size=int(reviewed_executable["bytes"]),
            expected_normalized_sha256=str(
                reviewed_executable["authenticode_neutral_sha256"]
            ),
        )
        if (
            application_exchange.get("signed_sha256")
            != application_identity.file_sha256
            or application_exchange.get("signed_bytes") != application_identity.bytes
        ):
            raise ValueError("Application receipt differs from packaged signed bytes")
        if (
            installer_exchange.get("signed_sha256")
            != installer_review["signed_installer_sha256"]
            or installer_exchange.get("signed_bytes")
            != installer_review["signed_installer_bytes"]
        ):
            raise ValueError("Installer receipt differs from packaged signed bytes")
        signatures["application"] = {
            **application_signature,
            "authenticode": "Valid",
            "trusted_timestamp": True,
            "unsigned_sha256": reviewed_executable["sha256"],
            "unsigned_bytes": reviewed_executable["bytes"],
            "signed_sha256": application_identity.file_sha256,
            "signed_bytes": application_identity.bytes,
            "authenticode_normalized_sha256": application_identity.normalized_sha256,
            "verified_at_utc": verified_raw,
            "exchange": application_exchange,
        }
        signatures["installer"] = {
            **installer_signature,
            "authenticode": "Valid",
            "trusted_timestamp": True,
            "unsigned_sha256": installer_review["unsigned_installer_sha256"],
            "unsigned_bytes": installer_review["unsigned_installer_bytes"],
            "signed_sha256": installer_review["signed_installer_sha256"],
            "signed_bytes": installer_review["signed_installer_bytes"],
            "authenticode_normalized_sha256": installer_review[
                "authenticode_normalized_sha256"
            ],
            "verified_at_utc": verified_raw,
            "exchange": installer_exchange,
        }
    legacy_signer_subject = str(getattr(args, "signer_subject", "") or "")
    legacy_timestamp_url = str(getattr(args, "timestamp_url", "") or "")
    legacy_timestamp_subject = str(getattr(args, "timestamp_subject", "") or "")
    top_signature = (
        {
            "provider": installer_signature["provider"],
            "publisher": installer_signature["publisher"],
            "signer_subject": installer_signature["signer_subject"],
            "timestamp_url": installer_signature["timestamp_url"],
            "timestamp_certificate_subject": installer_signature[
                "timestamp_certificate_subject"
            ],
            "timestamp_verified_at_utc": installer_signature[
                "timestamp_verified_at_utc"
            ],
            "publisher_policy_sha256": publisher_policy_sha256,
            "authenticode": "Valid",
            "trusted_timestamp": True,
            "verified_at_utc": verified_raw,
        }
        if installer_signature is not None
        else {
            "provider": args.signing_provider,
            "publisher": args.publisher,
            "signer_subject": legacy_signer_subject,
            "timestamp_url": legacy_timestamp_url,
            "timestamp_certificate_subject": legacy_timestamp_subject,
            "publisher_policy_sha256": None,
            "authenticode": "unverified",
            "trusted_timestamp": False,
            "verified_at_utc": verified_raw,
        }
    )
    build_manifest = {
        "schema": 2,
        "kind": "desktop-build",
        "product": PRODUCT_VERSION.product_name,
        "version": PRODUCT_VERSION.as_dict(),
        "release": {
            "tag": PRODUCT_VERSION.release_tag,
            "commit": args.commit,
            "baseline_commit": PRODUCT_VERSION.release_baseline,
            "source_tree": args.source_tree,
        },
        "build": {
            "source_date_epoch_utc": source_date_epoch_utc,
            "started_at_utc": build_started_raw,
            "finished_at_utc": build_finished_raw,
            "verified_at_utc": verified_raw,
            "target": "windows-x64",
            "python": args.python_version,
            "runtime_lock_sha256": args.runtime_lock_sha256,
            "build_lock_sha256": args.build_lock_sha256,
            "toolchain": toolchain_evidence,
        },
        "signature": top_signature,
        "signatures": signatures,
        "compliance": compliance,
        "installer_review": installer_review,
        "files": list_files(application_root, exclude={"release-manifest.json"}),
    }
    internal_manifest = application_root / "release-manifest.json"
    internal_manifest.write_text(
        json.dumps(build_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    version = PRODUCT_VERSION.semantic_version
    installer_name = f"DefenseTracker-Setup-v{version}-windows-x64.exe"
    portable_name = f"DefenseTracker-v{version}-windows-x64-portable.zip"
    sbom_name = f"DefenseTracker-v{version}.spdx.json"
    installer_asset = output_dir / installer_name
    portable_asset = output_dir / portable_name
    sbom_asset = output_dir / sbom_name
    notices_asset = output_dir / "THIRD_PARTY_NOTICES.md"
    shutil.copyfile(installer, installer_asset)
    shutil.copyfile(notices, notices_asset)
    write_portable_zip(application_root, portable_asset, epoch=epoch)
    write_spdx(
        sbom_asset,
        commit=args.commit,
        epoch=epoch,
        publisher=args.publisher,
        packages_file=packages_file,
        application_root=application_root,
        installer_asset=installer_asset,
        portable_asset=portable_asset,
        package_licenses=package_licenses,
        component_licenses=component_licenses,
        installer_review=(
            installer_review
            if installer_review.get("stable_release_eligible") is True
            else None
        ),
    )

    signed_assets = [installer_asset, portable_asset, sbom_asset, notices_asset]
    release_manifest = {
        "schema": 2,
        "kind": "stable-release",
        "product": PRODUCT_VERSION.product_name,
        "version": PRODUCT_VERSION.as_dict(),
        "release": build_manifest["release"],
        "build": build_manifest["build"],
        "signature": build_manifest["signature"],
        "signatures": build_manifest["signatures"],
        "compliance": build_manifest["compliance"],
        "installer_review": build_manifest["installer_review"],
        "assets": [file_entry(path) for path in signed_assets],
        "portable_contents": list_files(application_root),
    }
    manifest_asset = output_dir / "release-manifest.json"
    manifest_asset.write_text(
        json.dumps(release_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    checksum_assets = [*signed_assets, manifest_asset]
    sums_asset = output_dir / "SHA256SUMS.txt"
    sums_asset.write_text(
        "".join(f"{sha256_file(path)}  {path.name}\n" for path in checksum_assets),
        encoding="utf-8",
        newline="\n",
    )
    return release_manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--application-root", type=Path, required=True)
    parser.add_argument("--installer", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--third-party-notices", type=Path, required=True)
    parser.add_argument("--packages-file", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--source-date-epoch", required=True)
    parser.add_argument("--build-started-utc", required=True)
    parser.add_argument("--build-finished-utc", required=True)
    parser.add_argument("--verified-at-utc", required=True)
    parser.add_argument("--publisher", required=True)
    parser.add_argument("--signing-provider", required=True)
    parser.add_argument("--python-version", required=True)
    parser.add_argument("--runtime-lock-sha256", required=True)
    parser.add_argument("--build-lock-sha256", required=True)
    parser.add_argument("--toolchain-evidence", type=Path, required=True)
    # Signing-exchange paths are portable paths relative to the invocation CWD.
    # argparse must not turn untrusted text into a host path before validation.
    parser.add_argument("--publisher-policy")
    parser.add_argument("--application-signing-request")
    parser.add_argument("--application-signing-receipt")
    parser.add_argument("--installer-signing-request")
    parser.add_argument("--installer-signing-receipt")
    parser.add_argument("--signer-subject")
    parser.add_argument("--timestamp-url")
    parser.add_argument("--timestamp-subject")
    parser.add_argument("--compliance-evidence", type=Path)
    parser.add_argument("--compliance-evidence-sha256")
    parser.add_argument("--component-inventory", type=Path)
    parser.add_argument("--installer-review-request", type=Path)
    parser.add_argument("--installer-payload-root", type=Path)
    parser.add_argument("--signed-application-inventory", type=Path)
    parser.add_argument("--iss", type=Path)
    parser.add_argument("--iscc", type=Path)
    parser.add_argument("--iscc-version")
    parser.add_argument("--seven-zip", type=Path)
    parser.add_argument("--seven-zip-version")
    parser.add_argument("--bootstrap-license-declared")
    parser.add_argument("--bootstrap-license-concluded")
    parser.add_argument("--bootstrap-copyright-text")
    parser.add_argument("--bootstrap-license-text", type=Path)
    package_assets(parser.parse_args())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
