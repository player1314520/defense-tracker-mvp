# -*- coding: utf-8 -*-
"""Fail-closed offline verification for the fixed v9 stable asset set."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.authenticode_digest import inspect_authenticode_image  # noqa: E402
from scripts.installer_review import (  # noqa: E402
    _validate_request as validate_installer_review_request,
    canonical_json_bytes as installer_review_canonical_bytes,
)
from scripts.signing_exchange import (  # noqa: E402
    _validate_receipt as validate_signing_receipt,
    _validate_request as validate_signing_request,
    canonical_json_bytes as signing_exchange_canonical_bytes,
)


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_REPOSITORY = "player1314520/defense-tracker-mvp"
SIGNED_CANDIDATE_WORKFLOW_REF = (
    f"{EXPECTED_REPOSITORY}/.github/workflows/v9-signed-candidate.yml@refs/heads/main"
)
APPLICATION_SIGNING_WORKFLOW_REF = (
    f"{EXPECTED_REPOSITORY}/.github/workflows/v9-application-signing.yml@refs/heads/main"
)
PREPARATION_WORKFLOW_REF = (
    f"{EXPECTED_REPOSITORY}/.github/workflows/v9-release-preparation.yml@refs/heads/main"
)


def parse_utc(value: object, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{field} is not an ISO-8601 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{field} is not a valid ISO-8601 UTC timestamp") from exc
    return parsed.astimezone(timezone.utc)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_reparse(path: Path) -> bool:
    return bool(getattr(path.lstat(), "st_file_attributes", 0) & 0x400)


def _strict_json_object(payload: bytes, *, label: str) -> dict[str, object]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Embedded {label} is not UTF-8 JSON") from exc

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Embedded {label} contains duplicate keys")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ValueError(f"Embedded {label} contains {value}")

    try:
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise ValueError(f"Embedded {label} is malformed") from exc
    if not isinstance(value, dict):
        raise ValueError(f"Embedded {label} must be an object")
    return value


def _validate_embedded_exchange(
    record: dict[str, object],
    *,
    subject_kind: str,
    expected_commit: str,
    expected_publisher: str,
) -> tuple[dict[str, object], dict[str, object]]:
    exchange = record.get("exchange")
    if not isinstance(exchange, dict):
        raise ValueError(f"{subject_kind} signing exchange is absent")
    try:
        request_bytes = base64.b64decode(exchange["request_base64"], validate=True)
        receipt_bytes = base64.b64decode(exchange["receipt_base64"], validate=True)
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise ValueError(f"{subject_kind} signing exchange encoding is invalid") from exc
    request = validate_signing_request(
        _strict_json_object(request_bytes, label=f"{subject_kind} signing request")
    )
    receipt = validate_signing_receipt(
        _strict_json_object(receipt_bytes, label=f"{subject_kind} signing receipt")
    )
    if (
        signing_exchange_canonical_bytes(request) != request_bytes
        or signing_exchange_canonical_bytes(receipt) != receipt_bytes
        or hashlib.sha256(request_bytes).hexdigest() != exchange.get("request_sha256")
        or hashlib.sha256(receipt_bytes).hexdigest() != exchange.get("receipt_sha256")
    ):
        raise ValueError(f"{subject_kind} signing exchange is not canonical/hash-bound")
    release = request["release"]
    target = request["target"]
    request_provenance = request["provenance"]
    receipt_provenance = receipt["provenance"]
    signature = receipt["signature"]
    assert isinstance(release, dict)
    assert isinstance(target, dict)
    assert isinstance(request_provenance, dict)
    assert isinstance(receipt_provenance, dict)
    assert isinstance(signature, dict)
    expected_request_workflow = (
        PREPARATION_WORKFLOW_REF
        if subject_kind == "application"
        else APPLICATION_SIGNING_WORKFLOW_REF
    )
    expected_request_job = (
        "prepare-unsigned-application"
        if subject_kind == "application"
        else "prepare-unsigned-installer"
    )
    expected_receipt_workflow = (
        APPLICATION_SIGNING_WORKFLOW_REF
        if subject_kind == "application"
        else SIGNED_CANDIDATE_WORKFLOW_REF
    )
    expected_receipt_job = "sign-application" if subject_kind == "application" else "sign-installer"
    if (
        request["subject_kind"] != subject_kind
        or receipt["subject_kind"] != subject_kind
        or release["commit"] != expected_commit
        or release["publisher"] != expected_publisher
        or receipt["request_sha256"] != hashlib.sha256(request_bytes).hexdigest()
        or receipt["release_commit"] != expected_commit
        or receipt["target_path"] != target["path"]
        or receipt["unsigned_sha256"] != target["sha256"]
        or request_provenance["repository"] != EXPECTED_REPOSITORY
        or request_provenance["workflow_ref"] != expected_request_workflow
        or request_provenance["job"] != expected_request_job
        or receipt_provenance["repository"] != EXPECTED_REPOSITORY
        or receipt_provenance["workflow_ref"] != expected_receipt_workflow
        or receipt_provenance["job"] != expected_receipt_job
        or exchange.get("request_provenance") != request_provenance
        or exchange.get("receipt_provenance") != receipt_provenance
        or exchange.get("signature") != signature
    ):
        raise ValueError(f"{subject_kind} signing exchange provenance is inconsistent")
    for field, value in signature.items():
        if record.get(field) != value:
            raise ValueError(f"{subject_kind} manifest signature differs from receipt")
    if (
        record.get("signed_sha256") != receipt["signed_sha256"]
        or record.get("signed_bytes") != receipt["signed_bytes"]
    ):
        raise ValueError(f"{subject_kind} signed identity differs from receipt")
    return request, receipt


def _portable_relative_path(value: object) -> PurePosixPath:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or ":" in value
        or "\x00" in value
        or value.startswith("/")
    ):
        raise ValueError("Portable content inventory contains a Windows-unsafe path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != value
    ):
        raise ValueError("Portable content inventory contains an unsafe path")
    return path


def verify_portable_archive_inventory(root: Path, manifest: dict[str, object]) -> bytes:
    version_record = manifest.get("version")
    if not isinstance(version_record, dict):
        raise ValueError("Release version record is absent")
    version = version_record.get("semantic_version")
    if not isinstance(version, str):
        raise ValueError("Release semantic version is absent")
    portable_contents = manifest.get("portable_contents")
    if not isinstance(portable_contents, list) or not portable_contents:
        raise ValueError("Portable content inventory is absent")
    expected_portable_members: dict[str, dict[str, object]] = {}
    expected_casefold: set[str] = set()
    for entry in portable_contents:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "bytes", "sha256"}
            or not isinstance(entry.get("bytes"), int)
            or isinstance(entry.get("bytes"), bool)
            or int(entry["bytes"]) < 0
            or SHA256_RE.fullmatch(str(entry.get("sha256", ""))) is None
        ):
            raise ValueError("Portable content inventory is malformed")
        relative = _portable_relative_path(entry.get("path"))
        member_name = (PurePosixPath("DefenseTracker") / relative).as_posix()
        folded = member_name.casefold()
        if member_name in expected_portable_members or folded in expected_casefold:
            raise ValueError("Portable content inventory contains a duplicate path")
        expected_portable_members[member_name] = entry
        expected_casefold.add(folded)
    portable = root / f"DefenseTracker-v{version}-windows-x64-portable.zip"
    with zipfile.ZipFile(portable) as archive:
        members = archive.infolist()
        member_names = [member.filename for member in members]
        member_casefold = [name.casefold() for name in member_names]
        if (
            not members
            or len(set(member_names)) != len(member_names)
            or len(set(member_casefold)) != len(member_casefold)
            or set(member_names) != set(expected_portable_members)
        ):
            raise ValueError("Portable ZIP differs from its exact content inventory")
        for member in members:
            _portable_relative_path(member.filename)
            expected_entry = expected_portable_members[member.filename]
            if (
                member.is_dir()
                or member.flag_bits & 0x1
                or member.file_size != expected_entry["bytes"]
            ):
                raise ValueError("Portable ZIP contains an unsafe or mismatched member")
            digest = hashlib.sha256()
            with archive.open(member, "r") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            if digest.hexdigest() != expected_entry["sha256"]:
                raise ValueError("Portable ZIP member differs from its content inventory")
        required = {
            "DefenseTracker/DefenseTracker.exe",
            "DefenseTracker/release-manifest.json",
        }
        if not required.issubset(expected_portable_members):
            raise ValueError("Portable ZIP is missing the signed application or build manifest")
        return archive.read("DefenseTracker/DefenseTracker.exe")


def verify(
    root: Path,
    *,
    expected_commit: str,
) -> None:
    if root.is_symlink() or _is_reparse(root) or not root.is_dir():
        raise ValueError("Release asset root must be a regular directory")
    root = root.resolve()
    manifest_path = root / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    version = manifest["version"]["semantic_version"]
    expected_names = {
        f"DefenseTracker-Setup-v{version}-windows-x64.exe",
        f"DefenseTracker-v{version}-windows-x64-portable.zip",
        "SHA256SUMS.txt",
        "release-manifest.json",
        f"DefenseTracker-v{version}.spdx.json",
        "THIRD_PARTY_NOTICES.md",
    }
    root_entries = list(root.iterdir())
    if any(
        entry.is_symlink() or _is_reparse(entry) or not entry.is_file()
        for entry in root_entries
    ):
        raise ValueError("Release asset root contains a non-file or reparse entry")
    actual_names = {path.name for path in root_entries}
    if len(root_entries) != len(expected_names) or actual_names != expected_names:
        raise ValueError(
            f"Release asset set differs from the contract: {sorted(actual_names)}"
        )
    if manifest.get("schema") != 2 or manifest.get("kind") != "stable-release":
        raise ValueError("Release manifest is not schema 2 stable-release")
    if manifest["release"]["commit"] != expected_commit:
        raise ValueError("Release manifest commit differs from the requested release")
    if manifest["version"]["release_tag"] != f"v{version}":
        raise ValueError("Release tag/version relationship is invalid")
    compliance = manifest.get("compliance", {})
    if (
        not isinstance(compliance, dict)
        or compliance.get("stable_release_eligible") is not True
        or compliance.get("license_review") != "approved"
        or compliance.get("sbom_scope") != "final-shipped-bytes"
    ):
        raise ValueError("Stable release compliance review is incomplete")
    if manifest["signature"].get("authenticode") != "Valid":
        raise ValueError("Manifest does not record valid Authenticode")
    if manifest["signature"].get("trusted_timestamp") is not True:
        raise ValueError("Manifest does not record a trusted timestamp")
    build = manifest.get("build", {})
    started = parse_utc(build.get("started_at_utc"), field="build.started_at_utc")
    finished = parse_utc(build.get("finished_at_utc"), field="build.finished_at_utc")
    verified = parse_utc(build.get("verified_at_utc"), field="build.verified_at_utc")
    parse_utc(build.get("source_date_epoch_utc"), field="build.source_date_epoch_utc")
    if not started <= finished <= verified:
        raise ValueError("Manifest build timestamps are not ordered")
    release_verification = manifest.get("verification", {})
    if release_verification.get("schema") != 1:
        raise ValueError("Post-package release verification evidence is missing")
    completed = parse_utc(
        release_verification.get("completed_at_utc"),
        field="verification.completed_at_utc",
    )
    if completed < verified:
        raise ValueError("Post-package verification predates build verification")
    expected_gates = {
        "staged-authenticated-workspace",
        "installer-install-start-uninstall",
        "portable-authenticated-workspace",
        "legacy-migration-non-overwrite",
        "authenticode-chain-and-timestamp",
        "defender",
        "privacy-artifact-rescan",
    }
    if set(release_verification.get("gates", [])) != expected_gates:
        raise ValueError("Post-package release verification gates are incomplete")
    required_compliance_keys = {
        "sbom_scope",
        "license_review",
        "stable_release_eligible",
        "evidence_schema",
        "evidence_sha256",
        "reviewed_at_utc",
        "review_reference",
        "component_inventory_sha256",
        "evidence_base64",
        "application_signing_request_schema",
        "application_signing_request_sha256",
        "application_signing_request_base64",
        "application_signing_request_repository",
        "application_signing_request_workflow_ref",
        "application_signing_request_run_id",
        "application_signing_request_run_attempt",
        "application_signing_request_job",
    }
    if (
        set(compliance) != required_compliance_keys
        or compliance.get("evidence_schema") != 2
        or SHA256_RE.fullmatch(str(compliance.get("evidence_sha256", ""))) is None
        or SHA256_RE.fullmatch(
            str(compliance.get("component_inventory_sha256", ""))
        )
        is None
        or not str(compliance.get("review_reference", "")).strip()
        or not str(compliance.get("evidence_base64", "")).strip()
    ):
        raise ValueError("Stable release compliance evidence is incomplete")
    reviewed = parse_utc(
        compliance.get("reviewed_at_utc"), field="compliance.reviewed_at_utc"
    )
    if reviewed > verified:
        raise ValueError("Compliance review timestamp is after build verification")
    try:
        evidence_bytes = base64.b64decode(
            compliance["evidence_base64"], validate=True
        )
    except (TypeError, ValueError, binascii.Error) as exc:
        raise ValueError("Embedded compliance evidence is invalid") from exc
    if hashlib.sha256(evidence_bytes).hexdigest() != compliance["evidence_sha256"]:
        raise ValueError("Embedded compliance evidence hash is invalid")
    embedded_evidence = _strict_json_object(
        evidence_bytes, label="compliance evidence"
    )
    required_evidence_keys = {
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
    if (
        set(embedded_evidence) != required_evidence_keys
        or embedded_evidence.get("schema") != 2
        or embedded_evidence.get("release_commit") != expected_commit
        or embedded_evidence.get("source_tree") != manifest["release"].get("source_tree")
        or embedded_evidence.get("publisher")
        != manifest["signature"].get("publisher")
        or embedded_evidence.get("review_reference")
        != compliance["review_reference"]
        or embedded_evidence.get("reviewed_at_utc")
        != compliance["reviewed_at_utc"]
        or embedded_evidence.get("component_inventory_sha256")
        != compliance["component_inventory_sha256"]
        or embedded_evidence.get("license_review") != "approved"
        or embedded_evidence.get("sbom_scope") != "final-shipped-bytes"
        or embedded_evidence.get("stable_release_eligible") is not True
        or embedded_evidence.get("runtime_lock_sha256")
        != build.get("runtime_lock_sha256")
        or embedded_evidence.get("build_lock_sha256")
        != build.get("build_lock_sha256")
        or embedded_evidence.get("third_party_notices_sha256")
        != sha256_file(root / "THIRD_PARTY_NOTICES.md")
    ):
        raise ValueError("Embedded compliance decision differs from the release")
    try:
        application_request_bytes = base64.b64decode(
            compliance["application_signing_request_base64"], validate=True
        )
    except (TypeError, ValueError, binascii.Error) as exc:
        raise ValueError("Embedded application signing request is invalid") from exc
    if (
        hashlib.sha256(application_request_bytes).hexdigest()
        != compliance["application_signing_request_sha256"]
    ):
        raise ValueError("Embedded application signing request hash is invalid")
    application_request_value = _strict_json_object(
        application_request_bytes, label="application signing request"
    )
    application_request = validate_signing_request(application_request_value)
    if signing_exchange_canonical_bytes(application_request) != application_request_bytes:
        raise ValueError("Embedded application signing request is not canonical")
    application_release = application_request["release"]
    application_provenance = application_request["provenance"]
    assert isinstance(application_release, dict)
    assert isinstance(application_provenance, dict)
    if (
        application_request["subject_kind"] != "application"
        or application_release["commit"] != expected_commit
        or application_release["source_tree"] != manifest["release"].get("source_tree")
        or application_release["publisher"] != manifest["signature"].get("publisher")
        or application_provenance["repository"] != EXPECTED_REPOSITORY
        or application_provenance["workflow_ref"] != PREPARATION_WORKFLOW_REF
        or application_provenance["job"] != "prepare-unsigned-application"
        or compliance["application_signing_request_schema"] != application_request["schema"]
        or compliance["application_signing_request_repository"]
        != application_provenance["repository"]
        or compliance["application_signing_request_workflow_ref"]
        != application_provenance["workflow_ref"]
        or compliance["application_signing_request_run_id"]
        != application_provenance["run_id"]
        or compliance["application_signing_request_run_attempt"]
        != application_provenance["run_attempt"]
        or compliance["application_signing_request_job"] != application_provenance["job"]
    ):
        raise ValueError("Application signing request provenance differs from compliance")
    requested = parse_utc(
        application_request["created_at_utc"], field="application request created_at_utc"
    )
    if not requested <= reviewed <= verified:
        raise ValueError("Application request, compliance review and verification are unordered")

    reviewed_components = embedded_evidence.get("components")
    if not isinstance(reviewed_components, list):
        raise ValueError("Application compliance component inventory is missing")
    reviewed_executables = [
        item
        for item in reviewed_components
        if isinstance(item, dict) and item.get("path") == "DefenseTracker.exe"
    ]
    if len(reviewed_executables) != 1:
        raise ValueError("Application compliance does not uniquely bind DefenseTracker.exe")
    reviewed_executable = reviewed_executables[0]
    if (
        not isinstance(reviewed_executable.get("bytes"), int)
        or SHA256_RE.fullmatch(
            str(reviewed_executable.get("authenticode_neutral_sha256", ""))
        )
        is None
    ):
        raise ValueError("Application Authenticode-neutral review evidence is missing")

    installer_review = manifest.get("installer_review")
    required_installer_review_keys = {
        "schema",
        "scope",
        "stable_release_eligible",
        "request_sha256",
        "payload_inventory_sha256",
        "payload_file_count",
        "unsigned_installer_sha256",
        "unsigned_installer_bytes",
        "authenticode_normalized_sha256",
        "signed_installer_sha256",
        "signed_installer_bytes",
        "bootstrap_license",
        "request_base64",
    }
    if (
        not isinstance(installer_review, dict)
        or set(installer_review) != required_installer_review_keys
        or installer_review.get("schema") != 2
        or installer_review.get("scope") != "installer-release-review"
        or installer_review.get("stable_release_eligible") is not True
    ):
        raise ValueError("Independent installer review is incomplete")
    try:
        installer_request_bytes = base64.b64decode(
            installer_review["request_base64"], validate=True
        )
    except (TypeError, ValueError, binascii.Error) as exc:
        raise ValueError("Embedded installer review request is invalid") from exc
    if hashlib.sha256(installer_request_bytes).hexdigest() != installer_review.get(
        "request_sha256"
    ):
        raise ValueError("Embedded installer review request hash is invalid")
    request = validate_installer_review_request(
        _strict_json_object(installer_request_bytes, label="installer review request")
    )
    if installer_review_canonical_bytes(request) != installer_request_bytes:
        raise ValueError("Embedded installer review request is not canonical")
    if (
        request.get("release_commit") != expected_commit
        or request.get("source_tree") != manifest["release"].get("source_tree")
        or request.get("version") != version
        or request.get("publisher") != manifest["signature"].get("publisher")
    ):
        raise ValueError("Installer review request release identity differs")
    unsigned_installer = request.get("unsigned_installer")
    payload_inventory = request.get("payload_inventory")
    if not isinstance(unsigned_installer, dict) or not isinstance(payload_inventory, dict):
        raise ValueError("Installer review request is incomplete")
    payload_files = payload_inventory.get("files")
    if not isinstance(payload_files, list):
        raise ValueError("Installer review payload inventory is incomplete")
    if (
        request.get("payload_inventory_sha256")
        != installer_review["payload_inventory_sha256"]
        or len(payload_files) != installer_review["payload_file_count"]
        or unsigned_installer.get("sha256")
        != installer_review["unsigned_installer_sha256"]
        or unsigned_installer.get("bytes")
        != installer_review["unsigned_installer_bytes"]
        or unsigned_installer.get("normalized_sha256")
        != installer_review["authenticode_normalized_sha256"]
        or request.get("bootstrap_license") != installer_review["bootstrap_license"]
    ):
        raise ValueError("Installer review manifest differs from the signed decision")
    installer_path = root / f"DefenseTracker-Setup-v{version}-windows-x64.exe"
    installer_identity = inspect_authenticode_image(
        installer_path,
        require_state="signed",
        expected_unsigned_size=int(unsigned_installer["bytes"]),
        expected_normalized_sha256=str(unsigned_installer["normalized_sha256"]),
    )
    if (
        installer_identity.file_sha256
        != installer_review["signed_installer_sha256"]
        or installer_identity.bytes != installer_review["signed_installer_bytes"]
    ):
        raise ValueError("Signed installer identity differs from its review binding")
    signatures = manifest.get("signatures")
    if not isinstance(signatures, dict) or set(signatures) != {
        "application",
        "installer",
    }:
        raise ValueError("Per-artifact Authenticode identities are incomplete")
    for name in ("application", "installer"):
        signature_record = signatures.get(name)
        if (
            not isinstance(signature_record, dict)
            or signature_record.get("authenticode") != "Valid"
            or signature_record.get("trusted_timestamp") is not True
            or signature_record.get("publisher")
            != manifest["signature"].get("publisher")
            or signature_record.get("provider")
            != manifest["signature"].get("provider")
            or not str(signature_record.get("signer_subject", "")).strip()
            or not str(
                signature_record.get("timestamp_certificate_subject", "")
            ).strip()
        ):
            raise ValueError(f"{name} Authenticode identity is incomplete")
    application_exchange_request, application_exchange_receipt = (
        _validate_embedded_exchange(
            signatures["application"],
            subject_kind="application",
            expected_commit=expected_commit,
            expected_publisher=str(manifest["signature"].get("publisher", "")),
        )
    )
    installer_exchange_request, installer_exchange_receipt = _validate_embedded_exchange(
        signatures["installer"],
        subject_kind="installer",
        expected_commit=expected_commit,
        expected_publisher=str(manifest["signature"].get("publisher", "")),
    )
    app_receipt_provenance = application_exchange_receipt["provenance"]
    installer_request_provenance = installer_exchange_request["provenance"]
    assert isinstance(app_receipt_provenance, dict)
    assert isinstance(installer_request_provenance, dict)
    if (
        app_receipt_provenance["run_id"] != installer_request_provenance["run_id"]
        or app_receipt_provenance["run_attempt"]
        != installer_request_provenance["run_attempt"]
    ):
        raise ValueError("Installer request is not from the exact application-signing run")
    app_request_hash = hashlib.sha256(
        signing_exchange_canonical_bytes(application_exchange_request)
    ).hexdigest()
    if app_request_hash != compliance["application_signing_request_sha256"]:
        raise ValueError("Compliance and application signature bind different requests")
    top_policy_sha = manifest["signature"].get("publisher_policy_sha256")
    if SHA256_RE.fullmatch(str(top_policy_sha)) is None:
        raise ValueError("Manifest Publisher policy SHA-256 is invalid")
    application_receipt_signature = application_exchange_receipt["signature"]
    installer_receipt_signature = installer_exchange_receipt["signature"]
    assert isinstance(application_receipt_signature, dict)
    assert isinstance(installer_receipt_signature, dict)
    if (
        application_receipt_signature["provider"]
        != installer_receipt_signature["provider"]
        or application_receipt_signature["provider"]
        != manifest["signature"].get("provider")
    ):
        raise ValueError("Signing provider differs across signature receipts")
    application_policy = application_receipt_signature["publisher_policy"]
    installer_policy = installer_receipt_signature["publisher_policy"]
    assert isinstance(application_policy, dict)
    assert isinstance(installer_policy, dict)
    if (
        application_policy["sha256"] != top_policy_sha
        or installer_policy["sha256"] != top_policy_sha
    ):
        raise ValueError("Publisher policy SHA differs across signature receipts")
    provider = application_receipt_signature["provider"]
    if provider == "AzureArtifactSigning":
        durable_fields = (
            "leaf_spki_policy",
            "durable_identity_eku",
            "azure_endpoint",
            "azure_account_name",
            "azure_certificate_profile_name",
            "digicert_sm_host",
            "digicert_key_alias",
        )
        if any(
            application_policy[field] != installer_policy[field]
            for field in durable_fields
        ):
            raise ValueError("Azure durable Publisher identity differs across stages")
        if (
            application_policy["leaf_spki_policy"] != "record-only"
            or any(
                SHA256_RE.fullmatch(str(policy["azure_metadata_sha256"])) is None
                for policy in (application_policy, installer_policy)
            )
        ):
            raise ValueError("Azure Publisher policy evidence is incomplete")
    elif provider == "DigiCertKeyLocker":
        durable_fields = (
            "leaf_spki_policy",
            "digicert_sm_host",
            "digicert_key_alias",
            "durable_identity_eku",
            "azure_endpoint",
            "azure_account_name",
            "azure_certificate_profile_name",
            "azure_metadata_sha256",
        )
        identity_fields = (
            "signer_subject",
            "signer_spki_sha256",
            "signer_issuer_subject",
            "signer_root_sha256",
        )
        if (
            application_policy["leaf_spki_policy"] != "required-pin"
            or any(
                application_policy[field] != installer_policy[field]
                for field in durable_fields
            )
            or any(
                application_receipt_signature[field]
                != installer_receipt_signature[field]
                for field in identity_fields
            )
        ):
            raise ValueError("DigiCert durable signer identity differs across stages")
    else:  # pragma: no cover - rejected by the canonical receipt schema
        raise ValueError("Signing provider is unsupported")
    if (
        signatures["installer"].get("unsigned_sha256")
        != installer_review["unsigned_installer_sha256"]
        or signatures["installer"].get("signed_sha256")
        != installer_identity.file_sha256
        or signatures["installer"].get("signed_bytes") != installer_identity.bytes
        or signatures["installer"].get("authenticode_normalized_sha256")
        != installer_identity.normalized_sha256
        or installer_exchange_receipt["signed_sha256"]
        != installer_identity.file_sha256
        or installer_exchange_receipt["signed_bytes"] != installer_identity.bytes
    ):
        raise ValueError("Installer signature identity differs from reviewed bytes")
    required_tools = {"python", "signtool", "iscc", "seven_zip", "defender"}
    toolchain = manifest.get("build", {}).get("toolchain", {})
    if not isinstance(toolchain, dict) or not required_tools.issubset(toolchain):
        raise ValueError("Manifest signed toolchain evidence is incomplete")
    for name in sorted(required_tools):
        entry = toolchain[name]
        if (
            not isinstance(entry, dict)
            or SHA256_RE.fullmatch(str(entry.get("sha256", ""))) is None
            or entry.get("sha256") != entry.get("expected_sha256")
            or entry.get("hash_verified") is not True
            or not str(entry.get("version", "")).strip()
        ):
            raise ValueError(f"Manifest toolchain evidence is invalid for {name}")

    expected_manifest_names = expected_names.difference(
        {"SHA256SUMS.txt", "release-manifest.json"}
    )
    manifest_assets = manifest.get("assets")
    if not isinstance(manifest_assets, list):
        raise ValueError("Manifest asset inventory is absent")
    by_name: dict[str, dict[str, object]] = {}
    for entry in manifest_assets:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "bytes", "sha256"}
            or not isinstance(entry.get("path"), str)
            or not isinstance(entry.get("bytes"), int)
            or isinstance(entry.get("bytes"), bool)
            or int(entry["bytes"]) < 0
            or SHA256_RE.fullmatch(str(entry.get("sha256", ""))) is None
            or entry["path"] in by_name
        ):
            raise ValueError("Manifest asset inventory is malformed or duplicated")
        by_name[str(entry["path"])] = entry
    if set(by_name) != expected_manifest_names:
        raise ValueError("Manifest asset inventory differs from the fixed asset set")
    for name, entry in by_name.items():
        path = root / name
        if path.stat().st_size != entry["bytes"] or sha256_file(path) != entry["sha256"]:
            raise ValueError(f"Manifest hash/size mismatch for {name}")

    sums: dict[str, str] = {}
    for line in (root / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        digest, separator, name = line.partition("  ")
        if (
            separator != "  "
            or not SHA256_RE.fullmatch(digest)
            or name in sums
        ):
            raise ValueError("Malformed SHA256SUMS line")
        sums[name] = digest
    expected_sum_names = expected_names.difference({"SHA256SUMS.txt"})
    if set(sums) != expected_sum_names:
        raise ValueError("SHA256SUMS does not contain the exact release asset set")
    for name in expected_sum_names:
        if sums.get(name) != sha256_file(root / name):
            raise ValueError(f"SHA256SUMS mismatch for {name}")

    portable_exe_bytes = verify_portable_archive_inventory(root, manifest)
    portable_exe_hash = hashlib.sha256(portable_exe_bytes).hexdigest()
    if portable_exe_hash != release_verification.get("portable_exe_sha256"):
        raise ValueError("Portable EXE hash differs from release verification evidence")
    with tempfile.TemporaryDirectory(prefix="defense-v9-portable-exe-") as temporary:
        portable_exe_path = Path(temporary) / "DefenseTracker.exe"
        portable_exe_path.write_bytes(portable_exe_bytes)
        application_identity = inspect_authenticode_image(
            portable_exe_path,
            require_state="signed",
            expected_unsigned_size=int(reviewed_executable["bytes"]),
            expected_normalized_sha256=str(
                reviewed_executable["authenticode_neutral_sha256"]
            ),
        )
    if (
        signatures["application"].get("unsigned_sha256")
        != reviewed_executable.get("sha256")
        or signatures["application"].get("signed_sha256")
        != application_identity.file_sha256
        or signatures["application"].get("signed_bytes")
        != application_identity.bytes
        or signatures["application"].get("authenticode_normalized_sha256")
        != application_identity.normalized_sha256
        or application_exchange_receipt["signed_sha256"]
        != application_identity.file_sha256
        or application_exchange_receipt["signed_bytes"]
        != application_identity.bytes
    ):
        raise ValueError("Portable application differs from reviewed signed bytes")
    sbom = json.loads(
        (root / f"DefenseTracker-v{version}.spdx.json").read_text(encoding="utf-8")
    )
    if sbom.get("spdxVersion") != "SPDX-2.3" or not sbom.get("packages"):
        raise ValueError("SPDX asset is invalid")
    sbom_packages = sbom["packages"]
    if not isinstance(sbom_packages, list):
        raise ValueError("SPDX package inventory is invalid")
    for package in sbom_packages:
        if package.get("licenseDeclared") in {None, "", "NOASSERTION"} or package.get(
            "licenseConcluded"
        ) in {None, "", "NOASSERTION"}:
            raise ValueError("SPDX contains an unresolved package license")
        if package.get("downloadLocation") in {None, "", "NOASSERTION"}:
            raise ValueError("SPDX contains an unresolved package download location")
        if package.get("copyrightText") in {None, "", "NOASSERTION"}:
            raise ValueError("SPDX contains unresolved package copyright")
    packages_by_name = {
        package.get("name"): package
        for package in sbom_packages
        if isinstance(package, dict) and isinstance(package.get("name"), str)
    }
    artifact_packages = {
        f"DefenseTracker-Setup-v{version}-windows-x64.exe": (
            "DefenseTracker Windows Installer"
        ),
        f"DefenseTracker-v{version}-windows-x64-portable.zip": (
            "DefenseTracker Windows Portable"
        ),
    }
    for asset_name, package_name in artifact_packages.items():
        package = packages_by_name.get(package_name)
        checksums = package.get("checksums", []) if isinstance(package, dict) else []
        matching = [
            item.get("checksumValue")
            for item in checksums
            if isinstance(item, dict) and item.get("algorithm") == "SHA256"
        ]
        if matching != [sha256_file(root / asset_name)]:
            raise ValueError(f"SPDX does not bind final artifact bytes for {asset_name}")
    bootstrap_license = installer_review.get("bootstrap_license")
    if not isinstance(bootstrap_license, dict):
        raise ValueError("Installer bootstrap license evidence is missing")
    license_id = bootstrap_license.get("license_declared")
    extracted = sbom.get("hasExtractedLicensingInfos")
    matching_licenses = [
        item
        for item in extracted
        if isinstance(item, dict) and item.get("licenseId") == license_id
    ] if isinstance(extracted, list) else []
    if (
        not isinstance(license_id, str)
        or not license_id.startswith("LicenseRef-")
        or bootstrap_license.get("license_concluded") != license_id
        or len(matching_licenses) != 1
        or matching_licenses[0].get("extractedText")
        != bootstrap_license.get("license_text")
    ):
        raise ValueError("SPDX does not embed the reviewed installer bootstrap license")
    installer_package = packages_by_name.get("DefenseTracker Windows Installer")
    portable_package = packages_by_name.get("DefenseTracker Windows Portable")
    if (
        not isinstance(installer_package, dict)
        or license_id not in str(installer_package.get("licenseDeclared", ""))
        or license_id not in str(installer_package.get("licenseConcluded", ""))
        or not isinstance(portable_package, dict)
        or license_id in str(portable_package.get("licenseDeclared", ""))
        or license_id in str(portable_package.get("licenseConcluded", ""))
    ):
        raise ValueError("SPDX applies the installer-only license to the wrong artifact")
    sbom_files = sbom.get("files")
    if not isinstance(sbom_files, list):
        raise ValueError("SPDX final component inventory is missing")
    files_by_name: dict[str, dict[str, object]] = {}
    for item in sbom_files:
        if not isinstance(item, dict) or not isinstance(item.get("fileName"), str):
            raise ValueError("SPDX final component entry is invalid")
        filename = item["fileName"]
        if filename in files_by_name:
            raise ValueError("SPDX final component path is duplicated")
        files_by_name[filename] = item
    expected_portable_files = {
        f"./DefenseTracker/{entry['path']}": entry
        for entry in manifest.get("portable_contents", [])
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    }
    if set(files_by_name) != set(expected_portable_files):
        raise ValueError("SPDX does not cover every final portable component")
    for filename, expected_entry in expected_portable_files.items():
        item = files_by_name[filename]
        checksums = item.get("checksums", [])
        matching = [
            checksum.get("checksumValue")
            for checksum in checksums
            if isinstance(checksum, dict) and checksum.get("algorithm") == "SHA256"
        ]
        if matching != [expected_entry.get("sha256")]:
            raise ValueError(f"SPDX final component hash mismatch for {filename}")
        license_info = item.get("licenseInfoInFiles")
        if (
            item.get("licenseConcluded") in {None, "", "NOASSERTION"}
            or not isinstance(license_info, list)
            or not license_info
            or any(value in {None, "", "NOASSERTION"} for value in license_info)
        ):
            raise ValueError(f"SPDX final component license is unresolved for {filename}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--portable-inventory-only", action="store_true")
    args = parser.parse_args()
    if args.portable_inventory_only:
        root = args.root
        if root.is_symlink() or _is_reparse(root) or not root.is_dir():
            raise ValueError("Release asset root must be a regular directory")
        root = root.resolve()
        manifest = json.loads(
            (root / "release-manifest.json").read_text(encoding="utf-8-sig")
        )
        if (
            manifest.get("schema") != 2
            or manifest.get("kind") != "stable-release"
            or manifest.get("release", {}).get("commit") != args.expected_commit
        ):
            raise ValueError("Portable inventory manifest identity is invalid")
        verify_portable_archive_inventory(root, manifest)
        print("portable-inventory: PASS")
        return 0
    verify(args.root, expected_commit=args.expected_commit)
    print("release-assets: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
