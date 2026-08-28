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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.authenticode_digest import inspect_authenticode_image  # noqa: E402
from scripts.installer_review import load_installer_review  # noqa: E402


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


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


def verify(
    root: Path,
    *,
    expected_commit: str,
    reviewer_registry: Path | None = None,
    installer_reviewer_registry: Path | None = None,
) -> None:
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
    actual_names = {path.name for path in root.iterdir() if path.is_file()}
    if actual_names != expected_names:
        raise ValueError(
            f"Release asset set differs from the contract: {sorted(actual_names)}"
        )
    if manifest.get("schema") != 2 or manifest.get("kind") != "stable-release":
        raise ValueError("Release manifest is not schema 2 stable-release")
    if manifest["release"]["commit"] != expected_commit:
        raise ValueError("Release manifest commit differs from the requested release")
    if manifest["version"]["release_tag"] != f"v{version}":
        raise ValueError("Release tag/version relationship is invalid")
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
    compliance = manifest.get("compliance", {})
    if (
        compliance.get("stable_release_eligible") is not True
        or compliance.get("license_review") != "approved"
        or compliance.get("sbom_scope") != "final-shipped-bytes"
    ):
        raise ValueError("Stable release compliance review is incomplete")
    if (
        compliance.get("evidence_schema") != 1
        or SHA256_RE.fullmatch(str(compliance.get("evidence_sha256", ""))) is None
        or SHA256_RE.fullmatch(
            str(compliance.get("reviewer_registry_sha256", ""))
        )
        is None
        or SHA256_RE.fullmatch(str(compliance.get("signature_sha256", ""))) is None
        or SHA256_RE.fullmatch(
            str(compliance.get("reviewer_public_key_sha256", ""))
        )
        is None
        or SHA256_RE.fullmatch(
            str(compliance.get("component_inventory_sha256", ""))
        )
        is None
        or not str(compliance.get("reviewer_key_id", "")).strip()
        or not str(compliance.get("reviewer_organization", "")).strip()
        or not str(compliance.get("review_reference", "")).strip()
        or not str(compliance.get("evidence_base64", "")).strip()
        or not str(compliance.get("signature_base64", "")).strip()
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
        signature_bytes = base64.b64decode(
            compliance["signature_base64"], validate=True
        )
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Embedded compliance signature material is invalid") from exc
    if (
        hashlib.sha256(evidence_bytes).hexdigest() != compliance["evidence_sha256"]
        or hashlib.sha256(signature_bytes).hexdigest()
        != compliance["signature_sha256"]
        or len(signature_bytes) != 64
    ):
        raise ValueError("Embedded compliance evidence hashes are invalid")
    try:
        embedded_evidence = json.loads(evidence_bytes.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Embedded compliance evidence is malformed") from exc
    registry_path = (
        reviewer_registry.resolve()
        if reviewer_registry is not None
        else Path(__file__).resolve().parents[1]
        / "release"
        / "compliance-reviewers.json"
    )
    registry_bytes = registry_path.read_bytes()
    if hashlib.sha256(registry_bytes).hexdigest() != compliance[
        "reviewer_registry_sha256"
    ]:
        raise ValueError("Compliance reviewer registry differs from the build")
    registry = json.loads(registry_bytes.decode("utf-8-sig"))
    if (
        not isinstance(registry, dict)
        or registry.get("schema") != 1
        or registry.get("status") != "active"
        or not isinstance(registry.get("reviewers"), list)
    ):
        raise ValueError("Compliance reviewer registry is inactive or malformed")
    reviewer_entries = [
        item
        for item in registry["reviewers"]
        if isinstance(item, dict)
        and item.get("key_id") == compliance["reviewer_key_id"]
    ]
    if len(reviewer_entries) != 1:
        raise ValueError("Compliance reviewer key is not registered")
    reviewer = reviewer_entries[0]
    try:
        public_key_bytes = base64.b64decode(
            str(reviewer.get("public_key_base64", "")), validate=True
        )
    except binascii.Error as exc:
        raise ValueError("Compliance reviewer public key is invalid") from exc
    if (
        len(public_key_bytes) != 32
        or hashlib.sha256(public_key_bytes).hexdigest()
        != reviewer.get("public_key_sha256")
        or reviewer.get("public_key_sha256")
        != compliance["reviewer_public_key_sha256"]
        or reviewer.get("organization") != compliance["reviewer_organization"]
        or manifest["signature"].get("publisher")
        not in reviewer.get("allowed_publishers", [])
    ):
        raise ValueError("Compliance reviewer identity differs from the registry")
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature_bytes, evidence_bytes
        )
    except (ValueError, InvalidSignature) as exc:
        raise ValueError("Embedded compliance evidence signature is invalid") from exc
    if (
        not isinstance(embedded_evidence, dict)
        or embedded_evidence.get("release_commit") != expected_commit
        or embedded_evidence.get("source_tree") != manifest["release"].get("source_tree")
        or embedded_evidence.get("publisher")
        != manifest["signature"].get("publisher")
        or embedded_evidence.get("reviewer_key_id")
        != compliance["reviewer_key_id"]
        or embedded_evidence.get("reviewer_organization")
        != compliance["reviewer_organization"]
        or embedded_evidence.get("review_reference")
        != compliance["review_reference"]
        or embedded_evidence.get("reviewed_at_utc")
        != compliance["reviewed_at_utc"]
        or embedded_evidence.get("component_inventory_sha256")
        != compliance["component_inventory_sha256"]
    ):
        raise ValueError("Embedded compliance decision differs from the release")

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
        "evidence_sha256",
        "signature_sha256",
        "reviewer_registry_sha256",
        "reviewer_key_id",
        "reviewer_organization",
        "review_reference",
        "reviewed_at_utc",
        "request_sha256",
        "payload_inventory_sha256",
        "payload_file_count",
        "unsigned_installer_sha256",
        "unsigned_installer_bytes",
        "authenticode_normalized_sha256",
        "signed_installer_sha256",
        "signed_installer_bytes",
        "bootstrap_license",
        "pre_sign_binding",
        "post_sign_binding",
        "evidence_base64",
        "signature_base64",
    }
    if (
        not isinstance(installer_review, dict)
        or set(installer_review) != required_installer_review_keys
        or installer_review.get("schema") != 1
        or installer_review.get("scope") != "installer-release-review"
        or installer_review.get("stable_release_eligible") is not True
    ):
        raise ValueError("Independent installer review is incomplete")
    installer_reviewed = parse_utc(
        installer_review.get("reviewed_at_utc"),
        field="installer_review.reviewed_at_utc",
    )
    if installer_reviewed > verified:
        raise ValueError("Installer review timestamp is after build verification")
    try:
        installer_evidence_bytes = base64.b64decode(
            installer_review["evidence_base64"], validate=True
        )
        installer_signature_bytes = base64.b64decode(
            installer_review["signature_base64"], validate=True
        )
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Embedded installer review material is invalid") from exc
    if (
        hashlib.sha256(installer_evidence_bytes).hexdigest()
        != installer_review["evidence_sha256"]
        or hashlib.sha256(installer_signature_bytes).hexdigest()
        != installer_review["signature_sha256"]
        or len(installer_signature_bytes) != 64
    ):
        raise ValueError("Embedded installer review hashes are invalid")
    installer_registry_path = (
        installer_reviewer_registry.resolve()
        if installer_reviewer_registry is not None
        else PROJECT_ROOT / "release" / "installer-reviewers.json"
    )
    if sha256_file(installer_registry_path) != installer_review[
        "reviewer_registry_sha256"
    ]:
        raise ValueError("Installer reviewer registry differs from the build")
    with tempfile.TemporaryDirectory(prefix="defense-v9-installer-review-") as temporary:
        temporary_root = Path(temporary)
        evidence_path = temporary_root / "installer-review.json"
        signature_path = temporary_root / "installer-review.sig"
        evidence_path.write_bytes(installer_evidence_bytes)
        signature_path.write_text(
            base64.b64encode(installer_signature_bytes).decode("ascii") + "\n",
            encoding="ascii",
            newline="\n",
        )
        verified_installer_review = load_installer_review(
            evidence_path,
            signature_path,
            installer_registry_path,
            expected_evidence_sha256=str(installer_review["evidence_sha256"]),
            application_reviewer_key_id=str(compliance["reviewer_key_id"]),
            expected_commit=expected_commit,
            expected_source_tree=str(manifest["release"].get("source_tree", "")),
            expected_version=version,
            expected_publisher=str(manifest["signature"].get("publisher", "")),
        )
    request = verified_installer_review.request
    installer_registry = json.loads(
        installer_registry_path.read_text(encoding="utf-8-sig")
    )
    installer_reviewer_entries = [
        item
        for item in installer_registry.get("reviewers", [])
        if isinstance(item, dict)
        and item.get("key_id") == verified_installer_review.reviewer_key_id
    ] if isinstance(installer_registry, dict) else []
    if (
        len(installer_reviewer_entries) != 1
        or installer_reviewer_entries[0].get("public_key_sha256")
        == compliance["reviewer_public_key_sha256"]
    ):
        raise ValueError("Application and installer reviews do not use distinct keys")
    unsigned_installer = request.get("unsigned_installer")
    payload_inventory = request.get("payload_inventory")
    if not isinstance(unsigned_installer, dict) or not isinstance(payload_inventory, dict):
        raise ValueError("Installer review request is incomplete")
    payload_files = payload_inventory.get("files")
    if not isinstance(payload_files, list):
        raise ValueError("Installer review payload inventory is incomplete")
    if (
        verified_installer_review.request_sha256
        != installer_review["request_sha256"]
        or verified_installer_review.reviewer_key_id
        != installer_review["reviewer_key_id"]
        or verified_installer_review.reviewer_organization
        != installer_review["reviewer_organization"]
        or verified_installer_review.review_reference
        != installer_review["review_reference"]
        or request.get("payload_inventory_sha256")
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
    expected_binding_keys = {
        "schema",
        "phase",
        "installer_sha256",
        "installer_bytes",
        "unsigned_installer_bytes",
        "normalized_sha256",
        "signature_state",
        "payload_inventory_sha256",
        "payload_file_count",
    }
    pre_binding = installer_review.get("pre_sign_binding")
    post_binding = installer_review.get("post_sign_binding")
    if (
        not isinstance(pre_binding, dict)
        or not isinstance(post_binding, dict)
        or set(pre_binding) != expected_binding_keys
        or set(post_binding) != expected_binding_keys
        or pre_binding.get("schema") != 1
        or pre_binding.get("phase") != "pre-sign"
        or pre_binding.get("signature_state") != "unsigned"
        or pre_binding.get("installer_sha256")
        != installer_review["unsigned_installer_sha256"]
        or pre_binding.get("installer_bytes")
        != installer_review["unsigned_installer_bytes"]
        or post_binding.get("schema") != 1
        or post_binding.get("phase") != "post-sign"
        or post_binding.get("signature_state") != "signed"
        or post_binding.get("installer_sha256")
        != installer_review["signed_installer_sha256"]
        or post_binding.get("installer_bytes")
        != installer_review["signed_installer_bytes"]
        or pre_binding.get("unsigned_installer_bytes")
        != installer_review["unsigned_installer_bytes"]
        or post_binding.get("unsigned_installer_bytes")
        != installer_review["unsigned_installer_bytes"]
        or pre_binding.get("normalized_sha256")
        != installer_review["authenticode_normalized_sha256"]
        or post_binding.get("normalized_sha256")
        != installer_review["authenticode_normalized_sha256"]
        or pre_binding.get("payload_inventory_sha256")
        != installer_review["payload_inventory_sha256"]
        or post_binding.get("payload_inventory_sha256")
        != installer_review["payload_inventory_sha256"]
        or pre_binding.get("payload_file_count")
        != installer_review["payload_file_count"]
        or post_binding.get("payload_file_count")
        != installer_review["payload_file_count"]
    ):
        raise ValueError("Installer pre/post signing bindings are inconsistent")

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
    if (
        signatures["installer"].get("unsigned_sha256")
        != installer_review["unsigned_installer_sha256"]
        or signatures["installer"].get("signed_sha256")
        != installer_identity.file_sha256
        or signatures["installer"].get("authenticode_normalized_sha256")
        != installer_identity.normalized_sha256
    ):
        raise ValueError("Installer signature identity differs from reviewed bytes")
    required_tools = {"python", "signtool", "iscc", "seven_zip", "defender"}
    if manifest["signature"].get("provider") == "AzureArtifactSigning":
        required_tools.update({"azure_dlib", "azure_metadata"})
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

    by_name = {entry["path"]: entry for entry in manifest["assets"]}
    for name in expected_names.difference({"SHA256SUMS.txt", "release-manifest.json"}):
        entry = by_name.get(name)
        if not entry or not SHA256_RE.fullmatch(entry["sha256"]):
            raise ValueError(f"Manifest hash is missing for {name}")
        if sha256_file(root / name) != entry["sha256"]:
            raise ValueError(f"Manifest hash mismatch for {name}")

    sums: dict[str, str] = {}
    for line in (root / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        digest, separator, name = line.partition("  ")
        if separator != "  " or not SHA256_RE.fullmatch(digest):
            raise ValueError("Malformed SHA256SUMS line")
        sums[name] = digest
    for name in expected_names.difference({"SHA256SUMS.txt"}):
        if sums.get(name) != sha256_file(root / name):
            raise ValueError(f"SHA256SUMS mismatch for {name}")

    portable = root / f"DefenseTracker-v{version}-windows-x64-portable.zip"
    with zipfile.ZipFile(portable) as archive:
        members = archive.infolist()
        if not members:
            raise ValueError("Portable ZIP is empty")
        for member in members:
            path = PurePosixPath(member.filename)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("Portable ZIP contains an unsafe member path")
        required = {
            "DefenseTracker/DefenseTracker.exe",
            "DefenseTracker/release-manifest.json",
        }
        if not required.issubset({member.filename for member in members}):
            raise ValueError("Portable ZIP is missing the signed application or build manifest")
        portable_exe_bytes = archive.read("DefenseTracker/DefenseTracker.exe")
        portable_exe_hash = hashlib.sha256(portable_exe_bytes).hexdigest()
        if portable_exe_hash != release_verification.get("portable_exe_sha256"):
            raise ValueError("Portable EXE hash differs from release verification evidence")
        with tempfile.TemporaryDirectory(
            prefix="defense-v9-portable-exe-"
        ) as temporary:
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
    parser.add_argument("--reviewer-registry", type=Path)
    parser.add_argument("--installer-reviewer-registry", type=Path)
    args = parser.parse_args()
    verify(
        args.root,
        expected_commit=args.expected_commit,
        reviewer_registry=args.reviewer_registry,
        installer_reviewer_registry=args.installer_reviewer_registry,
    )
    print("release-assets: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
