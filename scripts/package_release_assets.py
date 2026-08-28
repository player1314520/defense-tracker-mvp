# -*- coding: utf-8 -*-
"""Create the fixed DefenseTracker release asset set without publishing it."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from packaging.licenses import InvalidLicenseExpression, canonicalize_license_expression


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from product_version import PRODUCT_VERSION  # noqa: E402
from scripts.authenticode_digest import inspect_authenticode_image  # noqa: E402
from scripts.installer_review import (  # noqa: E402
    verify_installer_after_sign,
    verify_installer_before_sign,
)


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s]+)$")
REVIEW_REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/\-]{2,127}$")


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
    if signing_provider == "AzureArtifactSigning":
        required.update({"azure_dlib", "azure_metadata"})
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
    signature_path: Path,
    reviewer_registry: Path,
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
        "reviewer_key_id",
        "reviewer_organization",
        "component_inventory_sha256",
        "components",
        "packages",
    }
    if not isinstance(evidence, dict) or set(evidence) != required_keys:
        raise ValueError("Compliance evidence keys differ from the schema")
    registry = json.loads(reviewer_registry.read_text(encoding="utf-8-sig"))
    if (
        not isinstance(registry, dict)
        or set(registry) != {"schema", "status", "reviewers"}
        or registry.get("schema") != 1
        or registry.get("status") != "active"
        or not isinstance(registry.get("reviewers"), list)
    ):
        raise ValueError("Compliance reviewer registry is inactive or malformed")
    reviewer_key_id = str(evidence.get("reviewer_key_id", ""))
    reviewer_entries = [
        item
        for item in registry["reviewers"]
        if isinstance(item, dict) and item.get("key_id") == reviewer_key_id
    ]
    if len(reviewer_entries) != 1:
        raise ValueError("Compliance reviewer key is not registered")
    reviewer = reviewer_entries[0]
    reviewer_keys = {
        "key_id",
        "organization",
        "public_key_base64",
        "public_key_sha256",
        "allowed_publishers",
    }
    if set(reviewer) != reviewer_keys or not isinstance(
        reviewer.get("allowed_publishers"), list
    ):
        raise ValueError("Compliance reviewer registration is malformed")
    try:
        public_key_bytes = base64.b64decode(
            str(reviewer["public_key_base64"]), validate=True
        )
        signature = base64.b64decode(
            signature_path.read_text(encoding="ascii").strip(), validate=True
        )
    except (OSError, UnicodeError, binascii.Error) as exc:
        raise ValueError("Compliance signature material is invalid") from exc
    if (
        len(public_key_bytes) != 32
        or len(signature) != 64
        or hashlib.sha256(public_key_bytes).hexdigest()
        != reviewer.get("public_key_sha256")
        or evidence.get("reviewer_organization") != reviewer.get("organization")
        or publisher not in reviewer["allowed_publishers"]
    ):
        raise ValueError("Compliance reviewer identity does not match the registry")
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature, evidence_bytes
        )
    except (ValueError, InvalidSignature) as exc:
        raise ValueError("Compliance evidence signature is invalid") from exc

    if (
        evidence.get("schema") != 1
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
    if reviewed > verified:
        raise ValueError("Compliance review timestamp is after build verification")
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
    for row in component_rows:
        if not isinstance(row, dict):
            raise ValueError("Compliance component entry differs from the schema")
        relative_value = row.get("path")
        if not isinstance(relative_value, str):
            raise ValueError("Compliance component entry differs from the schema")
        relative = relative_value
        pure = PurePosixPath(relative)
        if (
            pure.is_absolute()
            or ".." in pure.parts
            or "\\" in relative
            or relative in reviewed_components
        ):
            raise ValueError("Compliance component path is invalid")
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
        "evidence_schema": 1,
        "evidence_sha256": actual_sha256,
        "reviewed_at_utc": evidence["reviewed_at_utc"],
        "review_reference": review_reference,
        "reviewer_key_id": reviewer_key_id,
        "reviewer_public_key_sha256": reviewer["public_key_sha256"],
        "reviewer_organization": evidence["reviewer_organization"],
        "reviewer_registry_sha256": sha256_file(reviewer_registry),
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
        "component_inventory_sha256": evidence["component_inventory_sha256"],
        "evidence_base64": base64.b64encode(evidence_bytes).decode("ascii"),
        "signature_base64": base64.b64encode(signature).decode("ascii"),
    }
    return reviewed_packages, reviewed_components, compliance


def load_installer_compliance(
    *,
    evidence_path: Path,
    signature_path: Path,
    reviewer_registry: Path,
    expected_evidence_sha256: str,
    application_reviewer_key_id: str,
    application_reviewer_public_key_sha256: str,
    unsigned_installer: Path,
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
    """Verify and embed the independent installer review boundary."""

    review = verify_installer_before_sign(
        evidence_path=evidence_path,
        signature_path=signature_path,
        reviewer_registry=reviewer_registry,
        expected_evidence_sha256=expected_evidence_sha256,
        application_reviewer_key_id=application_reviewer_key_id,
        unsigned_installer=unsigned_installer,
        extracted_payload_root=extracted_payload_root,
        signed_application_inventory=signed_application_inventory,
        iss_path=iss_path,
        iscc_path=iscc_path,
        iscc_version=iscc_version,
        seven_zip_path=seven_zip_path,
        seven_zip_version=seven_zip_version,
        bootstrap_license_declared=bootstrap_license_declared,
        bootstrap_license_concluded=bootstrap_license_concluded,
        bootstrap_copyright_text=bootstrap_copyright_text,
        bootstrap_license_text_path=bootstrap_license_text_path,
        expected_commit=commit,
        expected_source_tree=source_tree,
        expected_version=PRODUCT_VERSION.semantic_version,
        expected_publisher=publisher,
    )
    post_sign = verify_installer_after_sign(
        review,
        signed_installer=signed_installer,
        extracted_payload_root=extracted_payload_root,
    )
    if review.pre_sign_binding is None:  # pragma: no cover - dataclass invariant
        raise ValueError("Installer review lacks a pre-sign binding")
    installer_registry = json.loads(reviewer_registry.read_text(encoding="utf-8-sig"))
    installer_reviewers = installer_registry.get("reviewers", [])
    installer_reviewer_entries = [
        item
        for item in installer_reviewers
        if isinstance(item, dict) and item.get("key_id") == review.reviewer_key_id
    ] if isinstance(installer_reviewers, list) else []
    if (
        len(installer_reviewer_entries) != 1
        or installer_reviewer_entries[0].get("public_key_sha256")
        == application_reviewer_public_key_sha256
    ):
        raise ValueError("Application and installer reviews require distinct keys")
    try:
        signature = base64.b64decode(
            signature_path.read_text(encoding="ascii").strip(), validate=True
        )
    except (OSError, UnicodeError, binascii.Error) as exc:
        raise ValueError("Installer review signature material is invalid") from exc
    if hashlib.sha256(signature).hexdigest() != review.signature_sha256:
        raise ValueError("Installer review signature hash changed after verification")
    request = review.request
    unsigned = request["unsigned_installer"]
    payload = request["payload_inventory"]
    bootstrap = request["bootstrap_license"]
    assert isinstance(unsigned, dict)
    assert isinstance(payload, dict)
    assert isinstance(bootstrap, dict)
    payload_files = payload.get("files")
    if not isinstance(payload_files, list):  # pragma: no cover - validated upstream
        raise ValueError("Installer payload inventory is malformed")
    evidence_bytes = evidence_path.read_bytes()
    return {
        "schema": 1,
        "scope": "installer-release-review",
        "stable_release_eligible": True,
        "evidence_sha256": review.evidence_sha256,
        "signature_sha256": review.signature_sha256,
        "reviewer_registry_sha256": review.reviewer_registry_sha256,
        "reviewer_key_id": review.reviewer_key_id,
        "reviewer_organization": review.reviewer_organization,
        "review_reference": review.review_reference,
        "reviewed_at_utc": review.reviewed_at_utc,
        "request_sha256": review.request_sha256,
        "payload_inventory_sha256": request["payload_inventory_sha256"],
        "payload_file_count": len(payload_files),
        "unsigned_installer_sha256": unsigned["sha256"],
        "unsigned_installer_bytes": unsigned["bytes"],
        "authenticode_normalized_sha256": unsigned["normalized_sha256"],
        "signed_installer_sha256": post_sign.installer_sha256,
        "signed_installer_bytes": post_sign.installer_bytes,
        "bootstrap_license": bootstrap,
        "pre_sign_binding": review.pre_sign_binding.as_dict(),
        "post_sign_binding": post_sign.as_dict(),
        "evidence_base64": base64.b64encode(evidence_bytes).decode("ascii"),
        "signature_base64": base64.b64encode(signature).decode("ascii"),
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
        source = application_root.joinpath(*PurePosixPath(relative).parts)
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
        compliance_evidence_path = Path(compliance_evidence_arg).resolve()
        signature_arg = getattr(args, "compliance_signature", None)
        registry_arg = getattr(args, "compliance_reviewer_registry", None)
        inventory_arg = getattr(args, "component_inventory", None)
        if signature_arg is None or registry_arg is None or inventory_arg is None:
            raise ValueError("Signed compliance evidence inputs are incomplete")
        signature_path = Path(signature_arg).resolve()
        registry_path = Path(registry_arg).resolve()
        component_inventory_path = Path(inventory_arg).resolve()
        for required_compliance_file in (
            compliance_evidence_path,
            signature_path,
            registry_path,
            component_inventory_path,
        ):
            if not required_compliance_file.is_file():
                raise FileNotFoundError(required_compliance_file)
        package_licenses, component_licenses, compliance = load_compliance_evidence(
            compliance_evidence_path,
            signature_path=signature_path,
            reviewer_registry=registry_path,
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
        )
    elif compliance_evidence_sha256:
        raise ValueError("Compliance evidence path is missing")
    installer_review_evidence_arg = getattr(args, "installer_review_evidence", None)
    installer_review: dict[str, object] = {
        "scope": "installer-release-review",
        "stable_release_eligible": False,
    }
    if compliance.get("stable_release_eligible") is True:
        installer_inputs = {
            "evidence_path": installer_review_evidence_arg,
            "signature_path": getattr(args, "installer_review_signature", None),
            "reviewer_registry": getattr(args, "installer_reviewer_registry", None),
            "expected_evidence_sha256": getattr(
                args, "installer_review_evidence_sha256", None
            ),
            "unsigned_installer": getattr(args, "unsigned_installer", None),
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
            "evidence_path",
            "signature_path",
            "reviewer_registry",
            "unsigned_installer",
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
            application_reviewer_key_id=str(compliance["reviewer_key_id"]),
            application_reviewer_public_key_sha256=str(
                compliance["reviewer_public_key_sha256"]
            ),
            signed_installer=installer,
            commit=args.commit,
            source_tree=args.source_tree,
            publisher=args.publisher,
        )
    elif installer_review_evidence_arg is not None:
        raise ValueError("Installer review cannot replace application compliance review")

    signatures: dict[str, object] = {}
    if compliance.get("stable_release_eligible") is True:
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
        application_signer_subject = str(
            getattr(args, "application_signer_subject", "") or ""
        ).strip()
        application_timestamp_subject = str(
            getattr(args, "application_timestamp_subject", "") or ""
        ).strip()
        if not application_signer_subject or not application_timestamp_subject:
            raise ValueError("Application Authenticode evidence is incomplete")
        signatures["application"] = {
            "provider": args.signing_provider,
            "publisher": args.publisher,
            "signer_subject": application_signer_subject,
            "timestamp_url": args.timestamp_url,
            "timestamp_certificate_subject": application_timestamp_subject,
            "authenticode": "Valid",
            "trusted_timestamp": True,
            "unsigned_sha256": reviewed_executable["sha256"],
            "unsigned_bytes": reviewed_executable["bytes"],
            "signed_sha256": application_identity.file_sha256,
            "signed_bytes": application_identity.bytes,
            "authenticode_normalized_sha256": application_identity.normalized_sha256,
            "verified_at_utc": verified_raw,
        }
        signatures["installer"] = {
            "provider": args.signing_provider,
            "publisher": args.publisher,
            "signer_subject": args.signer_subject,
            "timestamp_url": args.timestamp_url,
            "timestamp_certificate_subject": args.timestamp_subject,
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
        }
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
        "signature": {
            "provider": args.signing_provider,
            "publisher": args.publisher,
            "signer_subject": args.signer_subject,
            "timestamp_url": args.timestamp_url,
            "timestamp_certificate_subject": args.timestamp_subject,
            "authenticode": "Valid",
            "trusted_timestamp": True,
            "verified_at_utc": verified_raw,
        },
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
    parser.add_argument("--signer-subject", required=True)
    parser.add_argument("--timestamp-url", required=True)
    parser.add_argument("--timestamp-subject", required=True)
    parser.add_argument("--python-version", required=True)
    parser.add_argument("--runtime-lock-sha256", required=True)
    parser.add_argument("--build-lock-sha256", required=True)
    parser.add_argument("--toolchain-evidence", type=Path, required=True)
    parser.add_argument("--compliance-evidence", type=Path)
    parser.add_argument("--compliance-evidence-sha256")
    parser.add_argument("--compliance-signature", type=Path)
    parser.add_argument("--compliance-reviewer-registry", type=Path)
    parser.add_argument("--component-inventory", type=Path)
    parser.add_argument("--application-signer-subject")
    parser.add_argument("--application-timestamp-subject")
    parser.add_argument("--installer-review-evidence", type=Path)
    parser.add_argument("--installer-review-signature", type=Path)
    parser.add_argument("--installer-reviewer-registry", type=Path)
    parser.add_argument("--installer-review-evidence-sha256")
    parser.add_argument("--unsigned-installer", type=Path)
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
