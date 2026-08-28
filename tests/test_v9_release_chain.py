# -*- coding: utf-8 -*-
import argparse
import base64
import hashlib
import json
import re
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from product_version import PRODUCT_VERSION, load_build_metadata
from scripts.authenticode_digest import inspect_authenticode_image
from scripts.finalize_release_assets import finalize as finalize_release_assets
from scripts.generate_component_inventory import generate as generate_component_inventory
from scripts.generate_windows_version_info import render_version_info
from scripts.installer_review import (
    APPROVAL_KIND,
    INSTALLER_REVIEW_SCOPE,
    canonical_json_bytes,
    generate_installer_review_request,
    write_canonical_json,
)
from scripts.package_release_assets import package_assets
from scripts.verify_deployment_evidence import (
    CORE_PAYLOAD_FILES,
    PAYLOAD_FILES,
    PRODUCTION_CHECKS,
    STAGING_CHECKS,
    seal_origin_isolation,
    verify as verify_deployment_evidence,
)
from scripts.verify_release_assets import verify as verify_release_assets
from scripts.verify_release_checks import (
    GITHUB_ACTIONS_APP_ID,
    REQUIRED_CHECKS,
    verify as verify_checks,
    verify_workflow_run,
)


ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
TREE = "b" * 40
IMAGE_DIGEST = "sha256:" + "c" * 64
STAGING_ORIGIN = "https://staging.defense-tracker.example"
PRODUCTION_ORIGIN = "https://portal.defense-tracker.example"


def _minimal_unsigned_pe64(*, overlay: bytes = b"review") -> bytes:
    """Create a structurally complete one-section AMD64 PE for release tests."""

    pe_offset = 0x80
    optional_size = 240
    headers_size = 0x200
    raw_size = 0x200
    image = bytearray(headers_size + raw_size)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    coff = pe_offset + 4
    struct.pack_into(
        "<HHIIIHH",
        image,
        coff,
        0x8664,
        1,
        0,
        0,
        0,
        optional_size,
        0x0022,
    )
    optional = coff + 20
    struct.pack_into("<H", image, optional, 0x20B)
    struct.pack_into("<I", image, optional + 4, raw_size)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<I", image, optional + 20, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<I", image, optional + 56, 0x2000)
    struct.pack_into("<I", image, optional + 60, headers_size)
    struct.pack_into("<I", image, optional + 64, 0x12345678)
    struct.pack_into("<H", image, optional + 68, 3)
    struct.pack_into("<I", image, optional + 108, 16)
    section = optional + optional_size
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 16, 0x1000, raw_size, headers_size)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[headers_size : headers_size + 16] = b"reviewed-body!!!"
    return bytes(image) + overlay


def _mock_authenticode_sign(unsigned: bytes) -> bytes:
    """Apply only the PE mutations that Authenticode signing is allowed to make."""

    signed = bytearray(unsigned)
    pe_offset = struct.unpack_from("<I", signed, 0x3C)[0]
    optional = pe_offset + 24
    security_directory = optional + 112 + 4 * 8
    certificate_offset = (len(unsigned) + 7) & ~7
    certificate = struct.pack("<IHH", 12, 0x0200, 0x0002) + b"mock" + b"\0" * 4
    signed.extend(b"\0" * (certificate_offset - len(signed)))
    signed.extend(certificate)
    struct.pack_into("<I", signed, optional + 64, 0x87654321)
    struct.pack_into(
        "<II", signed, security_directory, certificate_offset, len(certificate)
    )
    return bytes(signed)


def test_authenticode_neutral_digest_accepts_only_signature_mutations(tmp_path):
    executable = tmp_path / "DefenseTracker.exe"
    unsigned = _minimal_unsigned_pe64()
    executable.write_bytes(unsigned)
    before = inspect_authenticode_image(executable, require_state="unsigned")

    signed = _mock_authenticode_sign(unsigned)
    executable.write_bytes(signed)
    after = inspect_authenticode_image(
        executable,
        require_state="signed",
        expected_unsigned_size=before.bytes,
        expected_normalized_sha256=before.normalized_sha256,
    )
    assert after.normalized_sha256 == before.normalized_sha256
    assert after.certificate_table_offset == (before.bytes + 7) & ~7
    assert after.certificate_table_offset + after.certificate_table_bytes == after.bytes

    nonzero_alignment = bytearray(signed)
    nonzero_alignment[before.bytes] = 0x01
    executable.write_bytes(nonzero_alignment)
    with pytest.raises(ValueError, match="alignment padding is not zero"):
        inspect_authenticode_image(
            executable,
            require_state="signed",
            expected_unsigned_size=before.bytes,
            expected_normalized_sha256=before.normalized_sha256,
        )

    tampered = bytearray(signed)
    tampered[0x200] ^= 0x01
    executable.write_bytes(tampered)
    with pytest.raises(ValueError, match="outside Authenticode fields"):
        inspect_authenticode_image(
            executable,
            require_state="signed",
            expected_unsigned_size=before.bytes,
            expected_normalized_sha256=before.normalized_sha256,
        )


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _probe(
    *,
    environment: str,
    origin: str,
    checks: dict[str, int],
    started: datetime,
    completed: datetime,
    certificate_sha256: str,
) -> dict[str, object]:
    return {
        "schema": 2,
        "environment": environment,
        "release_commit": COMMIT,
        "candidate_run_id": 123,
        "portal_image_digest": IMAGE_DIGEST,
        "origin": origin,
        "started_at_utc": _utc(started),
        "completed_at_utc": _utc(completed),
        "tls": {
            "server_name": origin.removeprefix("https://"),
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "peer_certificate_sha256": certificate_sha256,
            "not_before_utc": _utc(started - timedelta(days=1)),
            "not_after_utc": _utc(completed + timedelta(days=30)),
        },
        "checks": [
            {
                "name": name,
                "method": "GET",
                "url": f"{origin}/evidence/{name}",
                "status_code": status,
                "elapsed_ms": 100 + index,
                "observed_at_utc": _utc(started + timedelta(seconds=index + 1)),
                "response_sha256": _digest(f"{environment}-{name}"),
            }
            for index, (name, status) in enumerate(checks.items())
        ],
    }


def _observations(
    *,
    environment: str,
    origin: str,
    certificate_sha256: str,
    started: datetime,
    count: int,
    spacing: timedelta,
) -> str:
    records = []
    for index in range(count):
        records.append(
            json.dumps(
                {
                    "schema": 2,
                    "environment": environment,
                    "release_commit": COMMIT,
                    "candidate_run_id": 123,
                    "portal_image_digest": IMAGE_DIGEST,
                    "origin": origin,
                    "observed_at_utc": _utc(started + spacing * index),
                    "tls_certificate_sha256": certificate_sha256,
                    "http_status": 200,
                    "elapsed_ms": 250 + index,
                    "disk_free_percent": 55.5,
                    "backup_age_hours": 3.5,
                    "response_sha256": _digest(f"{environment}-sample-{index}"),
                },
                separators=(",", ":"),
            )
        )
    return "\n".join(records) + "\n"


def _refresh_evidence_manifest(root: Path, generated: datetime) -> None:
    manifest = {
        "schema": 3,
        "release_commit": COMMIT,
        "candidate_run_id": 123,
        "portal_image_digest": IMAGE_DIGEST,
        "staging_origin": STAGING_ORIGIN,
        "production_origin": PRODUCTION_ORIGIN,
        "generated_at_utc": _utc(generated),
        "artifacts": [
            {
                "path": name,
                "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest(),
                "size_bytes": (root / name).stat().st_size,
            }
            for name in sorted(PAYLOAD_FILES)
        ],
    }
    (root / "deployment-evidence.json").write_text(
        json.dumps(manifest, separators=(",", ":")), encoding="utf-8"
    )


def _write_schema_3_evidence(root: Path, *, staging_hours: float = 24) -> datetime:
    generated = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=1)
    staging_certificate = _digest("staging-certificate")
    production_certificate = _digest("production-certificate")
    isolation_gates = []
    for environment in ("staging", "production"):
        target_digest = _digest(f"{environment}-origin-target-hmac")
        gate_names = [
            f"{environment}_public_edge_https_reachable",
            f"{environment}_origin_tcp_80_blocked",
            f"{environment}_origin_tcp_443_blocked",
            f"{environment}_origin_sni_443_blocked",
        ]
        for gate_name in gate_names:
            isolation_gates.append(
                {
                    "gate": gate_name,
                    "status": "pass",
                    "target_hmac_sha256": target_digest,
                    "observed_at_utc": _utc(generated),
                }
            )
    (root / "origin-isolation.json").write_text(
        json.dumps({"schema": 1, "gates": isolation_gates}, separators=(",", ":")),
        encoding="utf-8",
    )
    staging_started = generated - timedelta(hours=2)
    production_started = generated - timedelta(minutes=5)
    (root / "staging-probe.json").write_text(
        json.dumps(
            _probe(
                environment="staging",
                origin=STAGING_ORIGIN,
                checks=STAGING_CHECKS,
                started=staging_started,
                completed=staging_started + timedelta(minutes=1),
                certificate_sha256=staging_certificate,
            )
        ),
        encoding="utf-8",
    )
    (root / "production-probe.json").write_text(
        json.dumps(
            _probe(
                environment="production",
                origin=PRODUCTION_ORIGIN,
                checks=PRODUCTION_CHECKS,
                started=production_started,
                completed=production_started + timedelta(minutes=1),
                certificate_sha256=production_certificate,
            )
        ),
        encoding="utf-8",
    )
    (root / "staging-observations.jsonl").write_text(
        _observations(
            environment="staging",
            origin=STAGING_ORIGIN,
            certificate_sha256=staging_certificate,
            started=generated - timedelta(hours=staging_hours + 1),
            count=25,
            spacing=timedelta(hours=staging_hours / 24),
        ),
        encoding="utf-8",
    )
    (root / "production-observations.jsonl").write_text(
        _observations(
            environment="production",
            origin=PRODUCTION_ORIGIN,
            certificate_sha256=production_certificate,
            started=generated - timedelta(minutes=20),
            count=100,
            spacing=timedelta(seconds=10),
        ),
        encoding="utf-8",
    )
    restore_started = generated - timedelta(minutes=90)
    restore_completed = generated - timedelta(minutes=60)
    step_names = ["restore_started", "restore_completed", "integrity_checked", "rollback_verified"]
    recovery = {
        "schema": 2,
        "release_commit": COMMIT,
        "candidate_run_id": 123,
        "portal_image_digest": IMAGE_DIGEST,
        "origin": STAGING_ORIGIN,
        "run_id_sha256": _digest("restore-run"),
        "started_at_utc": _utc(restore_started),
        "completed_at_utc": _utc(restore_completed),
        "backup_created_at_utc": _utc(restore_started - timedelta(hours=2)),
        "source_backup_sha256": _digest("source-backup"),
        "restored_snapshot_sha256": _digest("restored-snapshot"),
        "integrity_query_sha256": _digest("integrity-query"),
        "integrity_result_sha256": _digest("integrity-result"),
        "records_expected": 120,
        "records_restored": 120,
        "steps": [
            {
                "name": name,
                "started_at_utc": _utc(restore_started + timedelta(minutes=index * 5)),
                "completed_at_utc": _utc(restore_started + timedelta(minutes=index * 5 + 1)),
                "exit_code": 0,
                "stdout_sha256": _digest(f"{name}-stdout"),
                "stderr_sha256": _digest(f"{name}-stderr"),
            }
            for index, name in enumerate(step_names)
        ],
    }
    (root / "backup-restore.json").write_text(json.dumps(recovery), encoding="utf-8")
    _refresh_evidence_manifest(root, generated)
    return generated


def test_single_version_source_is_internally_consistent():
    assert PRODUCT_VERSION.semantic_version == "9.0.0"
    assert PRODUCT_VERSION.windows_file_version == "9.0.0.0"
    assert PRODUCT_VERSION.display_version == "V9"
    assert PRODUCT_VERSION.release_tag == "v9.0.0"
    assert PRODUCT_VERSION.release_baseline == "5402cb5b6b05540315f24ba82014551644113805"
    startup = (ROOT / "scripts" / "启动.bat").read_text(encoding="utf-8-sig")
    assert "v8.0" not in startup.lower()
    assert "优先级版" not in startup


def test_portal_build_metadata_extension_uses_same_contract(tmp_path):
    path = tmp_path / "build-metadata.json"
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "commit": COMMIT,
                "source_tree": TREE,
                "built_at_utc": "2026-08-28T00:00:00Z",
                "context_files": [{"path": "v9_cloud.py"}],
            }
        ),
        encoding="utf-8",
    )
    assert load_build_metadata(path).commit == COMMIT


def test_windows_version_info_contains_required_release_fields():
    rendered = render_version_info(PRODUCT_VERSION, "Example Legal Publisher")
    for value in (
        "FileVersion",
        "ProductVersion",
        "ProductName",
        "CompanyName",
        "OriginalFilename",
        "LegalCopyright",
        "9.0.0.0",
        "DefenseTracker.exe",
        "Example Legal Publisher",
    ):
        assert value in rendered


def test_release_packager_emits_exact_six_assets_and_schema_2(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    unsigned_executable = _minimal_unsigned_pe64()
    (app / "DefenseTracker.exe").write_bytes(unsigned_executable)
    (app / "_internal").mkdir()
    (app / "_internal" / "version.json").write_text("{}", encoding="utf-8")
    component_inventory = tmp_path / "unsigned-component-inventory.json"
    generate_component_inventory(app, component_inventory)
    inventory_before_signing = json.loads(
        component_inventory.read_text(encoding="utf-8")
    )
    assert inventory_before_signing["schema"] == 2
    executable_inventory = next(
        item
        for item in inventory_before_signing["files"]
        if item["path"] == "DefenseTracker.exe"
    )
    assert re.fullmatch(
        r"[0-9a-f]{64}", executable_inventory["authenticode_neutral_sha256"]
    )
    installer = tmp_path / "installer.exe"
    unsigned_installer_bytes = _minimal_unsigned_pe64(overlay=b"installer-body")
    installer.write_bytes(unsigned_installer_bytes)
    notices = tmp_path / "THIRD_PARTY_NOTICES.md"
    notices.write_text("notices\n", encoding="utf-8")
    packages = tmp_path / "packages.txt"
    packages.write_text("Flask==3.1.3\n", encoding="utf-8")
    toolchain = tmp_path / "toolchain-evidence.json"
    tool_names = {
        "python",
        "signtool",
        "iscc",
        "seven_zip",
        "defender",
        "azure_dlib",
        "azure_metadata",
    }
    toolchain.write_text(
        json.dumps(
            {
                name: {
                    "version": "1.0",
                    "sha256": str(index) * 64,
                    "expected_sha256": str(index) * 64,
                    "hash_verified": True,
                }
                for index, name in enumerate(sorted(tool_names), start=1)
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "assets"
    args = argparse.Namespace(
        application_root=app,
        installer=installer,
        output_dir=output,
        third_party_notices=notices,
        packages_file=packages,
        commit=COMMIT,
        source_tree=TREE,
        source_date_epoch="1787875200",
        build_started_utc="2026-08-28T00:00:00Z",
        build_finished_utc="2026-08-28T00:00:01Z",
        verified_at_utc="2026-08-28T00:00:02Z",
        publisher="Example Legal Publisher",
        signing_provider="AzureArtifactSigning",
        signer_subject="CN=Example Legal Publisher",
        timestamp_url="http://timestamp.example.invalid",
        timestamp_subject="CN=Example Timestamp",
        python_version="Python 3.11.14",
        runtime_lock_sha256="c" * 64,
        build_lock_sha256="d" * 64,
        toolchain_evidence=toolchain,
    )
    package_assets(args)
    finalize_release_assets(
        output,
        expected_commit=COMMIT,
        completed_at_utc="2026-08-28T00:00:03Z",
        portable_exe_sha256=hashlib.sha256((app / "DefenseTracker.exe").read_bytes()).hexdigest(),
    )
    assert len(list(output.iterdir())) == 6
    manifest = json.loads((output / "release-manifest.json").read_text())
    assert manifest["schema"] == 2
    assert manifest["release"]["baseline_commit"] == PRODUCT_VERSION.release_baseline
    assert set(manifest["build"]["toolchain"]) == tool_names
    assert manifest["build"]["source_date_epoch_utc"].endswith("Z")
    assert manifest["build"]["started_at_utc"] == args.build_started_utc
    assert manifest["build"]["finished_at_utc"] == args.build_finished_utc
    assert manifest["verification"]["completed_at_utc"] == "2026-08-28T00:00:03Z"
    assert manifest["compliance"]["stable_release_eligible"] is False
    with pytest.raises(ValueError, match="compliance review is incomplete"):
        verify_release_assets(output, expected_commit=COMMIT)

    reviewer_private_key = Ed25519PrivateKey.generate()
    reviewer_public_key = reviewer_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    reviewer_registry = tmp_path / "compliance-reviewers.json"
    reviewer_registry.write_text(
        json.dumps(
            {
                "schema": 1,
                "status": "active",
                "reviewers": [
                    {
                        "key_id": "example-reviewer-2026",
                        "organization": "Example Independent Reviewer",
                        "public_key_base64": base64.b64encode(
                            reviewer_public_key
                        ).decode("ascii"),
                        "public_key_sha256": hashlib.sha256(
                            reviewer_public_key
                        ).hexdigest(),
                        "allowed_publishers": ["Example Legal Publisher"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    inventory_payload = json.loads(component_inventory.read_text(encoding="utf-8"))
    compliance_evidence = tmp_path / "compliance-evidence.json"
    compliance_evidence.write_text(
        json.dumps(
            {
                "schema": 1,
                "release_commit": COMMIT,
                "source_tree": TREE,
                "publisher": "Example Legal Publisher",
                "reviewed_at_utc": "2026-08-27T23:59:59Z",
                "review_reference": "legal-review:V9-2026-001",
                "reviewer_key_id": "example-reviewer-2026",
                "reviewer_organization": "Example Independent Reviewer",
                "license_review": "approved",
                "sbom_scope": "final-shipped-bytes",
                "stable_release_eligible": True,
                "runtime_lock_sha256": "c" * 64,
                "build_lock_sha256": "d" * 64,
                "packages_inventory_sha256": hashlib.sha256(
                    packages.read_bytes()
                ).hexdigest(),
                "third_party_notices_sha256": hashlib.sha256(
                    notices.read_bytes()
                ).hexdigest(),
                "component_inventory_sha256": hashlib.sha256(
                    component_inventory.read_bytes()
                ).hexdigest(),
                "components": [
                    {
                        **item,
                        "license_declared": "AGPL-3.0-only",
                        "license_concluded": "AGPL-3.0-only",
                        "copyright_text": "Copyright Example Legal Publisher",
                    }
                    for item in inventory_payload["files"]
                ],
                "packages": [
                    {
                        "name": "flask",
                        "version": "3.1.3",
                        "license_declared": "BSD-3-Clause",
                        "license_concluded": "BSD-3-Clause",
                        "download_location": "https://pypi.org/project/Flask/3.1.3/",
                        "copyright_text": "Copyright Pallets contributors",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    compliance_signature = tmp_path / "compliance-evidence.sig"
    compliance_signature.write_text(
        base64.b64encode(
            reviewer_private_key.sign(compliance_evidence.read_bytes())
        ).decode("ascii")
        + "\n",
        encoding="ascii",
    )
    (app / "DefenseTracker.exe").write_bytes(
        _mock_authenticode_sign(unsigned_executable)
    )
    installer_payload = tmp_path / "installer-payload"
    (installer_payload / "_internal").mkdir(parents=True)
    (installer_payload / "DefenseTracker.exe").write_bytes(
        (app / "DefenseTracker.exe").read_bytes()
    )
    (installer_payload / "_internal" / "version.json").write_bytes(
        (app / "_internal" / "version.json").read_bytes()
    )
    signed_application_inventory = tmp_path / "signed-application-inventory.json"
    signed_application_inventory.write_text(
        json.dumps(
            {
                "schema": 1,
                "files": [
                    {
                        "path": path.relative_to(installer_payload).as_posix(),
                        "bytes": path.stat().st_size,
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    }
                    for path in sorted(installer_payload.rglob("*"))
                    if path.is_file()
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    iss = tmp_path / "DefenseTracker.iss"
    iss.write_text("[Setup]\nAppName=DefenseTracker\n", encoding="utf-8")
    iscc = tmp_path / "ISCC.exe"
    iscc.write_bytes(b"pinned synthetic ISCC")
    seven_zip = tmp_path / "7z.exe"
    seven_zip.write_bytes(b"pinned synthetic 7-Zip")
    inno_license = tmp_path / "INNO-LICENSE.txt"
    inno_license.write_text(
        "Synthetic Inno license fixture for release-chain tests.\n",
        encoding="utf-8",
        newline="\n",
    )
    installer_request = generate_installer_review_request(
        unsigned_installer=installer,
        extracted_payload_root=installer_payload,
        signed_application_inventory=signed_application_inventory,
        iss_path=iss,
        iscc_path=iscc,
        iscc_version="Inno Setup synthetic 1.0",
        seven_zip_path=seven_zip,
        seven_zip_version="7-Zip synthetic 1.0",
        bootstrap_license_declared="LicenseRef-Inno-Setup",
        bootstrap_license_concluded="LicenseRef-Inno-Setup",
        bootstrap_copyright_text="Copyright Synthetic Inno Authors",
        bootstrap_license_text_path=inno_license,
        release_commit=COMMIT,
        source_tree=TREE,
        version=PRODUCT_VERSION.semantic_version,
        publisher="Example Legal Publisher",
    )
    installer_reviewer_private_key = Ed25519PrivateKey.generate()
    installer_reviewer_public_key = (
        installer_reviewer_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    installer_reviewer_registry = tmp_path / "installer-reviewers.json"
    write_canonical_json(
        installer_reviewer_registry,
        {
            "schema": 1,
            "status": "active",
            "scope": INSTALLER_REVIEW_SCOPE,
            "reviewers": [
                {
                    "key_id": "installer-reviewer-2026",
                    "organization": "Example Independent Installer Reviewer",
                    "public_key_base64": base64.b64encode(
                        installer_reviewer_public_key
                    ).decode("ascii"),
                    "public_key_sha256": hashlib.sha256(
                        installer_reviewer_public_key
                    ).hexdigest(),
                    "allowed_publishers": ["Example Legal Publisher"],
                    "scope": INSTALLER_REVIEW_SCOPE,
                }
            ],
        },
    )
    installer_request_bytes = canonical_json_bytes(installer_request)
    installer_review_evidence = tmp_path / "installer-review-evidence.json"
    write_canonical_json(
        installer_review_evidence,
        {
            "schema": 1,
            "kind": APPROVAL_KIND,
            "request_sha256": hashlib.sha256(installer_request_bytes).hexdigest(),
            "request_base64": base64.b64encode(installer_request_bytes).decode(
                "ascii"
            ),
            "decision": "approved",
            "scope": INSTALLER_REVIEW_SCOPE,
            "reviewer_key_id": "installer-reviewer-2026",
            "reviewer_organization": "Example Independent Installer Reviewer",
            "review_reference": "installer-review:V9-2026-001",
            "reviewed_at_utc": "2026-08-27T23:59:59Z",
        },
    )
    installer_review_signature = tmp_path / "installer-review-evidence.sig"
    installer_review_signature.write_text(
        base64.b64encode(
            installer_reviewer_private_key.sign(
                installer_review_evidence.read_bytes()
            )
        ).decode("ascii")
        + "\n",
        encoding="ascii",
    )
    signed_installer = tmp_path / "signed-installer.exe"
    signed_installer.write_bytes(_mock_authenticode_sign(unsigned_installer_bytes))
    approved_output = tmp_path / "approved-assets"
    approved_args = argparse.Namespace(
        **{
            **vars(args),
            "output_dir": approved_output,
            "installer": signed_installer,
            "compliance_evidence": compliance_evidence,
            "compliance_evidence_sha256": hashlib.sha256(
                compliance_evidence.read_bytes()
            ).hexdigest(),
            "compliance_signature": compliance_signature,
            "compliance_reviewer_registry": reviewer_registry,
            "component_inventory": component_inventory,
            "application_signer_subject": "CN=Example Legal Publisher",
            "application_timestamp_subject": "CN=Example Timestamp",
            "installer_review_evidence": installer_review_evidence,
            "installer_review_signature": installer_review_signature,
            "installer_reviewer_registry": installer_reviewer_registry,
            "installer_review_evidence_sha256": hashlib.sha256(
                installer_review_evidence.read_bytes()
            ).hexdigest(),
            "unsigned_installer": installer,
            "installer_payload_root": installer_payload,
            "signed_application_inventory": signed_application_inventory,
            "iss": iss,
            "iscc": iscc,
            "iscc_version": "Inno Setup synthetic 1.0",
            "seven_zip": seven_zip,
            "seven_zip_version": "7-Zip synthetic 1.0",
            "bootstrap_license_declared": "LicenseRef-Inno-Setup",
            "bootstrap_license_concluded": "LicenseRef-Inno-Setup",
            "bootstrap_copyright_text": "Copyright Synthetic Inno Authors",
            "bootstrap_license_text": inno_license,
        }
    )
    package_assets(approved_args)
    finalize_release_assets(
        approved_output,
        expected_commit=COMMIT,
        completed_at_utc="2026-08-28T00:00:03Z",
        portable_exe_sha256=hashlib.sha256(
            (app / "DefenseTracker.exe").read_bytes()
        ).hexdigest(),
    )
    verify_release_assets(
        approved_output,
        expected_commit=COMMIT,
        reviewer_registry=reviewer_registry,
        installer_reviewer_registry=installer_reviewer_registry,
    )
    approved_manifest = json.loads(
        (approved_output / "release-manifest.json").read_text()
    )
    assert approved_manifest["compliance"]["evidence_sha256"] == hashlib.sha256(
        compliance_evidence.read_bytes()
    ).hexdigest()
    approved_sbom = json.loads(
        (approved_output / "DefenseTracker-v9.0.0.spdx.json").read_text()
    )
    assert "NOASSERTION" not in json.dumps(approved_sbom)
    assert len(approved_sbom["files"]) == len(approved_manifest["portable_contents"])

    signed_executable = (app / "DefenseTracker.exe").read_bytes()
    tampered_executable = bytearray(signed_executable)
    tampered_executable[0x200] ^= 0x01
    (app / "DefenseTracker.exe").write_bytes(tampered_executable)
    tampered_args = argparse.Namespace(
        **{
            **vars(approved_args),
            "output_dir": tmp_path / "tampered-assets",
        }
    )
    with pytest.raises(ValueError, match="outside Authenticode fields"):
        package_assets(tampered_args)
    (app / "DefenseTracker.exe").write_bytes(signed_executable)

    invalid_payload = json.loads(compliance_evidence.read_text(encoding="utf-8"))
    invalid_payload["packages"][0]["license_declared"] = "Definitely approved"
    invalid_evidence = tmp_path / "invalid-compliance-evidence.json"
    invalid_evidence.write_text(json.dumps(invalid_payload), encoding="utf-8")
    invalid_signature = tmp_path / "invalid-compliance-evidence.sig"
    invalid_signature.write_text(
        base64.b64encode(reviewer_private_key.sign(invalid_evidence.read_bytes())).decode(
            "ascii"
        ),
        encoding="ascii",
    )
    invalid_args = argparse.Namespace(
        **{
            **vars(args),
            "output_dir": tmp_path / "invalid-assets",
            "compliance_evidence": invalid_evidence,
            "compliance_evidence_sha256": hashlib.sha256(
                invalid_evidence.read_bytes()
            ).hexdigest(),
            "compliance_signature": invalid_signature,
            "compliance_reviewer_registry": reviewer_registry,
            "component_inventory": component_inventory,
        }
    )
    with pytest.raises(ValueError, match="package license is invalid"):
        package_assets(invalid_args)


def test_release_workflows_are_manual_exact_sha_and_fail_closed():
    candidate = (ROOT / ".github/workflows/v9-signed-candidate.yml").read_text()
    release = (ROOT / ".github/workflows/v9-stable-release.yml").read_text()
    deployment = (ROOT / ".github/workflows/v9-deployment-evidence.yml").read_text()
    assert "workflow_dispatch" in candidate and "workflow_dispatch" in release
    assert "-RequireSignedInstaller" in candidate
    assert "-CandidateOnly" in candidate
    assert "dist/candidates/v9.0.0/" in candidate
    assert "dist/releases/v9.0.0/" not in candidate
    assert "v9-trusted-signing" in candidate
    assert "v9-deployment-evidence.yml" in release
    assert "immutable-releases" in release
    assert "actions/attest@" in release
    assert "defense-v9-candidate-ephemeral" in candidate
    assert "defense-v9-stable-ephemeral" in release
    assert "DEFENSE_TRACKER_EPHEMERAL_RUNNER_MODE" in candidate
    assert "DEFENSE_TRACKER_COMPLIANCE_EVIDENCE" in candidate
    assert "DEFENSE_TRACKER_COMPLIANCE_SIGNATURE" in candidate
    assert "DEFENSE_TRACKER_COMPLIANCE_EVIDENCE_SHA256" in candidate
    assert "DEFENSE_TRACKER_EPHEMERAL_RUNNER_MODE" in release
    assert candidate.index("Attest candidate build provenance") < candidate.index(
        "Retain candidate"
    )
    assert release.index("Verify candidate provenance") < release.index(
        "Generate SLSA provenance"
    )
    for source_binding in (
        "--signer-workflow",
        "--source-ref refs/heads/main",
        "--source-digest $env:RELEASE_SHA",
    ):
        assert source_binding in release
    assert "$candidate.head_branch -ne 'main'" in release
    assert release.index("verify_release_assets.py") < release.index("gh release create")
    assert release.index("immutable-releases") < release.index("gh release create")
    assert release.index("git ls-remote --tags origin") < release.index("gh release create")
    assert release.count("git ls-remote --tags origin") >= 2
    for workflow in (candidate, release, deployment):
        lines = workflow.splitlines()
        run_blocks: list[str] = []
        for index, line in enumerate(lines):
            match = re.match(r"^(\s*)run:\s*\|\s*$", line)
            if match is None:
                continue
            indent = len(match.group(1))
            block: list[str] = []
            for candidate_line in lines[index + 1 :]:
                if candidate_line.strip() and len(candidate_line) - len(candidate_line.lstrip()) <= indent:
                    break
                block.append(candidate_line)
            run_blocks.append("\n".join(block))
        assert run_blocks
        assert all("${{ inputs." not in block for block in run_blocks)
    assert "^[0-9a-f]{40}$" in candidate
    assert "^[0-9a-f]{40}$" in release
    assert "^[0-9a-f]{40}$" in deployment
    assert "^[1-9][0-9]{0,19}$" in release
    assert "^[1-9][0-9]{0,19}$" in deployment
    assert "STAGING_ORIGIN: ${{ inputs.staging_origin }}" in deployment
    assert "PRODUCTION_ORIGIN: ${{ inputs.production_origin }}" in deployment
    assert "origin_pattern='^https://" in deployment
    assert "runs-on: ubuntu-24.04" in deployment
    assert "if: github.ref == 'refs/heads/main'" in deployment
    assert "git ls-remote --exit-code origin refs/heads/main" in deployment
    assert "probe-origin-isolation.py" in deployment
    assert "DEFENSE_TRACKER_STAGING_ORIGIN_TARGET: ${{ secrets." in deployment
    assert "DEFENSE_TRACKER_PRODUCTION_ORIGIN_TARGET: ${{ secrets." in deployment
    assert "DEFENSE_TRACKER_ORIGIN_EVIDENCE_HMAC_KEY: ${{ secrets." in deployment
    assert "--seal-origin-isolation" in deployment
    assert "--expected-staging-origin \"${STAGING_ORIGIN}\"" in deployment
    assert "--expected-production-origin \"${PRODUCTION_ORIGIN}\"" in deployment
    for evidence_file in PAYLOAD_FILES | {"deployment-evidence.json"}:
        assert evidence_file in deployment
    assert "backup-restore-redacted.log" not in deployment
    assert ".png" not in deployment.lower()


def test_compliance_reviewer_registry_is_fail_closed_until_legal_activation():
    registry = json.loads(
        (ROOT / "release" / "compliance-reviewers.json").read_text(encoding="utf-8")
    )
    assert registry == {"schema": 1, "status": "inactive", "reviewers": []}


def test_hash_locks_and_installers_require_hashes():
    for relative in (
        "requirements.runtime.lock",
        "requirements.build.lock",
        "requirements.bootstrap.lock",
        "deploy/requirements.cloud.txt",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        pins = re.findall(r"(?m)^[A-Za-z0-9_.-]+==[^\s\\]+", source)
        assert pins
        assert source.count("--hash=sha256:") >= len(pins)
    assert "--require-hashes" in (ROOT / "scripts/Prepare-BuildEnv.ps1").read_text()
    prepare = (ROOT / "scripts/Prepare-BuildEnv.ps1").read_text()
    gate = (ROOT / "scripts/Build-AndShip.ps1").read_text(encoding="utf-8")
    assert "RequireExpectedPythonHash" in prepare
    for variable in (
        "DEFENSE_TRACKER_BUILD_PYTHON_SHA256",
        "DEFENSE_TRACKER_SIGNTOOL_SHA256",
        "DEFENSE_TRACKER_ISCC_SHA256",
        "DEFENSE_TRACKER_7ZIP_SHA256",
        "DEFENSE_TRACKER_DEFENDER_SHA256",
        "DEFENSE_TRACKER_AZURE_SIGNING_DLIB_SHA256",
        "DEFENSE_TRACKER_AZURE_SIGNING_METADATA_SHA256",
    ):
        assert variable in (prepare + gate + (ROOT / ".github/workflows/v9-signed-candidate.yml").read_text())
    assert "--require-hashes" in (ROOT / "deploy/mvp/portal.Dockerfile").read_text()


def test_required_check_gate_rejects_any_non_success():
    successful = [
        {
            "name": name,
            "status": "completed",
            "conclusion": "success",
            "app": {"id": GITHUB_ACTIONS_APP_ID, "slug": "github-actions"},
            "details_url": "https://github.com/owner/repo/actions/runs/123/job/456",
            "check_suite": {"id": 789},
        }
        for name in REQUIRED_CHECKS
    ]
    assert verify_checks(successful, repository="owner/repo") == 123
    successful[0]["conclusion"] = "failure"
    with pytest.raises(ValueError, match="not green"):
        verify_checks(successful, repository="owner/repo")


def test_required_check_gate_rejects_spoofed_or_mixed_sources():
    successful = [
        {
            "name": name,
            "status": "completed",
            "conclusion": "success",
            "app": {"id": GITHUB_ACTIONS_APP_ID, "slug": "github-actions"},
            "details_url": "https://github.com/owner/repo/actions/runs/123/job/456",
            "check_suite": {"id": 789},
        }
        for name in REQUIRED_CHECKS
    ]
    successful[0]["app"] = {"id": 999, "slug": "third-party-checks"}
    with pytest.raises(ValueError, match="untrusted publisher"):
        verify_checks(successful, repository="owner/repo")
    successful[0]["app"] = {"id": GITHUB_ACTIONS_APP_ID, "slug": "github-actions"}
    successful[0]["details_url"] = "https://github.com/owner/repo/actions/runs/124/job/456"
    with pytest.raises(ValueError, match="one workflow run"):
        verify_checks(successful, repository="owner/repo")
    successful[0]["details_url"] = "https://github.com/owner/repo/actions/runs/123/job/456"
    successful.append(dict(successful[0]))
    with pytest.raises(ValueError, match="duplicates"):
        verify_checks(successful, repository="owner/repo")


def test_required_ci_workflow_run_is_exact_main_push():
    workflow = {
        "id": 123,
        "head_sha": COMMIT,
        "head_branch": "main",
        "path": ".github/workflows/ci.yml",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": "owner/repo"},
    }
    verify_workflow_run(workflow, repository="owner/repo", sha=COMMIT, run_id=123)
    workflow["path"] = ".github/workflows/spoof.yml"
    with pytest.raises(ValueError, match="provenance mismatch"):
        verify_workflow_run(workflow, repository="owner/repo", sha=COMMIT, run_id=123)


def test_deployment_evidence_schema_3_binds_raw_evidence_and_recomputes_thresholds(tmp_path):
    _write_schema_3_evidence(tmp_path)
    verify_deployment_evidence(
        tmp_path,
        expected_commit=COMMIT,
        expected_image_digest=IMAGE_DIGEST,
        expected_candidate_run_id=123,
        expected_staging_origin=STAGING_ORIGIN,
        expected_production_origin=PRODUCTION_ORIGIN,
    )
    # The stable workflow re-verifies the already bound artifact without
    # accepting a second pair of mutable origin inputs.
    verify_deployment_evidence(
        tmp_path,
        expected_commit=COMMIT,
        expected_image_digest=IMAGE_DIGEST,
        expected_candidate_run_id=123,
    )


def test_deployment_evidence_seals_legacy_manifest_without_publishing_screenshots(tmp_path):
    _write_schema_3_evidence(tmp_path)
    legacy = json.loads((tmp_path / "deployment-evidence.json").read_text(encoding="utf-8"))
    legacy["schema"] = 2
    legacy["artifacts"] = [
        {
            "path": name,
            "sha256": hashlib.sha256((tmp_path / name).read_bytes()).hexdigest(),
            "size_bytes": (tmp_path / name).stat().st_size,
        }
        for name in sorted(CORE_PAYLOAD_FILES)
    ]
    (tmp_path / "deployment-evidence.json").write_text(
        json.dumps(legacy, separators=(",", ":")), encoding="utf-8"
    )
    seal_origin_isolation(tmp_path)
    assert json.loads(
        (tmp_path / "deployment-evidence.json").read_text(encoding="utf-8")
    )["schema"] == 3
    assert not any(path.suffix.lower() == ".png" for path in tmp_path.iterdir())
    verify_deployment_evidence(
        tmp_path,
        expected_commit=COMMIT,
        expected_image_digest=IMAGE_DIGEST,
        expected_candidate_run_id=123,
    )


def test_deployment_evidence_rejects_self_asserted_or_stale_origin_isolation(tmp_path):
    generated = _write_schema_3_evidence(tmp_path)
    isolation_path = tmp_path / "origin-isolation.json"
    isolation = json.loads(isolation_path.read_text(encoding="utf-8"))
    isolation["gates"][0]["status"] = "fail"
    isolation_path.write_text(json.dumps(isolation), encoding="utf-8")
    _refresh_evidence_manifest(tmp_path, generated)
    with pytest.raises(ValueError, match="gate did not pass"):
        verify_deployment_evidence(
            tmp_path,
            expected_commit=COMMIT,
            expected_image_digest=IMAGE_DIGEST,
            expected_candidate_run_id=123,
        )

    stale_root = tmp_path / "stale"
    stale_root.mkdir()
    stale_generated = _write_schema_3_evidence(stale_root)
    stale_path = stale_root / "origin-isolation.json"
    stale = json.loads(stale_path.read_text(encoding="utf-8"))
    for gate in stale["gates"]:
        gate["observed_at_utc"] = _utc(
            datetime.now(timezone.utc) - timedelta(hours=1)
        )
    stale_path.write_text(json.dumps(stale), encoding="utf-8")
    _refresh_evidence_manifest(stale_root, stale_generated)
    with pytest.raises(ValueError, match="stale or in the future"):
        verify_deployment_evidence(
            stale_root,
            expected_commit=COMMIT,
            expected_image_digest=IMAGE_DIGEST,
            expected_candidate_run_id=123,
        )


def test_deployment_evidence_rejects_short_observation_and_wrong_origin(tmp_path):
    _write_schema_3_evidence(tmp_path, staging_hours=23)
    with pytest.raises(ValueError, match="24 hours"):
        verify_deployment_evidence(
            tmp_path,
            expected_commit=COMMIT,
            expected_image_digest=IMAGE_DIGEST,
            expected_candidate_run_id=123,
        )
    _write_schema_3_evidence(tmp_path)
    with pytest.raises(ValueError, match="staging origin mismatch"):
        verify_deployment_evidence(
            tmp_path,
            expected_commit=COMMIT,
            expected_image_digest=IMAGE_DIGEST,
            expected_candidate_run_id=123,
            expected_staging_origin="https://other.defense-tracker.example",
        )


def test_deployment_evidence_rejects_tampering_png_and_pass_text(tmp_path):
    _write_schema_3_evidence(tmp_path)
    (tmp_path / "production-probe.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="artifact (digest|size) mismatch"):
        verify_deployment_evidence(
            tmp_path,
            expected_commit=COMMIT,
            expected_image_digest=IMAGE_DIGEST,
            expected_candidate_run_id=123,
        )

    png_root = tmp_path / "png-extra"
    png_root.mkdir()
    _write_schema_3_evidence(png_root)
    (png_root / "production-mobile-redacted.png").write_bytes(b"not-public-evidence")
    with pytest.raises(ValueError, match="PNG deployment evidence is forbidden"):
        verify_deployment_evidence(
            png_root,
            expected_commit=COMMIT,
            expected_image_digest=IMAGE_DIGEST,
            expected_candidate_run_id=123,
        )

    text_root = tmp_path / "pass-text"
    text_root.mkdir()
    generated = _write_schema_3_evidence(text_root)
    (text_root / "backup-restore.json").write_text("restore PASS\n", encoding="utf-8")
    _refresh_evidence_manifest(text_root, generated)
    with pytest.raises(ValueError, match="not valid UTF-8 JSON"):
        verify_deployment_evidence(
            text_root,
            expected_commit=COMMIT,
            expected_image_digest=IMAGE_DIGEST,
            expected_candidate_run_id=123,
        )


def test_deployment_evidence_rejects_schema_1_self_reported_booleans(tmp_path):
    _write_schema_3_evidence(tmp_path)
    (tmp_path / "deployment-evidence.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "release_commit": COMMIT,
                "candidate_run_id": 123,
                "portal_image_digest": IMAGE_DIGEST,
                "staging": {"accepted": True, "observed_hours": 24},
                "production": {"accepted": True},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="fields differ|schema is unsupported"):
        verify_deployment_evidence(
            tmp_path,
            expected_commit=COMMIT,
            expected_image_digest=IMAGE_DIGEST,
            expected_candidate_run_id=123,
        )


def test_deployment_evidence_rejects_duplicate_security_keys(tmp_path):
    _write_schema_3_evidence(tmp_path)
    manifest_path = tmp_path / "deployment-evidence.json"
    manifest = manifest_path.read_text(encoding="utf-8")
    manifest_path.write_text(
        manifest.replace('"schema":3', '"schema":3,"schema":3', 1),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate JSON key"):
        verify_deployment_evidence(
            tmp_path,
            expected_commit=COMMIT,
            expected_image_digest=IMAGE_DIGEST,
            expected_candidate_run_id=123,
        )
