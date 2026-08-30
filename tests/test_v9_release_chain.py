# -*- coding: utf-8 -*-
import argparse
import base64
import hashlib
import io
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
    PORTAL_CONTAINER_NAME,
    PROBE_RESULT_CODES,
    PROBE_ROUTE_SPECS,
    PRODUCTION_CHECKS,
    PUBLIC_METADATA_PATHS,
    STAGING_CHECKS,
    seal_origin_isolation as _seal_origin_isolation,
    verify as _verify_deployment_evidence,
)
from scripts.verify_release_assets import verify as verify_release_assets
from scripts.verify_release_checks import (
    EXPECTED_CODEQL_EVENT,
    EXPECTED_CODEQL_WORKFLOW_PATH,
    EXPECTED_REPOSITORY,
    GITHUB_ACTIONS_APP_ID,
    REQUIRED_CHECKS,
    REQUIRED_CI_CHECKS,
    REQUIRED_CODEQL_CHECKS,
    load_check_runs,
    load_workflow_run,
    verify as verify_checks,
    verify_workflow_run,
)


ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
TREE = "b" * 40
IMAGE_DIGEST = "sha256:" + "c" * 64
STAGING_ORIGIN = "https://staging.defense-tracker.example"
PRODUCTION_ORIGIN = "https://portal.defense-tracker.example"
DEPLOYMENT_COLLECTOR_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(
    hashlib.sha256(b"test deployment collector key").digest()
)
DEPLOYMENT_COLLECTOR_PUBLIC_KEY = DEPLOYMENT_COLLECTOR_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
DEPLOYMENT_COLLECTOR_PUBLIC_KEY_SHA256 = hashlib.sha256(
    DEPLOYMENT_COLLECTOR_PUBLIC_KEY
).hexdigest()
DEPLOYMENT_COLLECTOR_KEY_ID = (
    f"deployment-collector-{DEPLOYMENT_COLLECTOR_PUBLIC_KEY_SHA256[:16]}"
)


def seal_origin_isolation(root: Path) -> None:
    _seal_origin_isolation(
        root,
        expected_collector_key_id=DEPLOYMENT_COLLECTOR_KEY_ID,
        expected_collector_public_key_sha256=DEPLOYMENT_COLLECTOR_PUBLIC_KEY_SHA256,
    )


def verify_deployment_evidence(root: Path, **kwargs) -> None:
    _verify_deployment_evidence(
        root,
        expected_collector_key_id=DEPLOYMENT_COLLECTOR_KEY_ID,
        expected_collector_public_key_sha256=DEPLOYMENT_COLLECTOR_PUBLIC_KEY_SHA256,
        **kwargs,
    )


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
        "schema": 3,
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
        "challenge_sha256": _digest(f"{environment}-probe-challenge"),
        "runtime_portal": {
            "environment": environment,
            "origin": origin,
            "container_name": PORTAL_CONTAINER_NAME,
            "image_reference": f"ghcr.io/example/portal@{IMAGE_DIGEST}",
            "image_digest": IMAGE_DIGEST,
            "image_id": "sha256:" + _digest(f"{environment}-image-config"),
            "release_commit": COMMIT,
            "wire_compatibility": "mvp-wire-v1",
            "state": "healthy",
        },
        "public_metadata": [
            {
                "name": name,
                "method": "GET",
                "url": f"{origin}{path}",
                "status_code": 200,
                "elapsed_ms": 50 + index,
                "observed_at_utc": _utc(started + timedelta(seconds=index + 1)),
                "response_sha256": _digest(f"{environment}-public-{name}"),
            }
            for index, (name, path) in enumerate(PUBLIC_METADATA_PATHS.items())
        ],
        "checks": [
            {
                "name": name,
                "method": PROBE_ROUTE_SPECS[name]["method"],
                "url": f"{origin}{PROBE_ROUTE_SPECS[name]['path']}",
                "status_code": status,
                "elapsed_ms": 100 + index,
                "observed_at_utc": _utc(started + timedelta(seconds=index + 1)),
                "response_sha256": _digest(f"{environment}-{name}"),
                "result_code": PROBE_RESULT_CODES[name],
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
                    "schema": 3,
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
                    "data_device_sha256": _digest(f"{environment}-data-device"),
                    "backup_receipt_sha256": _digest(
                        f"{environment}-backup-receipt-{index}"
                    ),
                    "response_sha256": _digest(f"{environment}-sample-{index}"),
                    "challenge_sha256": _digest(
                        f"{environment}-sample-challenge-{index}"
                    ),
                    "semantic_code": "PUBLIC_HEALTH_OK",
                },
                separators=(",", ":"),
            )
        )
    return "\n".join(records) + "\n"


def _refresh_evidence_manifest(root: Path, generated: datetime) -> None:
    core_artifacts = [
        {
            "path": name,
            "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest(),
            "size_bytes": (root / name).stat().st_size,
        }
        for name in sorted(CORE_PAYLOAD_FILES)
    ]
    public_key = DEPLOYMENT_COLLECTOR_PUBLIC_KEY
    public_key_sha256 = DEPLOYMENT_COLLECTOR_PUBLIC_KEY_SHA256
    receipt = {
        "schema": 1,
        "key_id": f"deployment-collector-{public_key_sha256[:16]}",
        "public_key_base64": base64.b64encode(public_key).decode("ascii"),
        "public_key_sha256": public_key_sha256,
        "release_commit": COMMIT,
        "candidate_run_id": 123,
        "portal_image_digest": IMAGE_DIGEST,
        "staging_origin": STAGING_ORIGIN,
        "production_origin": PRODUCTION_ORIGIN,
        "generated_at_utc": _utc(generated),
        "artifacts": core_artifacts,
    }
    signature = DEPLOYMENT_COLLECTOR_PRIVATE_KEY.sign(
        (
            json.dumps(
                receipt,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    )
    receipt["signature_base64"] = base64.b64encode(signature).decode("ascii")
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
        "collector_receipt": receipt,
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
            count=26,
            spacing=timedelta(hours=staging_hours / 25),
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
    assert "if: github.ref == 'refs/heads/main'" in release
    assert "ref: ${{ github.sha }}" in release
    assert "ref: ${{ inputs.release_sha }}" not in release
    assert "portal_image_run_id:" in release
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
    assert deployment.count("ref: ${{ github.sha }}") == 3
    assert "ref: ${{ inputs.release_sha }}" not in deployment
    assert "git ls-remote --exit-code origin refs/heads/main" in deployment
    assert "probe-origin-isolation.py" in deployment
    assert "DEFENSE_TRACKER_STAGING_ORIGIN_TARGET: ${{ secrets." in deployment
    assert "DEFENSE_TRACKER_PRODUCTION_ORIGIN_TARGET: ${{ secrets." in deployment
    assert "DEFENSE_TRACKER_ORIGIN_EVIDENCE_HMAC_KEY: ${{ secrets." in deployment
    assert "--seal-origin-isolation" in deployment
    collect_job = deployment.split("  collect-live-evidence:", 1)[1].split(
        "  seal-live-evidence:", 1
    )[0]
    seal_job = deployment.split("  seal-live-evidence:", 1)[1]
    assert "needs: verify-origin-isolation" in collect_job
    assert "runs-on: [self-hosted, Linux, X64, defense-deploy-auditor]" in collect_job
    assert "COLLECTOR_KEY_ID" not in collect_job
    assert "COLLECTOR_PUBLIC_KEY_SHA256" not in collect_job
    assert "id-token: write" not in collect_job
    assert "runs-on: ubuntu-24.04" in seal_job
    assert "--expected-collector-key-id" in seal_job
    assert "--expected-collector-public-key-sha256" in seal_job
    assert "actions/attest@" in seal_job
    assert "--require-hashes" in seal_job
    assert "requirements.deployment-evidence.lock" in seal_job
    assert seal_job.index("--seal-origin-isolation") < seal_job.index("actions/attest@")
    assert seal_job.index("actions/attest@") < seal_job.index(
        "name: v9-deployment-evidence-${{ inputs.release_sha }}"
    )
    assert "DEFENSE_TRACKER_DEPLOYMENT_COLLECTOR_KEY_ID" in release
    assert "DEFENSE_TRACKER_DEPLOYMENT_COLLECTOR_PUBLIC_KEY_SHA256" in release
    assert "DEFENSE_TRACKER_STAGING_ORIGIN" in release
    assert "DEFENSE_TRACKER_PRODUCTION_ORIGIN" in release
    assert "PORTAL_IMAGE_RUN_ID" in release
    assert "--expected-collector-key-id" in release
    assert "--expected-collector-public-key-sha256" in release
    assert "--expected-staging-origin $env:DEPLOYMENT_STAGING_ORIGIN" in release
    assert "--expected-production-origin $env:DEPLOYMENT_PRODUCTION_ORIGIN" in release
    assert "$portalImage.path -ne '.github/workflows/v9-portal-image.yml'" in release
    assert "v9-portal-image-${{ inputs.release_sha }}-${{ inputs.portal_image_run_id }}" in release
    assert "Portal image receipt does not bind the approved run, commit and digest" in release
    assert 'gh attestation verify "oci://$expectedReference"' in release
    assert ".github/workflows/v9-portal-image.yml" in release
    assert "--bundle-from-oci" in release
    assert "--deny-self-hosted-runners" in release
    assert "packages: read" in release
    assert (
        '$signerWorkflow = "$env:GITHUB_REPOSITORY/.github/workflows/v9-deployment-evidence.yml"'
        in release
    )
    assert release.count("gh attestation verify $_.FullName") >= 3
    assert "--expected-staging-origin \"${STAGING_ORIGIN}\"" in deployment
    assert "--expected-production-origin \"${PRODUCTION_ORIGIN}\"" in deployment
    for evidence_file in PAYLOAD_FILES | {"deployment-evidence.json"}:
        assert evidence_file in deployment
    assert "backup-restore-redacted.log" not in deployment
    assert ".png" not in deployment.lower()


def test_ci_pins_actionlint_and_validates_all_workflows():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()

    assert 'ACTIONLINT_VERSION: "1.7.12"' in workflow
    assert (
        'ACTIONLINT_LINUX_X64_SHA256: '
        '"8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"'
        in workflow
    )
    assert "sha256sum --check --strict" in workflow
    assert '"$tool_dir/actionlint" -no-color -shellcheck= -pyflakes=' in workflow


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
        "requirements.deployment-evidence.lock",
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


def test_deployment_evidence_lock_uses_audited_cryptography_release():
    lock = (ROOT / "requirements.deployment-evidence.lock").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/v9-deployment-evidence.yml").read_text(
        encoding="utf-8"
    )
    assert re.search(r"(?m)^cryptography==50\.0\.1 \\$", lock)
    assert "cryptography==46.0.5" not in lock
    assert "ff838d62ec1bfce4f9ba7fa16f4a7b554cd8d0c299e6be37502161a660c84eef" in lock
    assert 'importlib.metadata.version("cryptography")' in workflow
    assert '= "50.0.1"' in workflow
    assert "python -m pip check" in workflow


def _required_check_suite(run_id, suite_id, names):
    return [
        {
            "name": name,
            "status": "completed",
            "conclusion": "success",
            "app": {"id": GITHUB_ACTIONS_APP_ID, "slug": "github-actions"},
            "details_url": (
                f"https://github.com/{EXPECTED_REPOSITORY}/actions/runs/{run_id}/job/456"
            ),
            "check_suite": {"id": suite_id},
        }
        for name in names
    ]


def _required_ci_check_suite(run_id, suite_id):
    return _required_check_suite(run_id, suite_id, REQUIRED_CI_CHECKS)


def _required_codeql_check_suite(run_id, suite_id):
    return _required_check_suite(run_id, suite_id, REQUIRED_CODEQL_CHECKS)


def _required_ci_workflow_run(run_id, suite_id, **overrides):
    workflow = {
        "id": run_id,
        "check_suite_id": suite_id,
        "head_sha": COMMIT,
        "head_branch": "main",
        "path": ".github/workflows/ci.yml",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": EXPECTED_REPOSITORY},
    }
    workflow.update(overrides)
    return workflow


def _required_codeql_workflow_run(run_id, suite_id, **overrides):
    workflow = _required_ci_workflow_run(
        run_id,
        suite_id,
        path=EXPECTED_CODEQL_WORKFLOW_PATH,
        event=EXPECTED_CODEQL_EVENT,
    )
    workflow.update(overrides)
    return workflow


def test_required_check_loader_fetches_every_reported_page(monkeypatch):
    payloads = iter(
        [
            {
                "total_count": 101,
                "check_runs": [{"id": value} for value in range(1, 101)],
            },
            {"total_count": 101, "check_runs": [{"id": 101}]},
        ]
    )
    requested_urls = []

    def fake_urlopen(request, timeout):
        assert timeout == 30
        requested_urls.append(request.full_url)
        return io.BytesIO(json.dumps(next(payloads)).encode("utf-8"))

    monkeypatch.setattr(
        "scripts.verify_release_checks.urllib.request.urlopen", fake_urlopen
    )

    check_runs = load_check_runs(EXPECTED_REPOSITORY, COMMIT, "token")

    assert [run["id"] for run in check_runs] == list(range(1, 102))
    assert requested_urls[0].startswith(
        f"https://api.github.com/repos/{EXPECTED_REPOSITORY}/commits/main/check-runs"
    )
    assert requested_urls[0].endswith("filter=latest&page=1")
    assert requested_urls[1].endswith("filter=latest&page=2")


def test_required_check_loaders_refuse_any_other_repository_before_network(monkeypatch):
    def fail_urlopen(*_args, **_kwargs):
        raise AssertionError("untrusted repository reached the network")

    monkeypatch.setattr(
        "scripts.verify_release_checks.urllib.request.urlopen", fail_urlopen
    )

    with pytest.raises(ValueError, match="pinned public repository"):
        load_check_runs("attacker/fork", COMMIT, "token")
    with pytest.raises(ValueError, match="pinned public repository"):
        verify_checks(
            [],
            repository="attacker/fork",
            sha=COMMIT,
            workflow_run_loader=lambda _run_id: {},
        )
    with pytest.raises(ValueError, match="malformed"):
        load_check_runs(EXPECTED_REPOSITORY, COMMIT.upper(), "token")


def test_required_workflow_loader_uses_fixed_repository_url(monkeypatch):
    requested_urls = []

    def fake_urlopen(request, timeout):
        assert timeout == 30
        requested_urls.append(request.full_url)
        return io.BytesIO(b"{}")

    monkeypatch.setattr(
        "scripts.verify_release_checks.urllib.request.urlopen", fake_urlopen
    )

    assert load_workflow_run(EXPECTED_REPOSITORY, 123, "token") == {}
    assert requested_urls == [
        f"https://api.github.com/repos/{EXPECTED_REPOSITORY}/actions/runs/123"
    ]


@pytest.mark.parametrize(
    "second_page",
    [
        {"total_count": 102, "check_runs": [{"id": 101}]},
        {"total_count": 101, "check_runs": []},
    ],
)
def test_required_check_loader_rejects_changed_or_truncated_pagination(
    monkeypatch, second_page
):
    payloads = iter(
        [
            {
                "total_count": 101,
                "check_runs": [{"id": value} for value in range(1, 101)],
            },
            second_page,
        ]
    )

    def fake_urlopen(_request, timeout):
        assert timeout == 30
        return io.BytesIO(json.dumps(next(payloads)).encode("utf-8"))

    monkeypatch.setattr(
        "scripts.verify_release_checks.urllib.request.urlopen", fake_urlopen
    )

    with pytest.raises(ValueError, match="pagination"):
        load_check_runs(EXPECTED_REPOSITORY, COMMIT, "token")


def test_required_check_gate_rejects_any_non_success():
    successful = _required_ci_check_suite(123, 789) + _required_codeql_check_suite(
        223, 889
    )
    workflow_runs = {
        123: _required_ci_workflow_run(123, 789),
        223: _required_codeql_workflow_run(223, 889),
    }
    assert (
        verify_checks(
            successful,
            repository=EXPECTED_REPOSITORY,
            sha=COMMIT,
            workflow_run_loader=workflow_runs.__getitem__,
        )
        == 123
    )
    successful[0]["conclusion"] = "failure"
    with pytest.raises(ValueError, match="not green"):
        verify_checks(
            successful,
            repository=EXPECTED_REPOSITORY,
            sha=COMMIT,
            workflow_run_loader=workflow_runs.__getitem__,
        )


def test_required_check_gate_rejects_spoofed_or_mixed_sources():
    successful = _required_ci_check_suite(123, 789) + _required_codeql_check_suite(
        223, 889
    )
    successful[0]["app"] = {"id": 999, "slug": "third-party-checks"}
    with pytest.raises(ValueError, match="untrusted publisher"):
        verify_checks(
            successful,
            repository=EXPECTED_REPOSITORY,
            sha=COMMIT,
            workflow_run_loader={
                123: _required_ci_workflow_run(123, 789),
                223: _required_codeql_workflow_run(223, 889),
            }.__getitem__,
        )
    successful[0]["app"] = {"id": GITHUB_ACTIONS_APP_ID, "slug": "github-actions"}
    successful[0]["details_url"] = (
        f"https://github.com/{EXPECTED_REPOSITORY}/actions/runs/124/job/456"
    )
    with pytest.raises(ValueError, match="missing"):
        verify_checks(
            successful,
            repository=EXPECTED_REPOSITORY,
            sha=COMMIT,
            workflow_run_loader={
                123: _required_ci_workflow_run(123, 789),
                124: _required_ci_workflow_run(124, 789, event="workflow_dispatch"),
                223: _required_codeql_workflow_run(223, 889),
            }.__getitem__,
        )
    successful[0]["details_url"] = (
        f"https://github.com/{EXPECTED_REPOSITORY}/actions/runs/123/job/456"
    )
    successful.append(dict(successful[0]))
    with pytest.raises(ValueError, match="duplicates"):
        verify_checks(
            successful,
            repository=EXPECTED_REPOSITORY,
            sha=COMMIT,
            workflow_run_loader={
                123: _required_ci_workflow_run(123, 789),
                223: _required_codeql_workflow_run(223, 889),
            }.__getitem__,
        )


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"repository": EXPECTED_REPOSITORY},
        {"repository": EXPECTED_REPOSITORY, "sha": COMMIT},
    ],
)
def test_required_check_gate_rejects_missing_provenance_inputs(kwargs):
    with pytest.raises(ValueError, match="required for provenance"):
        verify_checks([], **kwargs)


def test_required_check_gate_selects_exact_push_suite_among_duplicate_named_runs():
    check_runs = (
        _required_ci_check_suite(124, 790)
        + _required_ci_check_suite(125, 791)
        + _required_ci_check_suite(123, 789)
        + _required_codeql_check_suite(223, 889)
    )
    workflow_runs = {
        123: _required_ci_workflow_run(123, 789),
        124: _required_ci_workflow_run(124, 790, event="workflow_dispatch"),
        125: _required_ci_workflow_run(
            125, 791, event="workflow_dispatch", conclusion="cancelled"
        ),
        223: _required_codeql_workflow_run(223, 889),
    }

    assert (
        verify_checks(
            check_runs,
            repository=EXPECTED_REPOSITORY,
            sha=COMMIT,
            workflow_run_loader=workflow_runs.__getitem__,
        )
        == 123
    )


@pytest.mark.parametrize("invalid_shape", ["missing", "duplicate", "failure"])
def test_required_check_gate_rejects_invalid_selected_push_suite(invalid_shape):
    check_runs = _required_ci_check_suite(123, 789)
    if invalid_shape == "missing":
        check_runs.pop()
        expected_error = "missing"
    elif invalid_shape == "duplicate":
        check_runs.append(dict(check_runs[0]))
        expected_error = "duplicates"
    else:
        check_runs[0]["conclusion"] = "failure"
        expected_error = "failed"
    check_runs += _required_ci_check_suite(124, 790)
    check_runs += _required_codeql_check_suite(223, 889)
    workflow_runs = {
        123: _required_ci_workflow_run(123, 789),
        124: _required_ci_workflow_run(124, 790, event="workflow_dispatch"),
        223: _required_codeql_workflow_run(223, 889),
    }

    with pytest.raises(ValueError, match=expected_error):
        verify_checks(
            check_runs,
            repository=EXPECTED_REPOSITORY,
            sha=COMMIT,
            workflow_run_loader=workflow_runs.__getitem__,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event", "workflow_dispatch"),
        ("head_sha", "c" * 40),
        ("path", ".github/workflows/spoof.yml"),
        ("conclusion", "failure"),
        ("check_suite_id", 999),
    ],
)
def test_required_check_gate_rejects_wrong_workflow_provenance(field, value):
    workflow = _required_ci_workflow_run(123, 789)
    workflow[field] = value

    with pytest.raises(ValueError, match="exactly one successful push CI suite"):
        verify_checks(
            _required_ci_check_suite(123, 789)
            + _required_codeql_check_suite(223, 889),
            repository=EXPECTED_REPOSITORY,
            sha=COMMIT,
            workflow_run_loader={
                123: workflow,
                223: _required_codeql_workflow_run(223, 889),
            }.__getitem__,
        )


def test_required_check_gate_rejects_multiple_exact_push_suites():
    workflow_runs = {
        123: _required_ci_workflow_run(123, 789),
        124: _required_ci_workflow_run(124, 790),
        223: _required_codeql_workflow_run(223, 889),
    }

    with pytest.raises(ValueError, match="exactly one successful push CI suite"):
        verify_checks(
            _required_ci_check_suite(123, 789)
            + _required_ci_check_suite(124, 790)
            + _required_codeql_check_suite(223, 889),
            repository=EXPECTED_REPOSITORY,
            sha=COMMIT,
            workflow_run_loader=workflow_runs.__getitem__,
        )


def test_required_check_gate_matches_all_nine_protected_branch_checks():
    assert REQUIRED_CHECKS == {
        "Public tree policy",
        "JavaScript tests and reproducible bundles",
        "Supabase Edge Functions",
        "MVP deployment assets",
        "Python 3.11 (ubuntu-latest)",
        "Python 3.11 (windows-latest)",
        "Analyze (actions)",
        "Analyze (javascript-typescript)",
        "Analyze (python)",
    }
    assert REQUIRED_CI_CHECKS.isdisjoint(REQUIRED_CODEQL_CHECKS)


@pytest.mark.parametrize("invalid_shape", ["missing", "duplicate", "failure", "pending"])
def test_required_check_gate_rejects_invalid_codeql_suite(invalid_shape):
    codeql_runs = _required_codeql_check_suite(223, 889)
    if invalid_shape == "missing":
        codeql_runs.pop()
        expected_error = "missing"
    elif invalid_shape == "duplicate":
        codeql_runs.append(dict(codeql_runs[0]))
        expected_error = "duplicates"
    elif invalid_shape == "failure":
        codeql_runs[0]["conclusion"] = "failure"
        expected_error = "failed"
    else:
        codeql_runs[0]["status"] = "in_progress"
        codeql_runs[0]["conclusion"] = None
        expected_error = "failed"

    with pytest.raises(ValueError, match=expected_error):
        verify_checks(
            _required_ci_check_suite(123, 789) + codeql_runs,
            repository=EXPECTED_REPOSITORY,
            sha=COMMIT,
            workflow_run_loader={
                123: _required_ci_workflow_run(123, 789),
                223: _required_codeql_workflow_run(223, 889),
            }.__getitem__,
        )


def test_required_check_gate_rejects_all_codeql_checks_missing():
    with pytest.raises(ValueError, match="CodeQL.*found=0"):
        verify_checks(
            _required_ci_check_suite(123, 789),
            repository=EXPECTED_REPOSITORY,
            sha=COMMIT,
            workflow_run_loader={123: _required_ci_workflow_run(123, 789)}.__getitem__,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event", "push"),
        ("head_sha", "c" * 40),
        ("head_branch", "release"),
        ("path", ".github/workflows/codeql.yml"),
        ("status", "in_progress"),
        ("conclusion", "failure"),
        ("check_suite_id", 999),
    ],
)
def test_required_check_gate_rejects_wrong_codeql_provenance(field, value):
    codeql_workflow = _required_codeql_workflow_run(223, 889)
    codeql_workflow[field] = value

    with pytest.raises(ValueError, match="exactly one successful dynamic CodeQL suite"):
        verify_checks(
            _required_ci_check_suite(123, 789)
            + _required_codeql_check_suite(223, 889),
            repository=EXPECTED_REPOSITORY,
            sha=COMMIT,
            workflow_run_loader={
                123: _required_ci_workflow_run(123, 789),
                223: codeql_workflow,
            }.__getitem__,
        )


def test_required_check_gate_rejects_multiple_exact_codeql_suites():
    with pytest.raises(ValueError, match="exactly one successful dynamic CodeQL suite"):
        verify_checks(
            _required_ci_check_suite(123, 789)
            + _required_codeql_check_suite(223, 889)
            + _required_codeql_check_suite(224, 890),
            repository=EXPECTED_REPOSITORY,
            sha=COMMIT,
            workflow_run_loader={
                123: _required_ci_workflow_run(123, 789),
                223: _required_codeql_workflow_run(223, 889),
                224: _required_codeql_workflow_run(224, 890),
            }.__getitem__,
        )


def test_required_check_gate_rejects_cross_workflow_check_mixing():
    ci_runs = _required_ci_check_suite(123, 789)
    ci_runs.append(_required_codeql_check_suite(123, 789)[0])

    with pytest.raises(ValueError, match="another workflow"):
        verify_checks(
            ci_runs + _required_codeql_check_suite(223, 889),
            repository=EXPECTED_REPOSITORY,
            sha=COMMIT,
            workflow_run_loader={
                123: _required_ci_workflow_run(123, 789),
                223: _required_codeql_workflow_run(223, 889),
            }.__getitem__,
        )


def test_required_ci_workflow_run_is_exact_main_push():
    workflow = {
        "id": 123,
        "head_sha": COMMIT,
        "head_branch": "main",
        "path": ".github/workflows/ci.yml",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": EXPECTED_REPOSITORY},
    }
    verify_workflow_run(
        workflow, repository=EXPECTED_REPOSITORY, sha=COMMIT, run_id=123
    )
    workflow["path"] = ".github/workflows/spoof.yml"
    with pytest.raises(ValueError, match="provenance mismatch"):
        verify_workflow_run(
            workflow, repository=EXPECTED_REPOSITORY, sha=COMMIT, run_id=123
        )


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


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        (
            lambda probe: probe["checks"][0].update(
                {"result_code": "GENERIC_STATUS_OK"}
            ),
            "wrong semantic code",
        ),
        (
            lambda probe: probe["runtime_portal"].update(
                {"image_digest": "sha256:" + "0" * 64}
            ),
            "runtime Portal identity mismatch",
        ),
        (
            lambda probe: probe.update(
                {
                    "schema": 2,
                    "checks": [
                        {
                            key: value
                            for key, value in check.items()
                            if key != "result_code"
                        }
                        for check in probe["checks"]
                    ],
                }
            ),
            "schema or environment mismatch",
        ),
    ],
)
def test_signed_probe_still_rejects_generic_semantics_runtime_drift_or_legacy_schema(
    tmp_path, mutation, error
):
    generated = _write_schema_3_evidence(tmp_path)
    path = tmp_path / "staging-probe.json"
    probe = json.loads(path.read_text(encoding="utf-8"))
    mutation(probe)
    path.write_text(json.dumps(probe, separators=(",", ":")), encoding="utf-8")
    _refresh_evidence_manifest(tmp_path, generated)
    with pytest.raises(ValueError, match=error):
        verify_deployment_evidence(
            tmp_path,
            expected_commit=COMMIT,
            expected_image_digest=IMAGE_DIGEST,
            expected_candidate_run_id=123,
        )


def test_stable_verifier_rejects_old_probe_even_with_fresh_observations(tmp_path):
    generated = _write_schema_3_evidence(tmp_path)
    path = tmp_path / "staging-probe.json"
    probe = json.loads(path.read_text(encoding="utf-8"))
    started = generated - timedelta(hours=50)
    completed = started + timedelta(minutes=20)
    probe["started_at_utc"] = _utc(started)
    probe["completed_at_utc"] = _utc(completed)
    probe["tls"]["not_before_utc"] = _utc(started - timedelta(days=1))
    probe["tls"]["not_after_utc"] = _utc(generated + timedelta(days=1))
    for index, row in enumerate([*probe["public_metadata"], *probe["checks"]]):
        row["observed_at_utc"] = _utc(started + timedelta(seconds=index + 1))
    path.write_text(json.dumps(probe, separators=(",", ":")), encoding="utf-8")
    _refresh_evidence_manifest(tmp_path, generated)
    with pytest.raises(ValueError, match="Staging probe evidence is stale"):
        verify_deployment_evidence(
            tmp_path,
            expected_commit=COMMIT,
            expected_image_digest=IMAGE_DIGEST,
            expected_candidate_run_id=123,
        )


def test_stable_verifier_rejects_old_observations_even_with_fresh_probe(tmp_path):
    generated = _write_schema_3_evidence(tmp_path)
    path = tmp_path / "production-observations.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    started = generated - timedelta(minutes=50)
    for index, row in enumerate(rows):
        row["observed_at_utc"] = _utc(started + timedelta(seconds=index * 10))
    path.write_text(
        "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )
    _refresh_evidence_manifest(tmp_path, generated)
    with pytest.raises(ValueError, match="Production observation evidence is stale"):
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


def test_deployment_evidence_requires_pin_and_rejects_self_signed_schema2(tmp_path):
    _write_schema_3_evidence(tmp_path)
    with pytest.raises(ValueError, match="protected key pin is required"):
        _verify_deployment_evidence(
            tmp_path,
            expected_commit=COMMIT,
            expected_image_digest=IMAGE_DIGEST,
            expected_candidate_run_id=123,
        )

    manifest_path = tmp_path / "deployment-evidence.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["schema"] = 2
    manifest["artifacts"] = [
        {
            "path": name,
            "sha256": hashlib.sha256((tmp_path / name).read_bytes()).hexdigest(),
            "size_bytes": (tmp_path / name).stat().st_size,
        }
        for name in sorted(CORE_PAYLOAD_FILES)
    ]
    attacker = Ed25519PrivateKey.generate()
    attacker_public = attacker.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    receipt = manifest["collector_receipt"]
    attacker_digest = hashlib.sha256(attacker_public).hexdigest()
    receipt["key_id"] = f"deployment-collector-{attacker_digest[:16]}"
    receipt["public_key_base64"] = base64.b64encode(attacker_public).decode("ascii")
    receipt["public_key_sha256"] = attacker_digest
    receipt.pop("signature_base64")
    receipt["signature_base64"] = base64.b64encode(
        attacker.sign(
            (
                json.dumps(
                    receipt,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8")
        )
    ).decode("ascii")
    manifest_path.write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
    with pytest.raises(ValueError, match="protected environment"):
        _seal_origin_isolation(
            tmp_path,
            expected_collector_key_id=DEPLOYMENT_COLLECTOR_KEY_ID,
            expected_collector_public_key_sha256=DEPLOYMENT_COLLECTOR_PUBLIC_KEY_SHA256,
        )


def test_deployment_evidence_schema2_payload_change_is_rejected_before_seal(tmp_path):
    _write_schema_3_evidence(tmp_path)
    manifest_path = tmp_path / "deployment-evidence.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["schema"] = 2
    manifest["artifacts"] = [
        {
            "path": name,
            "sha256": hashlib.sha256((tmp_path / name).read_bytes()).hexdigest(),
            "size_bytes": (tmp_path / name).stat().st_size,
        }
        for name in sorted(CORE_PAYLOAD_FILES)
    ]
    manifest_path.write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
    with (tmp_path / "staging-probe.json").open("ab") as stream:
        stream.write(b"x")
    with pytest.raises(ValueError, match="changed before sealing"):
        _seal_origin_isolation(
            tmp_path,
            expected_collector_key_id=DEPLOYMENT_COLLECTOR_KEY_ID,
            expected_collector_public_key_sha256=DEPLOYMENT_COLLECTOR_PUBLIC_KEY_SHA256,
        )


def test_deployment_evidence_rejects_wrong_collector_signature(tmp_path):
    _write_schema_3_evidence(tmp_path)
    manifest_path = tmp_path / "deployment-evidence.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    signature = bytearray(
        base64.b64decode(manifest["collector_receipt"]["signature_base64"])
    )
    signature[0] ^= 0x01
    manifest["collector_receipt"]["signature_base64"] = base64.b64encode(
        signature
    ).decode("ascii")
    manifest_path.write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
    with pytest.raises(ValueError, match="signature is invalid"):
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
