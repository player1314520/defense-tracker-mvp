import hashlib
import os
import struct
from pathlib import Path

import pytest

from scripts.signing_exchange import (
    canonical_json_bytes,
    create_request,
    sha256_bytes,
    verify_signed_return,
    verify_unsigned_request,
    write_canonical_json,
)


COMMIT = "1" * 40
TREE = "2" * 40
PUBLISHER = "Example Legal Publisher"
REPOSITORY = "example/defense-tracker"
WORKFLOW = f"{REPOSITORY}/.github/workflows/release.yml@refs/heads/main"
RUN_ID = 123456
RUN_ATTEMPT = 2
JOB = "prepare-unsigned-application"


def _unsigned_pe() -> bytes:
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    pe = 0x80
    data[pe : pe + 4] = b"PE\0\0"
    coff = pe + 4
    struct.pack_into("<HHIIIHH", data, coff, 0x8664, 1, 0, 0, 0, 240, 0x0002)
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 36, 512)
    struct.pack_into("<I", data, optional + 56, 4096)
    struct.pack_into("<I", data, optional + 60, 512)
    struct.pack_into("<I", data, optional + 108, 16)
    section = optional + 240
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<II", data, section + 16, 512, 512)
    data[512:1024] = bytes((index % 251 for index in range(512)))
    return bytes(data)


def _sign_in_place(path: Path) -> None:
    data = bytearray(path.read_bytes())
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe + 4 + 20
    checksum = optional + 64
    security_directory = optional + 112 + 4 * 8
    certificate_offset = (len(data) + 7) & ~7
    data.extend(b"\0" * (certificate_offset - len(data)))
    certificate = struct.pack("<IHH", 16, 0x0200, 0x0002) + b"signed!!"
    struct.pack_into("<I", data, checksum, 0xA5A5A5A5)
    struct.pack_into("<II", data, security_directory, certificate_offset, len(certificate))
    data.extend(certificate)
    path.write_bytes(data)


def _case(tmp_path: Path) -> dict[str, object]:
    root = tmp_path / "bundle"
    target = root / "payload" / "DefenseTracker" / "DefenseTracker.exe"
    target.parent.mkdir(parents=True)
    target.write_bytes(_unsigned_pe())
    support = root / "payload" / "DefenseTracker" / "support.txt"
    support.write_text("support", encoding="utf-8")
    material = tmp_path / "runtime-lock.txt"
    material.write_text("locked", encoding="utf-8")
    materials = {"runtime-lock": material}
    request = create_request(
        subject_kind="application",
        bundle_root=root,
        target_path="payload/DefenseTracker/DefenseTracker.exe",
        release_commit=COMMIT,
        source_tree=TREE,
        version="9.0.0",
        publisher=PUBLISHER,
        repository=REPOSITORY,
        workflow_ref=WORKFLOW,
        run_id=RUN_ID,
        run_attempt=RUN_ATTEMPT,
        job=JOB,
        materials=materials,
        created_at_utc="2026-08-30T01:00:00Z",
    )
    request_path = root / "signing-request.json"
    write_canonical_json(request_path, request)
    request_sha = sha256_bytes(canonical_json_bytes(request))
    return {
        "root": root,
        "target": target,
        "support": support,
        "request": request,
        "request_path": request_path,
        "request_sha": request_sha,
        "materials": materials,
    }


def _receipt(case: dict[str, object]) -> dict[str, object]:
    target = case["target"]
    request = case["request"]
    assert isinstance(target, Path) and isinstance(request, dict)
    payload = target.read_bytes()
    target_request = request["target"]
    assert isinstance(target_request, dict)
    return {
        "schema": 2,
        "kind": "defense-tracker-authenticode-signing-receipt",
        "subject_kind": "application",
        "request_sha256": case["request_sha"],
        "release_commit": COMMIT,
        "target_path": "payload/DefenseTracker/DefenseTracker.exe",
        "unsigned_sha256": target_request["sha256"],
        "signed_sha256": hashlib.sha256(payload).hexdigest(),
        "signed_bytes": len(payload),
        "signature": {
            "provider": "AzureArtifactSigning",
            "publisher": PUBLISHER,
            "signer_subject": "CN=Example Legal Publisher, O=Example Organization",
            "signer_spki_sha256": "3" * 64,
            "signer_issuer_subject": "CN=Example CA, O=Example Trust",
            "signer_root_sha256": "4" * 64,
            "timestamp_url": "https://timestamp.example.invalid",
            "timestamp_certificate_subject": "CN=Example TSA, O=Example Trust",
            "timestamp_verified_at_utc": "2026-08-30T01:01:00Z",
            "publisher_policy": {
                "sha256": "5" * 64,
                "leaf_spki_policy": "record-only",
                "durable_identity_eku": "1.3.6.1.4.1.311.97.1.9.9",
                "azure_endpoint": "https://eus.codesigning.azure.net/",
                "azure_account_name": "example-account",
                "azure_certificate_profile_name": "example-profile",
                "azure_metadata_sha256": "6" * 64,
                "digicert_sm_host": None,
                "digicert_key_alias": None,
            },
        },
        "provenance": {
            "repository": REPOSITORY,
            "workflow_ref": WORKFLOW,
            "run_id": RUN_ID,
            "run_attempt": RUN_ATTEMPT,
            "job": "sign-application",
        },
        "completed_at_utc": "2026-08-30T01:02:00Z",
    }


def _verify_unsigned(case: dict[str, object]) -> dict[str, object]:
    return verify_unsigned_request(
        bundle_root=case["root"],
        request_path=case["request_path"],
        expected_request_sha256=case["request_sha"],
        expected_subject_kind="application",
        expected_release_commit=COMMIT,
        expected_publisher=PUBLISHER,
        expected_repository=REPOSITORY,
        expected_workflow_ref=WORKFLOW,
        expected_run_id=RUN_ID,
        expected_run_attempt=RUN_ATTEMPT,
        expected_job=JOB,
        materials=case["materials"],
    )


def _verify_signed(case: dict[str, object]) -> dict[str, object]:
    return verify_signed_return(
        bundle_root=case["root"],
        request_path=case["request_path"],
        receipt_path=Path(case["root"]) / "signing-receipt.json",
        expected_request_sha256=case["request_sha"],
        expected_subject_kind="application",
        expected_release_commit=COMMIT,
        expected_publisher=PUBLISHER,
        expected_repository=REPOSITORY,
        expected_workflow_ref=WORKFLOW,
        expected_run_id=RUN_ID,
        expected_run_attempt=RUN_ATTEMPT,
        expected_job="sign-application",
    )


def test_unsigned_request_is_canonical_and_binds_every_payload_and_material(tmp_path):
    case = _case(tmp_path)
    result = _verify_unsigned(case)
    assert result["request_sha256"] == case["request_sha"]
    assert result["materials"] == [
        {
            "name": "runtime-lock",
            "sha256": hashlib.sha256(b"locked").hexdigest(),
        }
    ]


def test_signed_return_allows_only_authenticode_target_change(tmp_path):
    case = _case(tmp_path)
    _sign_in_place(case["target"])
    write_canonical_json(Path(case["root"]) / "signing-receipt.json", _receipt(case))
    result = _verify_signed(case)
    assert result["subject_kind"] == "application"
    assert result["signed_sha256"] != result["unsigned_sha256"]


@pytest.mark.parametrize("mode", ["extra", "missing", "support-tamper", "target-tamper"])
def test_return_rejects_extra_missing_and_non_authenticode_changes(tmp_path, mode):
    case = _case(tmp_path)
    _sign_in_place(case["target"])
    write_canonical_json(Path(case["root"]) / "signing-receipt.json", _receipt(case))
    if mode == "extra":
        (Path(case["root"]) / "extra.txt").write_text("extra", encoding="utf-8")
    elif mode == "missing":
        case["support"].unlink()
    elif mode == "support-tamper":
        case["support"].write_text("changed", encoding="utf-8")
    else:
        data = bytearray(case["target"].read_bytes())
        data[700] ^= 1
        case["target"].write_bytes(data)
    with pytest.raises(ValueError):
        _verify_signed(case)


def test_noncanonical_duplicate_or_extra_receipt_field_is_rejected(tmp_path):
    case = _case(tmp_path)
    _sign_in_place(case["target"])
    receipt = _receipt(case)
    receipt["unexpected"] = True
    write_canonical_json(Path(case["root"]) / "signing-receipt.json", receipt)
    with pytest.raises(ValueError, match="missing or unexpected"):
        _verify_signed(case)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlink is unavailable")
def test_unsigned_bundle_rejects_reparse_or_symlink(tmp_path):
    case = _case(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    link = Path(case["root"]) / "payload" / "linked.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("current Windows token cannot create symlinks")
    with pytest.raises(ValueError, match="reparse"):
        _verify_unsigned(case)
