import json
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.package_release_assets import resolve_signing_exchange_paths
from scripts.signing_exchange import (
    _parse_materials,
    _safe_relative_path,
    _validate_request,
    create_request,
    resolve_path_within,
    write_canonical_json,
)
import scripts.signing_exchange as signing_exchange_module

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


UNSAFE_RELATIVE_PATHS = [
    ".",
    "..",
    "../outside",
    "nested/../../outside",
    "/etc/passwd",
    "//server/share/file",
    r"\\server\share\file",
    "C:/Windows/System32/file",
    "C:Windows/System32/file",
    r"nested\file",
    "nested/./file",
    "nested//file",
    "nested/file/",
    "nested/fi\x00le",
    "nested/file:stream",
    "nested/NUL.txt",
    "nested/trailing.",
    "nested/trailing ",
]


@pytest.mark.parametrize("relative", UNSAFE_RELATIVE_PATHS)
def test_shared_relative_path_boundary_rejects_windows_and_posix_bypasses(relative):
    with pytest.raises(ValueError, match="relative path|portable"):
        _safe_relative_path(relative, label="candidate")


@pytest.mark.parametrize("relative", UNSAFE_RELATIVE_PATHS)
def test_cli_material_boundary_rejects_windows_and_posix_bypasses(tmp_path, relative):
    with pytest.raises(ValueError, match="relative path|portable"):
        _parse_materials([f"runtime-lock={relative}"], path_root=tmp_path)


@pytest.mark.parametrize("relative", UNSAFE_RELATIVE_PATHS)
def test_packager_exchange_boundary_rejects_windows_and_posix_bypasses(
    tmp_path, relative
):
    with pytest.raises(ValueError, match="relative path|portable"):
        resolve_signing_exchange_paths(
            {"application_request": relative},
            cli_root=tmp_path,
        )


def test_relative_resolver_keeps_valid_nested_unicode_file_inside_root(tmp_path):
    nested = tmp_path / "证据" / "request.json"
    nested.parent.mkdir()
    nested.write_text("{}\n", encoding="utf-8")

    assert resolve_path_within(
        tmp_path,
        "证据/request.json",
        label="request",
        kind="file",
    ) == nested


def test_cli_path_collections_reject_case_insensitive_duplicates(tmp_path):
    material = tmp_path / "Evidence.json"
    material.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="case-insensitively unique"):
        _parse_materials(
            ["first=Evidence.json", "second=evidence.JSON"],
            path_root=tmp_path,
        )
    with pytest.raises(ValueError, match="case-insensitively unique"):
        resolve_signing_exchange_paths(
            {
                "application_request": "Evidence.json",
                "application_receipt": "evidence.JSON",
            },
            cli_root=tmp_path,
        )


def test_signing_request_rejects_case_insensitive_payload_duplicates(tmp_path):
    bundle = tmp_path / "bundle"
    target = bundle / "payload" / "DefenseTracker" / "DefenseTracker.exe"
    target.parent.mkdir(parents=True)
    target.write_bytes(_unsigned_pe())
    support = target.parent / "support.txt"
    support.write_text("support", encoding="utf-8")
    request = create_request(
        subject_kind="application",
        bundle_root=bundle,
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
        materials={"runtime-lock": "a" * 64},
        created_at_utc="2026-08-30T01:00:00Z",
    )
    duplicate = json.loads(json.dumps(request))
    support_entry = next(
        item for item in duplicate["payload_files"] if item["path"].endswith("support.txt")
    )
    duplicate["payload_files"].append(
        {**support_entry, "path": "payload/DefenseTracker/SUPPORT.txt"}
    )
    duplicate["payload_files"].sort(key=lambda item: item["path"])

    with pytest.raises(ValueError, match="unique and sorted"):
        _validate_request(duplicate)


def test_linux_bundle_cannot_alias_reserved_windows_metadata_name(tmp_path):
    bundle = tmp_path / "bundle"
    target = bundle / "payload" / "DefenseTracker" / "DefenseTracker.exe"
    target.parent.mkdir(parents=True)
    target.write_bytes(_unsigned_pe())
    (bundle / "Signing-Request.json").write_text("attacker metadata\n", encoding="utf-8")

    with pytest.raises(ValueError, match="aliases reserved signing metadata"):
        create_request(
            subject_kind="application",
            bundle_root=bundle,
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
            materials={"python-source": "a" * 64},
            created_at_utc="2026-08-30T01:00:00Z",
        )


def test_request_inventory_rejects_case_alias_of_reserved_metadata(tmp_path):
    bundle = tmp_path / "bundle"
    target = bundle / "payload" / "DefenseTracker" / "DefenseTracker.exe"
    target.parent.mkdir(parents=True)
    target.write_bytes(_unsigned_pe())
    support = target.parent / "support.txt"
    support.write_text("support", encoding="utf-8")
    request = create_request(
        subject_kind="application",
        bundle_root=bundle,
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
        materials={"python-source": "a" * 64},
        created_at_utc="2026-08-30T01:00:00Z",
    )
    poisoned = json.loads(json.dumps(request))
    support_entry = next(
        item for item in poisoned["payload_files"] if item["path"].endswith("support.txt")
    )
    support_entry["path"] = "SIGNING-RECEIPT.JSON"
    poisoned["payload_files"].sort(key=lambda item: item["path"])

    with pytest.raises(ValueError, match="unique and sorted"):
        _validate_request(poisoned)


def test_output_boundary_rejects_parent_traversal_before_write(tmp_path):
    with pytest.raises(ValueError, match="relative path"):
        resolve_path_within(
            tmp_path,
            "../outside.json",
            label="output",
            kind="output",
        )


def test_signing_cli_accepts_bounded_relative_paths_and_rejects_escape(tmp_path):
    bundle = tmp_path / "bundle"
    target = bundle / "payload" / "DefenseTracker" / "DefenseTracker.exe"
    target.parent.mkdir(parents=True)
    target.write_bytes(_unsigned_pe())
    script = Path(__file__).resolve().parents[1] / "scripts" / "signing_exchange.py"
    base = [
        sys.executable,
        str(script),
        "create-request",
        "--subject-kind",
        "application",
        "--bundle-root",
        "bundle",
        "--target",
        "payload/DefenseTracker/DefenseTracker.exe",
        "--release-commit",
        COMMIT,
        "--source-tree",
        TREE,
        "--version",
        "9.0.0",
        "--publisher",
        PUBLISHER,
        "--repository",
        REPOSITORY,
        "--workflow-ref",
        WORKFLOW,
        "--run-id",
        str(RUN_ID),
        "--run-attempt",
        str(RUN_ATTEMPT),
        "--job",
        JOB,
        "--material-sha256",
        f"python-source={'a' * 64}",
    ]
    accepted = subprocess.run(
        [*base, "--output", "bundle/signing-request.json"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert accepted.returncode == 0, accepted.stderr
    assert (bundle / "signing-request.json").is_file()

    (bundle / "signing-request.json").unlink()
    rejected = subprocess.run(
        [*base, "--output", "../outside.json"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode != 0
    assert not (tmp_path.parent / "outside.json").exists()


def test_canonical_writer_detects_output_parent_swap_before_replace(
    tmp_path, monkeypatch
):
    parent = tmp_path / "output"
    moved = tmp_path / "moved-output"
    parent.mkdir()
    destination = parent / "receipt.json"
    original_mkstemp = signing_exchange_module.tempfile.mkstemp

    def swapped_mkstemp(*args, **kwargs):
        descriptor, temporary_name = original_mkstemp(*args, **kwargs)
        os.close(descriptor)
        temporary_leaf = Path(temporary_name).name
        parent.rename(moved)
        parent.mkdir()
        moved_descriptor = os.open(moved / temporary_leaf, os.O_WRONLY)
        return moved_descriptor, temporary_name

    monkeypatch.setattr(signing_exchange_module.tempfile, "mkstemp", swapped_mkstemp)
    with pytest.raises(ValueError, match="output parent changed"):
        write_canonical_json(destination, {"schema": 1})
    assert not destination.exists()
