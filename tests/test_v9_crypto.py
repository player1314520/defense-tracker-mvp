# -*- coding: utf-8 -*-
import hashlib
import json
import os
from dataclasses import replace

import pytest
from cryptography.exceptions import InvalidTag


def test_record_envelope_round_trip_and_tamper_detection():
    from v9.crypto import decrypt_record, encrypt_record, generate_org_key

    org_key = generate_org_key()
    content = {"title": "仅客户端可见", "body": "zero knowledge"}
    envelope = encrypt_record(
        org_key=org_key,
        org_id="org-1",
        record_id="rec-1",
        record_type="evidence",
        version=1,
        key_version=1,
        content=content,
    )

    serialized = json.dumps(envelope.to_dict(), ensure_ascii=False)
    assert content["title"] not in serialized
    assert content["body"] not in serialized
    assert decrypt_record(org_key, envelope) == content

    tampered = envelope.with_ciphertext(
        envelope.ciphertext[:-1] + bytes([envelope.ciphertext[-1] ^ 1])
    )
    with pytest.raises(InvalidTag):
        decrypt_record(org_key, tampered)


def test_record_content_hash_is_randomized_ciphertext_commitment():
    from v9.crypto import decrypt_record, encrypt_record, generate_org_key

    org_key = generate_org_key()
    content = {"status": "draft", "body": "low entropy private value"}
    first = encrypt_record(
        org_key=org_key,
        org_id="org-1",
        record_id="rec-1",
        record_type="case",
        version=1,
        key_version=1,
        content=content,
    )
    second = encrypt_record(
        org_key=org_key,
        org_id="org-1",
        record_id="rec-1",
        record_type="case",
        version=1,
        key_version=1,
        content=content,
    )
    canonical_plaintext = json.dumps(
        content,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    assert first.ciphertext != second.ciphertext
    assert first.content_hash != second.content_hash
    assert first.content_hash != hashlib.sha256(canonical_plaintext).hexdigest()
    assert second.content_hash != hashlib.sha256(canonical_plaintext).hexdigest()
    assert first.content_hash == hashlib.sha256(
        b"DefenseTracker-V9-record-ciphertext-commitment-v1\x00"
        b"v9:record-content:1:org-1:rec-1:case:1"
        + first.nonce
        + first.ciphertext
    ).hexdigest()
    assert decrypt_record(org_key, first) == content
    assert decrypt_record(org_key, second) == content

    tampered_commitment = replace(first, content_hash="0" * 64)
    with pytest.raises(ValueError, match="content hash mismatch"):
        decrypt_record(org_key, tampered_commitment)


def test_legacy_record_plaintext_hash_remains_readable_and_rewrappable():
    from v9.crypto import (
        decrypt_record,
        encrypt_record,
        generate_org_key,
        rewrap_record_data_key,
    )

    old_key = generate_org_key()
    new_key = generate_org_key()
    content = {"body": "legacy encrypted record"}
    plaintext = json.dumps(
        content, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    current = encrypt_record(
        org_key=old_key,
        org_id="org-legacy",
        record_id="record-legacy",
        record_type="document",
        version=7,
        key_version=1,
        content=content,
    )
    legacy = replace(current, content_hash=hashlib.sha256(plaintext).hexdigest())

    assert decrypt_record(old_key, legacy) == content
    rotated = rewrap_record_data_key(old_key, new_key, legacy, new_key_version=2)
    assert rotated.content_hash == legacy.content_hash
    assert decrypt_record(new_key, rotated) == content

    with pytest.raises(ValueError, match="content hash mismatch"):
        decrypt_record(old_key, replace(legacy, content_hash="0" * 64))

    assert set(legacy.to_dict()) == set(current.to_dict())


def test_device_envelope_only_opens_with_target_private_key():
    from v9.crypto import (
        create_device_keypair,
        open_org_key_for_device,
        seal_org_key_for_device,
        generate_org_key,
    )

    public_a, private_a = create_device_keypair()
    _, private_b = create_device_keypair()
    org_key = generate_org_key()
    envelope = seal_org_key_for_device(
        org_key, public_a, org_id="org-1", device_id="device-a", key_version=1
    )

    assert open_org_key_for_device(private_a, envelope) == org_key
    with pytest.raises(InvalidTag):
        open_org_key_for_device(private_b, envelope)


def test_p256_browser_envelope_uses_hkdf_sha256_and_aes_gcm():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from v9.crypto import (
        generate_org_key,
        open_org_key_for_p256,
        seal_org_key_for_p256,
    )

    browser_private = ec.generate_private_key(ec.SECP256R1())
    browser_public = browser_private.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    org_key = generate_org_key()
    envelope = seal_org_key_for_p256(
        org_key,
        browser_public,
        org_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        device_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        key_version=2,
    )

    assert envelope["key_algorithm"] == "p256"
    assert open_org_key_for_p256(browser_private, envelope) == org_key


def test_recovery_code_is_returned_separately_and_wrong_code_fails():
    from v9.crypto import create_recovery_envelope, recover_org_key, generate_org_key

    org_key = generate_org_key()
    code, envelope = create_recovery_envelope(org_key, "org-1", key_version=1)

    assert code not in json.dumps(envelope, ensure_ascii=False)
    assert recover_org_key(code, envelope) == org_key
    wrong_code = ("A" if code[0] != "A" else "B") + code[1:]
    with pytest.raises((InvalidTag, ValueError)):
        recover_org_key(wrong_code, envelope)


def test_rewrap_data_key_changes_wrap_not_record_ciphertext():
    from v9.crypto import (
        decrypt_record,
        encrypt_record,
        generate_org_key,
        rewrap_record_data_key,
    )

    old_key = generate_org_key()
    new_key = generate_org_key()
    envelope = encrypt_record(
        org_key=old_key,
        org_id="org-1",
        record_id="rec-1",
        record_type="case",
        version=3,
        key_version=1,
        content={"finding": "source-backed"},
    )
    rotated = rewrap_record_data_key(old_key, new_key, envelope, new_key_version=2)

    assert rotated.ciphertext == envelope.ciphertext
    assert rotated.nonce == envelope.nonce
    assert rotated.content_hash == envelope.content_hash
    assert rotated.wrapped_data_key != envelope.wrapped_data_key
    assert rotated.key_version == 2
    assert decrypt_record(new_key, rotated) == {"finding": "source-backed"}


def test_file_blob_uses_independent_data_key_and_contains_no_plaintext():
    from v9.crypto import decrypt_blob, encrypt_blob, generate_org_key

    org_key = generate_org_key()
    plaintext = b"private attachment body"
    envelope = encrypt_blob(
        org_key,
        org_id="org-1",
        object_id="object-1",
        key_version=1,
        plaintext=plaintext,
    )

    assert plaintext not in envelope.ciphertext
    assert decrypt_blob(org_key, envelope) == plaintext


def test_blob_content_hash_is_randomized_ciphertext_commitment():
    from v9.crypto import decrypt_blob, encrypt_blob, generate_org_key

    org_key = generate_org_key()
    plaintext = b"known private attachment"
    first = encrypt_blob(
        org_key,
        org_id="org-1",
        object_id="object-1",
        key_version=1,
        plaintext=plaintext,
    )
    second = encrypt_blob(
        org_key,
        org_id="org-1",
        object_id="object-1",
        key_version=1,
        plaintext=plaintext,
    )

    assert first.ciphertext != second.ciphertext
    assert first.content_hash != second.content_hash
    assert first.content_hash != hashlib.sha256(plaintext).hexdigest()
    assert second.content_hash != hashlib.sha256(plaintext).hexdigest()
    assert first.content_hash == hashlib.sha256(
        b"DefenseTracker-V9-blob-ciphertext-commitment-v1\x00"
        b"v9:blob-content:1:org-1:object-1"
        + first.nonce
        + first.ciphertext
    ).hexdigest()
    assert decrypt_blob(org_key, first) == plaintext
    assert decrypt_blob(org_key, second) == plaintext

    tampered_commitment = replace(first, content_hash="0" * 64)
    with pytest.raises(ValueError, match="content hash mismatch"):
        decrypt_blob(org_key, tampered_commitment)


def test_legacy_blob_plaintext_hash_remains_readable_and_wrong_hash_is_rejected():
    from v9.crypto import decrypt_blob, encrypt_blob, generate_org_key

    org_key = generate_org_key()
    plaintext = b"legacy encrypted attachment"
    current = encrypt_blob(
        org_key,
        org_id="org-legacy",
        object_id="blob-legacy",
        key_version=1,
        plaintext=plaintext,
    )
    legacy = replace(current, content_hash=hashlib.sha256(plaintext).hexdigest())

    assert decrypt_blob(org_key, legacy) == plaintext
    with pytest.raises(ValueError, match="content hash mismatch"):
        decrypt_blob(org_key, replace(legacy, content_hash="f" * 64))

    assert set(legacy.to_dict()) == set(current.to_dict())


def test_master_key_payload_is_created_private_and_without_following_links(
    tmp_path, monkeypatch
):
    import v9.service as service_module

    observed = {}
    real_open = service_module.os.open

    def recording_open(path, flags, mode=0o600, *args, **kwargs):
        observed.update(path=path, flags=flags, mode=mode)
        return real_open(path, flags, mode, *args, **kwargs)

    monkeypatch.setattr(service_module.os, "open", recording_open)
    target = tmp_path / "vault" / ".v9_local_master.key"
    target.parent.mkdir()

    service_module.V9Service._write_master_key_payload(
        target, b"k" * 32
    )

    assert target.read_bytes() == b"k" * 32
    assert observed["mode"] == 0o600
    assert observed["mode"] & 0o077 == 0
    assert observed["flags"] & os.O_EXCL
    assert observed["flags"] & os.O_CREAT
    if getattr(os, "O_NOFOLLOW", 0):
        assert observed["flags"] & os.O_NOFOLLOW


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI is required")
def test_legacy_raw_master_key_is_atomically_migrated_without_breaking_database(
    tmp_path,
):
    from v9.crypto import DPAPI_MASTER_KEY_MAGIC
    from v9.service import V9Service

    key_path = tmp_path / ".v9_local_master.key"
    legacy_key = os.urandom(32)
    key_path.write_bytes(legacy_key)
    database_path = tmp_path / "v9.sqlite3"

    service = V9Service(database_path, key_path)
    context = service.get_or_create_personal_context()
    record = service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "document",
        {"body": "existing encrypted database remains readable"},
    )

    migrated = key_path.read_bytes()
    assert migrated.startswith(DPAPI_MASTER_KEY_MAGIC)
    assert migrated != legacy_key
    assert legacy_key not in migrated

    reopened = V9Service(database_path, key_path)
    restored = reopened.read_record(
        context["organization_id"],
        context["user_id"],
        record["record_id"],
    )
    assert restored["content"]["body"] == "existing encrypted database remains readable"


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI is required")
def test_vault_startup_also_hardens_matching_legacy_config_copy(tmp_path):
    from v9.crypto import DPAPI_MASTER_KEY_MAGIC
    from v9.service import V9Service

    runtime = tmp_path / "runtime"
    vault_key = runtime / "vault" / ".v9_local_master.key"
    config_key = runtime / "config" / ".v9_local_master.key"
    vault_key.parent.mkdir(parents=True)
    config_key.parent.mkdir(parents=True)
    legacy_key = os.urandom(32)
    vault_key.write_bytes(legacy_key)
    config_key.write_bytes(legacy_key)

    V9Service(runtime / "data" / "v9.sqlite3", vault_key)

    assert vault_key.read_bytes().startswith(DPAPI_MASTER_KEY_MAGIC)
    assert config_key.read_bytes().startswith(DPAPI_MASTER_KEY_MAGIC)
    assert legacy_key not in vault_key.read_bytes()
    assert legacy_key not in config_key.read_bytes()


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI is required")
def test_vault_startup_hardens_matching_frozen_exe_adjacent_copy(
    tmp_path, monkeypatch
):
    from v9.crypto import DPAPI_MASTER_KEY_MAGIC
    import v9.service as service_module

    runtime = tmp_path / "runtime"
    vault_key = runtime / "vault" / ".v9_local_master.key"
    exe_dir = tmp_path / "installed"
    exe_key = exe_dir / ".v9_local_master.key"
    vault_key.parent.mkdir(parents=True)
    exe_dir.mkdir()
    legacy_key = os.urandom(32)
    vault_key.write_bytes(legacy_key)
    exe_key.write_bytes(legacy_key)
    monkeypatch.setattr(
        service_module.sys, "executable", str(exe_dir / "DefenseTracker.exe")
    )

    service_module.V9Service(runtime / "data" / "v9.sqlite3", vault_key)

    assert vault_key.read_bytes().startswith(DPAPI_MASTER_KEY_MAGIC)
    assert exe_key.read_bytes().startswith(DPAPI_MASTER_KEY_MAGIC)
    assert legacy_key not in exe_key.read_bytes()


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI is required")
def test_controlled_recovery_hardens_matching_legacy_config_copy(tmp_path):
    from v9.crypto import DPAPI_MASTER_KEY_MAGIC
    from v9.service import V9Service

    runtime = tmp_path / "runtime"
    vault_key = runtime / "vault" / ".v9_local_master.key"
    config_key = runtime / "config" / ".v9_local_master.key"
    database_path = runtime / "data" / "v9.sqlite3"

    service = V9Service(database_path, vault_key)
    context = service.get_or_create_personal_context()
    record = service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "document",
        {"body": "recover without leaving a raw legacy key"},
    )
    correct_key = bytes(service._master_key)
    config_key.parent.mkdir(parents=True)
    config_key.write_bytes(correct_key)
    vault_key.write_bytes(os.urandom(32))

    locked = V9Service(database_path, vault_key)
    assert locked.is_key_locked is True

    locked.restore_local_master_key(correct_key)

    assert vault_key.read_bytes().startswith(DPAPI_MASTER_KEY_MAGIC)
    assert config_key.read_bytes().startswith(DPAPI_MASTER_KEY_MAGIC)
    assert correct_key not in config_key.read_bytes()
    restored = locked.read_record(
        context["organization_id"], context["user_id"], record["record_id"]
    )
    assert restored["content"]["body"] == "recover without leaving a raw legacy key"
