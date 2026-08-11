# -*- coding: utf-8 -*-
import json
import os

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
