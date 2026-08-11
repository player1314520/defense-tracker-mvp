# -*- coding: utf-8 -*-

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


USER_ID = "11111111-1111-4111-8111-111111111111"
OTHER_USER_ID = "22222222-2222-4222-8222-222222222222"


def _device(*, device_id, status="active", device_kind="desktop"):
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    return ({
        "id": device_id,
        "user_id": USER_ID,
        "status": status,
        "device_kind": device_kind,
        "key_algorithm": "p256",
        "public_key": public_key,
    }, private_key)


def test_desktop_p256_identity_helper_round_trips_raw_private_key():
    from v9.ai_credentials import (
        create_desktop_credential_keypair,
        decrypt_api_credential,
        encrypt_api_credential,
    )

    public_key, private_key = create_desktop_credential_keypair()
    device = {
        "id": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        "user_id": USER_ID,
        "status": "active",
        "device_kind": "desktop",
        "key_algorithm": "p256",
        "public_key": public_key,
    }
    encrypted = encrypt_api_credential(
        "synthetic-test-key-created-by-helper",
        user_id=USER_ID,
        provider="deepseek",
        model_id="deepseek-v4-flash",
        credential_version=1,
        devices=[device],
    )

    assert len(public_key) == 65
    assert public_key[0] == 4
    assert len(private_key) == 32
    opened = decrypt_api_credential(
        encrypted,
        user_id=USER_ID,
        device=device,
        device_private_key=private_key,
    )
    assert opened.api_key_text() == "synthetic-test-key-created-by-helper"
    opened.clear()


def test_api_key_is_encrypted_for_active_desktop_p256_devices_only():
    from v9.ai_credentials import encrypt_api_credential

    desktop, _ = _device(
        device_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    )
    browser, _ = _device(
        device_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        device_kind="browser",
    )
    revoked, _ = _device(
        device_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        status="revoked",
    )
    secret = "synthetic-test-key-private-never-persist-in-plaintext"

    encrypted = encrypt_api_credential(
        secret,
        user_id=USER_ID,
        provider="deepseek",
        model_id="deepseek-v4-pro",
        credential_version=1,
        devices=[desktop, browser, revoked],
    )
    serialized = json.dumps(encrypted.to_mapping(), sort_keys=True)

    assert secret not in serialized
    assert [item.device_id for item in encrypted.device_envelopes] == [
        desktop["id"]
    ]
    assert encrypted.provider == "deepseek"
    assert encrypted.credential_version == 1
    assert set(encrypted.to_rpc_payload()) == {
        "provider",
        "model_id",
        "credential_version",
        "nonce",
        "ciphertext",
        "device_envelopes",
    }
    assert set(encrypted.to_rpc_payload()["device_envelopes"][0]) == {
        "credential_version",
        "device_id",
        "key_algorithm",
        "ephemeral_public_key",
        "nonce",
        "ciphertext",
    }


def test_api_key_round_trip_returns_redacted_clearable_memory_object():
    from v9.ai_credentials import (
        CredentialClearedError,
        decrypt_api_credential,
        encrypt_api_credential,
    )

    device, private_key = _device(
        device_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    )
    secret = "synthetic-test-key-round-trip-sensitive"
    encrypted = encrypt_api_credential(
        secret,
        user_id=USER_ID,
        provider="zhipu",
        model_id="glm-5.2",
        credential_version=7,
        devices=[device],
    )

    credential = decrypt_api_credential(
        encrypted,
        user_id=USER_ID,
        device=device,
        device_private_key=private_key,
    )

    assert credential.provider == "zhipu"
    assert credential.model_id == "glm-5.2"
    assert credential.credential_version == 7
    assert credential.endpoint == (
        "https://open.bigmodel.cn/api/paas/v4/chat/completions"
    )
    assert credential.api_key_text() == secret
    assert secret not in repr(credential)
    credential.clear()
    assert credential.cleared is True
    with pytest.raises(CredentialClearedError):
        credential.api_key_text()


def test_serialized_envelope_rejects_invalid_curve_point_or_lengths():
    from v9.ai_credentials import (
        AiCredentialError,
        EncryptedAiCredential,
        encrypt_api_credential,
    )

    device, _ = _device(
        device_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    )
    mapping = encrypt_api_credential(
        "synthetic-test-key-shape-validation",
        user_id=USER_ID,
        provider="deepseek",
        model_id="deepseek-v4-pro",
        credential_version=1,
        devices=[device],
    ).to_mapping()

    invalid_point = json.loads(json.dumps(mapping))
    invalid_point["device_envelopes"][0]["ephemeral_public_key"] = (
        base64.urlsafe_b64encode(b"\x04" + (b"\x00" * 64))
        .decode("ascii")
        .rstrip("=")
    )
    short_wrap = json.loads(json.dumps(mapping))
    short_wrap["device_envelopes"][0]["ciphertext"] = (
        base64.urlsafe_b64encode(b"x" * 47).decode("ascii").rstrip("=")
    )
    tag_only = json.loads(json.dumps(mapping))
    tag_only["ciphertext"] = (
        base64.urlsafe_b64encode(b"x" * 16).decode("ascii").rstrip("=")
    )

    for invalid in (invalid_point, short_wrap, tag_only):
        with pytest.raises(AiCredentialError, match="encrypted credential"):
            EncryptedAiCredential.from_mapping(invalid)


@pytest.mark.parametrize(
    "tamper",
    [
        {"user_id": OTHER_USER_ID},
        {"provider": "moonshot", "model_id": "kimi-k3"},
        {"credential_version": 2},
    ],
)
def test_aad_rejects_user_provider_or_version_substitution(tamper):
    from v9.ai_credentials import (
        CredentialAuthenticationError,
        EncryptedAiCredential,
        decrypt_api_credential,
        encrypt_api_credential,
    )

    device, private_key = _device(
        device_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    )
    encrypted = encrypt_api_credential(
        "sk-aad-sensitive",
        user_id=USER_ID,
        provider="deepseek",
        model_id="deepseek-v4-pro",
        credential_version=1,
        devices=[device],
    )
    mapping = encrypted.to_mapping()
    changes = dict(tamper)
    supplied_user_id = changes.pop("user_id", USER_ID)
    mapping.update(changes)
    if "credential_version" in changes:
        for envelope in mapping["device_envelopes"]:
            envelope["credential_version"] = changes["credential_version"]
    supplied_device = dict(device, user_id=supplied_user_id)

    with pytest.raises(
        CredentialAuthenticationError,
        match="credential authentication failed",
    ):
        decrypt_api_credential(
            EncryptedAiCredential.from_mapping(mapping),
            user_id=supplied_user_id,
            device=supplied_device,
            device_private_key=private_key,
        )


def test_no_eligible_desktop_device_fails_without_secret_in_error():
    from v9.ai_credentials import CredentialDeviceError, encrypt_api_credential

    browser, _ = _device(
        device_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        device_kind="browser",
    )
    secret = "synthetic-test-key-must-not-appear-in-exception"

    with pytest.raises(CredentialDeviceError) as exc:
        encrypt_api_credential(
            secret,
            user_id=USER_ID,
            provider="moonshot",
            model_id="kimi-k3",
            credential_version=1,
            devices=[browser],
        )

    assert secret not in str(exc.value)


def test_new_device_rewraps_dek_without_decrypting_or_reencrypting_api_key():
    from v9.ai_credentials import (
        decrypt_api_credential,
        encrypt_api_credential,
        rewrap_credential_for_new_device,
    )

    old_device, old_private = _device(
        device_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    )
    new_device, new_private = _device(
        device_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    )
    encrypted = encrypt_api_credential(
        "sk-rewrapped",
        user_id=USER_ID,
        provider="moonshot",
        model_id="kimi-k3",
        credential_version=3,
        devices=[old_device],
    )

    result = rewrap_credential_for_new_device(
        encrypted,
        user_id=USER_ID,
        source_device=old_device,
        source_private_key=old_private,
        target_device=new_device,
    )

    assert result.status == "rewrapped"
    assert result.credential is not None
    assert result.credential.ciphertext == encrypted.ciphertext
    assert result.credential.nonce == encrypted.nonce
    assert len(result.credential.device_envelopes) == 2
    opened = decrypt_api_credential(
        result.credential,
        user_id=USER_ID,
        device=new_device,
        device_private_key=new_private,
    )
    assert opened.api_key_text() == "sk-rewrapped"
    opened.clear()


def test_new_device_without_old_device_key_requires_reentry():
    from v9.ai_credentials import (
        encrypt_api_credential,
        rewrap_credential_for_new_device,
    )

    old_device, _ = _device(
        device_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    )
    new_device, _ = _device(
        device_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    )
    encrypted = encrypt_api_credential(
        "synthetic-test-key-reentry-required",
        user_id=USER_ID,
        provider="deepseek",
        model_id="deepseek-v4-pro",
        credential_version=1,
        devices=[old_device],
    )

    result = rewrap_credential_for_new_device(
        encrypted,
        user_id=USER_ID,
        source_device=old_device,
        source_private_key=None,
        target_device=new_device,
    )

    assert result.status == "reentry_required"
    assert result.reason == "trusted_device_unavailable"
    assert result.credential is None


def test_new_device_without_old_device_descriptor_requires_reentry():
    from v9.ai_credentials import (
        encrypt_api_credential,
        rewrap_credential_for_new_device,
    )

    old_device, _ = _device(
        device_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    )
    new_device, _ = _device(
        device_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    )
    encrypted = encrypt_api_credential(
        "synthetic-test-key-reentry-required",
        user_id=USER_ID,
        provider="deepseek",
        model_id="deepseek-v4-pro",
        credential_version=1,
        devices=[old_device],
    )

    result = rewrap_credential_for_new_device(
        encrypted,
        user_id=USER_ID,
        source_device=None,
        source_private_key=None,
        target_device=new_device,
    )

    assert result.status == "reentry_required"
    assert result.reason == "trusted_device_unavailable"
    assert result.credential is None
