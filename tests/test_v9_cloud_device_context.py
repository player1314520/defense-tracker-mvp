import base64
import json
import uuid

import pytest


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))


def _service(tmp_path):
    from v9.service import V9Service

    return V9Service(
        tmp_path / "v9.sqlite3",
        tmp_path / ".v9_local_master.key",
    )


class _AuthenticatedSession:
    def __init__(self, user_id: str, session_id: str):
        claims = json.dumps({
            "sub": user_id,
            "session_id": session_id,
        }).encode("utf-8")
        self._user_id = user_id
        self._access_token = ".".join((
            _b64url(b'{"alg":"ES256"}'),
            _b64url(claims),
            _b64url(b"synthetic-signature"),
        ))

    def access_token(self):
        return self._access_token

    def user_id(self):
        return self._user_id


def test_invited_cloud_device_is_separate_and_locked_until_envelope(tmp_path):
    from v9.crypto import seal_org_key_for_p256
    from v9.errors import PermissionDenied

    service = _service(tmp_path)
    service.get_or_create_personal_context()
    stored_personal = service.get_personal_context()
    organization_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())

    pending = service.prepare_cloud_device_registration(
        organization_id=organization_id,
        user_id=user_id,
        role="analyst",
        membership_status="invited",
        key_version=4,
        device_name="本机桌面",
    )
    repeated = service.prepare_cloud_device_registration(
        organization_id=organization_id,
        user_id=user_id,
        role="analyst",
        membership_status="invited",
        key_version=4,
        device_name="另一个名称不能轮换密钥",
    )

    assert pending == repeated
    assert service.get_personal_context() == stored_personal
    assert pending["organization_id"] == organization_id
    assert pending["user_id"] == user_id
    assert pending["key_algorithm"] == "p256"
    assert pending["device_kind"] == "desktop"
    assert pending["status"] == "pending"
    assert "private_key" not in json.dumps(pending)
    with pytest.raises(PermissionDenied, match="active cloud device"):
        service.resolve_cloud_context(organization_id, user_id)

    local_secret = service.repository.get_local_secret(
        organization_id,
        "device_private_key",
        pending["device_id"],
        0,
    )
    assert local_secret is not None
    assert bytes(local_secret["ciphertext"]) != _unb64url(
        pending["device_public_key"]
    )

    org_key = bytes(range(32))
    envelope = seal_org_key_for_p256(
        org_key,
        _unb64url(pending["device_public_key"]),
        org_id=organization_id,
        device_id=pending["device_id"],
        key_version=4,
    )
    active = service.activate_cloud_device_context(
        pending,
        remote_device={
            "id": pending["device_id"],
            "organization_id": organization_id,
            "user_id": user_id,
            "key_algorithm": "p256",
            "device_kind": "desktop",
            "public_key": _unb64url(pending["device_public_key"]),
            "status": "active",
        },
        envelope={
            "organization_id": organization_id,
            "device_id": pending["device_id"],
            "key_version": 4,
            "key_algorithm": "p256",
            "ephemeral_public_key": envelope["ephemeral_public_key"],
            "nonce": envelope["nonce"],
            "ciphertext": envelope["ciphertext"],
        },
        expected_key_version=4,
    )

    assert active["status"] == "active"
    assert service.resolve_cloud_context(organization_id, user_id) == active
    assert service.get_personal_context() == stored_personal


def test_cloud_context_activation_rejects_identity_and_algorithm_mismatch(
    tmp_path,
):
    from v9.errors import PermissionDenied

    service = _service(tmp_path)
    organization_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    pending = service.prepare_cloud_device_registration(
        organization_id=organization_id,
        user_id=user_id,
        role="collector",
        membership_status="active",
        key_version=1,
        device_name="本机桌面",
    )

    with pytest.raises(PermissionDenied):
        service.activate_cloud_device_context(
            pending,
            remote_device={
                "id": pending["device_id"],
                "organization_id": organization_id,
                "user_id": str(uuid.uuid4()),
                "key_algorithm": "p256",
                "public_key": b"\x04" + (b"x" * 64),
                "status": "active",
            },
            envelope={},
            expected_key_version=1,
        )

    assert service.get_cloud_device_context(organization_id)["status"] == "pending"
    with pytest.raises(PermissionDenied):
        service.resolve_cloud_context(organization_id, user_id)


def test_tampered_cloud_envelope_keeps_context_pending(tmp_path):
    from v9.crypto import seal_org_key_for_p256

    service = _service(tmp_path)
    organization_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    pending = service.prepare_cloud_device_registration(
        organization_id=organization_id,
        user_id=user_id,
        role="analyst",
        membership_status="invited",
        key_version=2,
        device_name="本机桌面",
    )
    envelope = seal_org_key_for_p256(
        bytes(range(32)),
        _unb64url(pending["device_public_key"]),
        org_id=organization_id,
        device_id=pending["device_id"],
        key_version=2,
    )
    ciphertext = bytearray(_unb64url(envelope["ciphertext"]))
    ciphertext[-1] ^= 1

    with pytest.raises(
        ValueError, match="envelope authentication failed"
    ):
        service.activate_cloud_device_context(
            pending,
            remote_device={
                "id": pending["device_id"],
                "organization_id": organization_id,
                "user_id": user_id,
                "key_algorithm": "p256",
                "device_kind": "desktop",
                "public_key": _unb64url(pending["device_public_key"]),
                "status": "active",
            },
            envelope={
                "organization_id": organization_id,
                "device_id": pending["device_id"],
                "key_version": 2,
                "key_algorithm": "p256",
                "ephemeral_public_key": envelope["ephemeral_public_key"],
                "nonce": envelope["nonce"],
                "ciphertext": _b64url(bytes(ciphertext)),
            },
            expected_key_version=2,
        )

    assert service.get_cloud_device_context(organization_id)["status"] == "pending"
    assert service.repository.get_local_secret(
        organization_id,
        "org_key",
        organization_id,
        2,
    ) is None


def test_tampered_rotated_envelope_preserves_previous_active_key(tmp_path):
    from v9.crypto import seal_org_key_for_p256

    service = _service(tmp_path)
    organization_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    pending = service.prepare_cloud_device_registration(
        organization_id=organization_id,
        user_id=user_id,
        role="analyst",
        membership_status="active",
        key_version=1,
        device_name="本机桌面",
    )
    remote_device = {
        "id": pending["device_id"],
        "organization_id": organization_id,
        "user_id": user_id,
        "key_algorithm": "p256",
        "device_kind": "desktop",
        "public_key": _unb64url(pending["device_public_key"]),
        "status": "active",
    }
    initial = seal_org_key_for_p256(
        bytes(range(32)),
        remote_device["public_key"],
        org_id=organization_id,
        device_id=pending["device_id"],
        key_version=1,
    )
    active = service.activate_cloud_device_context(
        pending,
        remote_device=remote_device,
        envelope={
            "organization_id": organization_id,
            "device_id": pending["device_id"],
            "key_version": 1,
            "key_algorithm": "p256",
            "ephemeral_public_key": initial["ephemeral_public_key"],
            "nonce": initial["nonce"],
            "ciphertext": initial["ciphertext"],
        },
        expected_key_version=1,
    )
    rotated = seal_org_key_for_p256(
        bytes(reversed(range(32))),
        remote_device["public_key"],
        org_id=organization_id,
        device_id=pending["device_id"],
        key_version=2,
    )
    ciphertext = bytearray(_unb64url(rotated["ciphertext"]))
    ciphertext[-1] ^= 1

    with pytest.raises(
        ValueError, match="envelope authentication failed"
    ):
        service.activate_cloud_device_context(
            active,
            remote_device=remote_device,
            envelope={
                "organization_id": organization_id,
                "device_id": pending["device_id"],
                "key_version": 2,
                "key_algorithm": "p256",
                "ephemeral_public_key": rotated["ephemeral_public_key"],
                "nonce": rotated["nonce"],
                "ciphertext": _b64url(bytes(ciphertext)),
            },
            expected_key_version=2,
        )

    assert service.resolve_cloud_context(
        organization_id, user_id
    )["key_version"] == 1
    assert service.repository.get_local_secret(
        organization_id,
        "org_key",
        organization_id,
        2,
    ) is None


def test_cloud_activation_rolls_back_new_org_key_if_profile_update_fails(
    tmp_path,
):
    import sqlite3

    from v9.crypto import seal_org_key_for_p256

    service = _service(tmp_path)
    organization_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    pending = service.prepare_cloud_device_registration(
        organization_id=organization_id,
        user_id=user_id,
        role="analyst",
        membership_status="invited",
        key_version=2,
        device_name="本机桌面",
    )
    envelope = seal_org_key_for_p256(
        bytes(range(32)),
        _unb64url(pending["device_public_key"]),
        org_id=organization_id,
        device_id=pending["device_id"],
        key_version=2,
    )
    with service.repository._connect() as conn:
        conn.execute(
            """
            CREATE TRIGGER fail_cloud_profile_update
            BEFORE UPDATE ON local_profile
            WHEN OLD.profile_key=NEW.profile_key
            BEGIN
                SELECT RAISE(ABORT, 'simulated profile write failure');
            END
            """
        )

    with pytest.raises(sqlite3.IntegrityError):
        service.activate_cloud_device_context(
            pending,
            remote_device={
                "id": pending["device_id"],
                "organization_id": organization_id,
                "user_id": user_id,
                "key_algorithm": "p256",
                "device_kind": "desktop",
                "public_key": _unb64url(pending["device_public_key"]),
                "status": "active",
            },
            envelope={
                "organization_id": organization_id,
                "device_id": pending["device_id"],
                "key_version": 2,
                "key_algorithm": "p256",
                "ephemeral_public_key": envelope["ephemeral_public_key"],
                "nonce": envelope["nonce"],
                "ciphertext": envelope["ciphertext"],
            },
            expected_key_version=2,
        )

    assert service.get_cloud_device_context(organization_id)["status"] == "pending"
    assert service.repository.get_local_secret(
        organization_id,
        "org_key",
        organization_id,
        2,
    ) is None


def test_cloud_bootstrap_identity_never_rewrites_default_personal_context(tmp_path):
    service = _service(tmp_path)
    personal = service.get_or_create_personal_context()
    service.acknowledge_personal_recovery(personal["organization_id"])
    stored_personal = service.get_personal_context()
    cloud_user_id = str(uuid.uuid4())
    authenticated = _AuthenticatedSession(
        cloud_user_id, str(uuid.uuid4())
    )

    service.build_mvp_owner_bootstrap_manifest(
        personal,
        authenticated_session=authenticated,
    )
    pending = service.get_cloud_device_context(personal["organization_id"])
    assert pending is not None
    remote_device = {
        "id": pending["device_id"],
        "organization_id": pending["organization_id"],
        "user_id": cloud_user_id,
        "key_algorithm": "p256",
        "device_kind": "desktop",
        "public_key": _unb64url(pending["device_public_key"]),
        "status": "active",
    }
    membership = {
        "organization_id": pending["organization_id"],
        "user_id": cloud_user_id,
        "role": "owner",
        "status": "active",
    }
    envelope = service.build_bootstrapped_cloud_key_envelope(
        pending,
        remote_device=remote_device,
        expected_key_version=1,
        membership=membership,
        authenticated_session=authenticated,
    )
    bound = service.activate_bootstrapped_cloud_context(
        pending,
        remote_device=remote_device,
        envelope=envelope,
        expected_key_version=1,
        membership=membership,
        authenticated_session=authenticated,
    )

    assert bound["organization_id"] == personal["organization_id"]
    assert bound["device_id"] != personal["device_id"]
    assert bound["user_id"] == cloud_user_id
    assert bound["key_algorithm"] == "p256"
    assert bound["device_kind"] == "desktop"
    assert bound["status"] == "active"
    assert "mvp_owner_bootstrap" not in bound
    assert service.resolve_cloud_context(
        personal["organization_id"], cloud_user_id
    ) == bound
    assert service.get_personal_context() == stored_personal


def test_pending_cloud_registration_cannot_advance_existing_local_key_version(
    tmp_path,
):
    service = _service(tmp_path)
    personal = service.get_or_create_personal_context()
    organization_id = personal["organization_id"]
    original_version = int(
        service.repository.get_organization(organization_id)["key_version"]
    )

    pending = service.prepare_cloud_device_registration(
        organization_id=organization_id,
        user_id=str(uuid.uuid4()),
        role="owner",
        membership_status="active",
        key_version=original_version + 4,
        device_name="第二台桌面",
    )

    assert pending["remote_key_version"] == original_version + 4
    assert int(
        service.repository.get_organization(organization_id)["key_version"]
    ) == original_version
    assert service.get_personal_context()["device_id"] == personal["device_id"]


def test_active_context_rejects_nonactive_local_membership(tmp_path):
    from v9.crypto import seal_org_key_for_p256
    from v9.errors import PermissionDenied

    service = _service(tmp_path)
    organization_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    pending = service.prepare_cloud_device_registration(
        organization_id=organization_id,
        user_id=user_id,
        role="analyst",
        membership_status="invited",
        key_version=1,
        device_name="本机桌面",
    )
    organization_key = bytes(range(32))
    envelope = seal_org_key_for_p256(
        organization_key,
        _unb64url(pending["device_public_key"]),
        org_id=organization_id,
        device_id=pending["device_id"],
        key_version=1,
    )
    active = service.activate_cloud_device_context(
        pending,
        remote_device={
            "id": pending["device_id"],
            "organization_id": organization_id,
            "user_id": user_id,
            "key_algorithm": "p256",
            "device_kind": "desktop",
            "public_key": _unb64url(pending["device_public_key"]),
            "status": "active",
        },
        envelope={
            "organization_id": organization_id,
            "device_id": pending["device_id"],
            "key_version": 1,
            "key_algorithm": "p256",
            "ephemeral_public_key": envelope["ephemeral_public_key"],
            "nonce": envelope["nonce"],
            "ciphertext": envelope["ciphertext"],
        },
        expected_key_version=1,
    )
    with service.repository._connect() as conn:
        conn.execute(
            """
            UPDATE memberships
            SET status='revoked'
            WHERE organization_id=? AND user_id=?
            """,
            (organization_id, user_id),
        )

    with pytest.raises(PermissionDenied, match="active cloud device"):
        service.resolve_cloud_context(organization_id, user_id)
    assert active["status"] == "active"


def test_minimal_sync_device_metadata_allows_cross_member_record_fk(tmp_path):
    from v9.crypto import create_device_keypair

    service = _service(tmp_path)
    context = service.get_or_create_personal_context()
    remote_device_id = str(uuid.uuid4())
    remote_public_key, _ = create_device_keypair()
    service.import_cloud_device_metadata(
        context,
        [{
            "org_id": context["organization_id"],
            "device_id": remote_device_id,
            "key_algorithm": "x25519",
            "public_key": remote_public_key,
        }],
    )
    record_id = str(uuid.uuid4())
    payload = service.build_encrypted_payload(
        context["organization_id"],
        remote_device_id,
        record_id,
        "evidence",
        1,
        {"title": "cross-member"},
    )

    result = service.apply_remote_event(
        context["organization_id"],
        context["user_id"],
        {
            "event_id": str(uuid.uuid4()),
            "organization_id": context["organization_id"],
            "record_id": record_id,
            "operation": "upsert",
            "payload": payload,
        },
        remote_cursor=7,
    )

    assert result["state"] == "applied"
    assert service.repository.get_device(remote_device_id)["user_id"].startswith(
        "sync-device:"
    )
