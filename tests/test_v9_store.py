# -*- coding: utf-8 -*-
import json
import sqlite3

import pytest


@pytest.fixture()
def service(tmp_path):
    from v9.service import V9Service

    return V9Service(
        database_path=tmp_path / "v9.sqlite3",
        local_master_key_path=tmp_path / ".v9_local_master.key",
    )


def test_bootstrap_creates_owner_device_and_recovery_code(service):
    result = service.bootstrap_organization(
        name="Personal",
        owner_user_id="user-owner",
        device_name="Desktop",
    )

    assert result["role"] == "owner"
    assert result["recovery_code"]
    assert service.authorize(
        result["organization_id"], "user-owner", "organization.manage"
    )
    assert "recovery_code" not in json.dumps(
        service.repository.list_key_envelopes(result["organization_id"])
    )


def test_encrypted_record_is_not_plaintext_in_sqlite(service):
    boot = service.bootstrap_organization("Org", "owner", "Desktop")
    record = service.create_record(
        organization_id=boot["organization_id"],
        user_id="owner",
        device_id=boot["device_id"],
        record_type="evidence",
        content={"title": "敏感原文标题", "body": "敏感正文"},
    )

    raw = service.database_path.read_bytes()
    assert "敏感原文标题".encode("utf-8") not in raw
    assert "敏感正文".encode("utf-8") not in raw
    assert service.read_record(
        boot["organization_id"], "owner", record["record_id"]
    )["content"]["body"] == "敏感正文"


def test_cross_organization_read_is_denied(service):
    from v9.errors import PermissionDenied

    org_a = service.bootstrap_organization("A", "owner-a", "A desktop")
    org_b = service.bootstrap_organization("B", "owner-b", "B desktop")
    record = service.create_record(
        org_a["organization_id"],
        "owner-a",
        org_a["device_id"],
        "case",
        {"title": "A only"},
    )

    with pytest.raises(PermissionDenied):
        service.read_record(org_b["organization_id"], "owner-b", record["record_id"])


@pytest.mark.parametrize(
    ("role", "allowed", "denied"),
    [
        ("owner", "organization.manage", "none"),
        ("admin", "rules.manage", "publication.approve"),
        ("collector", "evidence.create", "case.analyze"),
        ("analyst", "case.analyze", "publication.approve"),
        ("editor", "document.edit", "publication.approve"),
        ("approver", "publication.approve", "member.manage"),
    ],
)
def test_six_role_permission_matrix(service, role, allowed, denied):
    from v9.rbac import role_allows

    assert role_allows(role, allowed)
    assert denied == "none" or not role_allows(role, denied)


def test_stale_write_preserves_conflict_and_does_not_overwrite(service):
    from v9.errors import VersionConflict

    boot = service.bootstrap_organization("Org", "owner", "Desktop")
    first = service.create_record(
        boot["organization_id"],
        "owner",
        boot["device_id"],
        "document",
        {"body": "v1"},
    )
    service.update_record(
        boot["organization_id"],
        "owner",
        boot["device_id"],
        first["record_id"],
        expected_version=1,
        content={"body": "v2"},
    )

    with pytest.raises(VersionConflict):
        service.update_record(
            boot["organization_id"],
            "owner",
            boot["device_id"],
            first["record_id"],
            expected_version=1,
            content={"body": "stale"},
        )

    current = service.read_record(
        boot["organization_id"], "owner", first["record_id"]
    )
    assert current["version"] == 2
    assert current["content"]["body"] == "v2"
    assert len(service.repository.list_conflicts(boot["organization_id"])) == 1


def test_outbox_retry_schedule_then_manual_intervention(service):
    boot = service.bootstrap_organization("Org", "owner", "Desktop")
    record = service.create_record(
        boot["organization_id"],
        "owner",
        boot["device_id"],
        "source",
        {"name": "source"},
    )
    event = service.repository.get_outbox_for_record(record["record_id"])[0]

    delays = []
    for _ in range(5):
        updated = service.repository.mark_outbox_failed(event["event_id"], "offline")
        delays.append(updated["retry_delay_seconds"])

    assert delays == [1, 5, 30, 120, 600]
    final = service.repository.mark_outbox_failed(event["event_id"], "still offline")
    assert final["state"] == "manual"
    assert final["attempts"] == 5


def test_revocation_rotates_org_key_and_excludes_revoked_device(service):
    boot = service.bootstrap_organization("Org", "owner", "Owner desktop")
    paired = service.add_device(
        boot["organization_id"], "owner", "owner", "Second desktop"
    )
    record = service.create_record(
        boot["organization_id"],
        "owner",
        boot["device_id"],
        "evidence",
        {"body": "survives rotation"},
    )

    result = service.revoke_device(
        boot["organization_id"], "owner", paired["device_id"]
    )

    assert result["key_version"] == 2
    envelopes = service.repository.list_key_envelopes(
        boot["organization_id"], key_version=2
    )
    assert {row["device_id"] for row in envelopes} == {boot["device_id"]}
    assert service.read_record(
        boot["organization_id"], "owner", record["record_id"]
    )["content"]["body"] == "survives rotation"


def test_device_pairing_envelope_can_only_be_opened_by_new_device(service):
    from v9.crypto import create_device_keypair, open_org_key_for_device

    boot = service.bootstrap_organization("Org", "owner", "Owner desktop")
    public_key, private_key = create_device_keypair()
    paired = service.pair_device(
        boot["organization_id"],
        "owner",
        "owner",
        "Remote desktop",
        public_key,
    )

    opened = open_org_key_for_device(private_key, paired["key_envelope"])
    assert len(opened) == 32
    assert "private_key" not in json.dumps(paired)


def test_recovery_code_restores_org_key_for_replacement_device(service):
    boot = service.bootstrap_organization("Org", "owner", "Desktop")

    replacement = service.recover_device(
        boot["organization_id"],
        "owner",
        "Replacement",
        boot["recovery_code"],
    )

    assert replacement["device_id"] != boot["device_id"]
    assert replacement["key_version"] == 1
    assert "recovery_code" not in replacement


def test_remote_sync_is_idempotent_and_never_carries_plaintext(service):
    boot = service.bootstrap_organization("Org", "owner", "Desktop")
    record = service.create_record(
        boot["organization_id"],
        "owner",
        boot["device_id"],
        "evidence",
        {"body": "cloud must not see this"},
    )
    event = service.export_outbox(boot["organization_id"])[0]
    serialized = json.dumps(event, ensure_ascii=False)
    assert "cloud must not see this" not in serialized

    with sqlite3.connect(service.database_path) as conn:
        conn.execute(
            "DELETE FROM sync_outbox WHERE record_id=?", (record["record_id"],)
        )
        conn.execute(
            "DELETE FROM encrypted_records WHERE record_id=?", (record["record_id"],)
        )
    first = service.apply_remote_event(
        boot["organization_id"], "owner", event, remote_cursor=10
    )
    second = service.apply_remote_event(
        boot["organization_id"], "owner", event, remote_cursor=10
    )

    assert first["state"] == "applied"
    assert second["state"] == "duplicate"
    assert service.read_record(
        boot["organization_id"], "owner", record["record_id"]
    )["content"]["body"] == "cloud must not see this"


def test_newer_remote_body_conflict_is_preserved_when_local_outbox_pending(service):
    boot = service.bootstrap_organization("Org", "owner", "Desktop")
    record = service.create_record(
        boot["organization_id"],
        "owner",
        boot["device_id"],
        "document",
        {"body": "local v1"},
    )
    local = service.repository.get_record(record["record_id"])
    remote = service.build_encrypted_payload(
        boot["organization_id"],
        boot["device_id"],
        record["record_id"],
        "document",
        2,
        {"body": "remote v2"},
    )
    event = {
        "event_id": "11111111-1111-4111-8111-111111111111",
        "organization_id": boot["organization_id"],
        "record_id": record["record_id"],
        "operation": "upsert",
        "payload": remote,
    }

    result = service.apply_remote_event(
        boot["organization_id"], "owner", event, remote_cursor=11
    )

    assert result["state"] == "conflict"
    assert service.repository.get_record(record["record_id"])["content_hash"] == local[
        "content_hash"
    ]
    assert len(service.repository.list_conflicts(boot["organization_id"])) == 1


def test_member_revocation_revokes_devices_and_rotates_key_once(service):
    boot = service.bootstrap_organization("Org", "owner", "Owner desktop")
    service.add_member(boot["organization_id"], "owner", "analyst-1", "analyst")
    analyst_device = service.add_device(
        boot["organization_id"], "owner", "analyst-1", "Analyst desktop"
    )

    result = service.revoke_member(
        boot["organization_id"], "owner", "analyst-1"
    )

    assert result["key_version"] == 2
    assert not service.repository.get_membership(
        boot["organization_id"], "analyst-1"
    )
    assert service.repository.get_device(analyst_device["device_id"])["status"] == "revoked"
    new_envelopes = service.repository.list_key_envelopes(
        boot["organization_id"], key_version=2
    )
    assert {item["device_id"] for item in new_envelopes} == {boot["device_id"]}


def test_failed_rotation_does_not_commit_device_revocation(service, monkeypatch):
    boot = service.bootstrap_organization("Org", "owner", "Owner desktop")
    paired = service.add_device(
        boot["organization_id"], "owner", "owner", "Second desktop"
    )

    def fail_rotation(*args, **kwargs):
        raise RuntimeError("simulated transaction failure")

    monkeypatch.setattr(
        service.repository, "apply_key_rotation", fail_rotation
    )
    with pytest.raises(RuntimeError):
        service.revoke_device(
            boot["organization_id"], "owner", paired["device_id"]
        )

    assert service.repository.get_device(paired["device_id"])["status"] == "active"
    assert service.repository.get_organization(
        boot["organization_id"]
    )["key_version"] == 1
