# -*- coding: utf-8 -*-
import base64
import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest


def _service(tmp_path):
    from v9.service import V9Service

    service = V9Service(tmp_path / "v9.sqlite3", tmp_path / ".master")
    return service, service.get_or_create_personal_context()


def test_pkce_uses_s256_and_keeps_verifier_client_side():
    from v9.cloud import create_pkce_request

    request = create_pkce_request(
        "https://project.supabase.co",
        "defensetracker://auth/callback",
    )
    query = parse_qs(urlparse(request["authorization_url"]).query)
    digest = hashlib.sha256(request["code_verifier"].encode()).digest()
    expected = base64.urlsafe_b64encode(digest).decode().rstrip("=")

    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"] == [expected]
    assert query["state"] == [request["state"]]
    assert request["code_verifier"] not in request["authorization_url"]


def test_ciphertext_boundary_rejects_plaintext_at_any_depth(tmp_path):
    from v9.cloud import validate_ciphertext_event

    service, context = _service(tmp_path)
    service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "evidence",
        {"body": "never reaches cloud"},
    )
    event = service.export_outbox(context["organization_id"])[0]
    validated = validate_ciphertext_event(event)
    assert validated["event_id"] == event["event_id"]
    assert "never reaches cloud" not in json.dumps(validated)

    forged = json.loads(json.dumps(event))
    forged["payload"]["metadata"] = {"body": "leak"}
    with pytest.raises(ValueError, match="明文"):
        validate_ciphertext_event(forged)
    disguised = json.loads(json.dumps(event))
    disguised["payload"]["metadata"] = {"summary": "leak"}
    with pytest.raises(ValueError, match="unsupported fields"):
        validate_ciphertext_event(disguised)


def test_ciphertext_boundary_accepts_explicit_initial_snapshot_events(tmp_path):
    from v9.cloud import validate_ciphertext_event

    service, context = _service(tmp_path)
    service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "evidence",
        {"body": "legacy encrypted body"},
    )
    for event in service.export_outbox(context["organization_id"]):
        service.repository.mark_outbox_sent(event["event_id"])
    service.queue_initial_snapshot(
        context["organization_id"], context["user_id"]
    )

    event = service.export_outbox(context["organization_id"])[0]
    assert validate_ciphertext_event(event)["operation"] == "snapshot"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("nonce", base64.urlsafe_b64encode(b"n" * 11).decode().rstrip("=")),
        (
            "wrapped_data_key",
            base64.urlsafe_b64encode(b"k" * 47).decode().rstrip("="),
        ),
        (
            "wrap_nonce",
            base64.urlsafe_b64encode(b"w" * 13).decode().rstrip("="),
        ),
        (
            "ciphertext",
            base64.urlsafe_b64encode(b"c" * 16).decode().rstrip("="),
        ),
        ("nonce", "abcd="),
    ),
)
def test_ciphertext_boundary_rejects_invalid_aes_gcm_field_shapes(
    tmp_path, field, value
):
    from v9.cloud import validate_ciphertext_event

    service, context = _service(tmp_path)
    service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "evidence",
        {"title": "shape contract"},
    )
    event = service.export_outbox(context["organization_id"])[0]
    event["payload"][field] = value

    with pytest.raises(ValueError):
        validate_ciphertext_event(event)


def test_one_time_pairing_code_is_single_use(tmp_path):
    from v9.crypto import create_device_keypair, open_org_key_for_device

    service, owner = _service(tmp_path)
    session = service.create_pairing_session(
        owner,
        target_user_id=owner["user_id"],
        device_name="Second desktop",
        ttl_seconds=120,
    )
    public_key, private_key = create_device_keypair()
    claimed = service.claim_pairing_session(
        session["pairing_code"], public_key
    )
    opened = open_org_key_for_device(
        private_key, claimed["key_envelope"]
    )

    assert len(opened) == 32
    assert "pairing_code" not in json.dumps(claimed)
    with pytest.raises(ValueError, match="已使用|无效"):
        service.claim_pairing_session(session["pairing_code"], public_key)


def test_sync_cycle_marks_outbox_sent_without_logging_plaintext(tmp_path):
    from v9.cloud import run_sync_cycle

    service, context = _service(tmp_path)
    service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "document",
        {"body": "offline private draft"},
    )

    class Coordinator:
        def __init__(self):
            self.events = []

        def push(self, event):
            self.events.append({"cursor": len(self.events) + 1, **event})
            return {"cursor": len(self.events)}

        def pull(self, organization_id, after_cursor):
            return [
                event for event in self.events
                if event["organization_id"] == organization_id
                and event["cursor"] > after_cursor
            ]

    coordinator = Coordinator()
    result = run_sync_cycle(service, context, coordinator)

    assert result == {
        "pushed": 1,
        "pulled": 1,
        "applied": 0,
        "duplicates": 1,
        "conflicts": 0,
        "quarantined": 0,
        "failed": 0,
        "cursor": 1,
        "unresolved_quarantine": 0,
        "degraded": False,
    }
    assert service.export_outbox(context["organization_id"]) == []
    assert "offline private draft" not in json.dumps(coordinator.events)


def test_authenticated_poison_event_is_quarantined_without_blocking_successor(
    tmp_path,
):
    import uuid

    from v9.cloud import run_sync_cycle

    service, context = _service(tmp_path)
    poisoned_record_id = str(uuid.uuid4())
    poisoned_payload = service.build_encrypted_payload(
        context["organization_id"],
        context["device_id"],
        poisoned_record_id,
        "evidence",
        1,
        {"title": "poisoned"},
    )
    poisoned_ciphertext = bytearray(base64.urlsafe_b64decode(
        poisoned_payload["ciphertext"] + "=="
    ))
    poisoned_ciphertext[-1] ^= 1
    poisoned_payload["ciphertext"] = base64.urlsafe_b64encode(
        bytes(poisoned_ciphertext)
    ).decode("ascii").rstrip("=")
    valid_record_id = str(uuid.uuid4())
    valid_payload = service.build_encrypted_payload(
        context["organization_id"],
        context["device_id"],
        valid_record_id,
        "evidence",
        1,
        {"title": "valid successor"},
    )
    events = [
        {
            "cursor": 11,
            "event_id": str(uuid.uuid4()),
            "organization_id": context["organization_id"],
            "record_id": poisoned_record_id,
            "operation": "upsert",
            "payload": poisoned_payload,
        },
        {
            "cursor": 12,
            "event_id": str(uuid.uuid4()),
            "organization_id": context["organization_id"],
            "record_id": valid_record_id,
            "operation": "upsert",
            "payload": valid_payload,
        },
    ]

    class Coordinator:
        def push(self, _event):
            raise AssertionError("outbox is empty")

        def pull(self, organization_id, after_cursor):
            assert organization_id == context["organization_id"]
            assert after_cursor == 0
            return events

    result = run_sync_cycle(service, context, Coordinator())

    assert result["quarantined"] == 1
    assert result["applied"] == 1
    assert result["failed"] == 0
    assert result["cursor"] == 12
    assert result["unresolved_quarantine"] == 1
    assert result["degraded"] is True
    assert service.repository.get_record(poisoned_record_id) is None
    assert not service.repository.has_sync_event(events[0]["event_id"])
    assert service.read_record(
        context["organization_id"],
        context["user_id"],
        valid_record_id,
    )["content"]["title"] == "valid successor"
    quarantined = service.repository.list_sync_quarantine(
        context["organization_id"]
    )
    assert quarantined[0]["event_id"] == events[0]["event_id"]
    assert quarantined[0]["reason"] == "ciphertext_authentication_failed"
    assert len(quarantined[0]["event_hash"]) == 64
    assert "ciphertext" not in quarantined[0]


def test_structurally_invalid_event_is_quarantined_without_persisting_payload(
    tmp_path,
):
    import uuid

    from v9.cloud import run_sync_cycle

    service, context = _service(tmp_path)
    invalid_record_id = str(uuid.uuid4())
    invalid_payload = service.build_encrypted_payload(
        context["organization_id"],
        context["device_id"],
        invalid_record_id,
        "evidence",
        1,
        {"title": "invalid nonce"},
    )
    invalid_payload["nonce"] = base64.urlsafe_b64encode(
        b"x" * 11
    ).decode("ascii").rstrip("=")

    class Coordinator:
        def push(self, _event):
            raise AssertionError("outbox is empty")

        def pull(self, _organization_id, _after_cursor):
            return [{
                "cursor": 7,
                "event_id": str(uuid.uuid4()),
                "organization_id": context["organization_id"],
                "record_id": invalid_record_id,
                "operation": "upsert",
                "payload": invalid_payload,
            }]

    result = run_sync_cycle(service, context, Coordinator())
    with service.repository._connect() as conn:
        stored = conn.execute(
            """
            SELECT encrypted_event_json FROM sync_quarantine
            WHERE organization_id=? AND remote_cursor=7
            """,
            (context["organization_id"],),
        ).fetchone()

    assert result["quarantined"] == 1
    assert result["cursor"] == 7
    assert stored["encrypted_event_json"] is None


def test_out_of_order_cursor_page_fails_before_any_event_is_applied(tmp_path):
    import uuid

    from v9.cloud import run_sync_cycle

    service, context = _service(tmp_path)
    events = []
    for cursor in (12, 14, 13):
        record_id = str(uuid.uuid4())
        events.append({
            "cursor": cursor,
            "event_id": str(uuid.uuid4()),
            "organization_id": context["organization_id"],
            "record_id": record_id,
            "operation": "upsert",
            "payload": service.build_encrypted_payload(
                context["organization_id"],
                context["device_id"],
                record_id,
                "evidence",
                1,
                {"cursor": cursor},
            ),
        })

    class Coordinator:
        def push(self, _event):
            raise AssertionError("outbox is empty")

        def pull(self, _organization_id, _after_cursor):
            return events

    result = run_sync_cycle(service, context, Coordinator())

    assert result["failed"] == 1
    assert result["cursor"] == 0
    assert all(
        service.repository.get_record(event["record_id"]) is None
        for event in events
    )


def test_quarantine_audit_and_cursor_update_are_atomic(tmp_path):
    import sqlite3
    import uuid

    service, context = _service(tmp_path)
    with service.repository._connect() as conn:
        conn.execute(
            """
            CREATE TRIGGER fail_quarantine_audit
            BEFORE INSERT ON sync_quarantine_audit
            BEGIN
                SELECT RAISE(ABORT, 'simulated audit failure');
            END
            """
        )

    with pytest.raises(sqlite3.IntegrityError):
        service.repository.quarantine_sync_event(
            organization_id=context["organization_id"],
            remote_cursor=6,
            event_id=str(uuid.uuid4()),
            record_id=str(uuid.uuid4()),
            operation="upsert",
            reason="ciphertext_authentication_failed",
            event_hash="a" * 64,
            event_bytes=128,
            encrypted_event_json="{}",
        )

    assert service.repository.list_sync_quarantine(
        context["organization_id"]
    ) == []
    assert service.repository.get_sync_cursor(context["organization_id"]) == 0


def test_missing_local_rotation_key_stops_without_quarantine_or_cursor_advance(
    tmp_path,
):
    import uuid

    from v9.cloud import run_sync_cycle

    service, context = _service(tmp_path)
    record_id = str(uuid.uuid4())
    payload = service.build_encrypted_payload(
        context["organization_id"],
        context["device_id"],
        record_id,
        "evidence",
        1,
        {"title": "future key"},
    )
    payload["key_version"] = 99

    class Coordinator:
        def push(self, _event):
            raise AssertionError("outbox is empty")

        def pull(self, _organization_id, _after_cursor):
            return [{
                "cursor": 8,
                "event_id": str(uuid.uuid4()),
                "organization_id": context["organization_id"],
                "record_id": record_id,
                "operation": "upsert",
                "payload": payload,
            }]

    result = run_sync_cycle(service, context, Coordinator())

    assert result["failed"] == 1
    assert result["quarantined"] == 0
    assert result["cursor"] == 0
    assert result["degraded"] is False


def test_push_applied_false_freezes_record_without_acknowledging_cloud_head(
    tmp_path,
):
    from v9.cloud import run_sync_cycle

    service, context = _service(tmp_path)
    record = service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "document",
        {"body": "local branch"},
    )

    class Coordinator:
        def push(self, event):
            return {
                "cursor": 27,
                "duplicate": False,
                "applied": False,
                "head_version_id": (
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
                ),
            }

        def pull(self, organization_id, after_cursor):
            return []

    result = run_sync_cycle(service, context, Coordinator())
    rows = service.repository.get_outbox_for_record(record["record_id"])

    assert result["pushed"] == 1
    assert result["conflicts"] == 1
    assert result["failed"] == 0
    assert rows[0]["state"] == "conflict"
    assert service.repository.get_record(
        record["record_id"]
    )["cloud_version_id"] is None
    with pytest.raises(ValueError, match="blocked pending conflict"):
        service.update_record(
            context["organization_id"],
            context["user_id"],
            context["device_id"],
            record["record_id"],
            expected_version=1,
            content={"body": "must wait for manual merge"},
        )


def test_outbox_uses_uuid_version_ids_and_explicit_base_version(tmp_path):
    service, context = _service(tmp_path)
    first = service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "document",
        {"body": "v1"},
    )
    first_event = service.export_outbox(context["organization_id"])[0]
    service.update_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        first["record_id"],
        expected_version=1,
        content={"body": "v2"},
    )
    events = service.export_outbox(context["organization_id"])

    import uuid

    assert all(str(uuid.UUID(event["event_id"])) == event["event_id"] for event in events)
    assert all(
        str(uuid.UUID(event["payload"]["version_id"]))
        == event["payload"]["version_id"]
        for event in events
    )
    assert first_event["payload"]["base_version_id"] is None
    assert events[1]["payload"]["base_version_id"] == events[0]["payload"]["version_id"]


def test_cloud_bootstrap_preserves_local_ids_and_contains_no_plaintext_names(tmp_path):
    import uuid

    service, context = _service(tmp_path)
    cloud_context = service.prepare_cloud_bootstrap_context(
        context, str(uuid.uuid4())
    )
    payload = service.build_cloud_bootstrap(cloud_context)
    serialized = json.dumps(payload)

    assert payload["requested_organization_id"] == context["organization_id"]
    assert payload["device_id"] == cloud_context["device_id"]
    assert payload["device_id"] != context["device_id"]
    assert payload["key_algorithm"] == "p256"
    assert "个人工作区" not in serialized
    assert "本机桌面" not in serialized


def test_supabase_coordinator_maps_rpc_rows_to_ciphertext_events():
    from v9.cloud import SupabaseCoordinator

    class Manager:
        def __init__(self):
            self.calls = []

        def rpc(self, name, payload):
            self.calls.append((name, payload))
            if name == "push_record_event":
                return {"cursor": 9, "applied": True}
            return [{
                "cursor": 9,
                "event_id": "11111111-1111-4111-8111-111111111111",
                "operation": "upsert",
                "applied": True,
                "payload": {
                    "organization_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "record_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                },
            }]

    manager = Manager()
    coordinator = SupabaseCoordinator(manager)
    pushed = coordinator.push({"event_id": "event"})
    pulled = coordinator.pull(
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", 0
    )

    assert pushed["cursor"] == 9
    assert manager.calls[0] == (
        "push_record_event",
        {"p_event": {"event_id": "event"}},
    )
    assert pulled[0]["organization_id"] == pulled[0]["payload"]["organization_id"]
    assert pulled[0]["record_id"] == pulled[0]["payload"]["record_id"]
    assert pulled[0]["applied"] is True


def test_supabase_backlog_advances_one_bounded_page_per_sync_cycle(tmp_path):
    import uuid

    from v9.cloud import SupabaseCoordinator, run_sync_cycle

    service, context = _service(tmp_path)
    record_id = "aaaaaaaa-bbbb-4aaa-8aaa-aaaaaaaaaaaa"
    payload = service.build_encrypted_payload(
        context["organization_id"],
        context["device_id"],
        record_id,
        "document",
        1,
        {"body": "bounded remote page"},
    )

    class Manager:
        def __init__(self):
            self.calls = []
            self.rows = [
                {
                    "cursor": cursor,
                    "event_id": str(uuid.UUID(int=cursor)),
                    "operation": "upsert",
                    "applied": True,
                    "payload": payload,
                }
                for cursor in range(1, 206)
            ]

        def rpc(self, name, request):
            assert name == "pull_sync_events"
            self.calls.append(dict(request))
            after_cursor = int(request["after_cursor"])
            page_size = int(request["page_size"])
            return [
                row for row in self.rows
                if row["cursor"] > after_cursor
            ][:page_size]

    manager = Manager()
    coordinator = SupabaseCoordinator(manager, page_size=2)
    assert len(manager.rows) > 100 * coordinator.page_size

    first = run_sync_cycle(service, context, coordinator)

    assert first["failed"] == 0
    assert first["pulled"] == 2
    assert first["cursor"] == 2
    assert len(manager.calls) == 1
    assert manager.calls[0]["after_cursor"] == 0

    second = run_sync_cycle(service, context, coordinator)

    assert second["failed"] == 0
    assert second["pulled"] == 2
    assert second["cursor"] == 4
    assert len(manager.calls) == 2
    assert manager.calls[1]["after_cursor"] == 2


def test_upload_ack_does_not_skip_unapplied_remote_events(tmp_path):
    from v9.cloud import run_sync_cycle

    service, context = _service(tmp_path)
    service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "document",
        {"body": "outbound"},
    )

    class PullFailure:
        def push(self, event):
            return {"cursor": 17}

        def pull(self, organization_id, after_cursor):
            assert after_cursor == 0
            raise ConnectionError("offline")

    result = run_sync_cycle(service, context, PullFailure())
    assert result["pushed"] == 1
    assert result["failed"] == 1
    assert result["cursor"] == 0
    assert service.repository.get_sync_cursor(context["organization_id"]) == 0


def test_pull_quarantines_invalid_event_and_classifies_later_cursor(tmp_path):
    from v9.cloud import run_sync_cycle

    service, context = _service(tmp_path)
    first_record_id = "11111111-2222-4111-8111-111111111111"
    second_record_id = "22222222-3333-4222-8222-222222222222"
    first_payload = service.build_encrypted_payload(
        context["organization_id"],
        context["device_id"],
        first_record_id,
        "document",
        1,
        {"body": "first remote version"},
    )
    second_payload = service.build_encrypted_payload(
        context["organization_id"],
        context["device_id"],
        second_record_id,
        "document",
        1,
        {"body": "second remote version"},
    )
    tampered_first = json.loads(json.dumps(first_payload))
    ciphertext = bytearray(
        base64.urlsafe_b64decode(tampered_first["ciphertext"] + "==")
    )
    ciphertext[-1] ^= 1
    tampered_first["ciphertext"] = (
        base64.urlsafe_b64encode(ciphertext).decode().rstrip("=")
    )

    class Coordinator:
        def __init__(self):
            self.after_cursors = []

        def push(self, event):
            raise AssertionError("test has no outbound events")

        def pull(self, organization_id, after_cursor):
            self.after_cursors.append(after_cursor)
            events = [
                {
                    "cursor": 1,
                    "event_id": "33333333-4444-4333-8333-333333333333",
                    "organization_id": organization_id,
                    "record_id": first_record_id,
                    "operation": "upsert",
                    "payload": tampered_first,
                },
                {
                    "cursor": 2,
                    "event_id": "44444444-5555-4444-8444-444444444444",
                    "organization_id": organization_id,
                    "record_id": second_record_id,
                    "operation": "upsert",
                    "payload": second_payload,
                },
            ]
            return [
                event for event in events
                if event["cursor"] > after_cursor
            ]

    coordinator = Coordinator()
    first_result = run_sync_cycle(service, context, coordinator)

    assert first_result["pulled"] == 2
    assert first_result["quarantined"] == 1
    assert first_result["failed"] == 0
    assert first_result["applied"] == 1
    assert first_result["cursor"] == 2
    assert service.repository.get_sync_cursor(
        context["organization_id"]
    ) == 2
    assert service.repository.has_sync_event(
        "44444444-5555-4444-8444-444444444444"
    )
    assert service.repository.get_record(first_record_id) is None
    assert service.repository.get_record(second_record_id) is not None

    second_result = run_sync_cycle(service, context, coordinator)

    assert coordinator.after_cursors == [0, 2]
    assert second_result["pulled"] == 0
    assert second_result["applied"] == 0
    assert second_result["failed"] == 0
    assert second_result["cursor"] == 2
    assert second_result["degraded"] is True


def test_two_devices_offline_conflict_is_preserved_then_revocation_rotates(tmp_path):
    service, owner = _service(tmp_path)
    second = service.add_device(
        owner["organization_id"],
        owner["user_id"],
        owner["user_id"],
        "Offline desktop",
    )
    record = service.create_record(
        owner["organization_id"],
        owner["user_id"],
        owner["device_id"],
        "document",
        {"body": "device one"},
    )
    remote_payload = service.build_encrypted_payload(
        owner["organization_id"],
        second["device_id"],
        record["record_id"],
        "document",
        2,
        {"body": "device two offline edit"},
    )
    result = service.apply_remote_event(
        owner["organization_id"],
        owner["user_id"],
        {
            "event_id": "22222222-2222-4222-8222-222222222222",
            "organization_id": owner["organization_id"],
            "record_id": record["record_id"],
            "operation": "upsert",
            "payload": remote_payload,
        },
        remote_cursor=9,
    )

    assert result["state"] == "conflict"
    assert len(service.list_conflicts(
        owner["organization_id"], owner["user_id"]
    )) == 1
    revoked = service.revoke_device(
        owner["organization_id"], owner["user_id"], second["device_id"]
    )
    assert revoked["key_version"] == 2
    assert service.repository.get_device(second["device_id"])["status"] == "revoked"


@pytest.mark.parametrize("tamper", ["ciphertext", "content_hash"])
def test_remote_ciphertext_must_decrypt_and_hash_match_before_head_or_cursor_moves(
    tmp_path, tamper
):
    from v9.errors import UntrustedSyncEvent

    service, context = _service(tmp_path)
    local = service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "document",
        {"body": "trusted local head"},
    )
    payload = service.build_encrypted_payload(
        context["organization_id"],
        context["device_id"],
        local["record_id"],
        "document",
        2,
        {"body": "remote version"},
    )
    if tamper == "ciphertext":
        raw = bytearray(base64.urlsafe_b64decode(payload["ciphertext"] + "=="))
        raw[-1] ^= 1
        payload["ciphertext"] = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        expected_reason = "ciphertext_authentication_failed"
    else:
        payload["content_hash"] = "0" * 64
        expected_reason = "content_integrity_failed"

    with pytest.raises(UntrustedSyncEvent) as caught:
        service.apply_remote_event(
            context["organization_id"],
            context["user_id"],
            {
                "event_id": "33333333-3333-4333-8333-333333333333",
                "organization_id": context["organization_id"],
                "record_id": local["record_id"],
                "operation": "upsert",
                "payload": payload,
            },
            remote_cursor=12,
        )
    assert caught.value.reason == expected_reason

    assert service.read_record(
        context["organization_id"],
        context["user_id"],
        local["record_id"],
    )["version"] == 1
    assert service.repository.get_sync_cursor(context["organization_id"]) == 0
    assert not service.repository.has_sync_event(
        "33333333-3333-4333-8333-333333333333"
    )


def test_unapplied_remote_branch_is_a_conflict_and_never_advances_head(tmp_path):
    service, context = _service(tmp_path)
    local = service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "document",
        {"body": "current head"},
    )
    for event in service.export_outbox(context["organization_id"]):
        service.repository.mark_outbox_sent(event["event_id"])
    payload = service.build_encrypted_payload(
        context["organization_id"],
        context["device_id"],
        local["record_id"],
        "document",
        2,
        {"body": "server preserved conflict branch"},
    )

    result = service.apply_remote_event(
        context["organization_id"],
        context["user_id"],
        {
            "event_id": "44444444-4444-4444-8444-444444444444",
            "organization_id": context["organization_id"],
            "record_id": local["record_id"],
            "operation": "upsert",
            "applied": False,
            "payload": payload,
        },
        remote_cursor=13,
    )

    assert result["state"] == "conflict"
    assert service.read_record(
        context["organization_id"],
        context["user_id"],
        local["record_id"],
    )["version"] == 1
    assert service.repository.get_sync_cursor(context["organization_id"]) == 13
    assert len(service.list_conflicts(
        context["organization_id"], context["user_id"]
    )) == 1


def test_unapplied_remote_branch_without_local_head_is_preserved_not_created(
    tmp_path,
):
    service, context = _service(tmp_path)
    record_id = "55555555-5555-4555-8555-555555555555"
    payload = service.build_encrypted_payload(
        context["organization_id"],
        context["device_id"],
        record_id,
        "document",
        1,
        {"body": "remote-only conflict branch"},
    )

    result = service.apply_remote_event(
        context["organization_id"],
        context["user_id"],
        {
            "event_id": "66666666-6666-4666-8666-666666666666",
            "organization_id": context["organization_id"],
            "record_id": record_id,
            "operation": "upsert",
            "applied": False,
            "payload": payload,
        },
        remote_cursor=14,
    )

    assert result["state"] == "conflict"
    assert service.repository.get_record(record_id) is None
    assert service.repository.get_sync_cursor(context["organization_id"]) == 14


def test_initial_snapshot_queue_is_explicit_idempotent_and_keeps_ciphertext(
    tmp_path,
):
    service, context = _service(tmp_path)
    records = [
        service.create_record(
            context["organization_id"],
            context["user_id"],
            context["device_id"],
            "document",
            {"body": f"legacy-{index}"},
        )
        for index in range(2)
    ]
    original_rows = {
        record["record_id"]: service.repository.get_record(record["record_id"])
        for record in records
    }
    for event in service.export_outbox(context["organization_id"]):
        service.repository.mark_outbox_sent(event["event_id"])

    assert service.export_outbox(context["organization_id"]) == []
    first = service.queue_initial_snapshot(
        context["organization_id"], context["user_id"]
    )
    snapshot_events = service.export_outbox(context["organization_id"])
    second = service.queue_initial_snapshot(
        context["organization_id"], context["user_id"]
    )

    assert first == {
        "queued": 2,
        "already_queued": 0,
        "skipped_pending": 0,
        "requeued": 0,
    }
    assert second == {
        "queued": 0,
        "already_queued": 2,
        "skipped_pending": 0,
        "requeued": 0,
    }
    assert len(snapshot_events) == 2
    assert {event["operation"] for event in snapshot_events} == {"snapshot"}
    for event in snapshot_events:
        original = original_rows[event["record_id"]]
        assert event["payload"]["version"] == original["version"]
        assert (
            base64.urlsafe_b64decode(event["payload"]["ciphertext"] + "==")
            == original["ciphertext"]
        )
        assert event["payload"]["base_version_id"] is None
        assert service.repository.get_record(event["record_id"])["ciphertext"] == (
            original["ciphertext"]
        )


def test_initial_snapshot_blocks_entire_batch_when_any_local_edit_is_unsent(
    tmp_path,
):
    service, context = _service(tmp_path)
    ready = service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "document",
        {"body": "legacy sent"},
    )
    pending = service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "document",
        {"body": "not sent yet"},
    )
    for event in service.export_outbox(context["organization_id"]):
        if event["record_id"] == ready["record_id"]:
            service.repository.mark_outbox_sent(event["event_id"])

    with pytest.raises(ValueError, match="blocked by 1 unsent"):
        service.queue_initial_snapshot(
            context["organization_id"], context["user_id"]
        )

    assert not any(
        event["operation"] == "snapshot"
        for event in service.export_outbox(context["organization_id"])
    )
    assert service.repository.get_record(ready["record_id"]) is not None
    assert service.repository.get_record(pending["record_id"]) is not None


def test_edit_queued_after_legacy_snapshot_uses_snapshot_as_cloud_base(tmp_path):
    service, context = _service(tmp_path)
    record = service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "document",
        {"body": "legacy head"},
    )
    original = service.export_outbox(context["organization_id"])[0]
    service.repository.mark_outbox_sent(original["event_id"])

    service.queue_initial_snapshot(
        context["organization_id"], context["user_id"]
    )
    snapshot = service.export_outbox(context["organization_id"])[0]
    service.update_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        record["record_id"],
        expected_version=1,
        content={"body": "new edit after snapshot staging"},
    )
    events = service.export_outbox(context["organization_id"])
    update = next(event for event in events if event["operation"] == "upsert")

    assert snapshot["payload"]["version_id"] != original["payload"]["version_id"]
    assert update["payload"]["base_version_id"] == snapshot["payload"]["version_id"]


def test_initial_snapshot_queues_6091_ciphertext_heads_without_rewriting(tmp_path):
    from v9.repository import V9Repository

    repository = V9Repository(tmp_path / "scale.sqlite3")
    organization_id = "77777777-7777-4777-8777-777777777777"
    user_id = "88888888-8888-4888-8888-888888888888"
    device_id = "99999999-9999-4999-8999-999999999999"
    repository.create_organization(organization_id, "synthetic")
    repository.add_membership(organization_id, user_id, "owner")
    repository.add_device(
        device_id, organization_id, user_id, "synthetic", b"public"
    )
    rows = []
    for index in range(6091):
        rows.append(
            (
                f"record-{index:05d}",
                organization_id,
                "evidence",
                (index % 7) + 1,
                None,
                device_id,
                f"ciphertext-{index:05d}".encode(),
                b"n" * 12,
                b"wrapped-key",
                b"w" * 12,
                1,
                hashlib.sha256(f"plain-{index}".encode()).hexdigest(),
                f"2026-07-26T00:00:{index % 60:02d}+00:00",
                0,
            )
        )
    with repository._connect() as conn:
        conn.executemany(
            """
            INSERT INTO encrypted_records(
                record_id,organization_id,record_type,version,cloud_version_id,
                device_id,ciphertext,nonce,wrapped_data_key,wrap_nonce,
                key_version,content_hash,updated_at,deleted
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            rows,
        )
        before = conn.execute(
            """
            SELECT COUNT(*) AS count,SUM(LENGTH(ciphertext)) AS bytes
            FROM encrypted_records WHERE organization_id=?
            """,
            (organization_id,),
        ).fetchone()

    result = repository.queue_initial_snapshot(organization_id)

    with repository._connect() as conn:
        after = conn.execute(
            """
            SELECT COUNT(*) AS count,SUM(LENGTH(ciphertext)) AS bytes
            FROM encrypted_records WHERE organization_id=?
            """,
            (organization_id,),
        ).fetchone()
        snapshot_count = conn.execute(
            """
            SELECT COUNT(*) FROM sync_outbox
            WHERE organization_id=? AND operation='snapshot'
            """,
            (organization_id,),
        ).fetchone()[0]
    assert result == {
        "queued": 6091,
        "already_queued": 0,
        "skipped_pending": 0,
        "requeued": 0,
    }
    assert snapshot_count == 6091
    assert tuple(before) == tuple(after) == (6091, sum(
        len(f"ciphertext-{index:05d}".encode()) for index in range(6091)
    ))


def test_explicit_snapshot_call_requeues_manual_failure_with_same_event_id(
    tmp_path,
):
    service, context = _service(tmp_path)
    record = service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "document",
        {"body": "legacy"},
    )
    for event in service.export_outbox(context["organization_id"]):
        service.repository.mark_outbox_sent(event["event_id"])
    service.queue_initial_snapshot(
        context["organization_id"], context["user_id"]
    )
    snapshot = service.export_outbox(context["organization_id"])[0]
    for _ in range(6):
        service.repository.mark_outbox_failed(
            snapshot["event_id"], "synthetic offline"
        )
    assert service.repository.get_outbox_for_record(record["record_id"])[-1][
        "state"
    ] == "manual"

    result = service.queue_initial_snapshot(
        context["organization_id"], context["user_id"]
    )
    requeued = service.export_outbox(context["organization_id"])[0]

    assert result == {
        "queued": 0,
        "already_queued": 0,
        "skipped_pending": 0,
        "requeued": 1,
    }
    assert requeued["event_id"] == snapshot["event_id"]


def test_cloud_rejected_outbox_is_atomic_conflict_and_freezes_record(tmp_path):
    service, context = _service(tmp_path)
    record = service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "document",
        {"body": "cloud head"},
    )
    initial = service.export_outbox(context["organization_id"])[0]
    service.repository.mark_outbox_sent(initial["event_id"])
    service.update_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        record["record_id"],
        expected_version=1,
        content={"body": "conflicting local branch"},
    )
    outgoing = service.export_outbox(context["organization_id"])[0]

    result = service.repository.mark_outbox_conflicted(
        outgoing["event_id"], remote_cursor=33
    )

    outbox = service.repository.get_outbox_for_record(record["record_id"])
    assert result["state"] == "conflict"
    assert outbox[-1]["state"] == "conflict"
    assert service.repository.get_record(record["record_id"])[
        "cloud_version_id"
    ] == outgoing["payload"]["base_version_id"]
    assert service.repository.get_sync_cursor(context["organization_id"]) == 0
    with pytest.raises(ValueError, match="blocked pending conflict"):
        service.update_record(
            context["organization_id"],
            context["user_id"],
            context["device_id"],
            record["record_id"],
            expected_version=2,
            content={"body": "must wait for manual merge"},
        )


def test_rejected_snapshot_never_becomes_cloud_head_and_blocks_requeue(tmp_path):
    service, context = _service(tmp_path)
    record = service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "document",
        {"body": "legacy"},
    )
    original = service.export_outbox(context["organization_id"])[0]
    service.repository.mark_outbox_sent(original["event_id"])
    prior_cloud_version = service.repository.get_record(record["record_id"])[
        "cloud_version_id"
    ]
    service.queue_initial_snapshot(
        context["organization_id"], context["user_id"]
    )
    snapshot = service.export_outbox(context["organization_id"])[0]

    service.repository.mark_outbox_conflicted(
        snapshot["event_id"], remote_cursor=34
    )

    assert service.repository.get_record(record["record_id"])[
        "cloud_version_id"
    ] == prior_cloud_version
    assert service.repository.get_outbox_for_record(record["record_id"])[-1][
        "state"
    ] == "conflict"
    with pytest.raises(ValueError, match="unresolved cloud conflict"):
        service.queue_initial_snapshot(
            context["organization_id"], context["user_id"]
        )


def test_snapshot_import_session_sql_is_owner_gated_resumable_and_manifest_bound():
    migration = (
        Path(__file__).parents[1]
        / "supabase"
        / "migrations"
        / "202607260011_v9_snapshot_import_session.sql"
    ).read_text(encoding="utf-8")
    compact = " ".join(migration.lower().split())
    push_migration = (
        Path(__file__).parents[1]
        / "supabase"
        / "migrations"
        / "202607260009_v9_push_idempotency.sql"
    ).read_text(encoding="utf-8")
    push_compact = " ".join(push_migration.lower().split())

    assert "create table private.snapshot_imports" in compact
    assert "create table private.snapshot_import_items" in compact
    assert (
        "create or replace function public.begin_snapshot_import("
        in compact
    )
    assert (
        "create or replace function public.complete_snapshot_import("
        in compact
    )
    assert (
        "create or replace function public.abort_snapshot_import("
        in compact
    )
    assert "if not private.is_org_owner(organization_id)" in compact
    assert "for update" in compact
    assert "snapshot import manifest mismatch" in compact
    assert compact.index("status = 'staging'") < compact.index(
        "select exists ( select 1 from public.record_heads"
    )
    assert "before insert on public.sync_events" in compact
    assert "new.operation <> 'snapshot'" in compact
    assert "snapshot import blocks non-snapshot writes" in compact
    assert "new.applied is not true" in compact
    assert "snapshot import capacity exceeded" in compact
    assert "new.event_id" in compact
    assert "new.record_id" in compact
    assert "new.version_id" in compact
    assert "v.content_hash" in compact
    assert "string_agg(" in compact
    assert "e'\\n'" in migration.lower()
    assert "extensions.digest(" in compact
    assert "snapshot import manifest hash mismatch" in compact
    assert "snapshot import head count mismatch" in compact
    assert "snapshot import head set mismatch" in compact
    assert "accepted snapshot import cannot be aborted" in compact
    assert "if target.status = 'aborted' then" in compact
    assert "key rotation in progress" in compact
    assert "create trigger key_rotations_block_snapshot" in compact
    assert "snapshot import in progress" in compact
    org_lock = push_compact.index(
        "from public.organizations o where o.id = org_id for share"
    )
    head_lock = push_compact.index(
        "select * into current_head from public.record_heads h"
    )
    assert org_lock < head_lock
    assert (
        "revoke all on function private.capture_snapshot_import_item()"
        in compact
    )
    assert (
        "grant execute on function public.begin_snapshot_import("
        in compact
    )
    assert (
        "grant execute on function public.complete_snapshot_import("
        in compact
    )
    assert (
        "grant execute on function public.abort_snapshot_import("
        in compact
    )
