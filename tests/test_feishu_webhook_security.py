import base64
import hashlib
import json
import os
import threading

import pytest
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import feishu_webhook_security as security


def _actor_payload(
    *,
    chat_id: str = "oc-allowed",
    open_id: str = "ou-allowed",
    user_id: str = "user-allowed",
    union_id: str = "on-allowed",
) -> dict:
    return {
        "event": {
            "sender": {
                "sender_id": {
                    "open_id": open_id,
                    "user_id": user_id,
                    "union_id": union_id,
                },
            },
            "message": {"chat_id": chat_id},
        },
    }


def _signed_headers(body: bytes, key: str, timestamp: int) -> dict[str, str]:
    nonce = "nonce-for-security-test"
    signature = hashlib.sha256((str(timestamp) + nonce + key).encode("utf-8") + body).hexdigest()
    return {
        "X-Lark-Request-Timestamp": str(timestamp),
        "X-Lark-Request-Nonce": nonce,
        "X-Lark-Signature": signature,
    }


def _encrypt_payload(payload: dict, key: str) -> dict:
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    iv = os.urandom(16)
    encryptor = Cipher(
        algorithms.AES(hashlib.sha256(key.encode("utf-8")).digest()),
        modes.CBC(iv),
    ).encryptor()
    ciphertext = iv + encryptor.update(padded) + encryptor.finalize()
    return {"encrypt": base64.b64encode(ciphertext).decode("ascii")}


def test_signature_requires_fresh_timestamp_and_encrypt_key(monkeypatch):
    monkeypatch.setenv("FEISHU_WEBHOOK_MAX_SKEW_SECONDS", "300")
    body = b'{"schema":"2.0"}'
    key = "event-encrypt-key"
    now = 1_800_000_000

    security.verify_signed_request(
        _signed_headers(body, key, now), body, signing_key=key, now=now,
    )

    with pytest.raises(security.WebhookRejected) as stale:
        security.verify_signed_request(
            _signed_headers(body, key, now - 301), body, signing_key=key, now=now,
        )
    assert stale.value.code == "signature_timestamp_stale"

    with pytest.raises(security.WebhookMisconfigured) as no_key:
        security.verify_signed_request({}, body, signing_key="", now=now)
    assert no_key.value.code == "signature_key_not_configured"


def test_token_only_mode_requires_explicit_opt_in(monkeypatch):
    monkeypatch.delenv("FEISHU_WEBHOOK_ALLOW_TOKEN_ONLY", raising=False)
    with pytest.raises(security.WebhookMisconfigured):
        security.verify_signed_request({}, b"{}", signing_key="")

    monkeypatch.setenv("FEISHU_WEBHOOK_ALLOW_TOKEN_ONLY", "1")
    security.verify_signed_request({}, b"{}", signing_key="")


def test_encrypted_event_round_trip_and_tamper_rejection():
    key = "event-encrypt-key"
    payload = {"schema": "2.0", "header": {"event_id": "evt-1"}, "event": {}}

    encrypted = _encrypt_payload(payload, key)
    assert security.decrypt_event_payload(encrypted, encrypt_key=key) == payload

    encrypted["encrypt"] = encrypted["encrypt"][:-3] + "AAA"
    with pytest.raises(security.WebhookRejected):
        security.decrypt_event_payload(encrypted, encrypt_key=key)


def test_event_identity_binds_schema_app_and_tenant():
    payload = {
        "schema": "2.0",
        "header": {"app_id": "cli-app", "tenant_key": "tenant-1"},
    }
    security.validate_event_identity(
        payload,
        expected_app_id="cli-app",
        expected_tenant_key="tenant-1",
        allow_legacy=False,
    )

    payload["header"]["tenant_key"] = "other-tenant"
    with pytest.raises(security.WebhookRejected) as mismatch:
        security.validate_event_identity(
            payload,
            expected_app_id="cli-app",
            expected_tenant_key="tenant-1",
            allow_legacy=False,
        )
    assert mismatch.value.code == "event_tenant_mismatch"


def test_actor_identity_is_canonical_and_authorized_by_explicit_allowlists(monkeypatch):
    monkeypatch.setenv("FEISHU_ALLOWED_SENDER_IDS", "open_id:ou-allowed")
    monkeypatch.setenv("FEISHU_ALLOWED_CHAT_IDS", "oc-other")
    monkeypatch.setenv("FEISHU_ADMIN_SENDER_IDS", "user_id:user-allowed")
    monkeypatch.delenv("FEISHU_AUTH_ALLOW_UNLISTED_DEV", raising=False)

    actor = security.authorize_event_actor(_actor_payload())

    assert actor.sender_ids == (
        "open_id:ou-allowed",
        "user_id:user-allowed",
        "union_id:on-allowed",
    )
    assert actor.primary_sender == "open_id:ou-allowed"
    assert actor.chat_id == "oc-allowed"
    assert actor.is_admin is True


def test_actor_authorization_fails_closed_for_missing_or_unlisted_identity(monkeypatch):
    monkeypatch.setenv("FEISHU_ALLOWED_SENDER_IDS", "open_id:ou-allowed")
    monkeypatch.delenv("FEISHU_ALLOWED_CHAT_IDS", raising=False)
    monkeypatch.delenv("FEISHU_ADMIN_SENDER_IDS", raising=False)
    monkeypatch.delenv("FEISHU_AUTH_ALLOW_UNLISTED_DEV", raising=False)

    missing_sender = _actor_payload()
    del missing_sender["event"]["sender"]
    with pytest.raises(security.WebhookRejected) as missing:
        security.authorize_event_actor(missing_sender)
    assert missing.value.code == "event_sender_missing"

    with pytest.raises(security.WebhookRejected) as denied:
        security.authorize_event_actor(_actor_payload(open_id="ou-denied"))
    assert denied.value.code == "event_actor_not_allowed"


def test_actor_authorization_requires_configuration_outside_explicit_development(monkeypatch):
    for name in (
        "FEISHU_ALLOWED_SENDER_IDS",
        "FEISHU_ALLOWED_CHAT_IDS",
        "FEISHU_ADMIN_SENDER_IDS",
        "FEISHU_WEBHOOK_ALLOW_TOKEN_ONLY",
        "FEISHU_AUTH_ALLOW_UNLISTED_DEV",
    ):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(security.WebhookMisconfigured) as missing:
        security.authorize_event_actor(_actor_payload())
    assert missing.value.code == "authorization_allowlist_not_configured"

    with pytest.raises(security.WebhookMisconfigured):
        security.authorize_event_actor(
            _actor_payload(), allow_unlisted_development=True,
        )

    monkeypatch.setenv("FEISHU_WEBHOOK_ALLOW_TOKEN_ONLY", "1")
    monkeypatch.setenv("FEISHU_AUTH_ALLOW_UNLISTED_DEV", "1")
    actor = security.authorize_event_actor(_actor_payload(open_id="ou-dev"))
    assert actor.primary_sender == "open_id:ou-dev"
    assert actor.is_admin is False


def test_admin_authorization_never_inherits_chat_or_development_access(monkeypatch):
    monkeypatch.setenv("FEISHU_ALLOWED_CHAT_IDS", "oc-allowed")
    monkeypatch.delenv("FEISHU_ALLOWED_SENDER_IDS", raising=False)
    monkeypatch.delenv("FEISHU_ADMIN_SENDER_IDS", raising=False)
    monkeypatch.setenv("FEISHU_WEBHOOK_ALLOW_TOKEN_ONLY", "1")
    monkeypatch.setenv("FEISHU_AUTH_ALLOW_UNLISTED_DEV", "1")

    with pytest.raises(security.WebhookRejected) as denied:
        security.authorize_event_actor(_actor_payload(), require_admin=True)
    assert denied.value.code == "event_admin_required"


def test_authorization_rejects_ambiguous_or_malformed_allowlist_entries(monkeypatch):
    monkeypatch.setenv("FEISHU_ALLOWED_SENDER_IDS", "ou-raw-without-kind")
    monkeypatch.delenv("FEISHU_ALLOWED_CHAT_IDS", raising=False)
    monkeypatch.delenv("FEISHU_ADMIN_SENDER_IDS", raising=False)

    with pytest.raises(security.WebhookMisconfigured) as malformed:
        security.authorize_event_actor(_actor_payload())
    assert malformed.value.code == "invalid_authorization_allowlist"


def test_admission_limits_are_atomic_under_concurrent_pressure():
    actor = security.WebhookActor(
        sender_ids=("open_id:ou-allowed",),
        chat_id="oc-allowed",
        is_admin=False,
    )
    limits = security.WebhookAdmissionLimits(
        window_seconds=60,
        sender_events=100,
        chat_events=100,
        global_events=100,
        sender_cost=100,
        chat_cost=100,
        global_cost=100,
        max_inflight=3,
    )
    controller = security.WebhookAdmissionController(limits, clock=lambda: 1000.0)
    barrier = threading.Barrier(12)
    leases = []
    failures = []
    result_lock = threading.Lock()

    def attempt():
        barrier.wait()
        try:
            result = controller.acquire(actor, cost=1)
        except security.WebhookCapacityUnavailable as exc:
            with result_lock:
                failures.append(exc.code)
        else:
            with result_lock:
                leases.append(result)

    threads = [threading.Thread(target=attempt) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert all(not thread.is_alive() for thread in threads)
    assert len(leases) == 3
    assert failures == ["webhook_capacity_exhausted"] * 9
    assert controller.inflight == 3

    for lease in leases:
        lease.release()
    assert controller.inflight == 0


def test_admission_enforces_sender_chat_and_global_rate_and_cost_independently():
    limits = security.WebhookAdmissionLimits(
        window_seconds=60,
        sender_events=2,
        chat_events=3,
        global_events=4,
        sender_cost=3,
        chat_cost=5,
        global_cost=7,
        max_inflight=10,
    )
    controller = security.WebhookAdmissionController(limits, clock=lambda: 1000.0)
    first = security.WebhookActor(("open_id:ou-one",), "oc-one", False)
    second = security.WebhookActor(("open_id:ou-two",), "oc-one", False)

    lease = controller.acquire(first, cost=2)
    lease.release()
    with pytest.raises(security.WebhookRateLimited) as sender_cost:
        controller.acquire(first, cost=2)
    assert sender_cost.value.code == "sender_cost_limit"

    lease = controller.acquire(second, cost=2)
    lease.release()
    with pytest.raises(security.WebhookRateLimited) as chat_cost:
        controller.acquire(
            security.WebhookActor(("open_id:ou-three",), "oc-one", False),
            cost=2,
        )
    assert chat_cost.value.code == "chat_cost_limit"

    other = security.WebhookActor(("open_id:ou-four",), "oc-two", False)
    lease = controller.acquire(other, cost=2)
    lease.release()
    with pytest.raises(security.WebhookRateLimited) as global_cost:
        controller.acquire(
            security.WebhookActor(("open_id:ou-five",), "oc-three", False),
            cost=2,
        )
    assert global_cost.value.code == "global_cost_limit"


def test_admission_lease_release_is_idempotent_and_capacity_is_reusable():
    actor = security.WebhookActor(("open_id:ou-one",), "oc-one", False)
    limits = security.WebhookAdmissionLimits(
        window_seconds=60,
        sender_events=10,
        chat_events=10,
        global_events=10,
        sender_cost=10,
        chat_cost=10,
        global_cost=10,
        max_inflight=1,
    )
    controller = security.WebhookAdmissionController(limits, clock=lambda: 1000.0)

    first = controller.acquire(actor, cost=1)
    with pytest.raises(security.WebhookCapacityUnavailable):
        controller.acquire(actor, cost=1)
    assert first.release() is True
    assert first.release() is False
    second = controller.acquire(actor, cost=1)
    assert second.release() is True


def test_admission_counts_every_signed_sender_namespace_against_identity_variation():
    limits = security.WebhookAdmissionLimits(
        window_seconds=60,
        sender_events=1,
        chat_events=10,
        global_events=10,
        sender_cost=10,
        chat_cost=10,
        global_cost=10,
        max_inflight=10,
    )
    controller = security.WebhookAdmissionController(limits, clock=lambda: 1000.0)
    complete_identity = security.WebhookActor(
        ("open_id:ou-one", "user_id:user-one", "union_id:on-one"),
        "oc-one",
        False,
    )
    alternate_representation = security.WebhookActor(
        ("user_id:user-one",),
        "oc-two",
        False,
    )

    lease = controller.acquire(complete_identity, cost=1)
    lease.release()
    with pytest.raises(security.WebhookRateLimited) as limited:
        controller.acquire(alternate_representation, cost=1)
    assert limited.value.code == "sender_rate_limit"


def test_persistent_deduper_survives_new_instance_and_expires(tmp_path):
    path = tmp_path / "runtime" / "events.sqlite3"
    first_process = security.PersistentEventDeduper(path, ttl_seconds=300, max_entries=1000)
    second_process = security.PersistentEventDeduper(path, ttl_seconds=300, max_entries=1000)

    assert first_process.check_and_record("evt-persistent", now=1000) is True
    assert second_process.check_and_record("evt-persistent", now=1001) is False
    assert second_process.check_and_record("evt-persistent", now=1401) is True

    raw = path.read_bytes()
    assert b"evt-persistent" not in raw


def test_event_lease_blocks_inflight_and_completed_duplicates(tmp_path):
    path = tmp_path / "runtime" / "leases.sqlite3"
    first_process = security.PersistentEventDeduper(
        path, ttl_seconds=300, max_entries=1000, lease_seconds=30,
    )
    second_process = security.PersistentEventDeduper(
        path, ttl_seconds=300, max_entries=1000, lease_seconds=30,
    )

    lease = first_process.acquire("evt-leased", now=1000)
    assert lease is not None
    assert second_process.acquire("evt-leased", now=1001) is None

    assert lease.complete(now=1002) is True
    assert second_process.acquire("evt-leased", now=1003) is None


def test_expired_lease_can_be_taken_over_without_stale_completion(tmp_path):
    path = tmp_path / "runtime" / "takeover.sqlite3"
    first_process = security.PersistentEventDeduper(
        path, ttl_seconds=300, max_entries=1000, lease_seconds=30,
    )
    second_process = security.PersistentEventDeduper(
        path, ttl_seconds=300, max_entries=1000, lease_seconds=30,
    )

    stale_lease = first_process.acquire("evt-takeover", now=1000)
    replacement_lease = second_process.acquire("evt-takeover", now=1030)

    assert stale_lease is not None
    assert replacement_lease is not None
    assert stale_lease.complete(now=1031) is False
    assert replacement_lease.complete(now=1032) is True
    assert first_process.acquire("evt-takeover", now=1033) is None


def test_expired_lease_does_not_exhaust_store_capacity(tmp_path):
    store = security.PersistentEventDeduper(
        tmp_path / "runtime" / "capacity.sqlite3",
        ttl_seconds=300,
        max_entries=1,
        lease_seconds=30,
    )
    stale = store.acquire("evt-stale", now=1000)
    replacement = store.acquire("evt-new", now=1030)

    assert stale is not None
    assert replacement is not None
    assert stale.complete(now=1031) is False
    assert replacement.complete(now=1032) is True


def test_submit_failure_releases_lease_for_retry(tmp_path):
    path = tmp_path / "runtime" / "submit-failure.sqlite3"
    store = security.PersistentEventDeduper(
        path, ttl_seconds=300, max_entries=1000, lease_seconds=30,
    )
    lease = store.acquire("evt-submit-failure", now=1000)
    assert lease is not None

    class RejectingExecutor:
        def submit(self, _function, *_args, **_kwargs):
            raise RuntimeError("executor unavailable")

    with pytest.raises(security.WebhookMisconfigured) as exc:
        security.submit_leased_event(RejectingExecutor(), lease, lambda: None)

    assert exc.value.code == "event_dispatch_unavailable"
    assert store.acquire("evt-submit-failure", now=1001) is not None


def test_worker_failure_releases_handed_off_lease(tmp_path):
    path = tmp_path / "runtime" / "worker-failure.sqlite3"
    store = security.PersistentEventDeduper(
        path, ttl_seconds=300, max_entries=1000, lease_seconds=30,
    )
    lease = store.acquire("evt-worker-failure", now=1000)
    assert lease is not None

    class DeferredExecutor:
        task = None

        def submit(self, function, *args, **kwargs):
            self.task = lambda: function(*args, **kwargs)
            return object()

    executor = DeferredExecutor()

    def fail_processing():
        raise RuntimeError("processing failed")

    security.submit_leased_event(executor, lease, fail_processing)
    with pytest.raises(RuntimeError, match="processing failed"):
        executor.task()

    assert store.acquire("evt-worker-failure", now=1001) is not None


def test_default_dedupe_store_rejects_source_tree(monkeypatch):
    source_store = security.Path(security.__file__).resolve().parent / "unsafe.sqlite3"
    monkeypatch.setenv("FEISHU_DEDUPE_DB", str(source_store))

    with pytest.raises(security.WebhookMisconfigured) as exc:
        security.resolve_dedupe_store_path()

    assert exc.value.code == "dedupe_store_must_not_be_in_source_tree"
