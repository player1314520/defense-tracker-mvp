import base64
import hashlib
import json
import os

import pytest
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import feishu_webhook_security as security


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
