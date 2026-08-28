import hashlib
import json
import time

import pytest

import app as tracker
import feishu_bot


class _FakePool:
    def __init__(self):
        self.submitted = []

    def submit(self, fn, *args):
        self.submitted.append((fn.__name__, args))


@pytest.fixture(autouse=True)
def _isolated_webhook_runtime(monkeypatch, tmp_path):
    monkeypatch.setenv("FEISHU_WEBHOOK_ALLOW_TOKEN_ONLY", "1")
    monkeypatch.setenv("FEISHU_DEDUPE_DB", str(tmp_path / "events.sqlite3"))


def _event_payload(token: str = "", *, production: bool = False, event_id: str = "evt-local") -> dict:
    header = {"event_type": "im.message.receive_v1", "token": token}
    payload = {
        "header": header,
        "event": {
            "message": {
                "chat_id": "oc_security_test",
                "message_id": "om_security_test",
                "message_type": "text",
                "content": json.dumps({"text": "帮助"}),
            }
        },
    }
    if production:
        payload["schema"] = "2.0"
        header.update({
            "event_id": event_id,
            "app_id": "cli_test",
            "tenant_key": "tenant_test",
        })
    return payload


def _signed_headers(body: bytes, key: str, *, timestamp: int | None = None) -> dict:
    timestamp = int(time.time()) if timestamp is None else timestamp
    nonce = "nonce-local-test"
    signature = hashlib.sha256((str(timestamp) + nonce + key).encode("utf-8") + body).hexdigest()
    return {
        "X-Lark-Request-Timestamp": str(timestamp),
        "X-Lark-Request-Nonce": nonce,
        "X-Lark-Signature": signature,
    }


def test_feishu_admin_routes_accept_short_session_not_raw_master_cookie(monkeypatch):
    monkeypatch.setattr(tracker, "AUTH_REQUIRED", True)
    monkeypatch.setattr(tracker, "ACCESS_TOKEN", "feishu-admin-master")
    monkeypatch.setattr(feishu_bot, "send_text", lambda *args, **kwargs: True)
    with tracker._AUTH_SESSION_LOCK:
        tracker._AUTH_SESSIONS.clear()
    client = tracker.app.test_client()

    login = client.post("/login", data={"token": "feishu-admin-master"})
    assert login.status_code == 302
    assert client.get("/api/feishu/config").status_code == 200

    csrf_cookie = client.get_cookie(tracker.CSRF_COOKIE)
    assert csrf_cookie is not None
    tested = client.post(
        "/api/feishu/test",
        json={"chat_id": "oc_security_test"},
        headers={tracker.CSRF_HEADER: csrf_cookie.value},
    )
    assert tested.status_code == 200

    legacy = tracker.app.test_client()
    legacy.set_cookie(tracker.AUTH_COOKIE, "feishu-admin-master")
    assert legacy.get("/api/feishu/config").status_code == 401


def test_local_feishu_webhook_fails_closed_without_token(monkeypatch):
    pool = _FakePool()
    monkeypatch.setitem(feishu_bot.FEISHU_CONFIG, "verify_token", "")
    monkeypatch.setattr(feishu_bot, "_worker_pool", pool)

    response = tracker.app.test_client().post(
        "/api/feishu/webhook", json=_event_payload()
    )

    assert response.status_code == 503
    assert pool.submitted == []


def test_local_feishu_webhook_accepts_matching_token_and_rejects_wrong(monkeypatch):
    pool = _FakePool()
    token = "local_verify_secret_xyz"
    monkeypatch.setitem(feishu_bot.FEISHU_CONFIG, "verify_token", token)
    monkeypatch.setattr(feishu_bot, "_worker_pool", pool)
    monkeypatch.setattr(feishu_bot, "send_text", lambda *args, **kwargs: True)
    client = tracker.app.test_client()

    rejected = client.post("/api/feishu/webhook", json=_event_payload("wrong"))
    accepted = client.post("/api/feishu/webhook", json=_event_payload(token))

    assert rejected.status_code == 403
    assert accepted.status_code == 200
    assert pool.submitted == []  # help command is handled synchronously


def test_local_feishu_submit_failure_returns_503_and_allows_retry(monkeypatch):
    token = "local_verify_secret_xyz"
    monkeypatch.setitem(feishu_bot.FEISHU_CONFIG, "verify_token", token)
    payload = _event_payload(token)
    payload["event"]["message"]["content"] = json.dumps(
        {"text": "https://example.com/news"}
    )

    class RejectingPool:
        def submit(self, _function, *_args):
            raise RuntimeError("executor stopped")

    monkeypatch.setattr(feishu_bot, "_worker_pool", RejectingPool())
    client = tracker.app.test_client()
    rejected = client.post("/api/feishu/webhook", json=payload)

    retry_pool = _FakePool()
    monkeypatch.setattr(feishu_bot, "_worker_pool", retry_pool)
    retried = client.post("/api/feishu/webhook", json=payload)

    assert rejected.status_code == 503
    assert retried.status_code == 200
    assert retry_pool.submitted == [
        ("_process_async", ("oc_security_test", "https://example.com/news"))
    ]


def test_local_feishu_url_verification_requires_matching_token(monkeypatch):
    token = "local_verify_secret_xyz"
    monkeypatch.setitem(feishu_bot.FEISHU_CONFIG, "verify_token", token)
    client = tracker.app.test_client()

    rejected = client.post(
        "/api/feishu/webhook",
        json={"type": "url_verification", "token": "wrong", "challenge": "abc"},
    )
    accepted = client.post(
        "/api/feishu/webhook",
        json={"type": "url_verification", "token": token, "challenge": "abc"},
    )

    assert rejected.status_code == 403
    assert accepted.status_code == 200
    assert accepted.get_json() == {"challenge": "abc"}


def test_local_feishu_rejects_bad_optional_signature(monkeypatch):
    token = "local_verify_secret_xyz"
    encrypt_key = "local_encrypt_key_xyz"
    monkeypatch.setitem(feishu_bot.FEISHU_CONFIG, "verify_token", token)
    monkeypatch.setitem(feishu_bot.FEISHU_CONFIG, "encrypt_key", encrypt_key)
    body = json.dumps(_event_payload(token)).encode("utf-8")
    now = int(time.time())
    response = tracker.app.test_client().post(
        "/api/feishu/webhook",
        data=body,
        content_type="application/json",
        headers={
            "X-Lark-Request-Timestamp": str(now),
            "X-Lark-Request-Nonce": "nonce",
            "X-Lark-Signature": hashlib.sha256(b"wrong").hexdigest(),
        },
    )

    assert response.status_code == 403


def test_local_feishu_production_requires_fresh_signature_and_identity(monkeypatch):
    monkeypatch.delenv("FEISHU_WEBHOOK_ALLOW_TOKEN_ONLY", raising=False)
    token = "local_verify_secret_xyz"
    encrypt_key = "local_encrypt_key_xyz"
    monkeypatch.setitem(feishu_bot.FEISHU_CONFIG, "verify_token", token)
    monkeypatch.setitem(feishu_bot.FEISHU_CONFIG, "encrypt_key", encrypt_key)
    monkeypatch.setitem(feishu_bot.FEISHU_CONFIG, "app_id", "cli_test")
    monkeypatch.setitem(feishu_bot.FEISHU_CONFIG, "tenant_key", "tenant_test")
    monkeypatch.setattr(feishu_bot, "send_text", lambda *args, **kwargs: True)
    payload = _event_payload(token, production=True)
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    client = tracker.app.test_client()

    unsigned = client.post("/api/feishu/webhook", data=body, content_type="application/json")
    accepted = client.post(
        "/api/feishu/webhook",
        data=body,
        content_type="application/json",
        headers=_signed_headers(body, encrypt_key),
    )

    assert unsigned.status_code == 403
    assert accepted.status_code == 200


def test_local_feishu_production_rejects_stale_signature_and_wrong_tenant(monkeypatch):
    monkeypatch.delenv("FEISHU_WEBHOOK_ALLOW_TOKEN_ONLY", raising=False)
    token = "local_verify_secret_xyz"
    encrypt_key = "local_encrypt_key_xyz"
    monkeypatch.setitem(feishu_bot.FEISHU_CONFIG, "verify_token", token)
    monkeypatch.setitem(feishu_bot.FEISHU_CONFIG, "encrypt_key", encrypt_key)
    monkeypatch.setitem(feishu_bot.FEISHU_CONFIG, "app_id", "cli_test")
    monkeypatch.setitem(feishu_bot.FEISHU_CONFIG, "tenant_key", "tenant_test")
    payload = _event_payload(token, production=True, event_id="evt-rejected")
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    client = tracker.app.test_client()

    stale = client.post(
        "/api/feishu/webhook",
        data=body,
        content_type="application/json",
        headers=_signed_headers(body, encrypt_key, timestamp=int(time.time()) - 301),
    )
    payload["header"]["tenant_key"] = "other-tenant"
    wrong_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    wrong_tenant = client.post(
        "/api/feishu/webhook",
        data=wrong_body,
        content_type="application/json",
        headers=_signed_headers(wrong_body, encrypt_key),
    )

    assert stale.status_code == 403
    assert wrong_tenant.status_code == 403
