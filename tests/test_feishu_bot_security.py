import hashlib
import json

import app as tracker
import feishu_bot


class _FakePool:
    def __init__(self):
        self.submitted = []

    def submit(self, fn, *args):
        self.submitted.append((fn.__name__, args))


def _event_payload(token: str = "") -> dict:
    return {
        "header": {"event_type": "im.message.receive_v1", "token": token},
        "event": {
            "message": {
                "chat_id": "oc_security_test",
                "message_id": "om_security_test",
                "message_type": "text",
                "content": json.dumps({"text": "帮助"}),
            }
        },
    }


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
    feishu_bot._seen_msg_ids.clear()
    client = tracker.app.test_client()

    rejected = client.post("/api/feishu/webhook", json=_event_payload("wrong"))
    accepted = client.post("/api/feishu/webhook", json=_event_payload(token))

    assert rejected.status_code == 403
    assert accepted.status_code == 200
    assert pool.submitted == []  # help command is handled synchronously


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
    monkeypatch.setitem(feishu_bot.FEISHU_CONFIG, "verify_token", token)
    body = json.dumps(_event_payload(token)).encode("utf-8")
    response = tracker.app.test_client().post(
        "/api/feishu/webhook",
        data=body,
        content_type="application/json",
        headers={
            "X-Lark-Request-Timestamp": "1700000000",
            "X-Lark-Request-Nonce": "nonce",
            "X-Lark-Signature": hashlib.sha256(b"wrong").hexdigest(),
        },
    )

    assert response.status_code == 403
