import hashlib
import importlib
import json
import sys

import pytest
import requests


def _load_feishu_cloud(monkeypatch):
    monkeypatch.setenv("FEISHU_APP_ID", "cli_test")
    monkeypatch.setenv("FEISHU_APP_SECRET", "secret_test")
    monkeypatch.delenv("FEISHU_VERIFY_TOKEN", raising=False)
    monkeypatch.delenv("FEISHU_PUSH_CHAT_ID", raising=False)
    sys.modules.pop("feishu_cloud", None)
    return importlib.import_module("feishu_cloud")


def test_feishu_cloud_ssrf_rejects_private_dns(monkeypatch):
    cloud = _load_feishu_cloud(monkeypatch)
    monkeypatch.setattr(
        cloud.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, "", ("192.168.1.2", 80))],
    )
    safe, reason = cloud._is_ssrf_safe("https://example.test/news")
    assert safe is False
    assert "私有" in reason


def _load_feishu_cloud_with_token(monkeypatch, token):
    monkeypatch.setenv("FEISHU_APP_ID", "cli_test")
    monkeypatch.setenv("FEISHU_APP_SECRET", "secret_test")
    monkeypatch.setenv("FEISHU_VERIFY_TOKEN", token)
    monkeypatch.delenv("FEISHU_PUSH_CHAT_ID", raising=False)
    sys.modules.pop("feishu_cloud", None)
    return importlib.import_module("feishu_cloud")


def _text_webhook_payload(token=None):
    header = {"event_type": "im.message.receive_v1"}
    if token is not None:
        header["token"] = token
    return {
        "header": header,
        "event": {
            "message": {
                "chat_id": "oc_test",
                "chat_type": "p2p",
                "message_id": "om_auth_test",
                "message_type": "text",
                "content": json.dumps({"text": "https://example.com/news"}),
            }
        },
    }


def _fake_pool(monkeypatch, cloud):
    submitted = []

    class FakePool:
        def submit(self, fn, *args):
            submitted.append((fn.__name__, args))

    monkeypatch.setattr(cloud, "_worker_pool", FakePool())
    return submitted


def test_feishu_webhook_rejects_wrong_verify_token(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    cloud.app.config["TESTING"] = True
    cloud._seen_msg_ids.clear()
    submitted = _fake_pool(monkeypatch, cloud)

    client = cloud.app.test_client()
    resp = client.post("/api/feishu/webhook", json=_text_webhook_payload(token="WRONG"))

    assert resp.status_code == 403
    # 鉴权失败绝不能触发任何后台处理（防伪造请求刷接口/耗 AI 配额）
    assert submitted == []


def test_feishu_webhook_accepts_correct_verify_token(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    cloud.app.config["TESTING"] = True
    cloud._seen_msg_ids.clear()
    submitted = _fake_pool(monkeypatch, cloud)

    client = cloud.app.test_client()
    resp = client.post("/api/feishu/webhook", json=_text_webhook_payload(token="verify_secret_xyz"))

    assert resp.status_code == 200
    assert len(submitted) == 1
    assert submitted[0][0] == "_process_async"


def test_feishu_webhook_enforces_signature_when_present(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    cloud.app.config["TESTING"] = True
    submitted = _fake_pool(monkeypatch, cloud)
    client = cloud.app.test_client()

    body = json.dumps(_text_webhook_payload(token="verify_secret_xyz")).encode("utf-8")
    ts, nonce = "1700000000", "nonce_abc"
    good_sig = hashlib.sha256((ts + nonce + "verify_secret_xyz").encode("utf-8") + body).hexdigest()
    sig_headers = {"X-Lark-Request-Timestamp": ts, "X-Lark-Request-Nonce": nonce}

    # 带签名头但签名错误 → 403，且不触发后台处理
    cloud._seen_msg_ids.clear()
    bad = client.post(
        "/api/feishu/webhook", data=body, content_type="application/json",
        headers={**sig_headers, "X-Lark-Signature": "deadbeef"},
    )
    assert bad.status_code == 403
    assert submitted == []

    # 正确签名 → 200 + 恰好处理一次
    cloud._seen_msg_ids.clear()
    ok = client.post(
        "/api/feishu/webhook", data=body, content_type="application/json",
        headers={**sig_headers, "X-Lark-Signature": good_sig},
    )
    assert ok.status_code == 200
    assert len(submitted) == 1


def test_feishu_webhook_deduplicates_message(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    cloud.app.config["TESTING"] = True
    cloud._seen_msg_ids.clear()
    submitted = []

    class FakePool:
        def submit(self, fn, *args):
            submitted.append((fn.__name__, args))

    monkeypatch.setattr(cloud, "_worker_pool", FakePool())

    payload = {
        "header": {
            "event_type": "im.message.receive_v1",
            "token": "verify_secret_xyz",
        },
        "event": {
            "message": {
                "chat_id": "oc_test",
                "chat_type": "p2p",
                "message_id": "om_test",
                "message_type": "text",
                "content": json.dumps({"text": "https://example.com/news"}),
            }
        },
    }

    client = cloud.app.test_client()
    first = client.post("/api/feishu/webhook", json=payload)
    second = client.post("/api/feishu/webhook", json=payload)

    assert first.status_code == 200
    assert second.status_code == 200
    assert len(submitted) == 1
    assert submitted[0][0] == "_process_async"


def test_feishu_webhook_fails_closed_without_verify_token(monkeypatch):
    cloud = _load_feishu_cloud(monkeypatch)
    cloud.app.config["TESTING"] = True
    submitted = _fake_pool(monkeypatch, cloud)

    response = cloud.app.test_client().post(
        "/api/feishu/webhook", json=_text_webhook_payload()
    )

    assert response.status_code == 503
    assert submitted == []


def test_feishu_url_verification_requires_matching_token(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    client = cloud.app.test_client()

    rejected = client.post(
        "/api/feishu/webhook",
        json={"type": "url_verification", "token": "wrong", "challenge": "abc"},
    )
    accepted = client.post(
        "/api/feishu/webhook",
        json={
            "type": "url_verification",
            "token": "verify_secret_xyz",
            "challenge": "abc",
        },
    )

    assert rejected.status_code == 403
    assert accepted.status_code == 200
    assert accepted.get_json() == {"challenge": "abc"}


def test_feishu_cloud_rejects_private_connected_peer(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    response = requests.Response()
    response.status_code = 200
    response._content = b""
    response._content_consumed = True
    monkeypatch.setattr(cloud, "_connected_peer_ip", lambda _response: "10.0.0.8")

    with pytest.raises(requests.RequestException, match="重绑定到私有地址"):
        cloud._validate_connected_peer(response)


def test_feishu_cloud_rss_uses_ssrf_safe_transport(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    response = requests.Response()
    response.status_code = 200
    response._content = b"<rss/>"
    response._content_consumed = True
    calls = []

    def fake_safe_get(url, *, headers, timeout, max_bytes=cloud.MAX_FETCH_BYTES):
        calls.append((url, headers, timeout, max_bytes))
        return response

    monkeypatch.setattr(cloud, "_safe_get_once", fake_safe_get)
    monkeypatch.setattr(
        cloud.requests,
        "get",
        lambda *args, **kwargs: pytest.fail("RSS must not bypass the SSRF-safe transport"),
    )
    monkeypatch.setattr(cloud.feedparser, "parse", lambda _content: type("Feed", (), {"entries": []})())

    feed = {
        "url": "https://example.test/feed.xml",
        "name": "Example",
        "name_cn": "示例",
        "focus": "test",
    }
    assert cloud._fetch_one_feed(feed) == []
    assert calls == [(feed["url"], cloud._BROWSER_HEADERS, 12, cloud.MAX_FETCH_BYTES)]


def test_legacy_history_endpoint_does_not_expose_items(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    cloud._history[:] = [{"brief_preview": "sensitive"}]

    response = cloud.app.test_client().get("/api/history")

    assert response.status_code == 404
    assert "sensitive" not in response.get_data(as_text=True)


def test_legacy_sessions_are_memory_only(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")

    assert cloud._SESSION_STORE == ""
