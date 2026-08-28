import hashlib
import importlib
import json
import sys
import time

import pytest
import requests
import document_safety


@pytest.fixture(autouse=True)
def _isolated_webhook_runtime(monkeypatch, tmp_path):
    monkeypatch.setenv("FEISHU_WEBHOOK_ALLOW_TOKEN_ONLY", "1")
    monkeypatch.setenv("FEISHU_DEDUPE_DB", str(tmp_path / "events.sqlite3"))


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


def _text_webhook_payload(token=None, *, production=False, event_id="evt-cloud"):
    header = {"event_type": "im.message.receive_v1"}
    if token is not None:
        header["token"] = token
    payload = {
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
    if production:
        payload["schema"] = "2.0"
        header.update({
            "event_id": event_id,
            "app_id": "cli_test",
            "tenant_key": "tenant_test",
        })
    return payload


def _signed_headers(body, key, *, timestamp=None):
    timestamp = int(time.time()) if timestamp is None else timestamp
    nonce = "nonce-cloud-test"
    signature = hashlib.sha256((str(timestamp) + nonce + key).encode("utf-8") + body).hexdigest()
    return {
        "X-Lark-Request-Timestamp": str(timestamp),
        "X-Lark-Request-Nonce": nonce,
        "X-Lark-Signature": signature,
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
    submitted = _fake_pool(monkeypatch, cloud)

    client = cloud.app.test_client()
    resp = client.post("/api/feishu/webhook", json=_text_webhook_payload(token="WRONG"))

    assert resp.status_code == 403
    # 鉴权失败绝不能触发任何后台处理（防伪造请求刷接口/耗 AI 配额）
    assert submitted == []


def test_feishu_webhook_accepts_correct_verify_token(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    cloud.app.config["TESTING"] = True
    submitted = _fake_pool(monkeypatch, cloud)

    client = cloud.app.test_client()
    resp = client.post("/api/feishu/webhook", json=_text_webhook_payload(token="verify_secret_xyz"))

    assert resp.status_code == 200
    assert len(submitted) == 1
    assert submitted[0][0] == "_process_async"


def test_feishu_cloud_submit_failure_returns_503_and_allows_retry(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    cloud.app.config["TESTING"] = True

    class RejectingPool:
        def submit(self, _function, *_args):
            raise RuntimeError("executor stopped")

    monkeypatch.setattr(cloud, "_worker_pool", RejectingPool())
    payload = _text_webhook_payload(token="verify_secret_xyz")
    client = cloud.app.test_client()
    rejected = client.post("/api/feishu/webhook", json=payload)

    submitted = _fake_pool(monkeypatch, cloud)
    retried = client.post("/api/feishu/webhook", json=payload)

    assert rejected.status_code == 503
    assert retried.status_code == 200
    assert submitted == [("_process_async", ("oc_test", "https://example.com/news"))]


def test_feishu_webhook_enforces_signature_when_present(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    cloud.app.config["TESTING"] = True
    submitted = _fake_pool(monkeypatch, cloud)
    client = cloud.app.test_client()

    encrypt_key = "encrypt_key_xyz"
    monkeypatch.setitem(cloud.FEISHU_CONFIG, "encrypt_key", encrypt_key)
    body = json.dumps(_text_webhook_payload(token="verify_secret_xyz")).encode("utf-8")
    ts, nonce = str(int(time.time())), "nonce_abc"
    good_sig = hashlib.sha256((ts + nonce + encrypt_key).encode("utf-8") + body).hexdigest()
    sig_headers = {"X-Lark-Request-Timestamp": ts, "X-Lark-Request-Nonce": nonce}

    # 带签名头但签名错误 → 403，且不触发后台处理
    bad = client.post(
        "/api/feishu/webhook", data=body, content_type="application/json",
        headers={**sig_headers, "X-Lark-Signature": "deadbeef"},
    )
    assert bad.status_code == 403
    assert submitted == []

    # 正确签名 → 200 + 恰好处理一次
    ok = client.post(
        "/api/feishu/webhook", data=body, content_type="application/json",
        headers={**sig_headers, "X-Lark-Signature": good_sig},
    )
    assert ok.status_code == 200
    assert len(submitted) == 1


def test_feishu_cloud_production_requires_signature_app_and_tenant(monkeypatch):
    monkeypatch.delenv("FEISHU_WEBHOOK_ALLOW_TOKEN_ONLY", raising=False)
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    cloud.app.config["TESTING"] = True
    encrypt_key = "encrypt_key_xyz"
    monkeypatch.setitem(cloud.FEISHU_CONFIG, "encrypt_key", encrypt_key)
    monkeypatch.setitem(cloud.FEISHU_CONFIG, "tenant_key", "tenant_test")
    submitted = _fake_pool(monkeypatch, cloud)
    payload = _text_webhook_payload("verify_secret_xyz", production=True)
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    client = cloud.app.test_client()

    unsigned = client.post("/api/feishu/webhook", data=body, content_type="application/json")
    accepted = client.post(
        "/api/feishu/webhook",
        data=body,
        content_type="application/json",
        headers=_signed_headers(body, encrypt_key),
    )

    assert unsigned.status_code == 403
    assert accepted.status_code == 200
    assert len(submitted) == 1


def test_feishu_cloud_production_rejects_stale_and_cross_tenant_events(monkeypatch):
    monkeypatch.delenv("FEISHU_WEBHOOK_ALLOW_TOKEN_ONLY", raising=False)
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    encrypt_key = "encrypt_key_xyz"
    monkeypatch.setitem(cloud.FEISHU_CONFIG, "encrypt_key", encrypt_key)
    monkeypatch.setitem(cloud.FEISHU_CONFIG, "tenant_key", "tenant_test")
    submitted = _fake_pool(monkeypatch, cloud)
    payload = _text_webhook_payload(
        "verify_secret_xyz", production=True, event_id="evt-cloud-rejected",
    )
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    client = cloud.app.test_client()

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
    assert submitted == []


def test_feishu_webhook_deduplicates_message(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    cloud.app.config["TESTING"] = True
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


def test_feishu_cloud_docx_parser_reuses_container_preflight(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")

    with pytest.raises(document_safety.DocumentSafetyError) as exc:
        cloud._extract_docx_text(b"not-a-docx")

    assert exc.value.code == "DOCX_BAD_MAGIC"


def test_legacy_history_endpoint_does_not_expose_items(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    cloud._history[:] = [{"brief_preview": "sensitive"}]

    response = cloud.app.test_client().get("/api/history")

    assert response.status_code == 404
    assert "sensitive" not in response.get_data(as_text=True)


def test_legacy_sessions_are_memory_only(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")

    assert cloud._SESSION_STORE == ""
