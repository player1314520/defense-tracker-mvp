import hashlib
import importlib
import json
import sys


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
    cloud = _load_feishu_cloud(monkeypatch)
    cloud.app.config["TESTING"] = True
    cloud._seen_msg_ids.clear()
    submitted = []

    class FakePool:
        def submit(self, fn, *args):
            submitted.append((fn.__name__, args))

    monkeypatch.setattr(cloud, "_worker_pool", FakePool())

    payload = {
        "header": {"event_type": "im.message.receive_v1"},
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
