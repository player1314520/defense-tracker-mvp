import hashlib
import importlib
import json
import logging
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
    monkeypatch.delenv("AI_ALLOWED_HOSTS", raising=False)
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
    monkeypatch.delenv("AI_ALLOWED_HOSTS", raising=False)
    sys.modules.pop("feishu_cloud", None)
    return importlib.import_module("feishu_cloud")


def _text_webhook_payload(
    token=None,
    *,
    production=False,
    event_id="evt-cloud",
    text="https://example.com/news",
):
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
                "content": json.dumps({"text": text}),
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


def test_feishu_webhook_acknowledges_overlong_text_without_parsing_or_dispatch(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    cloud.app.config["TESTING"] = True
    submitted = _fake_pool(monkeypatch, cloud)
    monkeypatch.setattr(
        cloud,
        "_try_extract_rename",
        lambda _text: pytest.fail("overlong text must not reach rename parsing"),
    )

    payload = _text_webhook_payload(
        token="verify_secret_xyz",
        text="help" + ("x" * cloud.MAX_MESSAGE_TEXT_CHARS),
    )
    response = cloud.app.test_client().post("/api/feishu/webhook", json=payload)

    assert response.status_code == 200
    assert response.get_json() == {"code": 0}
    assert submitted == []


@pytest.mark.parametrize(
    ("instruction", "expected"),
    [
        ("把文件名改成「台海态势」", "台海态势"),
        ("把导出的 DOCX 文件标题设为 V9_要讯.docx", "V9_要讯.docx"),
        ("重命名：联合演训", "联合演训"),
        ("filename 为 release-note", "release-note"),
    ],
)
def test_feishu_rename_parser_preserves_supported_intents(monkeypatch, instruction, expected):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")

    assert cloud._try_extract_rename(instruction) == expected


def test_feishu_rename_parser_handles_bounded_adversarial_whitespace(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    instruction = "把" + (" " * 8000) + "文件名改成测试"

    assert len(instruction) <= cloud.MAX_MESSAGE_TEXT_CHARS
    assert cloud._try_extract_rename(instruction) == "测试"
    assert cloud._try_extract_rename("文件名=" + ("a" * 115)) == "a" * 115


@pytest.mark.parametrize(
    "instruction",
    [
        "把文件名改成   ",
        "导出文件名：　",
        "文件名=" + ("a" * 116),
        "把" + (" 导出" * 1000) + " 文件名改成测试",
    ],
)
def test_feishu_rename_parser_rejects_missing_oversized_or_repeated_intents(
    monkeypatch, instruction,
):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")

    assert cloud._try_extract_rename(instruction) in (None, "")
    assert not hasattr(cloud, "_RENAME_INTENT_RE")


def test_feishu_webhook_missing_rename_filename_is_not_sent_to_ai(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    submitted = _fake_pool(monkeypatch, cloud)
    replies = []
    monkeypatch.setattr(cloud, "send_text", lambda _chat_id, text: replies.append(text) or True)
    payload = _text_webhook_payload(
        token="verify_secret_xyz",
        text="把文件名改成   ",
    )

    response = cloud.app.test_client().post("/api/feishu/webhook", json=payload)

    assert response.status_code == 200
    assert submitted == []
    assert replies == ["文件名不能为空，且 UTF-8 编码后不得超过 120 字节（含 .docx）。"]


class _AiResponse:
    status_code = 200

    def __init__(self, payload, headers=None):
        self._payload = payload
        self.headers = headers or {"X-Request-ID": "req-safe-123"}

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def test_feishu_ai_invalid_response_log_excludes_body_prompt_and_user_content(
    monkeypatch, caplog,
):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    monkeypatch.setitem(cloud.AI_CONFIG, "api_key", "unit-key")
    monkeypatch.setitem(cloud.AI_CONFIG, "base_url", "https://api.deepseek.com")
    secret = "response-secret-must-not-be-logged"
    prompt = "user-prompt-must-not-be-logged"
    monkeypatch.setattr(
        cloud,
        "pinned_post",
        lambda *args, **kwargs: _AiResponse({"choices": [], "body": secret}),
    )

    with caplog.at_level(logging.WARNING, logger="feishu_cloud"):
        with pytest.raises(ValueError, match="缺少 choices"):
            cloud._call_ai([{"role": "user", "content": prompt}])

    assert secret not in caplog.text
    assert prompt not in caplog.text
    assert "request_id=req-safe-123" in caplog.text
    assert "kind=chat" in caplog.text
    assert "reason=MISSING_CHOICES" in caplog.text


def test_feishu_ai_empty_content_log_maps_untrusted_finish_reason_to_enum(
    monkeypatch, caplog,
):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    monkeypatch.setitem(cloud.AI_CONFIG, "api_key", "unit-key")
    monkeypatch.setitem(cloud.AI_CONFIG, "base_url", "https://api.deepseek.com")
    secret = "finish-reason-secret-must-not-be-logged"
    monkeypatch.setattr(
        cloud,
        "pinned_post",
        lambda *args, **kwargs: _AiResponse({
            "choices": [{"message": {"content": ""}, "finish_reason": secret}],
        }),
    )

    with caplog.at_level(logging.WARNING, logger="feishu_cloud"):
        assert cloud._call_ai([{"role": "user", "content": "ordinary prompt"}]) == ""

    assert secret not in caplog.text
    assert "reason=EMPTY_CONTENT" in caplog.text


def test_feishu_multimodal_ai_invalid_response_log_excludes_body_and_prompt(
    monkeypatch, caplog,
):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    monkeypatch.setitem(cloud.AI_CONFIG, "api_key", "unit-key")
    monkeypatch.setitem(cloud.AI_CONFIG, "base_url", "https://api.deepseek.com")
    secret = "multimodal-response-secret"
    prompt = "multimodal-user-prompt"
    monkeypatch.setattr(
        cloud,
        "pinned_post",
        lambda *args, **kwargs: _AiResponse({"choices": [], "body": secret}),
    )

    with caplog.at_level(logging.WARNING, logger="feishu_cloud"):
        with pytest.raises(ValueError, match="缺少 choices"):
            cloud._call_ai_with_image("aW1hZ2U=", "image/png", prompt)

    assert secret not in caplog.text
    assert prompt not in caplog.text
    assert "kind=multimodal" in caplog.text
    assert "reason=MISSING_CHOICES" in caplog.text


def test_feishu_ai_request_id_cannot_inject_log_lines(monkeypatch, caplog):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    secret = "request-id-injected-secret"
    response = _AiResponse({}, headers={"X-Request-ID": "req-safe\n" + secret})

    with caplog.at_level(logging.WARNING, logger="feishu_cloud"):
        cloud._log_ai_upstream_anomaly(
            response, kind="chat", reason="EMPTY_CONTENT", level=logging.WARNING,
        )

    assert secret not in caplog.text
    assert "request_id=unavailable" in caplog.text


def _invoke_cloud_ai(cloud, *, multimodal=False):
    if multimodal:
        return cloud._call_ai_with_image("aW1hZ2U=", "image/png", "unit prompt")
    return cloud._call_ai([{"role": "user", "content": "unit prompt"}])


@pytest.mark.parametrize("multimodal", [False, True])
def test_feishu_ai_simpleai_allowlist_never_disables_tls_verification(
    monkeypatch, multimodal,
):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    monkeypatch.setitem(cloud.AI_CONFIG, "api_key", "unit-key")
    monkeypatch.setitem(cloud.AI_CONFIG, "base_url", "https://api.simpleai.com.cn/v1")
    monkeypatch.setitem(cloud.AI_CONFIG, "allowed_hosts", "api.simpleai.com.cn")
    calls = []

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return _AiResponse({
            "choices": [{"message": {"content": "ok"}}],
        })

    monkeypatch.setattr(cloud, "pinned_post", fake_post)

    assert _invoke_cloud_ai(cloud, multimodal=multimodal) == "ok"
    assert len(calls) == 1
    assert "verify" not in calls[0][1]


@pytest.mark.parametrize("multimodal", [False, True])
@pytest.mark.parametrize(
    "base_url",
    [
        "http://api.deepseek.com",
        "https://placeholder-user:placeholder-password@api.deepseek.example",
        "https://api.deepseek.com/v1?token=query-secret",
        "https://api.deepseek.com/v1#fragment",
        "https://api.deepseek.com../v1",
        "https://api.deepseek.com/v 1",
        "https://127.0.0.1/v1",
        "https://10.0.0.8/v1",
        "https://localhost/v1",
        "https://api.deepseek.com.attacker.example/v1",
        "https://unreviewed.example/v1",
    ],
)
def test_feishu_ai_rejects_untrusted_endpoint_before_requests(
    monkeypatch, multimodal, base_url,
):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    monkeypatch.setitem(cloud.AI_CONFIG, "api_key", "unit-key")
    monkeypatch.setitem(cloud.AI_CONFIG, "base_url", base_url)
    monkeypatch.setitem(cloud.AI_CONFIG, "allowed_hosts", "")
    monkeypatch.setattr(
        cloud,
        "pinned_post",
        lambda *args, **kwargs: pytest.fail("untrusted endpoint must fail before pinned_post"),
    )

    with pytest.raises(ValueError, match="AI_BASE_URL"):
        _invoke_cloud_ai(cloud, multimodal=multimodal)


@pytest.mark.parametrize(
    "allowed_hosts",
    [
        "*",
        "https://ai.example.com",
        "ai.example.com/path",
        "ai.example.com:443",
        ".example.com",
        "localhost",
        "127.0.0.1",
        "ai.example.com..",
    ],
)
def test_feishu_ai_rejects_malformed_allowed_hosts_before_requests(
    monkeypatch, allowed_hosts,
):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    monkeypatch.setitem(cloud.AI_CONFIG, "api_key", "unit-key")
    monkeypatch.setitem(cloud.AI_CONFIG, "base_url", "https://ai.example.com/v1")
    monkeypatch.setitem(cloud.AI_CONFIG, "allowed_hosts", allowed_hosts)
    monkeypatch.setattr(
        cloud,
        "pinned_post",
        lambda *args, **kwargs: pytest.fail("malformed allowlist must fail before pinned_post"),
    )

    with pytest.raises(ValueError, match="AI_ALLOWED_HOSTS"):
        cloud._call_ai([{"role": "user", "content": "unit prompt"}])


def test_feishu_ai_explicit_custom_https_host_is_allowed_with_default_tls(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    monkeypatch.setitem(cloud.AI_CONFIG, "api_key", "unit-key")
    monkeypatch.setitem(cloud.AI_CONFIG, "base_url", "https://AI.Example.COM./v1")
    monkeypatch.setitem(cloud.AI_CONFIG, "allowed_hosts", "ai.example.com")
    calls = []

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return _AiResponse({"choices": [{"message": {"content": "ok"}}]})

    monkeypatch.setattr(cloud, "pinned_post", fake_post)

    assert cloud._call_ai([{"role": "user", "content": "unit prompt"}]) == "ok"
    assert calls[0][0] == "https://ai.example.com/v1/chat/completions"
    assert "verify" not in calls[0][1]


@pytest.mark.parametrize(
    ("base_url", "expected_base", "expected_host"),
    [
        ("https://api.deepseek.com", "https://api.deepseek.com", "api.deepseek.com"),
        ("https://api.openai.com/v1", "https://api.openai.com/v1", "api.openai.com"),
        ("https://api.anthropic.com", "https://api.anthropic.com", "api.anthropic.com"),
    ],
)
def test_feishu_ai_official_hosts_are_allowed_by_default(
    monkeypatch, base_url, expected_base, expected_host,
):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    monkeypatch.setitem(cloud.AI_CONFIG, "base_url", base_url)
    monkeypatch.setitem(cloud.AI_CONFIG, "allowed_hosts", "")

    assert cloud._validated_ai_base_url() == (expected_base, expected_host)


def test_feishu_ai_invalid_endpoint_is_rejected_before_api_key_header_construction(
    monkeypatch,
):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")

    class ApiKeySentinel:
        def __bool__(self):
            return True

        def __str__(self):
            raise AssertionError("API key must not enter a header for an invalid endpoint")

    monkeypatch.setitem(cloud.AI_CONFIG, "api_key", ApiKeySentinel())
    monkeypatch.setitem(cloud.AI_CONFIG, "base_url", "https://unreviewed.example/v1")
    monkeypatch.setitem(cloud.AI_CONFIG, "allowed_hosts", "")

    with pytest.raises(ValueError, match="AI_BASE_URL"):
        cloud._call_ai([{"role": "user", "content": "unit prompt"}])


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


def test_feishu_cloud_maps_dns_pinned_transport_rejection_to_request_error(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    monkeypatch.setattr(cloud, "_is_ssrf_safe", lambda _url: (True, ""))

    def reject_private_peer(*_args, **_kwargs):
        raise cloud.UnsafeTargetError("连接对端是非公网地址")

    monkeypatch.setattr(cloud, "pinned_get", reject_private_peer)
    with pytest.raises(requests.RequestException, match="非公网地址"):
        cloud._safe_get_once("https://example.test/report", {}, 1)


def test_feishu_brief_validation_rejects_oversized_text_before_regex_parsing(monkeypatch):
    cloud = _load_feishu_cloud_with_token(monkeypatch, "verify_secret_xyz")
    monkeypatch.setattr(
        cloud,
        "_parse_brief_for_validation",
        lambda _value: pytest.fail("oversized brief must not reach parsers"),
    )

    oversized = cloud._validate_brief_text("x" * (cloud.MAX_BRIEF_TEXT_CHARS + 1))
    overlong_line = cloud._validate_brief_text("x" * (cloud.MAX_BRIEF_LINE_CHARS + 1))

    assert oversized["valid"] is False
    assert "16 KiB" in oversized["errors"][0]
    assert overlong_line["valid"] is False
    assert "4 KiB" in overlong_line["errors"][0]


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
