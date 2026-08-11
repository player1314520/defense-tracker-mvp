# -*- coding: utf-8 -*-
import base64
import hashlib
import json
from pathlib import Path

import pytest


def _app(tmp_path):
    from v9_cloud import create_app

    return create_app(
        database_path=tmp_path / "cloud.sqlite3",
        coordinator_token="x" * 48,
        feishu_verify_token="verify-token",
        allowed_origins={"https://portal.example.test"},
        supabase_url="https://project-ref.supabase.co",
        supabase_publishable_key="sb_publishable_public",
        access_applications_enabled=True,
    )


def _event():
    def encode(value):
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    return {
        "event_id": "11111111-1111-4111-8111-111111111111",
        "organization_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "record_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "operation": "upsert",
        "payload": {
            "organization_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "record_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "record_type": "evidence",
            "version": 1,
            "version_id": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            "base_version_id": None,
            "key_version": 1,
            "ciphertext": encode(b"c" * 17),
            "nonce": encode(b"n" * 12),
            "wrapped_data_key": encode(b"k" * 48),
            "wrap_nonce": encode(b"w" * 12),
            "content_hash": "a" * 64,
            "device_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            "deleted": False,
        },
    }


def _auth():
    return {"Authorization": f"Bearer {'x' * 48}"}


def test_cloud_coordinator_fails_closed_and_stores_only_ciphertext(tmp_path):
    app = _app(tmp_path)
    client = app.test_client()
    assert client.get("/health").status_code == 200
    assert client.post("/api/v9/sync/events", json=_event()).status_code == 401

    pushed = client.post(
        "/api/v9/sync/events", json=_event(), headers=_auth()
    )
    assert pushed.status_code == 201
    duplicate = client.post(
        "/api/v9/sync/events", json=_event(), headers=_auth()
    )
    assert duplicate.status_code == 200
    pulled = client.get(
        "/api/v9/sync/events",
        query_string={
            "organization_id": _event()["organization_id"],
            "after_cursor": 0,
        },
        headers=_auth(),
    )
    assert pulled.status_code == 200
    assert pulled.get_json()["events"][0]["payload"]["ciphertext"]
    raw = (tmp_path / "cloud.sqlite3").read_bytes()
    assert b"body" not in raw
    assert b"plaintext" not in raw


def test_legacy_coordinator_is_disabled_in_production_by_default(
    tmp_path, monkeypatch
):
    from v9_cloud import create_app

    monkeypatch.setenv("V9_COORDINATOR_TOKEN", "x" * 48)
    monkeypatch.delenv("V9_LEGACY_COORDINATOR_ENABLED", raising=False)
    client = create_app(
        database_path=tmp_path / "cloud.sqlite3",
    ).test_client()

    assert client.get("/health").get_json()["sync_backend"] == "supabase"
    response = client.post(
        "/api/v9/sync/events", json=_event(), headers=_auth()
    )
    assert response.status_code == 410


def test_cloud_cors_is_explicit_not_wildcard(tmp_path):
    client = _app(tmp_path).test_client()
    allowed = client.options(
        "/api/v9/sync/events",
        headers={"Origin": "https://portal.example.test"},
    )
    denied = client.options(
        "/api/v9/sync/events",
        headers={"Origin": "https://evil.example"},
    )

    assert allowed.headers["Access-Control-Allow-Origin"] == "https://portal.example.test"
    assert "Access-Control-Allow-Origin" not in denied.headers


def test_mobile_portal_is_static_and_keeps_keys_out_of_browser_storage(tmp_path):
    client = _app(tmp_path).test_client()
    page = client.get("/portal/")
    script = client.get("/portal/app.js")
    crypto_script = client.get("/portal/crypto.mjs")
    session_script = client.get("/portal/session.mjs")
    config = client.get("/portal/config.json")

    assert page.status_code == 200
    assert script.status_code == 200
    assert crypto_script.mimetype == "application/javascript"
    assert session_script.mimetype == "application/javascript"
    assert config.get_json() == {
        "configured": True,
        "url": "https://project-ref.supabase.co",
        "publishable_key": "sb_publishable_public",
        "invited_signup_enabled": False,
        "access_applications_enabled": True,
        "account_limit": 100,
        "deployment_mode": "mvp",
    }
    assert "frame-ancestors 'none'" in page.headers["Content-Security-Policy"]
    assert "总览、告警、审批和任务状态" in page.get_data(as_text=True)
    assert 'id="endpoint"' not in page.get_data(as_text=True)
    assert 'id="bearer"' not in page.get_data(as_text=True)
    assert 'id="org-key"' not in page.get_data(as_text=True)
    assert "indexedDB" in script.get_data(as_text=True)
    assert "page < 100" in script.get_data(as_text=True)
    assert "localStorage" not in script.get_data(as_text=True)
    assert "sessionStorage" not in script.get_data(as_text=True)
    assert 'id="logout"' in page.get_data(as_text=True)
    assert "logoutPortalSession" in script.get_data(as_text=True)
    portal_source = script.get_data(as_text=True)
    session_source = session_script.get_data(as_text=True)
    assert "clear: () => databaseOperation(" in portal_source
    assert '"auth", "readwrite", (store) => store.clear()' in portal_source
    assert "await clearAuth()" in session_source


def test_mobile_portal_refuses_direct_signup_enablement(tmp_path):
    from v9_cloud import create_app

    with pytest.raises(ValueError, match="must remain false"):
        create_app(
            database_path=tmp_path / "cloud.sqlite3",
            supabase_url="https://project-ref.supabase.co",
            supabase_publishable_key="sb_publishable_public",
            invited_signup_enabled=True,
        )


def test_mobile_portal_invited_signup_env_is_strict_boolean(
    tmp_path, monkeypatch
):
    from v9_cloud import create_app

    monkeypatch.setenv("V9_AUTH_INVITED_SIGNUP_ENABLED", "maybe")
    with pytest.raises(ValueError, match="V9_AUTH_INVITED_SIGNUP_ENABLED"):
        create_app(database_path=tmp_path / "cloud.sqlite3")

    monkeypatch.delenv("V9_AUTH_INVITED_SIGNUP_ENABLED")
    with pytest.raises(ValueError, match="invited_signup_enabled"):
        create_app(
            database_path=tmp_path / "cloud-explicit.sqlite3",
            invited_signup_enabled="true",
        )


@pytest.mark.parametrize(
    "raw_value",
    ["true", "1"],
)
def test_mobile_portal_rejects_signup_enablement_from_env(
    tmp_path, monkeypatch, raw_value
):
    from v9_cloud import create_app

    monkeypatch.setenv("V9_AUTH_INVITED_SIGNUP_ENABLED", raw_value)
    with pytest.raises(ValueError, match="must remain false"):
        create_app(
            database_path=tmp_path / f"cloud-{raw_value}.sqlite3",
        )


@pytest.mark.parametrize("raw_value", ["false", "0"])
def test_mobile_portal_keeps_direct_signup_disabled_from_env(
    tmp_path, monkeypatch, raw_value
):
    from v9_cloud import create_app

    monkeypatch.setenv("V9_AUTH_INVITED_SIGNUP_ENABLED", raw_value)
    client = create_app(
        database_path=tmp_path / f"cloud-{raw_value}.sqlite3",
    ).test_client()

    assert client.get("/portal/config.json").get_json()[
        "invited_signup_enabled"
    ] is False


def test_self_hosted_supabase_origin_is_exact_in_portal_csp(tmp_path):
    from v9_cloud import create_app

    client = create_app(
        database_path=tmp_path / "cloud.sqlite3",
        supabase_url="https://api.example.cn",
        supabase_publishable_key="sb_publishable_public",
        allowed_origins={"https://portal.example.cn"},
    ).test_client()

    response = client.get("/portal/")
    csp = response.headers["Content-Security-Policy"]
    assert "https://api.example.cn" in csp
    assert "wss://api.example.cn" in csp
    assert "*.supabase.co" not in csp
    assert client.get("/").status_code == 302


def test_production_mode_requires_exact_public_configuration(tmp_path):
    from v9_cloud import create_app

    with pytest.raises(ValueError, match="Supabase"):
        create_app(
            database_path=tmp_path / "missing.sqlite3",
            production_mode=True,
            allowed_origins={"https://portal.example.cn"},
        )
    with pytest.raises(ValueError, match="publishable"):
        create_app(
            database_path=tmp_path / "secret.sqlite3",
            production_mode=True,
            allowed_origins={"https://portal.example.cn"},
            supabase_url="https://api.example.cn",
            supabase_publishable_key="service-role-secret",
        )
    with pytest.raises(ValueError, match="HTTPS origin"):
        create_app(
            database_path=tmp_path / "origin.sqlite3",
            production_mode=True,
            allowed_origins={"http://portal.example.cn"},
            supabase_url="https://api.example.cn",
            supabase_publishable_key="sb_publishable_public",
        )


def test_readiness_checks_dependency_without_leaking_key(tmp_path):
    from v9_cloud import create_app

    calls = []

    def ready(url, key):
        calls.append((url, key))
        return True

    client = create_app(
        database_path=tmp_path / "ready.sqlite3",
        supabase_url="https://api.example.cn",
        supabase_publishable_key="sb_publishable_public",
        readiness_probe=ready,
    ).test_client()
    response = client.get("/ready")

    assert response.status_code == 200
    assert response.get_json() == {
        "status": "ready",
        "mode": "ciphertext-only",
    }
    assert calls == [("https://api.example.cn", "sb_publishable_public")]
    assert "sb_publishable_public" not in response.get_data(as_text=True)

    unavailable = create_app(
        database_path=tmp_path / "not-ready.sqlite3",
        supabase_url="https://api.example.cn",
        supabase_publishable_key="sb_publishable_public",
        readiness_probe=lambda _url, _key: False,
    ).test_client().get("/ready")
    assert unavailable.status_code == 503
    assert unavailable.get_json()["status"] == "not_ready"


def test_feishu_accepts_only_task_metadata_commands_and_never_echoes_text(tmp_path):
    app = _app(tmp_path)
    client = app.test_client()

    def post_text(text, message_id):
        body = json.dumps(
            {
                "header": {"event_id": message_id},
                "event": {
                    "message": {
                        "message_id": message_id,
                        "message_type": "text",
                        "content": json.dumps({"text": text}),
                        "chat_id": "sensitive-chat-id",
                    }
                },
            },
            ensure_ascii=False,
        ).encode()
        timestamp, nonce = "100", "nonce"
        signature = hashlib.sha256(
            (timestamp + nonce + "verify-token").encode() + body
        ).hexdigest()
        return client.post(
            "/api/feishu/webhook",
            data=body,
            content_type="application/json",
            headers={
                "X-Lark-Request-Timestamp": timestamp,
                "X-Lark-Request-Nonce": nonce,
                "X-Lark-Signature": signature,
            },
        )

    rejected = post_text(
        "这是不应进入 Railway 的报告正文和证据", "evt-reject"
    )
    assert rejected.status_code == 200
    assert rejected.get_json()["accepted"] is False
    assert "报告正文" not in rejected.get_data(as_text=True)

    accepted = post_text("claim TASK_20260725_001", "evt-accept")
    assert accepted.status_code == 200
    assert accepted.get_json()["accepted"] is True
    assert accepted.get_json()["task_id"] == "TASK_20260725_001"
    raw = (tmp_path / "cloud.sqlite3").read_bytes()
    assert "报告正文".encode() not in raw
    assert b"sensitive-chat-id" not in raw


def test_cloud_deployment_allowlist_excludes_full_text_runtime():
    root = Path(__file__).resolve().parents[1]
    requirements = {
        line.strip()
        for line in (root / "deploy/requirements.cloud.txt").read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip() and not line.startswith("#")
    }
    dockerfile = (root / "deploy/Dockerfile.cloud").read_text(
        encoding="utf-8"
    )
    staging = (root / "deploy/docker-compose.staging.yml").read_text(
        encoding="utf-8"
    )
    procfile = (root / "Procfile").read_text(encoding="utf-8")

    assert requirements == {"Flask==3.1.3", "gunicorn==23.0.0"}
    assert "v9_cloud:app" in procfile
    assert "feishu_cloud" not in procfile
    assert "COPY v9 ./v9" not in dockerfile
    for forbidden in (
        "AI_API_KEY",
        "python-docx",
        "reportlab",
        "trafilatura",
        "feishu_cloud.py",
    ):
        assert forbidden not in dockerfile
        assert forbidden not in staging
    assert "127.0.0.1:8088:8080" in staging
    assert "no-new-privileges:true" in staging
    assert "V9_COORDINATOR_TOKEN: ${V9_COORDINATOR_TOKEN:?" in staging


def test_public_cloud_manifests_fail_closed_and_probe_readiness():
    root = Path(__file__).resolve().parents[1]
    railway = json.loads((root / "railway.json").read_text(encoding="utf-8"))
    render = (root / "render.yaml").read_text(encoding="utf-8")
    fly = (root / "fly.toml").read_text(encoding="utf-8")
    dockerfile = (root / "deploy/Dockerfile.cloud").read_text(encoding="utf-8")
    staging = (root / "deploy/docker-compose.staging.yml").read_text(
        encoding="utf-8"
    )

    assert railway["deploy"]["healthcheckPath"] == "/ready"
    assert "healthCheckPath: /ready" in render
    assert "key: V9_PRODUCTION_MODE" in render
    assert 'value: "true"' in render
    assert 'V9_PRODUCTION_MODE = "true"' in fly
    assert 'path = "/ready"' in fly
    assert "V9_PRODUCTION_MODE=true" in dockerfile
    assert 'V9_PRODUCTION_MODE: "false"' in staging
