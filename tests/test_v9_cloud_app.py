# -*- coding: utf-8 -*-
import ast
import base64
import gc
import hashlib
import json
import os
import re
import sqlite3
import stat
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


TEST_BUILD_COMMIT = "a" * 40
RELEASE_METADATA = {
    "version": "9.0.0",
    "display_version": "V9",
    "release_tag": "v9.0.0",
    "build_commit": TEST_BUILD_COMMIT,
    "wire_compatibility": "mvp-wire-v1",
}


@pytest.fixture(autouse=True)
def _isolated_feishu_dedupe(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "FEISHU_DEDUPE_DB", str(tmp_path / "feishu-event-dedupe.sqlite3")
    )


def _app(tmp_path):
    from v9_cloud import create_app

    return create_app(
        database_path=tmp_path / "cloud.sqlite3",
        coordinator_token="x" * 48,
        feishu_app_id="cli-v9-test",
        feishu_verify_token="verify-token",
        feishu_encrypt_key="encrypt-key",
        feishu_tenant_key="tenant-v9-test",
        allowed_origins={"https://portal.example.test"},
        supabase_url="https://project-ref.supabase.co",
        supabase_publishable_key="sb_publishable_public",
        access_applications_enabled=True,
        build_commit=TEST_BUILD_COMMIT,
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


def test_cloud_store_rejects_traversal_in_database_path(tmp_path):
    from v9_cloud import CloudStore

    with pytest.raises(ValueError, match="must not contain parent traversal"):
        CloudStore(tmp_path / "nested" / ".." / "cloud.sqlite3")


def test_cloud_store_rejects_symlinked_database_parent(tmp_path):
    from v9_cloud import CloudStore

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("directory symlinks are unavailable on this host")

    with pytest.raises(ValueError, match="symbolic link or reparse point"):
        CloudStore(linked_parent / "cloud.sqlite3")


def test_cloud_store_rejects_symlinked_database_file(tmp_path):
    from v9_cloud import CloudStore

    target = tmp_path / "target.sqlite3"
    target.write_bytes(b"")
    linked_database = tmp_path / "linked.sqlite3"
    try:
        linked_database.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("file symlinks are unavailable on this host")

    with pytest.raises(ValueError, match="symbolic link or reparse point"):
        CloudStore(linked_database)


def test_cloud_store_hardens_directory_and_database_permissions(tmp_path):
    from v9_cloud import CloudStore

    database_parent = tmp_path / "private-store"
    database_path = database_parent / "cloud.sqlite3"
    CloudStore(database_path)

    assert database_parent.is_dir()
    assert stat.S_ISREG(database_path.stat().st_mode)
    if os.name != "nt":
        assert stat.S_IMODE(database_parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(database_path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory-mode policy")
def test_cloud_store_rejects_shared_parent_without_rechmodding_it(tmp_path):
    from v9_cloud import CloudStore

    shared_parent = tmp_path / "shared-store"
    shared_parent.mkdir(mode=0o755)
    shared_parent.chmod(0o755)

    with pytest.raises(ValueError, match="private"):
        CloudStore(shared_parent / "cloud.sqlite3")

    assert stat.S_IMODE(shared_parent.stat().st_mode) == 0o755


def test_cloud_store_rejects_hard_linked_database_file(tmp_path):
    from v9_cloud import CloudStore

    target = tmp_path / "target.sqlite3"
    target.write_bytes(b"")
    linked_database = tmp_path / "linked.sqlite3"
    try:
        os.link(target, linked_database)
    except OSError:
        pytest.skip("hard links are unavailable on this host")

    with pytest.raises(ValueError, match="hard links"):
        CloudStore(linked_database)


def test_cloud_store_rejects_database_file_replaced_after_initialization(tmp_path):
    from v9_cloud import CloudStore

    database = tmp_path / "cloud.sqlite3"
    store = CloudStore(database)
    replacement = tmp_path / "replacement.sqlite3"
    replacement.write_bytes(b"")
    gc.collect()
    os.replace(replacement, database)

    with pytest.raises(ValueError, match="replaced after initialization"):
        store._connect()


def test_cloud_app_rejects_environment_database_path_outside_fixed_volume(
    tmp_path, monkeypatch
):
    from v9_cloud import create_app

    injected = tmp_path / "injected" / "cloud.sqlite3"
    monkeypatch.setenv("V9_CLOUD_DB_PATH", str(injected))

    with pytest.raises(ValueError, match="fixed deployment path"):
        create_app()

    assert not injected.parent.exists()


def test_development_database_path_preserves_the_only_legacy_database(
    tmp_path, monkeypatch
):
    import v9_cloud

    legacy = tmp_path / "defense-tracker-v9-cloud.sqlite3"
    legacy.write_bytes(b"legacy database bytes")
    monkeypatch.setattr(v9_cloud.tempfile, "gettempdir", lambda: str(tmp_path))

    assert v9_cloud._cloud_database_path(None, production_mode=False) == legacy


def test_development_database_path_rejects_divergent_legacy_and_hardened_files(
    tmp_path, monkeypatch
):
    import v9_cloud

    legacy = tmp_path / "defense-tracker-v9-cloud.sqlite3"
    hardened = tmp_path / "defense-tracker-v9-cloud" / "cloud.sqlite3"
    hardened.parent.mkdir()
    legacy.write_bytes(b"legacy database bytes")
    hardened.write_bytes(b"different database bytes")
    monkeypatch.setattr(v9_cloud.tempfile, "gettempdir", lambda: str(tmp_path))

    with pytest.raises(ValueError, match="both exist"):
        v9_cloud._cloud_database_path(None, production_mode=False)


def test_development_database_path_rejects_identical_legacy_and_hardened_files(
    tmp_path, monkeypatch
):
    import v9_cloud

    legacy = tmp_path / "defense-tracker-v9-cloud.sqlite3"
    hardened = tmp_path / "defense-tracker-v9-cloud" / "cloud.sqlite3"
    hardened.parent.mkdir()
    legacy.write_bytes(b"same database bytes")
    hardened.write_bytes(legacy.read_bytes())
    monkeypatch.setattr(v9_cloud.tempfile, "gettempdir", lambda: str(tmp_path))
    before = {
        path: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in (legacy, hardened)
    }

    with pytest.raises(ValueError, match="both exist"):
        v9_cloud._cloud_database_path(None, production_mode=False)
    assert {
        path: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in (legacy, hardened)
    } == before


def test_development_database_path_rejects_committed_legacy_wal_divergence(
    tmp_path, monkeypatch
):
    import v9_cloud

    legacy = tmp_path / "defense-tracker-v9-cloud.sqlite3"
    hardened = tmp_path / "defense-tracker-v9-cloud" / "cloud.sqlite3"
    hardened.parent.mkdir()
    connection = sqlite3.connect(legacy)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE continuity(value TEXT NOT NULL)")
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        hardened.write_bytes(legacy.read_bytes())
        connection.execute(
            "INSERT INTO continuity(value) VALUES (?)",
            ("committed-only-in-wal",),
        )
        connection.commit()

        wal_path = Path(f"{legacy}-wal")
        assert wal_path.stat().st_size > 0
        assert legacy.read_bytes() == hardened.read_bytes()
        monkeypatch.setattr(v9_cloud.tempfile, "gettempdir", lambda: str(tmp_path))

        with pytest.raises(ValueError, match="both exist"):
            v9_cloud._cloud_database_path(None, production_mode=False)

        row = connection.execute("SELECT value FROM continuity").fetchone()
        assert row == ("committed-only-in-wal",)
    finally:
        connection.close()


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal", "-mj000001"])
def test_development_database_path_rejects_orphaned_other_candidate_sidecar(
    tmp_path, monkeypatch, suffix
):
    import v9_cloud

    legacy = tmp_path / "defense-tracker-v9-cloud.sqlite3"
    legacy.write_bytes(b"legacy database bytes")
    hardened = tmp_path / "defense-tracker-v9-cloud" / "cloud.sqlite3"
    hardened.parent.mkdir()
    Path(f"{hardened}{suffix}").write_bytes(b"unresolved sidecar bytes")
    monkeypatch.setattr(v9_cloud.tempfile, "gettempdir", lambda: str(tmp_path))

    with pytest.raises(ValueError, match="orphaned hardened database sidecar"):
        v9_cloud._cloud_database_path(None, production_mode=False)


@pytest.mark.parametrize("candidate_name", ["legacy", "hardened"])
def test_development_database_path_preserves_only_candidate_with_wal(
    tmp_path, monkeypatch, candidate_name
):
    import v9_cloud

    legacy = tmp_path / "defense-tracker-v9-cloud.sqlite3"
    hardened = tmp_path / "defense-tracker-v9-cloud" / "cloud.sqlite3"
    selected = legacy if candidate_name == "legacy" else hardened
    selected.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(selected)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE continuity(value TEXT NOT NULL)")
        connection.execute(
            "INSERT INTO continuity(value) VALUES (?)", ("committed-in-wal",)
        )
        connection.commit()
        assert Path(f"{selected}-wal").stat().st_size > 0
        monkeypatch.setattr(v9_cloud.tempfile, "gettempdir", lambda: str(tmp_path))

        assert v9_cloud._cloud_database_path(None, production_mode=False) == selected
        assert connection.execute("SELECT value FROM continuity").fetchone() == (
            "committed-in-wal",
        )
    finally:
        connection.close()


def test_development_database_path_survives_write_and_restart(
    tmp_path, monkeypatch
):
    import v9_cloud

    legacy = tmp_path / "defense-tracker-v9-cloud.sqlite3"
    with sqlite3.connect(legacy) as connection:
        connection.execute("CREATE TABLE continuity(value TEXT NOT NULL)")
    monkeypatch.setattr(v9_cloud.tempfile, "gettempdir", lambda: str(tmp_path))

    selected = v9_cloud._cloud_database_path(None, production_mode=False)
    with sqlite3.connect(selected) as connection:
        connection.execute(
            "INSERT INTO continuity(value) VALUES (?)", ("after-selection",)
        )

    restarted = v9_cloud._cloud_database_path(None, production_mode=False)
    assert restarted == selected == legacy
    with sqlite3.connect(restarted) as connection:
        assert connection.execute("SELECT value FROM continuity").fetchall() == [
            ("after-selection",)
        ]


def _feishu_payload(text: str, event_id: str) -> dict:
    return {
        "schema": "2.0",
        "header": {
            "event_id": event_id,
            "event_type": "im.message.receive_v1",
            "token": "verify-token",
            "app_id": "cli-v9-test",
            "tenant_key": "tenant-v9-test",
        },
        "event": {
            "message": {
                "message_id": f"message-{event_id}",
                "message_type": "text",
                "content": json.dumps({"text": text}),
                "chat_id": "sensitive-chat-id",
            }
        },
    }


def _signed_feishu_post(client, payload: dict, *, key: str = "encrypt-key", timestamp=None):
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    timestamp = int(time.time()) if timestamp is None else timestamp
    nonce = "nonce-v9-test"
    signature = hashlib.sha256(
        (str(timestamp) + nonce + key).encode() + body
    ).hexdigest()
    return client.post(
        "/api/feishu/webhook",
        data=body,
        content_type="application/json",
        headers={
            "X-Lark-Request-Timestamp": str(timestamp),
            "X-Lark-Request-Nonce": nonce,
            "X-Lark-Signature": signature,
        },
    )


def _encrypt_feishu_payload(payload: dict, key: str = "encrypt-key") -> dict:
    plaintext = json.dumps(payload, separators=(",", ":")).encode()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    iv = os.urandom(16)
    encryptor = Cipher(
        algorithms.AES(hashlib.sha256(key.encode()).digest()), modes.CBC(iv)
    ).encryptor()
    encrypted = iv + encryptor.update(padded) + encryptor.finalize()
    return {"encrypt": base64.b64encode(encrypted).decode("ascii")}


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
        "daily_event_limit": 1000,
        "deployment_mode": "mvp",
        **RELEASE_METADATA,
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
            build_commit=TEST_BUILD_COMMIT,
        )
    with pytest.raises(ValueError, match="publishable"):
        create_app(
            database_path=tmp_path / "secret.sqlite3",
            production_mode=True,
            allowed_origins={"https://portal.example.cn"},
            supabase_url="https://api.example.cn",
            supabase_publishable_key="service-role-secret",
            build_commit=TEST_BUILD_COMMIT,
        )
    with pytest.raises(ValueError, match="HTTPS origin"):
        create_app(
            database_path=tmp_path / "origin.sqlite3",
            production_mode=True,
            allowed_origins={"http://portal.example.cn"},
            supabase_url="https://api.example.cn",
            supabase_publishable_key="sb_publishable_public",
            build_commit=TEST_BUILD_COMMIT,
        )


def test_release_metadata_is_consistent_across_public_status_routes(tmp_path):
    client = _app(tmp_path).test_client()

    for path in ("/health", "/ready", "/api/status", "/portal/config.json"):
        payload = client.get(path).get_json()
        for key, value in RELEASE_METADATA.items():
            assert payload[key] == value


def test_production_requires_an_exact_build_commit(tmp_path):
    from v9_cloud import create_app

    with pytest.raises(ValueError, match="full lowercase Git SHA"):
        create_app(
            database_path=tmp_path / "unknown-build.sqlite3",
            production_mode=True,
            allowed_origins={"https://portal.example.cn"},
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
        "version": "9.0.0",
        "display_version": "V9",
        "release_tag": "v9.0.0",
        "build_commit": "development",
        "wire_compatibility": "mvp-wire-v1",
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
        return _signed_feishu_post(client, _feishu_payload(text, message_id))

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
    assert b"evt-accept" not in raw
    assert hashlib.sha256(b"sensitive-chat-id").hexdigest().encode() not in raw
    assert hashlib.sha256(b"evt-accept").hexdigest().encode() not in raw


def test_feishu_webhook_rejects_token_only_stale_and_cross_tenant_events(tmp_path):
    client = _app(tmp_path).test_client()
    payload = _feishu_payload("status TASK_20260725_001", "evt-security")

    token_only = _signed_feishu_post(client, payload, key="verify-token")
    stale = _signed_feishu_post(
        client, payload, timestamp=int(time.time()) - 301,
    )
    payload["header"]["tenant_key"] = "another-tenant"
    cross_tenant = _signed_feishu_post(client, payload)

    assert token_only.status_code == 403
    assert stale.status_code == 403
    assert cross_tenant.status_code == 403


def test_feishu_encrypted_challenge_is_verified_and_bounded(tmp_path):
    client = _app(tmp_path).test_client()
    encrypted = _encrypt_feishu_payload({
        "type": "url_verification",
        "token": "verify-token",
        "challenge": "challenge-v9",
    })

    response = _signed_feishu_post(client, encrypted)

    assert response.status_code == 200
    assert response.get_json() == {"challenge": "challenge-v9"}


@pytest.mark.parametrize(
    "missing_setting",
    (
        "feishu_app_id",
        "feishu_verify_token",
        "feishu_encrypt_key",
        "feishu_tenant_key",
    ),
)
def test_feishu_webhook_fails_closed_when_security_config_is_incomplete(
    tmp_path, missing_setting,
):
    from v9_cloud import create_app

    settings = {
        "feishu_app_id": "cli-v9-test",
        "feishu_verify_token": "verify-token",
        "feishu_encrypt_key": "encrypt-key",
        "feishu_tenant_key": "tenant-v9-test",
    }
    settings[missing_setting] = ""
    client = create_app(
        database_path=tmp_path / "incomplete.sqlite3",
        **settings,
    ).test_client()

    response = _signed_feishu_post(
        client,
        _feishu_payload("claim TASK_20260725_001", "evt-incomplete"),
    )

    assert response.status_code == 503
    assert "verify-token" not in response.get_data(as_text=True)


def test_feishu_completed_event_is_persistently_deduplicated(tmp_path):
    first_client = _app(tmp_path).test_client()
    payload = _feishu_payload("approve TASK_20260725_001", "evt-persistent")

    first = _signed_feishu_post(first_client, payload)
    second_client = _app(tmp_path).test_client()
    duplicate = _signed_feishu_post(second_client, payload)

    assert first.status_code == 200
    assert first.get_json()["accepted"] is True
    assert duplicate.status_code == 200
    assert duplicate.get_json()["accepted"] is False


def test_cloud_deployment_allowlist_excludes_full_text_runtime():
    root = Path(__file__).resolve().parents[1]
    requirements_text = (root / "deploy/requirements.cloud.txt").read_text(
        encoding="utf-8"
    )
    requirements = {
        name.lower()
        for name in re.findall(
            r"(?m)^([A-Za-z0-9_.-]+)==[A-Za-z0-9_.+-]+(?:\s*\\)?$",
            requirements_text,
        )
    }
    dockerfile = (root / "deploy/Dockerfile.cloud").read_text(
        encoding="utf-8"
    )
    staging = (root / "deploy/docker-compose.staging.yml").read_text(
        encoding="utf-8"
    )
    procfile = (root / "Procfile").read_text(encoding="utf-8")

    assert {"cryptography", "flask", "gunicorn"}.issubset(requirements)
    assert re.search(r"(?m)^cryptography==50\.0\.1 \\$", requirements_text)
    server_requirements = (root / "deploy/requirements.server.txt").read_text(
        encoding="utf-8"
    )
    assert re.search(r"(?m)^cryptography==50\.0\.1 \\$", server_requirements)
    assert requirements_text.count("--hash=sha256:") >= len(requirements)
    assert "--require-hashes" in (root / "deploy/mvp/portal.Dockerfile").read_text(
        encoding="utf-8"
    )
    assert "v9_cloud:app" in procfile
    assert "feishu_cloud" not in procfile
    assert "COPY v9 ./v9" not in dockerfile
    assert (
        "COPY v9_cloud.py feishu_webhook_security.py product_version.py version.json ./"
        in dockerfile
    )
    assert dockerfile.startswith(
        "FROM python:3.11.14-slim-bookworm@sha256:"
        "65a93d69fa75478d554f4ad27c85c1e69fa184956261b4301ebaf6dbb0a3543d"
    )
    assert "--require-hashes" in dockerfile
    assert "--only-binary=:all:" in dockerfile
    assert "chmod 0700 /data" in dockerfile
    for forbidden in (
        "AI_API_KEY",
        "python-docx",
        "reportlab",
        "trafilatura",
        "feishu_cloud.py",
    ):
        assert forbidden not in dockerfile
        assert forbidden not in staging
        assert forbidden.lower() not in requirements
    assert "127.0.0.1:8088:8080" in staging
    assert "no-new-privileges:true" in staging
    assert "V9_COORDINATOR_TOKEN: ${V9_COORDINATOR_TOKEN:?" in staging
    for required in (
        "FEISHU_APP_ID: ${FEISHU_APP_ID:?",
        "FEISHU_VERIFY_TOKEN: ${FEISHU_VERIFY_TOKEN:?",
        "FEISHU_ENCRYPT_KEY: ${FEISHU_ENCRYPT_KEY:?",
        "FEISHU_TENANT_KEY: ${FEISHU_TENANT_KEY:?",
        "FEISHU_DEDUPE_DB: /data/feishu-event-dedupe.sqlite3",
    ):
        assert required in staging


def test_full_stack_server_uses_a_reproducible_hash_lock():
    root = Path(__file__).resolve().parents[1]
    input_text = (root / "deploy/requirements.server.in").read_text(
        encoding="utf-8"
    )
    lock_text = (root / "deploy/requirements.server.txt").read_text(
        encoding="utf-8"
    )
    build_input_text = (root / "deploy/requirements.server-build.in").read_text(
        encoding="utf-8"
    )
    build_lock_text = (root / "deploy/requirements.server-build.txt").read_text(
        encoding="utf-8"
    )
    dockerfile = (root / "deploy/Dockerfile").read_text(encoding="utf-8")
    dockerignore = (root / "deploy/Dockerfile.dockerignore").read_text(
        encoding="utf-8"
    )
    ci_workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    compiler = (root / "scripts/Compile-DependencyLocks.ps1").read_text(
        encoding="utf-8"
    )

    for requirements_input, requirements_lock in (
        (input_text, lock_text),
        (build_input_text, build_lock_text),
    ):
        direct = [
            line
            for line in requirements_input.splitlines()
            if line and not line.startswith("#")
        ]
        assert direct
        assert all(
            re.fullmatch(r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.+-]+", line)
            for line in direct
        )
        locked = re.findall(
            r"(?m)^([A-Za-z0-9_.-]+)==[A-Za-z0-9_.+-]+(?:\s*\\)?$",
            requirements_lock,
        )
        assert {line.split("==", 1)[0].lower() for line in direct}.issubset(
            {name.lower() for name in locked}
        )
        assert requirements_lock.count("--hash=sha256:") >= len(locked)

    assert "urllib3" in {
        name.lower()
        for name in re.findall(
            r"(?m)^([A-Za-z0-9_.-]+)==[A-Za-z0-9_.+-]+(?:\s*\\)?$",
            lock_text,
        )
    }
    assert dockerfile.startswith(
        "FROM python:3.11-slim@sha256:"
        "1042b61448fef4ba92d16a8c7eb4996d027568ce64792a7877fd88511e0af7c6"
    )
    assert "apt-get" not in dockerfile
    assert "requirements.server-build.txt" in dockerfile
    assert "--only-binary=:all:" in dockerfile
    assert "--no-binary=sgmllib3k" in dockerfile
    assert "--require-hashes" in dockerfile
    assert "--no-build-isolation" in dockerfile
    assert dockerignore.splitlines()[1] == "**"
    allowed_context_paths = {
        line[1:]
        for line in dockerignore.splitlines()
        if line.startswith("!")
    }
    expected_context_paths = {
        "deploy/",
        "deploy/Dockerfile",
        "deploy/requirements.server-build.txt",
        "deploy/requirements.server.txt",
        "app.py",
        "state.py",
        "quality.py",
        "tracking.py",
        "auth_devices.py",
        "user_state.py",
        "feishu_bot.py",
        "feishu_common.py",
        "consulting_agent.py",
        "report_agent.py",
        "search_adapters.py",
        "pinned_http.py",
        "protected_secrets.py",
        "wechat_runtime.py",
        "product_version.py",
        "document_safety.py",
        "feishu_webhook_security.py",
        "version.json",
        "v9/",
        "templates/",
        "static/",
        "static/css/",
        "static/img/",
        "static/js/",
        "static/js/vendor/",
    }
    expected_context_paths.update(
        path.relative_to(root).as_posix()
        for runtime_dir in (root / "v9", root / "templates", root / "static")
        for path in runtime_dir.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    )
    assert allowed_context_paths == expected_context_paths
    assert not any(path.endswith(("/**", "/*")) for path in allowed_context_paths)
    for forbidden_runtime_material in (
        "**/.access_token",
        "**/.ai_config.json",
        "**/.feishu_config.json",
        "**/.env.*",
        "**/*.key",
        "**/*.p12",
        "**/*二维码*",
    ):
        assert forbidden_runtime_material in dockerignore
    assert "docker build --file deploy/Dockerfile --tag defense-tracker-full-stack:ci ." in ci_workflow
    app_tree = ast.parse((root / "app.py").read_text(encoding="utf-8"))
    root_modules = {path.stem for path in root.glob("*.py")}
    imported_root_modules = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(app_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".", 1)[0]
        for node in ast.walk(app_tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    app_copy = next(
        line for line in dockerfile.splitlines() if line.startswith("COPY app.py ")
    )
    copied_root_modules = {
        Path(token).stem
        for token in app_copy.split()[1:-1]
        if token.endswith(".py")
    }
    assert imported_root_modules & root_modules <= copied_root_modules
    assert (
        '"deploy/requirements.server-build.in" '
        '"deploy/requirements.server-build.txt"'
    ) in compiler
    assert '"deploy/requirements.server.in" "deploy/requirements.server.txt"' in compiler


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
    assert "DEFENSE_TRACKER_BUILD_COMMIT=$RAILWAY_GIT_COMMIT_SHA" in railway["deploy"]["startCommand"]
    assert "healthCheckPath: /ready" in render
    assert "key: V9_PRODUCTION_MODE" in render
    assert 'value: "true"' in render
    assert "DEFENSE_TRACKER_BUILD_COMMIT=$RENDER_GIT_COMMIT" in render
    for required_render_key in (
        "FEISHU_APP_ID",
        "FEISHU_VERIFY_TOKEN",
        "FEISHU_ENCRYPT_KEY",
        "FEISHU_TENANT_KEY",
        "FEISHU_DEDUPE_DB",
    ):
        assert f"key: {required_render_key}" in render
    assert 'V9_PRODUCTION_MODE = "true"' in fly
    assert 'FEISHU_DEDUPE_DB = "/data/feishu-event-dedupe.sqlite3"' in fly
    assert 'path = "/ready"' in fly
    assert "V9_PRODUCTION_MODE=true" in dockerfile
    assert "ARG DEFENSE_TRACKER_BUILD_COMMIT" in dockerfile
    assert "^[0-9a-f]{40}$" in dockerfile
    full_stack_dockerfile = (root / "deploy/Dockerfile").read_text(encoding="utf-8")
    for required_module in (
        "deploy/requirements.server.txt",
        "auth_devices.py",
        "pinned_http.py",
        "product_version.py",
        "version.json",
        "document_safety.py",
        "feishu_webhook_security.py",
        "COPY v9/ v9/",
    ):
        assert required_module in full_stack_dockerfile
    assert 'V9_PRODUCTION_MODE: "false"' in staging
