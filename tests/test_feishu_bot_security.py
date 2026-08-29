import hashlib
import json
import threading
import time
from pathlib import Path

import pytest

import app as tracker
import feishu_bot
import protected_secrets


class _ReversingProtector:
    prefix = b"test-protected:"

    def protect(self, value: bytes) -> bytes:
        return self.prefix + value[::-1]

    def unprotect(self, value: bytes) -> bytes:
        if not value.startswith(self.prefix):
            raise ValueError("invalid test payload")
        return value[len(self.prefix) :][::-1]


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


def test_feishu_secret_store_protects_every_secret_and_round_trips(tmp_path):
    path = tmp_path / ".feishu_config.json"
    store = protected_secrets.FeishuSecretStore(
        path,
        protector=_ReversingProtector(),
    )
    expected = {
        "app_id": "cli_public_identifier",
        "app_secret": "secret-not-for-disk",
        "verify_token": "verify-not-for-disk",
        "encrypt_key": "encrypt-not-for-disk",
        "tenant_key": "tenant-not-for-disk",
    }

    store.save(expected)

    raw = path.read_bytes()
    for secret_name in protected_secrets.FEISHU_SECRET_FIELDS:
        assert expected[secret_name].encode("utf-8") not in raw
    envelope = json.loads(raw.decode("utf-8"))
    assert envelope == {
        "app_id": "cli_public_identifier",
        "protected_blob": envelope["protected_blob"],
        "protection": "windows-dpapi-current-user",
        "rotation_required": False,
        "schema": "defense-tracker.feishu-config",
        "version": 1,
    }
    loaded = store.load()
    assert loaded is not None
    assert loaded.values == expected
    assert loaded.migrated is False
    assert loaded.rotation_required is False


def test_feishu_secret_store_atomically_migrates_plaintext_and_warns_rotation(
    tmp_path,
):
    path = tmp_path / ".feishu_config.json"
    legacy = {
        "app_id": "cli_legacy_identifier",
        "app_secret": "legacy-app-secret",
        "verify_token": "legacy-verify-token",
        "encrypt_key": "legacy-encrypt-key",
        "tenant_key": "legacy-tenant-key",
    }
    path.write_text(json.dumps(legacy), encoding="utf-8")
    store = protected_secrets.FeishuSecretStore(
        path,
        protector=_ReversingProtector(),
    )

    loaded = store.load()

    assert loaded is not None
    assert loaded.values == legacy
    assert loaded.migrated is True
    assert loaded.rotation_required is True
    raw = path.read_bytes()
    assert all(value.encode("utf-8") not in raw for value in legacy.values() if value != legacy["app_id"])
    assert json.loads(raw.decode("utf-8"))["rotation_required"] is True
    assert list(tmp_path.glob("*.tmp")) == []


def test_failed_plaintext_migration_preserves_the_original_file(
    monkeypatch,
    tmp_path,
):
    path = tmp_path / ".feishu_config.json"
    legacy = {
        "app_id": "cli_legacy_failure",
        "app_secret": "legacy-secret",
        "verify_token": "legacy-verify",
        "encrypt_key": "legacy-encrypt",
        "tenant_key": "legacy-tenant",
    }
    original = json.dumps(legacy).encode("utf-8")
    path.write_bytes(original)
    store = protected_secrets.FeishuSecretStore(
        path,
        protector=_ReversingProtector(),
    )
    monkeypatch.setattr(
        protected_secrets.os,
        "replace",
        lambda *_args: (_ for _ in ()).throw(OSError("simulated replace failure")),
    )

    with pytest.raises(protected_secrets.ProtectedSecretError) as rejected:
        store.load()

    assert rejected.value.code == "PERSIST_FAILED"
    assert path.read_bytes() == original
    assert list(tmp_path.glob("*.tmp")) == []


def test_feishu_secret_store_rejects_corrupt_protected_blob(tmp_path):
    path = tmp_path / ".feishu_config.json"
    store = protected_secrets.FeishuSecretStore(
        path,
        protector=_ReversingProtector(),
    )
    store.save(
        {
            "app_id": "cli_corrupt_test",
            "app_secret": "secret",
            "verify_token": "verify",
            "encrypt_key": "encrypt",
            "tenant_key": "tenant",
        }
    )
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["protected_blob"] = "not-valid-base64%%%"
    path.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(protected_secrets.ProtectedSecretError) as rejected:
        store.load()

    assert rejected.value.code == "INVALID_PROTECTED_CONFIG"


def test_feishu_secret_store_round_trips_below_final_envelope_limit(tmp_path):
    path = tmp_path / ".feishu_config.json"
    store = protected_secrets.FeishuSecretStore(
        path,
        protector=_ReversingProtector(),
    )
    expected = {
        "app_id": "cli_large_valid",
        "app_secret": "s" * 180_000,
        "verify_token": "verify",
        "encrypt_key": "encrypt",
        "tenant_key": "tenant",
    }

    store.save(expected)

    assert path.stat().st_size <= 256 * 1024
    loaded = store.load()
    assert loaded is not None and loaded.values == expected


def test_feishu_secret_store_rejects_oversize_final_envelope_without_commit(
    tmp_path,
):
    path = tmp_path / ".feishu_config.json"
    store = protected_secrets.FeishuSecretStore(
        path,
        protector=_ReversingProtector(),
    )
    original = {
        "app_id": "cli_size_original",
        "app_secret": "original-secret",
        "verify_token": "original-verify",
        "encrypt_key": "original-encrypt",
        "tenant_key": "original-tenant",
    }
    store.save(original)
    before = path.read_bytes()

    with pytest.raises(protected_secrets.ProtectedSecretError) as rejected:
        store.save({**original, "app_secret": "x" * 220_000})

    assert rejected.value.code == "CONFIG_TOO_LARGE"
    assert path.read_bytes() == before
    loaded = store.load()
    assert loaded is not None and loaded.values == original


def test_file_security_failure_occurs_before_atomic_commit(tmp_path):
    path = tmp_path / ".feishu_config.json"
    protector = _ReversingProtector()
    store = protected_secrets.FeishuSecretStore(path, protector=protector)
    original = {
        "app_id": "cli_permissions_original",
        "app_secret": "original-secret",
        "verify_token": "original-verify",
        "encrypt_key": "original-encrypt",
        "tenant_key": "original-tenant",
    }
    store.save(original)
    before = path.read_bytes()

    def reject_permissions(_path):
        raise RuntimeError("simulated ACL validation failure")

    failing_store = protected_secrets.FeishuSecretStore(
        path,
        protector=protector,
        file_security=reject_permissions,
    )
    with pytest.raises(protected_secrets.ProtectedSecretError) as rejected:
        failing_store.save({**original, "app_secret": "replacement-secret"})

    assert rejected.value.code == "PERSIST_FAILED"
    assert path.read_bytes() == before
    loaded = store.load()
    assert loaded is not None and loaded.values == original


def test_feishu_secret_store_refuses_non_windows_persistence_without_protector(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(protected_secrets.sys, "platform", "linux")
    path = tmp_path / ".feishu_config.json"
    store = protected_secrets.FeishuSecretStore(path)

    with pytest.raises(protected_secrets.ProtectedSecretError) as rejected:
        store.save(
            {
                "app_id": "cli_env_only",
                "app_secret": "secret",
                "verify_token": "verify",
                "encrypt_key": "encrypt",
                "tenant_key": "tenant",
            }
        )

    assert rejected.value.code == "PROTECTION_UNAVAILABLE"
    assert not path.exists()


def test_non_windows_without_config_file_uses_environment_only(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(protected_secrets.sys, "platform", "linux")
    monkeypatch.setattr(
        feishu_bot,
        "_FEISHU_CONFIG_FILE",
        str(tmp_path / "missing-feishu-config.json"),
    )
    monkeypatch.setenv("FEISHU_APP_ID", "cli_environment")
    monkeypatch.setenv("FEISHU_APP_SECRET", "environment-secret")
    monkeypatch.setenv("FEISHU_VERIFY_TOKEN", "environment-verify")
    monkeypatch.setenv("FEISHU_ENCRYPT_KEY", "environment-encrypt")
    monkeypatch.setenv("FEISHU_TENANT_KEY", "environment-tenant")

    loaded = feishu_bot._load_feishu_config()

    assert loaded == {
        "app_id": "cli_environment",
        "app_secret": "environment-secret",
        "verify_token": "environment-verify",
        "encrypt_key": "environment-encrypt",
        "tenant_key": "environment-tenant",
    }


def test_feishu_config_api_rolls_back_when_protected_persistence_fails(monkeypatch):
    monkeypatch.setattr(tracker, "AUTH_REQUIRED", True)
    monkeypatch.setattr(tracker, "ACCESS_TOKEN", "feishu-storage-master")
    before = dict(feishu_bot.FEISHU_CONFIG)

    def reject_save(*_args, **_kwargs):
        raise protected_secrets.ProtectedSecretError("PROTECTION_UNAVAILABLE")

    monkeypatch.setattr(feishu_bot, "_save_feishu_config", reject_save)
    with tracker._AUTH_SESSION_LOCK:
        tracker._AUTH_SESSIONS.clear()
    client = tracker.app.test_client()
    assert client.post("/login", data={"token": "feishu-storage-master"}).status_code == 302
    csrf_cookie = client.get_cookie(tracker.CSRF_COOKIE)
    assert csrf_cookie is not None

    response = client.post(
        "/api/feishu/config",
        json={
            "app_id": "cli_failed_update",
            "app_secret": "must-not-survive",
            "verify_token": "must-not-survive",
            "encrypt_key": "must-not-survive",
            "tenant_key": "must-not-survive",
        },
        headers={tracker.CSRF_HEADER: csrf_cookie.value},
    )

    assert response.status_code == 503
    assert response.get_json()["code"] == "FEISHU_SECRET_STORAGE_UNAVAILABLE"
    assert feishu_bot.FEISHU_CONFIG == before
    assert "must-not-survive" not in response.get_data(as_text=True)


def test_feishu_config_api_rejects_oversize_envelope_without_live_update(monkeypatch):
    monkeypatch.setattr(tracker, "AUTH_REQUIRED", True)
    monkeypatch.setattr(tracker, "ACCESS_TOKEN", "feishu-size-master")
    before = dict(feishu_bot.FEISHU_CONFIG)

    def reject_save(*_args, **_kwargs):
        raise protected_secrets.ProtectedSecretError("CONFIG_TOO_LARGE")

    monkeypatch.setattr(feishu_bot, "_save_feishu_config", reject_save)
    with tracker._AUTH_SESSION_LOCK:
        tracker._AUTH_SESSIONS.clear()
    client = tracker.app.test_client()
    assert client.post("/login", data={"token": "feishu-size-master"}).status_code == 302
    csrf_cookie = client.get_cookie(tracker.CSRF_COOKIE)
    assert csrf_cookie is not None

    response = client.post(
        "/api/feishu/config",
        json={"app_id": "cli_too_large", "app_secret": "x"},
        headers={tracker.CSRF_HEADER: csrf_cookie.value},
    )

    assert response.status_code == 413
    assert response.get_json()["code"] == "FEISHU_CONFIG_TOO_LARGE"
    assert feishu_bot.FEISHU_CONFIG == before


def test_feishu_config_api_persists_protected_values_and_keeps_working(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(tracker, "AUTH_REQUIRED", True)
    monkeypatch.setattr(tracker, "ACCESS_TOKEN", "feishu-protected-save-master")
    monkeypatch.setattr(
        feishu_bot,
        "_FEISHU_CONFIG_FILE",
        str(tmp_path / ".feishu_config.json"),
    )
    monkeypatch.setattr(feishu_bot, "_FEISHU_ROTATION_REQUIRED", True)
    original_save = feishu_bot._save_feishu_config

    def save_with_test_protector(config, *, rotation_required=None):
        return original_save(
            config,
            protector=_ReversingProtector(),
            rotation_required=rotation_required,
        )

    monkeypatch.setattr(feishu_bot, "_save_feishu_config", save_with_test_protector)
    before = dict(feishu_bot.FEISHU_CONFIG)
    with tracker._AUTH_SESSION_LOCK:
        tracker._AUTH_SESSIONS.clear()
    client = tracker.app.test_client()
    assert client.post(
        "/login",
        data={"token": "feishu-protected-save-master"},
    ).status_code == 302
    csrf_cookie = client.get_cookie(tracker.CSRF_COOKIE)
    assert csrf_cookie is not None
    submitted = {
        "app_id": "cli_protected_update",
        "app_secret": "saved-secret",
        "verify_token": "saved-verify",
        "encrypt_key": "saved-encrypt",
        "tenant_key": "saved-tenant",
    }
    request_payload = {
        **submitted,
        "old_credentials_revoked": True,
    }

    try:
        response = client.post(
            "/api/feishu/config",
            json=request_payload,
            headers={tracker.CSRF_HEADER: csrf_cookie.value},
        )
        raw = (tmp_path / ".feishu_config.json").read_bytes()
        loaded = protected_secrets.FeishuSecretStore(
            tmp_path / ".feishu_config.json",
            protector=_ReversingProtector(),
        ).load()

        assert response.status_code == 200
        assert response.get_json()["credential_rotation_required"] is False
        assert loaded is not None and loaded.values == submitted
        assert all(
            submitted[field].encode("utf-8") not in raw
            for field in protected_secrets.FEISHU_SECRET_FIELDS
        )
    finally:
        feishu_bot.FEISHU_CONFIG.clear()
        feishu_bot.FEISHU_CONFIG.update(before)


def test_feishu_rotation_requires_explicit_remote_revocation_confirmation(
    monkeypatch,
):
    monkeypatch.setattr(tracker, "AUTH_REQUIRED", True)
    monkeypatch.setattr(tracker, "ACCESS_TOKEN", "feishu-rotation-confirm-master")
    migrated = {
        "app_id": "cli_migrated",
        "app_secret": "migrated-secret",
        "verify_token": "migrated-verify",
        "encrypt_key": "migrated-encrypt",
        "tenant_key": "migrated-tenant",
    }
    replacement = {
        "app_id": "cli_migrated",
        "app_secret": "replacement-secret",
        "verify_token": "replacement-verify",
        "encrypt_key": "replacement-encrypt",
        "tenant_key": "replacement-tenant",
    }
    monkeypatch.setattr(feishu_bot, "FEISHU_CONFIG", dict(migrated))
    monkeypatch.setattr(feishu_bot, "_FEISHU_ROTATION_REQUIRED", True)
    save_calls = []
    monkeypatch.setattr(
        feishu_bot,
        "_save_feishu_config",
        lambda *args, **kwargs: save_calls.append((args, kwargs)),
    )
    with tracker._AUTH_SESSION_LOCK:
        tracker._AUTH_SESSIONS.clear()
    client = tracker.app.test_client()
    assert client.post(
        "/login",
        data={"token": "feishu-rotation-confirm-master"},
    ).status_code == 302
    csrf_cookie = client.get_cookie(tracker.CSRF_COOKIE)
    assert csrf_cookie is not None

    response = client.post(
        "/api/feishu/config",
        json=replacement,
        headers={tracker.CSRF_HEADER: csrf_cookie.value},
    )

    assert response.status_code == 409
    assert response.get_json()["code"] == "FEISHU_REVOCATION_CONFIRMATION_REQUIRED"
    assert feishu_bot.FEISHU_CONFIG == migrated
    assert feishu_bot._FEISHU_ROTATION_REQUIRED is True
    assert save_calls == []

    app_id_only = client.post(
        "/api/feishu/config",
        json={"app_id": "cli_must_not_replace_migrated_envelope"},
        headers={tracker.CSRF_HEADER: csrf_cookie.value},
    )

    assert app_id_only.status_code == 409
    assert app_id_only.get_json()["code"] == "FEISHU_ROTATION_INCOMPLETE"
    assert feishu_bot.FEISHU_CONFIG == migrated
    assert save_calls == []

    whitespace_secret = client.post(
        "/api/feishu/config",
        json={
            **replacement,
            "verify_token": "   ",
            "old_credentials_revoked": True,
        },
        headers={tracker.CSRF_HEADER: csrf_cookie.value},
    )

    assert whitespace_secret.status_code == 400
    assert (
        whitespace_secret.get_json()["code"]
        == "FEISHU_ROTATION_SECRET_WHITESPACE"
    )
    assert feishu_bot.FEISHU_CONFIG == migrated
    assert save_calls == []

    invalid_confirmation = client.post(
        "/api/feishu/config",
        json={**replacement, "old_credentials_revoked": "true"},
        headers={tracker.CSRF_HEADER: csrf_cookie.value},
    )

    assert invalid_confirmation.status_code == 400
    assert (
        invalid_confirmation.get_json()["code"]
        == "FEISHU_REVOCATION_CONFIRMATION_INVALID"
    )
    assert feishu_bot.FEISHU_CONFIG == migrated
    assert save_calls == []


def test_feishu_rotation_rejects_exact_migrated_credential_set(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(tracker, "AUTH_REQUIRED", True)
    monkeypatch.setattr(tracker, "ACCESS_TOKEN", "feishu-rotation-reuse-master")
    migrated = {
        "app_id": "cli_migrated_reuse",
        "app_secret": "migrated-secret-reuse",
        "verify_token": "migrated-verify-reuse",
        "encrypt_key": "migrated-encrypt-reuse",
        "tenant_key": "migrated-tenant-reuse",
    }
    config_path = tmp_path / ".feishu_config.json"
    config_path.write_text(json.dumps(migrated), encoding="utf-8")
    monkeypatch.setattr(feishu_bot, "_FEISHU_CONFIG_FILE", str(config_path))
    loaded = feishu_bot._load_feishu_config(protector=_ReversingProtector())
    monkeypatch.setattr(feishu_bot, "FEISHU_CONFIG", loaded)
    save_calls = []
    monkeypatch.setattr(
        feishu_bot,
        "_save_feishu_config",
        lambda *args, **kwargs: save_calls.append((args, kwargs)),
    )
    with tracker._AUTH_SESSION_LOCK:
        tracker._AUTH_SESSIONS.clear()
    client = tracker.app.test_client()
    assert client.post(
        "/login",
        data={"token": "feishu-rotation-reuse-master"},
    ).status_code == 302
    csrf_cookie = client.get_cookie(tracker.CSRF_COOKIE)
    assert csrf_cookie is not None

    response = client.post(
        "/api/feishu/config",
        json={**migrated, "old_credentials_revoked": True},
        headers={tracker.CSRF_HEADER: csrf_cookie.value},
    )

    assert response.status_code == 409
    assert response.get_json()["code"] == "FEISHU_CREDENTIALS_UNCHANGED"
    assert feishu_bot.FEISHU_CONFIG == migrated
    assert feishu_bot._FEISHU_ROTATION_REQUIRED is True
    assert save_calls == []

    padded_reuse = client.post(
        "/api/feishu/config",
        json={
            **migrated,
            "verify_token": f" {migrated['verify_token']} ",
            "encrypt_key": f"\t{migrated['encrypt_key']}",
            "tenant_key": f"{migrated['tenant_key']}\n",
            "old_credentials_revoked": True,
        },
        headers={tracker.CSRF_HEADER: csrf_cookie.value},
    )

    assert padded_reuse.status_code == 409
    assert padded_reuse.get_json()["code"] == "FEISHU_CREDENTIALS_UNCHANGED"
    assert feishu_bot.FEISHU_CONFIG == migrated
    assert feishu_bot._FEISHU_ROTATION_REQUIRED is True
    assert save_calls == []


def test_feishu_rotation_rejects_partial_secret_update_before_confirmation(
    monkeypatch,
):
    monkeypatch.setattr(tracker, "AUTH_REQUIRED", True)
    monkeypatch.setattr(tracker, "ACCESS_TOKEN", "feishu-rotation-partial-master")
    migrated = {
        "app_id": "cli_migrated_partial",
        "app_secret": "migrated-secret-partial",
        "verify_token": "migrated-verify-partial",
        "encrypt_key": "migrated-encrypt-partial",
        "tenant_key": "migrated-tenant-partial",
    }
    monkeypatch.setattr(feishu_bot, "FEISHU_CONFIG", dict(migrated))
    monkeypatch.setattr(feishu_bot, "_FEISHU_ROTATION_REQUIRED", True)
    save_calls = []
    monkeypatch.setattr(
        feishu_bot,
        "_save_feishu_config",
        lambda *args, **kwargs: save_calls.append((args, kwargs)),
    )
    with tracker._AUTH_SESSION_LOCK:
        tracker._AUTH_SESSIONS.clear()
    client = tracker.app.test_client()
    assert client.post(
        "/login",
        data={"token": "feishu-rotation-partial-master"},
    ).status_code == 302
    csrf_cookie = client.get_cookie(tracker.CSRF_COOKIE)
    assert csrf_cookie is not None

    response = client.post(
        "/api/feishu/config",
        json={
            "app_secret": "only-one-new-secret",
            "old_credentials_revoked": True,
        },
        headers={tracker.CSRF_HEADER: csrf_cookie.value},
    )

    assert response.status_code == 409
    assert response.get_json()["code"] == "FEISHU_ROTATION_INCOMPLETE"
    assert feishu_bot.FEISHU_CONFIG == migrated
    assert feishu_bot._FEISHU_ROTATION_REQUIRED is True
    assert save_calls == []


def test_feishu_rotation_refuses_local_clear_when_secrets_are_environment_managed(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(tracker, "AUTH_REQUIRED", True)
    monkeypatch.setattr(tracker, "ACCESS_TOKEN", "feishu-rotation-env-master")
    for field in protected_secrets.FEISHU_SECRET_FIELDS:
        monkeypatch.delenv(f"FEISHU_{field.upper()}", raising=False)
    environment_secret = "environment-managed-secret-must-not-leak"
    monkeypatch.setenv("FEISHU_APP_SECRET", environment_secret)
    migrated = {
        "app_id": "cli_migrated_environment",
        "app_secret": "migrated-environment-secret",
        "verify_token": "migrated-environment-verify",
        "encrypt_key": "migrated-environment-encrypt",
        "tenant_key": "migrated-environment-tenant",
    }
    replacement = {
        "app_id": "cli_replacement_environment",
        "app_secret": "replacement-environment-secret",
        "verify_token": "replacement-environment-verify",
        "encrypt_key": "replacement-environment-encrypt",
        "tenant_key": "replacement-environment-tenant",
    }
    config_path = tmp_path / ".feishu_config.json"
    config_path.write_text(json.dumps(migrated), encoding="utf-8")
    monkeypatch.setattr(feishu_bot, "_FEISHU_CONFIG_FILE", str(config_path))
    loaded = feishu_bot._load_feishu_config(protector=_ReversingProtector())
    monkeypatch.setattr(feishu_bot, "FEISHU_CONFIG", loaded)
    save_calls = []
    monkeypatch.setattr(
        feishu_bot,
        "_save_feishu_config",
        lambda *args, **kwargs: save_calls.append((args, kwargs)),
    )
    with tracker._AUTH_SESSION_LOCK:
        tracker._AUTH_SESSIONS.clear()
    client = tracker.app.test_client()
    assert client.post(
        "/login",
        data={"token": "feishu-rotation-env-master"},
    ).status_code == 302
    csrf_cookie = client.get_cookie(tracker.CSRF_COOKIE)
    assert csrf_cookie is not None

    response = client.post(
        "/api/feishu/config",
        json={**replacement, "old_credentials_revoked": True},
        headers={tracker.CSRF_HEADER: csrf_cookie.value},
    )
    response_text = response.get_data(as_text=True)

    assert response.status_code == 409
    assert response.get_json()["code"] == "FEISHU_ROTATION_ENVIRONMENT_MANAGED"
    assert feishu_bot._FEISHU_ROTATION_REQUIRED is True
    assert feishu_bot.FEISHU_CONFIG == loaded
    assert save_calls == []
    assert environment_secret not in response_text
    assert all(value not in response_text for value in replacement.values())
    assert all(
        migrated[field] not in response_text
        for field in protected_secrets.FEISHU_SECRET_FIELDS
    )


def test_plaintext_migration_logs_only_the_fixed_rotation_notice(
    monkeypatch,
    tmp_path,
    caplog,
):
    path = tmp_path / ".feishu_config.json"
    secret = "legacy-value-must-not-be-logged"
    path.write_text(
        json.dumps(
            {
                "app_id": "cli_log_notice",
                "app_secret": secret,
                "verify_token": secret,
                "encrypt_key": secret,
                "tenant_key": secret,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(feishu_bot, "_FEISHU_CONFIG_FILE", str(path))
    monkeypatch.setattr(feishu_bot, "_FEISHU_ROTATION_REQUIRED", False)

    with caplog.at_level("WARNING"):
        feishu_bot._load_feishu_config(protector=_ReversingProtector())

    assert protected_secrets.ROTATION_NOTICE in caplog.text
    assert secret not in caplog.text


def test_concurrent_feishu_config_posts_are_linearized(monkeypatch, tmp_path):
    monkeypatch.setattr(tracker, "AUTH_REQUIRED", True)
    monkeypatch.setattr(tracker, "ACCESS_TOKEN", "feishu-concurrency-master")
    monkeypatch.setattr(
        feishu_bot,
        "_FEISHU_CONFIG_FILE",
        str(tmp_path / ".feishu_config.json"),
    )
    monkeypatch.setattr(feishu_bot, "_FEISHU_ROTATION_REQUIRED", False)
    original_config = dict(feishu_bot.FEISHU_CONFIG)
    original_save = feishu_bot._save_feishu_config
    first_entered = threading.Event()
    release_first = threading.Event()
    save_order = []

    def controlled_save(config, *, rotation_required=None):
        save_order.append(config["app_id"])
        if config["app_id"] == "cli_concurrent_a":
            first_entered.set()
            if not release_first.wait(5):
                raise RuntimeError("concurrency test timed out")
        return original_save(
            config,
            protector=_ReversingProtector(),
            rotation_required=rotation_required,
        )

    monkeypatch.setattr(feishu_bot, "_save_feishu_config", controlled_save)

    def client_and_headers():
        client = tracker.app.test_client()
        login = client.post(
            "/login",
            data={"token": "feishu-concurrency-master"},
        )
        assert login.status_code == 302
        csrf = client.get_cookie(tracker.CSRF_COOKIE)
        assert csrf is not None
        return client, {tracker.CSRF_HEADER: csrf.value}

    client_a, headers_a = client_and_headers()
    client_b, headers_b = client_and_headers()
    payload_a = {
        "app_id": "cli_concurrent_a",
        "app_secret": "secret-a",
        "verify_token": "verify-a",
        "encrypt_key": "encrypt-a",
        "tenant_key": "tenant-a",
    }
    payload_b = {
        "app_id": "cli_concurrent_b",
        "app_secret": "secret-b",
        "verify_token": "verify-b",
        "encrypt_key": "encrypt-b",
        "tenant_key": "tenant-b",
    }
    responses = {}

    def post(name, client, headers, payload):
        responses[name] = client.post(
            "/api/feishu/config",
            json=payload,
            headers=headers,
        )

    first = threading.Thread(
        target=post,
        args=("a", client_a, headers_a, payload_a),
    )
    second = threading.Thread(
        target=post,
        args=("b", client_b, headers_b, payload_b),
    )
    try:
        first.start()
        assert first_entered.wait(5)
        second.start()
        time.sleep(0.1)
        assert save_order == ["cli_concurrent_a"]
        release_first.set()
        first.join(5)
        second.join(5)
        assert not first.is_alive() and not second.is_alive()
        assert responses["a"].status_code == 200
        assert responses["b"].status_code == 200
        assert save_order == ["cli_concurrent_a", "cli_concurrent_b"]
        loaded = protected_secrets.FeishuSecretStore(
            tmp_path / ".feishu_config.json",
            protector=_ReversingProtector(),
        ).load()
        assert loaded is not None and loaded.values == payload_b
        assert feishu_bot.FEISHU_CONFIG == payload_b
    finally:
        release_first.set()
        if first.ident is not None:
            first.join(5)
        if second.ident is not None:
            second.join(5)
        feishu_bot.FEISHU_CONFIG = original_config


def test_feishu_config_ui_exposes_fixed_rotation_notice_without_secrets(monkeypatch):
    monkeypatch.setattr(tracker, "AUTH_REQUIRED", True)
    monkeypatch.setattr(tracker, "ACCESS_TOKEN", "feishu-notice-master")
    monkeypatch.setattr(feishu_bot, "_FEISHU_ROTATION_REQUIRED", True)
    with tracker._AUTH_SESSION_LOCK:
        tracker._AUTH_SESSIONS.clear()
    client = tracker.app.test_client()
    assert client.post("/login", data={"token": "feishu-notice-master"}).status_code == 302

    payload = client.get("/api/feishu/config").get_json()

    assert payload["credential_rotation_required"] is True
    assert payload["credential_notice"] == protected_secrets.ROTATION_NOTICE
    assert "app_secret" not in payload
    assert "verify_token" not in payload
    assert "encrypt_key" not in payload
    assert "tenant_key" not in payload


def test_feishu_protected_storage_is_in_desktop_and_server_packages():
    from scripts.make_release_zip import (
        REQUIRED_RELEASE_FILES,
        should_include,
        validate_required_release_files,
    )

    root = Path(__file__).resolve().parents[1]
    builder = (root / "scripts/build_app.py").read_text(encoding="utf-8")
    dockerfile = (root / "deploy/Dockerfile").read_text(encoding="utf-8")
    source_zip = (root / "scripts/make_release_zip.py").read_text(encoding="utf-8")
    dockerignore = (root / ".dockerignore").read_text(encoding="utf-8")
    server_dockerignore = (root / "deploy/Dockerfile.dockerignore").read_text(
        encoding="utf-8"
    )

    assert '"protected_secrets"' in builder
    assert '"wechat_runtime"' in builder
    assert "protected_secrets.py" in dockerfile
    assert "wechat_runtime.py" in dockerfile
    assert '".feishu_config.json"' in source_zip
    assert should_include(root / "protected_secrets.py", root) is True
    assert should_include(root / ".feishu_config.json", root) is False
    assert ".feishu_config.json" in dockerignore
    assert "protected_secrets.py" not in dockerignore
    assert "wechat_runtime.py" in dockerignore
    assert "!protected_secrets.py" in server_dockerignore
    assert "!wechat_runtime.py" in server_dockerignore
    validate_required_release_files(root, REQUIRED_RELEASE_FILES)
    with pytest.raises(RuntimeError, match="protected_secrets.py"):
        validate_required_release_files(
            root,
            REQUIRED_RELEASE_FILES - {"protected_secrets.py"},
        )


def test_source_release_rejects_required_file_missing_from_commit_manifest(tmp_path):
    from scripts.make_release_zip import (
        REQUIRED_RELEASE_FILES,
        validate_required_release_files,
    )

    with pytest.raises(RuntimeError, match="protected_secrets.py"):
        validate_required_release_files(
            tmp_path,
            REQUIRED_RELEASE_FILES - {"protected_secrets.py"},
        )


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
