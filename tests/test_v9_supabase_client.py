# -*- coding: utf-8 -*-
import inspect
import json
from datetime import datetime, timedelta, timezone

import pytest


class _ReversingProtector:
    def protect(self, value: bytes) -> bytes:
        return b"protected:" + value[::-1]

    def unprotect(self, value: bytes) -> bytes:
        assert value.startswith(b"protected:")
        return value.removeprefix(b"protected:")[::-1]


class _Response:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = json.dumps(self._payload)

    def json(self):
        return self._payload


class _Transport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


def _settings_file(tmp_path, **overrides):
    payload = {
        "url": "https://project-ref.supabase.co",
        "publishable_key": "sb_publishable_public",
        "project_ref": "project-ref",
        "environment": "staging",
        "redirect_ports": [49231, 49232, 49233, 49234, 49235],
    }
    payload.update(overrides)
    path = tmp_path / ".supabase_v9_config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_settings_reject_noncanonical_filename(tmp_path):
    from v9.supabase_client import SupabaseSettings

    wrong_name = tmp_path / "selected-by-request.json"
    wrong_name.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid Supabase V9 config path"):
        SupabaseSettings.load(wrong_name)


def test_settings_reject_linked_config(tmp_path):
    from v9.supabase_client import SupabaseSettings

    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    linked = tmp_path / ".supabase_v9_config.json"
    try:
        linked.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(ValueError, match="invalid Supabase V9 config path"):
        SupabaseSettings.load(linked)


def _encrypted_credential_payload():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from v9.ai_credentials import encrypt_api_credential

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    return encrypt_api_credential(
        "synthetic-test-key-not-persisted",
        user_id="11111111-1111-4111-8111-111111111111",
        provider="deepseek",
        model_id="deepseek-v4-pro",
        credential_version=1,
        devices=[{
            "id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "user_id": "11111111-1111-4111-8111-111111111111",
            "status": "active",
            "device_kind": "desktop",
            "key_algorithm": "p256",
            "public_key": public_key,
        }],
    ).to_rpc_payload()


def test_settings_only_expose_publishable_configuration(tmp_path):
    from v9.supabase_client import SupabaseSettings

    settings = SupabaseSettings.load(_settings_file(tmp_path))

    assert settings.project_ref == "project-ref"
    assert settings.redirect_ports == (49231, 49232, 49233, 49234, 49235)
    assert settings.public_config() == {
        "configured": True,
        "url": "https://project-ref.supabase.co",
        "publishable_key": "sb_publishable_public",
        "environment": "staging",
        "redirect_ports": [49231, 49232, 49233, 49234, 49235],
        "invited_signup_enabled": False,
    }


def test_settings_accept_self_hosted_https_origin_with_publishable_key(tmp_path):
    from v9.supabase_client import SupabaseSettings

    settings = SupabaseSettings.load(_settings_file(
        tmp_path,
        url="https://supabase.defense.example:8443",
        project_ref="defense-tracker",
        environment="production",
    ))

    assert settings.url == "https://supabase.defense.example:8443"
    assert settings.project_ref == "defense-tracker"


@pytest.mark.parametrize(
    "url",
    [
        "http://supabase.defense.example",
        "https://user@supabase.defense.example",
        "https://supabase.defense.example/rest/v1",
        "https://supabase.defense.example?redirect=evil",
        "https://supabase.defense.example#fragment",
    ],
)
def test_settings_reject_non_origin_or_insecure_self_hosted_url(tmp_path, url):
    from v9.supabase_client import SupabaseSettings

    with pytest.raises(ValueError, match="HTTPS project root"):
        SupabaseSettings.load(_settings_file(
            tmp_path,
            url=url,
            project_ref="defense-tracker",
        ))


def test_settings_keep_hosted_project_ref_binding(tmp_path):
    from v9.supabase_client import SupabaseSettings

    with pytest.raises(ValueError, match="do not match"):
        SupabaseSettings.load(_settings_file(
            tmp_path,
            url="https://other-project.supabase.co",
            project_ref="project-ref",
        ))


def test_http_client_exposes_only_encrypted_user_credential_rpc_contract(
    tmp_path,
):
    from v9.supabase_client import SupabaseHttpClient, SupabaseSettings

    transport = _Transport([
        _Response(payload={"provider": "deepseek", "version": 1}),
        _Response(payload=[{"provider": "deepseek", "version": 1}]),
        _Response(payload={"provider": "deepseek", "ciphertext": "opaque"}),
        _Response(payload={"deleted": True}),
    ])
    client = SupabaseHttpClient(
        SupabaseSettings.load(_settings_file(tmp_path)),
        transport=transport,
    )
    encrypted = _encrypted_credential_payload()

    client.put_user_ai_credential(encrypted, "jwt-memory-only")
    client.list_user_ai_credentials("jwt-memory-only")
    client.get_user_ai_credential("deepseek", "jwt-memory-only")
    client.delete_user_ai_credential("deepseek", "jwt-memory-only")

    names = [call[1].rsplit("/", 1)[-1] for call in transport.calls]
    assert names == [
        "put_user_ai_credential",
        "list_user_ai_credentials",
        "get_user_ai_credential",
        "delete_user_ai_credential",
    ]
    assert transport.calls[0][2]["json"] == {"credential": encrypted}
    assert transport.calls[1][2]["json"] == {}
    assert transport.calls[2][2]["json"] == {"provider_name": "deepseek"}
    assert transport.calls[3][2]["json"] == {"provider_name": "deepseek"}
    serialized_calls = json.dumps(transport.calls)
    assert "api_key" not in serialized_calls
    assert "base_url" not in serialized_calls
    assert "user_id" not in serialized_calls


def test_http_client_lists_byok_eligible_device_descriptors(tmp_path):
    from v9.supabase_client import SupabaseHttpClient, SupabaseSettings

    descriptors = [{
        "device_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "user_id": "11111111-1111-4111-8111-111111111111",
        "status": "active",
        "device_kind": "desktop",
        "key_algorithm": "p256",
        "public_key": "opaque-public-key",
    }]
    transport = _Transport([_Response(payload=descriptors)])
    client = SupabaseHttpClient(
        SupabaseSettings.load(_settings_file(tmp_path)),
        transport=transport,
    )

    result = client.list_user_ai_credential_devices("jwt-memory-only")

    assert result == descriptors
    method, url, kwargs = transport.calls[0]
    assert method == "POST"
    assert url.endswith("/rest/v1/rpc/list_user_ai_credential_devices")
    assert kwargs["json"] == {}
    assert kwargs["headers"]["Authorization"] == "Bearer jwt-memory-only"


@pytest.mark.parametrize("field", ["api_key", "base_url", "access_token"])
def test_credential_put_rpc_rejects_plaintext_or_routing_fields(tmp_path, field):
    from v9.supabase_client import SupabaseHttpClient, SupabaseSettings

    client = SupabaseHttpClient(
        SupabaseSettings.load(_settings_file(tmp_path)),
        transport=_Transport([]),
    )
    payload = _encrypted_credential_payload()
    payload[field] = "sensitive-value"

    with pytest.raises(ValueError, match="encrypted credential payload") as exc:
        client.put_user_ai_credential(payload, "jwt-memory-only")

    assert "sensitive-value" not in str(exc.value)


def test_credential_put_rpc_rejects_nested_plaintext_field(tmp_path):
    from v9.supabase_client import SupabaseHttpClient, SupabaseSettings

    client = SupabaseHttpClient(
        SupabaseSettings.load(_settings_file(tmp_path)),
        transport=_Transport([]),
    )
    payload = _encrypted_credential_payload()
    payload["device_envelopes"][0]["api_key"] = "nested-sensitive-value"

    with pytest.raises(ValueError, match="encrypted credential payload") as exc:
        client.put_user_ai_credential(payload, "jwt-memory-only")

    assert "nested-sensitive-value" not in str(exc.value)


@pytest.mark.parametrize("field", ["secret_key", "service_role_key", "anon_key"])
def test_settings_reject_secret_or_legacy_keys(tmp_path, field):
    from v9.supabase_client import SupabaseSettings

    path = _settings_file(tmp_path, **{field: "must-not-be-here"})
    with pytest.raises(ValueError, match="publishable"):
        SupabaseSettings.load(path)


@pytest.mark.parametrize("value", [0, 1, "false", "true", None, [], {}])
def test_settings_reject_non_boolean_invited_signup_flag(tmp_path, value):
    from v9.supabase_client import SupabaseSettings

    with pytest.raises(ValueError, match="invited_signup_enabled"):
        SupabaseSettings.load(
            _settings_file(tmp_path, invited_signup_enabled=value)
        )


def test_refresh_token_is_protected_and_access_token_never_written(tmp_path):
    from v9.supabase_client import SessionVault

    vault = SessionVault(tmp_path / "vault", protector=_ReversingProtector())
    vault.save_refresh_token(
        "refresh-token-sensitive",
        user_id="11111111-1111-4111-8111-111111111111",
    )
    raw = (tmp_path / "vault" / "supabase-session.vault").read_bytes()

    assert b"refresh-token-sensitive" not in raw
    assert b"access-token-sensitive" not in raw
    loaded = vault.load_refresh_token()
    assert loaded["refresh_token"] == "refresh-token-sensitive"
    assert loaded["user_id"] == "11111111-1111-4111-8111-111111111111"


def test_pkce_verifier_is_dpapi_protected_and_one_time(tmp_path):
    from v9.supabase_client import SessionVault

    vault = SessionVault(tmp_path / "vault", protector=_ReversingProtector())
    verifier = "verifier-must-never-be-plaintext-" + ("x" * 24)
    vault.save_pkce_attempt(
        verifier,
        redirect_uri=(
            "http://127.0.0.1:49231/api/v9/auth/callback"
        ),
    )
    raw = (tmp_path / "vault" / "supabase-pkce.vault").read_bytes()

    assert verifier.encode() not in raw
    attempt = vault.load_pkce_attempt()
    assert attempt["verifier"] == verifier
    vault.clear_pkce_attempt()
    assert vault.load_pkce_attempt() is None


def test_http_client_validates_user_and_uses_jwt_for_rpc(tmp_path):
    from v9.supabase_client import SupabaseHttpClient, SupabaseSettings

    transport = _Transport([
        _Response(payload={"id": "user-1", "email": "member@example.test"}),
        _Response(payload={"cursor": 3}),
    ])
    client = SupabaseHttpClient(
        SupabaseSettings.load(_settings_file(tmp_path)),
        transport=transport,
    )

    user = client.validate_access_token("jwt-in-memory")
    result = client.rpc("pull_sync_events", {"after_cursor": 0}, "jwt-in-memory")

    assert user["id"] == "user-1"
    assert result == {"cursor": 3}
    for _, _, kwargs in transport.calls:
        assert kwargs["headers"]["apikey"] == "sb_publishable_public"
        assert kwargs["headers"]["Authorization"] == "Bearer jwt-in-memory"
    assert "/rest/v1/rpc/pull_sync_events" in transport.calls[1][1]


def test_http_client_starts_and_exchanges_pkce_without_leaking_verifier():
    from v9.supabase_client import SupabaseHttpClient, SupabaseSettings

    transport = _Transport([
        _Response(payload={}),
        _Response(payload={
            "access_token": "memory-access",
            "refresh_token": "protected-refresh",
            "expires_in": 3600,
        }),
    ])
    settings = SupabaseSettings(
        "https://project-ref.supabase.co",
        "sb_publishable_public",
        "project-ref",
        "staging",
        (49231, 49232, 49233, 49234, 49235),
    )
    client = SupabaseHttpClient(settings, transport=transport)

    client.send_magic_link(
        "member@example.test",
        (
            "http://127.0.0.1:49231/api/v9/auth/callback"
        ),
        "challenge",
    )
    session = client.exchange_pkce("one-time-code", "secret-verifier")

    assert session["access_token"] == "memory-access"
    assert "redirect_to=http%3A%2F%2F127.0.0.1%3A49231" in (
        transport.calls[0][1]
    )
    assert transport.calls[0][2]["json"]["code_challenge"] == "challenge"
    assert transport.calls[0][2]["json"]["create_user"] is False
    assert transport.calls[1][2]["json"] == {
        "auth_code": "one-time-code",
        "code_verifier": "secret-verifier",
    }


def test_http_client_enables_user_creation_only_for_invited_signup_flag(tmp_path):
    from v9.supabase_client import SupabaseHttpClient, SupabaseSettings

    transport = _Transport([_Response(payload={})])
    settings = SupabaseSettings.load(
        _settings_file(tmp_path, invited_signup_enabled=True)
    )
    client = SupabaseHttpClient(settings, transport=transport)

    client.send_magic_link(
        "invited@example.test",
        "http://127.0.0.1:49231/api/v9/auth/callback",
        "challenge",
    )

    assert settings.public_config()["invited_signup_enabled"] is True
    assert transport.calls[0][2]["json"]["create_user"] is True


def test_http_client_accepts_pending_invitations_with_current_jwt(tmp_path):
    from v9.supabase_client import SupabaseHttpClient, SupabaseSettings

    transport = _Transport([
        _Response(payload={"accepted_count": 2}),
    ])
    client = SupabaseHttpClient(
        SupabaseSettings.load(_settings_file(tmp_path)),
        transport=transport,
    )

    result = client.accept_pending_invitations("jwt-in-memory")

    assert result == {"accepted_count": 2}
    method, url, kwargs = transport.calls[0]
    assert method == "POST"
    assert url.endswith("/rest/v1/rpc/accept_member_invitation")
    assert kwargs["headers"]["Authorization"] == "Bearer jwt-in-memory"
    assert kwargs["json"] == {}


def test_session_manager_validates_before_persisting_refresh_token(tmp_path):
    from v9.supabase_client import (
        SessionVault,
        SupabaseSessionManager,
        SupabaseSettings,
    )

    class Client:
        def validate_access_token(self, token):
            assert token == "access-in-memory"
            return {
                "id": "22222222-2222-4222-8222-222222222222",
                "email": "analyst@example.test",
            }

    manager = SupabaseSessionManager(
        SupabaseSettings.load(_settings_file(tmp_path)),
        SessionVault(tmp_path / "vault", protector=_ReversingProtector()),
        Client(),
    )
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    status = manager.accept_session(
        access_token="access-in-memory",
        refresh_token="refresh-protected",
        expires_at=expires_at.timestamp(),
    )

    assert status["authenticated"] is True
    assert status["user_id"] == "22222222-2222-4222-8222-222222222222"
    assert manager.access_token() == "access-in-memory"
    assert b"access-in-memory" not in (
        tmp_path / "vault" / "supabase-session.vault"
    ).read_bytes()


def test_session_manager_owns_pkce_verifier_and_rejects_unregistered_callback(
    tmp_path,
):
    from v9.supabase_client import (
        SessionVault,
        SupabaseSessionManager,
        SupabaseSettings,
    )

    class Client:
        def __init__(self):
            self.challenge = None
            self.verifier = None

        def send_magic_link(self, email, redirect_uri, challenge):
            assert email == "member@example.test"
            self.challenge = challenge

        def exchange_pkce(self, code, verifier):
            assert code == "one-time-code"
            self.verifier = verifier
            return {
                "access_token": "access-in-memory",
                "refresh_token": "refresh-protected",
                "expires_at": (
                    datetime.now(timezone.utc) + timedelta(hours=1)
                ).timestamp(),
            }

        def validate_access_token(self, token):
            assert token == "access-in-memory"
            return {
                "id": "33333333-3333-4333-8333-333333333333",
                "email": "member@example.test",
            }

        def accept_pending_invitations(self, token):
            assert token == "access-in-memory"
            return {"accepted_count": 1}

    client = Client()
    vault = SessionVault(
        tmp_path / "vault", protector=_ReversingProtector()
    )
    manager = SupabaseSessionManager(
        SupabaseSettings.load(_settings_file(tmp_path)),
        vault,
        client,
    )
    callback = "http://127.0.0.1:49231/api/v9/auth/callback"

    started = manager.start_email_login("member@example.test", callback)
    completed = manager.complete_email_login("one-time-code")

    assert started == {"sent": True}
    assert client.challenge
    assert client.verifier
    assert completed["authenticated"] is True
    assert completed["onboarding"] == {
        "status": "accepted",
        "accepted_count": 1,
    }
    assert vault.load_pkce_attempt() is None
    with pytest.raises(ValueError, match="callback"):
        manager.start_email_login(
            "member@example.test",
            "http://localhost:49231/api/v9/auth/callback",
        )


def test_email_validation_is_linear_and_preserves_254_character_boundary(
    tmp_path,
):
    import v9.supabase_client as supabase_client

    assert "re.fullmatch" not in inspect.getsource(
        supabase_client.SupabaseSessionManager.start_email_login
    )

    class Client:
        def __init__(self):
            self.emails = []

        def send_magic_link(self, email, _redirect_uri, _challenge):
            self.emails.append(email)

    callback = "http://127.0.0.1:49231/api/v9/auth/callback"
    client = Client()
    manager = supabase_client.SupabaseSessionManager(
        supabase_client.SupabaseSettings.load(_settings_file(tmp_path)),
        supabase_client.SessionVault(
            tmp_path / "linear-email-vault",
            protector=_ReversingProtector(),
        ),
        client,
    )
    longest_valid = "a" * 241 + "@example.test"

    assert len(longest_valid) == 254
    assert manager.start_email_login(longest_valid.upper(), callback) == {
        "sent": True
    }
    assert client.emails == [longest_valid]

    invalid = [
        "a" * 242 + "@example.test",
        "missing-at.example.test",
        "@example.test",
        "member@localhost",
        "member@.test",
        "member@example.",
        "member@@example.test",
        "member @example.test",
    ]
    for email in invalid:
        with pytest.raises(ValueError, match="valid invited email"):
            manager.start_email_login(email, callback)

    assert client.emails == [longest_valid]


def test_pkce_login_survives_invitation_rpc_failure_with_explicit_retry_status(
    tmp_path,
):
    from v9.supabase_client import (
        SessionVault,
        SupabaseRequestError,
        SupabaseSessionManager,
        SupabaseSettings,
    )

    class Client:
        def send_magic_link(self, _email, _redirect_uri, _challenge):
            return None

        def exchange_pkce(self, _code, _verifier):
            return {
                "access_token": "access-in-memory",
                "refresh_token": "refresh-protected",
                "expires_at": (
                    datetime.now(timezone.utc) + timedelta(hours=1)
                ).timestamp(),
            }

        def validate_access_token(self, token):
            assert token == "access-in-memory"
            return {
                "id": "55555555-5555-4555-8555-555555555555",
                "email": "member@example.test",
            }

        def accept_pending_invitations(self, token):
            assert token == "access-in-memory"
            raise SupabaseRequestError(503, "rpc:accept_member_invitation")

    vault = SessionVault(
        tmp_path / "vault", protector=_ReversingProtector()
    )
    manager = SupabaseSessionManager(
        SupabaseSettings.load(_settings_file(tmp_path)),
        vault,
        Client(),
    )
    manager.start_email_login(
        "member@example.test",
        "http://127.0.0.1:49231/api/v9/auth/callback",
    )

    completed = manager.complete_email_login("one-time-code")

    assert completed["authenticated"] is True
    assert completed["onboarding"] == {
        "status": "retry_required",
        "accepted_count": None,
    }
    assert manager.access_token() == "access-in-memory"
    assert vault.load_refresh_token()["refresh_token"] == "refresh-protected"
    assert vault.load_pkce_attempt() is None


def test_session_manager_clears_local_state_when_remote_sign_out_fails(
    tmp_path,
):
    from v9.supabase_client import (
        SessionVault,
        SupabaseSessionManager,
        SupabaseSettings,
    )

    class Client:
        def validate_access_token(self, token):
            assert token == "access-in-memory"
            return {
                "id": "44444444-4444-4444-8444-444444444444",
                "email": "member@example.test",
            }

        def sign_out(self, token):
            assert token == "access-in-memory"
            raise RuntimeError("remote auth unavailable")

    vault = SessionVault(
        tmp_path / "vault", protector=_ReversingProtector()
    )
    manager = SupabaseSessionManager(
        SupabaseSettings.load(_settings_file(tmp_path)),
        vault,
        Client(),
    )
    manager.accept_session(
        access_token="access-in-memory",
        refresh_token="refresh-protected",
        expires_at=(
            datetime.now(timezone.utc) + timedelta(hours=1)
        ).timestamp(),
    )
    vault.save_pkce_attempt(
        "verifier-" + ("x" * 48),
        redirect_uri=(
            "http://127.0.0.1:49231/api/v9/auth/callback"
        ),
    )

    with pytest.raises(RuntimeError, match="remote auth unavailable"):
        manager.sign_out()

    assert manager.status()["authenticated"] is False
    assert vault.load_refresh_token() is None
    assert vault.load_pkce_attempt() is None


def test_session_manager_credential_methods_use_current_in_memory_jwt(tmp_path):
    from v9.supabase_client import (
        SessionVault,
        SupabaseSessionManager,
        SupabaseSettings,
    )

    calls = []

    class Client:
        def validate_access_token(self, token):
            assert token == "access-in-memory"
            return {
                "id": "44444444-4444-4444-8444-444444444444",
                "email": "member@example.test",
            }

        def put_user_ai_credential(self, credential, token):
            calls.append(("put", credential, token))
            return {"provider": "deepseek"}

        def list_user_ai_credentials(self, token):
            calls.append(("list", token))
            return [{"provider": "deepseek"}]

        def get_user_ai_credential(self, provider, token):
            calls.append(("get", provider, token))
            return {"provider": provider, "ciphertext": "opaque"}

        def delete_user_ai_credential(self, provider, token):
            calls.append(("delete", provider, token))
            return {"deleted": True}

        def list_user_ai_credential_devices(self, token):
            calls.append(("devices", token))
            return []

    manager = SupabaseSessionManager(
        SupabaseSettings.load(_settings_file(tmp_path)),
        SessionVault(tmp_path / "vault", protector=_ReversingProtector()),
        Client(),
    )
    manager.accept_session(
        access_token="access-in-memory",
        refresh_token="refresh-protected",
        expires_at=(
            datetime.now(timezone.utc) + timedelta(hours=1)
        ).timestamp(),
    )
    payload = _encrypted_credential_payload()

    manager.put_user_ai_credential(payload)
    manager.list_user_ai_credentials()
    manager.get_user_ai_credential("deepseek")
    manager.delete_user_ai_credential("deepseek")
    manager.list_user_ai_credential_devices()

    assert calls == [
        ("put", payload, "access-in-memory"),
        ("list", "access-in-memory"),
        ("get", "deepseek", "access-in-memory"),
        ("delete", "deepseek", "access-in-memory"),
        ("devices", "access-in-memory"),
    ]
