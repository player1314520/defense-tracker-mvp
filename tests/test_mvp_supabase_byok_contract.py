# -*- coding: utf-8 -*-
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (
    ROOT
    / "supabase"
    / "migrations"
    / "202608090024_mvp_byok_credentials.sql"
)


def _compact(value: str) -> str:
    return " ".join(value.split())


def test_byok_tables_are_private_ciphertext_only():
    sql = _compact(MIGRATION.read_text(encoding="utf-8").lower())

    assert "create table if not exists private.user_ai_credentials" in sql
    assert "create table if not exists private.user_ai_key_envelopes" in sql
    assert "ciphertext bytea not null" in sql
    assert "nonce bytea not null" in sql
    assert "provider in ('deepseek','zhipu','moonshot')" in sql
    assert "unique (user_id,provider)" in sql
    for forbidden in ("api_key", "secret_value", "base_url"):
        assert forbidden not in sql
    assert "revoke all on table private.user_ai_credentials" in sql
    assert "revoke all on table private.user_ai_key_envelopes" in sql


def test_put_validates_exact_bundle_models_sizes_versions_and_envelopes():
    sql = _compact(MIGRATION.read_text(encoding="utf-8").lower())
    start = sql.index("create or replace function public.put_user_ai_credential")
    end = sql.index("$$;", start)
    body = sql[start:end]

    assert "jsonb_object_keys(credential)" in body
    for field in (
        "provider",
        "model_id",
        "credential_version",
        "ciphertext",
        "nonce",
        "device_envelopes",
    ):
        assert f"'{field}'" in body
    for model in (
        "deepseek-v4-flash",
        "deepseek-v4-pro",
        "glm-5.2",
        "glm-5-turbo",
        "kimi-k3",
        "kimi-k2.6",
    ):
        assert f"'{model}'" in body
    assert "jsonb_array_length" in body
    assert "<= 32" in body or " > 32" in body
    assert "octet_length(decoded_nonce) <> 12" in body
    assert "octet_length(decoded_ephemeral_public_key) <> 65" in body
    assert "octet_length(decoded_envelope_nonce) <> 12" in body
    assert "octet_length(decoded_envelope_ciphertext) <> 48" in body
    assert "length(credential->>'ciphertext') > 5483" in body
    assert "length(credential->>'nonce') <> 16" in body
    assert "length(envelope->>'ephemeral_public_key') <> 87" in body
    assert "length(envelope->>'nonce') <> 16" in body
    assert "length(envelope->>'ciphertext') <> 64" in body
    assert "private.encode_base64url(decoded_ciphertext)" in body
    assert "private.encode_base64url(decoded_ephemeral_public_key)" in body
    assert "jsonb_typeof(envelope->'credential_version') <> 'number'" in body
    assert "credential version conflict" in body
    assert "supplied_version <> existing.credential_version + 1" in body
    assert "pg_catalog.pg_advisory_xact_lock" in body
    assert body.index("pg_catalog.pg_advisory_xact_lock") < body.index(
        "for update"
    )


def test_byok_is_bound_to_current_users_active_desktop_p256_device():
    sql = _compact(MIGRATION.read_text(encoding="utf-8").lower())

    assert "private.current_active_desktop_context" in sql
    helper_start = sql.index(
        "create or replace function private.current_active_desktop_context"
    )
    helper_end = sql.index("$$;", helper_start)
    helper = sql[helper_start:helper_end]
    assert "private.current_session_id()" in helper
    assert "ds.status = 'active'" in helper
    assert "d.status = 'active'" in helper
    assert "d.device_kind = 'desktop'" in helper
    assert "d.key_algorithm = 'p256'" in helper
    assert "d.user_id = (select auth.uid())" in helper
    assert "join public.memberships m" in helper
    assert "m.status = 'active'" in helper
    assert "user_id" not in sql[
        sql.index("create or replace function public.put_user_ai_credential"):
        sql.index("returns jsonb", sql.index("create or replace function public.put_user_ai_credential"))
    ]


def test_same_version_is_core_idempotent_and_envelope_additive_only():
    sql = _compact(MIGRATION.read_text(encoding="utf-8").lower())
    start = sql.index("create or replace function public.put_user_ai_credential")
    end = sql.index("$$;", start)
    body = sql[start:end]

    assert "supplied_version = existing.credential_version" in body
    assert "existing.core_sha256 <> core_hash" in body
    assert "credential envelope conflict" in body
    assert "insert into private.user_ai_key_envelopes" in body
    assert "elsif supplied_version = existing.credential_version + 1" in body
    assert "delete from private.user_ai_key_envelopes" in body


def test_get_returns_only_current_device_envelope_and_list_is_metadata_only():
    sql = _compact(MIGRATION.read_text(encoding="utf-8").lower())

    get_start = sql.index("create or replace function public.get_user_ai_credential")
    get_end = sql.index("$$;", get_start)
    get_body = sql[get_start:get_end]
    assert "e.device_id = context_device" in get_body
    assert "device_envelopes" in get_body
    assert "private.encode_base64url" in get_body
    list_start = sql.index("create or replace function public.list_user_ai_credentials")
    list_end = sql.index("$$;", list_start)
    list_body = sql[list_start:list_end]
    assert "ciphertext" not in list_body
    assert "nonce" not in list_body
    assert "model_id" in list_body
    assert "credential_version" in list_body


def test_four_byok_rpcs_are_authenticated_only():
    sql = _compact(MIGRATION.read_text(encoding="utf-8").lower())

    for name in (
        "put_user_ai_credential",
        "get_user_ai_credential",
        "list_user_ai_credentials",
        "delete_user_ai_credential",
    ):
        assert f"create or replace function public.{name}" in sql
        revoke = sql.index(f"revoke all on function public.{name}")
        assert "from public, anon, authenticated" in sql[revoke:revoke + 500]
        grant = sql.index(f"grant execute on function public.{name}")
        assert "to authenticated" in sql[grant:grant + 500]
