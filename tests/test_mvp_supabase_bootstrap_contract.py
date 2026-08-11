# -*- coding: utf-8 -*-
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (
    ROOT
    / "supabase"
    / "migrations"
    / "202608090021_mvp_device_sessions.sql"
)


def _compact(value: str) -> str:
    return " ".join(value.split())


def _sql() -> str:
    return _compact(MIGRATION.read_text(encoding="utf-8").lower())


def _bootstrap_body(sql: str) -> str:
    start = sql.index(
        "create or replace function public.bootstrap_mvp_first_owner"
    )
    return sql[start:sql.index("$$;", start)]


def test_clean_install_bootstrap_is_service_only_and_fixed_shape():
    sql = _sql()

    assert "create table if not exists private.mvp_owner_bootstrap" in sql
    assert "create or replace function public.bootstrap_mvp_first_owner" in sql
    for parameter in (
        "p_owner_user_id uuid",
        "p_session_id text",
        "p_organization_id uuid",
        "p_name_ciphertext text",
        "p_name_nonce text",
        "p_device_id uuid",
        "p_device_public_key text",
        "p_device_name_ciphertext text",
        "p_device_name_nonce text",
    ):
        assert parameter in sql
    body = _bootstrap_body(sql)
    assert "auth.jwt()) ->> 'role'" in body
    assert "'service_role'" in body
    assert "marker.status <> 'invited'" in body
    assert "marker.auth_user_id is distinct from p_owner_user_id" in body
    assert "from auth.users" in body
    assert "auth_user_count <> 1" in body
    for table in (
        "public.organizations",
        "public.memberships",
        "public.devices",
        "private.device_sessions",
    ):
        assert f"from {table}" in body
    assert "'owner','active'" in body
    assert "'p256'" in body
    assert "'desktop'" in body
    revoke = sql.index(
        "revoke all on function public.bootstrap_mvp_first_owner"
    )
    grant = sql.index(
        "grant execute on function public.bootstrap_mvp_first_owner"
    )
    assert "from public, anon, authenticated, service_role" in sql[
        revoke:grant
    ]
    grant_statement = sql[grant:sql.index(";", grant)]
    assert "to service_role" in grant_statement
    assert "to authenticated" not in grant_statement


def test_bootstrap_is_single_tenant_attempt_fenced_and_idempotent():
    sql = _sql()
    body = _bootstrap_body(sql)

    assert "mvp_singleton boolean" in sql
    assert "unique (mvp_singleton)" in sql
    assert "pg_catalog.pg_advisory_xact_lock" in body
    assert "for update" in body
    assert body.index("pg_catalog.pg_advisory_xact_lock") < body.index(
        "for update"
    )
    assert "payload_sha256" in body
    assert "marker.status in ('provisioned','finalized')" in body
    assert "bootstrap payload mismatch" in body
    assert "bootstrap state mismatch" in body
    assert "set status = 'provisioned'" in body
    assert "insert into private.device_sessions" in body
    assert "'status','provisioned'" in body
    assert "'organization_id',p_organization_id" in body
    assert "'device_id',p_device_id" in body


def test_bootstrap_rejects_noncanonical_or_unbounded_ciphertext_inputs():
    body = _bootstrap_body(_sql())

    assert "invalid bootstrap payload" in body
    assert "p_device_public_key !~ '^[a-za-z0-9_-]+$'" in body
    assert "octet_length(decoded_device_public_key) <> 65" in body
    assert "pg_catalog.get_byte(decoded_device_public_key,0) <> 4" in body
    assert "octet_length(decoded_name_nonce) <> 12" in body
    assert "octet_length(decoded_device_name_nonce) <> 12" in body
    assert "private.encode_base64url(decoded_device_public_key)" in body
