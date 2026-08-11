# -*- coding: utf-8 -*-
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (
    ROOT
    / "supabase"
    / "migrations"
    / "202608100025_mvp_first_owner_key_envelope.sql"
)


def _compact(value: str) -> str:
    return " ".join(value.lower().split())


def _sql() -> str:
    return _compact(MIGRATION.read_text(encoding="utf-8"))


def test_first_owner_envelope_rpc_is_narrow_and_authenticated_only():
    sql = _sql()

    assert (
        "create or replace function public.put_mvp_first_owner_key_envelope( "
        "p_key_version integer, p_ephemeral_public_key text, "
        "p_envelope_nonce text, p_envelope_ciphertext text )"
    ) in sql
    assert "security definer" in sql
    assert "set search_path = ''" in sql
    assert "actor uuid := (select auth.uid())" in sql
    assert "caller_session text := private.current_session_id()" in sql
    assert "marker.status <> 'finalized'" in sql
    assert "request.jwt.claim.role" not in sql
    assert "service_role required" not in sql

    signature = (
        "public.put_mvp_first_owner_key_envelope(integer,text,text,text)"
    )
    revoke = sql.index(f"revoke all on function {signature}")
    grant = sql.index(f"grant execute on function {signature}")
    assert "from public, anon, authenticated, service_role" in sql[
        revoke:grant
    ]
    assert "to authenticated" in sql[grant:grant + 180]
    assert "grant insert on public.key_envelopes" not in sql


def test_first_owner_envelope_requires_exact_live_bound_identity():
    sql = _sql()

    assert "from auth.sessions s" in sql
    assert "s.id::text = caller_session" in sql
    assert "s.user_id = actor" in sql
    assert "from private.device_sessions ds" in sql
    assert "ds.session_id = caller_session" in sql
    assert "ds.user_id = actor" in sql
    assert "ds.status = 'active'" in sql
    assert "ds.revoked_at is null" in sql
    assert "marker.auth_user_id is distinct from actor" in sql
    assert "marker.organization_id is distinct from binding.organization_id" in sql
    assert "marker.device_id is distinct from binding.device_id" in sql
    assert "select count(*) into organization_count from public.organizations" in sql
    assert "organization_count <> 1" in sql
    assert "o.mvp_singleton" in sql
    assert "o.created_by = actor" in sql
    assert "m.role = 'owner'" in sql
    assert "m.status = 'active'" in sql
    assert "d.user_id = actor" in sql
    assert "d.status = 'active'" in sql
    assert "d.device_kind = 'desktop'" in sql
    assert "d.key_algorithm = 'p256'" in sql
    assert sql.index("select o.key_version into organization_key_version") < sql.index(
        "select ds.* into binding"
    )


def test_first_owner_envelope_validates_current_version_and_canonical_p256():
    sql = _sql()

    assert "p_key_version is distinct from organization_key_version" in sql
    assert "length(p_ephemeral_public_key) <> 87" in sql
    assert "length(p_envelope_nonce) <> 16" in sql
    assert "length(p_envelope_ciphertext) <> 64" in sql
    assert "octet_length(decoded_ephemeral_public_key) <> 65" in sql
    assert "pg_catalog.get_byte(decoded_ephemeral_public_key,0) <> 4" in sql
    assert "octet_length(decoded_envelope_nonce) <> 12" in sql
    assert "octet_length(decoded_envelope_ciphertext) <> 48" in sql
    assert (
        "private.encode_base64url(decoded_ephemeral_public_key) "
        "<> p_ephemeral_public_key"
    ) in sql
    assert "'p256'" in sql


def test_first_owner_envelope_is_one_time_and_exactly_idempotent():
    sql = _sql()
    lock = sql.index("pg_advisory_xact_lock")
    existing = sql.index("select e.* into existing")
    compare = sql.index(
        "existing.ephemeral_public_key = decoded_ephemeral_public_key",
        existing,
    )
    conflict = sql.index("raise exception 'first owner envelope conflict'", compare)
    insert = sql.index("insert into public.key_envelopes", conflict)

    assert lock < existing < compare < conflict < insert
    assert "envelope_count not in (0,1)" in sql
    assert "existing.nonce = decoded_envelope_nonce" in sql
    assert "existing.ciphertext = decoded_envelope_ciphertext" in sql
    assert "existing.key_algorithm = 'p256'" in sql
    assert "status','ready'" in sql
    assert "on conflict" not in sql[insert:]
    assert "update public.key_envelopes" not in sql
    assert "delete from public.key_envelopes" not in sql


def test_first_owner_envelope_errors_never_interpolate_secret_material():
    sql = _sql()

    for secret_name in (
        "p_ephemeral_public_key",
        "p_envelope_nonce",
        "p_envelope_ciphertext",
    ):
        assert f"raise exception {secret_name}" not in sql
        assert f"raise exception '%',{secret_name}" not in sql
