# -*- coding: utf-8 -*-
"""Source contracts for the invite-only Supabase Auth creation hook.

Operational gate: applying the SQL is not enough.  Staging must select
``public.hook_v9_before_user_created`` in Dashboard -> Authentication -> Hooks
before any PKCE flow that may create an Auth user is enabled.
"""

from pathlib import Path


MIGRATION = (
    Path(__file__).resolve().parents[1]
    / "supabase"
    / "migrations"
    / "202607300016_v9_invitation_signup_hook.sql"
)


def _source() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def _function_body() -> str:
    source = _source()
    return source.split("as $hook$", 1)[1].split("$hook$;", 1)[0]


def test_auth_hook_migration_is_transactional_and_replayable():
    source = _source()

    assert "\nbegin;\n" in source
    assert source.rstrip().endswith("commit;")
    assert (
        "create or replace function "
        "public.hook_v9_before_user_created(event jsonb)"
    ) in source
    assert "returns jsonb" in source
    assert "language plpgsql" in source
    assert "security definer" in source
    assert "set search_path = ''" in source


def test_auth_hook_is_callable_only_by_supabase_auth_admin():
    source = _source()

    assert (
        "revoke all on function "
        "public.hook_v9_before_user_created(jsonb)\n"
        "    from public, anon, authenticated, service_role;"
    ) in source
    assert (
        "grant execute on function "
        "public.hook_v9_before_user_created(jsonb)\n"
        "    to supabase_auth_admin;"
    ) in source
    assert source.count("grant execute on function") == 1


def test_auth_hook_accepts_only_strict_email_provider_payloads():
    body = _function_body()

    assert "#>> '{user,app_metadata,provider}'" in body
    assert "#> '{user,app_metadata,providers}'" in body
    assert "is distinct from 'email'" in body
    assert "is distinct from '[\"email\"]'::jsonb" in body
    assert "jsonb_typeof(event #> '{user,email}')" in body
    assert "length(normalized_email) > 254" in body
    assert "pg_catalog.split_part(normalized_email, '@', 1)" in body
    assert ") > 64" in body
    assert "normalized_email !~ '^[a-z0-9" in body


def test_auth_hook_hashes_the_normalized_email_and_requires_live_invitation():
    source = _source()
    body = _function_body()

    assert (
        "create index if not exists "
        "member_invitation_requests_auth_hook_idx"
    ) in source
    assert "on private.member_invitation_requests(" in source
    assert "email_sha256,expires_at,id" in source
    assert "where status = 'requested';" in source
    assert "pg_catalog.lower(pg_catalog.btrim(raw_email))" in body
    assert "extensions.digest(" in body
    assert "pg_catalog.convert_to(normalized_email, 'UTF8')" in body
    assert "'sha256'" in body
    assert "pg_catalog.encode(" in body
    assert "from private.member_invitation_requests r" in body
    assert "r.email_sha256 = normalized_email_sha256" in body
    assert "r.status = 'requested'" in body
    assert "r.expires_at > pg_catalog.statement_timestamp()" in body
    assert "join public.memberships inviter" in body
    assert "inviter.user_id = r.requested_by" in body
    assert "inviter.status = 'active'" in body
    assert "inviter.role in ('owner','admin')" in body
    assert "r.role <> 'owner' or inviter.role = 'owner'" in body
    assert "order by r.organization_id, r.id" in body
    organization_lock = body.index("from public.organizations o")
    invitation_lock = body.index("for share of r, inviter")
    assert organization_lock < invitation_lock
    assert "for share;" in body[organization_lock:invitation_lock]


def test_auth_hook_is_read_only_and_returns_one_generic_denial():
    body = _function_body().lower()

    assert "update private.member_invitation_requests" not in body
    assert "insert into private.member_invitation_requests" not in body
    assert "delete from private.member_invitation_requests" not in body
    assert body.count("'message'") == 1
    assert "'http_code', 403" in body
    assert "'registration is not permitted.'" in body
    assert "return '{}'::jsonb;" in body


def test_migration_records_the_remote_dashboard_activation_gate():
    source = _source()

    assert "does not activate the hook" in source
    assert "Dashboard -> Authentication -> Hooks" in source
    assert "before opening create-user PKCE flows" in source
