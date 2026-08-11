# -*- coding: utf-8 -*-
"""Static security contract for sync-safe Supabase device discovery."""

from pathlib import Path


MIGRATION = (
    Path(__file__).resolve().parents[1]
    / "supabase"
    / "migrations"
    / "202607300018_v9_sync_device_metadata.sql"
)


def _source() -> str:
    return MIGRATION.read_text(encoding="utf-8").lower()


def _compact(text: str) -> str:
    return " ".join(text.split())


def _function_body() -> str:
    source = _source()
    return source.split("as $sync_devices$", 1)[1].split(
        "$sync_devices$;", 1
    )[0]


def test_sync_device_rpc_migration_is_transactional_and_replayable():
    source = _source()

    assert "\nbegin;\n" in source
    assert source.rstrip().endswith("commit;")
    assert (
        "create or replace function public.list_sync_devices(\n"
        "    p_organization_id uuid\n"
        ")"
    ) in source


def test_sync_device_rpc_is_a_fixed_path_security_definer():
    compact = _compact(_source())

    assert (
        "returns table ( org_id uuid, device_id uuid, "
        "key_algorithm text, public_key text ) "
        "language plpgsql stable security definer set search_path = ''"
    ) in compact


def test_sync_device_rpc_guards_membership_and_scopes_every_device_row():
    body = _compact(_function_body())

    membership_guard = body.index(
        "if not private.is_org_member(p_organization_id) then"
    )
    device_query = body.index("from public.devices d")
    assert membership_guard < device_query
    assert (
        "raise exception 'active membership required' "
        "using errcode = '42501'"
    ) in body
    assert (
        "where d.organization_id = p_organization_id "
        "and d.status = 'active'"
    ) in body


def test_sync_device_rpc_returns_only_active_sync_key_metadata():
    source = _source()
    body = _compact(_function_body())

    assert (
        "select d.organization_id as org_id, d.id as device_id, "
        "d.key_algorithm, "
        "private.encode_base64url(d.public_key) as public_key "
        "from public.devices d"
    ) in body
    for forbidden in (
        "user_id",
        "email",
        "created_at",
        "revoked_at",
        "name_ciphertext",
        "name_nonce",
        "key_version",
    ):
        assert forbidden not in source
    assert "status text" not in source
    assert "select d.*" not in body


def test_sync_device_rpc_keeps_table_rls_and_grants_only_authenticated():
    compact = _compact(_source())

    assert "create policy" not in compact
    assert "drop policy" not in compact
    assert "alter table public.devices" not in compact
    assert "grant select on public.devices" not in compact
    assert (
        "revoke all on function public.list_sync_devices(uuid) "
        "from public, anon, authenticated;"
    ) in compact
    assert (
        "grant execute on function public.list_sync_devices(uuid) "
        "to authenticated;"
    ) in compact
    assert compact.count("grant execute on function") == 1
