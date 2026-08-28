# -*- coding: utf-8 -*-
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (
    ROOT
    / "supabase"
    / "migrations"
    / "202608090021_mvp_device_sessions.sql"
)
SESSION_REGEX_COMPAT_MIGRATION = (
    ROOT
    / "supabase"
    / "migrations"
    / "202608280029_v9_session_id_regex_compat.sql"
)


def _sql() -> str:
    return MIGRATION.read_text(encoding="utf-8").lower()


def _compact(value: str) -> str:
    return " ".join(value.split())


def test_device_session_migration_is_transactional_and_private():
    sql = _sql()
    compact = _compact(sql)

    assert compact.startswith("-- bind every privileged request")
    assert "begin;" in compact
    assert compact.endswith("commit;")
    assert "create table if not exists private.device_sessions" in compact
    assert "session_id text primary key" in compact
    assert "status text not null default 'active'" in compact
    assert "revoke all on table private.device_sessions" in compact
    assert "grant select on table private.device_sessions" not in compact
    assert "grant select on private.device_sessions" not in compact


def test_device_kind_is_explicit_and_registration_accepts_it():
    sql = _compact(_sql())

    assert (
        "select count(*) as existing_devices from public.devices" in sql
    )
    assert "add column if not exists device_kind text" in sql
    assert "device_kind backfill required before mvp migration" in sql
    assert "where d.device_kind is null" in sql
    assert "alter column device_kind set not null" in sql
    assert "device_kind in ('desktop','browser')" in sql
    assert (
        "public.register_device( uuid,uuid,text,text,text,text,text )"
        in sql
    )
    assert "device_kind text default 'desktop'" in sql
    assert "invalid device kind" in sql


def test_session_id_is_derived_only_from_verified_jwt_claims():
    sql = _sql()
    compact = _compact(sql)

    assert "create or replace function private.current_session_id()" in compact
    assert "(select auth.jwt()) ->> 'session_id'" in compact
    assert "current_setting('request.jwt.claims'" not in sql
    assert "create or replace function public.bind_device_session" in compact
    bind_start = compact.index(
        "create or replace function public.bind_device_session"
    )
    bind_end = compact.index("$$;", bind_start)
    bind = compact[bind_start:bind_end]
    assert "private.current_session_id()" in bind
    assert "d.user_id = actor" in bind
    assert "d.status = 'active'" in bind
    assert "m.user_id = actor" in bind
    assert "m.status = 'active'" in bind
    assert "device session is revoked" in bind
    assert "p_session_id" not in bind


def test_current_session_id_avoids_postgres_regex_repeat_bound_limit():
    sql = _compact(SESSION_REGEX_COMPAT_MIGRATION.read_text(encoding="utf-8"))

    assert "create or replace function private.current_session_id()" in sql
    assert "length(session_id) between 16 and 256" in sql
    assert "session_id ~ '^[A-Za-z0-9._~-]+$'" in sql
    assert "{16,256}" not in sql
    assert "revoke all on function private.current_session_id()" in sql


def test_revoking_device_or_member_revokes_bound_sessions():
    sql = _compact(_sql())

    assert "create or replace function private.revoke_bound_device_sessions()" in sql
    assert "after update of status on public.devices" in sql
    assert "new.status = 'revoked'" in sql
    assert "set status = 'revoked'" in sql
    assert "revoked_at = coalesce" in sql
    assert (
        "create or replace function private.revoke_member_device_sessions()"
        in sql
    )
    assert "after update of status or delete on public.memberships" in sql
    assert "new.status is distinct from 'active'" in sql


def test_active_session_predicate_requires_active_membership_too():
    sql = _compact(_sql())
    start = sql.index(
        "create or replace function private.has_active_device_session"
    )
    end = sql.index("$$;", start)
    helper = sql[start:end]

    assert "join public.memberships m" in helper
    assert "m.organization_id = ds.organization_id" in helper
    assert "m.user_id = ds.user_id" in helper
    assert "m.status = 'active'" in helper


def test_membership_role_and_device_helpers_require_active_session():
    sql = _compact(_sql())

    for helper in (
        "private.is_org_member",
        "private.is_org_admin",
        "private.is_org_owner",
        "private.can_write_record",
        "private.is_active_device_owner",
        "private.can_read_device",
    ):
        start = sql.index(f"create or replace function {helper}")
        end = sql.index("$$;", start)
        assert "private.has_active_device_session" in sql[start:end]
    active_device = sql[
        sql.index("create or replace function private.is_active_device_owner"):
    ]
    assert "target_device" in active_device
    assert "private.has_active_device_session(target_org,target_device)" in active_device


def test_sensitive_rpc_wrappers_fail_closed_on_revoked_session():
    sql = _compact(_sql())

    guarded = (
        "begin_member_invitation",
        "cancel_member_invitation",
        "list_member_invitations",
        "pair_device",
        "revoke_device",
        "revoke_member",
        "pull_sync_events",
        "transition_workflow",
    )
    for name in guarded:
        start = sql.index(f"create or replace function public.{name}")
        end = sql.index("$$;", start)
        assert "private.require_active_device_session" in sql[start:end]
    assert "private.can_register_device_session" in sql[
        sql.index("create or replace function public.register_device"):
    ]
    assert "revoke all on function private.begin_member_invitation" in sql
    assert "revoke all on function private.register_device" in sql
    accept_start = sql.index(
        "create or replace function public.accept_member_invitation"
    )
    accept_end = sql.index("$$;", accept_start)
    assert "private.can_accept_member_invitation_session()" in sql[
        accept_start:accept_end
    ]
    assert "revoke all on function private.accept_member_invitation()" in sql


def test_privileged_wrappers_close_null_role_authorization_paths():
    sql = _compact(_sql())

    for name in (
        "begin_member_invitation",
        "cancel_member_invitation",
        "list_member_invitations",
        "pair_device",
        "revoke_device",
        "revoke_member",
    ):
        start = sql.index(f"create or replace function public.{name}")
        end = sql.index("$$;", start)
        assert "private.is_org_admin" in sql[start:end]
    start = sql.index("create or replace function public.begin_member_invitation")
    end = sql.index("$$;", start)
    assert "private.is_org_owner" in sql[start:end]


def test_sensitive_rls_has_restrictive_session_backstop():
    sql = _compact(_sql())

    for table in ("organizations", "memberships", "devices"):
        assert f"on public.{table} as restrictive" in sql
    for table in (
        "key_envelopes",
        "record_heads",
        "record_versions",
        "sync_events",
        "conflicts",
        "encrypted_objects",
        "workflow_states",
        "audit_chain",
    ):
        assert f"'{table}'" in sql
    assert "create policy mvp_session_backstop on public.%i" in sql
    assert "as restrictive for all to authenticated" in sql
    assert "private.has_active_device_session" in sql
    assert "on storage.objects as restrictive" in sql
    assert "bucket_id <> 'defense-v9-encrypted'" in sql
    assert (
        "grant execute on function private.has_active_device_session(uuid,uuid)"
        in sql
    )
    assert (
        "grant execute on function private.can_register_device_session(uuid)"
        in sql
    )


def test_unbound_bootstrap_exposes_only_own_membership_and_pending_device():
    sql = _compact(_sql())
    membership_start = sql.index(
        "create policy mvp_session_memberships_select"
    )
    membership_end = sql.index(";", membership_start)
    membership = sql[membership_start:membership_end]
    assert "for select to authenticated" in membership
    assert "memberships.user_id = (select auth.uid())" in membership
    assert "memberships.status = 'active'" in membership
    assert "memberships.status = 'invited'" in membership
    assert "revoke select on table public.memberships from authenticated" in sql
    assert (
        "grant select (organization_id,user_id,role,status) on table "
        "public.memberships to authenticated"
    ) in sql
    organization_start = sql.index("create policy mvp_session_organizations")
    organization_end = sql.index(";", organization_start)
    organization = sql[organization_start:organization_end]
    assert "status = 'invited'" not in organization
    assert "private.has_active_device_session" in organization
    device_start = sql.index("create policy mvp_session_devices")
    device_end = sql.index(";", device_start)
    device = sql[device_start:device_end]
    assert "devices.status = 'pending'" in device
    assert "devices.status = 'active'" not in device
    assert "private.can_register_device_session" in device
    base_device_start = sql.index("create policy devices_select")
    base_device_end = sql.index(";", base_device_start)
    base_device = sql[base_device_start:base_device_end]
    assert "devices.status = 'pending'" in base_device
    assert "private.has_active_device_session" in base_device


def test_public_org_bootstrap_is_closed_for_mvp_accounts():
    sql = _compact(_sql())

    assert "revoke all on function public.bootstrap_organization" in sql
    assert "grant execute on function public.bootstrap_organization" not in sql[
        sql.rindex("revoke all on function public.bootstrap_organization"):
    ]
