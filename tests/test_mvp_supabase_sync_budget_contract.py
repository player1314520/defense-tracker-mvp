# -*- coding: utf-8 -*-
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (
    ROOT
    / "supabase"
    / "migrations"
    / "202608300030_v9_sync_byte_session_quarantine.sql"
)
SQL_TEST = (
    ROOT / "supabase" / "tests" / "v9_sync_byte_session_quarantine_test.sql"
)
ISOLATION_TEST = (
    ROOT / "supabase" / "tests" / "v9_sync_byte_quota_isolation.spec"
)
CLOUD_CLIENT = ROOT / "v9" / "cloud.py"
STORAGE_OVERRIDE = ROOT / "deploy" / "mvp" / "supabase.production.override.yml"
PREFLIGHT = ROOT / "deploy" / "mvp" / "bin" / "preflight.sh"
VERIFIER = ROOT / "deploy" / "mvp" / "bin" / "verify-supabase-app.sh"


def compact(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").lower().split())


def test_sync_byte_limits_are_atomic_and_decoded():
    sql = compact(MIGRATION)

    assert "record_versions_ciphertext_v9_0_size_check" in sql
    assert "octet_length(ciphertext) between 17 and 1048592" in sql
    assert "add column if not exists ciphertext_bytes bigint" in sql
    assert "create table private.organization_sync_daily_usage" in sql
    assert "primary key (organization_id,usage_date)" in sql
    assert "octet_length(v.ciphertext)" in sql
    assert "on conflict (user_id,usage_date) do update" in sql
    assert "on conflict (organization_id,usage_date) do update" in sql
    assert "daily user sync byte limit exceeded" in sql
    assert "daily organization sync byte limit exceeded" in sql
    assert "before insert on public.sync_events" in sql


def test_write_side_ciphertext_limit_is_identical_across_client_db_and_storage():
    client = CLOUD_CLIENT.read_text(encoding="utf-8")
    override = STORAGE_OVERRIDE.read_text(encoding="utf-8")
    preflight = PREFLIGHT.read_text(encoding="utf-8")

    assert "_MAX_RECORD_CIPHERTEXT_BYTES = (1 * 1024 * 1024) + 16" in client
    assert 'FILE_SIZE_LIMIT: "1048592"' in override
    assert '!= "1048592"' in preflight
    assert "octet_length(ciphertext) between 17 and 1048592" in compact(MIGRATION)


def test_production_verifier_requires_every_new_security_rpc():
    verifier = VERIFIER.read_text(encoding="utf-8")
    for signature in (
        "public.revoke_current_device_session()",
        "public.report_sync_event_quarantine(uuid,bigint,uuid,uuid,uuid,text)",
        "public.list_sync_quarantine_reports(uuid,integer)",
        "public.admin_tombstone_quarantined_record(uuid,jsonb)",
        "public.admin_mark_quarantine_repaired(uuid)",
    ):
        assert f"'{signature}'" in verifier


def test_pull_preserves_wire_signature_and_caps_total_encoded_bytes():
    sql = compact(MIGRATION)
    start = sql.index("create or replace function public.pull_sync_events(")
    end = sql.index("$$;", start)
    body = sql[start:end]

    assert "organization_id uuid, after_cursor bigint default 0," in body
    assert "page_size integer default 200" in body
    assert "returns table ( cursor bigint, event_id uuid," in body
    assert "private.require_active_device_session" in body
    assert "max_encoded_page_bytes constant bigint := 25165824" in body
    assert "cumulative_encoded_bytes bigint := 2" in body
    assert "case when emitted_rows > 0 then 1 else 0 end" in body
    assert "cumulative_encoded_bytes + encoded_row_bytes" in body
    assert "sync event exceeds pull byte limit" in body


def test_current_session_revoke_has_no_caller_controlled_identity():
    sql = compact(MIGRATION)
    start = sql.index(
        "create or replace function public.revoke_current_device_session()"
    )
    end = sql.index("$$;", start)
    body = sql[start:end]

    assert "auth.uid()" in body
    assert "private.current_session_id()" in body
    assert "where ds.session_id = current_session" in body
    assert "and ds.user_id = actor" in body
    assert "session_id text" not in body.split("returns", 1)[0]
    assert "grant execute on function public.revoke_current_device_session()" in sql


def test_quarantine_reports_are_metadata_only_and_admin_resolvable():
    sql = compact(MIGRATION)

    assert "create table private.sync_event_quarantine_reports" in sql
    assert "ciphertext" not in sql[
        sql.index("create table private.sync_event_quarantine_reports"):
        sql.index(");", sql.index("create table private.sync_event_quarantine_reports"))
    ]
    assert "create or replace function public.report_sync_event_quarantine" in sql
    assert "create or replace function public.list_sync_quarantine_reports" in sql
    assert "create or replace function public.admin_tombstone_quarantined_record" in sql
    assert "create or replace function public.admin_mark_quarantine_repaired" in sql
    assert "logical_version bigint not null" in sql
    assert "admin_tombstone_quarantined_record( p_report_id uuid, p_event jsonb" in sql
    assert "perform private.validate_sync_ciphertext_event(p_event)" in sql
    assert "v9:server-tombstone:" not in sql
    tombstone_start = sql.index(
        "create or replace function public.admin_tombstone_quarantined_record"
    )
    tombstone_end = sql.index("$$;", tombstone_start)
    tombstone = sql[tombstone_start:tombstone_end]
    assert "private.decode_base64url(payload->>'ciphertext')" in tombstone
    assert "quarantine tombstone event does not match report" in tombstone
    assert "private.is_active_device_owner" in tombstone
    assert "insert into public.sync_events" in tombstone
    assert "private.is_org_admin" in sql
    assert "private.require_active_device_session" in sql


def test_sql_fixture_covers_boundaries_concurrent_upserts_and_rollback():
    sql = compact(SQL_TEST)

    assert "user byte boundary accepts the last byte" in sql
    assert "organization byte rejection rolls back the user reservation" in sql
    assert "primary-key upserts serialize concurrent quota reservations" in sql
    assert "current device session is revoked without accepting an id argument" in sql
    assert "quarantine report contains no ciphertext" in sql
    assert "a tombstone cannot target a different record" in sql
    assert "rejected cross-record tombstone leaves the head unchanged" in sql
    assert "organization usage at the seven-day utc boundary is retained" in sql
    assert "session audit at exactly 180 days is deleted" in sql
    assert "an old open quarantine remains in the repair queue" in sql


def test_new_private_retention_extension_is_bounded_and_counted():
    sql = compact(MIGRATION)
    start = sql.index(
        "create or replace function private.purge_access_application_data"
    )
    end = sql.index("$$;", start)
    body = sql[start:end]

    assert (
        "delete from private.organization_sync_daily_usage u "
        "where u.usage_date < (p_now at time zone 'utc')::date - 7"
    ) in body
    assert (
        "delete from private.device_session_revocation_audit a "
        "where a.revoked_at <= p_now - interval '180 days'"
    ) in body
    assert (
        "delete from private.sync_event_quarantine_reports q "
        "where q.status in ('tombstoned','repaired') "
        "and q.resolved_at <= p_now - interval '180 days'"
    ) in body
    assert "q.status = 'open'" not in body
    for field in (
        "'organization_sync_daily_usage_deleted'",
        "'device_session_revocation_audit_deleted'",
        "'sync_event_quarantine_reports_deleted'",
    ):
        assert field in body
    for existing_field in (
        "'expired_invitations'",
        "'expired_memberships'",
        "'stale_approvals'",
        "'pending_deleted'",
        "'contacts_purged'",
        "'invitation_contacts_purged'",
        "'audit_deleted'",
        "'invitation_audit_deleted'",
        "'applications_deleted'",
        "'rate_buckets_deleted'",
        "'event_usage_deleted'",
    ):
        assert existing_field in body


def test_isolation_fixture_forces_two_transactions_onto_one_org_ledger_row():
    spec = compact(ISOLATION_TEST)

    assert "session s1" in spec
    assert "session s2" in spec
    assert "step s1_reserve" in spec
    assert "step s2_reserve" in spec
    assert spec.count("permutation ") == 2
    assert "536870912 - 89" in spec
    assert "s1_reserve s2_reserve s1_commit" in spec
    assert "s2_reserve s1_reserve s2_commit" in spec
