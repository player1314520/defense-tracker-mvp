# -*- coding: utf-8 -*-
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CAPACITY = (
    ROOT
    / "supabase"
    / "migrations"
    / "202608280027_v9_atomic_capacity_and_event_quota.sql"
)
RETENTION = (
    ROOT
    / "supabase"
    / "migrations"
    / "202608280028_v9_access_retention.sql"
)
PUSH = (
    ROOT
    / "supabase"
    / "migrations"
    / "202607300020_v9_push_runtime_fix.sql"
)
CAPACITY_TEST = (
    ROOT / "supabase" / "tests" / "v9_capacity_quota_test.sql"
)


def compact(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").lower().split())


def test_active_and_reserved_seats_share_one_atomic_capacity_ledger():
    sql = compact(CAPACITY)

    assert "create table private.organization_seat_usage" in sql
    assert "check (used_seats between 0 and 100)" in sql
    assert "create table private.organization_seat_reservations" in sql
    assert "for update" in sql
    assert "u.used_seats < 100" in sql
    assert "organization active and reserved seat limit exceeded" in sql
    assert "member_invitation_capacity_guard" in sql
    assert "memberships_capacity_guard" in sql
    assert "'invitation:' || m.invitation_request_id::text" in sql
    assert "on conflict (organization_id,reservation_key) do nothing" in sql
    assert "revoke all on table private.organization_seat_usage" in sql


def test_event_quota_is_atomic_per_user_and_utc_day():
    sql = compact(CAPACITY)

    assert "create table private.sync_event_daily_usage" in sql
    assert "primary key (user_id,usage_date)" in sql
    assert "event_count between 1 and 1000" in sql
    assert "statement_timestamp() at time zone 'utc'" in sql
    assert "on conflict (user_id,usage_date) do update" in sql
    assert "event_count < 1000" in sql
    assert "daily sync event limit exceeded" in sql
    assert "before insert on public.sync_events" in sql
    assert "event device owner mismatch" in sql


def test_duplicate_push_returns_before_quota_triggered_insert():
    push = compact(PUSH)
    duplicate = push.index("'duplicate',true")
    event_insert = push.index("insert into public.sync_events", duplicate)

    assert duplicate < event_insert
    assert "perform pg_advisory_xact_lock" in push[:duplicate]


def test_capacity_fixture_supplies_required_request_hashes():
    sql = compact(CAPACITY_TEST)

    assert sql.count("operation,applied,request_hash") == 3
    assert sql.count("extensions.digest(") == 3
    assert "'50000000-0000-0000-0000-000000001001','sha256'" in sql
    assert "'50000000-0000-0000-0000-000000000001','sha256'" in sql


def test_access_retention_is_bounded_and_service_role_only():
    sql = compact(RETENTION)

    assert "p_now - interval '29 days'" in sql
    assert sql.count("p_now - interval '179 days'") >= 3
    assert "a.reviewed_at <= p_now" in sql
    assert "coalesce(r.finalized_at,r.cancelled_at,r.expires_at) <= p_now" in sql
    assert "m.status = 'invited'" in sql
    assert "usage_date < (p_now at time zone 'utc')::date - 7" in sql
    for column in (
        "email_hmac = null",
        "email_ciphertext = null",
        "email_nonce = null",
        "last_ip_hmac = null",
        "last_user_agent_hmac = null",
        "invitation_request_id = null",
    ):
        assert column in sql
    assert "email_sha256 = null" in sql
    assert "if (select auth.role()) is distinct from 'service_role'" in sql
    assert (
        "grant execute on function "
        "public.purge_expired_access_application_data() to service_role"
    ) in sql
    assert (
        "revoke all on function public.purge_expired_access_application_data() "
        "from public, anon, authenticated"
    ) in sql
    assert "jsonb_build_object(" in sql


def test_purged_contacts_are_excluded_before_list_pagination_and_review():
    sql = compact(RETENTION)
    list_start = sql.index(
        "create or replace function public.list_access_applications"
    )
    review_start = sql.index(
        "create or replace function public.get_access_application_for_review",
        list_start,
    )
    purge_start = sql.index(
        "create or replace function private.purge_access_application_data",
        review_start,
    )
    list_body = sql[list_start:review_start]
    review_body = sql[review_start:purge_start]

    assert "where a.contact_purged_at is null" in list_body
    assert list_body.index("where a.contact_purged_at is null") < list_body.index(
        "limit bounded_limit"
    )
    assert "select a.created_at into cursor_created" in list_body
    assert "where a.id = p_cursor" in list_body
    assert "where a.id = p_cursor and a.contact_purged_at is null" not in list_body
    assert "and a.contact_purged_at is null" in review_body
    assert "'contact_purged'" not in list_body


def test_approved_provisioning_grace_and_lease_are_bounded_by_contact_deadline():
    sql = compact(RETENTION)
    purge_start = sql.index(
        "create or replace function private.purge_access_application_data"
    )
    public_purge_start = sql.index(
        "create or replace function public.purge_expired_access_application_data",
        purge_start,
    )
    body = sql[purge_start:public_purge_start]

    assert "provisioning_grace interval := interval '5 minutes'" in body
    assert "contact_retention_limit interval := interval '24 hours'" in body
    assert "a.reviewed_at + contact_retention_limit <= p_now" in body
    assert "a.reviewed_at + provisioning_grace <= p_now" in body
    assert "r.id = a.invitation_request_id" in body
    assert "r.status = 'requested'" in body
    assert "r.provisioning_state = 'leased'" in body
    assert "r.provisioning_attempt_id is not null" in body
    assert "r.provisioning_lease_until > p_now" in body
    assert "closed_requests as ( update private.member_invitation_requests r" in body
    assert "from stale s" in body
    assert "r.id = s.invitation_request_id" in body
    assert body.count("then r.provisioning_attempt_id else null") >= 2
    assert body.count("then r.provisioning_lease_until else null") >= 2
    assert body.count("else 'terminal_failed' end") >= 2

    contact_update = body.index("set email_hmac = null")
    contact_where = body[contact_update:]
    assert "and a.status <> 'approved'" in contact_where
