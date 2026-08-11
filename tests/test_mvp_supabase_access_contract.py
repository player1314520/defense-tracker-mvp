# -*- coding: utf-8 -*-
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (
    ROOT
    / "supabase"
    / "migrations"
    / "202608090023_mvp_access_applications.sql"
)
EDGE = ROOT / "supabase" / "functions" / "access-applications" / "index.ts"
DECISION_POLICY = (
    ROOT
    / "supabase"
    / "functions"
    / "access-applications"
    / "decision-policy.mjs"
)
PROVISIONING_OUTCOME = (
    ROOT
    / "supabase"
    / "functions"
    / "access-applications"
    / "provisioning-outcome.mjs"
)
CONFIG = ROOT / "supabase" / "config.toml"


def _sql() -> str:
    return MIGRATION.read_text(encoding="utf-8").lower()


def _compact(value: str) -> str:
    return " ".join(value.split())


def test_access_application_storage_never_has_plaintext_email():
    sql = _compact(_sql())

    assert "create table if not exists private.access_applications" in sql
    assert "email_hmac text not null" in sql
    assert "email_ciphertext bytea not null" in sql
    assert "email_nonce bytea not null" in sql
    assert "email_key_version integer not null" in sql
    assert "unique (email_hmac)" in sql
    for forbidden in ("email text", "raw_email", "email_address"):
        assert forbidden not in sql
    assert "revoke all on table private.access_applications" in sql


def test_access_application_has_bounded_state_audit_and_rate_limits():
    sql = _compact(_sql())

    assert "status in ('pending','approved','rejected','invited','cancelled')" in sql
    assert "create table if not exists private.access_application_audit" in sql
    assert "create table if not exists private.access_application_rate_buckets" in sql
    assert "submission_count between 1 and 100" in sql
    assert "p_ip_hmac" in sql
    assert "p_user_agent_hmac" in sql
    assert "date_trunc('hour',statement_timestamp())" in sql
    assert "ip_count >= 20" in sql
    assert "date_trunc('day',statement_timestamp())" in sql
    assert "email_count >= 3" in sql
    assert "global_count >= 200" in sql
    assert "consume_access_application_rates(p_ip_hmac,p_email_hmac)" in sql
    assert "on conflict (email_hmac)" in sql


def test_rate_buckets_are_checked_and_incremented_as_one_atomic_unit():
    sql = _compact(_sql())
    start = sql.index(
        "create or replace function private.consume_access_application_rates"
    )
    end = sql.index("$$;", start)
    body = sql[start:end]

    lock = body.index("pg_advisory_xact_lock")
    check = body.index("global_count >= 200")
    increment = body.index("insert into private.access_application_rate_buckets")
    assert lock < check < increment
    assert "or ip_count >= 20 or email_count >= 3" in body
    assert "('global_hour',repeat('0',64),hour_start,1)" in body
    assert "('ip_hour',p_ip_hmac,hour_start,1)" in body
    assert "('email_day',p_email_hmac,day_start,1)" in body
    assert "request_count = bucket.request_count + 1" in body

    submit_start = sql.index(
        "create or replace function private.submit_access_application"
    )
    submit_end = sql.index("$$;", submit_start)
    submit = sql[submit_start:submit_end]
    assert submit.count("consume_access_application_rates(") == 1
    assert "consume_access_application_rate(" not in submit


def test_anonymous_submit_rpc_is_service_only_and_deduplicated():
    sql = _compact(_sql())

    assert "create or replace function public.submit_access_application" in sql
    assert "on conflict (email_hmac)" in sql
    assert "returning id" in sql
    start = sql.index("revoke all on function public.submit_access_application")
    assert "from public, anon, authenticated" in sql[start:start + 500]
    grant = sql.index("grant execute on function public.submit_access_application")
    assert "to service_role" in sql[grant:grant + 500]


def test_review_rpcs_are_single_org_role_and_session_bound():
    sql = _compact(_sql())

    assert "create or replace function private.current_review_organization()" in sql
    helper_start = sql.index(
        "create or replace function private.current_review_organization()"
    )
    helper_end = sql.index("$$;", helper_start)
    helper = sql[helper_start:helper_end]
    assert "m.role in ('owner','admin')" in helper
    assert "private.has_active_device_session" in helper
    assert "more than one review organization" in helper
    for name in (
        "list_access_applications",
        "get_access_application_for_review",
        "decide_access_application",
    ):
        start = sql.index(f"create or replace function public.{name}")
        end = sql.index("$$;", start)
        assert "private.current_review_organization()" in sql[start:end]
    assert "private.begin_member_invitation" in sql


def test_access_review_state_machine_is_locked_and_audited():
    sql = _compact(_sql())
    start = sql.index("create or replace function public.decide_access_application")
    end = sql.index("$$;", start)
    body = sql[start:end]

    assert "for update" in body
    assert "target.status <> 'pending'" in body
    assert "p_decision not in ('approved','rejected')" in body
    assert "insert into private.access_application_audit" in body
    assert "invitation_request_id" in body
    assert "p_email_sha256" in body
    assert (
        "p_role is null or p_role not in ( 'collector','analyst','editor','approver' )"
        in body
    )
    assert "'owner','admin','collector'" not in body
    assert "return jsonb_build_object" in body
    assert "next_status text" in body
    assert "from private.member_invitation_requests r" in body
    assert "next_status := 'invited'" in body
    assert "target.status = 'approved'" in body
    assert "target.invitation_request_id" in body
    assert "invitation_provisioning_state = 'provisioned'" in body
    assert "invitation_provisioning_state = 'terminal_failed'" in body
    assert "target.requested_role = p_role" not in body
    assert "invitation_cancelled" in sql
    assert "p_outcome not in ('invited','retryable','cancelled')" in sql


def test_pending_review_queue_keeps_approved_retryable_items_actionable():
    sql = _compact(_sql())
    start = sql.index("create or replace function public.list_access_applications")
    end = sql.index("$$;", start)
    body = sql[start:end]

    assert (
        "p_status = 'pending' and a.status in ('pending','approved')"
        in body
    )
    assert "'provisioning_status',case" in body
    assert "when item.status = 'approved' then 'retryable'" in body


def test_edge_uses_one_action_endpoint_and_generic_apply_response():
    source = EDGE.read_text(encoding="utf-8")
    compact = _compact(source)

    for action in ('"apply"', '"list"', '"decision"'):
        assert action in source
    assert "ACCESS_APPLICATION_HMAC_KEY" in source
    assert "ACCESS_APPLICATION_ENCRYPTION_KEY" in source
    assert "encryptEmail" in source
    assert "hmacHex" in source
    assert '.rpc("submit_access_application"' in source
    assert "return response(202" in compact
    assert 'status: "received"' in source
    assert "already_exists" not in source
    assert "raw_email" not in source


def test_apply_rate_source_uses_only_the_trusted_proxy_contract():
    source = EDGE.read_text(encoding="utf-8").lower()

    assert 'from "./request-source.mjs"' in source
    assert "trustedrequestsource(request.headers)" in source
    assert "x-real-ip" not in source
    assert "cf-connecting-ip" not in source
    assert "x-forwarded-for" not in source


def test_list_and_decision_require_jwt_and_only_return_masked_email():
    source = EDGE.read_text(encoding="utf-8")

    assert "auth.getUser(token)" in source
    assert '.rpc("list_access_applications"' in source
    assert '"decide_access_application"' in source
    assert "maskEmail" in source
    assert "email_masked" in source
    assert 'delete item.email_ciphertext' in source
    assert 'delete item.email_nonce' in source
    assert 'delete item.email_key_version' in source
    assert "applications," in source
    assert "email: normalizedEmail," in source  # internal provisioning only
    assert "applications.push(item)" not in source
    assert "EdgeRuntime.waitUntil" not in source
    assert ".catch(() => undefined)" not in source
    assert "await provisionInvitation({" in source
    assert "accessProvisioningStatus(provisioning)" in source
    assert "provisioning_status: item.provisioning_status ?? null" in source
    assert '[functions.access-applications]' in CONFIG.read_text(encoding="utf-8")
    assert "verify_jwt = false" in CONFIG.read_text(encoding="utf-8")


def test_access_provisioning_wire_has_explicit_bounded_outcomes():
    policy = PROVISIONING_OUTCOME.read_text(encoding="utf-8")

    assert "export function accessProvisioningStatus" in policy
    for outcome in ('"invited"', '"retryable"', '"cancelled"'):
        assert outcome in policy


def test_edge_decision_uses_the_restricted_application_role_policy():
    source = EDGE.read_text(encoding="utf-8")
    policy = _compact(DECISION_POLICY.read_text(encoding="utf-8"))

    assert 'from "./decision-policy.mjs"' in source
    assert "isApplicationApprovalRole(input.role)" in source
    assert "const APPLICATION_APPROVAL_ROLES = Object.freeze([" in policy
    for role in ("collector", "analyst", "editor", "approver"):
        assert f'"{role}"' in policy
    assert '"owner"' not in policy
    assert '"admin"' not in policy
