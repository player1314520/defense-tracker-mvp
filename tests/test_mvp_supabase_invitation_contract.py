# -*- coding: utf-8 -*-
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (
    ROOT
    / "supabase"
    / "migrations"
    / "202608090022_mvp_invitation_provisioning.sql"
)
EDGE = ROOT / "supabase" / "functions" / "invite-member" / "index.ts"
ADMIN = (
    ROOT
    / "supabase"
    / "functions"
    / "invite-member"
    / "admin-provisioning.ts"
)


def _compact(value: str) -> str:
    return " ".join(value.split())


def test_invitation_provisioning_uses_attempt_fencing_and_replay_safe_ddl():
    sql = _compact(MIGRATION.read_text(encoding="utf-8").lower())

    assert "add column if not exists provisioning_state" in sql
    assert "add column if not exists provisioning_attempt_id" in sql
    assert "add column if not exists provisioning_lease_until" in sql
    assert "provisioning_attempt_count" in sql
    assert "create or replace function private.claim_member_invitation_provisioning" in sql
    assert "for update" in sql
    assert "gen_random_uuid()" in sql
    assert "interval '120 seconds'" in sql
    assert "stale_attempt" in sql


def test_provisioning_rpcs_are_service_role_only_and_redacted():
    sql = _compact(MIGRATION.read_text(encoding="utf-8").lower())

    for name in (
        "claim_member_invitation_provisioning",
        "finish_member_invitation_provisioning",
    ):
        revoke = sql.index(f"revoke all on function public.{name}")
        assert "from public, anon, authenticated" in sql[revoke:revoke + 500]
        grant = sql.index(f"grant execute on function public.{name}")
        assert "to service_role" in sql[grant:grant + 500]
    assert "'email_sha256'" not in sql


def test_cancelled_inflight_attempt_requests_compensation():
    sql = _compact(MIGRATION.read_text(encoding="utf-8").lower())

    assert "'compensate',true" in sql
    assert "'invitation_closed'" in sql
    assert "provisioning_state = 'terminal_failed'" in sql
    assert "compensation_failed" in sql


def test_already_finalized_invitation_is_never_compensated():
    sql = _compact(MIGRATION.read_text(encoding="utf-8").lower())
    finish = sql[
        sql.index(
            "create or replace function private."
            "finish_member_invitation_provisioning"
        ):
    ]
    assert "target.status = 'finalized'" in finish
    finalized = finish.index("target.status = 'finalized'")
    closed = finish.index("if target.status <> 'requested'", finalized)
    assert finalized < closed
    assert "'compensate',false" in finish[finalized:closed]


def test_missing_inviter_membership_is_fail_closed():
    sql = _compact(MIGRATION.read_text(encoding="utf-8").lower())

    assert sql.count(
        "inviter_role is null or inviter_role not in ('owner','admin')"
    ) >= 2


def test_claim_reports_reconcilable_terminal_and_retry_states():
    sql = _compact(MIGRATION.read_text(encoding="utf-8").lower())
    start = sql.index(
        "create or replace function private.claim_member_invitation_provisioning"
    )
    end = sql.index("$$;", start)
    claim = sql[start:end]

    assert "'action','noop'" not in claim
    assert "'action','busy'" in claim
    assert "'action','provisioned'" in claim
    assert "'action','cancelled'" in claim
    assert "'action','provision'" in claim


def test_invite_edge_runs_background_email_invitation_with_fixed_redirect():
    source = EDGE.read_text(encoding="utf-8")
    admin = ADMIN.read_text(encoding="utf-8")

    assert "provisionInvitation" in source
    assert "EdgeRuntime.waitUntil" in source
    assert "SUPABASE_SERVICE_ROLE_KEY" not in source
    assert "inviteUserByEmail" in admin
    assert "V9_INVITE_REDIRECT_URL" in admin
    assert "input.redirect_to" not in source
    assert '.rpc("claim_member_invitation_provisioning"' in admin
    assert '.rpc("finish_member_invitation_provisioning"' in admin
    assert '.rpc(\n        "finish_access_application_invitation"' in admin
    assert "applicationApplied: await finishApplication(applicationOutcome)" in admin
    assert "deleteUser" in admin
    assert "console.log" not in admin
