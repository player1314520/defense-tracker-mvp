# -*- coding: utf-8 -*-
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (
    ROOT
    / "supabase"
    / "migrations"
    / "202608100026_mvp_idempotent_device_registration.sql"
)


def _sql() -> str:
    return " ".join(MIGRATION.read_text(encoding="utf-8").lower().split())


def test_registration_wrapper_uses_the_device_kind_aware_private_rpc():
    sql = _sql()

    assert (
        "create or replace function private.register_mvp_device( "
        "organization_id uuid, device_id uuid, key_algorithm text, "
        "device_public_key text, device_name_ciphertext text, "
        "device_name_nonce text, device_kind text )"
    ) in sql
    public = sql[sql.index("create or replace function public.register_device"):]
    assert "private.can_register_device_session(organization_id)" in public
    assert "private.register_mvp_device(" in public
    assert "update public.devices" not in public


def test_exact_pending_or_active_desktop_replay_is_idempotent():
    sql = _sql()
    start = sql.index("create or replace function private.register_mvp_device")
    end = sql.index("$$;", start)
    body = sql[start:end]

    existing = body.index("select d.* into existing")
    limits = body.index("select count(*) into pending_device_count")
    inserted = body.index("insert into public.devices")
    assert existing < limits < inserted
    assert "existing.user_id is distinct from actor" in body
    assert "existing.key_algorithm <> 'p256'" in body
    assert "existing.device_kind <> 'desktop'" in body
    assert "key_algorithm <> 'p256'" in body
    assert "device_kind <> 'desktop'" in body
    assert "existing.public_key <> decoded_public_key" in body
    assert "existing.name_ciphertext <> decoded_name_ciphertext" in body
    assert "existing.name_nonce <> decoded_name_nonce" in body
    assert "existing.status not in ('pending','active')" in body
    assert "existing.status = 'active' and membership_status <> 'active'" in body
    assert "return existing.id" in body


def test_replay_preserves_invitation_binding_and_rejects_any_difference():
    sql = _sql()
    start = sql.index("create or replace function private.register_mvp_device")
    end = sql.index("$$;", start)
    body = sql[start:end]

    assert "membership_invitation_id" in body
    assert (
        "membership_status = 'invited' and existing.invitation_request_id "
        "is distinct from membership_invitation_id"
    ) in body
    assert (
        "existing.invitation_request_id is not null and "
        "existing.invitation_request_id is distinct from membership_invitation_id"
    ) in body
    assert "raise exception 'device registration conflict'" in body
    insert = body[body.index("insert into public.devices"):]
    assert " on conflict " not in f" {insert} "
    assert "update public.devices" not in body


def test_new_registration_retains_original_limits_and_invitation_binding():
    sql = _sql()

    assert "invited member already has pending device" in sql
    assert "active member pending device limit reached" in sql
    assert "pending_device_count >= 1" in sql
    assert "pending_device_count >= 5" in sql
    assert (
        "when membership_status = 'invited' then membership_invitation_id"
        in sql
    )
    assert "device_kind" in sql


def test_registration_acl_remains_authenticated_rpc_only():
    sql = _sql()
    private_signature = (
        "private.register_mvp_device(uuid,uuid,text,text,text,text,text)"
    )
    public_signature = "public.register_device(uuid,uuid,text,text,text,text,text)"

    private_revoke = sql.index(f"revoke all on function {private_signature}")
    public_revoke = sql.index(f"revoke all on function {public_signature}")
    public_grant = sql.index(f"grant execute on function {public_signature}")
    assert "from public, anon, authenticated, service_role" in sql[
        private_revoke:public_revoke
    ]
    assert "from public, anon, authenticated" in sql[
        public_revoke:public_grant
    ]
    assert "to authenticated" in sql[public_grant:public_grant + 180]
    assert f"grant execute on function {private_signature}" not in sql
