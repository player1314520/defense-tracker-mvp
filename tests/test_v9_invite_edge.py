# -*- coding: utf-8 -*-
from pathlib import Path


EDGE_FUNCTION = (
    Path(__file__).resolve().parents[1]
    / "supabase"
    / "functions"
    / "invite-member"
    / "index.ts"
)


def test_invite_contract_does_not_accept_or_choose_auth_redirects():
    source = EDGE_FUNCTION.read_text(encoding="utf-8")

    assert '"redirect_to"' not in source
    assert "V9_ALLOWED_REDIRECT_URLS" not in source
    assert "allowedRedirects" not in source
    assert "redirectTo" not in source


def test_invite_function_accepts_metadata_only_and_requires_authenticated_admin():
    source = EDGE_FUNCTION.read_text(encoding="utf-8")

    assert '"organization_id"' in source
    assert '"email"' in source
    assert '"role"' in source
    assert '"redirect_to"' not in source
    assert "metadata_fields_only" in source
    assert '.rpc("begin_member_invitation"' in source
    assert '.rpc("accept_member_invitation"' not in source
    assert '.from("memberships")' not in source
    assert "membership_write_failed" not in source


def test_invite_authenticates_before_bounded_plain_object_body_read():
    source = EDGE_FUNCTION.read_text(encoding="utf-8")

    authenticate = source.index("auth.getUser(token)")
    body_read = source.index("readBoundedJsonObject(request)")
    assert authenticate < body_read
    assert "MAX_BODY_BYTES = 8 * 1024" in source
    assert "request.body.getReader()" in source
    assert "request.json()" not in source
    assert "body_too_large" in source
    assert "plain_json_object_required" in source
    assert "verify_jwt = false" in (
        EDGE_FUNCTION.parents[2] / "config.toml"
    ).read_text(encoding="utf-8")


def test_invite_hashes_email_and_only_registers_business_invitation():
    source = EDGE_FUNCTION.read_text(encoding="utf-8")

    assert "crypto.subtle.digest" in source
    assert "emailSha256" in source
    assert "inviteUserByEmail" not in source
    assert "signInWithOtp" not in source
    assert "SUPABASE_SECRET_KEYS" not in source
    assert "SUPABASE_SERVICE_ROLE_KEY" not in source
    assert 'typeof input.organization_id !== "string"' in source
    assert 'typeof input.email !== "string"' in source
    assert 'typeof input.role !== "string"' in source
    assert "input.redirect_to" not in source
    assert "accepted: true" not in source
    assert 'status: "registered"' in source
    assert "request_reference: crypto.randomUUID()" in source
    assert "邀请已登记，成员需在目标设备发起登录" in source


def test_invite_returns_generic_202_without_auth_email_enumeration():
    source = EDGE_FUNCTION.read_text(encoding="utf-8")

    assert "lookup_invitation_auth_user" not in source
    assert "return response(201" not in source
    assert "return response(409" not in source
    assert "invitationRegisteredResponse(" in source
    assert "invitationRegisteredResponse(origin, invitationId)" not in source
    assert "response(202" in source
    assert "PKCE 已闭环" not in source


def test_invite_email_validation_matches_signup_hook_and_key_is_publishable():
    source = EDGE_FUNCTION.read_text(encoding="utf-8")

    assert "email.split(\"@\", 1)[0].length > 64" in source
    assert "sb_publishable_" in source
    assert "SUPABASE_ANON_KEY" not in source


def test_invite_does_not_claim_target_pkce_is_complete():
    source = EDGE_FUNCTION.read_text(encoding="utf-8")

    assert "Auth 模板和目标设备 PKCE 仍是外部配置门" in source
    assert "inviteUserByEmail" not in source
    assert "signInWithOtp" not in source
