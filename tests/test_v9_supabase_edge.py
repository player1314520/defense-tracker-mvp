# -*- coding: utf-8 -*-
from pathlib import Path


FUNCTION = (
    Path(__file__).resolve().parents[1]
    / "supabase"
    / "functions"
    / "invite-member"
    / "index.ts"
)


def test_invite_function_is_metadata_only_and_pins_dependencies():
    source = FUNCTION.read_text(encoding="utf-8")

    assert "functions-js@2.4.5" in source
    assert "supabase-js@2.95.0" in source
    assert "inviteUserByEmail" not in source
    assert '"organization_id"' in source
    assert '"email"' in source
    assert '"role"' in source
    for forbidden in (
        '"content"',
        '"body"',
        '"plaintext"',
        '"evidence_body"',
        '"report_body"',
    ):
        assert forbidden not in source


def test_invite_function_verifies_jwt_role_and_origin():
    source = FUNCTION.read_text(encoding="utf-8")

    assert "auth.getUser(token)" in source
    assert '.rpc("begin_member_invitation"' in source
    assert "accept_member_invitation" not in source
    assert '.from("memberships")' not in source
    assert "V9_ALLOWED_ORIGINS" in source
    assert "origin_not_allowed" in source


def test_invite_function_manually_verifies_opaque_publishable_key_sessions():
    config = FUNCTION.parents[2] / "config.toml"
    source = config.read_text(encoding="utf-8")

    assert "[functions.invite-member]" in source
    assert "verify_jwt = false" in source


def test_invite_edge_never_reads_secret_or_sends_auth_email():
    source = FUNCTION.read_text(encoding="utf-8")

    assert "lookup_invitation_auth_user" not in source
    assert "SUPABASE_SECRET_KEYS" not in source
    assert "SUPABASE_SERVICE_ROLE_KEY" not in source
    assert "inviteUserByEmail" not in source
    assert "signInWithOtp" not in source


def test_invite_function_supports_new_named_keys_without_logging_them():
    source = FUNCTION.read_text(encoding="utf-8")

    assert '"SUPABASE_PUBLISHABLE_KEYS"' in source
    assert '"SUPABASE_ANON_KEY"' not in source
    assert "JSON.parse" in source
    assert '["default"]' in source
    assert 'startsWith("sb_publishable_")' in source
    assert "console.log" not in source
    assert "console.error" not in source
