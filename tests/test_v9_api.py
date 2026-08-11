# -*- coding: utf-8 -*-
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask


def _client(
    tmp_path,
    agent_phase_executor=None,
    cloud_provider=None,
    auth_check=None,
):
    from v9.api import create_blueprint
    from v9.service import V9Service

    service = V9Service(
        tmp_path / "v9.sqlite3", tmp_path / ".v9_local_master.key"
    )
    app = Flask(__name__)
    app.register_blueprint(
        create_blueprint(
            lambda: service,
            auth_check=auth_check,
            agent_phase_executor=agent_phase_executor,
            cloud_provider=cloud_provider,
        )
    )
    return app.test_client(), service


def _personal_headers(context):
    return {
        "X-V9-Context-Mode": "personal",
        "X-V9-Organization-ID": context["organization_id"],
    }


def _cloud_headers(organization_id):
    return {
        "X-V9-Context-Mode": "cloud",
        "X-V9-Organization-ID": organization_id,
    }


def _ready_personal_context(service):
    context = service.get_or_create_personal_context()
    service.acknowledge_personal_recovery(context["organization_id"])
    return context


class _CloudSettings:
    def public_config(self):
        return {
            "configured": True,
            "url": "https://project-ref.supabase.co",
            "publishable_key": "sb_publishable_public",
            "environment": "staging",
            "redirect_ports": [49231, 49232, 49233, 49234, 49235],
        }


class _CloudClient:
    def __init__(self):
        self.calls = []
        self.record_heads = []
        self.devices = []
        self.organization_id = "00000000-0000-4000-8000-000000000001"
        self.user_id = "00000000-0000-4000-8000-000000000099"
        self.key_version = 1

    def select(self, table, token, query=None):
        self.calls.append((table, token, query))
        if table == "memberships":
            return [{
                "organization_id": self.organization_id,
                "user_id": self.user_id,
                "role": "analyst",
                "status": "active",
            }]
        if table == "organizations":
            return [{
                "id": self.organization_id,
                "key_version": self.key_version,
            }]
        if table == "record_heads":
            return list(self.record_heads)
        if table == "devices":
            return list(self.devices)
        return []


class _CloudSession:
    def __init__(self):
        self.settings = _CloudSettings()
        self.client = _CloudClient()
        self.accepted = None
        self.sign_out_called = False
        self.snapshot_import = None
        self.resolve_result = None
        self.resolve_error = None
        self.rpc_calls = []

    def status(self):
        return {
            "configured": True,
            "authenticated": self.accepted is not None,
            "user_id": (
                "00000000-0000-4000-8000-000000000099"
                if self.accepted else None
            ),
        }

    def accept_session(self, **payload):
        self.accepted = payload
        return self.status()

    def access_token(self):
        return "jwt-from-memory"

    def user_id(self):
        return "00000000-0000-4000-8000-000000000099"

    def clear(self):
        self.accepted = None

    def sign_out(self):
        self.sign_out_called = True
        self.accepted = None

    def start_email_login(self, email, redirect_uri):
        self.login_start = {
            "email": email,
            "redirect_uri": redirect_uri,
        }
        return {"sent": True, "redirect_uri": redirect_uri}

    def complete_email_login(self, code):
        self.login_code = code
        self.accepted = {
            "access_token": "from-pkce",
            "refresh_token": "dpapi-only",
            "expires_at": 1900000000.0,
        }
        return self.status()

    def rpc(self, name, payload):
        self.rpc_calls.append((name, payload))
        if name == "bootstrap_organization":
            import base64

            self.client.organization_id = payload[
                "requested_organization_id"
            ]
            self.client.devices = [{
                "id": payload["device_id"],
                "organization_id": payload["requested_organization_id"],
                "user_id": self.user_id(),
                "key_algorithm": payload["key_algorithm"],
                "device_kind": "desktop",
                "public_key": "\\x" + base64.urlsafe_b64decode(
                    payload["device_public_key"] + "="
                ).hex(),
                "status": "active",
            }]
            return payload["requested_organization_id"]
        if name == "bind_device_session":
            matches = [
                device for device in self.client.devices
                if device.get("id") == payload.get("p_device_id")
                and device.get("organization_id")
                == payload.get("p_organization_id")
                and device.get("user_id") == self.user_id()
                and device.get("status") == "active"
            ]
            if len(matches) != 1:
                from v9.supabase_client import SupabaseRequestError

                raise SupabaseRequestError(
                    403, "rpc:bind_device_session"
                )
            return {
                "organization_id": payload["p_organization_id"],
                "device_id": payload["p_device_id"],
                "status": "active",
            }
        if name == "push_record_event":
            event = payload["p_event"]
            if (
                event["operation"] == "snapshot"
                and self.snapshot_import is not None
                and self.snapshot_import["status"] == "staging"
            ):
                self.snapshot_import["accepted_count"] += 1
            return {"cursor": 1, "applied": True}
        if name == "pull_sync_events":
            return []
        if name == "list_sync_devices":
            import base64

            rows = []
            for device in self.client.devices:
                if (
                    device.get("organization_id")
                    != payload["p_organization_id"]
                    or device.get("status") != "active"
                ):
                    continue
                raw = device.get("public_key")
                if isinstance(raw, str) and raw.startswith("\\x"):
                    raw = bytes.fromhex(raw[2:])
                rows.append({
                    "org_id": device["organization_id"],
                    "device_id": device["id"],
                    "key_algorithm": device["key_algorithm"],
                    "public_key": base64.urlsafe_b64encode(
                        bytes(raw)
                    ).decode("ascii").rstrip("="),
                })
            return rows
        if name == "begin_snapshot_import":
            requested = {
                "organization_id": payload["organization_id"],
                "expected_count": payload["expected_count"],
                "manifest_hash": payload["manifest_hash"],
            }
            if self.snapshot_import is None:
                self.snapshot_import = {
                    "import_id": "00000000-0000-4000-8000-000000000091",
                    **requested,
                    "accepted_count": 0,
                    "status": "staging",
                    "resumed": False,
                }
            elif any(
                self.snapshot_import[key] != value
                for key, value in requested.items()
            ):
                raise RuntimeError("snapshot import manifest mismatch")
            else:
                self.snapshot_import["resumed"] = True
            return dict(self.snapshot_import)
        if name == "complete_snapshot_import":
            if self.snapshot_import is None:
                raise RuntimeError("snapshot import not found")
            if (
                self.snapshot_import["accepted_count"]
                != self.snapshot_import["expected_count"]
            ):
                raise RuntimeError("snapshot import is incomplete")
            self.snapshot_import["status"] = "completed"
            return dict(self.snapshot_import)
        if name == "abort_snapshot_import":
            if self.snapshot_import is None:
                raise RuntimeError("snapshot import not found")
            if self.snapshot_import["accepted_count"] != 0:
                raise RuntimeError("accepted snapshot import cannot be aborted")
            self.snapshot_import["status"] = "aborted"
            return dict(self.snapshot_import)
        if name == "resolve_conflict":
            if self.resolve_error is not None:
                raise self.resolve_error
            return self.resolve_result or {
                "resolved_conflict_id": payload["conflict_id"],
                "head_version_id": (
                    payload["resolution_event"]["payload"]["version_id"]
                ),
                "version_id": (
                    payload["resolution_event"]["payload"]["version_id"]
                ),
                "applied": True,
            }
        raise AssertionError(name)


def test_bootstrap_create_and_read_local_encrypted_record(tmp_path):
    client, _ = _client(tmp_path)
    boot = client.post(
        "/api/v9/organizations/bootstrap",
        json={"name": "Personal", "user_id": "owner", "device_name": "Desktop"},
    ).get_json()
    acknowledged = client.post(
        "/api/v9/organizations/bootstrap/acknowledge",
        json={"organization_id": boot["organization_id"]},
    )
    assert acknowledged.status_code == 200

    created = client.post(
        "/api/v9/records",
        headers=_personal_headers(boot),
        json={
            "organization_id": boot["organization_id"],
            "user_id": "owner",
            "device_id": boot["device_id"],
            "record_type": "evidence",
            "content": {"body": "local only"},
        },
    )
    assert created.status_code == 201
    record_id = created.get_json()["record_id"]

    read = client.get(
        f"/api/v9/records/{record_id}",
        headers=_personal_headers(boot),
        query_string={
            "organization_id": boot["organization_id"],
            "user_id": "owner",
        },
    )
    assert read.status_code == 200
    assert read.get_json()["content"]["body"] == "local only"


def test_unacknowledged_recovery_survives_restart_and_blocks_business(
    tmp_path,
):
    first_client, _ = _client(tmp_path)
    first = first_client.post(
        "/api/v9/organizations/bootstrap",
        json={"name": "Personal", "device_name": "Desktop"},
    ).get_json()

    blocked = first_client.get(
        "/api/v9/evidence",
        headers=_personal_headers(first),
    )
    discovery = first_client.get("/api/v9/business-context/personal")

    restarted_client, restarted_service = _client(tmp_path)
    resumed = restarted_client.post(
        "/api/v9/organizations/bootstrap",
        json={"name": "Personal", "device_name": "Desktop"},
    ).get_json()

    assert blocked.status_code == 403
    assert discovery.status_code == 409
    assert discovery.get_json()["recovery_pending"] is True
    assert resumed["organization_id"] == first["organization_id"]
    assert resumed["recovery_code"] == first["recovery_code"]

    acknowledged = restarted_client.post(
        "/api/v9/organizations/bootstrap/acknowledge",
        json={"organization_id": first["organization_id"]},
    )
    available = restarted_client.get("/api/v9/business-context/personal")

    assert acknowledged.status_code == 200
    assert acknowledged.get_json()["recovery_acknowledged"] is True
    assert available.status_code == 200
    assert restarted_service.personal_recovery_pending() is False


def test_cloud_sync_endpoint_rejects_plaintext_business_body(tmp_path):
    client, _ = _client(tmp_path)
    organization_id = "00000000-0000-4000-8000-000000000001"

    response = client.post(
        "/api/v9/sync/push",
        headers=_personal_headers({"organization_id": organization_id}),
        json={
            "organization_id": organization_id,
            "user_id": "user",
            "content": {"body": "must never reach cloud adapter"},
        },
    )

    assert response.status_code == 400
    assert "密文" in response.get_json()["error"]


def test_publication_api_rejects_forged_signed_generic_record(tmp_path):
    client, service = _client(tmp_path)
    context = _ready_personal_context(service)

    response = client.post(
        "/api/v9/records",
        headers=_personal_headers(context),
        json={
            "organization_id": context["organization_id"],
            "user_id": context["user_id"],
            "device_id": context["device_id"],
            "record_type": "publication_item",
            "content": {"status": "signed"},
        },
    )

    assert response.status_code == 403
    assert "工作流" in response.get_json()["error"]


def test_main_application_registers_v9_routes():
    import app as tracker

    rules = {rule.rule for rule in tracker.app.url_map.iter_rules()}
    assert "/api/v9/organizations/bootstrap" in rules
    assert "/api/v9/records" in rules
    assert "/api/v9/sync/push" in rules
    assert "/api/v9/jobs" in rules
    assert "/api/v9/scenarios" in rules
    assert "/api/v9/documents" in rules
    assert "/api/v9/publications" in rules
    assert "/api/v9/pairing-sessions" in rules
    assert "/api/v9/pairing-sessions/claim" in rules
    assert "/api/v9/organizations/<org_id>/diagnostics" in rules
    assert "/api/v9/organizations/<org_id>/backups" in rules
    assert "/api/v9/diagnostics/export" in rules
    assert "/api/v9/backups" in rules
    assert "/api/v9/auth/start" in rules
    assert "/api/v9/auth/callback" in rules
    assert "/api/v9/auth/session" in rules
    assert "/api/v9/auth/realtime-token" in rules
    assert "/api/v9/organizations" in rules
    assert "/api/v9/devices" in rules
    assert "/api/v9/devices/self" in rules
    assert "/api/v9/members/invitations" in rules
    assert "/api/v9/members/invitations/<invitation_id>" in rules
    assert "/api/v9/sync/run" in rules
    assert "/api/v9/sync/status" in rules
    assert "/api/v9/sync/bootstrap-snapshot" in rules
    assert "/api/v9/sync/bootstrap-snapshot/complete" in rules
    assert "/api/v9/conflicts/<conflict_id>/resolve" in rules


def test_cloud_auth_uses_server_pkce_and_organizations_use_jwt_identity(tmp_path):
    cloud = _CloudSession()
    client, _ = _client(tmp_path, cloud_provider=lambda: cloud)

    config = client.get(
        "/api/v9/auth/start",
        base_url="http://127.0.0.1:49231",
    )
    assert config.status_code == 200
    assert config.get_json()["publishable_key"] == "sb_publishable_public"

    started = client.post(
        "/api/v9/auth/start",
        json={"email": "invited@example.test"},
        base_url="http://127.0.0.1:49231",
    )
    assert started.status_code == 202
    assert cloud.login_start == {
        "email": "invited@example.test",
        "redirect_uri": (
            "http://127.0.0.1:49231/api/v9/auth/callback"
        ),
    }
    accepted = client.get(
        "/api/v9/auth/callback?code=one-time-code",
        base_url="http://127.0.0.1:49231",
    )
    assert accepted.status_code == 302
    assert cloud.login_code == "one-time-code"

    organizations = client.get(
        "/api/v9/organizations",
        query_string={"user_id": "forged-user-must-be-ignored"},
        base_url="http://127.0.0.1:49231",
    )
    assert organizations.status_code == 200
    assert organizations.get_json()["organizations"][0]["role"] == "analyst"
    assert organizations.headers["Cache-Control"] == "no-store, private"
    assert organizations.headers["Pragma"] == "no-cache"
    assert cloud.client.calls[0][1] == "jwt-from-memory"

    realtime = client.get(
        "/api/v9/auth/realtime-token",
        base_url="http://127.0.0.1:49231",
    )
    assert realtime.status_code == 200
    assert realtime.get_json()["access_token"] == "jwt-from-memory"
    assert realtime.headers["Cache-Control"] == "no-store, private"
    assert realtime.headers["Pragma"] == "no-cache"


def test_v9_api_rejects_dns_rebinding_wrong_port_and_cross_origin_posts(tmp_path):
    client, _ = _client(tmp_path)

    rebound = client.get(
        "/api/v9/auth/session",
        headers={"Host": "attacker.example:49231"},
        environ_overrides={"SERVER_PORT": "49231"},
    )
    wrong_port = client.get(
        "/api/v9/auth/session",
        headers={"Host": "127.0.0.1:49232"},
        environ_overrides={"SERVER_PORT": "49231"},
    )
    cross_origin = client.post(
        "/api/v9/organizations/bootstrap",
        json={"name": "Personal", "device_name": "Desktop"},
        base_url="http://127.0.0.1:49231",
        headers={"Origin": "https://attacker.example"},
    )

    assert rebound.status_code == 403
    assert wrong_port.status_code == 403
    assert cross_origin.status_code == 403


def test_v9_api_requires_origin_for_browser_context_but_allows_local_clients(
    tmp_path,
):
    client, _ = _client(tmp_path)

    missing_browser_origin = client.post(
        "/api/v9/organizations/bootstrap",
        json={"name": "Personal", "device_name": "Desktop"},
        base_url="http://127.0.0.1:49231",
        headers={"Sec-Fetch-Site": "same-origin"},
    )
    local_client = client.post(
        "/api/v9/organizations/bootstrap",
        json={"name": "Personal", "device_name": "Desktop"},
        base_url="http://127.0.0.1:49231",
    )

    assert missing_browser_origin.status_code == 403
    assert local_client.status_code == 201


def test_server_side_pkce_uses_exact_current_loopback_callback(tmp_path):
    cloud = _CloudSession()
    client, _ = _client(tmp_path, cloud_provider=lambda: cloud)

    started = client.post(
        "/api/v9/auth/start",
        json={"email": "member@example.test"},
        base_url="http://127.0.0.1:49231",
        headers={"Origin": "http://127.0.0.1:49231"},
    )
    callback = client.get(
        "/api/v9/auth/callback?code=one-time-code",
        base_url="http://127.0.0.1:49231",
    )

    assert started.status_code == 202
    assert cloud.login_start == {
        "email": "member@example.test",
        "redirect_uri": (
            "http://127.0.0.1:49231/api/v9/auth/callback"
        ),
    }
    assert callback.status_code == 302
    assert callback.headers["Location"].endswith("/?v9-auth=complete")
    assert cloud.login_code == "one-time-code"


def test_pkce_callback_bypasses_only_legacy_access_token_gate(tmp_path):
    from flask import jsonify

    cloud = _CloudSession()

    def deny_legacy_access():
        return jsonify({"error": "legacy access token required"}), 401

    client, _ = _client(
        tmp_path,
        cloud_provider=lambda: cloud,
        auth_check=deny_legacy_access,
    )

    callback = client.get(
        "/api/v9/auth/callback?code=one-time-code",
        base_url="http://127.0.0.1:49231",
    )
    session = client.get(
        "/api/v9/auth/session",
        base_url="http://127.0.0.1:49231",
    )
    wrong_host = client.get(
        "/api/v9/auth/callback?code=one-time-code",
        headers={"Host": "attacker.example:49231"},
        environ_overrides={"SERVER_PORT": "49231"},
    )
    wrong_method = client.post(
        "/api/v9/auth/callback?code=one-time-code",
        base_url="http://127.0.0.1:49231",
    )

    assert callback.status_code == 302
    assert cloud.login_code == "one-time-code"
    assert session.status_code == 401
    assert wrong_host.status_code == 403
    assert wrong_method.status_code == 405


def test_auth_callback_rejects_token_hash_and_non_pkce_query_shapes(tmp_path):
    cloud = _CloudSession()
    client, _ = _client(tmp_path, cloud_provider=lambda: cloud)

    token_hash = "secret-token-hash-must-not-be-processed"
    token_response = client.get(
        "/api/v9/auth/callback",
        query_string={"token_hash": token_hash, "type": "invite"},
        base_url="http://127.0.0.1:49231",
    )
    mixed_response = client.get(
        "/api/v9/auth/callback",
        query_string={
            "code": "one-time-code",
            "token_hash": token_hash,
            "type": "magiclink",
        },
        base_url="http://127.0.0.1:49231",
    )
    duplicate_code = client.get(
        "/api/v9/auth/callback?code=first&code=second",
        base_url="http://127.0.0.1:49231",
    )

    assert token_response.status_code == 400
    assert mixed_response.status_code == 400
    assert duplicate_code.status_code == 400
    assert token_hash not in token_response.get_data(as_text=True)
    assert not hasattr(cloud, "login_code")


def test_auth_callback_access_log_redacts_the_entire_query():
    import logging

    from v9.api import _redact_auth_callback_access_log

    secret = "one-time-code-must-not-be-logged"
    message = (
        '127.0.0.1 - - "GET /api/v9/auth/callback?'
        f'code={secret}&type=invite HTTP/1.1" 302 -'
    )

    redacted = _redact_auth_callback_access_log(message)

    assert secret not in redacted
    assert "/api/v9/auth/callback?[REDACTED]" in redacted
    assert "type=invite" not in redacted

    record = logging.LogRecord(
        "werkzeug",
        logging.INFO,
        __file__,
        1,
        message,
        (),
        None,
    )
    for log_filter in logging.getLogger("werkzeug").filters:
        log_filter.filter(record)
    assert secret not in record.getMessage()
    assert "/api/v9/auth/callback?[REDACTED]" in record.getMessage()


def test_v9_auth_frontend_carries_csrf_and_signs_out_before_vault_clear():
    source = Path("web/v9-auth/src/index.js").read_text(encoding="utf-8")
    bundle = Path(
        "static/js/vendor/v9-supabase-auth.mjs"
    ).read_text(encoding="utf-8")

    assert 'headers["X-CSRF-Token"] = csrf' in source
    assert 'credentials: "same-origin"' in source
    assert 'supabase.realtime.setAuth(token.access_token)' in source
    assert "/api/v9/auth/realtime-token" in bundle
    assert "refresh_token" not in source
    remote_sign_out = source.index("await supabase.auth.signOut()")
    local_vault_clear = source.index(
        'jsonRequest("/api/v9/auth/session", { method: "DELETE" })'
    )
    assert remote_sign_out < local_vault_clear
    assert "finally {" in source[remote_sign_out:local_vault_clear]
    assert "remoteSignOutError" in source
    assert 'jsonRequest("/api/v9/devices/self"' in source
    assert "membershipStatus" in source
    assert "redirect_to" not in source
    assert "/api/v9/members/invitations?" in source
    assert "invitation.invitation_id" in source


def test_v9_auth_frontend_rewraps_byok_for_approved_desktop_device():
    source = Path("web/v9-auth/src/index.js").read_text(encoding="utf-8")

    helper = source.split(
        "async function rewrapAiCredentialsForDevice", 1
    )[1].split("async function loadDevices", 1)[0]
    approve = source.split(
        'jsonRequest(`/api/v9/devices/${device.id}/approve`', 1
    )[1].split("target.append(button)", 1)[0]
    assert 'device.device_kind !== "desktop"' in helper
    assert 'device.key_algorithm !== "p256"' in helper
    assert "device.user_id !== currentCloudUserId" in helper
    assert "/api/v9/ai/credentials?organization_id=" in helper
    assert "/rewrap`" in helper
    assert "target_device_id: device.id" in helper
    assert 'error.payload?.status === "reentry_required"' in helper
    assert "rewrapAiCredentialsForDevice" in approve
    assert "differentUser" in approve
    assert "补发 BYOK" in source
    assert "item.id !== currentCloudDeviceId" in source


def test_logout_revokes_supabase_session_before_reporting_local_clear(tmp_path):
    cloud = _CloudSession()
    cloud.accepted = {"access_token": "memory-only"}
    client, _ = _client(tmp_path, cloud_provider=lambda: cloud)

    response = client.delete(
        "/api/v9/auth/session",
        base_url="http://127.0.0.1:49231",
    )

    assert response.status_code == 200
    assert response.get_json() == {"authenticated": False}
    assert cloud.sign_out_called is True


def test_devices_require_an_organization_but_never_accept_user_id(tmp_path):
    cloud = _CloudSession()
    cloud.accepted = {}
    client, _ = _client(tmp_path, cloud_provider=lambda: cloud)
    organization_id = "00000000-0000-4000-8000-000000000001"

    missing = client.get("/api/v9/devices")
    assert missing.status_code == 400
    response = client.get(
        "/api/v9/devices",
        headers=_cloud_headers(organization_id),
        query_string={
            "organization_id": organization_id,
            "user_id": "forged",
        },
    )

    assert response.status_code == 200
    table, token, query = cloud.client.calls[0]
    assert table == "devices"
    assert token == "jwt-from-memory"
    assert "user_id" not in query


def test_invited_desktop_registers_once_unlocks_after_pairing_and_then_syncs(
    tmp_path,
):
    import base64
    import uuid

    from v9.crypto import create_device_keypair, seal_org_key_for_p256
    from v9.supabase_client import SupabaseRequestError

    organization_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())

    class Client:
        def __init__(self):
            self.devices = []
            self.sync_devices = []
            self.envelopes = []
            self.pull_events = []
            self.calls = []
            self.key_version = 3
            self.bound = False

        def select(self, table, token, query=None):
            self.calls.append((table, token, query))
            if table == "memberships":
                return [{
                    "organization_id": organization_id,
                    "user_id": user_id,
                    "role": "analyst",
                    "status": (
                        "active"
                        if self.devices
                        and self.devices[0]["status"] == "active"
                        else "invited"
                    ),
                }]
            if table == "organizations":
                assert self.bound is True
                return [{
                    "id": organization_id,
                    "key_version": self.key_version,
                }]
            if table == "devices":
                assert self.bound is True
                device_id = str((query or {}).get("id") or "").removeprefix(
                    "eq."
                )
                rows = self.devices
                if device_id:
                    rows = [
                        row for row in rows if row["id"] == device_id
                    ]
                return list(rows)
            if table == "key_envelopes":
                return list(self.envelopes)
            return []

        def invoke(self, *_args):
            raise AssertionError("not used")

    class Cloud(_CloudSession):
        def __init__(self):
            super().__init__()
            self.client = Client()
            self.accepted = {"access_token": "memory-only"}

        def user_id(self):
            return user_id

        def rpc(self, name, payload):
            self.rpc_calls.append((name, payload))
            if name == "bind_device_session":
                matches = [
                    device for device in self.client.devices
                    if device["id"] == payload["p_device_id"]
                    and device["organization_id"]
                    == payload["p_organization_id"]
                    and device["user_id"] == user_id
                    and device["status"] == "active"
                ]
                if len(matches) != 1:
                    raise SupabaseRequestError(
                        403, "rpc:bind_device_session"
                    )
                self.client.bound = True
                return {
                    "organization_id": organization_id,
                    "device_id": payload["p_device_id"],
                    "status": "active",
                }
            if name == "accept_member_invitation":
                return {"accepted_count": 0}
            if name == "register_device":
                device = {
                    "id": payload["device_id"],
                    "organization_id": organization_id,
                    "user_id": user_id,
                    "key_algorithm": payload["key_algorithm"],
                    "device_kind": payload["device_kind"],
                    "public_key": "\\x" + base64.urlsafe_b64decode(
                        payload["device_public_key"] + "="
                    ).hex(),
                    "status": "pending",
                }
                self.client.devices.append(device)
                self.client.sync_devices.append(device)
                return payload["device_id"]
            if name == "pull_sync_events":
                return list(self.client.pull_events)
            if name == "list_sync_devices":
                return [{
                    "org_id": organization_id,
                    "device_id": device["id"],
                    "key_algorithm": device["key_algorithm"],
                    "public_key": base64.urlsafe_b64encode(
                        bytes.fromhex(device["public_key"][2:])
                    ).decode("ascii").rstrip("="),
                } for device in self.client.sync_devices
                    if device["status"] == "active"]
            if name == "push_record_event":
                return {"cursor": 1, "applied": True}
            raise AssertionError(name)

    cloud = Cloud()
    client, service = _client(tmp_path, cloud_provider=lambda: cloud)
    headers = _cloud_headers(organization_id)

    organizations = client.get("/api/v9/organizations")
    assert organizations.status_code == 200
    membership_query = cloud.client.calls[-1][2]
    assert membership_query["status"] == "in.(active,invited)"
    assert membership_query["user_id"] == f"eq.{user_id}"

    first = client.post(
        "/api/v9/devices/self",
        headers=headers,
        json={
            "organization_id": organization_id,
            "user_id": "forged-user",
        },
    )
    assert first.status_code == 202
    assert first.get_json()["status"] == "pending"
    assert first.headers["Cache-Control"] == "no-store, private"
    assert first.headers["Pragma"] == "no-cache"
    assert service.get_personal_context() is None
    assert [name for name, _ in cloud.rpc_calls].count(
        "register_device"
    ) == 1
    assert [name for name, _ in cloud.rpc_calls].count(
        "accept_member_invitation"
    ) == 1

    pending = service.get_cloud_device_context(organization_id)
    public_key = base64.urlsafe_b64decode(
        pending["device_public_key"] + "="
    )
    org_key = bytes(range(32))
    sealed = seal_org_key_for_p256(
        org_key,
        public_key,
        org_id=organization_id,
        device_id=pending["device_id"],
        key_version=3,
    )
    cloud.client.devices[0]["status"] = "active"
    cloud.client.envelopes = [{
        "organization_id": organization_id,
        "device_id": pending["device_id"],
        "key_version": 3,
        "key_algorithm": "p256",
        "ephemeral_public_key": "\\x" + base64.urlsafe_b64decode(
            sealed["ephemeral_public_key"] + "="
        ).hex(),
        "nonce": "\\x" + base64.urlsafe_b64decode(
            sealed["nonce"] + "=="
        ).hex(),
        "ciphertext": "\\x" + base64.urlsafe_b64decode(
            sealed["ciphertext"] + "=="
        ).hex(),
    }]

    unlocked = client.post(
        "/api/v9/devices/self",
        headers=headers,
        json={"organization_id": organization_id},
    )
    remote_device_id = str(uuid.uuid4())
    remote_public_key, _ = create_device_keypair()
    cloud.client.sync_devices.append({
        "id": remote_device_id,
        "organization_id": organization_id,
        "user_id": str(uuid.uuid4()),
        "key_algorithm": "x25519",
        "public_key": "\\x" + remote_public_key.hex(),
        "status": "active",
    })
    remote_record_id = str(uuid.uuid4())
    remote_payload = service.build_encrypted_payload(
        organization_id,
        remote_device_id,
        remote_record_id,
        "evidence",
        1,
        {"title": "cross-member"},
    )
    cloud.client.pull_events = [{
        "cursor": 1,
        "event_id": str(uuid.uuid4()),
        "operation": "upsert",
        "applied": True,
        "payload": remote_payload,
    }]
    synced = client.post(
        "/api/v9/sync/run",
        headers=headers,
        json={
            "organization_id": organization_id,
            "user_id": "forged-user",
        },
    )

    assert unlocked.status_code == 200
    assert unlocked.get_json()["status"] == "active"
    assert synced.status_code == 200
    assert synced.get_json()["applied"] == 1
    assert service.read_record(
        organization_id, user_id, remote_record_id
    )["content"]["title"] == "cross-member"
    assert service.resolve_cloud_context(
        organization_id, user_id
    )["device_id"] == pending["device_id"]
    assert [name for name, _ in cloud.rpc_calls].count(
        "register_device"
    ) == 1
    assert [name for name, _ in cloud.rpc_calls].count(
        "accept_member_invitation"
    ) == 2

    rotated_key = bytes(reversed(range(32)))
    rotated = seal_org_key_for_p256(
        rotated_key,
        public_key,
        org_id=organization_id,
        device_id=pending["device_id"],
        key_version=4,
    )
    cloud.client.key_version = 4
    cloud.client.envelopes = [{
        "organization_id": organization_id,
        "device_id": pending["device_id"],
        "key_version": 4,
        "key_algorithm": "p256",
        "ephemeral_public_key": "\\x" + base64.urlsafe_b64decode(
            rotated["ephemeral_public_key"] + "="
        ).hex(),
        "nonce": "\\x" + base64.urlsafe_b64decode(
            rotated["nonce"] + "=="
        ).hex(),
        "ciphertext": "\\x" + base64.urlsafe_b64decode(
            rotated["ciphertext"] + "=="
        ).hex(),
    }]

    advanced = client.post(
        "/api/v9/devices/self",
        headers=headers,
        json={"organization_id": organization_id},
    )

    assert advanced.status_code == 200
    assert advanced.get_json()["key_version"] == 4
    assert service.resolve_cloud_context(
        organization_id, user_id
    )["key_version"] == 4
    encrypted = service.build_encrypted_payload(
        organization_id,
        pending["device_id"],
        str(uuid.uuid4()),
        "evidence",
        1,
        {"title": "rotated"},
    )
    assert encrypted["key_version"] == 4


def test_invitation_edge_request_has_no_redirect_and_preserves_generic_202(
    tmp_path,
):
    cloud = _CloudSession()
    cloud.accepted = {"access_token": "memory-only"}
    invocation = {}

    def invoke(name, payload, token):
        invocation.update({
            "name": name,
            "payload": payload,
            "token": token,
        })
        return {"accepted": True}

    cloud.client.invoke = invoke
    client, _ = _client(tmp_path, cloud_provider=lambda: cloud)
    organization_id = "00000000-0000-4000-8000-000000000001"

    response = client.post(
        "/api/v9/members/invite",
        headers=_cloud_headers(organization_id),
        json={
            "organization_id": organization_id,
            "email": "member@example.test",
            "role": "analyst",
        },
    )

    assert response.status_code == 202
    assert invocation["name"] == "invite-member"
    assert invocation["token"] == "jwt-from-memory"
    assert invocation["payload"] == {
        "organization_id": organization_id,
        "email": "member@example.test",
        "role": "analyst",
    }


def test_invitation_list_and_cancel_use_metadata_only_rpc(tmp_path):
    cloud = _CloudSession()
    cloud.accepted = {"access_token": "memory-only"}
    rpc_calls = []
    invitation_id = "00000000-0000-4000-8000-000000000081"
    organization_id = "00000000-0000-4000-8000-000000000001"

    def rpc(name, payload):
        rpc_calls.append((name, payload))
        if name == "list_member_invitations":
            return [{
                "invitation_id": invitation_id,
                "invitation_role": "analyst",
                "invitation_status": "requested",
                "expires_at": "2030-01-01T00:00:00Z",
                "created_at": "2029-12-31T00:00:00Z",
                "finalized_at": None,
                "cancelled_at": None,
            }]
        if name == "cancel_member_invitation":
            return True
        raise AssertionError(name)

    cloud.rpc = rpc
    client, _ = _client(tmp_path, cloud_provider=lambda: cloud)

    listed = client.get(
        "/api/v9/members/invitations",
        headers=_cloud_headers(organization_id),
        query_string={
            "organization_id": organization_id,
            "user_id": "forged",
        },
    )
    cancelled = client.delete(
        f"/api/v9/members/invitations/{invitation_id}",
        headers=_cloud_headers(organization_id),
        json={"user_id": "forged"},
    )

    assert listed.status_code == 200
    assert listed.get_json()["invitations"][0]["invitation_role"] == "analyst"
    assert cancelled.status_code == 200
    assert cancelled.get_json() == {"cancelled": True}
    assert rpc_calls == [
        (
            "list_member_invitations",
            {"p_organization_id": organization_id},
        ),
        (
            "cancel_member_invitation",
            {"p_invitation_id": invitation_id},
        ),
    ]


def test_cloud_bootstrap_requires_operator_manifest_not_browser_rpc(tmp_path):
    cloud = _CloudSession()
    cloud.accepted = {}
    client, service = _client(tmp_path, cloud_provider=lambda: cloud)
    context = _ready_personal_context(service)
    service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "document",
        {"body": "ciphertext only"},
    )

    boot = client.post(
        "/api/v9/organizations",
        json={"user_id": "forged", "organization_id": "forged"},
    )

    assert boot.status_code == 409
    assert boot.get_json() == {
        "status": "operator_provisioning_required",
        "manifest_command": "scripts/export_mvp_owner_manifest.py",
    }
    assert all(name != "bootstrap_organization" for name, _ in cloud.rpc_calls)


def test_cloud_bootstrap_never_silently_consumes_personal_recovery_code(
    tmp_path,
):
    cloud = _CloudSession()
    cloud.accepted = {}
    client, service = _client(tmp_path, cloud_provider=lambda: cloud)

    response = client.post("/api/v9/organizations", json={})

    assert response.status_code == 409
    assert service.get_personal_context() is None


def test_initial_cloud_snapshot_requires_explicit_empty_cloud_confirmation(
    tmp_path,
):
    cloud = _CloudSession()
    cloud.accepted = {"access_token": "memory-only"}
    client, service = _client(tmp_path, cloud_provider=lambda: cloud)
    context = _ready_personal_context(service)
    created = service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "evidence",
        {"body": "encrypted locally"},
    )
    for event in service.export_outbox(context["organization_id"]):
        service.repository.mark_outbox_sent(event["event_id"])

    missing_confirmation = client.post(
        "/api/v9/sync/bootstrap-snapshot",
        headers=_personal_headers(context),
        json={"organization_id": context["organization_id"]},
        base_url="http://127.0.0.1:49231",
    )
    assert missing_confirmation.status_code == 400
    assert service.export_outbox(context["organization_id"]) == []

    staged = client.post(
        "/api/v9/sync/bootstrap-snapshot",
        headers=_personal_headers(context),
        json={
            "organization_id": context["organization_id"],
            "confirm_empty_cloud": True,
        },
        base_url="http://127.0.0.1:49231",
    )
    assert staged.status_code == 202
    assert staged.get_json()["queued"] == 1
    snapshots = service.export_outbox(context["organization_id"])
    assert snapshots[0]["record_id"] == created["record_id"]
    assert snapshots[0]["operation"] == "snapshot"


def test_initial_cloud_snapshot_resumes_same_remote_import_after_partial_push(
    tmp_path,
):
    cloud = _CloudSession()
    cloud.accepted = {"access_token": "memory-only"}
    client, service = _client(tmp_path, cloud_provider=lambda: cloud)
    context = _ready_personal_context(service)
    service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "evidence",
        {"body": "one"},
    )
    service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "evidence",
        {"body": "two"},
    )
    for event in service.export_outbox(context["organization_id"]):
        service.repository.mark_outbox_sent(event["event_id"])

    first = client.post(
        "/api/v9/sync/bootstrap-snapshot",
        headers=_personal_headers(context),
        json={
            "organization_id": context["organization_id"],
            "confirm_empty_cloud": True,
        },
        base_url="http://127.0.0.1:49231",
    )
    assert first.status_code == 202
    first_manifest = first.get_json()["manifest_hash"]
    snapshots = service.export_outbox(context["organization_id"])
    service.repository.mark_outbox_sent(snapshots[0]["event_id"])
    cloud.snapshot_import["accepted_count"] = 1
    cloud.client.record_heads = [{"record_id": snapshots[0]["record_id"]}]

    resumed = client.post(
        "/api/v9/sync/bootstrap-snapshot",
        headers=_personal_headers(context),
        json={
            "organization_id": context["organization_id"],
            "confirm_empty_cloud": True,
        },
        base_url="http://127.0.0.1:49231",
    )

    assert resumed.status_code == 200
    assert resumed.get_json()["manifest_hash"] == first_manifest
    assert resumed.get_json()["import"]["resumed"] is True


def test_initial_cloud_snapshot_rejects_a_different_resume_manifest(tmp_path):
    cloud = _CloudSession()
    cloud.accepted = {"access_token": "memory-only"}
    client, service = _client(tmp_path, cloud_provider=lambda: cloud)
    context = _ready_personal_context(service)
    first_manifest = "a" * 64
    cloud.snapshot_import = {
        "import_id": "00000000-0000-4000-8000-000000000091",
        "organization_id": context["organization_id"],
        "expected_count": 9,
        "manifest_hash": first_manifest,
        "accepted_count": 1,
        "status": "staging",
        "resumed": False,
    }

    response = client.post(
        "/api/v9/sync/bootstrap-snapshot",
        headers=_personal_headers(context),
        json={
            "organization_id": context["organization_id"],
            "confirm_empty_cloud": True,
        },
        base_url="http://127.0.0.1:49231",
    )

    assert response.status_code == 503
    assert cloud.snapshot_import["manifest_hash"] == first_manifest
    frozen_after_uncertain_begin = client.post(
        "/api/v9/records",
        headers=_personal_headers(context),
        json={
            "organization_id": context["organization_id"],
            "device_id": context["device_id"],
            "record_type": "evidence",
            "content": {"body": "must remain frozen after uncertain begin"},
        },
        base_url="http://127.0.0.1:49231",
    )
    assert frozen_after_uncertain_begin.status_code == 400
    assert "frozen" in frozen_after_uncertain_begin.get_json()["error"]


def test_initial_cloud_snapshot_aborts_empty_remote_session_if_queue_fails(
    tmp_path,
    monkeypatch,
):
    cloud = _CloudSession()
    cloud.accepted = {"access_token": "memory-only"}
    client, service = _client(tmp_path, cloud_provider=lambda: cloud)
    context = _ready_personal_context(service)

    def fail_queue(*_args, **_kwargs):
        raise ValueError("synthetic queue failure")

    monkeypatch.setattr(service, "queue_initial_snapshot", fail_queue)
    response = client.post(
        "/api/v9/sync/bootstrap-snapshot",
        headers=_personal_headers(context),
        json={
            "organization_id": context["organization_id"],
            "confirm_empty_cloud": True,
        },
        base_url="http://127.0.0.1:49231",
    )

    assert response.status_code == 409
    assert cloud.snapshot_import["status"] == "aborted"
    created = service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "evidence",
        {"body": "local writes were unfrozen"},
    )
    assert created["record_id"]


def test_initial_cloud_snapshot_complete_requires_all_local_snapshots_sent(
    tmp_path,
):
    cloud = _CloudSession()
    cloud.accepted = {"access_token": "memory-only"}
    client, service = _client(tmp_path, cloud_provider=lambda: cloud)
    context = _ready_personal_context(service)
    service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "evidence",
        {"body": "complete me"},
    )
    for event in service.export_outbox(context["organization_id"]):
        service.repository.mark_outbox_sent(event["event_id"])
    staged = client.post(
        "/api/v9/sync/bootstrap-snapshot",
        headers=_personal_headers(context),
        json={
            "organization_id": context["organization_id"],
            "confirm_empty_cloud": True,
        },
        base_url="http://127.0.0.1:49231",
    )
    assert staged.status_code == 202
    frozen_write = client.post(
        "/api/v9/records",
        headers=_personal_headers(context),
        json={
            "organization_id": context["organization_id"],
            "device_id": context["device_id"],
            "record_type": "evidence",
            "content": {"body": "must wait for snapshot completion"},
        },
        base_url="http://127.0.0.1:49231",
    )
    assert frozen_write.status_code == 400
    assert "frozen" in frozen_write.get_json()["error"]
    blocked_rotation = client.delete(
        (
            f"/api/v9/organizations/{context['organization_id']}"
            f"/devices/{context['device_id']}"
        ),
        headers=_personal_headers(context),
        base_url="http://127.0.0.1:49231",
    )
    assert blocked_rotation.status_code == 400
    assert "rotation is blocked" in blocked_rotation.get_json()["error"]
    assert service.repository.get_device(context["device_id"])[
        "status"
    ] == "active"

    blocked = client.post(
        "/api/v9/sync/bootstrap-snapshot/complete",
        headers=_personal_headers(context),
        json={"organization_id": context["organization_id"]},
        base_url="http://127.0.0.1:49231",
    )
    assert blocked.status_code == 409
    assert not any(
        name == "complete_snapshot_import" for name, _ in cloud.rpc_calls
    )

    snapshot = service.export_outbox(context["organization_id"])[0]
    service.repository.mark_outbox_sent(snapshot["event_id"])
    cloud.snapshot_import["accepted_count"] = 1
    completed = client.post(
        "/api/v9/sync/bootstrap-snapshot/complete",
        headers=_personal_headers(context),
        json={"organization_id": context["organization_id"]},
        base_url="http://127.0.0.1:49231",
    )

    assert completed.status_code == 200
    assert completed.get_json()["import"]["status"] == "completed"
    unfrozen_write = client.post(
        "/api/v9/records",
        headers=_personal_headers(context),
        json={
            "organization_id": context["organization_id"],
            "device_id": context["device_id"],
            "record_type": "evidence",
            "content": {"body": "writes resume after completion"},
        },
        base_url="http://127.0.0.1:49231",
    )
    assert unfrozen_write.status_code == 201


def _blocked_cloud_record(service, context):
    record = service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "evidence",
        {"body": "base"},
    )
    initial = service.export_outbox(context["organization_id"])[0]
    service.repository.mark_outbox_sent(initial["event_id"])
    service.update_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        record["record_id"],
        expected_version=1,
        content={"body": "local branch"},
    )
    outgoing = service.export_outbox(context["organization_id"])[0]
    service.repository.mark_outbox_conflicted(outgoing["event_id"], 21)
    return outgoing


def test_successful_remote_conflict_resolution_unfreezes_matching_local_record(
    tmp_path,
):
    cloud = _CloudSession()
    cloud.accepted = {"access_token": "memory-only"}
    client, service = _client(tmp_path, cloud_provider=lambda: cloud)
    context = _ready_personal_context(service)
    outgoing = _blocked_cloud_record(service, context)
    conflict_id = "00000000-0000-4000-8000-000000000061"
    chosen_head = outgoing["payload"]["version_id"]
    cloud.resolve_result = {
        "resolved_conflict_id": conflict_id,
        "head_version_id": chosen_head,
        "version_id": chosen_head,
        "applied": True,
    }

    response = client.post(
        f"/api/v9/conflicts/{conflict_id}/resolve",
        headers=_personal_headers(context),
        json={
            "expected_head_version_id": outgoing["payload"]["base_version_id"],
            "resolution_event": outgoing,
        },
        base_url="http://127.0.0.1:49231",
    )

    assert response.status_code == 200
    block = service.repository.get_sync_block(
        context["organization_id"], outgoing["record_id"]
    )
    assert block["resolved_at"] is not None
    assert service.repository.get_record(outgoing["record_id"])[
        "cloud_version_id"
    ] == chosen_head


def test_failed_or_invalid_remote_conflict_resolution_never_unfreezes_local(
    tmp_path,
):
    cloud = _CloudSession()
    cloud.accepted = {"access_token": "memory-only"}
    client, service = _client(tmp_path, cloud_provider=lambda: cloud)
    context = _ready_personal_context(service)
    outgoing = _blocked_cloud_record(service, context)
    conflict_id = "00000000-0000-4000-8000-000000000071"
    cloud.resolve_error = RuntimeError("remote resolution failed")

    failed = client.post(
        f"/api/v9/conflicts/{conflict_id}/resolve",
        headers=_personal_headers(context),
        json={
            "expected_head_version_id": outgoing["payload"]["base_version_id"],
            "resolution_event": outgoing,
        },
        base_url="http://127.0.0.1:49231",
    )
    assert failed.status_code == 503
    assert service.repository.get_sync_block(
        context["organization_id"], outgoing["record_id"]
    )["resolved_at"] is None

    cloud.resolve_error = None
    tampered = dict(outgoing)
    tampered["payload"] = dict(outgoing["payload"])
    tampered["payload"]["content_hash"] = "0" * 64
    resolve_calls_before = sum(
        name == "resolve_conflict" for name, _ in cloud.rpc_calls
    )
    rejected_local_mismatch = client.post(
        f"/api/v9/conflicts/{conflict_id}/resolve",
        headers=_personal_headers(context),
        json={
            "expected_head_version_id": outgoing["payload"]["base_version_id"],
            "resolution_event": tampered,
        },
        base_url="http://127.0.0.1:49231",
    )
    assert rejected_local_mismatch.status_code == 400
    assert sum(
        name == "resolve_conflict" for name, _ in cloud.rpc_calls
    ) == resolve_calls_before
    assert service.repository.get_sync_block(
        context["organization_id"], outgoing["record_id"]
    )["resolved_at"] is None

    cloud.resolve_result = {
        "resolved_conflict_id": conflict_id,
        "head_version_id": "not-a-version-uuid",
        "version_id": "not-a-version-uuid",
        "applied": True,
    }
    invalid = client.post(
        f"/api/v9/conflicts/{conflict_id}/resolve",
        headers=_personal_headers(context),
        json={
            "expected_head_version_id": outgoing["payload"]["base_version_id"],
            "resolution_event": outgoing,
        },
        base_url="http://127.0.0.1:49231",
    )
    assert invalid.status_code == 400
    assert service.repository.get_sync_block(
        context["organization_id"], outgoing["record_id"]
    )["resolved_at"] is None


def test_legacy_local_identity_routes_cannot_target_another_organization(
    tmp_path,
):
    client, service = _client(tmp_path)
    context = _ready_personal_context(service)
    foreign = service.bootstrap_organization(
        "Foreign", "foreign-owner", "Foreign desktop"
    )

    forged_record = client.post(
        "/api/v9/records",
        headers=_personal_headers(context),
        json={
            "organization_id": foreign["organization_id"],
            "user_id": "foreign-owner",
            "device_id": foreign["device_id"],
            "record_type": "evidence",
            "content": {"body": "must not be accessible"},
        },
        base_url="http://127.0.0.1:49231",
    )
    local_record = client.post(
        "/api/v9/records",
        headers=_personal_headers(context),
        json={
            "organization_id": context["organization_id"],
            "user_id": "forged-owner-is-ignored",
            "device_id": context["device_id"],
            "record_type": "evidence",
            "content": {"body": "local"},
        },
        base_url="http://127.0.0.1:49231",
    )

    assert forged_record.status_code == 403
    assert local_record.status_code == 201


def test_one_time_pairing_api_returns_only_device_envelope(tmp_path):
    import base64

    from v9.crypto import create_device_keypair, open_org_key_for_device

    client, service = _client(tmp_path)
    context = _ready_personal_context(service)
    issued = client.post(
        "/api/v9/pairing-sessions",
        headers=_personal_headers(context),
        json={
            "organization_id": context["organization_id"],
            "acting_user_id": context["user_id"],
            "device_id": context["device_id"],
            "user_id": context["user_id"],
            "device_name": "API paired desktop",
            "ttl_seconds": 120,
        },
    )
    assert issued.status_code == 201
    public_key, private_key = create_device_keypair()
    encoded = base64.urlsafe_b64encode(public_key).decode().rstrip("=")
    claimed = client.post(
        "/api/v9/pairing-sessions/claim",
        json={
            "pairing_code": issued.get_json()["pairing_code"],
            "public_key": encoded,
        },
    )
    assert claimed.status_code == 201
    payload = claimed.get_json()
    assert len(open_org_key_for_device(
        private_key, payload["key_envelope"]
    )) == 32
    replay = client.post(
        "/api/v9/pairing-sessions/claim",
        json={
            "pairing_code": issued.get_json()["pairing_code"],
            "public_key": encoded,
        },
    )
    assert replay.status_code == 400


def test_desktop_api_rejects_non_loopback_call(tmp_path):
    client, _ = _client(tmp_path)

    response = client.post(
        "/api/v9/organizations/bootstrap",
        json={"name": "x", "user_id": "u", "device_name": "d"},
        environ_base={"REMOTE_ADDR": "192.0.2.10"},
    )

    assert response.status_code == 403


def test_personal_diagnostics_and_backup_routes(tmp_path):
    client, service = _client(tmp_path)
    context = _ready_personal_context(service)
    service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "evidence",
        {"body": "must remain encrypted"},
    )

    headers = _personal_headers(context)
    diagnostics = client.get("/api/v9/diagnostics/export", headers=headers)
    backup = client.post("/api/v9/backups", headers=headers, json={})

    assert diagnostics.status_code == 200
    assert diagnostics.mimetype == "application/zip"
    assert b"must remain encrypted" not in diagnostics.data
    assert backup.status_code == 201
    assert backup.get_json()["ciphertext_database"] is True
    assert backup.get_json()["plaintext_included"] is False


def test_situation_and_news_archive_routes(tmp_path):
    from v9.api import create_blueprint
    from v9.service import V9Service

    service = V9Service(tmp_path / "v9.sqlite3", tmp_path / ".master")
    app = Flask(__name__)
    app.register_blueprint(
        create_blueprint(
            lambda: service,
            situation_provider=lambda: {
                "regions": [],
                "wire": [{"article_id": "a1", "title": "real"}],
            },
        )
    )
    client = app.test_client()
    context = _ready_personal_context(service)
    headers = _personal_headers(context)
    assert client.get("/api/v9/situation").status_code == 200

    archived = client.post(
        "/api/v9/evidence/archive-news",
        headers=headers,
        json={
            "article": {
                "aid": "a1",
                "title": "traceable",
                "source": "source",
                "link": "https://example.test/a1",
                "date": "2026-07-25T08:00:00+00:00",
            }
        },
    )
    assert archived.status_code == 201
    listed = client.get("/api/v9/evidence", headers=headers)
    assert listed.status_code == 200
    assert listed.get_json()["evidence"][0]["content"]["title"] == "traceable"


def test_v9_alert_rule_api_returns_rhythm(tmp_path):
    from v9.api import create_blueprint
    from v9.service import V9Service

    service = V9Service(tmp_path / "v9.sqlite3", tmp_path / ".master")
    app = Flask(__name__)
    app.register_blueprint(
        create_blueprint(
            lambda: service,
            news_provider=lambda: [
                {
                    "aid": "a1",
                    "title": "Carrier movement",
                    "source": "Source A",
                    "date": datetime.now(timezone.utc).isoformat(),
                    "priority": {"stars": 8},
                }
            ],
        )
    )
    client = app.test_client()
    context = _ready_personal_context(service)
    headers = _personal_headers(context)

    created = client.post(
        "/api/v9/alert-rules",
        headers=headers,
        json={
            "name": "航母",
            "keywords": ["carrier"],
            "min_stars": 6,
            "severity": "high",
        },
    )
    assert created.status_code == 201
    evaluated = client.get("/api/v9/alert-rules/evaluate", headers=headers)
    assert evaluated.status_code == 200
    assert evaluated.get_json()["total_hits"] == 1
    assert len(evaluated.get_json()["rhythm"]) == 24


def test_v9_alert_case_graph_and_geo_routes(tmp_path):
    from v9.api import create_blueprint
    from v9.service import V9Service

    service = V9Service(tmp_path / "v9.sqlite3", tmp_path / ".master")
    app = Flask(__name__)
    app.register_blueprint(create_blueprint(lambda: service))
    client = app.test_client()

    context = _ready_personal_context(service)
    headers = _personal_headers(context)
    evidence = service.archive_news_evidence(
        context,
        {
            "aid": "api-evidence",
            "title": "API evidence",
            "source": "source",
            "link": "https://example.test/api-evidence",
        },
    )
    entity = client.post(
        "/api/v9/graph/entities",
        headers=headers,
        json={
            "name": "entity",
            "kind": "organization",
            "epistemic_status": "fact",
            "evidence_ids": [evidence["record_id"]],
        },
    )
    assert entity.status_code == 201
    geo = client.post(
        "/api/v9/geo-events",
        headers=headers,
        json={
            "title": "event",
            "latitude": 20,
            "longitude": 120,
            "epistemic_status": "source_claim",
            "evidence_ids": [evidence["record_id"]],
        },
    )
    assert geo.status_code == 201
    assert client.get("/api/v9/graph", headers=headers).status_code == 200
    assert client.get(
        "/api/v9/geo-events?hours=120", headers=headers
    ).status_code == 200
    assert client.get("/api/v9/alerts", headers=headers).status_code == 200
    assert client.get("/api/v9/cases", headers=headers).status_code == 200


def test_v9_materialize_and_convert_alert_api(tmp_path):
    from v9.api import create_blueprint
    from v9.service import V9Service

    current_news = {
        "aid": "api-news",
        "title": "Carrier near Taiwan",
        "summary": "traceable",
        "source": "Source",
        "link": "https://example.test/api-news",
        "date": datetime.now(timezone.utc).isoformat(),
        "priority": {"stars": 9},
    }
    service = V9Service(tmp_path / "v9.sqlite3", tmp_path / ".master")
    context = _ready_personal_context(service)
    service.save_alert_rule(
        context,
        {
            "name": "carrier",
            "keywords": ["carrier"],
            "min_stars": 7,
            "severity": "high",
        },
    )
    app = Flask(__name__)
    app.register_blueprint(
        create_blueprint(lambda: service, news_provider=lambda: [current_news])
    )
    client = app.test_client()
    headers = _personal_headers(context)

    materialized = client.post(
        "/api/v9/alerts/materialize", headers=headers, json={}
    )
    assert materialized.status_code == 200
    assert materialized.get_json()["created"] == 1
    alert = client.get("/api/v9/alerts", headers=headers).get_json()["alerts"][0]
    converted = client.post(
        f"/api/v9/alerts/{alert['record_id']}/action",
        headers=headers,
        json={"action": "convert_case", "version": alert["version"]},
    )
    assert converted.status_code == 200
    assert converted.get_json()["case_id"]
    assert len(
        client.get("/api/v9/cases", headers=headers).get_json()["cases"]
    ) == 1


def test_v9_agent_job_and_scenario_routes(tmp_path):
    client, service = _client(
        tmp_path,
        agent_phase_executor=lambda payload: "本机阶段输出 [E1]",
    )
    context = _ready_personal_context(service)
    headers = _personal_headers(context)
    evidence = service.archive_news_evidence(
        context,
        {
            "aid": "p4-api",
            "title": "P4 API evidence",
            "source": "Source",
            "link": "https://example.test/p4-api",
        },
    )
    evidence_ids = [evidence["record_id"]]

    created_job = client.post(
        "/api/v9/jobs",
        headers=headers,
        json={
            "template": "rapid_assessment",
            "title": "快速研判",
            "evidence_ids": evidence_ids,
        },
    )
    assert created_job.status_code == 201
    job = client.get("/api/v9/jobs", headers=headers).get_json()["jobs"][0]
    started = client.post(
        f"/api/v9/jobs/{job['record_id']}/action",
        headers=headers,
        json={"action": "start", "version": job["version"]},
    )
    assert started.status_code == 200
    assert started.get_json()["transition"]["state"] == "running"
    executed = client.post(
        f"/api/v9/jobs/{job['record_id']}/action",
        headers=headers,
        json={
            "action": "execute_phase",
            "version": started.get_json()["version"],
        },
    )
    assert executed.status_code == 200
    assert executed.get_json()["transition"]["phase"] == "close_read"

    created_scenario = client.post(
        "/api/v9/scenarios",
        headers=headers,
        json={
            "title": "三分支推演",
            "question": "未来 72 小时如何演化？",
            "evidence_ids": evidence_ids,
        },
    )
    assert created_scenario.status_code == 201
    scenario = client.get(
        "/api/v9/scenarios", headers=headers
    ).get_json()["scenarios"][0]
    assert scenario["content"]["classification"] == "scenario_inference"
    updated = client.patch(
        f"/api/v9/scenarios/{scenario['record_id']}",
        headers=headers,
        json={
            "version": scenario["version"],
            "changes": {
                "branches": {
                    "baseline": {
                        "summary": "维持",
                        "triggers": [],
                        "indicators": [],
                        "counter_evidence_ids": [],
                        "confidence": 0.5,
                    },
                    "escalation": {
                        "summary": "升级",
                        "triggers": [],
                        "indicators": [],
                        "counter_evidence_ids": [],
                        "confidence": 0.3,
                    },
                    "deescalation": {
                        "summary": "缓和",
                        "triggers": [],
                        "indicators": [],
                        "counter_evidence_ids": [],
                        "confidence": 0.2,
                    },
                }
            },
        },
    )
    assert updated.status_code == 200
    assert updated.get_json()["version"] == 2
