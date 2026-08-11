# -*- coding: utf-8 -*-
"""Fail-closed API contracts for personal and cloud business contexts."""

import base64
from pathlib import Path

import pytest
from flask import Flask

from v9.errors import PermissionDenied


PERSONAL_ORG = "00000000-0000-4000-8000-000000000011"
PERSONAL_DEVICE = "00000000-0000-4000-8000-000000000012"
CLOUD_ORG = "00000000-0000-4000-8000-000000000021"
CLOUD_USER = "00000000-0000-4000-8000-000000000022"
CLOUD_DEVICE = "00000000-0000-4000-8000-000000000023"
OTHER_ORG = "00000000-0000-4000-8000-000000000031"
DEVICE_KEY = b"\x04" + bytes(range(1, 65))
DEVICE_KEY_B64 = base64.urlsafe_b64encode(DEVICE_KEY).decode().rstrip("=")
API_SOURCE = (
    Path(__file__).resolve().parents[1] / "v9" / "api.py"
).read_text(encoding="utf-8")


class _BusinessService:
    def __init__(self):
        self.personal_reads = 0
        self.personal_creates = 0
        self.resolve_calls = []
        self.refresh_calls = []
        self.evidence_contexts = []
        self.record_writes = []
        self.remote_events = []
        self.resolve_error = None
        self.personal = {
            "organization_id": PERSONAL_ORG,
            "user_id": "local-owner",
            "device_id": PERSONAL_DEVICE,
        }
        self.cloud = {
            "organization_id": CLOUD_ORG,
            "user_id": CLOUD_USER,
            "device_id": CLOUD_DEVICE,
            "device_public_key": DEVICE_KEY_B64,
            "key_algorithm": "p256",
            "device_kind": "desktop",
            "key_version": 1,
            "role": "analyst",
            "status": "active",
        }

    def get_personal_context(self):
        self.personal_reads += 1
        return dict(self.personal) if self.personal is not None else None

    def get_or_create_personal_context(self):
        self.personal_creates += 1
        return dict(self.personal) if self.personal is not None else None

    def resolve_cloud_context(self, organization_id, cloud_user_id):
        self.resolve_calls.append((organization_id, cloud_user_id))
        if self.resolve_error is not None:
            raise self.resolve_error
        return dict(self.cloud)

    def refresh_cloud_membership(self, context, *, cloud_user_id, role):
        self.refresh_calls.append(
            (context["organization_id"], cloud_user_id, role)
        )

    def list_evidence(self, context):
        self.evidence_contexts.append(context["organization_id"])
        return [{"organization_id": context["organization_id"]}]

    def create_record(
        self,
        organization_id,
        user_id,
        device_id,
        record_type,
        content,
    ):
        self.record_writes.append(
            (organization_id, user_id, device_id, record_type, content)
        )
        return {"record_id": "not-written-in-mismatch-tests"}

    def apply_remote_event(
        self,
        organization_id,
        user_id,
        event,
        *,
        remote_cursor,
    ):
        self.remote_events.append(
            (organization_id, user_id, event, remote_cursor)
        )
        return {"applied": True}


class _BusinessCloudClient:
    def __init__(self):
        self.membership_status = "active"
        self.organization_key_version = 1
        self.device_overrides = {}
        self.calls = []

    def select(self, table, token, query=None):
        self.calls.append((table, token, query))
        if table == "memberships":
            return [{
                "organization_id": CLOUD_ORG,
                "user_id": CLOUD_USER,
                "role": "analyst",
                "status": self.membership_status,
            }]
        if table == "organizations":
            return [{
                "id": CLOUD_ORG,
                "key_version": self.organization_key_version,
            }]
        if table == "devices":
            device = {
                "id": CLOUD_DEVICE,
                "organization_id": CLOUD_ORG,
                "user_id": CLOUD_USER,
                "key_algorithm": "p256",
                "device_kind": "desktop",
                "public_key": "\\x" + DEVICE_KEY.hex(),
                "status": "active",
            }
            device.update(self.device_overrides)
            return [device]
        raise AssertionError(table)


class _BusinessCloud:
    def __init__(self):
        self.client = _BusinessCloudClient()
        self.token_calls = 0
        self.user_calls = 0
        self.rpc_calls = []

    def access_token(self):
        self.token_calls += 1
        return "current-jwt"

    def user_id(self):
        self.user_calls += 1
        return CLOUD_USER

    def rpc(self, name, payload):
        self.rpc_calls.append((name, payload))
        if name == "bind_device_session":
            return {
                "organization_id": payload["p_organization_id"],
                "device_id": payload["p_device_id"],
                "status": "active",
            }
        raise AssertionError(f"unexpected RPC: {name}")


def _client(service, cloud=None):
    from v9.api import create_blueprint

    app = Flask(__name__)
    app.register_blueprint(
        create_blueprint(
            lambda: service,
            cloud_provider=(lambda: cloud) if cloud is not None else None,
        )
    )
    return app.test_client()


def _headers(mode, organization_id):
    return {
        "X-V9-Context-Mode": mode,
        "X-V9-Organization-ID": organization_id,
    }


def _function_block(name):
    marker = f"    def {name}("
    start = API_SOURCE.index(marker)
    end = API_SOURCE.find("\n    @bp.", start)
    if end < 0:
        end = API_SOURCE.index("\n    return bp", start)
    return API_SOURCE[start:end]


def test_missing_business_context_is_rejected_without_personal_side_effects():
    service = _BusinessService()
    response = _client(service).get("/api/v9/evidence")

    assert response.status_code == 400
    assert "X-V9-Context-Mode" in response.get_json()["error"]
    assert service.personal_reads == 0
    assert service.personal_creates == 0


@pytest.mark.parametrize("mode", ("personal", "cloud"))
def test_explicit_mode_without_organization_is_rejected_before_side_effects(
    mode,
):
    service = _BusinessService()
    cloud = _BusinessCloud()

    response = _client(service, cloud).get(
        "/api/v9/evidence",
        headers={"X-V9-Context-Mode": mode},
    )

    assert response.status_code == 400
    assert "X-V9-Organization-ID" in response.get_json()["error"]
    assert service.personal_reads == 0
    assert service.personal_creates == 0
    assert cloud.token_calls == 0
    assert cloud.user_calls == 0


def test_personal_business_context_discovery_returns_only_public_context():
    service = _BusinessService()

    response = _client(service).get(
        "/api/v9/business-context/personal"
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "mode": "personal",
        "organization_id": PERSONAL_ORG,
    }
    assert "device_id" not in response.get_json()
    assert "recovery_code" not in response.get_json()


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    (
        (
            "GET",
            f"/api/v9/devices?organization_id={CLOUD_ORG}",
            {},
        ),
        (
            "POST",
            "/api/v9/members/invite",
            {
                "json": {
                    "organization_id": CLOUD_ORG,
                    "email": "member@example.test",
                    "role": "analyst",
                },
            },
        ),
        (
            "POST",
            "/api/v9/sync/run",
            {"json": {"organization_id": CLOUD_ORG}},
        ),
        (
            "GET",
            f"/api/v9/sync/status?organization_id={CLOUD_ORG}",
            {},
        ),
        (
            "POST",
            "/api/v9/pairing-sessions",
            {
                "json": {
                    "organization_id": PERSONAL_ORG,
                    "device_id": PERSONAL_DEVICE,
                    "user_id": "local-owner",
                    "device_name": "new desktop",
                },
            },
        ),
        (
            "POST",
            f"/api/v9/organizations/{PERSONAL_ORG}/members",
            {"json": {"user_id": "analyst", "role": "analyst"}},
        ),
    ),
)
def test_control_and_sync_routes_require_context_before_side_effects(
    method,
    path,
    kwargs,
):
    service = _BusinessService()
    cloud = _BusinessCloud()

    response = _client(service, cloud).open(path, method=method, **kwargs)

    assert response.status_code == 400
    assert "X-V9-Context-Mode" in response.get_json()["error"]
    assert service.personal_reads == 0
    assert service.personal_creates == 0
    assert service.resolve_calls == []
    assert cloud.token_calls == 0
    assert cloud.user_calls == 0


def test_control_route_rejects_header_and_payload_organization_mismatch():
    service = _BusinessService()
    cloud = _BusinessCloud()

    response = _client(service, cloud).get(
        f"/api/v9/devices?organization_id={CLOUD_ORG}",
        headers=_headers("cloud", OTHER_ORG),
    )

    assert response.status_code == 403
    assert cloud.token_calls == 0
    assert cloud.user_calls == 0


@pytest.mark.parametrize(
    ("method", "path", "headers", "kwargs"),
    (
        (
            "GET",
            f"/api/v9/devices?organization_id={CLOUD_ORG}",
            _headers("personal", CLOUD_ORG),
            {},
        ),
        (
            "POST",
            "/api/v9/members/invite",
            _headers("personal", CLOUD_ORG),
            {
                "json": {
                    "organization_id": CLOUD_ORG,
                    "email": "member@example.test",
                    "role": "analyst",
                },
            },
        ),
        (
            "POST",
            "/api/v9/sync/run",
            _headers("personal", CLOUD_ORG),
            {"json": {"organization_id": CLOUD_ORG}},
        ),
        (
            "POST",
            f"/api/v9/organizations/{PERSONAL_ORG}/members",
            _headers("cloud", PERSONAL_ORG),
            {"json": {"user_id": "analyst", "role": "analyst"}},
        ),
        (
            "POST",
            "/api/v9/pairing-sessions",
            _headers("cloud", PERSONAL_ORG),
            {
                "json": {
                    "organization_id": PERSONAL_ORG,
                    "device_id": PERSONAL_DEVICE,
                    "user_id": "local-owner",
                    "device_name": "new desktop",
                },
            },
        ),
        (
            "POST",
            "/api/v9/sync/bootstrap-snapshot",
            _headers("cloud", PERSONAL_ORG),
            {
                "json": {
                    "organization_id": PERSONAL_ORG,
                    "confirm_empty_cloud": True,
                },
            },
        ),
    ),
)
def test_control_routes_reject_wrong_context_mode_before_side_effects(
    method,
    path,
    headers,
    kwargs,
):
    service = _BusinessService()
    cloud = _BusinessCloud()

    response = _client(service, cloud).open(
        path,
        method=method,
        headers=headers,
        **kwargs,
    )

    assert response.status_code == 400
    assert "X-V9-Context-Mode" in response.get_json()["error"]
    assert service.personal_reads == 0
    assert service.personal_creates == 0
    assert service.resolve_calls == []
    assert cloud.token_calls == 0
    assert cloud.user_calls == 0


def test_explicit_personal_never_initializes_cloud():
    service = _BusinessService()

    def forbidden_cloud_provider():
        raise AssertionError("personal mode must not initialize cloud")

    from v9.api import create_blueprint

    app = Flask(__name__)
    app.register_blueprint(
        create_blueprint(
            lambda: service,
            cloud_provider=forbidden_cloud_provider,
        )
    )
    response = app.test_client().get(
        "/api/v9/evidence",
        headers=_headers("personal", PERSONAL_ORG),
    )

    assert response.status_code == 200
    assert response.get_json()["evidence"][0]["organization_id"] == PERSONAL_ORG
    assert response.headers["X-V9-Resolved-Context-Mode"] == "personal"
    assert response.headers["X-V9-Resolved-Organization-ID"] == PERSONAL_ORG
    assert "Deprecation" not in response.headers
    assert service.resolve_calls == []


def test_uninitialized_personal_does_not_echo_an_unresolved_org():
    service = _BusinessService()
    service.personal = None

    response = _client(service).get(
        "/api/v9/evidence",
        headers=_headers("personal", OTHER_ORG),
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "evidence": [],
        "needs_bootstrap": True,
    }
    assert response.headers["X-V9-Resolved-Context-Mode"] == "personal"
    assert "X-V9-Resolved-Organization-ID" not in response.headers


def test_cloud_context_uses_current_jwt_active_identity_and_refreshes_role():
    service = _BusinessService()
    cloud = _BusinessCloud()
    response = _client(service, cloud).get(
        "/api/v9/evidence",
        headers=_headers("cloud", CLOUD_ORG),
    )

    assert response.status_code == 200
    assert response.get_json()["evidence"] == [
        {"organization_id": CLOUD_ORG}
    ]
    assert response.headers["X-V9-Resolved-Context-Mode"] == "cloud"
    assert response.headers["X-V9-Resolved-Organization-ID"] == CLOUD_ORG
    assert "X-V9-Context-Mode" in response.headers["Vary"]
    assert "X-V9-Organization-ID" in response.headers["Vary"]
    assert service.personal_reads == 0
    assert service.personal_creates == 0
    assert service.resolve_calls == [(CLOUD_ORG, CLOUD_USER)]
    assert service.refresh_calls == [(CLOUD_ORG, CLOUD_USER, "analyst")]
    assert cloud.token_calls >= 1
    assert cloud.user_calls >= 1
    device_query = next(
        query
        for table, _, query in cloud.client.calls
        if table == "devices"
    )
    assert device_query["organization_id"] == f"eq.{CLOUD_ORG}"
    assert device_query["user_id"] == f"eq.{CLOUD_USER}"
    assert device_query["id"] == f"eq.{CLOUD_DEVICE}"
    assert device_query["status"] == "eq.active"


@pytest.mark.parametrize(
    ("failure", "configure"),
    (
        (
            "inactive membership",
            lambda service, cloud: setattr(
                cloud.client, "membership_status", "invited"
            ),
        ),
        (
            "missing local cloud context",
            lambda service, cloud: setattr(
                service,
                "resolve_error",
                PermissionDenied("active cloud device context required"),
            ),
        ),
        (
            "remote device mismatch",
            lambda service, cloud: cloud.client.device_overrides.update(
                {"public_key": "\\x" + (b"x" * 65).hex()}
            ),
        ),
        (
            "remote key version is ahead",
            lambda service, cloud: setattr(
                cloud.client,
                "organization_key_version",
                2,
            ),
        ),
        (
            "remote key version is behind",
            lambda service, cloud: service.cloud.update(
                {"key_version": 2}
            ),
        ),
    ),
)
def test_cloud_failure_never_reads_or_creates_personal(
    failure,
    configure,
):
    service = _BusinessService()
    cloud = _BusinessCloud()
    configure(service, cloud)

    response = _client(service, cloud).get(
        "/api/v9/evidence",
        headers=_headers("cloud", CLOUD_ORG),
    )

    assert response.status_code == 403, failure
    assert service.personal_reads == 0
    assert service.personal_creates == 0
    assert service.evidence_contexts == []
    assert service.refresh_calls == []
    if "key version" in failure:
        assert "/api/v9/devices/self" in response.get_json()["error"]


def test_cloud_body_path_and_event_org_mismatch_precede_side_effects(
    monkeypatch,
):
    service = _BusinessService()
    cloud = _BusinessCloud()
    client = _client(service, cloud)

    record = client.post(
        "/api/v9/records",
        headers=_headers("cloud", CLOUD_ORG),
        json={
            "organization_id": OTHER_ORG,
            "device_id": CLOUD_DEVICE,
            "record_type": "evidence",
            "content": {"ciphertext": "opaque"},
        },
    )
    event = client.post(
        "/api/v9/sync/push",
        headers=_headers("cloud", CLOUD_ORG),
        json={
            "organization_id": CLOUD_ORG,
            "event": {"organization_id": OTHER_ORG},
        },
    )
    path = client.post(
        f"/api/v9/organizations/{OTHER_ORG}/backups",
        headers=_headers("cloud", CLOUD_ORG),
    )
    monkeypatch.setattr(
        "v9.api.validate_ciphertext_event",
        lambda _: {
            "organization_id": OTHER_ORG,
            "record_id": CLOUD_DEVICE,
            "payload": {"version_id": CLOUD_DEVICE},
        },
    )
    conflict = client.post(
        f"/api/v9/conflicts/{CLOUD_DEVICE}/resolve",
        headers=_headers("cloud", CLOUD_ORG),
        json={"resolution_event": {}},
    )

    assert record.status_code == 403
    assert event.status_code == 403
    assert path.status_code == 403
    assert conflict.status_code == 403
    assert service.personal_reads == 0
    assert service.personal_creates == 0
    assert service.record_writes == []
    assert service.remote_events == []
    assert cloud.token_calls == 0
    assert cloud.user_calls == 0
    assert cloud.client.calls == []
    assert cloud.rpc_calls == []


def test_all_business_data_routes_use_the_context_resolver():
    route_functions = (
        "archive_news",
        "evidence",
        "claims",
        "create_claim",
        "alert_rules",
        "save_alert_rule",
        "evaluate_rules",
        "graph",
        "create_graph_entity",
        "create_graph_relation",
        "geo_events",
        "create_geo_event",
        "alerts",
        "materialize_alerts",
        "triage_alert",
        "cases",
        "update_case",
        "jobs",
        "create_job",
        "control_job",
        "scenarios",
        "create_scenario",
        "update_scenario",
        "documents",
        "create_document",
        "update_document",
        "export_document",
        "publications",
        "create_publication",
        "move_publication",
        "sign_publication",
        "recall_publication",
        "export_publication",
        "audit_events",
        "create_record",
        "read_record",
        "update_record",
        "outbox",
        "resolve_cloud_conflict",
        "conflicts",
        "diagnostics",
        "create_backup",
        "personal_diagnostics",
        "personal_backup",
        "sync_push",
    )

    for name in route_functions:
        block = _function_block(name)
        assert "_business_context(" in block, name
        assert ".get_personal_context(" not in block, name
        assert ".get_or_create_personal_context(" not in block, name
        assert "_personal_context(" not in block, name


def test_operator_bootstrap_is_not_exposed_to_authenticated_desktop():
    cloud_bootstrap = _function_block("bootstrap_cloud_organization")
    assert "operator_provisioning_required" in cloud_bootstrap
    assert "get_personal_context()" not in cloud_bootstrap
    assert ".rpc(" not in cloud_bootstrap


def test_snapshot_bootstrap_keeps_personal_semantics():
    for name in (
        "bootstrap",
        "bootstrap_cloud_snapshot",
        "complete_cloud_snapshot",
    ):
        block = _function_block(name)
        assert "_personal_context(" in block
        assert "_business_context(" not in block
