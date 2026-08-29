# -*- coding: utf-8 -*-
from __future__ import annotations

import base64
import json
import os
import stat
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from flask import Flask


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))


def _service(tmp_path):
    from v9.service import V9Service

    return V9Service(
        tmp_path / "v9.sqlite3",
        tmp_path / ".v9_local_master.key",
    )


def _activate_p256_cloud_context(service, *, key_version=1):
    from v9.crypto import seal_org_key_for_p256

    organization_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    pending = service.prepare_cloud_device_registration(
        organization_id=organization_id,
        user_id=user_id,
        role="owner",
        membership_status="active",
        key_version=key_version,
        device_name="Desktop",
    )
    public_key = _unb64(pending["device_public_key"])
    org_key = bytes(range(32))
    envelope = seal_org_key_for_p256(
        org_key,
        public_key,
        org_id=organization_id,
        device_id=pending["device_id"],
        key_version=key_version,
    )
    remote_device = {
        "id": pending["device_id"],
        "organization_id": organization_id,
        "user_id": user_id,
        "key_algorithm": "p256",
        "device_kind": "desktop",
        "public_key": public_key,
        "status": "active",
    }
    active = service.activate_cloud_device_context(
        pending,
        remote_device=remote_device,
        envelope=envelope,
        expected_key_version=key_version,
        role="owner",
    )
    return active, remote_device, org_key


class _AuthenticatedSession:
    def __init__(self, user_id: str, session_id: str, *, token_sub=None):
        claims = {
            "sub": token_sub or user_id,
            "session_id": session_id,
        }
        self._user_id = user_id
        self._access_token = ".".join((
            _b64(b'{"alg":"ES256","typ":"JWT"}'),
            _b64(json.dumps(claims, sort_keys=True).encode("utf-8")),
            _b64(b"synthetic-signature"),
        ))

    def access_token(self):
        return self._access_token

    def user_id(self):
        return self._user_id


def test_new_cloud_desktop_is_p256_and_activation_is_strict(tmp_path):
    from v9.errors import PermissionDenied

    service = _service(tmp_path)
    active, remote, _org_key = _activate_p256_cloud_context(service)
    stored = service.repository.get_device(active["device_id"])

    assert active["key_algorithm"] == "p256"
    assert active["device_kind"] == "desktop"
    assert len(remote["public_key"]) == 65
    assert remote["public_key"][0] == 4
    assert stored["key_algorithm"] == "p256"
    assert stored["device_kind"] == "desktop"
    assert service.resolve_cloud_context(
        active["organization_id"], active["user_id"]
    ) == active

    wrong = dict(remote, key_algorithm="x25519")
    with pytest.raises(PermissionDenied, match="identity mismatch"):
        service.activate_cloud_device_context(
            active,
            remote_device=wrong,
            envelope={},
            expected_key_version=1,
        )


def test_repository_migration_does_not_guess_legacy_device_metadata(tmp_path):
    import sqlite3

    database = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(database) as conn:
        conn.executescript(
            """
            CREATE TABLE organizations(
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                key_version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            CREATE TABLE devices(
                id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL REFERENCES organizations(id),
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                public_key BLOB NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                revoked_at TEXT
            );
            INSERT INTO organizations VALUES ('legacy-org','Legacy',1,'now');
            INSERT INTO devices VALUES (
                'legacy-device','legacy-org','legacy-user','Legacy device',
                x'0000000000000000000000000000000000000000000000000000000000000000',
                'active','now',NULL
            );
            """
        )

    from v9.repository import V9Repository

    repository = V9Repository(database)
    legacy = repository.get_device("legacy-device")
    assert legacy["key_algorithm"] is None
    assert legacy["device_kind"] is None


def test_owner_bootstrap_manifest_uses_authenticated_session_and_p256(tmp_path):
    from v9.errors import PermissionDenied

    service = _service(tmp_path)
    personal = service.get_or_create_personal_context()
    service.acknowledge_personal_recovery(personal["organization_id"])
    owner_user_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    authenticated = _AuthenticatedSession(owner_user_id, session_id)

    manifest = service.build_mvp_owner_bootstrap_manifest(
        personal,
        authenticated_session=authenticated,
    )

    assert set(manifest) == {
        "schema_version",
        "organization_id",
        "owner_user_id",
        "session_id",
        "name_ciphertext",
        "name_nonce",
        "device_id",
        "device_public_key",
        "device_name_ciphertext",
        "device_name_nonce",
        "key_algorithm",
        "device_kind",
    }
    assert manifest["schema_version"] == 1
    assert manifest["organization_id"] == personal["organization_id"]
    assert manifest["owner_user_id"] == owner_user_id
    assert manifest["session_id"] == session_id
    assert manifest["key_algorithm"] == "p256"
    assert manifest["device_kind"] == "desktop"
    assert len(_unb64(manifest["device_public_key"])) == 65
    serialized = json.dumps(manifest, sort_keys=True)
    assert authenticated.access_token() not in serialized
    assert "private" not in serialized.lower()
    assert "org_key" not in serialized.lower()
    device = service.repository.get_device(manifest["device_id"])
    assert device["key_algorithm"] == "p256"
    assert device["device_kind"] == "desktop"

    forged = _AuthenticatedSession(
        owner_user_id,
        str(uuid.uuid4()),
        token_sub=str(uuid.uuid4()),
    )
    with pytest.raises(PermissionDenied, match="session identity"):
        service.build_mvp_owner_bootstrap_manifest(
            personal,
            authenticated_session=forged,
        )


def test_owner_bootstrap_manifest_export_is_atomic_private_and_no_overwrite(
    tmp_path,
):
    from scripts.export_mvp_owner_manifest import write_owner_manifest_atomic

    manifest = {
        "schema_version": 1,
        "organization_id": str(uuid.uuid4()),
        "owner_user_id": str(uuid.uuid4()),
        "session_id": str(uuid.uuid4()),
        "name_ciphertext": "ciphertext",
        "name_nonce": "nonce",
        "device_id": str(uuid.uuid4()),
        "device_public_key": _b64(b"\x04" + (b"p" * 64)),
        "device_name_ciphertext": "device-ciphertext",
        "device_name_nonce": "device-nonce",
        "key_algorithm": "p256",
        "device_kind": "desktop",
    }
    destination = tmp_path / "owner-bootstrap.json"

    written = write_owner_manifest_atomic(manifest, destination)

    assert written == destination.resolve()
    assert json.loads(destination.read_text(encoding="utf-8")) == manifest
    if os.name != "nt":
        assert stat.S_IMODE(destination.stat().st_mode) & 0o077 == 0
    with pytest.raises(FileExistsError):
        write_owner_manifest_atomic(manifest, destination)


def test_owner_manifest_windows_acl_uses_only_path_and_current_sid(
    tmp_path,
    monkeypatch,
):
    import scripts.export_mvp_owner_manifest as exporter

    target = tmp_path / "owner-bootstrap.tmp"
    target.touch()
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        if command[0] == "whoami":
            return SimpleNamespace(
                returncode=0,
                stdout='"desktop","S-1-5-21-1000"\n',
                stderr="",
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(exporter.subprocess, "run", fake_run)

    exporter._harden_windows_private_file(target)

    assert calls == [
        ["whoami", "/user", "/fo", "csv", "/nh"],
        [
            "icacls",
            str(target),
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-21-1000:F",
        ],
    ]
    assert "synthetic-sensitive-manifest-marker" not in repr(calls)


@pytest.mark.parametrize(
    ("responses", "message"),
    [
        ([SimpleNamespace(returncode=1, stdout="", stderr="missing")], "SID"),
        ([
            SimpleNamespace(
                returncode=0,
                stdout='"desktop","S-1-5-21-1000"\n',
                stderr="",
            ),
            SimpleNamespace(returncode=1, stdout="", stderr="denied"),
        ], "ACL"),
    ],
)
def test_owner_manifest_windows_acl_tools_fail_closed(
    tmp_path,
    monkeypatch,
    responses,
    message,
):
    import scripts.export_mvp_owner_manifest as exporter

    results = iter(responses)
    monkeypatch.setattr(
        exporter.subprocess,
        "run",
        lambda *_args, **_kwargs: next(results),
    )

    with pytest.raises(PermissionError, match=message):
        exporter._harden_windows_private_file(tmp_path / "owner.tmp")


def test_owner_export_session_uses_canonical_vault_and_selected_config(
    tmp_path,
    monkeypatch,
):
    import scripts.export_mvp_owner_manifest as exporter

    explicit_config = (
        tmp_path / "external" / "config" / ".supabase_v9_config.json"
    )
    explicit_config.parent.mkdir(parents=True)
    explicit_config.write_text("{}", encoding="utf-8")
    old_bug_vault = explicit_config.parent.parent / "vault"
    old_bug_vault.mkdir()
    (old_bug_vault / "supabase-pkce.vault").write_bytes(b"legacy-pkce")
    canonical_vault = tmp_path / "canonical-vault"
    loaded = []
    vaults = []

    class FakeSettings:
        @classmethod
        def load(cls, path):
            loaded.append(Path(path))
            return cls()

    class FakeVault:
        def __init__(self, path):
            vaults.append(Path(path))

    class FakeHttpClient:
        def __init__(self, _settings):
            pass

    class FakeSessionManager:
        def __init__(self, settings, vault, client):
            self.settings = settings
            self.vault = vault
            self.client = client

    monkeypatch.setattr(exporter, "CONFIG_DIR", explicit_config.parent)
    monkeypatch.setattr(exporter, "VAULT_DIR", canonical_vault)
    monkeypatch.setattr(exporter, "SupabaseSettings", FakeSettings)
    monkeypatch.setattr(exporter, "SessionVault", FakeVault)
    monkeypatch.setattr(exporter, "SupabaseHttpClient", FakeHttpClient)
    monkeypatch.setattr(exporter, "SupabaseSessionManager", FakeSessionManager)

    session = exporter._authenticated_cloud_session()

    assert isinstance(session, FakeSessionManager)
    assert loaded == [explicit_config.resolve()]
    assert vaults == [canonical_vault]
    assert (canonical_vault / "supabase-pkce.vault").read_bytes() == b"legacy-pkce"
    assert (old_bug_vault / "supabase-pkce.vault").read_bytes() == b"legacy-pkce"


class _Settings:
    def public_config(self):
        return {"configured": True}


class _ByokClient:
    def __init__(self, cloud):
        self.cloud = cloud

    def select(self, table, _token, query=None):
        if self.cloud.revoked:
            raise PermissionError("session revoked")
        if table == "memberships":
            return [{
                "organization_id": self.cloud.organization_id,
                "user_id": self.cloud.user_id(),
                "role": self.cloud.membership_role,
                "status": self.cloud.membership_status,
            }]
        if table == "organizations":
            return [{
                "id": self.cloud.organization_id,
                "key_version": self.cloud.organization_key_version,
            }]
        if table == "devices":
            rows = list(self.cloud.devices)
            query = query or {}
            if query.get("id"):
                wanted = str(query["id"]).removeprefix("eq.")
                rows = [row for row in rows if row["id"] == wanted]
            return [
                dict(row, public_key="\\x" + row["public_key"].hex())
                for row in rows
            ]
        if table == "key_envelopes":
            self.cloud.key_envelope_queries += 1
            return list(self.cloud.key_envelopes)
        return []


class _ByokCloud:
    def __init__(self, organization_id, user_id, devices):
        self.settings = _Settings()
        self.organization_id = organization_id
        self._user_id = user_id
        self.devices = list(devices)
        self.client = _ByokClient(self)
        self.credentials = {}
        self.put_payloads = []
        self.revoked = False
        self.next_user_id = None
        self.membership_role = "owner"
        self.membership_status = "active"
        self.organization_key_version = 1
        self.key_envelope_queries = 0
        self.key_envelopes = []
        self.bootstrap_envelope_payloads = []
        self.fail_bootstrap_envelope_response_once = False
        self.device_registration_payloads = []
        self.fail_device_registration_before_commit_once = False
        self.fail_device_registration_after_commit_once = False
        self._access_token = "jwt-memory-only"

    def access_token(self):
        if self.revoked:
            raise PermissionError("session revoked")
        return self._access_token

    def user_id(self):
        return self._user_id

    def complete_email_login(self, _code):
        if self.next_user_id is not None:
            self._user_id = self.next_user_id
        return {"authenticated": True, "user_id": self._user_id}

    def rpc(self, name, payload):
        if self.revoked:
            raise PermissionError("session revoked")
        if name == "accept_member_invitation":
            return {"accepted_count": 0}
        if name == "register_device":
            copied = json.loads(json.dumps(payload))
            self.device_registration_payloads.append(copied)
            if self.fail_device_registration_before_commit_once:
                self.fail_device_registration_before_commit_once = False
                raise RuntimeError("synthetic request loss before commit")
            matches = [
                row for row in self.devices
                if row["id"] == payload["device_id"]
            ]
            if matches:
                existing = matches[0]
                if (
                    existing["organization_id"]
                    != payload["organization_id"]
                    or existing["user_id"] != self.user_id()
                    or existing["key_algorithm"]
                    != payload["key_algorithm"]
                    or existing["device_kind"] != payload["device_kind"]
                    or existing["public_key"]
                    != _unb64(payload["device_public_key"])
                    or existing["device_name_ciphertext"]
                    != payload["device_name_ciphertext"]
                    or existing["device_name_nonce"]
                    != payload["device_name_nonce"]
                    or existing["status"] != "pending"
                ):
                    raise RuntimeError("synthetic registration conflict")
            else:
                self.devices.append({
                    "id": payload["device_id"],
                    "organization_id": payload["organization_id"],
                    "user_id": self.user_id(),
                    "key_algorithm": payload["key_algorithm"],
                    "device_kind": payload["device_kind"],
                    "public_key": _unb64(payload["device_public_key"]),
                    "device_name_ciphertext": (
                        payload["device_name_ciphertext"]
                    ),
                    "device_name_nonce": payload["device_name_nonce"],
                    "status": "pending",
                })
            if self.fail_device_registration_after_commit_once:
                self.fail_device_registration_after_commit_once = False
                raise RuntimeError("synthetic response loss after commit")
            return payload["device_id"]
        if name == "put_mvp_first_owner_key_envelope":
            self.bootstrap_envelope_payloads.append(dict(payload))
            self.key_envelopes.append({
                "organization_id": self.organization_id,
                "device_id": self.devices[0]["id"],
                "key_version": payload["p_key_version"],
                "key_algorithm": "p256",
                "ephemeral_public_key": _unb64(
                    payload["p_ephemeral_public_key"]
                ),
                "nonce": _unb64(payload["p_envelope_nonce"]),
                "ciphertext": _unb64(payload["p_envelope_ciphertext"]),
            })
            if self.fail_bootstrap_envelope_response_once:
                self.fail_bootstrap_envelope_response_once = False
                raise RuntimeError("synthetic response loss after commit")
            return {
                "status": "ready",
                "organization_id": self.organization_id,
                "device_id": self.devices[0]["id"],
                "key_version": payload["p_key_version"],
            }
        if name != "bind_device_session":
            raise AssertionError(name)
        device_id = payload.get("p_device_id")
        matches = [
            row for row in self.devices
            if row["id"] == device_id
            and row["organization_id"] == payload.get("p_organization_id")
            and row["user_id"] == self.user_id()
            and row["status"] == "active"
        ]
        if len(matches) != 1:
            from v9.supabase_client import SupabaseRequestError

            raise SupabaseRequestError(
                403, "rpc:bind_device_session"
            )
        return {
            "organization_id": self.organization_id,
            "device_id": device_id,
            "status": "active",
        }

    def list_user_ai_credential_devices(self):
        if self.revoked:
            raise PermissionError("session revoked")
        return [
            {
                "id": row["id"],
                "user_id": row["user_id"],
                "status": row["status"],
                "device_kind": row["device_kind"],
                "key_algorithm": row["key_algorithm"],
                "public_key": _b64(row["public_key"]),
            }
            for row in self.devices
        ]

    def put_user_ai_credential(self, payload):
        if self.revoked:
            raise PermissionError("session revoked")
        copied = json.loads(json.dumps(payload))
        self.put_payloads.append(copied)
        self.credentials[payload["provider"]] = copied
        return {
            "provider": payload["provider"],
            "model_id": payload["model_id"],
            "credential_version": payload["credential_version"],
            "device_count": len(payload["device_envelopes"]),
        }

    def list_user_ai_credentials(self):
        if self.revoked:
            raise PermissionError("session revoked")
        return [
            {
                "provider": item["provider"],
                "model_id": item["model_id"],
                "credential_version": item["credential_version"],
                "device_count": len(item["device_envelopes"]),
            }
            for item in self.credentials.values()
        ]

    def get_user_ai_credential(self, provider):
        if self.revoked:
            raise PermissionError("session revoked")
        return self.credentials.get(provider)

    def delete_user_ai_credential(self, provider):
        if self.revoked:
            raise PermissionError("session revoked")
        deleted = self.credentials.pop(provider, None) is not None
        return {"provider": provider, "deleted": deleted}


def _byok_client(tmp_path):
    from v9.api import create_blueprint

    service = _service(tmp_path)
    context, current_device, _ = _activate_p256_cloud_context(service)
    cloud = _ByokCloud(
        context["organization_id"], context["user_id"], [current_device]
    )
    app = Flask(__name__)
    app.register_blueprint(
        create_blueprint(lambda: service, cloud_provider=lambda: cloud)
    )
    headers = {
        "X-V9-Context-Mode": "cloud",
        "X-V9-Organization-ID": context["organization_id"],
    }
    return app.test_client(), service, cloud, context, headers


def _owner_bootstrap_client(tmp_path, *, export_manifest=True):
    from v9.api import create_blueprint

    service = _service(tmp_path)
    personal = service.get_or_create_personal_context()
    service.acknowledge_personal_recovery(personal["organization_id"])
    owner_user_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    authenticated = _AuthenticatedSession(owner_user_id, session_id)
    if export_manifest:
        service.build_mvp_owner_bootstrap_manifest(
            personal,
            authenticated_session=authenticated,
        )
    else:
        service.prepare_cloud_bootstrap_context(personal, owner_user_id)
    context = service.get_cloud_device_context(personal["organization_id"])
    assert context is not None
    cloud = _ByokCloud(context["organization_id"], owner_user_id, [{
        "id": context["device_id"],
        "organization_id": context["organization_id"],
        "user_id": owner_user_id,
        "key_algorithm": "p256",
        "device_kind": "desktop",
        "public_key": _unb64(context["device_public_key"]),
        "status": "active",
    }])
    cloud._access_token = authenticated.access_token()
    app = Flask(__name__)
    app.register_blueprint(
        create_blueprint(lambda: service, cloud_provider=lambda: cloud)
    )
    headers = {
        "X-V9-Context-Mode": "cloud",
        "X-V9-Organization-ID": context["organization_id"],
    }
    return app.test_client(), service, cloud, context, headers, session_id


def _pending_registration_client(tmp_path):
    from v9.api import create_blueprint

    service = _service(tmp_path)
    organization_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    cloud = _ByokCloud(organization_id, user_id, [])
    app = Flask(__name__)
    app.register_blueprint(
        create_blueprint(lambda: service, cloud_provider=lambda: cloud)
    )
    headers = {
        "X-V9-Context-Mode": "cloud",
        "X-V9-Organization-ID": organization_id,
    }
    return app.test_client(), service, cloud, organization_id, headers


@pytest.mark.parametrize("failure_point", ["before_commit", "after_commit"])
def test_pending_desktop_registration_retries_same_identity_after_loss(
    tmp_path,
    failure_point,
):
    client, service, cloud, organization_id, headers = (
        _pending_registration_client(tmp_path)
    )
    if failure_point == "before_commit":
        cloud.fail_device_registration_before_commit_once = True
    else:
        cloud.fail_device_registration_after_commit_once = True

    lost = client.post(
        "/api/v9/devices/self",
        headers=headers,
        json={"organization_id": organization_id},
    )

    assert lost.status_code == 503
    pending = service.get_cloud_device_context(organization_id)
    assert pending is not None and pending["status"] == "pending"
    expected_remote_count = 0 if failure_point == "before_commit" else 1
    assert len(cloud.devices) == expected_remote_count

    retried = client.post(
        "/api/v9/devices/self",
        headers=headers,
        json={"organization_id": organization_id},
    )

    assert retried.status_code == 202
    assert retried.get_json() == {
        "organization_id": organization_id,
        "device_id": pending["device_id"],
        "status": "pending",
    }
    assert len(cloud.devices) == 1
    assert len(cloud.device_registration_payloads) == 2
    assert (
        cloud.device_registration_payloads[0]
        == cloud.device_registration_payloads[1]
    )
    assert cloud.devices[0]["id"] == pending["device_id"]
    assert cloud.devices[0]["key_algorithm"] == "p256"
    assert cloud.devices[0]["device_kind"] == "desktop"


def test_first_owner_manifest_device_activates_without_remote_envelope(
    tmp_path,
):
    client, service, cloud, context, headers, session_id = (
        _owner_bootstrap_client(tmp_path)
    )
    stored = service.get_cloud_device_context(context["organization_id"])
    assert stored is not None
    assert stored["mvp_owner_bootstrap"]["schema_version"] == 1
    assert session_id not in json.dumps(stored, sort_keys=True)

    response = client.post(
        "/api/v9/devices/self",
        headers=headers,
        json={"organization_id": context["organization_id"]},
    )

    assert response.status_code == 200
    assert response.get_json()["status"] == "active"
    assert cloud.key_envelope_queries == 1
    assert len(cloud.bootstrap_envelope_payloads) == 1
    uploaded = cloud.bootstrap_envelope_payloads[0]
    assert set(uploaded) == {
        "p_key_version",
        "p_ephemeral_public_key",
        "p_envelope_nonce",
        "p_envelope_ciphertext",
    }
    assert len(_unb64(uploaded["p_ephemeral_public_key"])) == 65
    assert len(_unb64(uploaded["p_envelope_nonce"])) == 12
    assert len(_unb64(uploaded["p_envelope_ciphertext"])) == 48
    active = service.resolve_cloud_context(
        context["organization_id"], context["user_id"]
    )
    assert active["device_id"] == context["device_id"]
    assert "mvp_owner_bootstrap" not in active


def test_first_owner_envelope_response_loss_reuses_remote_envelope(tmp_path):
    client, service, cloud, context, headers, _ = _owner_bootstrap_client(
        tmp_path
    )
    cloud.fail_bootstrap_envelope_response_once = True

    lost = client.post(
        "/api/v9/devices/self",
        headers=headers,
        json={"organization_id": context["organization_id"]},
    )
    assert lost.status_code == 503
    pending = service.get_cloud_device_context(context["organization_id"])
    assert pending is not None and pending["status"] == "pending"
    assert len(cloud.bootstrap_envelope_payloads) == 1
    assert len(cloud.key_envelopes) == 1

    retried = client.post(
        "/api/v9/devices/self",
        headers=headers,
        json={"organization_id": context["organization_id"]},
    )

    assert retried.status_code == 200
    assert retried.get_json()["status"] == "active"
    assert len(cloud.bootstrap_envelope_payloads) == 1
    assert cloud.key_envelope_queries == 2
    active = service.get_cloud_device_context(context["organization_id"])
    assert active is not None and active["status"] == "active"
    assert "mvp_owner_bootstrap" not in active


def test_first_owner_rejects_malformed_existing_remote_envelope(tmp_path):
    client, service, cloud, context, headers, _ = _owner_bootstrap_client(
        tmp_path
    )
    cloud.key_envelopes.append({
        "organization_id": context["organization_id"],
        "device_id": context["device_id"],
        "key_version": 1,
        "key_algorithm": "p256",
        "ephemeral_public_key": b"\x04" + os.urandom(63),
        "nonce": os.urandom(12),
        "ciphertext": os.urandom(48),
    })

    response = client.post(
        "/api/v9/devices/self",
        headers=headers,
        json={"organization_id": context["organization_id"]},
    )

    assert response.status_code == 403
    assert cloud.bootstrap_envelope_payloads == []
    pending = service.get_cloud_device_context(context["organization_id"])
    assert pending is not None and pending["status"] == "pending"


@pytest.mark.parametrize(
    ("mutation", "envelope_queries"),
    [
        ("missing_marker", 1),
        ("different_session", 0),
        ("non_owner", 0),
        ("key_version", 0),
        ("different_user", 0),
        ("different_public_key", 0),
    ],
)
def test_first_owner_local_activation_rejects_unbound_identity(
    tmp_path,
    mutation,
    envelope_queries,
):
    client, service, cloud, context, headers, _ = _owner_bootstrap_client(
        tmp_path,
        export_manifest=mutation != "missing_marker",
    )
    if mutation == "different_session":
        membership = {
            "organization_id": context["organization_id"],
            "user_id": context["user_id"],
            "role": "owner",
            "status": "active",
        }
        envelope = service.build_bootstrapped_cloud_key_envelope(
            context,
            remote_device=cloud.devices[0],
            expected_key_version=1,
            membership=membership,
            authenticated_session=cloud,
        )
        cloud.key_envelopes.append({
            "organization_id": context["organization_id"],
            "device_id": context["device_id"],
            "key_version": 1,
            "key_algorithm": "p256",
            "ephemeral_public_key": _unb64(
                envelope["ephemeral_public_key"]
            ),
            "nonce": _unb64(envelope["nonce"]),
            "ciphertext": _unb64(envelope["ciphertext"]),
        })
        cloud._access_token = _AuthenticatedSession(
            context["user_id"], str(uuid.uuid4())
        ).access_token()
    elif mutation == "non_owner":
        cloud.membership_role = "admin"
    elif mutation == "key_version":
        cloud.organization_key_version = 2
    elif mutation == "different_user":
        cloud._user_id = str(uuid.uuid4())
        cloud._access_token = _AuthenticatedSession(
            cloud.user_id(), str(uuid.uuid4())
        ).access_token()
    elif mutation == "different_public_key":
        cloud.devices[0]["public_key"] = b"\x04" + os.urandom(64)

    response = client.post(
        "/api/v9/devices/self",
        headers=headers,
        json={"organization_id": context["organization_id"]},
    )

    assert response.status_code == 403
    assert cloud.key_envelope_queries == envelope_queries
    assert cloud.bootstrap_envelope_payloads == []
    pending = service.get_cloud_device_context(context["organization_id"])
    assert pending is not None and pending["status"] == "pending"


def test_byok_routes_never_return_persist_or_log_plaintext(tmp_path, caplog):
    from v9.api import (
        active_ai_credential_binding,
        lease_active_ai_credential,
    )

    client, _service, cloud, context, headers = _byok_client(tmp_path)
    secret = "synthetic-test-key-never-in-response-or-database"
    saved = client.put(
        "/api/v9/ai/credentials/deepseek",
        headers=headers,
        json={
            "organization_id": context["organization_id"],
            "model_id": "deepseek-v4-pro",
            "credential_version": 1,
            "api_key": secret,
        },
    )
    assert saved.status_code == 200
    assert saved.headers["Cache-Control"] == "no-store, private"
    assert saved.headers["Pragma"] == "no-cache"
    assert secret not in saved.get_data(as_text=True)
    assert secret not in json.dumps(cloud.put_payloads)
    assert secret not in caplog.text

    listed = client.get(
        "/api/v9/ai/credentials",
        headers=headers,
        query_string={"organization_id": context["organization_id"]},
    )
    assert listed.status_code == 200
    assert listed.headers["Cache-Control"] == "no-store, private"
    assert listed.headers["Pragma"] == "no-cache"
    assert secret not in listed.get_data(as_text=True)

    activated = client.post(
        "/api/v9/ai/credentials/deepseek/activate",
        headers=headers,
        json={"organization_id": context["organization_id"]},
    )
    assert activated.status_code == 200
    assert secret not in activated.get_data(as_text=True)
    assert not {
        "user_id",
        "organization_id",
        "device_id",
    }.intersection(activated.get_json())
    assert active_ai_credential_binding() == {
        "user_id": context["user_id"],
        "organization_id": context["organization_id"],
        "device_id": context["device_id"],
        "provider": "deepseek",
        "model_id": "deepseek-v4-pro",
        "credential_version": 1,
    }
    assert activated.get_json()["credential_version"] == 1
    with lease_active_ai_credential(
        "deepseek",
        user_id=context["user_id"],
        organization_id=context["organization_id"],
        device_id=context["device_id"],
        credential_version=1,
    ) as credential:
        assert credential.api_key_text() == secret

    deleted = client.delete(
        "/api/v9/ai/credentials/deepseek",
        headers=headers,
        json={"organization_id": context["organization_id"]},
    )
    assert deleted.status_code == 200
    with pytest.raises(PermissionError):
        with lease_active_ai_credential(
            "deepseek",
            user_id=context["user_id"],
            organization_id=context["organization_id"],
            device_id=context["device_id"],
            credential_version=1,
        ):
            pass


def test_active_byok_is_single_provider_identity_bound_and_login_clears_it(
    tmp_path,
):
    from v9.api import (
        active_ai_credential_binding,
        lease_active_ai_credential,
    )

    client, _service, cloud, context, headers = _byok_client(tmp_path)
    for provider, model_id in (
        ("deepseek", "deepseek-v4-pro"),
        ("moonshot", "kimi-k3"),
    ):
        saved = client.put(
            f"/api/v9/ai/credentials/{provider}",
            headers=headers,
            json={
                "organization_id": context["organization_id"],
                "model_id": model_id,
                "credential_version": 1,
                "api_key": f"synthetic-test-key-{provider}",
            },
        )
        assert saved.status_code == 200
        activated = client.post(
            f"/api/v9/ai/credentials/{provider}/activate",
            headers=headers,
            json={"organization_id": context["organization_id"]},
        )
        assert activated.status_code == 200

    with pytest.raises(PermissionError):
        with lease_active_ai_credential(
            "deepseek",
            user_id=context["user_id"],
            organization_id=context["organization_id"],
            device_id=context["device_id"],
            credential_version=1,
        ):
            pass
    with pytest.raises(PermissionError):
        with lease_active_ai_credential(
            "moonshot",
            user_id=str(uuid.uuid4()),
            organization_id=context["organization_id"],
            device_id=context["device_id"],
            credential_version=1,
        ):
            pass
    with lease_active_ai_credential(
        "moonshot",
        user_id=context["user_id"],
        organization_id=context["organization_id"],
        device_id=context["device_id"],
        credential_version=1,
    ) as credential:
        assert credential.model_id == "kimi-k3"

    previous_user_id = context["user_id"]
    cloud.next_user_id = str(uuid.uuid4())
    switched = client.get(
        "/api/v9/auth/callback?code=one-time-code",
        base_url="http://127.0.0.1:49231",
    )
    assert switched.status_code == 302
    assert cloud.user_id() != previous_user_id
    assert active_ai_credential_binding() is None
    for user_id in (previous_user_id, cloud.user_id()):
        with pytest.raises(PermissionError):
            with lease_active_ai_credential(
                "moonshot",
                user_id=user_id,
                organization_id=context["organization_id"],
                device_id=context["device_id"],
                credential_version=1,
            ):
                pass


def test_byok_remote_version_change_invalidates_and_zeros_active_key(tmp_path):
    from v9.api import (
        _ACTIVE_AI_CREDENTIALS,
        active_ai_credential_binding,
        lease_active_ai_credential,
    )

    client, _service, _cloud, context, headers = _byok_client(tmp_path)
    saved = client.put(
        "/api/v9/ai/credentials/deepseek",
        headers=headers,
        json={
            "organization_id": context["organization_id"],
            "model_id": "deepseek-v4-pro",
            "credential_version": 1,
            "api_key": "synthetic-test-key-version-one",
        },
    )
    assert saved.status_code == 200
    activated = client.post(
        "/api/v9/ai/credentials/deepseek/activate",
        headers=headers,
        json={"organization_id": context["organization_id"]},
    )
    assert activated.status_code == 200
    loaded = _ACTIVE_AI_CREDENTIALS._credential
    assert loaded is not None
    assert loaded.cleared is False

    with pytest.raises(PermissionError, match="version"):
        with lease_active_ai_credential(
            "deepseek",
            user_id=context["user_id"],
            organization_id=context["organization_id"],
            device_id=context["device_id"],
            credential_version=2,
        ):
            pass

    assert loaded.cleared is True
    assert active_ai_credential_binding() is None
    with pytest.raises(PermissionError):
        with lease_active_ai_credential(
            "deepseek",
            user_id=context["user_id"],
            organization_id=context["organization_id"],
            device_id=context["device_id"],
            credential_version=1,
        ):
            pass


def test_byok_same_version_rewrap_keeps_ciphertext_and_adds_target(tmp_path):
    from v9.ai_credentials import create_desktop_credential_keypair

    client, _service, cloud, context, headers = _byok_client(tmp_path)
    saved = client.put(
        "/api/v9/ai/credentials/moonshot",
        headers=headers,
        json={
            "organization_id": context["organization_id"],
            "model_id": "kimi-k3",
            "credential_version": 1,
            "api_key": "synthetic-test-key-same-version",
        },
    )
    assert saved.status_code == 200
    original = cloud.credentials["moonshot"]
    target_public, _target_private = create_desktop_credential_keypair()
    target_id = str(uuid.uuid4())
    cloud.devices.append({
        "id": target_id,
        "organization_id": context["organization_id"],
        "user_id": context["user_id"],
        "status": "active",
        "device_kind": "desktop",
        "key_algorithm": "p256",
        "public_key": target_public,
    })

    rewrapped = client.post(
        "/api/v9/ai/credentials/moonshot/rewrap",
        headers=headers,
        json={
            "organization_id": context["organization_id"],
            "target_device_id": target_id,
        },
    )
    assert rewrapped.status_code == 200
    latest = cloud.put_payloads[-1]
    assert latest["credential_version"] == 1
    assert latest["ciphertext"] == original["ciphertext"]
    assert latest["nonce"] == original["nonce"]
    assert {item["device_id"] for item in latest["device_envelopes"]} == {
        context["device_id"], target_id
    }


def test_byok_new_device_without_trusted_envelope_requires_reentry(tmp_path):
    from v9.ai_credentials import (
        create_desktop_credential_keypair,
        encrypt_api_credential,
    )

    client, _service, cloud, context, headers = _byok_client(tmp_path)
    old_public, _old_private = create_desktop_credential_keypair()
    old_device = {
        "id": str(uuid.uuid4()),
        "organization_id": context["organization_id"],
        "user_id": context["user_id"],
        "status": "active",
        "device_kind": "desktop",
        "key_algorithm": "p256",
        "public_key": old_public,
    }
    cloud.devices.append(old_device)
    secret = "synthetic-test-key-reentry-required"
    cloud.credentials["deepseek"] = encrypt_api_credential(
        secret,
        user_id=context["user_id"],
        provider="deepseek",
        model_id="deepseek-v4-pro",
        credential_version=1,
        devices=[old_device],
    ).to_rpc_payload()

    response = client.post(
        "/api/v9/ai/credentials/deepseek/activate",
        headers=headers,
        json={"organization_id": context["organization_id"]},
    )

    assert response.status_code == 409
    assert response.get_json() == {
        "status": "reentry_required",
        "reason": "trusted_device_unavailable",
    }
    assert secret not in response.get_data(as_text=True)


def test_byok_revoked_session_and_untrusted_new_device_fail_closed(tmp_path):
    client, _service, cloud, context, headers = _byok_client(tmp_path)
    cloud.revoked = True
    response = client.get(
        "/api/v9/ai/credentials",
        headers=headers,
        query_string={"organization_id": context["organization_id"]},
    )
    assert response.status_code == 401
    assert "jwt-memory-only" not in response.get_data(as_text=True)


def test_byok_wrong_user_device_is_rejected_before_secret_storage(tmp_path):
    client, _service, cloud, context, headers = _byok_client(tmp_path)
    cloud.devices[0]["user_id"] = str(uuid.uuid4())
    secret = "synthetic-test-key-wrong-user"

    response = client.put(
        "/api/v9/ai/credentials/deepseek",
        headers=headers,
        json={
            "organization_id": context["organization_id"],
            "model_id": "deepseek-v4-pro",
            "credential_version": 1,
            "api_key": secret,
        },
    )

    assert response.status_code == 403
    assert cloud.put_payloads == []
    assert secret not in response.get_data(as_text=True)
