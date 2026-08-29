import hashlib
import inspect
import json
import os
import ssl
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import scripts.collect_deployment_evidence as collector
from scripts.verify_deployment_evidence import (
    ORIGIN_ISOLATION_GATES,
    PRODUCTION_CHECKS,
    STAGING_CHECKS,
    seal_origin_isolation,
    verify,
)


COMMIT = "1a2b3c4d5e6f78900112233445566778899aabbc"
IMAGE_DIGEST = "sha256:" + hashlib.sha256(b"portal image").hexdigest()
IMAGE_ID = "sha256:" + hashlib.sha256(b"portal image config").hexdigest()
RUN_ID = 424242
STAGING_ORIGIN = "https://staging.example.test"
PRODUCTION_ORIGIN = "https://production.example.test"
STAGING_CERT = hashlib.sha256(b"staging cert").hexdigest()
PRODUCTION_CERT = hashlib.sha256(b"production cert").hexdigest()
SECURE_ENSURE_ROOT = collector._ensure_root


def test_deployment_evidence_tls_context_requires_tls12_and_identity_verification():
    context = collector._tls_client_context()

    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED


@pytest.fixture(autouse=True)
def _collector_machine_identity(tmp_path, monkeypatch):
    key = tmp_path / "deployment-evidence.key"
    key.write_bytes(hashlib.sha256(b"test-only collector key").digest())
    key.chmod(0o600)
    monkeypatch.setattr(collector, "COLLECTOR_KEY_PATH", key)
    monkeypatch.setattr(
        collector,
        "COLLECTOR_STATE_ROOT",
        tmp_path / "deployment-evidence-state",
    )
    def test_evidence_root(root: Path) -> Path:
        if root.is_symlink():
            raise collector.CollectionError("test evidence root is unsafe")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        return root

    monkeypatch.setattr(collector, "_ensure_root", test_evidence_root)


@pytest.mark.skipif(os.name != "nt", reason="Windows fail-closed check")
def test_secure_evidence_root_rejects_windows_runtime(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "EVIDENCE_ROOT_BASE", tmp_path)
    with pytest.raises(collector.CollectionError, match="requires a POSIX host"):
        SECURE_ENSURE_ROOT(tmp_path / COMMIT)


def test_secure_evidence_root_rejects_arbitrary_root_before_mutation(tmp_path):
    arbitrary = tmp_path / COMMIT
    with pytest.raises(
        collector.CollectionError, match="fixed release directory"
    ):
        SECURE_ENSURE_ROOT(arbitrary)
    assert not arbitrary.exists()


def _root_owned_directory_stat(metadata: os.stat_result, *, mode: int = 0o700, uid: int = 0):
    fields = list(metadata)
    fields[0] = stat.S_IFDIR | mode
    fields[4] = uid
    return os.stat_result(fields)


@pytest.mark.skipif(os.name == "nt", reason="dirfd trust checks are POSIX-only")
def test_secure_evidence_root_rejects_non_root_owned_existing_root(tmp_path, monkeypatch):
    root = tmp_path / COMMIT
    root.mkdir()
    real_fstat = os.fstat

    def fake_fstat(descriptor):
        metadata = real_fstat(descriptor)
        target = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
        uid = 1234 if target == root else 0
        return _root_owned_directory_stat(metadata, uid=uid)

    monkeypatch.setattr(collector.os, "geteuid", lambda: 0)
    monkeypatch.setattr(collector.os, "fstat", fake_fstat)
    monkeypatch.setattr(collector, "EVIDENCE_ROOT_BASE", tmp_path)
    with pytest.raises(collector.CollectionError, match="evidence root is not root-controlled"):
        SECURE_ENSURE_ROOT(root)


@pytest.mark.skipif(os.name == "nt", reason="dirfd trust checks are POSIX-only")
def test_secure_evidence_root_rejects_writable_parent(tmp_path, monkeypatch):
    root = tmp_path / "trusted-parent" / COMMIT
    root.mkdir(parents=True)
    writable_parent = root.parent
    real_fstat = os.fstat

    def fake_fstat(descriptor):
        metadata = real_fstat(descriptor)
        target = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
        mode = 0o777 if target == writable_parent else 0o700
        return _root_owned_directory_stat(metadata, mode=mode)

    monkeypatch.setattr(collector.os, "geteuid", lambda: 0)
    monkeypatch.setattr(collector.os, "fstat", fake_fstat)
    monkeypatch.setattr(collector, "EVIDENCE_ROOT_BASE", root.parent)
    with pytest.raises(
        collector.CollectionError, match="evidence root parent is not root-controlled"
    ):
        SECURE_ENSURE_ROOT(root)


@pytest.mark.skipif(os.name == "nt", reason="dirfd trust checks are POSIX-only")
def test_secure_evidence_root_rejects_symlink_swap_race(tmp_path, monkeypatch):
    parent = tmp_path / "trusted-parent"
    root = parent / COMMIT
    attacker = tmp_path / "attacker"
    root.mkdir(parents=True)
    attacker.mkdir()
    real_fstat = os.fstat
    real_open = os.open
    swapped = False

    def fake_fstat(descriptor):
        return _root_owned_directory_stat(real_fstat(descriptor))

    def racing_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if path == root.name and dir_fd is not None and not swapped:
            swapped = True
            root.rename(parent / "evidence-original")
            root.symlink_to(attacker, target_is_directory=True)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(collector.os, "geteuid", lambda: 0)
    monkeypatch.setattr(collector.os, "fstat", fake_fstat)
    monkeypatch.setattr(collector.os, "open", racing_open)
    monkeypatch.setattr(collector, "EVIDENCE_ROOT_BASE", parent)
    with pytest.raises(collector.CollectionError, match="changed or contains a symbolic link"):
        SECURE_ENSURE_ROOT(root)
    assert swapped


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tls(origin: str, certificate_sha256: str, at: datetime) -> collector.TlsMeasurement:
    return collector.TlsMeasurement(
        server_name=origin.removeprefix("https://"),
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        peer_certificate_sha256=certificate_sha256,
        not_before_utc=_utc(at - timedelta(days=1)),
        not_after_utc=_utc(at + timedelta(days=30)),
    )


def _plan(path: Path, environment: str, *, secret_env: str = "TEST_AUTH_TOKEN") -> None:
    checks = STAGING_CHECKS if environment == "staging" else PRODUCTION_CHECKS
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "environment": environment,
                "checks": [
                    {
                        "name": name,
                        "method": collector.PROBE_ROUTE_SPECS[name]["method"],
                        "path": collector.PROBE_ROUTE_SPECS[name]["path"],
                        "headers": [
                            {"name": "Authorization", "value_env": secret_env}
                        ],
                        "body_env": "TEST_REQUEST_BODY" if status != 200 else None,
                    }
                    for name, status in checks.items()
                ],
            },
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )


def _env() -> dict[str, str]:
    return {
        "STAGING_ORIGIN": STAGING_ORIGIN,
        "PRODUCTION_ORIGIN": PRODUCTION_ORIGIN,
        "TEST_AUTH_TOKEN": "Bearer secret-that-must-not-be-written",
        "TEST_REQUEST_BODY": '{"secret":"must-not-be-written"}',
    }


def _release_fields() -> dict[str, object]:
    return {
        "version": "9.0.0",
        "semantic_version": "9.0.0",
        "display_version": "V9",
        "release_tag": "v9.0.0",
        "build_commit": COMMIT,
        "wire_compatibility": "mvp-wire-v1",
    }


def _public_response(name: str, challenge: str) -> bytes:
    payload: dict[str, object] = {
        **_release_fields(),
        "evidence_challenge": challenge,
    }
    if name in {"health", "api_status"}:
        payload.update(
            {"status": "ok", "mode": "ciphertext-only", "sync_backend": "supabase"}
        )
    else:
        payload.update(
            {
                "configured": True,
                "url": "https://api.example.test",
                "publishable_key": "sb_publishable_test_public_value",
                "invited_signup_enabled": False,
                "access_applications_enabled": False,
                "account_limit": 100,
                "daily_event_limit": 1000,
                "deployment_mode": "mvp",
            }
        )
    return json.dumps(payload, separators=(",", ":")).encode()


def _probe_response(name: str, challenge: str, environment: str) -> bytes:
    origin = STAGING_ORIGIN if environment == "staging" else PRODUCTION_ORIGIN
    return json.dumps(
        {
            "schema": 1,
            "check": name,
            "result": "pass",
            "result_code": collector.PROBE_RESULT_CODES[name],
            "environment": environment,
            "origin": origin,
            "semantic_version": "9.0.0",
            "release_commit": COMMIT,
            "wire_compatibility": "mvp-wire-v1",
            "portal_image_digest": IMAGE_DIGEST,
            "evidence_challenge": challenge,
        },
        separators=(",", ":"),
    ).encode()


def _runtime_portal(
    environment: str = "staging", origin: str = STAGING_ORIGIN
) -> dict[str, object]:
    return {
        "environment": environment,
        "origin": origin,
        "container_name": collector.PORTAL_CONTAINER_NAME,
        "image_reference": f"ghcr.io/example/portal@{IMAGE_DIGEST}",
        "image_digest": IMAGE_DIGEST,
        "image_id": IMAGE_ID,
        "release_commit": COMMIT,
        "wire_compatibility": "mvp-wire-v1",
        "state": "healthy",
    }


def _fake_http_factory(
    *,
    environment: str,
    clock: datetime,
    wrong_name: str | None = None,
):
    expected = STAGING_CHECKS if environment == "staging" else PRODUCTION_CHECKS

    origin = STAGING_ORIGIN if environment == "staging" else PRODUCTION_ORIGIN
    certificate = STAGING_CERT if environment == "staging" else PRODUCTION_CERT

    def fake_http(method, url, headers, body, timeout_seconds):
        challenge = headers[collector.EVIDENCE_CHALLENGE_HEADER]
        assert collector.EVIDENCE_CHALLENGE_RE.fullmatch(challenge)
        public_name = next(
            (
                candidate
                for candidate, path in collector.PUBLIC_METADATA_PATHS.items()
                if url.endswith(path)
            ),
            None,
        )
        if public_name is not None:
            name = public_name
            status = 200
            response = _public_response(name, challenge)
        else:
            name = url.rsplit("/", 1)[-1]
            status = expected[name]
            if name == wrong_name:
                status = 418
            response = _probe_response(name, challenge, environment)
        return (
            _tls(origin, certificate, clock),
            collector.HttpMeasurement(
                status_code=status,
                elapsed_ms=10,
                observed_at_utc=_utc(clock),
                response_sha256=hashlib.sha256(response).hexdigest(),
                response_body=response,
            ),
        )

    return fake_http


def _collect_probe(
    monkeypatch,
    root: Path,
    *,
    environment: str,
    at: datetime,
    wrong_name: str | None = None,
):
    plan = root.parent / f"{environment}-plan.json"
    _plan(plan, environment)
    monkeypatch.setattr(collector, "_utc_now", lambda: at)
    monkeypatch.setattr(
        collector,
        "_perform_https_request",
        _fake_http_factory(
            environment=environment,
            clock=at,
            wrong_name=wrong_name,
        ),
    )
    monkeypatch.setattr(
        collector,
        "_running_portal_identity",
        lambda **kwargs: _runtime_portal(kwargs["environment"], kwargs["origin"]),
    )
    return collector.collect_probe(
        evidence_root=root,
        environment=environment,
        origin_env=f"{environment.upper()}_ORIGIN",
        plan_path=plan,
        release_commit=COMMIT,
        candidate_run_id=RUN_ID,
        portal_image_digest=IMAGE_DIGEST,
        timeout_seconds=15,
        environ=_env(),
    )


def test_probe_uses_real_http_tls_measurements_without_persisting_secrets(
    tmp_path, monkeypatch
):
    root = tmp_path / "evidence"
    at = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=5)
    output = _collect_probe(monkeypatch, root, environment="staging", at=at)
    assert output == root / "staging-probe.json"
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema"] == 3
    assert payload["origin"] == STAGING_ORIGIN
    assert payload["tls"]["peer_certificate_sha256"] == STAGING_CERT
    assert {row["name"] for row in payload["checks"]} == set(STAGING_CHECKS)
    assert {row["name"] for row in payload["public_metadata"]} == set(
        collector.PUBLIC_METADATA_PATHS
    )
    assert payload["runtime_portal"] == _runtime_portal("staging", STAGING_ORIGIN)
    assert collector.SHA256_RE.fullmatch(payload["challenge_sha256"])
    assert {row["status_code"] for row in payload["checks"]} == set(
        STAGING_CHECKS.values()
    )
    rendered = output.read_text(encoding="utf-8")
    assert "secret-that-must-not-be-written" not in rendered
    assert "must-not-be-written" not in rendered
    assert "evidence_challenge" not in rendered


def test_probe_wrong_live_status_fails_without_writing_evidence(tmp_path, monkeypatch):
    root = tmp_path / "evidence"
    at = datetime.now(timezone.utc).replace(microsecond=0)
    with pytest.raises(collector.CollectionError, match="unexpected status"):
        _collect_probe(
            monkeypatch,
            root,
            environment="production",
            at=at,
            wrong_name="release_metadata",
        )
    assert not (root / "production-probe.json").exists()


def _measurement_with_body(
    measurement: collector.HttpMeasurement, body: bytes
) -> collector.HttpMeasurement:
    return collector.HttpMeasurement(
        status_code=measurement.status_code,
        elapsed_ms=measurement.elapsed_ms,
        observed_at_utc=measurement.observed_at_utc,
        response_sha256=hashlib.sha256(body).hexdigest(),
        response_body=body,
    )


def test_legacy_status_matrix_service_is_rejected_without_evidence(tmp_path, monkeypatch):
    """Correct HTTP statuses alone must never impersonate a V9 deployment."""

    root = tmp_path / "evidence"
    plan = tmp_path / "plan.json"
    _plan(plan, "production")
    at = datetime.now(timezone.utc).replace(microsecond=0)
    monkeypatch.setattr(collector, "_utc_now", lambda: at)
    monkeypatch.setattr(
        collector,
        "_running_portal_identity",
        lambda **kwargs: _runtime_portal(kwargs["environment"], kwargs["origin"]),
    )

    def status_matrix(method, url, headers, body, timeout_seconds):
        del method, headers, body, timeout_seconds
        name = url.rsplit("/", 1)[-1]
        status = PRODUCTION_CHECKS.get(name, 200)
        response = b'{"status":"ok"}'
        return (
            _tls(PRODUCTION_ORIGIN, PRODUCTION_CERT, at),
            collector.HttpMeasurement(
                status_code=status,
                elapsed_ms=5,
                observed_at_utc=_utc(at),
                response_sha256=hashlib.sha256(response).hexdigest(),
                response_body=response,
            ),
        )

    monkeypatch.setattr(collector, "_perform_https_request", status_matrix)
    with pytest.raises(collector.CollectionError, match="fields differ"):
        collector.collect_probe(
            evidence_root=root,
            environment="production",
            origin_env="PRODUCTION_ORIGIN",
            plan_path=plan,
            release_commit=COMMIT,
            candidate_run_id=RUN_ID,
            portal_image_digest=IMAGE_DIGEST,
            timeout_seconds=15,
            environ=_env(),
        )
    assert not (root / "production-probe.json").exists()


@pytest.mark.parametrize(
    ("target", "field", "value", "error"),
    [
        ("health", "build_commit", "0" * 40, "release metadata differs"),
        (
            "cross_role_rls_negative",
            "result_code",
            "GENERIC_FORBIDDEN",
            "response semantics differ",
        ),
        (
            "event_1001_rejected",
            "evidence_challenge",
            "0" * 64,
            "response semantics differ",
        ),
        (
            "member_101_rejected",
            "environment",
            "production",
            "response semantics differ",
        ),
        (
            "duplicate_request_rejection",
            "origin",
            PRODUCTION_ORIGIN,
            "response semantics differ",
        ),
    ],
)
def test_probe_rejects_stale_release_generic_error_or_replayed_challenge(
    tmp_path, monkeypatch, target, field, value, error
):
    root = tmp_path / "evidence"
    plan = tmp_path / "plan.json"
    _plan(plan, "staging")
    at = datetime.now(timezone.utc).replace(microsecond=0)
    base = _fake_http_factory(environment="staging", clock=at)
    monkeypatch.setattr(collector, "_utc_now", lambda: at)
    monkeypatch.setattr(
        collector,
        "_running_portal_identity",
        lambda **kwargs: _runtime_portal(kwargs["environment"], kwargs["origin"]),
    )

    def tampered(method, url, headers, body, timeout_seconds):
        tls, measurement = base(method, url, headers, body, timeout_seconds)
        public_name = next(
            (
                candidate
                for candidate, path in collector.PUBLIC_METADATA_PATHS.items()
                if url.endswith(path)
            ),
            None,
        )
        name = public_name or url.rsplit("/", 1)[-1]
        if name == target:
            payload = json.loads(measurement.response_body)
            payload[field] = value
            mutated = json.dumps(payload, separators=(",", ":")).encode()
            measurement = _measurement_with_body(measurement, mutated)
        return tls, measurement

    monkeypatch.setattr(collector, "_perform_https_request", tampered)
    with pytest.raises(collector.CollectionError, match=error):
        collector.collect_probe(
            evidence_root=root,
            environment="staging",
            origin_env="STAGING_ORIGIN",
            plan_path=plan,
            release_commit=COMMIT,
            candidate_run_id=RUN_ID,
            portal_image_digest=IMAGE_DIGEST,
            timeout_seconds=15,
            environ=_env(),
        )
    assert not (root / "staging-probe.json").exists()


def test_running_portal_identity_uses_fixed_container_inspection(tmp_path, monkeypatch):
    docker = tmp_path / "docker"
    docker.write_bytes(b"fixed docker client")
    captured: dict[str, object] = {"calls": []}
    monkeypatch.setattr(collector.shutil, "which", lambda *args, **kwargs: str(docker))
    monkeypatch.setattr(collector, "_require_root_controlled_path", lambda path, label: path)

    def run(argv, *, timeout_seconds, child_environment=None):
        del child_environment
        captured["calls"].append(argv)
        captured["timeout"] = timeout_seconds
        now = collector._utc_now()
        if argv[1] == "container":
            payload = {
                "image_reference": f"ghcr.io/example/portal@{IMAGE_DIGEST}",
                "image_id": IMAGE_ID,
                "release_commit": COMMIT,
                "wire_compatibility": "mvp-wire-v1",
                "running": True,
                "health": "healthy",
            }
        else:
            payload = {
                "image_id": IMAGE_ID,
                "repo_digests": [f"ghcr.io/example/portal@{IMAGE_DIGEST}"],
                "release_commit": COMMIT,
                "wire_compatibility": "mvp-wire-v1",
            }
        stdout = json.dumps(payload, separators=(",", ":")).encode()
        return collector.CommandMeasurement(
            exit_code=0,
            stdout=stdout,
            stderr=b"",
            started_at_utc=_utc(now),
            completed_at_utc=_utc(now),
        )

    monkeypatch.setattr(collector, "run_command", run)
    assert collector._running_portal_identity(
        environment="production",
        origin=PRODUCTION_ORIGIN,
        release_commit=COMMIT,
        portal_image_digest=IMAGE_DIGEST,
    ) == _runtime_portal("production", PRODUCTION_ORIGIN)
    assert captured["timeout"] == 30
    calls = captured["calls"]
    assert calls[0][-1] == collector.PORTAL_CONTAINER_NAME
    assert calls[0][1:4] == ["container", "inspect", "--format"]
    assert calls[1][1:4] == ["image", "inspect", "--format"]
    assert calls[1][-1] == IMAGE_ID


def test_running_portal_identity_rejects_cli_digest_not_deployed(tmp_path, monkeypatch):
    monkeypatch.setattr(collector.shutil, "which", lambda *args, **kwargs: str(tmp_path / "docker"))
    monkeypatch.setattr(collector, "_require_root_controlled_path", lambda path, label: path)
    wrong_digest = "sha256:" + "0" * 64
    now = collector._utc_now()
    monkeypatch.setattr(
        collector,
        "run_command",
        lambda *args, **kwargs: collector.CommandMeasurement(
            exit_code=0,
            stdout=json.dumps(
                {
                    "image_reference": f"ghcr.io/example/portal@{wrong_digest}",
                    "image_id": IMAGE_ID,
                    "release_commit": COMMIT,
                    "wire_compatibility": "mvp-wire-v1",
                    "running": True,
                    "health": "healthy",
                }
            ).encode(),
            stderr=b"",
            started_at_utc=_utc(now),
            completed_at_utc=_utc(now),
        ),
    )
    with pytest.raises(collector.CollectionError, match="identity differs"):
        collector._running_portal_identity(
            environment="production",
            origin=PRODUCTION_ORIGIN,
            release_commit=COMMIT,
            portal_image_digest=IMAGE_DIGEST,
        )


def test_running_portal_identity_rejects_config_reference_absent_from_repo_digests(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        collector.shutil, "which", lambda *args, **kwargs: str(tmp_path / "docker")
    )
    monkeypatch.setattr(
        collector, "_require_root_controlled_path", lambda path, label: path
    )
    calls = {"count": 0}

    def run(*args, **kwargs):
        del args, kwargs
        calls["count"] += 1
        now = collector._utc_now()
        payload = (
            {
                "image_reference": f"ghcr.io/example/portal@{IMAGE_DIGEST}",
                "image_id": IMAGE_ID,
                "release_commit": COMMIT,
                "wire_compatibility": "mvp-wire-v1",
                "running": True,
                "health": "healthy",
            }
            if calls["count"] == 1
            else {
                "image_id": IMAGE_ID,
                "repo_digests": ["ghcr.io/example/portal@sha256:" + "0" * 64],
                "release_commit": COMMIT,
                "wire_compatibility": "mvp-wire-v1",
            }
        )
        return collector.CommandMeasurement(
            exit_code=0,
            stdout=json.dumps(payload).encode(),
            stderr=b"",
            started_at_utc=_utc(now),
            completed_at_utc=_utc(now),
        )

    monkeypatch.setattr(collector, "run_command", run)
    with pytest.raises(collector.CollectionError, match="RepoDigest differs"):
        collector._running_portal_identity(
            environment="production",
            origin=PRODUCTION_ORIGIN,
            release_commit=COMMIT,
            portal_image_digest=IMAGE_DIGEST,
        )


def test_public_metadata_endpoints_echo_only_bounded_evidence_challenge(tmp_path):
    from v9_cloud import create_app

    application = create_app(
        database_path=tmp_path / "portal.sqlite3",
        legacy_coordinator_enabled=False,
        allowed_origins={"https://portal.example.test"},
        supabase_url="https://api.example.test",
        supabase_publishable_key="sb_publishable_test_public_value",
        invited_signup_enabled=False,
        access_applications_enabled=False,
        production_mode=True,
        build_commit=COMMIT,
    )
    client = application.test_client()
    challenge = "a1" * 32
    for name, path in collector.PUBLIC_METADATA_PATHS.items():
        response = client.get(path, headers={collector.EVIDENCE_CHALLENGE_HEADER: challenge})
        assert response.status_code == 200
        payload = response.get_json()
        assert payload["semantic_version"] == "9.0.0"
        assert payload["build_commit"] == COMMIT
        assert payload["wire_compatibility"] == "mvp-wire-v1"
        assert payload["evidence_challenge"] == challenge
        collector._validate_public_metadata_response(
            name,
            collector.HttpMeasurement(
                status_code=response.status_code,
                elapsed_ms=1,
                observed_at_utc=_utc(datetime.now(timezone.utc).replace(microsecond=0)),
                response_sha256=hashlib.sha256(response.data).hexdigest(),
                response_body=response.data,
            ),
            release_commit=COMMIT,
            challenge=challenge,
        )

    invalid = client.get(
        "/health",
        headers={collector.EVIDENCE_CHALLENGE_HEADER: "refuse arbitrary reflected text"},
    )
    assert invalid.status_code == 400
    assert invalid.get_json() == {"error_code": "INVALID_EVIDENCE_CHALLENGE"}


def test_probe_plan_cannot_override_collector_challenge_header(tmp_path, monkeypatch):
    plan = tmp_path / "plan.json"
    _plan(plan, "staging")
    payload = json.loads(plan.read_text(encoding="utf-8"))
    payload["checks"][0]["headers"].append(
        {
            "name": collector.EVIDENCE_CHALLENGE_HEADER,
            "value_env": "TEST_AUTH_TOKEN",
        }
    )
    plan.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(
        collector,
        "_perform_https_request",
        lambda *args: pytest.fail("reserved challenge header reached the network"),
    )
    with pytest.raises(collector.CollectionError, match="unsafe or duplicated"):
        collector.collect_probe(
            evidence_root=tmp_path / "evidence",
            environment="staging",
            origin_env="STAGING_ORIGIN",
            plan_path=plan,
            release_commit=COMMIT,
            candidate_run_id=RUN_ID,
            portal_image_digest=IMAGE_DIGEST,
            timeout_seconds=15,
            environ=_env(),
        )


@pytest.mark.parametrize(
    "mutation,error",
    [
        (lambda plan: plan["checks"][0].update({"status_code": 200}), "fields differ"),
        (
            lambda plan: plan["checks"][0].update(
                {"path": "https://attacker.example.test/health"}
            ),
            "relative HTTPS-origin path",
        ),
        (
            lambda plan: plan["checks"][0]["headers"][0].update(
                {"value": "literal secret"}
            ),
            "fields differ",
        ),
    ],
)
def test_probe_plan_has_no_manual_result_or_literal_secret_escape(
    tmp_path, monkeypatch, mutation, error
):
    root = tmp_path / "evidence"
    plan = tmp_path / "plan.json"
    _plan(plan, "staging")
    payload = json.loads(plan.read_text(encoding="utf-8"))
    mutation(payload)
    plan.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(
        collector,
        "_perform_https_request",
        lambda *args: pytest.fail("invalid plan reached the network"),
    )
    with pytest.raises(collector.CollectionError, match=error):
        collector.collect_probe(
            evidence_root=root,
            environment="staging",
            origin_env="STAGING_ORIGIN",
            plan_path=plan,
            release_commit=COMMIT,
            candidate_run_id=RUN_ID,
            portal_image_digest=IMAGE_DIGEST,
            timeout_seconds=15,
            environ=_env(),
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda checks: checks[0].update({"path": "/health"}),
        lambda checks: checks[0].update({"method": "DELETE"}),
        lambda checks: (
            checks[0].update({"path": checks[1]["path"]}),
            checks[1].update({"path": checks[0]["path"]}),
        ),
    ],
)
def test_probe_plan_cannot_relabel_or_swap_fixed_semantic_routes(
    tmp_path, monkeypatch, mutation
):
    plan = tmp_path / "plan.json"
    _plan(plan, "staging")
    payload = json.loads(plan.read_text(encoding="utf-8"))
    mutation(payload["checks"])
    plan.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(
        collector,
        "_perform_https_request",
        lambda *args: pytest.fail("invalid route contract reached the network"),
    )
    with pytest.raises(collector.CollectionError, match="fixed route contract"):
        collector.collect_probe(
            evidence_root=tmp_path / "evidence",
            environment="staging",
            origin_env="STAGING_ORIGIN",
            plan_path=plan,
            release_commit=COMMIT,
            candidate_run_id=RUN_ID,
            portal_image_digest=IMAGE_DIGEST,
            timeout_seconds=15,
            environ=_env(),
        )


@pytest.mark.parametrize(
    "origin",
    [
        "http://staging.example.test",
        "https://staging.example.test/path",
        "https://user:pass@staging.example.test",
        "https://127.0.0.1",
        "HTTPS://STAGING.EXAMPLE.TEST",
    ],
)
def test_origin_must_be_exact_lowercase_public_https(tmp_path, monkeypatch, origin):
    root = tmp_path / "evidence"
    plan = tmp_path / "plan.json"
    _plan(plan, "staging")
    environment = _env()
    environment["STAGING_ORIGIN"] = origin
    with pytest.raises(collector.CollectionError, match="lowercase public HTTPS origin"):
        collector.collect_probe(
            evidence_root=root,
            environment="staging",
            origin_env="STAGING_ORIGIN",
            plan_path=plan,
            release_commit=COMMIT,
            candidate_run_id=RUN_ID,
            portal_image_digest=IMAGE_DIGEST,
            timeout_seconds=15,
            environ=environment,
        )


def _command_env(value: str) -> str:
    return json.dumps([str(Path(sys.executable).resolve()), "-c", f"print({value!r})"])


def _observation_environment(tmp_path: Path) -> dict[str, str]:
    return _env()


def _install_observation_measurements(
    monkeypatch,
    *,
    environment: str,
    start: datetime,
    certificate: str,
    wrong_certificate: bool = False,
) -> None:
    origin = STAGING_ORIGIN if environment == "staging" else PRODUCTION_ORIGIN
    interval = collector.OBSERVATION_POLICIES[environment]["interval_seconds"]
    calls = {"count": 0}

    def measure(*args, **kwargs):
        headers = args[2]
        challenge = headers[collector.EVIDENCE_CHALLENGE_HEADER]
        index = calls["count"]
        calls["count"] += 1
        observed = start + timedelta(seconds=interval * index)
        actual_certificate = (
            hashlib.sha256(b"wrong certificate").hexdigest()
            if wrong_certificate
            else certificate
        )
        body = _public_response("health", challenge)
        return (
            _tls(origin, actual_certificate, observed),
            collector.HttpMeasurement(
                status_code=200,
                elapsed_ms=25,
                observed_at_utc=_utc(observed),
                response_sha256=hashlib.sha256(body).hexdigest(),
                response_body=body,
            ),
        )

    monkeypatch.setattr(collector, "_perform_https_request", measure)
    monkeypatch.setattr(collector.time, "sleep", lambda delay: None)
    monkeypatch.setattr(
        collector,
        "_collect_host_metrics",
        lambda measured_environment, observed: (
            55.5,
            3.5,
            hashlib.sha256(f"{measured_environment}-device".encode()).hexdigest(),
            hashlib.sha256(f"{measured_environment}-backup".encode()).hexdigest(),
        ),
    )


def test_observation_collects_complete_nonresumable_window_from_native_metrics(
    tmp_path, monkeypatch
):
    root = tmp_path / "evidence"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    _collect_probe(
        monkeypatch,
        root,
        environment="staging",
        at=now - timedelta(hours=24, minutes=5),
    )
    environment = _observation_environment(tmp_path)
    _install_observation_measurements(
        monkeypatch,
        environment="staging",
        start=now - timedelta(hours=24),
        certificate=STAGING_CERT,
    )
    output = collector.collect_observation(
        evidence_root=root,
        environment="staging",
        origin_env="STAGING_ORIGIN",
        health_path="/health",
        release_commit=COMMIT,
        candidate_run_id=RUN_ID,
        portal_image_digest=IMAGE_DIGEST,
        http_timeout_seconds=15,
        environ=environment,
    )
    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 26
    assert records[0]["disk_free_percent"] == 55.5
    assert records[-1]["backup_age_hours"] == 3.5
    assert _parse_test_utc(records[-1]["observed_at_utc"]) - _parse_test_utc(
        records[0]["observed_at_utc"]
    ) == timedelta(hours=25)


def _parse_test_utc(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


@pytest.mark.skipif(os.name == "nt", reason="fixed production paths are POSIX-only")
def test_observation_host_metrics_use_fixed_root_config_and_backup_receipt(
    tmp_path, monkeypatch
):
    data_root = tmp_path / "opt" / "defense-tracker"
    data_path = data_root / "supabase" / "db-data"
    backup_root = tmp_path / "var" / "defense-tracker-backup"
    backup_state = backup_root / "staging"
    data_path.mkdir(parents=True)
    backup_state.mkdir(parents=True)
    completed = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=3)
    receipt = backup_state / "last-success"
    receipt.write_text(
        "schema=1\n"
        f"completed_at_utc={_utc(completed)}\n"
        "backup_file=defense-tracker-test.tar.age\n"
        f"sha256={hashlib.sha256(b'backup').hexdigest()}\n",
        encoding="ascii",
    )
    config = tmp_path / "staging.env"
    config.write_text(
        f"SUPABASE_POSTGRES_DATA_DIR={data_path}\n"
        f"BACKUP_STATE_DIR={backup_state}\n"
        "UNRELATED_SECRET=never-read-into-evidence\n",
        encoding="utf-8",
    )
    config.chmod(0o640)
    receipt.chmod(0o640)
    monkeypatch.setattr(collector, "OBSERVATION_CONFIG_PATHS", {"staging": config})
    monkeypatch.setattr(collector, "OBSERVATION_DATA_ROOT", data_root)
    monkeypatch.setattr(collector, "OBSERVATION_BACKUP_ROOT", backup_root)
    monkeypatch.setattr(collector, "_expected_root_uid", os.geteuid)
    monkeypatch.setattr(collector, "_disk_free_percent", lambda path: 55.5)

    disk_free, backup_age, device_digest, receipt_digest = (
        collector._collect_host_metrics("staging", completed + timedelta(hours=3))
    )
    assert disk_free == 55.5
    assert backup_age == 3
    assert collector.SHA256_RE.fullmatch(device_digest)
    assert receipt_digest == hashlib.sha256(receipt.read_bytes()).hexdigest()

    outside = tmp_path / "outside"
    outside.mkdir()
    config.write_text(
        f"SUPABASE_POSTGRES_DATA_DIR={outside}\n"
        f"BACKUP_STATE_DIR={backup_state}\n",
        encoding="utf-8",
    )
    with pytest.raises(collector.CollectionError, match="fixed deployment root"):
        collector._collect_host_metrics("staging", completed + timedelta(hours=3))


def test_observation_rejects_prefill_and_certificate_mismatch_before_publishing(
    tmp_path, monkeypatch
):
    root = tmp_path / "evidence"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    _collect_probe(monkeypatch, root, environment="staging", at=now)
    environment = _observation_environment(tmp_path)
    prefilled = root / "staging-observations.jsonl"
    prefilled.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        collector, "_perform_https_request", lambda *args: pytest.fail("network reached")
    )
    with pytest.raises(collector.CollectionError, match="cannot be resumed"):
        collector.collect_observation(
            evidence_root=root,
        environment="staging",
        origin_env="STAGING_ORIGIN",
        health_path="/health",
        release_commit=COMMIT,
            candidate_run_id=RUN_ID,
            portal_image_digest=IMAGE_DIGEST,
            http_timeout_seconds=15,
            environ=environment,
        )
    prefilled.unlink()
    _install_observation_measurements(
        monkeypatch,
        environment="staging",
        start=now,
        certificate=STAGING_CERT,
        wrong_certificate=True,
    )
    with pytest.raises(collector.CollectionError, match="certificate differs"):
        collector.collect_observation(
            evidence_root=root,
            environment="staging",
            origin_env="STAGING_ORIGIN",
            health_path="/health",
            release_commit=COMMIT,
            candidate_run_id=RUN_ID,
            portal_image_digest=IMAGE_DIGEST,
            http_timeout_seconds=15,
            environ=environment,
        )
    assert not prefilled.exists()


def test_fixed_command_timeout_and_environment_are_bounded(tmp_path):
    argv = [str(Path(sys.executable).resolve()), "-c", "import time; time.sleep(2)"]
    with pytest.raises(collector.CollectionError, match="timed out"):
        collector.run_command(argv, timeout_seconds=0.05)


def test_fixed_command_does_not_inherit_unrelated_parent_secrets(monkeypatch):
    monkeypatch.setenv("TEST_AUTH_TOKEN", "must-not-reach-child")
    measurement = collector.run_command(
        [
            str(Path(sys.executable).resolve()),
            "-c",
            "import os; print(os.environ.get('TEST_AUTH_TOKEN', 'missing'))",
        ],
        timeout_seconds=5,
    )
    assert measurement.exit_code == 0
    assert measurement.stdout.strip() == b"missing"


def test_fixed_command_kills_runaway_output_before_completion(monkeypatch):
    monkeypatch.setattr(collector, "MAX_COMMAND_OUTPUT_BYTES", 128)
    with pytest.raises(collector.CollectionError, match="output exceeded"):
        collector.run_command(
            [
                str(Path(sys.executable).resolve()),
                "-c",
                "import sys,time; sys.stdout.write('x'*8192); sys.stdout.flush(); time.sleep(2)",
            ],
            timeout_seconds=5,
        )


def test_backup_restore_api_has_no_operator_supplied_command_surface():
    parameters = inspect.signature(collector.collect_backup_restore).parameters
    assert "step_command_envs" not in parameters
    assert "production_config_path_env" not in parameters
    assert not any("command_env" in name for name in parameters)
    observation_parameters = inspect.signature(collector.collect_observation).parameters
    assert "disk_path_env" not in observation_parameters
    assert "backup_path_env" not in observation_parameters


def test_public_endpoint_resolution_rejects_any_private_answer(monkeypatch):
    monkeypatch.setattr(
        collector.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (
                collector.socket.AF_INET,
                collector.socket.SOCK_STREAM,
                collector.socket.IPPROTO_TCP,
                "",
                ("127.0.0.1", 443),
            )
        ],
    )
    with pytest.raises(collector.CollectionError, match="non-public"):
        collector._resolve_public_endpoint("staging.example.test", 443)


def test_public_endpoint_resolution_is_inside_the_total_deadline(monkeypatch):
    def blocked_resolution(*args, **kwargs):
        collector.time.sleep(0.05)
        return []

    monkeypatch.setattr(collector.socket, "getaddrinfo", blocked_resolution)
    with pytest.raises(collector.CollectionError, match="DNS exceeded"):
        collector._resolve_public_endpoint("staging.example.test", 443, 0.01)


def test_http_and_tls_are_measured_on_one_direct_socket_without_proxy(monkeypatch):
    events = []

    class RawSocket:
        def settimeout(self, timeout):
            events.append(("timeout", timeout))

        def connect(self, endpoint):
            events.append(("connect", endpoint))

        def close(self):
            events.append(("raw-close",))

    class TlsSocket:
        def getpeername(self):
            return ("8.8.8.8", 443)

        def getpeercert(self, binary_form=False):
            if binary_form:
                return b"certificate bytes"
            return {
                "notBefore": "Jan  1 00:00:00 2020 GMT",
                "notAfter": "Jan  1 00:00:00 2035 GMT",
            }

        def version(self):
            return "TLSv1.3"

        def cipher(self):
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        def close(self):
            events.append(("tls-close",))

    tls_socket = TlsSocket()

    class Context:
        def wrap_socket(self, raw, server_hostname):
            events.append(("wrap", raw, server_hostname))
            return tls_socket

    class Response:
        status = 302

        def read(self, maximum):
            return b"redirect not followed"

    class Connection:
        def __init__(self, host, port, timeout, context):
            self.sock = None
            events.append(("connection", host, port))

        def request(self, method, target, body, headers):
            assert self.sock is tls_socket
            events.append(("request", method, target))

        def getresponse(self):
            return Response()

        def close(self):
            assert self.sock is tls_socket
            self.sock.close()

    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:8080")
    monkeypatch.setattr(
        collector,
        "_resolve_public_endpoint",
        lambda host, port, timeout=30: (2, ("8.8.8.8", 443)),
    )
    monkeypatch.setattr(collector.socket, "socket", lambda *args: RawSocket())
    monkeypatch.setattr(collector.ssl, "create_default_context", lambda: Context())
    monkeypatch.setattr(collector.http.client, "HTTPSConnection", Connection)
    tls, http = collector._perform_https_request(
        "GET", "https://staging.example.test/health", {}, None, 5
    )
    assert tls.peer_certificate_sha256 == hashlib.sha256(b"certificate bytes").hexdigest()
    assert http.status_code == 302
    assert [event[0] for event in events].count("connect") == 1
    assert [event[0] for event in events].count("request") == 1
    assert ("request", "GET", "/health") in events


def test_https_request_enforces_one_total_wall_clock_deadline(monkeypatch):
    class RawSocket:
        def settimeout(self, timeout):
            pass

        def connect(self, endpoint):
            pass

        def close(self):
            pass

    class TlsSocket:
        def getpeername(self):
            return ("8.8.8.8", 443)

        def close(self):
            pass

    tls_socket = TlsSocket()

    class Context:
        def wrap_socket(self, raw, server_hostname):
            return tls_socket

    class Response:
        status = 200

        def read(self, maximum):
            collector.time.sleep(0.05)
            return b"late"

    class Connection:
        def __init__(self, *args, **kwargs):
            self.sock = None

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return Response()

        def close(self):
            pass

    now = datetime.now(timezone.utc).replace(microsecond=0)
    monkeypatch.setattr(
        collector,
        "_resolve_public_endpoint",
        lambda host, port, timeout=30: (2, ("8.8.8.8", 443)),
    )
    monkeypatch.setattr(collector.socket, "socket", lambda *args: RawSocket())
    monkeypatch.setattr(collector.ssl, "create_default_context", lambda: Context())
    monkeypatch.setattr(collector.http.client, "HTTPSConnection", Connection)
    monkeypatch.setattr(
        collector,
        "_tls_measurement",
        lambda socket, hostname: _tls(STAGING_ORIGIN, STAGING_CERT, now),
    )
    with pytest.raises(collector.CollectionError, match="total deadline"):
        collector._perform_https_request(
            "GET", "https://staging.example.test/health", {}, None, 0.01
        )


def test_https_request_total_deadline_includes_tls_context_loading(monkeypatch):
    monkeypatch.setattr(
        collector,
        "_resolve_public_endpoint",
        lambda host, port, timeout=30: (2, ("8.8.8.8", 443)),
    )

    class Context:
        pass

    def slow_context():
        collector.time.sleep(0.05)
        return Context()

    monkeypatch.setattr(collector.ssl, "create_default_context", slow_context)
    monkeypatch.setattr(
        collector.socket,
        "socket",
        lambda *args: pytest.fail("expired TLS context budget reached the socket"),
    )
    with pytest.raises(collector.CollectionError, match="total deadline"):
        collector._perform_https_request(
            "GET", "https://staging.example.test/health", {}, None, 0.01
        )


def _backup_environment(tmp_path: Path) -> dict[str, str]:
    source = tmp_path / "source-backup.age"
    identity = tmp_path / "age-identity.txt"
    checksum = tmp_path / "source-backup.age.sha256"
    config = tmp_path / "production.env"
    source.write_bytes(b"real encrypted backup bytes")
    identity.write_text("private identity material", encoding="utf-8")
    checksum.write_text(
        hashlib.sha256(source.read_bytes()).hexdigest() + "  source-backup.age\n",
        encoding="ascii",
    )
    config.write_text("PRIVATE_CONFIG=not-for-evidence\n", encoding="utf-8")
    old = datetime.now(timezone.utc).timestamp() - 3 * 3600
    os.utime(source, (old, old))
    environment = _env()
    environment.update(
        {
            "RESTORE_RUN_ID": "opaque-restore-run-2026-08-28",
            "SOURCE_BACKUP_PATH": str(source.resolve()),
            "AGE_IDENTITY_PATH": str(identity.resolve()),
            "CHECKSUM_PATH": str(checksum.resolve()),
            "PRODUCTION_CONFIG_PATH": str(config.resolve()),
        }
    )
    return environment


def _install_recovery_harness(
    monkeypatch,
    tmp_path: Path,
    *,
    exit_code: int = 0,
    receipt_line: bytes = (
        b'{"schema":1,"measurement_kind":"database_count",'
        b'"records_expected":2,"records_restored":2}'
    ),
):
    harness = tmp_path / "restore-dry-run.sh"
    harness.write_text("fixed harness", encoding="utf-8")
    harness_hash = hashlib.sha256(harness.read_bytes()).hexdigest()
    monkeypatch.setattr(
        collector,
        "_trusted_recovery_harness",
        lambda release_commit: (harness.read_bytes(), harness_hash, tmp_path),
    )
    monkeypatch.setattr(
        collector,
        "_fixed_production_config",
        lambda: tmp_path / "production.env",
    )
    captured = {}

    def run(argv, *, timeout_seconds, child_environment=None):
        captured["argv"] = list(argv)
        captured["materialized_harness"] = Path(argv[0]).read_bytes()
        captured["environment"] = dict(child_environment or {})
        now = collector._utc_now()
        stdout = (
            b"\n".join(collector.RECOVERY_SUCCESS_MARKERS)
            + b"\n"
            + receipt_line
            + b"\n"
        )
        return collector.CommandMeasurement(
            exit_code=exit_code,
            stdout=stdout,
            stderr=b"",
            started_at_utc=_utc(now),
            completed_at_utc=_utc(now),
        )

    monkeypatch.setattr(collector, "run_command", run)
    return harness, captured


def test_materialized_recovery_harness_cannot_be_swapped_through_source_path(
    tmp_path,
):
    source = tmp_path / "restore-dry-run.sh"
    source.write_bytes(b"#!/bin/sh\nprintf trusted\n")
    verified_blob = source.read_bytes()
    with collector._materialized_recovery_harness(verified_blob) as executable:
        source.write_bytes(b"#!/bin/sh\nprintf attacker\n")
        assert executable != source
        assert executable.read_bytes() == verified_blob
        if os.name != "nt":
            assert executable.stat().st_mode & 0o222 == 0
            assert executable.parent.stat().st_mode & 0o222 == 0


def test_trusted_recovery_harness_rejects_dirty_collector_checkout(
    tmp_path, monkeypatch
):
    repository = tmp_path / "release"
    script = repository / collector.RECOVERY_SCRIPT_RELATIVE
    script.parent.mkdir(parents=True)
    script.write_bytes(b"fixed harness")
    git_directory = repository / ".git"
    git_directory.mkdir()
    git_executable = tmp_path / "git"
    git_executable.write_bytes(b"git")
    monkeypatch.setattr(
        collector,
        "__file__",
        str(repository / "scripts" / "collect_deployment_evidence.py"),
    )
    monkeypatch.setattr(
        collector,
        "_require_root_controlled_path",
        lambda path, label: Path(path).resolve(),
    )
    monkeypatch.setattr(collector.shutil, "which", lambda *args, **kwargs: str(git_executable))

    def measured(stdout=b"", stderr=b"", exit_code=0):
        now = collector._utc_now()
        return collector.CommandMeasurement(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            started_at_utc=_utc(now),
            completed_at_utc=_utc(now),
        )

    def run(argv, *, timeout_seconds, child_environment=None):
        del timeout_seconds, child_environment
        if "--absolute-git-dir" in argv:
            return measured(str(git_directory.resolve()).encode() + b"\n")
        if "HEAD^{commit}" in argv:
            return measured(COMMIT.encode() + b"\n")
        if "status" in argv:
            return measured(b" M deploy/mvp/bin/restore-dry-run.sh\n")
        pytest.fail(f"dirty checkout unexpectedly reached command: {argv}")

    monkeypatch.setattr(collector, "run_command", run)
    with pytest.raises(collector.CollectionError, match="checkout is not clean"):
        collector._trusted_recovery_harness(COMMIT)


def test_backup_restore_uses_only_git_bound_harness_and_real_file_hashes(
    tmp_path, monkeypatch
):
    root = tmp_path / "evidence"
    environment = _backup_environment(tmp_path)
    harness, captured = _install_recovery_harness(monkeypatch, tmp_path)
    output = collector.collect_backup_restore(
        evidence_root=root,
        origin_env="STAGING_ORIGIN",
        run_id_env="RESTORE_RUN_ID",
        source_backup_path_env="SOURCE_BACKUP_PATH",
        age_identity_path_env="AGE_IDENTITY_PATH",
        checksum_path_env="CHECKSUM_PATH",
        release_commit=COMMIT,
        candidate_run_id=RUN_ID,
        portal_image_digest=IMAGE_DIGEST,
        command_timeout_seconds=5,
        environ=environment,
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["records_expected"] == payload["records_restored"] == 2
    assert payload["source_backup_sha256"] == hashlib.sha256(
        Path(environment["SOURCE_BACKUP_PATH"]).read_bytes()
    ).hexdigest()
    assert captured["argv"][0] != str(harness)
    assert Path(captured["argv"][0]).name == "restore-dry-run.sh"
    assert captured["materialized_harness"] == harness.read_bytes()
    assert captured["argv"][1:] == [
        environment["SOURCE_BACKUP_PATH"],
        environment["AGE_IDENTITY_PATH"],
        environment["CHECKSUM_PATH"],
    ]
    assert captured["environment"] == {
        "MVP_PRODUCTION_ENV": environment["PRODUCTION_CONFIG_PATH"],
        "DEFENSE_TRACKER_RELEASE_ROOT": str(tmp_path),
        "DEFENSE_TRACKER_RELEASE_SHA": COMMIT,
    }
    rendered = output.read_text(encoding="utf-8")
    assert "opaque-restore-run" not in rendered
    assert "private identity material" not in rendered
    assert "PRIVATE_CONFIG" not in rendered


def test_backup_restore_failed_fixed_harness_fails_without_evidence(
    tmp_path, monkeypatch
):
    root = tmp_path / "evidence"
    environment = _backup_environment(tmp_path)
    _install_recovery_harness(monkeypatch, tmp_path, exit_code=3)
    with pytest.raises(collector.CollectionError, match="fixed recovery harness failed"):
        collector.collect_backup_restore(
            evidence_root=root,
            origin_env="STAGING_ORIGIN",
            run_id_env="RESTORE_RUN_ID",
            source_backup_path_env="SOURCE_BACKUP_PATH",
            age_identity_path_env="AGE_IDENTITY_PATH",
            checksum_path_env="CHECKSUM_PATH",
            release_commit=COMMIT,
            candidate_run_id=RUN_ID,
            portal_image_digest=IMAGE_DIGEST,
            command_timeout_seconds=5,
            environ=environment,
        )
    assert not (root / "backup-restore.json").exists()


def test_backup_restore_rejects_missing_or_unequal_real_harness_receipt(
    tmp_path, monkeypatch
):
    root = tmp_path / "evidence"
    environment = _backup_environment(tmp_path)
    _install_recovery_harness(
        monkeypatch,
        tmp_path,
        receipt_line=(
            b'{"schema":1,"measurement_kind":"database_count",'
            b'"records_expected":2,"records_restored":1}'
        ),
    )
    with pytest.raises(collector.CollectionError, match="equal counts"):
        collector.collect_backup_restore(
            evidence_root=root,
            origin_env="STAGING_ORIGIN",
            run_id_env="RESTORE_RUN_ID",
            source_backup_path_env="SOURCE_BACKUP_PATH",
            age_identity_path_env="AGE_IDENTITY_PATH",
            checksum_path_env="CHECKSUM_PATH",
            release_commit=COMMIT,
            candidate_run_id=RUN_ID,
            portal_image_digest=IMAGE_DIGEST,
            command_timeout_seconds=5,
            environ=environment,
        )
    assert not (root / "backup-restore.json").exists()


def test_backup_restore_rejects_tampered_checksum_before_running_harness(
    tmp_path, monkeypatch
):
    root = tmp_path / "evidence"
    environment = _backup_environment(tmp_path)
    Path(environment["CHECKSUM_PATH"]).write_text("0" * 64 + "  fake.age\n")
    monkeypatch.setattr(
        collector,
        "_trusted_recovery_harness",
        lambda commit: pytest.fail("tampered checksum reached the harness"),
    )
    with pytest.raises(collector.CollectionError, match="checksum differs"):
        collector.collect_backup_restore(
            evidence_root=root,
            origin_env="STAGING_ORIGIN",
            run_id_env="RESTORE_RUN_ID",
            source_backup_path_env="SOURCE_BACKUP_PATH",
            age_identity_path_env="AGE_IDENTITY_PATH",
            checksum_path_env="CHECKSUM_PATH",
            release_commit=COMMIT,
            candidate_run_id=RUN_ID,
            portal_image_digest=IMAGE_DIGEST,
            command_timeout_seconds=5,
            environ=environment,
        )


def _write_observations_for_manifest(
    monkeypatch,
    root: Path,
    *,
    environment: str,
    start: datetime,
    count: int,
    spacing: timedelta,
):
    cert = STAGING_CERT if environment == "staging" else PRODUCTION_CERT
    policy = collector.OBSERVATION_POLICIES[environment]
    assert count == policy["samples"]
    assert spacing.total_seconds() == policy["interval_seconds"]
    command_environment = _observation_environment(root.parent)
    _install_observation_measurements(
        monkeypatch,
        environment=environment,
        start=start,
        certificate=cert,
    )
    collector.collect_observation(
        evidence_root=root,
        environment=environment,
        origin_env=f"{environment.upper()}_ORIGIN",
        health_path="/health",
        release_commit=COMMIT,
        candidate_run_id=RUN_ID,
        portal_image_digest=IMAGE_DIGEST,
        http_timeout_seconds=15,
        environ=command_environment,
    )


def test_manifest_schema2_closes_local_six_file_set_and_is_sealable(
    tmp_path, monkeypatch
):
    root = tmp_path / "evidence"
    generated = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=1)
    _collect_probe(
        monkeypatch,
        root,
        environment="staging",
        at=generated - timedelta(hours=2),
    )
    _collect_probe(
        monkeypatch,
        root,
        environment="production",
        at=generated - timedelta(minutes=5),
    )
    _write_observations_for_manifest(
        monkeypatch,
        root,
        environment="staging",
        start=generated - timedelta(hours=25),
        count=26,
        spacing=timedelta(hours=1),
    )
    _write_observations_for_manifest(
        monkeypatch,
        root,
        environment="production",
        start=generated - timedelta(minutes=100),
        count=100,
        spacing=timedelta(seconds=60),
    )
    backup_environment = _backup_environment(tmp_path)
    _install_recovery_harness(monkeypatch, tmp_path)
    monkeypatch.setattr(
        collector, "_utc_now", lambda: generated - timedelta(minutes=30)
    )
    collector.collect_backup_restore(
        evidence_root=root,
        origin_env="STAGING_ORIGIN",
        run_id_env="RESTORE_RUN_ID",
        source_backup_path_env="SOURCE_BACKUP_PATH",
        age_identity_path_env="AGE_IDENTITY_PATH",
        checksum_path_env="CHECKSUM_PATH",
        release_commit=COMMIT,
        candidate_run_id=RUN_ID,
        portal_image_digest=IMAGE_DIGEST,
        command_timeout_seconds=5,
        environ=backup_environment,
    )
    monkeypatch.setattr(collector, "_utc_now", lambda: generated)
    manifest_path = collector.write_schema2_manifest(
        evidence_root=root,
        staging_origin_env="STAGING_ORIGIN",
        production_origin_env="PRODUCTION_ORIGIN",
        release_commit=COMMIT,
        candidate_run_id=RUN_ID,
        portal_image_digest=IMAGE_DIGEST,
        environ=_env(),
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["schema"] == 2
    assert {path.name for path in root.iterdir()} == {
        "staging-probe.json",
        "production-probe.json",
        "staging-observations.jsonl",
        "production-observations.jsonl",
        "backup-restore.json",
        "deployment-evidence.json",
    }
    assert {row["path"] for row in manifest["artifacts"]} == {
        "staging-probe.json",
        "production-probe.json",
        "staging-observations.jsonl",
        "production-observations.jsonl",
        "backup-restore.json",
    }
    tampered = root / "staging-probe.json"
    original = tampered.read_bytes()
    tampered.write_bytes(original + b" ")
    with pytest.raises(collector.CollectionError, match="authentication failed"):
        collector._verify_collector_state(
            evidence_root=root,
            release_commit=COMMIT,
            candidate_run_id=RUN_ID,
            portal_image_digest=IMAGE_DIGEST,
        )
    tampered.write_bytes(original)

    gates = []
    for environment in ("staging", "production"):
        target = hashlib.sha256(f"{environment} target".encode()).hexdigest()
        for gate in sorted(
            name for name in ORIGIN_ISOLATION_GATES if name.startswith(environment)
        ):
            gates.append(
                {
                    "gate": gate,
                    "status": "pass",
                    "target_hmac_sha256": target,
                    "observed_at_utc": _utc(
                        datetime.now(timezone.utc).replace(microsecond=0)
                    ),
                }
            )
    (root / "origin-isolation.json").write_text(
        json.dumps({"schema": 1, "gates": gates}), encoding="utf-8"
    )
    receipt = manifest["collector_receipt"]
    with pytest.raises(ValueError, match="protected environment"):
        seal_origin_isolation(
            root,
            expected_collector_key_id="deployment-collector-0000000000000000",
            expected_collector_public_key_sha256=receipt["public_key_sha256"],
        )
    seal_origin_isolation(
        root,
        expected_collector_key_id=receipt["key_id"],
        expected_collector_public_key_sha256=receipt["public_key_sha256"],
    )
    verify(
        root,
        expected_commit=COMMIT,
        expected_image_digest=IMAGE_DIGEST,
        expected_candidate_run_id=RUN_ID,
        expected_staging_origin=STAGING_ORIGIN,
        expected_production_origin=PRODUCTION_ORIGIN,
        expected_collector_key_id=receipt["key_id"],
        expected_collector_public_key_sha256=receipt["public_key_sha256"],
    )


def test_manifest_refuses_missing_extra_or_symlink_payload(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "unexpected.txt").write_text("not evidence", encoding="utf-8")
    with pytest.raises(collector.CollectionError, match="exact five payload files"):
        collector.write_schema2_manifest(
            evidence_root=root,
            staging_origin_env="STAGING_ORIGIN",
            production_origin_env="PRODUCTION_ORIGIN",
            release_commit=COMMIT,
            candidate_run_id=RUN_ID,
            portal_image_digest=IMAGE_DIGEST,
            environ=_env(),
        )


def test_manifest_rejects_manually_prefilled_complete_payload_set(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    for name in collector.CORE_PAYLOAD_FILES:
        (root / name).write_text("{}\n", encoding="utf-8")
    with pytest.raises(collector.CollectionError, match="collector state is missing"):
        collector.write_schema2_manifest(
            evidence_root=root,
            staging_origin_env="STAGING_ORIGIN",
            production_origin_env="PRODUCTION_ORIGIN",
            release_commit=COMMIT,
            candidate_run_id=RUN_ID,
            portal_image_digest=IMAGE_DIGEST,
            environ=_env(),
        )


@pytest.mark.parametrize("stale_component", ["probe", "observation"])
def test_manifest_checks_probe_and_observation_freshness_independently(
    tmp_path, monkeypatch, stale_component
):
    root = tmp_path / "evidence"
    root.mkdir()
    for name in collector.CORE_PAYLOAD_FILES:
        (root / name).write_bytes(b"x\n")
    generated = datetime.now(timezone.utc).replace(microsecond=0)
    stale = generated - timedelta(hours=7)
    fresh = generated - timedelta(minutes=5)

    def probe(*args, environment, **kwargs):
        end = stale if environment == "production" and stale_component == "probe" else fresh
        certificate = PRODUCTION_CERT if environment == "production" else STAGING_CERT
        return end, end, certificate

    def observations(*args, environment, **kwargs):
        end = (
            stale
            if environment == "production" and stale_component == "observation"
            else fresh
        )
        return end - timedelta(minutes=1), end

    monkeypatch.setattr(collector, "_validate_probe", probe)
    monkeypatch.setattr(collector, "_validate_observations", observations)
    monkeypatch.setattr(collector, "_validate_backup_restore", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector, "_verify_collector_state", lambda **kwargs: None)
    monkeypatch.setattr(collector, "_utc_now", lambda: generated)
    with pytest.raises(collector.CollectionError, match="schema validation"):
        collector.write_schema2_manifest(
            evidence_root=root,
            staging_origin_env="STAGING_ORIGIN",
            production_origin_env="PRODUCTION_ORIGIN",
            release_commit=COMMIT,
            candidate_run_id=RUN_ID,
            portal_image_digest=IMAGE_DIGEST,
            environ=_env(),
        )
    assert not (root / "deployment-evidence.json").exists()


def test_atomic_no_clobber_preserves_concurrent_writer(tmp_path, monkeypatch):
    output = tmp_path / "evidence.json"
    original_link = collector.os.link

    def racing_link(source, destination):
        Path(destination).write_bytes(b"concurrent\n")
        return original_link(source, destination)

    monkeypatch.setattr(collector.os, "link", racing_link)
    with pytest.raises(collector.CollectionError, match="appeared concurrently"):
        collector._atomic_write(output, b"collector\n", replace_existing=False)
    assert output.read_bytes() == b"concurrent\n"
