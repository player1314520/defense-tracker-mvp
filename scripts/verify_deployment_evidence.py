# -*- coding: utf-8 -*-
"""Validate immutable, redaction-safe deployment evidence before release."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
DNS_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:+/-]{1,128}$")

LEGACY_SCREENSHOTS = {
    "staging-desktop-redacted.png",
    "production-desktop-redacted.png",
    "production-mobile-redacted.png",
}
CORE_PAYLOAD_FILES = {
    "staging-probe.json",
    "production-probe.json",
    "staging-observations.jsonl",
    "production-observations.jsonl",
    "backup-restore.json",
}
ORIGIN_ISOLATION_FILE = "origin-isolation.json"
PAYLOAD_FILES = CORE_PAYLOAD_FILES | {ORIGIN_ISOLATION_FILE}
ALL_FILES = PAYLOAD_FILES | {"deployment-evidence.json"}

ORIGIN_ISOLATION_GATES = {
    "staging_public_edge_https_reachable",
    "staging_origin_tcp_80_blocked",
    "staging_origin_tcp_443_blocked",
    "staging_origin_sni_443_blocked",
    "production_public_edge_https_reachable",
    "production_origin_tcp_80_blocked",
    "production_origin_tcp_443_blocked",
    "production_origin_sni_443_blocked",
}

STAGING_CHECKS = {
    "release_metadata": 200,
    "application_invite_flow": 200,
    "two_users_two_devices": 200,
    "desktop_pkce": 200,
    "ciphertext_sync": 200,
    "approval_and_withdrawal": 200,
    "member_and_device_revocation": 200,
    "cross_role_rls_negative": 403,
    "old_jwt_revocation": 401,
    "duplicate_request_rejection": 409,
    "member_101_rejected": 409,
    "event_1001_rejected": 429,
    "concurrency_20": 200,
    "portal_rollback": 200,
}
PRODUCTION_CHECKS = {
    "release_metadata": 200,
    "application_closed_during_smoke": 503,
    "owner_bootstrap": 200,
    "two_user_flow": 200,
    "desktop_pkce": 200,
    "desktop_browser_smoke": 200,
    "mobile_browser_smoke": 200,
    "monitoring_smoke": 200,
    "application_opened_after_acceptance": 202,
}


def _require_object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _require_exact_keys(value: dict[str, object], keys: set[str], label: str) -> None:
    actual = set(value)
    if actual != keys:
        raise ValueError(
            f"{label} fields differ: missing={sorted(keys - actual)}, extra={sorted(actual - keys)}"
        )


def _parse_utc(value: object, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be canonical UTC seconds")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    if len(set(value)) < 8:
        raise ValueError(f"{label} is an obvious placeholder")
    return value


def _require_positive_int(value: object, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= maximum:
        raise ValueError(f"{label} must be a bounded positive integer")
    return value


def _validate_origin(value: object, label: str) -> str:
    if not isinstance(value, str) or value != value.lower():
        raise ValueError(f"{label} must be a lowercase HTTPS origin")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{label} must be a valid HTTPS origin") from exc
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or port not in (None, 443)
        or parsed.hostname is None
        or DNS_RE.fullmatch(parsed.hostname) is None
    ):
        raise ValueError(f"{label} must be a public HTTPS DNS origin without a path")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        raise ValueError(f"{label} must not use an IP literal")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _strict_json_loads(payload: str, label: str) -> object:
    def reject_constant(value: str) -> object:
        raise ValueError(f"{label} contains a non-finite JSON number: {value}")

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains a duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(
        payload,
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_constant,
    )


def _load_json(path: Path, label: str) -> dict[str, object]:
    try:
        parsed = _strict_json_loads(path.read_text(encoding="utf-8"), label)
        return _require_object(parsed, label)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc


def _load_jsonl(path: Path, label: str) -> list[dict[str, object]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8") from exc
    if not lines or any(not line.strip() for line in lines):
        raise ValueError(f"{label} must contain nonblank JSON lines")
    records: list[dict[str, object]] = []
    for index, line in enumerate(lines, start=1):
        try:
            records.append(
                _require_object(
                    _strict_json_loads(line, f"{label} line {index}"),
                    f"{label} line {index}",
                )
            )
        except json.JSONDecodeError as exc:
            raise ValueError(f"{label} line {index} is invalid JSON") from exc
    return records


def _artifact_record(path: Path) -> dict[str, object]:
    return {
        "path": path.name,
        "sha256": _sha256(path),
        "size_bytes": path.stat().st_size,
    }


def seal_origin_isolation(root: Path) -> None:
    """Bind the current-run external gate to a legacy safe evidence manifest.

    Legacy local evidence may have listed three screenshots.  They are never
    copied into ``root`` and are deliberately dropped here.  Every retained
    machine-readable payload must still match the digest in the source
    manifest before schema 3 is written atomically.
    """

    root = root.resolve()
    expected_unsealed = CORE_PAYLOAD_FILES | {
        ORIGIN_ISOLATION_FILE,
        "deployment-evidence.json",
    }
    children = list(root.iterdir()) if root.is_dir() else []
    actual = {path.name for path in children if path.is_file() and not path.is_symlink()}
    if actual != expected_unsealed or any(path.is_symlink() or not path.is_file() for path in children):
        raise ValueError("Unsealed deployment evidence contains undeclared files")
    if any(path.suffix.lower() == ".png" for path in children):
        raise ValueError("PNG deployment evidence is forbidden in public artifacts")

    manifest_path = root / "deployment-evidence.json"
    manifest = _load_json(manifest_path, "deployment evidence manifest")
    _require_exact_keys(
        manifest,
        {
            "schema",
            "release_commit",
            "candidate_run_id",
            "portal_image_digest",
            "staging_origin",
            "production_origin",
            "generated_at_utc",
            "artifacts",
        },
        "deployment evidence manifest",
    )
    if manifest["schema"] != 2:
        raise ValueError("Only schema 2 local evidence can be sealed")
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list):
        raise ValueError("Deployment evidence artifact manifest is incomplete")
    source_records: dict[str, dict[str, object]] = {}
    allowed_source_files = CORE_PAYLOAD_FILES | LEGACY_SCREENSHOTS
    for raw_artifact in artifacts:
        artifact = _require_object(raw_artifact, "deployment evidence artifact")
        _require_exact_keys(artifact, {"path", "sha256", "size_bytes"}, "deployment evidence artifact")
        name = artifact["path"]
        if (
            not isinstance(name, str)
            or name not in allowed_source_files
            or name in source_records
        ):
            raise ValueError("Deployment evidence artifact path is unknown or duplicated")
        source_records[name] = artifact
    if set(source_records) not in (
        CORE_PAYLOAD_FILES,
        CORE_PAYLOAD_FILES | LEGACY_SCREENSHOTS,
    ):
        raise ValueError("Deployment evidence artifact manifest is incomplete")
    for name in CORE_PAYLOAD_FILES:
        path = root / name
        record = source_records[name]
        if (
            record["size_bytes"] != path.stat().st_size
            or record["sha256"] != _sha256(path)
        ):
            raise ValueError(f"Deployment evidence artifact changed before sealing: {name}")

    manifest["schema"] = 3
    manifest["artifacts"] = [
        _artifact_record(root / name) for name in sorted(PAYLOAD_FILES)
    ]
    temporary = manifest_path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    os.replace(temporary, manifest_path)


def _validate_origin_isolation(path: Path) -> None:
    label = "external origin isolation evidence"
    evidence = _load_json(path, label)
    _require_exact_keys(evidence, {"schema", "gates"}, label)
    if evidence["schema"] != 1:
        raise ValueError(f"{label} schema is unsupported")
    gates = evidence["gates"]
    if not isinstance(gates, list) or len(gates) != len(ORIGIN_ISOLATION_GATES):
        raise ValueError(f"{label} does not contain the exact required gates")
    now = datetime.now(timezone.utc)
    seen: set[str] = set()
    target_digests: dict[str, str] = {}
    for raw_gate in gates:
        gate = _require_object(raw_gate, f"{label} gate")
        _require_exact_keys(
            gate,
            {"gate", "status", "target_hmac_sha256", "observed_at_utc"},
            f"{label} gate",
        )
        name = gate["gate"]
        if not isinstance(name, str) or name not in ORIGIN_ISOLATION_GATES or name in seen:
            raise ValueError(f"{label} contains an unknown or duplicate gate")
        seen.add(name)
        if gate["status"] != "pass":
            raise ValueError(f"{label} gate did not pass: {name}")
        digest = _require_sha256(gate["target_hmac_sha256"], f"{label} target digest")
        environment = name.split("_", 1)[0]
        previous = target_digests.setdefault(environment, digest)
        if previous != digest:
            raise ValueError(f"{label} target digest changed within {environment}")
        observed = _parse_utc(gate["observed_at_utc"], f"{label} timestamp")
        if observed > now + timedelta(minutes=5) or now - observed > timedelta(minutes=30):
            raise ValueError(f"{label} is stale or in the future")
    if seen != ORIGIN_ISOLATION_GATES:
        raise ValueError(f"{label} does not contain the exact required gates")
    if target_digests.get("staging") == target_digests.get("production"):
        raise ValueError(f"{label} reused one protected target for both environments")


def _validate_bindings(
    record: dict[str, object],
    *,
    commit: str,
    candidate_run_id: int,
    image_digest: str,
    origin: str,
    label: str,
) -> None:
    if record.get("release_commit") != commit:
        raise ValueError(f"{label} release commit mismatch")
    if record.get("candidate_run_id") != candidate_run_id:
        raise ValueError(f"{label} candidate run mismatch")
    if record.get("portal_image_digest") != image_digest:
        raise ValueError(f"{label} image digest mismatch")
    if record.get("origin") != origin:
        raise ValueError(f"{label} origin mismatch")


def _validate_probe(
    path: Path,
    *,
    environment: str,
    commit: str,
    candidate_run_id: int,
    image_digest: str,
    origin: str,
    generated_at: datetime,
) -> tuple[datetime, datetime, str]:
    label = f"{environment} probe"
    probe = _load_json(path, label)
    _require_exact_keys(
        probe,
        {
            "schema",
            "environment",
            "release_commit",
            "candidate_run_id",
            "portal_image_digest",
            "origin",
            "started_at_utc",
            "completed_at_utc",
            "tls",
            "checks",
        },
        label,
    )
    if probe["schema"] != 2 or probe["environment"] != environment:
        raise ValueError(f"{label} schema or environment mismatch")
    _validate_bindings(
        probe,
        commit=commit,
        candidate_run_id=candidate_run_id,
        image_digest=image_digest,
        origin=origin,
        label=label,
    )
    started = _parse_utc(probe["started_at_utc"], f"{label} start")
    completed = _parse_utc(probe["completed_at_utc"], f"{label} completion")
    if completed < started or completed - started > timedelta(minutes=30) or completed > generated_at:
        raise ValueError(f"{label} time interval is invalid")

    tls = _require_object(probe["tls"], f"{label} TLS")
    _require_exact_keys(
        tls,
        {
            "server_name",
            "protocol",
            "cipher",
            "peer_certificate_sha256",
            "not_before_utc",
            "not_after_utc",
        },
        f"{label} TLS",
    )
    hostname = urlsplit(origin).hostname
    if tls["server_name"] != hostname or tls["protocol"] not in {"TLSv1.2", "TLSv1.3"}:
        raise ValueError(f"{label} TLS identity or protocol mismatch")
    if not isinstance(tls["cipher"], str) or SAFE_TOKEN_RE.fullmatch(tls["cipher"]) is None:
        raise ValueError(f"{label} TLS cipher is malformed")
    certificate_sha256 = _require_sha256(
        tls["peer_certificate_sha256"], f"{label} TLS certificate"
    )
    not_before = _parse_utc(tls["not_before_utc"], f"{label} TLS not-before")
    not_after = _parse_utc(tls["not_after_utc"], f"{label} TLS not-after")
    if not (not_before <= started <= completed <= not_after):
        raise ValueError(f"{label} was not collected during certificate validity")

    expected_checks = STAGING_CHECKS if environment == "staging" else PRODUCTION_CHECKS
    checks = probe["checks"]
    if not isinstance(checks, list) or len(checks) != len(expected_checks):
        raise ValueError(f"{label} does not contain the exact required checks")
    seen: set[str] = set()
    for index, raw_check in enumerate(checks):
        check = _require_object(raw_check, f"{label} check {index}")
        _require_exact_keys(
            check,
            {
                "name",
                "method",
                "url",
                "status_code",
                "elapsed_ms",
                "observed_at_utc",
                "response_sha256",
            },
            f"{label} check {index}",
        )
        name = check["name"]
        if not isinstance(name, str) or name not in expected_checks or name in seen:
            raise ValueError(f"{label} has an unknown or duplicate check")
        seen.add(name)
        if check["method"] not in {"GET", "POST", "PATCH", "DELETE"}:
            raise ValueError(f"{label} check method is unsupported: {name}")
        url = check["url"]
        if not isinstance(url, str):
            raise ValueError(f"{label} check URL is malformed: {name}")
        parsed_url = urlsplit(url)
        if (
            f"{parsed_url.scheme}://{parsed_url.netloc}" != origin
            or not parsed_url.path.startswith("/")
            or parsed_url.username is not None
            or parsed_url.password is not None
            or parsed_url.query
            or parsed_url.fragment
        ):
            raise ValueError(f"{label} check escaped its expected origin: {name}")
        if check["status_code"] != expected_checks[name]:
            raise ValueError(f"{label} check returned the wrong status: {name}")
        _require_positive_int(check["elapsed_ms"], f"{label} elapsed time", 120_000)
        observed = _parse_utc(check["observed_at_utc"], f"{label} check time")
        if not (started <= observed <= completed):
            raise ValueError(f"{label} check time is outside the probe: {name}")
        _require_sha256(check["response_sha256"], f"{label} response digest")
    if seen != set(expected_checks):
        raise ValueError(f"{label} does not contain the exact required checks")
    return started, completed, certificate_sha256


def _validate_observations(
    path: Path,
    *,
    environment: str,
    commit: str,
    candidate_run_id: int,
    image_digest: str,
    origin: str,
    certificate_sha256: str,
    generated_at: datetime,
) -> tuple[datetime, datetime]:
    label = f"{environment} observations"
    records = _load_jsonl(path, label)
    minimum_records = 25 if environment == "staging" else 100
    if len(records) < minimum_records:
        raise ValueError(f"{label} has fewer than {minimum_records} samples")
    times: list[datetime] = []
    latencies: list[int] = []
    server_errors = 0
    for index, record in enumerate(records):
        _require_exact_keys(
            record,
            {
                "schema",
                "environment",
                "release_commit",
                "candidate_run_id",
                "portal_image_digest",
                "origin",
                "observed_at_utc",
                "tls_certificate_sha256",
                "http_status",
                "elapsed_ms",
                "disk_free_percent",
                "backup_age_hours",
                "response_sha256",
            },
            f"{label} line {index + 1}",
        )
        if record["schema"] != 2 or record["environment"] != environment:
            raise ValueError(f"{label} schema or environment mismatch")
        _validate_bindings(
            record,
            commit=commit,
            candidate_run_id=candidate_run_id,
            image_digest=image_digest,
            origin=origin,
            label=label,
        )
        if record["tls_certificate_sha256"] != certificate_sha256:
            raise ValueError(f"{label} TLS certificate does not match the probe")
        observed = _parse_utc(record["observed_at_utc"], f"{label} sample time")
        if times and observed <= times[-1]:
            raise ValueError(f"{label} timestamps must increase strictly")
        times.append(observed)
        status = _require_positive_int(record["http_status"], f"{label} HTTP status", 599)
        if status < 100:
            raise ValueError(f"{label} HTTP status is invalid")
        if status >= 500:
            server_errors += 1
        latency = _require_positive_int(record["elapsed_ms"], f"{label} latency", 120_000)
        latencies.append(latency)
        disk_free = record["disk_free_percent"]
        backup_age = record["backup_age_hours"]
        if isinstance(disk_free, bool) or not isinstance(disk_free, (int, float)) or not 20 < disk_free <= 100:
            raise ValueError(f"{label} free disk is not above 20 percent")
        if isinstance(backup_age, bool) or not isinstance(backup_age, (int, float)) or not 0 <= backup_age < 26:
            raise ValueError(f"{label} backup is not newer than 26 hours")
        _require_sha256(record["response_sha256"], f"{label} response digest")
    if times[-1] > generated_at:
        raise ValueError(f"{label} contains future samples")
    if environment == "staging":
        if times[-1] - times[0] < timedelta(hours=24):
            raise ValueError("Staging observation interval is shorter than 24 hours")
        if any(later - earlier > timedelta(minutes=90) for earlier, later in zip(times, times[1:])):
            raise ValueError("Staging observation interval contains a gap longer than 90 minutes")
    if server_errors / len(records) >= 0.01:
        raise ValueError(f"{label} 5xx rate is not below 1 percent")
    p95 = sorted(latencies)[math.ceil(len(latencies) * 0.95) - 1]
    if p95 >= 2_000:
        raise ValueError(f"{label} P95 is not below 2 seconds")
    return times[0], times[-1]


def _validate_backup_restore(
    path: Path,
    *,
    commit: str,
    candidate_run_id: int,
    image_digest: str,
    origin: str,
    generated_at: datetime,
) -> None:
    label = "backup/restore evidence"
    evidence = _load_json(path, label)
    _require_exact_keys(
        evidence,
        {
            "schema",
            "release_commit",
            "candidate_run_id",
            "portal_image_digest",
            "origin",
            "run_id_sha256",
            "started_at_utc",
            "completed_at_utc",
            "backup_created_at_utc",
            "source_backup_sha256",
            "restored_snapshot_sha256",
            "integrity_query_sha256",
            "integrity_result_sha256",
            "records_expected",
            "records_restored",
            "steps",
        },
        label,
    )
    if evidence["schema"] != 2:
        raise ValueError(f"{label} schema is unsupported")
    _validate_bindings(
        evidence,
        commit=commit,
        candidate_run_id=candidate_run_id,
        image_digest=image_digest,
        origin=origin,
        label=label,
    )
    for field in (
        "run_id_sha256",
        "source_backup_sha256",
        "restored_snapshot_sha256",
        "integrity_query_sha256",
        "integrity_result_sha256",
    ):
        _require_sha256(evidence[field], f"{label} {field}")
    started = _parse_utc(evidence["started_at_utc"], f"{label} start")
    completed = _parse_utc(evidence["completed_at_utc"], f"{label} completion")
    backup_created = _parse_utc(evidence["backup_created_at_utc"], f"{label} backup time")
    if not (backup_created <= started <= completed <= generated_at):
        raise ValueError(f"{label} timeline is invalid")
    if completed - started > timedelta(hours=6) or started - backup_created >= timedelta(hours=26):
        raise ValueError(f"{label} duration or backup age is invalid")
    expected_records = _require_positive_int(evidence["records_expected"], f"{label} expected records", 10**12)
    restored_records = _require_positive_int(evidence["records_restored"], f"{label} restored records", 10**12)
    if expected_records != restored_records:
        raise ValueError(f"{label} record counts differ")
    steps = evidence["steps"]
    expected_steps = ["restore_started", "restore_completed", "integrity_checked", "rollback_verified"]
    if not isinstance(steps, list) or len(steps) != len(expected_steps):
        raise ValueError(f"{label} does not contain the exact recovery steps")
    previous = started
    for expected_name, raw_step in zip(expected_steps, steps):
        step = _require_object(raw_step, f"{label} step")
        _require_exact_keys(
            step,
            {"name", "started_at_utc", "completed_at_utc", "exit_code", "stdout_sha256", "stderr_sha256"},
            f"{label} step",
        )
        if step["name"] != expected_name or step["exit_code"] != 0:
            raise ValueError(f"{label} recovery step did not succeed: {expected_name}")
        step_started = _parse_utc(step["started_at_utc"], f"{label} step start")
        step_completed = _parse_utc(step["completed_at_utc"], f"{label} step completion")
        if not (previous <= step_started <= step_completed <= completed):
            raise ValueError(f"{label} recovery step timeline is invalid")
        previous = step_completed
        _require_sha256(step["stdout_sha256"], f"{label} stdout digest")
        _require_sha256(step["stderr_sha256"], f"{label} stderr digest")


def verify(
    root: Path,
    *,
    expected_commit: str,
    expected_image_digest: str,
    expected_candidate_run_id: int | None = None,
    expected_staging_origin: str | None = None,
    expected_production_origin: str | None = None,
) -> None:
    root = root.resolve()
    if SHA_RE.fullmatch(expected_commit) is None or DIGEST_RE.fullmatch(expected_image_digest) is None:
        raise ValueError("Expected commit or image digest is malformed")
    if expected_candidate_run_id is not None:
        _require_positive_int(expected_candidate_run_id, "expected candidate run ID", 10**20 - 1)
    if not root.is_dir():
        raise ValueError("Deployment evidence root is not a directory")
    children = list(root.iterdir())
    if any(path.suffix.lower() == ".png" for path in children):
        raise ValueError("PNG deployment evidence is forbidden in public artifacts")
    actual_files = {path.name for path in children if path.is_file() and not path.is_symlink()}
    if actual_files != ALL_FILES or any(path.is_symlink() or not path.is_file() for path in children):
        raise ValueError(
            f"Deployment evidence file set differs: missing={sorted(ALL_FILES - actual_files)}, "
            f"extra={sorted({path.name for path in children} - ALL_FILES)}"
        )

    manifest = _load_json(root / "deployment-evidence.json", "deployment evidence manifest")
    _require_exact_keys(
        manifest,
        {
            "schema",
            "release_commit",
            "candidate_run_id",
            "portal_image_digest",
            "staging_origin",
            "production_origin",
            "generated_at_utc",
            "artifacts",
        },
        "deployment evidence manifest",
    )
    if manifest["schema"] != 3:
        raise ValueError("Deployment evidence schema is unsupported")
    if manifest["release_commit"] != expected_commit:
        raise ValueError("Deployment evidence commit mismatch")
    if manifest["portal_image_digest"] != expected_image_digest:
        raise ValueError("Deployment evidence image digest mismatch")
    candidate_run_id = _require_positive_int(
        manifest["candidate_run_id"], "candidate run ID", 10**20 - 1
    )
    if expected_candidate_run_id is not None and candidate_run_id != expected_candidate_run_id:
        raise ValueError("Deployment evidence belongs to another signed candidate run")
    staging_origin = _validate_origin(manifest["staging_origin"], "staging origin")
    production_origin = _validate_origin(manifest["production_origin"], "production origin")
    if staging_origin == production_origin:
        raise ValueError("Staging and production origins must be different")
    if expected_staging_origin is not None and staging_origin != _validate_origin(
        expected_staging_origin, "expected staging origin"
    ):
        raise ValueError("Deployment evidence staging origin mismatch")
    if expected_production_origin is not None and production_origin != _validate_origin(
        expected_production_origin, "expected production origin"
    ):
        raise ValueError("Deployment evidence production origin mismatch")
    generated_at = _parse_utc(manifest["generated_at_utc"], "evidence generation time")
    now = datetime.now(timezone.utc)
    if generated_at > now + timedelta(minutes=5) or now - generated_at > timedelta(hours=48):
        raise ValueError("Deployment evidence generation time is stale or in the future")

    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != len(PAYLOAD_FILES):
        raise ValueError("Deployment evidence artifact manifest is incomplete")
    artifact_names: set[str] = set()
    for raw_artifact in artifacts:
        artifact = _require_object(raw_artifact, "deployment evidence artifact")
        _require_exact_keys(artifact, {"path", "sha256", "size_bytes"}, "deployment evidence artifact")
        name = artifact["path"]
        if not isinstance(name, str) or name not in PAYLOAD_FILES or name in artifact_names:
            raise ValueError("Deployment evidence artifact path is unknown or duplicated")
        artifact_names.add(name)
        path = root / name
        expected_size = _require_positive_int(artifact["size_bytes"], f"{name} size", 8 * 1024 * 1024)
        if path.stat().st_size != expected_size:
            raise ValueError(f"Deployment evidence artifact size mismatch: {name}")
        expected_hash = _require_sha256(artifact["sha256"], f"{name} digest")
        if _sha256(path) != expected_hash:
            raise ValueError(f"Deployment evidence artifact digest mismatch: {name}")
    if artifact_names != PAYLOAD_FILES:
        raise ValueError("Deployment evidence artifact manifest is incomplete")

    _validate_origin_isolation(root / ORIGIN_ISOLATION_FILE)
    _, staging_probe_end, staging_certificate = _validate_probe(
        root / "staging-probe.json",
        environment="staging",
        commit=expected_commit,
        candidate_run_id=candidate_run_id,
        image_digest=expected_image_digest,
        origin=staging_origin,
        generated_at=generated_at,
    )
    _, production_probe_end, production_certificate = _validate_probe(
        root / "production-probe.json",
        environment="production",
        commit=expected_commit,
        candidate_run_id=candidate_run_id,
        image_digest=expected_image_digest,
        origin=production_origin,
        generated_at=generated_at,
    )
    _, staging_observation_end = _validate_observations(
        root / "staging-observations.jsonl",
        environment="staging",
        commit=expected_commit,
        candidate_run_id=candidate_run_id,
        image_digest=expected_image_digest,
        origin=staging_origin,
        certificate_sha256=staging_certificate,
        generated_at=generated_at,
    )
    _, production_observation_end = _validate_observations(
        root / "production-observations.jsonl",
        environment="production",
        commit=expected_commit,
        candidate_run_id=candidate_run_id,
        image_digest=expected_image_digest,
        origin=production_origin,
        certificate_sha256=production_certificate,
        generated_at=generated_at,
    )
    if generated_at - max(staging_probe_end, staging_observation_end) > timedelta(hours=48):
        raise ValueError("Staging evidence is stale")
    if generated_at - max(production_probe_end, production_observation_end) > timedelta(hours=6):
        raise ValueError("Production evidence is stale")
    _validate_backup_restore(
        root / "backup-restore.json",
        commit=expected_commit,
        candidate_run_id=candidate_run_id,
        image_digest=expected_image_digest,
        origin=staging_origin,
        generated_at=generated_at,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-image-digest", required=True)
    parser.add_argument("--expected-candidate-run-id", type=int)
    parser.add_argument("--expected-staging-origin")
    parser.add_argument("--expected-production-origin")
    parser.add_argument(
        "--seal-origin-isolation",
        action="store_true",
        help="replace legacy screenshot entries with this run's external origin gate",
    )
    args = parser.parse_args()
    if args.seal_origin_isolation:
        seal_origin_isolation(args.root)
    verify(
        args.root,
        expected_commit=args.expected_commit,
        expected_image_digest=args.expected_image_digest,
        expected_candidate_run_id=args.expected_candidate_run_id,
        expected_staging_origin=args.expected_staging_origin,
        expected_production_origin=args.expected_production_origin,
    )
    print("deployment-evidence: PASS (schema 3, machine-readable only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
