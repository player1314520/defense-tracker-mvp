#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Collect redaction-safe, machine-verifiable V9 deployment evidence.

Every success value in the emitted evidence is derived from a live HTTPS/TLS
request, a bounded command execution, or bytes read from a concrete artifact.
The collector never accepts status codes, record counts, latency, hashes, or a
generic ``pass`` flag as operator input.

Honest boundaries:

* an HTTP status and response digest do not prove that a business workflow was
  semantically correct; the configured endpoint must itself be an audited E2E
  probe for the named gate;
* hashed command output prevents public disclosure but does not make a
  compromised command or host trustworthy;
* this local collector cannot prove public origin isolation.  The separate
  GitHub-hosted gate adds that evidence and seals schema 2 as schema 3;
* one observation process is not continuous monitoring and does not establish
  high availability, RPO, or RTO beyond the measured interval.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import math
import os
import queue
import re
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Iterator, Mapping, Sequence
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from scripts.verify_deployment_evidence import (
        CORE_PAYLOAD_FILES,
        PRODUCTION_CHECKS,
        STAGING_CHECKS,
        _validate_backup_restore,
        _validate_observations,
        _validate_probe,
    )
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    from verify_deployment_evidence import (  # type: ignore[no-redef]
        CORE_PAYLOAD_FILES,
        PRODUCTION_CHECKS,
        STAGING_CHECKS,
        _validate_backup_restore,
        _validate_observations,
        _validate_probe,
    )


SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
DNS_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
HEADER_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
SAFE_TLS_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:+/-]{1,128}$")
NUMBER_RE = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")

PROBE_PLAN_KEYS = {"schema", "environment", "checks"}
PROBE_CHECK_KEYS = {"name", "method", "path", "headers", "body_env"}
PROBE_HEADER_KEYS = {"name", "value_env"}
OBSERVATION_KEYS = {
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
    "data_device_sha256",
    "backup_receipt_sha256",
    "response_sha256",
}
STEP_NAMES = (
    "restore_started",
    "restore_completed",
    "integrity_checked",
    "rollback_verified",
)
PROBE_ROUTE_SPECS = {
    name: {
        "method": "GET" if name == "release_metadata" else "POST",
        "path": f"/api/v9/deployment-evidence/{name}",
    }
    for name in {*STAGING_CHECKS, *PRODUCTION_CHECKS}
}
OBSERVATION_POLICIES = {
    "staging": {"samples": 26, "interval_seconds": 3600},
    "production": {"samples": 100, "interval_seconds": 60},
}
OBSERVATION_CONFIG_PATHS = {
    "staging": Path("/etc/defense-tracker/staging.env"),
    "production": Path("/etc/defense-tracker/production.env"),
}
OBSERVATION_DATA_ROOT = Path("/opt/defense-tracker")
OBSERVATION_BACKUP_ROOT = Path("/var/lib/defense-tracker-backup")
OBSERVATION_CONFIG_NAMES = {
    "SUPABASE_POSTGRES_DATA_DIR",
    "BACKUP_STATE_DIR",
}
RECOVERY_SCRIPT_RELATIVE = Path("deploy/mvp/bin/restore-dry-run.sh")
RECOVERY_PRODUCTION_CONFIG = Path("/etc/defense-tracker/production.env")
COLLECTOR_KEY_PATH = Path("/etc/defense-tracker/deployment-evidence.key")
COLLECTOR_STATE_ROOT = Path("/var/lib/defense-tracker/deployment-evidence-state")
RECOVERY_INTEGRITY_QUERY = (
    b"select count(*) from pg_database where datistemplate = false;"
)
RECOVERY_SUCCESS_MARKERS = (
    b"Encrypted checksum, decryption and all payload hashes passed.",
    b"Both databases restored",
    b"Storage/config archives were read-tested",
    b"Production data and containers were not modified.",
)
SAFE_COMMAND_ENVIRONMENT = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}
FORBIDDEN_REQUEST_HEADERS = {
    "connection",
    "content-length",
    "host",
    "proxy-authorization",
    "transfer-encoding",
}
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_PLAN_BYTES = 1024 * 1024
LOCK_NAME = ".deployment-evidence-collector.lock"
RECOVERY_RECEIPT_KEYS = {
    "schema",
    "measurement_kind",
    "records_expected",
    "records_restored",
}


class CollectionError(RuntimeError):
    """A fail-closed, redaction-safe collection failure."""


@dataclass(frozen=True)
class TlsMeasurement:
    server_name: str
    protocol: str
    cipher: str
    peer_certificate_sha256: str
    not_before_utc: str
    not_after_utc: str

    def as_dict(self) -> dict[str, object]:
        return {
            "server_name": self.server_name,
            "protocol": self.protocol,
            "cipher": self.cipher,
            "peer_certificate_sha256": self.peer_certificate_sha256,
            "not_before_utc": self.not_before_utc,
            "not_after_utc": self.not_after_utc,
        }


@dataclass(frozen=True)
class HttpMeasurement:
    status_code: int
    elapsed_ms: int
    observed_at_utc: str
    response_sha256: str


@dataclass(frozen=True)
class CommandMeasurement:
    exit_code: int
    stdout: bytes
    stderr: bytes
    started_at_utc: str
    completed_at_utc: str


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise CollectionError(f"{label} is not canonical UTC seconds")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise CollectionError(f"{label} is not canonical UTC seconds") from exc
    return parsed.replace(tzinfo=timezone.utc)


def _exact_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise CollectionError(f"{label} fields differ from the schema")


def _strict_json_loads(payload: str, label: str) -> object:
    def reject_constant(value: str) -> object:
        raise CollectionError(f"{label} contains a non-finite number")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise CollectionError(f"{label} contains a duplicate key")
            result[key] = value
        return result

    try:
        return json.loads(
            payload,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise CollectionError(f"{label} is not valid JSON") from exc


def _load_json(path: Path, label: str, *, maximum: int = MAX_PLAN_BYTES) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise CollectionError(f"{label} must be a regular file")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise CollectionError(f"{label} could not be read") from exc
    if not payload or len(payload) > maximum:
        raise CollectionError(f"{label} size is invalid")
    try:
        decoded = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CollectionError(f"{label} is not UTF-8") from exc
    value = _strict_json_loads(decoded, label)
    if not isinstance(value, dict):
        raise CollectionError(f"{label} must be an object")
    return value


def _validate_bindings(
    *, release_commit: str, candidate_run_id: int, portal_image_digest: str
) -> None:
    if SHA1_RE.fullmatch(release_commit) is None:
        raise CollectionError("release commit is malformed")
    if (
        isinstance(candidate_run_id, bool)
        or not isinstance(candidate_run_id, int)
        or not 0 < candidate_run_id < 10**20
    ):
        raise CollectionError("candidate run ID is malformed")
    if IMAGE_DIGEST_RE.fullmatch(portal_image_digest) is None:
        raise CollectionError("portal image digest is malformed")


def _environment_value(name: str, environ: Mapping[str, str], label: str) -> str:
    if ENV_NAME_RE.fullmatch(name) is None:
        raise CollectionError(f"{label} environment-variable reference is invalid")
    value = environ.get(name)
    if not isinstance(value, str) or not value:
        raise CollectionError(f"{label} environment variable is missing or empty")
    if "\0" in value:
        raise CollectionError(f"{label} environment variable contains a NUL byte")
    return value


def _origin_from_environment(name: str, environ: Mapping[str, str]) -> str:
    value = _environment_value(name, environ, "origin")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise CollectionError("origin must be an exact lowercase public HTTPS origin") from exc
    if (
        value != value.lower()
        or parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or port not in (None, 443)
        or parsed.hostname is None
        or DNS_RE.fullmatch(parsed.hostname) is None
    ):
        raise CollectionError("origin must be an exact lowercase public HTTPS origin")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        raise CollectionError("origin must be an exact lowercase public HTTPS origin")
    return value


def _relative_origin_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise CollectionError(f"{label} must be a relative HTTPS-origin path")
    parsed = urlsplit(value)
    pure = PurePosixPath(parsed.path)
    if (
        not value.startswith("/")
        or value.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or "\\" in value
        or ".." in pure.parts
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise CollectionError(f"{label} must be a relative HTTPS-origin path")
    return value


def _timeout(value: float, label: str, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) <= maximum
    ):
        raise CollectionError(f"{label} timeout is outside policy")
    return float(value)


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path, label: str) -> str:
    if path.is_symlink() or not path.is_file():
        raise CollectionError(f"{label} must be a regular file")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
            after = os.fstat(stream.fileno())
        current = path.stat()
    except OSError as exc:
        raise CollectionError(f"{label} could not be hashed") from exc
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_size != current.st_size
        or before.st_mtime_ns != current.st_mtime_ns
    ):
        raise CollectionError(f"{label} changed while it was being hashed")
    return digest.hexdigest()


def _canonical_json(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CollectionError("evidence is not canonicalizable JSON") from exc


def _require_trusted_directory_fd(descriptor: int, label: str) -> None:
    try:
        metadata = os.fstat(descriptor)
    except OSError as exc:
        raise CollectionError(f"{label} metadata could not be read") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise CollectionError(f"{label} is not a directory")
    if (
        metadata.st_uid != _expected_root_uid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise CollectionError(f"{label} is not root-controlled")


def _ensure_root(root: Path) -> Path:
    """Open every POSIX path component without following links, then pin permissions."""

    if os.name == "nt":  # no equivalent owner/openat trust chain is implemented
        raise CollectionError("secure evidence collection requires a POSIX host")

    if not root.is_absolute() or root == Path("/") or ".." in root.parts:
        raise CollectionError("evidence root must be a specific absolute path")
    if not hasattr(os, "geteuid") or os.geteuid() != _expected_root_uid():
        raise CollectionError("evidence collection requires the root service identity")
    required_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        current_descriptor = os.open("/", required_flags)
    except OSError as exc:
        raise CollectionError("evidence root filesystem could not be opened") from exc
    try:
        _require_trusted_directory_fd(current_descriptor, "evidence root parent")
        components = root.parts[1:]
        for index, component in enumerate(components):
            final_component = index == len(components) - 1
            try:
                next_descriptor = os.open(
                    component,
                    required_flags,
                    dir_fd=current_descriptor,
                )
            except FileNotFoundError as exc:
                if not final_component:
                    raise CollectionError("evidence root parent is missing") from exc
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current_descriptor)
                    next_descriptor = os.open(
                        component,
                        required_flags,
                        dir_fd=current_descriptor,
                    )
                except OSError as create_exc:
                    raise CollectionError(
                        "evidence root could not be created securely"
                    ) from create_exc
            except OSError as exc:
                raise CollectionError(
                    "evidence root path changed or contains a symbolic link"
                ) from exc
            try:
                _require_trusted_directory_fd(
                    next_descriptor,
                    "evidence root" if final_component else "evidence root parent",
                )
            except Exception:
                os.close(next_descriptor)
                raise
            os.close(current_descriptor)
            current_descriptor = next_descriptor
        try:
            os.fchmod(current_descriptor, 0o700)
            _require_trusted_directory_fd(current_descriptor, "evidence root")
        except OSError as exc:
            raise CollectionError(
                "evidence root permissions could not be restricted"
            ) from exc
    finally:
        os.close(current_descriptor)
    return root


@contextmanager
def _root_lock(root: Path) -> Iterator[None]:
    lock = root / LOCK_NAME
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
    except FileExistsError as exc:
        raise CollectionError("another evidence collector holds the root lock") from exc
    except OSError as exc:
        raise CollectionError("evidence root lock could not be created") from exc
    try:
        yield
    finally:
        try:
            lock.unlink()
        except FileNotFoundError:
            pass


def _atomic_write(path: Path, payload: bytes, *, replace_existing: bool) -> None:
    if path.is_symlink():
        raise CollectionError("evidence output must not be a symbolic link")
    if path.exists() and not replace_existing:
        raise CollectionError("evidence output already exists and is immutable")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    if temporary.exists():
        raise CollectionError("stale evidence temporary file exists")
    try:
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        if replace_existing:
            os.replace(temporary, path)
        else:
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise CollectionError("evidence output appeared concurrently") from exc
            temporary.unlink()
        if hasattr(os, "O_DIRECTORY"):
            directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    except CollectionError:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    except OSError as exc:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise CollectionError("evidence output could not be written atomically") from exc


def _collector_key() -> bytes:
    path = COLLECTOR_KEY_PATH
    if path.is_symlink() or not path.is_file():
        raise CollectionError("deployment collector key is missing or unsafe")
    try:
        metadata = path.stat()
        key = path.read_bytes()
    except OSError as exc:
        raise CollectionError("deployment collector key could not be read") from exc
    if len(key) != 32:
        raise CollectionError("deployment collector key must contain exactly 32 random bytes")
    if os.name != "nt" and (
        metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise CollectionError("deployment collector key permissions are unsafe")
    return key


def _collector_state_path(evidence_root: Path, release_commit: str) -> Path:
    state_root = COLLECTOR_STATE_ROOT
    if state_root.exists():
        if state_root.is_symlink() or not state_root.is_dir():
            raise CollectionError("deployment collector state root is unsafe")
    else:
        try:
            state_root.mkdir(parents=True, mode=0o700)
        except OSError as exc:
            raise CollectionError("deployment collector state root could not be created") from exc
    try:
        os.chmod(state_root, 0o700)
        metadata = state_root.stat()
    except OSError as exc:
        raise CollectionError("deployment collector state root is unreadable") from exc
    if os.name != "nt" and (
        metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise CollectionError("deployment collector state root permissions are unsafe")
    root_hash = _sha256_bytes(str(evidence_root.resolve()).encode("utf-8"))[:24]
    return state_root / f"{release_commit}-{root_hash}.json"


def _collector_artifact_tag(
    *,
    key: bytes,
    evidence_root: Path,
    artifact_name: str,
    artifact_sha256: str,
    release_commit: str,
    candidate_run_id: int,
    portal_image_digest: str,
) -> str:
    message = _canonical_json(
        {
            "domain": "DefenseTracker deployment evidence collector v1",
            "evidence_root_sha256": _sha256_bytes(
                str(evidence_root.resolve()).encode("utf-8")
            ),
            "artifact_name": artifact_name,
            "artifact_sha256": artifact_sha256,
            "release_commit": release_commit,
            "candidate_run_id": candidate_run_id,
            "portal_image_digest": portal_image_digest,
        }
    )
    state_key = hmac.new(
        key,
        b"DefenseTracker deployment collector state-HMAC key v1\0",
        hashlib.sha256,
    ).digest()
    return hmac.new(state_key, message, hashlib.sha256).hexdigest()


def _load_collector_state(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    state = _load_json(path, "deployment collector state", maximum=1024 * 1024)
    _exact_keys(
        state,
        {
            "schema",
            "evidence_root_sha256",
            "release_commit",
            "candidate_run_id",
            "portal_image_digest",
            "artifacts",
        },
        "deployment collector state",
    )
    if state.get("schema") != 1 or not isinstance(state.get("artifacts"), dict):
        raise CollectionError("deployment collector state schema is invalid")
    return state


def _record_collected_artifact(
    *,
    evidence_root: Path,
    artifact_path: Path,
    release_commit: str,
    candidate_run_id: int,
    portal_image_digest: str,
) -> None:
    key = _collector_key()
    state_path = _collector_state_path(evidence_root, release_commit)
    root_hash = _sha256_bytes(str(evidence_root.resolve()).encode("utf-8"))
    state = _load_collector_state(state_path)
    if state is None:
        state = {
            "schema": 1,
            "evidence_root_sha256": root_hash,
            "release_commit": release_commit,
            "candidate_run_id": candidate_run_id,
            "portal_image_digest": portal_image_digest,
            "artifacts": {},
        }
    if (
        state.get("evidence_root_sha256") != root_hash
        or state.get("release_commit") != release_commit
        or state.get("candidate_run_id") != candidate_run_id
        or state.get("portal_image_digest") != portal_image_digest
    ):
        raise CollectionError("deployment collector state has different bindings")
    artifacts = state["artifacts"]
    if not isinstance(artifacts, dict) or artifact_path.name in artifacts:
        raise CollectionError("deployment collector state already contains this artifact")
    artifact_sha256 = _sha256_file(artifact_path, "collected deployment artifact")
    artifacts[artifact_path.name] = {
        "sha256": artifact_sha256,
        "hmac_sha256": _collector_artifact_tag(
            key=key,
            evidence_root=evidence_root,
            artifact_name=artifact_path.name,
            artifact_sha256=artifact_sha256,
            release_commit=release_commit,
            candidate_run_id=candidate_run_id,
            portal_image_digest=portal_image_digest,
        ),
    }
    _atomic_write(
        state_path,
        _canonical_json(state),
        replace_existing=state_path.exists(),
    )


def _verify_collector_state(
    *,
    evidence_root: Path,
    release_commit: str,
    candidate_run_id: int,
    portal_image_digest: str,
) -> None:
    key = _collector_key()
    state_path = _collector_state_path(evidence_root, release_commit)
    state = _load_collector_state(state_path)
    root_hash = _sha256_bytes(str(evidence_root.resolve()).encode("utf-8"))
    if state is None or (
        state.get("evidence_root_sha256") != root_hash
        or state.get("release_commit") != release_commit
        or state.get("candidate_run_id") != candidate_run_id
        or state.get("portal_image_digest") != portal_image_digest
    ):
        raise CollectionError("deployment collector state is missing or has different bindings")
    artifacts = state.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != CORE_PAYLOAD_FILES:
        raise CollectionError("deployment collector state does not contain the exact payload set")
    for name in sorted(CORE_PAYLOAD_FILES):
        entry = artifacts.get(name)
        if not isinstance(entry, dict):
            raise CollectionError("deployment collector state artifact is malformed")
        _exact_keys(entry, {"sha256", "hmac_sha256"}, "collector artifact state")
        actual_sha256 = _sha256_file(evidence_root / name, "collected deployment artifact")
        expected_tag = _collector_artifact_tag(
            key=key,
            evidence_root=evidence_root,
            artifact_name=name,
            artifact_sha256=actual_sha256,
            release_commit=release_commit,
            candidate_run_id=candidate_run_id,
            portal_image_digest=portal_image_digest,
        )
        if (
            entry.get("sha256") != actual_sha256
            or not isinstance(entry.get("hmac_sha256"), str)
            or not hmac.compare_digest(str(entry["hmac_sha256"]), expected_tag)
        ):
            raise CollectionError("deployment collector state authentication failed")


def _build_collector_receipt(
    *,
    release_commit: str,
    candidate_run_id: int,
    portal_image_digest: str,
    staging_origin: str,
    production_origin: str,
    generated_at_utc: str,
    artifacts: list[dict[str, object]],
) -> dict[str, object]:
    signing_seed = hmac.new(
        _collector_key(),
        b"DefenseTracker deployment collector Ed25519 seed v1\0",
        hashlib.sha256,
    ).digest()
    private_key = Ed25519PrivateKey.from_private_bytes(signing_seed)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_key_sha256 = _sha256_bytes(public_key)
    receipt: dict[str, object] = {
        "schema": 1,
        "key_id": f"deployment-collector-{public_key_sha256[:16]}",
        "public_key_base64": base64.b64encode(public_key).decode("ascii"),
        "public_key_sha256": public_key_sha256,
        "release_commit": release_commit,
        "candidate_run_id": candidate_run_id,
        "portal_image_digest": portal_image_digest,
        "staging_origin": staging_origin,
        "production_origin": production_origin,
        "generated_at_utc": generated_at_utc,
        "artifacts": artifacts,
    }
    signature = private_key.sign(_canonical_json(receipt))
    receipt["signature_base64"] = base64.b64encode(signature).decode("ascii")
    return receipt


def _tls_measurement(tls: ssl.SSLSocket, hostname: str) -> TlsMeasurement:
    certificate_der = tls.getpeercert(binary_form=True)
    certificate = tls.getpeercert()
    protocol = tls.version()
    cipher_info = tls.cipher()
    if (
        not certificate_der
        or not isinstance(certificate, dict)
        or protocol not in {"TLSv1.2", "TLSv1.3"}
        or not cipher_info
        or SAFE_TLS_TOKEN_RE.fullmatch(str(cipher_info[0])) is None
    ):
        raise CollectionError("TLS measurement is incomplete or unsupported")
    try:
        not_before = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(str(certificate["notBefore"])), timezone.utc
        )
        not_after = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(str(certificate["notAfter"])), timezone.utc
        )
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise CollectionError("TLS certificate validity could not be parsed") from exc
    return TlsMeasurement(
        server_name=hostname,
        protocol=str(protocol),
        cipher=str(cipher_info[0]),
        peer_certificate_sha256=_sha256_bytes(certificate_der),
        not_before_utc=_utc(not_before),
        not_after_utc=_utc(not_after),
    )


def _resolve_public_endpoint(
    hostname: str, port: int, timeout_seconds: float = 30
) -> tuple[int, tuple[object, ...]]:
    timeout_seconds = _timeout(timeout_seconds, "DNS", 120)
    resolved: queue.Queue[tuple[str, object]] = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            rows = socket.getaddrinfo(
                hostname,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except Exception as exc:
            resolved.put(("error", exc))
        else:
            resolved.put(("rows", rows))

    resolver = threading.Thread(target=resolve, daemon=True)
    resolver.start()
    resolver.join(timeout_seconds)
    if resolver.is_alive():
        raise CollectionError("HTTPS origin DNS exceeded the total deadline")
    try:
        kind, value = resolved.get_nowait()
    except queue.Empty as exc:  # defensive: a resolver must always publish one result
        raise CollectionError("HTTPS origin DNS resolution failed") from exc
    if kind == "error":
        raise CollectionError("HTTPS origin DNS resolution failed") from value
    rows = value
    if not isinstance(rows, list):
        raise CollectionError("HTTPS origin DNS returned an invalid result")
    endpoints: list[tuple[int, tuple[object, ...]]] = []
    for family, socktype, protocol, _canonical, sockaddr in rows:
        if socktype != socket.SOCK_STREAM or protocol not in (0, socket.IPPROTO_TCP):
            continue
        try:
            address = ipaddress.ip_address(str(sockaddr[0]))
        except ValueError as exc:
            raise CollectionError("HTTPS origin resolved to an invalid address") from exc
        if not address.is_global:
            raise CollectionError("HTTPS origin resolved to a non-public address")
        candidate = (family, sockaddr)
        if candidate not in endpoints:
            endpoints.append(candidate)
    if not endpoints:
        raise CollectionError("HTTPS origin did not resolve to a public endpoint")
    return endpoints[0]


def _perform_https_request(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes | None,
    timeout_seconds: float,
) -> tuple[TlsMeasurement, HttpMeasurement]:
    """Measure TLS and HTTP on one direct, public-address connection."""

    timeout_seconds = _timeout(timeout_seconds, "HTTP", 120)
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.hostname is None
        or parsed.port not in (None, 443)
        or parsed.fragment
    ):
        raise CollectionError("HTTP request escaped HTTPS policy")
    request_headers = {
        "Accept": "application/json",
        "User-Agent": "DefenseTracker-Deployment-Evidence/1",
        **dict(headers),
    }
    if body is not None and not any(
        name.lower() == "content-type" for name in request_headers
    ):
        request_headers["Content-Type"] = "application/json"
    started = time.monotonic()
    family, sockaddr = _resolve_public_endpoint(parsed.hostname, 443, timeout_seconds)
    remaining = timeout_seconds - (time.monotonic() - started)
    if remaining <= 0:
        raise CollectionError("HTTPS request exceeded the total deadline")
    context = ssl.create_default_context()
    remaining = timeout_seconds - (time.monotonic() - started)
    if remaining <= 0:
        raise CollectionError("HTTPS request exceeded the total deadline")
    raw: socket.socket | None = None
    tls_socket: ssl.SSLSocket | None = None
    connection: http.client.HTTPSConnection | None = None
    deadline_reached = threading.Event()

    def abort_request() -> None:
        deadline_reached.set()
        for stream in (connection, tls_socket, raw):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    deadline_timer = threading.Timer(remaining, abort_request)
    deadline_timer.daemon = True
    deadline_timer.start()
    try:
        raw = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        raw.settimeout(remaining)
        raw.connect(sockaddr)
        tls_socket = context.wrap_socket(raw, server_hostname=parsed.hostname)
        raw = None
        peer_address = ipaddress.ip_address(str(tls_socket.getpeername()[0]))
        if not peer_address.is_global:
            raise CollectionError("HTTPS connection reached a non-public peer")
        tls_measurement = _tls_measurement(tls_socket, parsed.hostname)
        connection = http.client.HTTPSConnection(
            parsed.hostname,
            443,
            timeout=remaining,
            context=context,
        )
        connection.sock = tls_socket
        tls_socket = None
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        connection.request(method, target, body=body, headers=request_headers)
        response = connection.getresponse()
        status = int(response.status)
        response_bytes = response.read(MAX_RESPONSE_BYTES + 1)
    except CollectionError:
        raise
    except (http.client.HTTPException, ssl.SSLError, TimeoutError, OSError) as exc:
        if deadline_reached.is_set():
            raise CollectionError("HTTPS request exceeded the total deadline") from exc
        raise CollectionError("HTTPS probe failed before receiving a response") from exc
    finally:
        deadline_timer.cancel()
        if connection is not None:
            connection.close()
        if tls_socket is not None:
            tls_socket.close()
        if raw is not None:
            raw.close()
        deadline_timer.join(timeout=1)
    if deadline_reached.is_set():
        raise CollectionError("HTTPS request exceeded the total deadline")
    elapsed_ms = max(1, math.ceil((time.monotonic() - started) * 1000))
    if len(response_bytes) > MAX_RESPONSE_BYTES:
        raise CollectionError("HTTPS response exceeded the evidence limit")
    return (
        tls_measurement,
        HttpMeasurement(
            status_code=status,
            elapsed_ms=elapsed_ms,
            observed_at_utc=_utc(_utc_now()),
            response_sha256=_sha256_bytes(response_bytes),
        ),
    )


def _load_probe_plan(
    plan_path: Path,
    *,
    environment: str,
    origin: str,
    environ: Mapping[str, str],
) -> list[dict[str, object]]:
    plan = _load_json(plan_path, "probe plan")
    _exact_keys(plan, PROBE_PLAN_KEYS, "probe plan")
    if plan.get("schema") != 1 or plan.get("environment") != environment:
        raise CollectionError("probe plan schema or environment differs")
    expected = STAGING_CHECKS if environment == "staging" else PRODUCTION_CHECKS
    rows = plan.get("checks")
    if not isinstance(rows, list) or len(rows) != len(expected):
        raise CollectionError("probe plan does not contain the exact required checks")
    normalized: list[dict[str, object]] = []
    seen: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise CollectionError("probe plan check must be an object")
        _exact_keys(row, PROBE_CHECK_KEYS, "probe plan check")
        name = row.get("name")
        if not isinstance(name, str) or name not in expected or name in seen:
            raise CollectionError("probe plan contains an unknown or duplicate check")
        seen.add(name)
        method = row.get("method")
        route = PROBE_ROUTE_SPECS[name]
        if method != route["method"]:
            raise CollectionError("probe plan method differs from the fixed route contract")
        path = _relative_origin_path(row.get("path"), "probe check path")
        if path != route["path"]:
            raise CollectionError("probe plan path differs from the fixed route contract")
        url = origin + path
        parsed = urlsplit(url)
        if f"{parsed.scheme}://{parsed.netloc}" != origin:
            raise CollectionError("probe check URL escaped its configured origin")
        raw_headers = row.get("headers")
        if not isinstance(raw_headers, list) or len(raw_headers) > 32:
            raise CollectionError("probe plan headers are invalid")
        headers: dict[str, str] = {}
        for raw_header in raw_headers:
            if not isinstance(raw_header, dict):
                raise CollectionError("probe plan header must be an object")
            _exact_keys(raw_header, PROBE_HEADER_KEYS, "probe plan header")
            header_name = raw_header.get("name")
            if (
                not isinstance(header_name, str)
                or HEADER_NAME_RE.fullmatch(header_name) is None
                or header_name.lower() in FORBIDDEN_REQUEST_HEADERS
                or any(existing.lower() == header_name.lower() for existing in headers)
            ):
                raise CollectionError("probe plan header name is unsafe or duplicated")
            value_env = raw_header.get("value_env")
            if not isinstance(value_env, str):
                raise CollectionError("probe plan header must use an environment reference")
            header_value = _environment_value(value_env, environ, "probe header")
            if (
                len(header_value) > 8192
                or "\r" in header_value
                or "\n" in header_value
                or any(ord(character) == 127 for character in header_value)
            ):
                raise CollectionError("probe header environment value is unsafe")
            headers[header_name] = header_value
        body_env = row.get("body_env")
        body: bytes | None
        if body_env is None:
            body = None
        elif isinstance(body_env, str):
            body = _environment_value(body_env, environ, "probe body").encode("utf-8")
            if len(body) > 1024 * 1024:
                raise CollectionError("probe body exceeds the request limit")
        else:
            raise CollectionError("probe body must use an environment reference")
        if method == "GET" and body is not None:
            raise CollectionError("GET probe checks must not carry a request body")
        normalized.append(
            {
                "name": name,
                "method": method,
                "url": url,
                "headers": headers,
                "body": body,
                "expected_status": expected[name],
            }
        )
    if seen != set(expected):
        raise CollectionError("probe plan does not contain the exact required checks")
    return normalized


def _validate_tls_measurement(
    tls: TlsMeasurement,
    *,
    origin: str,
    started: datetime,
    completed: datetime,
) -> None:
    hostname = urlsplit(origin).hostname
    if (
        tls.server_name != hostname
        or tls.protocol not in {"TLSv1.2", "TLSv1.3"}
        or SAFE_TLS_TOKEN_RE.fullmatch(tls.cipher) is None
        or SHA256_RE.fullmatch(tls.peer_certificate_sha256) is None
    ):
        raise CollectionError("TLS measurement differs from the exact origin")
    not_before = _parse_utc(tls.not_before_utc, "TLS not-before")
    not_after = _parse_utc(tls.not_after_utc, "TLS not-after")
    if not (not_before <= started <= completed <= not_after):
        raise CollectionError("TLS certificate was not valid throughout collection")


def collect_probe(
    *,
    evidence_root: Path,
    environment: str,
    origin_env: str,
    plan_path: Path,
    release_commit: str,
    candidate_run_id: int,
    portal_image_digest: str,
    timeout_seconds: float,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Collect one complete staging or production live probe."""

    if environment not in {"staging", "production"}:
        raise CollectionError("probe environment must be staging or production")
    _validate_bindings(
        release_commit=release_commit,
        candidate_run_id=candidate_run_id,
        portal_image_digest=portal_image_digest,
    )
    timeout_seconds = _timeout(timeout_seconds, "probe", 120)
    environment_values = os.environ if environ is None else environ
    origin = _origin_from_environment(origin_env, environment_values)
    checks = _load_probe_plan(
        plan_path,
        environment=environment,
        origin=origin,
        environ=environment_values,
    )
    root = _ensure_root(evidence_root)
    output = root / f"{environment}-probe.json"
    started = _utc_now()
    tls: TlsMeasurement | None = None
    observed_checks: list[dict[str, object]] = []
    for check in checks:
        connection_tls, measurement = _perform_https_request(
            str(check["method"]),
            str(check["url"]),
            check["headers"],  # type: ignore[arg-type]
            check["body"],  # type: ignore[arg-type]
            timeout_seconds,
        )
        if tls is None:
            tls = connection_tls
        elif connection_tls.peer_certificate_sha256 != tls.peer_certificate_sha256:
            raise CollectionError("probe responses used different TLS certificates")
        if measurement.status_code != check["expected_status"]:
            raise CollectionError(
                f"live probe returned an unexpected status for {check['name']}"
            )
        if (
            isinstance(measurement.elapsed_ms, bool)
            or not 0 < measurement.elapsed_ms <= 120_000
            or SHA256_RE.fullmatch(measurement.response_sha256) is None
        ):
            raise CollectionError("live HTTP measurement is malformed")
        observed_checks.append(
            {
                "name": check["name"],
                "method": check["method"],
                "url": check["url"],
                "status_code": measurement.status_code,
                "elapsed_ms": measurement.elapsed_ms,
                "observed_at_utc": measurement.observed_at_utc,
                "response_sha256": measurement.response_sha256,
            }
        )
    if tls is None:  # Exact route validation guarantees at least one check.
        raise CollectionError("probe did not make an HTTPS request")
    completed = _utc_now()
    if completed < started or completed - started > timedelta(minutes=30):
        raise CollectionError("probe duration is invalid")
    _validate_tls_measurement(tls, origin=origin, started=started, completed=completed)
    for check in observed_checks:
        observed = _parse_utc(check["observed_at_utc"], "HTTP observation time")
        if not started <= observed <= completed:
            raise CollectionError("HTTP observation time is outside the probe interval")
    payload = {
        "schema": 2,
        "environment": environment,
        "release_commit": release_commit,
        "candidate_run_id": candidate_run_id,
        "portal_image_digest": portal_image_digest,
        "origin": origin,
        "started_at_utc": _utc(started),
        "completed_at_utc": _utc(completed),
        "tls": tls.as_dict(),
        "checks": observed_checks,
    }
    with _root_lock(root):
        _atomic_write(output, _canonical_json(payload), replace_existing=False)
        _record_collected_artifact(
            evidence_root=root,
            artifact_path=output,
            release_commit=release_commit,
            candidate_run_id=candidate_run_id,
            portal_image_digest=portal_image_digest,
        )
    return output


def run_command(
    argv: Sequence[str],
    *,
    timeout_seconds: float,
    child_environment: Mapping[str, str] | None = None,
) -> CommandMeasurement:
    """Run a fixed argv with bounded disk capture and a minimal environment."""

    timeout_seconds = _timeout(timeout_seconds, "command", 6 * 60 * 60)
    if not argv:
        raise CollectionError("command argv is empty")
    executable = Path(argv[0])
    if not executable.is_absolute() or executable.is_symlink() or not executable.is_file():
        raise CollectionError("command executable must be an absolute regular file")
    started = _utc_now()
    environment = dict(SAFE_COMMAND_ENVIRONMENT)
    if child_environment is not None:
        for name, value in child_environment.items():
            if ENV_NAME_RE.fullmatch(name) is None or not isinstance(value, str) or "\0" in value:
                raise CollectionError("fixed command environment is malformed")
            environment[name] = value
    creation_flags = 0
    start_new_session = os.name != "nt"
    preexec_fn = None
    if os.name == "nt":  # pragma: no cover - production recovery runs on Linux
        creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        import resource

        def restrict_capture_files() -> None:
            _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
            limit = MAX_COMMAND_OUTPUT_BYTES
            if hard != resource.RLIM_INFINITY:
                limit = min(limit, hard)
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

        preexec_fn = restrict_capture_files

    def terminate(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        if os.name == "nt":  # pragma: no cover - Windows safety fallback
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()

    try:
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            process = subprocess.Popen(
                list(argv),
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                env=environment,
                start_new_session=start_new_session,
                creationflags=creation_flags,
                preexec_fn=preexec_fn,
            )
            deadline = time.monotonic() + timeout_seconds
            while process.poll() is None:
                stdout_size = os.fstat(stdout_file.fileno()).st_size
                stderr_size = os.fstat(stderr_file.fileno()).st_size
                if (
                    stdout_size > MAX_COMMAND_OUTPUT_BYTES
                    or stderr_size > MAX_COMMAND_OUTPUT_BYTES
                ):
                    terminate(process)
                    raise CollectionError(
                        "evidence command output exceeded the capture limit"
                    )
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    terminate(process)
                    raise CollectionError("evidence command timed out")
                time.sleep(min(0.05, remaining))
            stdout_size = os.fstat(stdout_file.fileno()).st_size
            stderr_size = os.fstat(stderr_file.fileno()).st_size
            if (
                stdout_size > MAX_COMMAND_OUTPUT_BYTES
                or stderr_size > MAX_COMMAND_OUTPUT_BYTES
                or (
                    process.returncode != 0
                    and max(stdout_size, stderr_size) >= MAX_COMMAND_OUTPUT_BYTES
                )
            ):
                raise CollectionError("evidence command output exceeded the capture limit")
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read()
            stderr = stderr_file.read()
    except OSError as exc:
        raise CollectionError("evidence command could not be executed") from exc
    completed = _utc_now()
    return CommandMeasurement(
        exit_code=int(process.returncode),
        stdout=stdout,
        stderr=stderr,
        started_at_utc=_utc(started),
        completed_at_utc=_utc(completed),
    )


def _disk_free_percent(path: Path) -> float:
    try:
        usage = shutil.disk_usage(path)
    except OSError as exc:
        raise CollectionError("disk-free measurement failed") from exc
    if usage.total <= 0:
        raise CollectionError("disk-free measurement returned an invalid total")
    return usage.free * 100.0 / usage.total


def _expected_root_uid() -> int:
    return 0


def _root_owned_readable_file(path: Path, label: str, *, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise CollectionError(f"{label} is missing or unsafe")
    try:
        metadata = path.stat()
        payload = path.read_bytes()
    except OSError as exc:
        raise CollectionError(f"{label} could not be read") from exc
    if not payload or len(payload) > maximum:
        raise CollectionError(f"{label} size is invalid")
    if os.name != "nt" and (
        metadata.st_uid != _expected_root_uid()
        or stat.S_IMODE(metadata.st_mode) & 0o037
    ):
        raise CollectionError(f"{label} permissions are unsafe")
    return payload


def _fixed_observation_paths(environment: str) -> tuple[Path, Path]:
    config_path = OBSERVATION_CONFIG_PATHS[environment]
    payload = _root_owned_readable_file(
        config_path, f"{environment} observation configuration", maximum=1024 * 1024
    )
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise CollectionError("observation configuration is not UTF-8") from exc
    values: dict[str, str] = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        for name in OBSERVATION_CONFIG_NAMES:
            prefix = f"{name}="
            if not line.startswith(prefix):
                continue
            if name in values:
                raise CollectionError("observation configuration contains duplicate paths")
            value = line[len(prefix) :].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            if re.fullmatch(r"/[A-Za-z0-9._/-]{1,1023}", value) is None:
                raise CollectionError("observation configuration path is unsafe")
            values[name] = value
    if set(values) != OBSERVATION_CONFIG_NAMES:
        raise CollectionError("observation configuration is missing fixed measurement paths")

    def scoped_path(raw: str, anchor: Path, label: str, *, directory: bool) -> Path:
        candidate = Path(raw)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(anchor.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise CollectionError(f"{label} escaped its fixed deployment root") from exc
        if resolved != candidate or (directory and not resolved.is_dir()):
            raise CollectionError(f"{label} is missing or traverses a symbolic link")
        return resolved

    data_path = scoped_path(
        values["SUPABASE_POSTGRES_DATA_DIR"],
        OBSERVATION_DATA_ROOT,
        "Postgres data path",
        directory=True,
    )
    backup_state = scoped_path(
        values["BACKUP_STATE_DIR"],
        OBSERVATION_BACKUP_ROOT,
        "backup state path",
        directory=True,
    )
    return data_path, backup_state / "last-success"


def _collect_host_metrics(
    environment: str, observed: datetime
) -> tuple[float, float, str, str]:
    data_path, receipt_path = _fixed_observation_paths(environment)
    receipt_bytes = _root_owned_readable_file(
        receipt_path, f"{environment} backup success receipt", maximum=8192
    )
    try:
        receipt_lines = receipt_bytes.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise CollectionError("backup success receipt is not ASCII") from exc
    receipt: dict[str, str] = {}
    for line in receipt_lines:
        if "=" not in line:
            raise CollectionError("backup success receipt is malformed")
        name, value = line.split("=", 1)
        if name in receipt:
            raise CollectionError("backup success receipt contains a duplicate field")
        receipt[name] = value
    if set(receipt) != {"schema", "completed_at_utc", "backup_file", "sha256"}:
        raise CollectionError("backup success receipt fields differ from the schema")
    if (
        receipt["schema"] != "1"
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}", receipt["backup_file"])
        is None
        or SHA256_RE.fullmatch(receipt["sha256"]) is None
    ):
        raise CollectionError("backup success receipt values are malformed")
    completed = _parse_utc(
        receipt["completed_at_utc"], f"{environment} backup completion"
    )
    age = (observed - completed).total_seconds() / 3600.0
    if age < 0:
        raise CollectionError("backup timestamp is in the future")
    try:
        device = data_path.stat().st_dev
    except OSError as exc:
        raise CollectionError("Postgres data device measurement failed") from exc
    return (
        _disk_free_percent(data_path),
        age,
        _sha256_bytes(f"deployment-data-device-v1\0{device}".encode("ascii")),
        _sha256_bytes(receipt_bytes),
    )


def collect_observation(
    *,
    evidence_root: Path,
    environment: str,
    origin_env: str,
    health_path: str,
    release_commit: str,
    candidate_run_id: int,
    portal_image_digest: str,
    http_timeout_seconds: float,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Collect one complete, non-resumable live observation window."""

    if environment not in {"staging", "production"}:
        raise CollectionError("observation environment must be staging or production")
    _validate_bindings(
        release_commit=release_commit,
        candidate_run_id=candidate_run_id,
        portal_image_digest=portal_image_digest,
    )
    http_timeout_seconds = _timeout(http_timeout_seconds, "observation HTTP", 120)
    environment_values = os.environ if environ is None else environ
    origin = _origin_from_environment(origin_env, environment_values)
    path = _relative_origin_path(health_path, "observation health path")
    if path != "/health":
        raise CollectionError("observation health path must be the fixed /health route")
    root = _ensure_root(evidence_root)
    output = root / f"{environment}-observations.jsonl"
    probe_path = root / f"{environment}-probe.json"
    probe = _load_json(probe_path, f"{environment} probe", maximum=8 * 1024 * 1024)
    probe_digest = _sha256_file(probe_path, f"{environment} probe")
    if (
        probe.get("schema") != 2
        or probe.get("environment") != environment
        or probe.get("release_commit") != release_commit
        or probe.get("candidate_run_id") != candidate_run_id
        or probe.get("portal_image_digest") != portal_image_digest
        or probe.get("origin") != origin
        or not isinstance(probe.get("tls"), dict)
    ):
        raise CollectionError("observation probe binding differs from this collection")
    probe_certificate = probe["tls"].get("peer_certificate_sha256")
    if not isinstance(probe_certificate, str) or SHA256_RE.fullmatch(probe_certificate) is None:
        raise CollectionError("observation probe certificate is malformed")
    policy = OBSERVATION_POLICIES[environment]
    with _root_lock(root):
        if output.exists() or output.is_symlink():
            raise CollectionError("observation window is immutable and cannot be resumed")
        records: list[dict[str, object]] = []
        previous_time: datetime | None = None
        next_deadline = time.monotonic()
        for index in range(int(policy["samples"])):
            tls, measurement = _perform_https_request(
                "GET", origin + path, {}, None, http_timeout_seconds
            )
            if tls.peer_certificate_sha256 != probe_certificate:
                raise CollectionError("observation TLS certificate differs from the probe")
            observed = _parse_utc(measurement.observed_at_utc, "observation HTTP timestamp")
            _validate_tls_measurement(
                tls, origin=origin, started=observed, completed=observed
            )
            (
                disk_free,
                backup_age,
                data_device_sha256,
                backup_receipt_sha256,
            ) = _collect_host_metrics(environment, observed)
            if (
                measurement.status_code != 200
                or isinstance(measurement.elapsed_ms, bool)
                or not isinstance(measurement.elapsed_ms, int)
                or not 0 < measurement.elapsed_ms <= 120_000
                or SHA256_RE.fullmatch(measurement.response_sha256) is None
                or SHA256_RE.fullmatch(data_device_sha256) is None
                or SHA256_RE.fullmatch(backup_receipt_sha256) is None
                or not 20 < disk_free <= 100
                or not 0 <= backup_age < 26
            ):
                raise CollectionError("live observation is outside the acceptance policy")
            if previous_time is not None and observed <= previous_time:
                raise CollectionError("observation timestamp must increase strictly")
            previous_time = observed
            records.append(
                {
                    "schema": 2,
                    "environment": environment,
                    "release_commit": release_commit,
                    "candidate_run_id": candidate_run_id,
                    "portal_image_digest": portal_image_digest,
                    "origin": origin,
                    "observed_at_utc": measurement.observed_at_utc,
                    "tls_certificate_sha256": tls.peer_certificate_sha256,
                    "http_status": measurement.status_code,
                    "elapsed_ms": measurement.elapsed_ms,
                    "disk_free_percent": disk_free,
                    "backup_age_hours": backup_age,
                    "data_device_sha256": data_device_sha256,
                    "backup_receipt_sha256": backup_receipt_sha256,
                    "response_sha256": measurement.response_sha256,
                }
            )
            if index + 1 < int(policy["samples"]):
                next_deadline += float(policy["interval_seconds"])
                time.sleep(max(0.0, next_deadline - time.monotonic()))
        if environment == "staging" and previous_time is not None:
            first_time = _parse_utc(records[0]["observed_at_utc"], "first observation")
            if previous_time - first_time < timedelta(hours=24):
                raise CollectionError("staging observation window is shorter than 24 hours")
        if probe_digest != _sha256_file(probe_path, f"{environment} probe"):
            raise CollectionError("probe changed during the observation window")
        _atomic_write(output, b"".join(_canonical_json(row) for row in records), replace_existing=False)
        _record_collected_artifact(
            evidence_root=root,
            artifact_path=output,
            release_commit=release_commit,
            candidate_run_id=candidate_run_id,
            portal_image_digest=portal_image_digest,
        )
    return output


def _path_from_environment(
    name: str,
    environ: Mapping[str, str],
    label: str,
    *,
    must_exist: bool,
    allow_directory: bool = False,
) -> Path:
    raw = _environment_value(name, environ, label)
    path = Path(raw)
    if not path.is_absolute():
        raise CollectionError(f"{label} path must be absolute")
    if path.is_symlink():
        raise CollectionError(f"{label} path must not be a symbolic link")
    if must_exist:
        acceptable = path.is_file() or (allow_directory and path.is_dir())
        if not acceptable:
            raise CollectionError(f"{label} path must be a regular file or approved directory")
    return path


def _require_root_controlled_path(path: Path, label: str) -> Path:
    """Reject any symlink or group/other-writable component in a trusted path."""

    try:
        absolute = path.absolute()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CollectionError(f"{label} is missing or cannot be resolved") from exc
    if os.name == "nt":  # production collection is Linux-only
        return resolved
    if absolute != resolved:
        raise CollectionError(f"{label} traverses a symbolic link")
    current = resolved
    while True:
        try:
            metadata = current.stat()
        except OSError as exc:
            raise CollectionError(f"{label} path metadata is unreadable") from exc
        if (
            metadata.st_uid != _expected_root_uid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise CollectionError(f"{label} is not root-controlled")
        if current.parent == current:
            break
        current = current.parent
    return resolved


@contextmanager
def _materialized_recovery_harness(payload: bytes) -> Iterator[Path]:
    """Execute only a private copy of the already verified Git blob."""

    with tempfile.TemporaryDirectory(prefix="defense-restore-harness-") as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        executable = root / "restore-dry-run.sh"
        try:
            descriptor = os.open(executable, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o500)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(executable, 0o500)
        except OSError as exc:
            raise CollectionError("verified recovery harness could not be materialized") from exc
        if _sha256_file(executable, "materialized recovery harness") != _sha256_bytes(
            payload
        ):
            raise CollectionError("materialized recovery harness digest differs")
        os.chmod(root, 0o500)
        try:
            yield executable
        finally:
            # TemporaryDirectory needs directory write permission for cleanup.
            os.chmod(root, 0o700)


def _trusted_recovery_harness(release_commit: str) -> tuple[bytes, str, Path]:
    """Bind the one allowed recovery script to the requested Git commit."""

    repository = _require_root_controlled_path(
        Path(__file__).absolute().parents[1], "collector checkout"
    )
    script = repository / RECOVERY_SCRIPT_RELATIVE
    if script.is_symlink() or not script.is_file():
        raise CollectionError("fixed recovery harness is missing or unsafe")
    _require_root_controlled_path(script, "fixed recovery harness")
    git = shutil.which("git", path=SAFE_COMMAND_ENVIRONMENT["PATH"])
    if git is None:
        raise CollectionError("trusted Git executable is unavailable")
    git_path = Path(git).resolve()
    if not git_path.is_absolute() or not git_path.is_file():
        raise CollectionError("trusted Git executable is unavailable")
    _require_root_controlled_path(git_path, "trusted Git executable")
    git_directory = run_command(
        [str(git_path), "-C", str(repository), "rev-parse", "--absolute-git-dir"],
        timeout_seconds=30,
    )
    if git_directory.exit_code != 0 or git_directory.stderr:
        raise CollectionError("collector checkout Git directory is unavailable")
    try:
        git_directory_path = Path(
            git_directory.stdout.decode("utf-8", "strict").strip()
        )
    except UnicodeError as exc:
        raise CollectionError("collector checkout Git directory is invalid") from exc
    _require_root_controlled_path(git_directory_path, "collector Git directory")
    head = run_command(
        [str(git_path), "-C", str(repository), "rev-parse", "--verify", "HEAD^{commit}"],
        timeout_seconds=30,
    )
    if head.exit_code != 0 or head.stderr or head.stdout.decode("ascii", "strict").strip() != release_commit:
        raise CollectionError("recovery harness checkout differs from the release commit")
    status = run_command(
        [
            str(git_path),
            "-C",
            str(repository),
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
        timeout_seconds=30,
    )
    if status.exit_code != 0 or status.stderr or status.stdout:
        raise CollectionError("collector checkout is not clean")
    committed = run_command(
        [
            str(git_path),
            "-C",
            str(repository),
            "show",
            f"{release_commit}:{RECOVERY_SCRIPT_RELATIVE.as_posix()}",
        ],
        timeout_seconds=30,
    )
    actual = script.read_bytes()
    if committed.exit_code != 0 or committed.stderr or committed.stdout != actual:
        raise CollectionError("recovery harness bytes differ from the release commit")
    required_fragments = (
        b"docker run --detach --pull never",
        b"--network none",
        RECOVERY_INTEGRITY_QUERY,
        b'[ "$database_count" = 2 ]',
        b'"measurement_kind":"database_count"',
        b"trap cleanup EXIT HUP INT TERM",
    )
    if any(fragment not in actual for fragment in required_fragments):
        raise CollectionError("fixed recovery harness contract is incomplete")
    return committed.stdout, _sha256_bytes(actual), repository


def _fixed_production_config() -> Path:
    path = RECOVERY_PRODUCTION_CONFIG
    if path.is_symlink() or not path.is_file():
        raise CollectionError("fixed production recovery configuration is missing")
    try:
        metadata = path.stat()
    except OSError as exc:
        raise CollectionError("fixed production recovery configuration is unreadable") from exc
    if os.name != "nt" and (
        metadata.st_uid != _expected_root_uid()
        or stat.S_IMODE(metadata.st_mode) & 0o037
    ):
        raise CollectionError("fixed production recovery configuration permissions are unsafe")
    return path


def _parse_recovery_receipt(stdout: bytes) -> tuple[int, int, bytes]:
    candidate_lines = [line for line in stdout.splitlines() if line.startswith(b"{")]
    if len(candidate_lines) != 1:
        raise CollectionError("fixed recovery harness did not emit one machine receipt")
    receipt_bytes = candidate_lines[0] + b"\n"
    try:
        decoded = candidate_lines[0].decode("ascii")
    except UnicodeError as exc:
        raise CollectionError("fixed recovery harness receipt is not ASCII") from exc
    receipt = _strict_json_loads(decoded, "fixed recovery harness receipt")
    if not isinstance(receipt, dict):
        raise CollectionError("fixed recovery harness receipt must be an object")
    _exact_keys(receipt, RECOVERY_RECEIPT_KEYS, "fixed recovery harness receipt")
    expected = receipt.get("records_expected")
    restored = receipt.get("records_restored")
    if (
        receipt.get("schema") != 1
        or receipt.get("measurement_kind") != "database_count"
        or isinstance(expected, bool)
        or not isinstance(expected, int)
        or isinstance(restored, bool)
        or not isinstance(restored, int)
        or not 0 < expected <= 1000
        or restored != expected
    ):
        raise CollectionError("fixed recovery harness receipt did not prove equal counts")
    return expected, restored, receipt_bytes


def collect_backup_restore(
    *,
    evidence_root: Path,
    origin_env: str,
    run_id_env: str,
    source_backup_path_env: str,
    age_identity_path_env: str,
    checksum_path_env: str,
    release_commit: str,
    candidate_run_id: int,
    portal_image_digest: str,
    command_timeout_seconds: float,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Run the one Git-bound isolated restore harness and emit its receipt."""

    _validate_bindings(
        release_commit=release_commit,
        candidate_run_id=candidate_run_id,
        portal_image_digest=portal_image_digest,
    )
    command_timeout_seconds = _timeout(
        command_timeout_seconds, "recovery command", 6 * 60 * 60
    )
    environment_values = os.environ if environ is None else environ
    origin = _origin_from_environment(origin_env, environment_values)
    run_id = _environment_value(run_id_env, environment_values, "restore run ID")
    if len(run_id.encode("utf-8")) > 1024:
        raise CollectionError("restore run ID is too large")
    source_backup = _path_from_environment(
        source_backup_path_env,
        environment_values,
        "source backup",
        must_exist=True,
    )
    age_identity = _path_from_environment(
        age_identity_path_env,
        environment_values,
        "age identity",
        must_exist=True,
    )
    checksum = _path_from_environment(
        checksum_path_env,
        environment_values,
        "backup checksum",
        must_exist=True,
    )
    source_hash = _sha256_file(source_backup, "source backup")
    try:
        checksum_lines = checksum.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as exc:
        raise CollectionError("backup checksum could not be read") from exc
    if len(checksum_lines) != 1 or checksum_lines[0].split(maxsplit=1)[0] != source_hash:
        raise CollectionError("backup checksum differs from the source backup")
    harness_payload, harness_hash, release_repository = _trusted_recovery_harness(
        release_commit
    )
    production_config = _fixed_production_config()
    try:
        backup_created = datetime.fromtimestamp(
            source_backup.stat().st_mtime, timezone.utc
        ).replace(microsecond=0)
    except OSError as exc:
        raise CollectionError("source backup timestamp could not be read") from exc
    started = _utc_now()
    with _materialized_recovery_harness(harness_payload) as harness:
        measurement = run_command(
            [str(harness), str(source_backup), str(age_identity), str(checksum)],
            timeout_seconds=command_timeout_seconds,
            child_environment={
                "MVP_PRODUCTION_ENV": str(production_config),
                "DEFENSE_TRACKER_RELEASE_ROOT": str(release_repository),
                "DEFENSE_TRACKER_RELEASE_SHA": release_commit,
            },
        )
    completed = _utc_now()
    if (
        measurement.exit_code != 0
        or measurement.stderr
        or any(marker not in measurement.stdout for marker in RECOVERY_SUCCESS_MARKERS)
    ):
        raise CollectionError("fixed recovery harness failed or returned an incomplete receipt")
    if source_hash != _sha256_file(source_backup, "source backup"):
        raise CollectionError("source backup changed during the recovery exercise")
    records_expected, records_restored, result_bytes = _parse_recovery_receipt(
        measurement.stdout
    )
    query_hash = _sha256_bytes(RECOVERY_INTEGRITY_QUERY)
    result_hash = _sha256_bytes(result_bytes)
    stdout_hash = _sha256_bytes(measurement.stdout)
    stderr_hash = _sha256_bytes(measurement.stderr)
    restored_hash = _sha256_bytes(
        _canonical_json(
            {
                "source_backup_sha256": source_hash,
                "recovery_harness_sha256": harness_hash,
                "harness_stdout_sha256": stdout_hash,
                "integrity_query_sha256": query_hash,
                "integrity_result_sha256": result_hash,
            }
        )
    )
    if not (backup_created <= started <= completed):
        raise CollectionError("backup/restore timeline is invalid")
    if completed - started > timedelta(hours=6) or started - backup_created >= timedelta(
        hours=26
    ):
        raise CollectionError("backup/restore duration or backup age is outside policy")
    harness_started = _parse_utc(measurement.started_at_utc, "recovery harness start")
    harness_completed = _parse_utc(
        measurement.completed_at_utc, "recovery harness completion"
    )
    if not started <= harness_started <= harness_completed <= completed:
        raise CollectionError("backup/restore harness timeline is invalid")
    step_records = [
        {
            "name": "restore_started",
            "started_at_utc": _utc(started),
            "completed_at_utc": measurement.started_at_utc,
            "exit_code": 0,
            "stdout_sha256": _sha256_bytes(b""),
            "stderr_sha256": _sha256_bytes(b""),
        },
        {
            "name": "restore_completed",
            "started_at_utc": measurement.started_at_utc,
            "completed_at_utc": measurement.completed_at_utc,
            "exit_code": 0,
            "stdout_sha256": stdout_hash,
            "stderr_sha256": stderr_hash,
        },
        {
            "name": "integrity_checked",
            "started_at_utc": measurement.completed_at_utc,
            "completed_at_utc": measurement.completed_at_utc,
            "exit_code": 0,
            "stdout_sha256": result_hash,
            "stderr_sha256": stderr_hash,
        },
        {
            "name": "rollback_verified",
            "started_at_utc": measurement.completed_at_utc,
            "completed_at_utc": _utc(completed),
            "exit_code": 0,
            "stdout_sha256": stdout_hash,
            "stderr_sha256": stderr_hash,
        },
    ]
    payload = {
        "schema": 2,
        "release_commit": release_commit,
        "candidate_run_id": candidate_run_id,
        "portal_image_digest": portal_image_digest,
        "origin": origin,
        "run_id_sha256": _sha256_bytes(run_id.encode("utf-8")),
        "started_at_utc": _utc(started),
        "completed_at_utc": _utc(completed),
        "backup_created_at_utc": _utc(backup_created),
        "source_backup_sha256": source_hash,
        "restored_snapshot_sha256": restored_hash,
        "integrity_query_sha256": query_hash,
        "integrity_result_sha256": result_hash,
        "records_expected": records_expected,
        "records_restored": records_restored,
        "steps": step_records,
    }
    root = _ensure_root(evidence_root)
    output = root / "backup-restore.json"
    with _root_lock(root):
        _atomic_write(output, _canonical_json(payload), replace_existing=False)
        _record_collected_artifact(
            evidence_root=root,
            artifact_path=output,
            release_commit=release_commit,
            candidate_run_id=candidate_run_id,
            portal_image_digest=portal_image_digest,
        )
    return output


def _artifact_record(path: Path) -> dict[str, object]:
    size = path.stat().st_size
    if not 0 < size <= 8 * 1024 * 1024:
        raise CollectionError("deployment evidence artifact size is outside policy")
    return {
        "path": path.name,
        "sha256": _sha256_file(path, "deployment evidence artifact"),
        "size_bytes": size,
    }


def write_schema2_manifest(
    *,
    evidence_root: Path,
    staging_origin_env: str,
    production_origin_env: str,
    release_commit: str,
    candidate_run_id: int,
    portal_image_digest: str,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Validate the five local payloads and atomically close schema 2."""

    _validate_bindings(
        release_commit=release_commit,
        candidate_run_id=candidate_run_id,
        portal_image_digest=portal_image_digest,
    )
    environment_values = os.environ if environ is None else environ
    staging_origin = _origin_from_environment(staging_origin_env, environment_values)
    production_origin = _origin_from_environment(
        production_origin_env, environment_values
    )
    if staging_origin == production_origin:
        raise CollectionError("staging and production origins must differ")
    root = _ensure_root(evidence_root)
    generated = _utc_now()
    manifest_path = root / "deployment-evidence.json"
    with _root_lock(root):
        children = [path for path in root.iterdir() if path.name != LOCK_NAME]
        actual = {
            path.name for path in children if path.is_file() and not path.is_symlink()
        }
        if (
            actual != CORE_PAYLOAD_FILES
            or any(path.is_symlink() or not path.is_file() for path in children)
        ):
            raise CollectionError(
                "schema 2 requires the exact five payload files and no extras"
            )
        _verify_collector_state(
            evidence_root=root,
            release_commit=release_commit,
            candidate_run_id=candidate_run_id,
            portal_image_digest=portal_image_digest,
        )
        try:
            _, staging_probe_end, staging_certificate = _validate_probe(
                root / "staging-probe.json",
                environment="staging",
                commit=release_commit,
                candidate_run_id=candidate_run_id,
                image_digest=portal_image_digest,
                origin=staging_origin,
                generated_at=generated,
            )
            _, production_probe_end, production_certificate = _validate_probe(
                root / "production-probe.json",
                environment="production",
                commit=release_commit,
                candidate_run_id=candidate_run_id,
                image_digest=portal_image_digest,
                origin=production_origin,
                generated_at=generated,
            )
            _, staging_observation_end = _validate_observations(
                root / "staging-observations.jsonl",
                environment="staging",
                commit=release_commit,
                candidate_run_id=candidate_run_id,
                image_digest=portal_image_digest,
                origin=staging_origin,
                certificate_sha256=staging_certificate,
                generated_at=generated,
            )
            _, production_observation_end = _validate_observations(
                root / "production-observations.jsonl",
                environment="production",
                commit=release_commit,
                candidate_run_id=candidate_run_id,
                image_digest=portal_image_digest,
                origin=production_origin,
                certificate_sha256=production_certificate,
                generated_at=generated,
            )
            if (
                generated - staging_probe_end > timedelta(hours=48)
                or generated - staging_observation_end > timedelta(minutes=90)
            ):
                raise ValueError("staging evidence is stale")
            if (
                generated - production_probe_end > timedelta(hours=6)
                or generated - production_observation_end > timedelta(minutes=30)
            ):
                raise ValueError("production evidence is stale")
            _validate_backup_restore(
                root / "backup-restore.json",
                commit=release_commit,
                candidate_run_id=candidate_run_id,
                image_digest=portal_image_digest,
                origin=staging_origin,
                generated_at=generated,
            )
        except (OSError, UnicodeError, ValueError) as exc:
            raise CollectionError("local deployment evidence failed schema validation") from exc
        artifacts = [_artifact_record(root / name) for name in sorted(CORE_PAYLOAD_FILES)]
        generated_at_utc = _utc(generated)
        manifest = {
            "schema": 2,
            "release_commit": release_commit,
            "candidate_run_id": candidate_run_id,
            "portal_image_digest": portal_image_digest,
            "staging_origin": staging_origin,
            "production_origin": production_origin,
            "generated_at_utc": generated_at_utc,
            "artifacts": artifacts,
            "collector_receipt": _build_collector_receipt(
                release_commit=release_commit,
                candidate_run_id=candidate_run_id,
                portal_image_digest=portal_image_digest,
                staging_origin=staging_origin,
                production_origin=production_origin,
                generated_at_utc=generated_at_utc,
                artifacts=artifacts,
            ),
        }
        _atomic_write(
            manifest_path,
            _canonical_json(manifest),
            replace_existing=False,
        )
    return manifest_path


def _add_bindings(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--candidate-run-id", type=int, required=True)
    parser.add_argument("--portal-image-digest", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="stage", required=True)

    probe = subparsers.add_parser("probe")
    _add_bindings(probe)
    probe.add_argument("--environment", choices=("staging", "production"), required=True)
    probe.add_argument("--origin-env", required=True)
    probe.add_argument("--plan", type=Path, required=True)
    probe.add_argument("--timeout-seconds", type=float, default=30)

    observation = subparsers.add_parser("observation")
    _add_bindings(observation)
    observation.add_argument(
        "--environment", choices=("staging", "production"), required=True
    )
    observation.add_argument("--origin-env", required=True)
    observation.add_argument("--health-path", default="/health")
    observation.add_argument("--http-timeout-seconds", type=float, default=30)

    backup = subparsers.add_parser("backup-restore")
    _add_bindings(backup)
    backup.add_argument("--origin-env", required=True)
    backup.add_argument("--run-id-env", required=True)
    backup.add_argument("--source-backup-path-env", required=True)
    backup.add_argument("--age-identity-path-env", required=True)
    backup.add_argument("--checksum-path-env", required=True)
    backup.add_argument("--command-timeout-seconds", type=float, default=3600)

    manifest = subparsers.add_parser("manifest")
    _add_bindings(manifest)
    manifest.add_argument("--staging-origin-env", required=True)
    manifest.add_argument("--production-origin-env", required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    common = {
        "evidence_root": args.evidence_root,
        "release_commit": args.release_commit,
        "candidate_run_id": args.candidate_run_id,
        "portal_image_digest": args.portal_image_digest,
    }
    if args.stage == "probe":
        output = collect_probe(
            **common,
            environment=args.environment,
            origin_env=args.origin_env,
            plan_path=args.plan,
            timeout_seconds=args.timeout_seconds,
        )
    elif args.stage == "observation":
        output = collect_observation(
            **common,
            environment=args.environment,
            origin_env=args.origin_env,
            health_path=args.health_path,
            http_timeout_seconds=args.http_timeout_seconds,
        )
    elif args.stage == "backup-restore":
        output = collect_backup_restore(
            **common,
            origin_env=args.origin_env,
            run_id_env=args.run_id_env,
            source_backup_path_env=args.source_backup_path_env,
            age_identity_path_env=args.age_identity_path_env,
            checksum_path_env=args.checksum_path_env,
            command_timeout_seconds=args.command_timeout_seconds,
        )
    else:
        output = write_schema2_manifest(
            **common,
            staging_origin_env=args.staging_origin_env,
            production_origin_env=args.production_origin_env,
        )
    print(f"deployment-evidence-{args.stage}: COLLECTED ({output.name})")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CollectionError as exc:
        print(f"deployment evidence collection failed: {exc}", file=os.sys.stderr)
        raise SystemExit(70)
