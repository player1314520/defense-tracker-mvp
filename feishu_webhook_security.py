# -*- coding: utf-8 -*-
"""Shared fail-closed controls for Feishu event callbacks.

Only opaque event identifiers are persisted, as SHA-256 digests with expiry.
Message bodies, chat identifiers, filenames and user content never enter the
deduplication database or its error messages.
"""
from __future__ import annotations

import hashlib
import hmac
import base64
import binascii
import functools
import json
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Mapping


MAX_WEBHOOK_BODY_BYTES = 2 * 1024 * 1024


class WebhookRejected(ValueError):
    """A caller-controlled webhook failed authentication or schema checks."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class WebhookMisconfigured(RuntimeError):
    """A required production-side webhook control is unavailable."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _env_true(name: str) -> bool:
    return (os.environ.get(name) or "").strip().casefold() in {"1", "true", "yes", "on"}


def token_only_development_enabled() -> bool:
    """Legacy token-only callbacks require an explicit development opt-in."""
    return _env_true("FEISHU_WEBHOOK_ALLOW_TOKEN_ONLY")


def signature_max_skew_seconds() -> int:
    raw = (os.environ.get("FEISHU_WEBHOOK_MAX_SKEW_SECONDS") or "300").strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise WebhookMisconfigured("invalid_signature_freshness_config") from exc
    if value < 30 or value > 900:
        raise WebhookMisconfigured("invalid_signature_freshness_config")
    return value


def verify_signed_request(
    headers: Mapping[str, str],
    body: bytes,
    *,
    signing_key: str,
    now: float | None = None,
    allow_token_only: bool | None = None,
) -> None:
    """Require a complete, fresh and valid X-Lark signature by default.

    Feishu event callbacks use the configured event Encrypt Key as the signing
    key.  Verification Token remains an independent field in the JSON payload.
    Official reference: https://open.feishu.cn/document/server-docs/
    event-subscription-guide/event-subscription-configure-/
    encrypt-key-encryption-configuration-case
    """
    if allow_token_only is None:
        allow_token_only = token_only_development_enabled()
    signature = str(headers.get("X-Lark-Signature") or "").strip()
    timestamp = str(headers.get("X-Lark-Request-Timestamp") or "").strip()
    nonce = str(headers.get("X-Lark-Request-Nonce") or "").strip()

    if not signature and allow_token_only:
        return
    if not signing_key:
        raise WebhookMisconfigured("signature_key_not_configured")
    if not all((signature, timestamp, nonce)):
        raise WebhookRejected("signature_headers_missing")
    try:
        request_time = int(timestamp)
    except ValueError as exc:
        raise WebhookRejected("signature_timestamp_invalid") from exc
    current_time = int(time.time() if now is None else now)
    if abs(current_time - request_time) > signature_max_skew_seconds():
        raise WebhookRejected("signature_timestamp_stale")

    signed = (timestamp + nonce + signing_key).encode("utf-8") + bytes(body)
    expected = hashlib.sha256(signed).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise WebhookRejected("signature_invalid")


def decrypt_event_payload(data: dict, *, encrypt_key: str) -> dict:
    """Decrypt the optional Feishu ``encrypt`` envelope with AES-256-CBC."""
    encrypted = data.get("encrypt")
    if encrypted is None or encrypted == "":
        return data
    if not encrypt_key:
        raise WebhookMisconfigured("event_decryption_key_not_configured")
    if not isinstance(encrypted, str) or len(encrypted) > 4 * 1024 * 1024:
        raise WebhookRejected("event_envelope_invalid")
    try:
        ciphertext = base64.b64decode(encrypted, validate=True)
    except (binascii.Error, ValueError):
        raise WebhookRejected("event_envelope_invalid") from None
    if len(ciphertext) < 32 or len(ciphertext) % 16:
        raise WebhookRejected("event_envelope_invalid")
    try:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        key = hashlib.sha256(encrypt_key.encode("utf-8")).digest()
        decryptor = Cipher(algorithms.AES(key), modes.CBC(ciphertext[:16])).decryptor()
        padded = decryptor.update(ciphertext[16:]) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
    except ImportError as exc:
        raise WebhookMisconfigured("event_decryption_unavailable") from exc
    except (TypeError, ValueError):
        raise WebhookRejected("event_envelope_invalid") from None
    if len(plaintext) > 2 * 1024 * 1024:
        raise WebhookRejected("event_envelope_too_large")
    try:
        decoded = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise WebhookRejected("event_envelope_invalid") from None
    if not isinstance(decoded, dict):
        raise WebhookRejected("event_envelope_invalid")
    return decoded


def validate_event_identity(
    data: dict,
    *,
    expected_app_id: str,
    expected_tenant_key: str,
    allow_legacy: bool | None = None,
) -> dict:
    """Validate schema 2.0 application and tenant binding.

    Production mode requires both bindings.  Explicit token-only development
    mode accepts older fixtures, but still rejects a conflicting field when it
    is present.
    """
    if allow_legacy is None:
        allow_legacy = token_only_development_enabled()
    header = data.get("header")
    if not isinstance(header, dict):
        raise WebhookRejected("event_header_missing")
    app_id = str(header.get("app_id") or "").strip()
    tenant_key = str(header.get("tenant_key") or "").strip()
    schema = str(data.get("schema") or "").strip()

    if allow_legacy:
        if app_id and expected_app_id and not hmac.compare_digest(expected_app_id, app_id):
            raise WebhookRejected("event_app_mismatch")
        if tenant_key and expected_tenant_key and not hmac.compare_digest(expected_tenant_key, tenant_key):
            raise WebhookRejected("event_tenant_mismatch")
        return header

    if schema != "2.0":
        raise WebhookRejected("event_schema_invalid")
    if not expected_app_id:
        raise WebhookMisconfigured("expected_app_not_configured")
    if not expected_tenant_key:
        raise WebhookMisconfigured("expected_tenant_not_configured")
    if not app_id or not hmac.compare_digest(expected_app_id, app_id):
        raise WebhookRejected("event_app_mismatch")
    if not tenant_key or not hmac.compare_digest(expected_tenant_key, tenant_key):
        raise WebhookRejected("event_tenant_mismatch")
    return header


def event_id_from_payload(data: dict, *, allow_legacy: bool | None = None) -> str:
    if allow_legacy is None:
        allow_legacy = token_only_development_enabled()
    header = data.get("header") if isinstance(data.get("header"), dict) else {}
    event_id = str(header.get("event_id") or "").strip()
    if event_id:
        return event_id
    if allow_legacy:
        event = data.get("event") if isinstance(data.get("event"), dict) else {}
        message = event.get("message") if isinstance(event.get("message"), dict) else {}
        return str(message.get("message_id") or "").strip()
    raise WebhookRejected("event_id_missing")


def _default_store_path() -> Path:
    explicit_file = (os.environ.get("FEISHU_DEDUPE_DB") or "").strip()
    if explicit_file:
        path = Path(explicit_file).expanduser()
        if not path.is_absolute():
            raise WebhookMisconfigured("dedupe_path_must_be_absolute")
        return path.resolve()

    explicit_root = (
        os.environ.get("FEISHU_RUNTIME_DIR")
        or os.environ.get("DEFENSE_TRACKER_HOME")
        or ""
    ).strip()
    if explicit_root:
        root = Path(explicit_root).expanduser()
        if not root.is_absolute():
            raise WebhookMisconfigured("dedupe_path_must_be_absolute")
        return (root / "data" / "feishu-event-dedupe.sqlite3").resolve()

    if os.name == "nt":
        root_text = (os.environ.get("LOCALAPPDATA") or "").strip()
        if not root_text:
            raise WebhookMisconfigured("dedupe_runtime_not_configured")
        root = Path(root_text) / "DefenseTracker"
    else:
        state_home = (os.environ.get("XDG_STATE_HOME") or "").strip()
        root = Path(state_home) / "defense-tracker" if state_home else Path.home() / ".local" / "state" / "defense-tracker"
    return (root / "feishu-event-dedupe.sqlite3").resolve()


def resolve_dedupe_store_path() -> Path:
    path = _default_store_path()
    source_root = Path(__file__).resolve().parent
    try:
        path.relative_to(source_root)
    except ValueError:
        return path
    raise WebhookMisconfigured("dedupe_store_must_not_be_in_source_tree")


class EventLease:
    """Opaque ownership token for one webhook delivery attempt.

    The raw Feishu event identifier is never retained.  A lease may be handed
    to a worker, completed after successful processing, or released so Feishu's
    retry can acquire it again.
    """

    def __init__(self, store: "PersistentEventDeduper", event_hash: str, token: str):
        self._store = store
        self._event_hash = event_hash
        self._token = token
        self._lock = threading.Lock()
        self._closed = False
        self._handed_off = False

    def _mark_handed_off(self) -> None:
        with self._lock:
            self._handed_off = True

    def complete(self, *, now: float | None = None) -> bool:
        with self._lock:
            if self._closed:
                return False
            completed = self._store._complete(
                self._event_hash, self._token, now=now,
            )
            self._closed = True
            return completed

    def release(self) -> bool:
        with self._lock:
            if self._closed:
                return False
            released = self._store._release(self._event_hash, self._token)
            self._closed = True
            return released

    def __enter__(self) -> "EventLease":
        return self

    def __exit__(self, exc_type, _exc, _traceback) -> bool:
        with self._lock:
            if self._closed or self._handed_off:
                return False
        if exc_type is None:
            self.complete()
        else:
            self.release()
        return False


class PersistentEventDeduper:
    def __init__(
        self,
        path: Path,
        *,
        ttl_seconds: int,
        max_entries: int,
        lease_seconds: int = 900,
    ):
        self.path = Path(path)
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self.lease_seconds = lease_seconds
        self._lock = threading.Lock()

    def _prepare_parent(self) -> None:
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if os.name != "nt":
                os.chmod(self.path.parent, 0o700)
        except OSError as exc:
            raise WebhookMisconfigured("dedupe_store_unavailable") from exc

    @staticmethod
    def _event_hash(event_id: str) -> str:
        if not event_id or len(event_id) > 512:
            raise WebhookRejected("event_id_invalid")
        return hashlib.sha256(event_id.encode("utf-8")).hexdigest()

    @staticmethod
    def _ensure_schema(connection: sqlite3.Connection) -> None:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS event_deliveries ("
            "event_hash TEXT PRIMARY KEY NOT NULL, "
            "state TEXT NOT NULL CHECK (state IN ('leased', 'completed')), "
            "claim_token TEXT, "
            "updated_at INTEGER NOT NULL, "
            "lease_expires_at INTEGER, "
            "completed_at INTEGER) WITHOUT ROWID"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS event_dedupe_meta ("
            "meta_key TEXT PRIMARY KEY NOT NULL, "
            "meta_value TEXT NOT NULL) WITHOUT ROWID"
        )
        # Safe one-way compatibility with the previous seen-events table.
        # Existing rows represented acknowledged deliveries, so importing them
        # as completed prevents an upgrade from replaying already handled work.
        migrated = connection.execute(
            "SELECT 1 FROM event_dedupe_meta WHERE meta_key='seen_events_migrated'"
        ).fetchone()
        if migrated:
            return
        legacy_exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='seen_events'"
        ).fetchone()
        if legacy_exists:
            connection.execute(
                "INSERT OR IGNORE INTO event_deliveries("
                "event_hash, state, claim_token, updated_at, lease_expires_at, completed_at) "
                "SELECT event_hash, 'completed', NULL, seen_at, NULL, seen_at FROM seen_events"
            )
        connection.execute(
            "INSERT INTO event_dedupe_meta(meta_key, meta_value) "
            "VALUES ('seen_events_migrated', '1')"
        )

    def _open(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=5, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA secure_delete=ON")
        return connection

    @staticmethod
    def _rollback(connection: sqlite3.Connection | None) -> None:
        if connection is None:
            return
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def acquire(self, event_id: str, *, now: float | None = None) -> EventLease | None:
        digest = self._event_hash(event_id)
        acquired_at = int(time.time() if now is None else now)
        cutoff = acquired_at - self.ttl_seconds
        lease_expires_at = acquired_at + self.lease_seconds
        claim_token = secrets.token_hex(32)
        self._prepare_parent()

        with self._lock:
            connection: sqlite3.Connection | None = None
            try:
                connection = self._open()
                connection.execute("BEGIN IMMEDIATE")
                self._ensure_schema(connection)
                connection.execute(
                    "DELETE FROM event_deliveries "
                    "WHERE state='completed' AND completed_at < ?",
                    (cutoff,),
                )
                connection.execute(
                    "DELETE FROM event_deliveries "
                    "WHERE state='leased' AND lease_expires_at <= ?",
                    (acquired_at,),
                )
                row = connection.execute(
                    "SELECT state, lease_expires_at FROM event_deliveries WHERE event_hash=?",
                    (digest,),
                ).fetchone()
                if row is not None and row[0] == "completed":
                    connection.execute("COMMIT")
                    return None
                if row is not None and row[0] == "leased" and int(row[1] or 0) > acquired_at:
                    connection.execute("COMMIT")
                    return None

                if row is None:
                    count = connection.execute(
                        "SELECT COUNT(*) FROM event_deliveries"
                    ).fetchone()[0]
                    if count >= self.max_entries:
                        connection.execute(
                            "DELETE FROM event_deliveries WHERE event_hash IN ("
                            "SELECT event_hash FROM event_deliveries "
                            "WHERE state='completed' ORDER BY completed_at ASC LIMIT ?)",
                            (count - self.max_entries + 1,),
                        )
                    count = connection.execute(
                        "SELECT COUNT(*) FROM event_deliveries"
                    ).fetchone()[0]
                    if count >= self.max_entries:
                        raise WebhookMisconfigured("dedupe_store_capacity_exceeded")
                    connection.execute(
                        "INSERT INTO event_deliveries("
                        "event_hash, state, claim_token, updated_at, lease_expires_at, completed_at) "
                        "VALUES (?, 'leased', ?, ?, ?, NULL)",
                        (digest, claim_token, acquired_at, lease_expires_at),
                    )
                else:
                    cursor = connection.execute(
                        "UPDATE event_deliveries SET state='leased', claim_token=?, "
                        "updated_at=?, lease_expires_at=?, completed_at=NULL "
                        "WHERE event_hash=? AND state='leased' AND lease_expires_at <= ?",
                        (
                            claim_token,
                            acquired_at,
                            lease_expires_at,
                            digest,
                            acquired_at,
                        ),
                    )
                    if cursor.rowcount != 1:
                        connection.execute("COMMIT")
                        return None
                connection.execute("COMMIT")
            except WebhookMisconfigured:
                self._rollback(connection)
                raise
            except sqlite3.Error as exc:
                self._rollback(connection)
                raise WebhookMisconfigured("dedupe_store_unavailable") from exc
            finally:
                if connection is not None:
                    connection.close()
            try:
                if os.name != "nt":
                    os.chmod(self.path, 0o600)
            except OSError:
                pass
            return EventLease(self, digest, claim_token)

    def _complete(
        self,
        event_hash: str,
        claim_token: str,
        *,
        now: float | None = None,
    ) -> bool:
        completed_at = int(time.time() if now is None else now)
        return self._finish(
            "UPDATE event_deliveries SET state='completed', claim_token=NULL, "
            "updated_at=?, lease_expires_at=NULL, completed_at=? "
            "WHERE event_hash=? AND state='leased' AND claim_token=?",
            (completed_at, completed_at, event_hash, claim_token),
        )

    def _release(self, event_hash: str, claim_token: str) -> bool:
        return self._finish(
            "DELETE FROM event_deliveries "
            "WHERE event_hash=? AND state='leased' AND claim_token=?",
            (event_hash, claim_token),
        )

    def _finish(self, statement: str, parameters: tuple) -> bool:
        self._prepare_parent()
        with self._lock:
            connection: sqlite3.Connection | None = None
            try:
                connection = self._open()
                connection.execute("BEGIN IMMEDIATE")
                self._ensure_schema(connection)
                cursor = connection.execute(statement, parameters)
                connection.execute("COMMIT")
                return cursor.rowcount == 1
            except sqlite3.Error as exc:
                self._rollback(connection)
                raise WebhookMisconfigured("dedupe_store_unavailable") from exc
            finally:
                if connection is not None:
                    connection.close()

    def check_and_record(self, event_id: str, *, now: float | None = None) -> bool:
        """Compatibility helper with the former immediate-completion semantics."""
        lease = self.acquire(event_id, now=now)
        if lease is None:
            return False
        lease.complete(now=now)
        return True


_DEDUPERS: dict[tuple[str, int, int, int], PersistentEventDeduper] = {}
_DEDUPERS_LOCK = threading.Lock()


def _dedupe_settings() -> tuple[int, int, int]:
    try:
        ttl = int((os.environ.get("FEISHU_DEDUPE_TTL_SECONDS") or "86400").strip())
        maximum = int((os.environ.get("FEISHU_DEDUPE_MAX_EVENTS") or "100000").strip())
        lease = int((os.environ.get("FEISHU_EVENT_LEASE_SECONDS") or "900").strip())
    except ValueError as exc:
        raise WebhookMisconfigured("invalid_dedupe_config") from exc
    if (
        ttl < 300
        or ttl > 7 * 86400
        or maximum < 1000
        or maximum > 1_000_000
        or lease < 30
        or lease > 3600
    ):
        raise WebhookMisconfigured("invalid_dedupe_config")
    return ttl, maximum, lease


def check_and_record_event(data: dict, *, allow_legacy: bool | None = None) -> bool:
    """Compatibility helper. New webhook handlers should acquire a lease."""
    lease = acquire_event_lease(data, allow_legacy=allow_legacy)
    if lease is None:
        return False
    lease.complete()
    return True


def acquire_event_lease(
    data: dict,
    *,
    allow_legacy: bool | None = None,
) -> EventLease | None:
    event_id = event_id_from_payload(data, allow_legacy=allow_legacy)
    path = resolve_dedupe_store_path()
    ttl, maximum, lease_seconds = _dedupe_settings()
    key = (str(path), ttl, maximum, lease_seconds)
    with _DEDUPERS_LOCK:
        deduper = _DEDUPERS.get(key)
        if deduper is None:
            deduper = PersistentEventDeduper(
                path,
                ttl_seconds=ttl,
                max_entries=maximum,
                lease_seconds=lease_seconds,
            )
            _DEDUPERS[key] = deduper
    return deduper.acquire(event_id)


def submit_leased_event(executor, lease: EventLease, function, *args, **kwargs):
    """Submit work without acknowledging the event until the worker returns.

    Submission failure releases the claim immediately.  Worker failure also
    releases it; a process crash leaves a bounded lease that another Feishu
    retry can take over after expiry.
    """

    @functools.wraps(function)
    def _run(*worker_args, **worker_kwargs):
        try:
            result = function(*worker_args, **worker_kwargs)
        except BaseException:
            lease.release()
            raise
        lease.complete()
        return result

    try:
        future = executor.submit(_run, *args, **kwargs)
    except Exception as exc:
        lease.release()
        raise WebhookMisconfigured("event_dispatch_unavailable") from exc
    lease._mark_handed_off()
    return future
