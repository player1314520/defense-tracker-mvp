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
import re
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping


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


class WebhookRateLimited(RuntimeError):
    """A verified actor exceeded one of the bounded admission budgets."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class WebhookCapacityUnavailable(RuntimeError):
    """The bounded worker admission pool has no free lease."""

    def __init__(self, code: str = "webhook_capacity_exhausted"):
        self.code = code
        super().__init__(code)


def _env_true(name: str) -> bool:
    return (os.environ.get(name) or "").strip().casefold() in {"1", "true", "yes", "on"}


def token_only_development_enabled() -> bool:
    """Legacy token-only callbacks require an explicit development opt-in."""
    return _env_true("FEISHU_WEBHOOK_ALLOW_TOKEN_ONLY")


_ACTOR_ID_KINDS = ("open_id", "user_id", "union_id")
_ACTOR_VALUE_RE = re.compile(r"\A[A-Za-z0-9._-]{1,256}\Z")
_MAX_ALLOWLIST_CHARS = 8192
_MAX_ALLOWLIST_ENTRIES = 1000


@dataclass(frozen=True)
class WebhookActor:
    """Canonical, signed Feishu actor identity used by authorization and quotas."""

    sender_ids: tuple[str, ...]
    chat_id: str
    is_admin: bool

    @property
    def primary_sender(self) -> str:
        return self.sender_ids[0]


def _validated_actor_value(value, *, code: str) -> str:
    if not isinstance(value, str):
        raise WebhookRejected(code)
    normalized = value.strip()
    if not _ACTOR_VALUE_RE.fullmatch(normalized):
        raise WebhookRejected(code)
    return normalized


def extract_event_actor(data: dict) -> WebhookActor:
    """Extract the sender namespace IDs and chat ID from a signed event.

    Values are never guessed from message content or request headers.  Each
    sender ID retains its namespace so an allowlisted user ID cannot collide
    with an open ID or union ID that happens to contain the same text.
    """
    event = data.get("event") if isinstance(data, dict) else None
    if not isinstance(event, dict):
        raise WebhookRejected("event_actor_missing")
    message = event.get("message")
    if not isinstance(message, dict):
        raise WebhookRejected("event_message_missing")
    chat_id = _validated_actor_value(
        message.get("chat_id"), code="event_chat_id_invalid",
    )

    sender = event.get("sender")
    sender_ids = sender.get("sender_id") if isinstance(sender, dict) else None
    if not isinstance(sender_ids, dict):
        raise WebhookRejected("event_sender_missing")
    canonical = []
    for kind in _ACTOR_ID_KINDS:
        raw = sender_ids.get(kind)
        if raw in (None, ""):
            continue
        canonical.append(
            f"{kind}:{_validated_actor_value(raw, code='event_sender_invalid')}"
        )
    if not canonical:
        raise WebhookRejected("event_sender_missing")
    return WebhookActor(tuple(canonical), chat_id, False)


def _parse_authorization_allowlist(name: str, *, sender_ids: bool) -> frozenset[str]:
    raw = os.environ.get(name) or ""
    if len(raw) > _MAX_ALLOWLIST_CHARS:
        raise WebhookMisconfigured("invalid_authorization_allowlist")
    entries = [part for part in re.split(r"[,;\s]+", raw.strip()) if part]
    if len(entries) > _MAX_ALLOWLIST_ENTRIES:
        raise WebhookMisconfigured("invalid_authorization_allowlist")

    parsed = set()
    for entry in entries:
        if sender_ids:
            kind, separator, value = entry.partition(":")
            if not separator or kind not in _ACTOR_ID_KINDS:
                raise WebhookMisconfigured("invalid_authorization_allowlist")
        else:
            if entry.startswith("chat_id:"):
                value = entry.removeprefix("chat_id:")
            elif ":" in entry:
                raise WebhookMisconfigured("invalid_authorization_allowlist")
            else:
                value = entry
            kind = "chat_id"
        if not _ACTOR_VALUE_RE.fullmatch(value):
            raise WebhookMisconfigured("invalid_authorization_allowlist")
        parsed.add(f"{kind}:{value}" if sender_ids else value)
    return frozenset(parsed)


def authorize_event_actor(
    data: dict,
    *,
    require_admin: bool = False,
    allow_unlisted_development: bool | None = None,
) -> WebhookActor:
    """Authorize a signed event against explicit sender/chat allowlists.

    Production is fail-closed.  The compatibility bypass requires two explicit
    development flags and never grants administrator privileges.  A sender
    identity is mandatory even when that development bypass is enabled.
    """
    actor = extract_event_actor(data)
    allowed_senders = _parse_authorization_allowlist(
        "FEISHU_ALLOWED_SENDER_IDS", sender_ids=True,
    )
    allowed_chats = _parse_authorization_allowlist(
        "FEISHU_ALLOWED_CHAT_IDS", sender_ids=False,
    )
    admin_senders = _parse_authorization_allowlist(
        "FEISHU_ADMIN_SENDER_IDS", sender_ids=True,
    )
    configured_development_bypass = (
        token_only_development_enabled()
        and _env_true("FEISHU_AUTH_ALLOW_UNLISTED_DEV")
    )
    if allow_unlisted_development is None:
        allow_unlisted_development = configured_development_bypass
    else:
        allow_unlisted_development = (
            bool(allow_unlisted_development) and configured_development_bypass
        )

    identity_set = frozenset(actor.sender_ids)
    is_admin = bool(identity_set & admin_senders)
    is_allowed = bool(
        is_admin
        or identity_set & allowed_senders
        or actor.chat_id in allowed_chats
    )
    if not allowed_senders and not allowed_chats and not admin_senders:
        if not allow_unlisted_development:
            raise WebhookMisconfigured("authorization_allowlist_not_configured")
        is_allowed = True
    elif not is_allowed and allow_unlisted_development:
        is_allowed = True
    if not is_allowed:
        raise WebhookRejected("event_actor_not_allowed")
    if require_admin and not is_admin:
        raise WebhookRejected("event_admin_required")
    return WebhookActor(actor.sender_ids, actor.chat_id, is_admin)


@dataclass(frozen=True)
class WebhookAdmissionLimits:
    window_seconds: int = 60
    sender_events: int = 12
    chat_events: int = 30
    global_events: int = 120
    sender_cost: int = 48
    chat_cost: int = 120
    global_cost: int = 480
    max_inflight: int = 8


class WebhookAdmissionLease:
    """Idempotent ownership token for one bounded concurrent work slot."""

    def __init__(self, controller: "WebhookAdmissionController"):
        self._controller = controller
        self._lock = threading.Lock()
        self._released = False
        self._handed_off = False

    @property
    def handed_off(self) -> bool:
        with self._lock:
            return self._handed_off

    def mark_handed_off(self) -> None:
        with self._lock:
            self._handed_off = True

    def release(self) -> bool:
        with self._lock:
            if self._released:
                return False
            self._released = True
        self._controller._release_slot()
        return True

    def __enter__(self) -> "WebhookAdmissionLease":
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> bool:
        self.release()
        return False


class WebhookAdmissionController:
    """Atomic per-sender/chat/global sliding-window and concurrency gate."""

    def __init__(
        self,
        limits: WebhookAdmissionLimits,
        *,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not isinstance(limits, WebhookAdmissionLimits):
            raise TypeError("limits must be WebhookAdmissionLimits")
        numeric_limits = (
            limits.window_seconds,
            limits.sender_events,
            limits.chat_events,
            limits.global_events,
            limits.sender_cost,
            limits.chat_cost,
            limits.global_cost,
            limits.max_inflight,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 1
               for value in numeric_limits):
            raise WebhookMisconfigured("invalid_admission_config")
        self.limits = limits
        self._clock = clock
        self._lock = threading.Lock()
        self._events: dict[tuple[str, str], deque[tuple[float, int]]] = {}
        self._inflight = 0
        self._next_cleanup = 0.0

    @property
    def inflight(self) -> int:
        with self._lock:
            return self._inflight

    def _release_slot(self) -> None:
        with self._lock:
            if self._inflight <= 0:
                raise RuntimeError("admission lease accounting underflow")
            self._inflight -= 1

    def acquire(self, actor: WebhookActor, *, cost: int) -> WebhookAdmissionLease:
        if not isinstance(actor, WebhookActor) or not actor.sender_ids or not actor.chat_id:
            raise WebhookMisconfigured("invalid_admission_actor")
        if isinstance(cost, bool) or not isinstance(cost, int) or cost < 1:
            raise WebhookMisconfigured("invalid_admission_cost")
        now = self._clock()
        cutoff = now - self.limits.window_seconds
        sender_scopes = tuple(("sender", sender_id) for sender_id in actor.sender_ids)
        scopes = sender_scopes + (("chat", actor.chat_id), ("global", "all"))
        event_limits = (
            (self.limits.sender_events,) * len(sender_scopes)
            + (self.limits.chat_events, self.limits.global_events)
        )
        cost_limits = (
            (self.limits.sender_cost,) * len(sender_scopes)
            + (self.limits.chat_cost, self.limits.global_cost)
        )
        event_codes = (
            ("sender_rate_limit",) * len(sender_scopes)
            + ("chat_rate_limit", "global_rate_limit")
        )
        cost_codes = (
            ("sender_cost_limit",) * len(sender_scopes)
            + ("chat_cost_limit", "global_cost_limit")
        )

        with self._lock:
            if now >= self._next_cleanup:
                for scope, bucket in tuple(self._events.items()):
                    while bucket and bucket[0][0] <= cutoff:
                        bucket.popleft()
                    if not bucket:
                        del self._events[scope]
                self._next_cleanup = now + min(self.limits.window_seconds, 60)
            buckets = []
            for scope in scopes:
                bucket = self._events.get(scope)
                if bucket is None:
                    bucket = deque()
                while bucket and bucket[0][0] <= cutoff:
                    bucket.popleft()
                buckets.append(bucket)
            for index, bucket in enumerate(buckets):
                if len(bucket) + 1 > event_limits[index]:
                    raise WebhookRateLimited(event_codes[index])
                if sum(item_cost for _timestamp, item_cost in bucket) + cost > cost_limits[index]:
                    raise WebhookRateLimited(cost_codes[index])
            if self._inflight >= self.limits.max_inflight:
                raise WebhookCapacityUnavailable()
            for scope, bucket in zip(scopes, buckets):
                self._events[scope] = bucket
                bucket.append((now, cost))
            self._inflight += 1
        return WebhookAdmissionLease(self)


def _bounded_environment_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = (os.environ.get(name) or str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise WebhookMisconfigured("invalid_admission_config") from exc
    if value < minimum or value > maximum:
        raise WebhookMisconfigured("invalid_admission_config")
    return value


def load_webhook_admission_controller() -> WebhookAdmissionController:
    limits = WebhookAdmissionLimits(
        window_seconds=_bounded_environment_int(
            "FEISHU_RATE_WINDOW_SECONDS", 60, 1, 3600,
        ),
        sender_events=_bounded_environment_int(
            "FEISHU_RATE_SENDER_EVENTS", 12, 1, 10_000,
        ),
        chat_events=_bounded_environment_int(
            "FEISHU_RATE_CHAT_EVENTS", 30, 1, 50_000,
        ),
        global_events=_bounded_environment_int(
            "FEISHU_RATE_GLOBAL_EVENTS", 120, 1, 100_000,
        ),
        sender_cost=_bounded_environment_int(
            "FEISHU_COST_SENDER_LIMIT", 48, 1, 100_000,
        ),
        chat_cost=_bounded_environment_int(
            "FEISHU_COST_CHAT_LIMIT", 120, 1, 500_000,
        ),
        global_cost=_bounded_environment_int(
            "FEISHU_COST_GLOBAL_LIMIT", 480, 1, 1_000_000,
        ),
        max_inflight=_bounded_environment_int(
            "FEISHU_MAX_INFLIGHT_JOBS", 8, 1, 64,
        ),
    )
    return WebhookAdmissionController(limits)


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
