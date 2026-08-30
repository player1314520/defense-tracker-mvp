"""Client-side PKCE and ciphertext-only synchronization helpers."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
import uuid
from typing import Any
from urllib.parse import urlencode

from .errors import UntrustedSyncEvent


_FORBIDDEN_PLAINTEXT_KEYS = {
    "body",
    "content",
    "document_body",
    "evidence_body",
    "original_text",
    "plaintext",
    "report_body",
    "text",
}
_REQUIRED_EVENT_KEYS = {
    "event_id",
    "organization_id",
    "record_id",
    "operation",
    "payload",
}
_REQUIRED_PAYLOAD_KEYS = {
    "organization_id",
    "record_id",
    "record_type",
    "version",
    "version_id",
    "base_version_id",
    "key_version",
    "ciphertext",
    "nonce",
    "wrapped_data_key",
    "wrap_nonce",
    "content_hash",
    "device_id",
    "deleted",
}
_ALLOWED_EVENT_KEYS = _REQUIRED_EVENT_KEYS | {"cursor", "applied"}
_ALLOWED_PAYLOAD_KEYS = _REQUIRED_PAYLOAD_KEYS | {"updated_at"}
_MAX_RECORD_CIPHERTEXT_BYTES = (1 * 1024 * 1024) + 16
_MAX_SYNC_EVENT_BYTES = 24 * 1024 * 1024
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")


class SupabaseCoordinator:
    """Ciphertext-only RPC adapter for the Supabase sync log."""

    def __init__(self, session_manager, *, page_size: int = 200):
        self.session_manager = session_manager
        self.page_size = min(500, max(1, int(page_size)))

    def push(self, event: dict) -> dict:
        return self.session_manager.rpc(
            "push_record_event",
            {"p_event": event},
        )

    def pull(self, organization_id: str, after_cursor: int) -> list[dict]:
        cursor = max(0, int(after_cursor))
        rows = self.session_manager.rpc(
            "pull_sync_events",
            {
                "organization_id": organization_id,
                "after_cursor": cursor,
                "page_size": self.page_size,
            },
        ) or []
        events = []
        for row in rows:
            payload = row.get("payload")
            events.append({
                "cursor": row["cursor"],
                "event_id": row["event_id"],
                "organization_id": organization_id,
                "record_id": (
                    payload.get("record_id")
                    if isinstance(payload, dict)
                    else None
                ),
                "operation": row["operation"],
                "applied": row.get("applied", True),
                "payload": payload,
            })
        return events


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def create_pkce_request(
    supabase_url: str,
    redirect_uri: str,
    *,
    client_id: str = "defense-tracker-desktop",
    scope: str = "openid email profile",
) -> dict[str, str]:
    """Create an OAuth authorization request while retaining the verifier locally."""
    base_url = str(supabase_url or "").strip().rstrip("/")
    callback = str(redirect_uri or "").strip()
    if not base_url.startswith("https://"):
        raise ValueError("Supabase URL must use HTTPS")
    if not callback:
        raise ValueError("redirect_uri is required")
    verifier = _b64url(secrets.token_bytes(48))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    state = _b64url(secrets.token_bytes(24))
    query = urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": callback,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "scope": scope,
        }
    )
    return {
        "authorization_url": f"{base_url}/auth/v1/oauth/authorize?{query}",
        "code_verifier": verifier,
        "state": state,
    }


def _reject_plaintext(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in _FORBIDDEN_PLAINTEXT_KEYS:
                raise ValueError("云同步边界检测到明文字段")
            _reject_plaintext(child)
    elif isinstance(value, list):
        for child in value:
            _reject_plaintext(child)


def _decode_ciphertext_field(
    value: Any,
    field: str,
    *,
    exact_size: int | None = None,
    min_size: int | None = None,
    max_size: int | None = None,
) -> bytes:
    if not isinstance(value, str) or not _BASE64URL.fullmatch(value):
        raise ValueError(f"{field} must be canonical base64url text")
    if max_size is not None and len(value) > ((max_size + 2) // 3) * 4:
        raise ValueError(f"{field} exceeds encrypted record limit")
    try:
        decoded = base64.b64decode(
            value + ("=" * (-len(value) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error):
        raise ValueError(f"{field} must be canonical base64url text") from None
    if _b64url(decoded) != value:
        raise ValueError(f"{field} must be canonical base64url text")
    if exact_size is not None and len(decoded) != exact_size:
        raise ValueError(f"{field} has invalid encrypted length")
    if min_size is not None and len(decoded) < min_size:
        raise ValueError(f"{field} has invalid encrypted length")
    if max_size is not None and len(decoded) > max_size:
        raise ValueError(f"{field} exceeds encrypted record limit")
    return decoded


def validate_ciphertext_event(event: dict) -> dict:
    """Validate and detach a ciphertext event before any network call."""
    if not isinstance(event, dict):
        raise ValueError("encrypted event must be an object")
    try:
        event_bytes = len(json.dumps(
            event,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8"))
    except (TypeError, ValueError):
        raise ValueError("encrypted event must be JSON serializable") from None
    if event_bytes > _MAX_SYNC_EVENT_BYTES:
        raise ValueError("encrypted event exceeds sync size limit")
    _reject_plaintext(event)
    missing = _REQUIRED_EVENT_KEYS.difference(event)
    if missing:
        raise ValueError(f"encrypted event missing fields: {sorted(missing)}")
    extra = set(event).difference(_ALLOWED_EVENT_KEYS)
    if extra:
        raise ValueError(f"encrypted event has unsupported fields: {sorted(extra)}")
    payload = event.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("encrypted payload must be an object")
    missing_payload = _REQUIRED_PAYLOAD_KEYS.difference(payload)
    if missing_payload:
        raise ValueError(
            f"encrypted payload missing fields: {sorted(missing_payload)}"
        )
    extra_payload = set(payload).difference(_ALLOWED_PAYLOAD_KEYS)
    if extra_payload:
        raise ValueError(
            f"encrypted payload has unsupported fields: {sorted(extra_payload)}"
        )
    if event["operation"] not in {
        "upsert",
        "delete",
        "snapshot",
        "rewrap",
        "resolve",
    }:
        raise ValueError("unsupported sync operation")
    if payload["organization_id"] != event["organization_id"]:
        raise ValueError("payload organization mismatch")
    if payload["record_id"] != event["record_id"]:
        raise ValueError("payload record mismatch")
    if "applied" in event and not isinstance(event["applied"], bool):
        raise ValueError("applied must be boolean")
    for field, value in (
        ("event_id", event["event_id"]),
        ("organization_id", event["organization_id"]),
        ("record_id", event["record_id"]),
        ("version_id", payload["version_id"]),
        ("device_id", payload["device_id"]),
    ):
        try:
            if str(uuid.UUID(str(value))) != str(value):
                raise ValueError
        except (ValueError, AttributeError, TypeError):
            raise ValueError(f"{field} must be a canonical UUID") from None
    base_version_id = payload.get("base_version_id")
    if base_version_id is not None:
        try:
            if str(uuid.UUID(str(base_version_id))) != str(base_version_id):
                raise ValueError
        except (ValueError, AttributeError, TypeError):
            raise ValueError("base_version_id must be a canonical UUID") from None
    for field in ("version", "key_version"):
        value = payload[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"{field} must be a positive integer")
    if not isinstance(payload["deleted"], bool):
        raise ValueError("deleted must be boolean")
    record_type = str(payload["record_type"] or "")
    if not record_type or len(record_type) > 64:
        raise ValueError("record_type has invalid length")
    _decode_ciphertext_field(
        payload["ciphertext"],
        "ciphertext",
        min_size=17,
        max_size=_MAX_RECORD_CIPHERTEXT_BYTES,
    )
    _decode_ciphertext_field(payload["nonce"], "nonce", exact_size=12)
    _decode_ciphertext_field(
        payload["wrapped_data_key"],
        "wrapped_data_key",
        exact_size=48,
    )
    _decode_ciphertext_field(
        payload["wrap_nonce"], "wrap_nonce", exact_size=12
    )
    content_hash = str(payload["content_hash"])
    if len(content_hash) != 64 or any(
        character not in "0123456789abcdefABCDEF"
        for character in content_hash
    ):
        raise ValueError("content_hash must be SHA-256 hexadecimal")
    return json.loads(json.dumps(event))


def _quarantine_identity(
    raw_event: dict,
    expected_organization_id: str,
) -> dict | None:
    if not isinstance(raw_event, dict):
        return None
    try:
        organization_id = str(uuid.UUID(
            str(raw_event.get("organization_id") or "")
        ))
        cursor = int(raw_event["cursor"])
    except (KeyError, TypeError, ValueError, AttributeError):
        return None
    raw_event_id = raw_event.get("event_id")
    raw_record_id = raw_event.get("record_id")
    try:
        event_id = (
            str(uuid.UUID(str(raw_event_id)))
            if raw_event_id is not None
            else None
        )
    except (TypeError, ValueError, AttributeError):
        event_id = None
    try:
        record_id = (
            str(uuid.UUID(str(raw_record_id)))
            if raw_record_id is not None
            else None
        )
    except (TypeError, ValueError, AttributeError):
        record_id = None
    if (
        (
            event_id is not None
            and event_id != str(raw_event_id)
        )
        or organization_id != str(raw_event.get("organization_id"))
        or (
            record_id is not None
            and record_id != str(raw_record_id)
        )
        or organization_id != expected_organization_id
        or isinstance(raw_event.get("cursor"), bool)
        or cursor < 1
    ):
        return None
    try:
        serialized = json.dumps(
            raw_event,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError):
        return None
    return {
        "event_id": event_id,
        "organization_id": organization_id,
        "record_id": record_id,
        "remote_cursor": cursor,
        "operation": (
            str(raw_event.get("operation"))
            if isinstance(raw_event.get("operation"), str)
            and re.fullmatch(r"[a-z_]{1,32}", raw_event["operation"])
            else None
        ),
        "event_hash": hashlib.sha256(serialized).hexdigest(),
        "event_bytes": len(serialized),
    }


def run_sync_cycle(service, context: dict, coordinator) -> dict[str, Any]:
    """Push local ciphertext then pull and apply remote ciphertext events."""
    organization_id = str(context["organization_id"])
    user_id = str(context["user_id"])
    counters = {
        "pushed": 0,
        "pulled": 0,
        "applied": 0,
        "duplicates": 0,
        "conflicts": 0,
        "quarantined": 0,
        "failed": 0,
    }
    after_cursor = service.repository.get_sync_cursor(organization_id)
    for event in service.export_outbox(organization_id):
        try:
            response = coordinator.push(validate_ciphertext_event(event))
            remote_cursor = int(response["cursor"])
            if response.get("applied") is False:
                service.repository.mark_outbox_conflicted(
                    event["event_id"],
                    remote_cursor,
                )
                counters["pushed"] += 1
                counters["conflicts"] += 1
                continue
            service.repository.mark_outbox_sent(
                event["event_id"], remote_cursor
            )
            counters["pushed"] += 1
        except Exception as exc:
            counters["failed"] += 1
            service.repository.mark_outbox_failed(
                event["event_id"],
                f"sync_push:{type(exc).__name__}",
            )

    try:
        pulled = coordinator.pull(organization_id, after_cursor)
    except Exception:
        counters["failed"] += 1
        counters["cursor"] = service.repository.get_sync_cursor(
            organization_id
        )
        counters["unresolved_quarantine"] = (
            service.repository.count_unresolved_sync_quarantine(
                organization_id
            )
        )
        counters["degraded"] = bool(counters["unresolved_quarantine"])
        return counters
    try:
        page_cursors = [
            int(item["cursor"])
            for item in pulled
            if (
                isinstance(item, dict)
                and not isinstance(item.get("cursor"), bool)
            )
        ]
        if (
            len(page_cursors) != len(pulled)
            or any(cursor < 1 for cursor in page_cursors)
            or page_cursors != sorted(set(page_cursors))
            or (page_cursors and page_cursors[0] <= after_cursor)
        ):
            raise ValueError("sync cursor page is not strictly increasing")
    except (KeyError, TypeError, ValueError):
        counters["failed"] += 1
        counters["cursor"] = service.repository.get_sync_cursor(
            organization_id
        )
        counters["unresolved_quarantine"] = (
            service.repository.count_unresolved_sync_quarantine(
                organization_id
            )
        )
        counters["degraded"] = bool(counters["unresolved_quarantine"])
        return counters
    for raw_event in pulled:
        counters["pulled"] += 1
        identity = _quarantine_identity(raw_event, organization_id)
        if (
            identity is None
            or identity["remote_cursor"]
            <= service.repository.get_sync_cursor(organization_id)
        ):
            counters["failed"] += 1
            break
        try:
            event = validate_ciphertext_event(raw_event)
        except ValueError:
            service.repository.quarantine_sync_event(
                **identity,
                reason="invalid_ciphertext_structure",
                encrypted_event_json=None,
            )
            counters["quarantined"] += 1
            continue
        try:
            cursor = identity["remote_cursor"]
            result = service.apply_remote_event(
                organization_id,
                user_id,
                event,
                remote_cursor=cursor,
            )
            state = result["state"]
            if state == "applied":
                counters["applied"] += 1
            elif state == "duplicate":
                counters["duplicates"] += 1
            elif state == "conflict":
                counters["conflicts"] += 1
        except UntrustedSyncEvent as error:
            service.repository.quarantine_sync_event(
                **identity,
                reason=error.reason,
                encrypted_event_json=json.dumps(
                    event,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
            counters["quarantined"] += 1
        except Exception:
            counters["failed"] += 1
            # A later cursor must never be committed across a failed event.
            # Stop this batch so the failed event and every successor are
            # fetched again from the last contiguous local cursor.
            break

    counters["cursor"] = service.repository.get_sync_cursor(organization_id)
    counters["unresolved_quarantine"] = (
        service.repository.count_unresolved_sync_quarantine(organization_id)
    )
    counters["degraded"] = bool(counters["unresolved_quarantine"])
    return counters
