"""Ciphertext-only synchronization and task-metadata coordinator.

This process intentionally has no imports from the desktop application, AI
clients, document parsers, or key-management code.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import tempfile
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from flask import Flask, jsonify, redirect, request, send_from_directory

from feishu_webhook_security import (
    WebhookMisconfigured,
    WebhookRejected,
    acquire_event_lease,
    decrypt_event_payload,
    validate_event_identity,
    verify_signed_request,
)
from product_version import PRODUCT_VERSION, current_build_commit
from v9.cloud import validate_ciphertext_event


_TASK_ID = re.compile(r"^[A-Z][A-Z0-9_-]{5,63}$")
_FULL_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_WIRE_COMPATIBILITY = "mvp-wire-v1"
_TASK_ACTIONS = {"claim", "approve", "status"}
_TASK_STATUSES = {
    "queued",
    "claimed",
    "waiting_desktop",
    "waiting_approval",
    "approved",
    "rejected",
    "cancelled",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve_build_commit(explicit: str | None = None) -> str:
    """Resolve the immutable source revision without exposing local paths."""
    if explicit is None:
        return current_build_commit()
    candidate = explicit.strip()
    if _FULL_GIT_SHA.fullmatch(candidate) is None:
        raise ValueError("build_commit must be a full lowercase Git SHA")
    return candidate


def _release_metadata(build_commit: str) -> dict[str, str]:
    return {
        "version": PRODUCT_VERSION.semantic_version,
        "display_version": PRODUCT_VERSION.display_version,
        "release_tag": PRODUCT_VERSION.release_tag,
        "build_commit": build_commit,
        "wire_compatibility": _WIRE_COMPATIBILITY,
    }


def _strict_bool_setting(
    explicit: bool | None,
    environment_name: str,
    *,
    setting_name: str | None = None,
) -> bool:
    setting_name = setting_name or environment_name
    if explicit is not None:
        if type(explicit) is not bool:
            raise ValueError(f"{setting_name} must be a boolean")
        return explicit
    raw = os.getenv(environment_name)
    if raw is None or not raw.strip():
        return False
    normalized = raw.strip().lower()
    if normalized in {"1", "true"}:
        return True
    if normalized in {"0", "false"}:
        return False
    raise ValueError(f"{environment_name} must be true or false")


def _https_origin(value: str, *, setting_name: str) -> str:
    """Return a normalized, exact HTTPS origin or fail closed."""
    parsed = urlsplit(value.strip())
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{setting_name} must be an exact HTTPS origin")
    return urlunsplit(("https", parsed.netloc.lower(), "", "", ""))


def _public_supabase_config(url: str, key: str) -> tuple[str, str] | None:
    if not url or not key:
        return None
    try:
        origin = _https_origin(url, setting_name="Supabase URL")
    except ValueError:
        return None
    if not key.startswith("sb_publishable_"):
        return None
    return origin, key


def _default_readiness_probe(url: str, publishable_key: str) -> bool:
    request_object = urllib.request.Request(
        f"{url}/auth/v1/health",
        headers={
            "apikey": publishable_key,
            "Authorization": f"Bearer {publishable_key}",
            "User-Agent": "DefenseTracker-MVP-Readiness/1",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request_object, timeout=3) as response:
            return 200 <= int(response.status) < 300
    except (OSError, ValueError, urllib.error.URLError):
        return False


class CloudStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._connect() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS encrypted_events(
                    cursor INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    organization_id TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_cloud_sync_pull
                    ON encrypted_events(organization_id, cursor);
                CREATE TABLE IF NOT EXISTS task_metadata(
                    task_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    assignee_hash TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS feishu_commands(
                    event_id TEXT PRIMARY KEY,
                    action TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    actor_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def push_event(self, event: dict) -> tuple[int, bool]:
        payload_json = json.dumps(
            event["payload"], ensure_ascii=True, separators=(",", ":")
        )
        with self._lock, self._connect() as conn:
            existing = conn.execute(
                "SELECT cursor FROM encrypted_events WHERE event_id=?",
                (event["event_id"],),
            ).fetchone()
            if existing:
                return int(existing["cursor"]), False
            cursor = conn.execute(
                """
                INSERT INTO encrypted_events(
                    event_id,organization_id,record_id,operation,payload_json,
                    created_at
                ) VALUES(?,?,?,?,?,?)
                """,
                (
                    event["event_id"],
                    event["organization_id"],
                    event["record_id"],
                    event["operation"],
                    payload_json,
                    _now(),
                ),
            ).lastrowid
            return int(cursor), True

    def pull_events(
        self, organization_id: str, after_cursor: int, limit: int
    ) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT cursor,event_id,organization_id,record_id,operation,
                       payload_json
                FROM encrypted_events
                WHERE organization_id=? AND cursor>?
                ORDER BY cursor LIMIT ?
                """,
                (organization_id, after_cursor, limit),
            ).fetchall()
        return [
            {
                "cursor": int(row["cursor"]),
                "event_id": row["event_id"],
                "organization_id": row["organization_id"],
                "record_id": row["record_id"],
                "operation": row["operation"],
                "payload": json.loads(row["payload_json"]),
            }
            for row in rows
        ]

    def put_task(self, task_id: str, status: str, assignee_hash: str = "") -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO task_metadata(task_id,status,assignee_hash,updated_at)
                VALUES(?,?,?,?)
                ON CONFLICT(task_id) DO UPDATE SET
                    status=excluded.status,
                    assignee_hash=excluded.assignee_hash,
                    updated_at=excluded.updated_at
                """,
                (task_id, status, assignee_hash or None, _now()),
            )

    def get_task(self, task_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT task_id,status,updated_at FROM task_metadata WHERE task_id=?",
                (task_id,),
            ).fetchone()
        return dict(row) if row else None

    def record_command(
        self, event_id: str, action: str, task_id: str, actor_hash: str
    ) -> bool:
        with self._lock, self._connect() as conn:
            result = conn.execute(
                """
                INSERT OR IGNORE INTO feishu_commands(
                    event_id,action,task_id,actor_hash,created_at
                ) VALUES(?,?,?,?,?)
                """,
                (event_id, action, task_id, actor_hash, _now()),
            )
        return result.rowcount == 1


def create_app(
    *,
    database_path: Path | str | None = None,
    coordinator_token: str | None = None,
    legacy_coordinator_enabled: bool | None = None,
    feishu_app_id: str | None = None,
    feishu_verify_token: str | None = None,
    feishu_encrypt_key: str | None = None,
    feishu_tenant_key: str | None = None,
    allowed_origins: set[str] | None = None,
    supabase_url: str | None = None,
    supabase_publishable_key: str | None = None,
    invited_signup_enabled: bool | None = None,
    access_applications_enabled: bool | None = None,
    production_mode: bool | None = None,
    build_commit: str | None = None,
    readiness_probe=None,
) -> Flask:
    application = Flask(__name__)
    application.config["MAX_CONTENT_LENGTH"] = 256 * 1024
    database_path = database_path or os.getenv(
        "V9_CLOUD_DB_PATH",
        str(Path(tempfile.gettempdir()) / "defense-tracker-v9-cloud.sqlite3"),
    )
    store = CloudStore(Path(database_path))
    portal_root = Path(__file__).resolve().parent / "web" / "v9-portal"
    token = (
        coordinator_token
        if coordinator_token is not None
        else os.getenv("V9_COORDINATOR_TOKEN", "")
    )
    if legacy_coordinator_enabled is None:
        legacy_coordinator_enabled = (
            coordinator_token is not None
            or os.getenv("V9_LEGACY_COORDINATOR_ENABLED", "").strip().lower()
            in {"1", "true", "yes"}
        )
    feishu_app_id = (
        feishu_app_id
        if feishu_app_id is not None
        else os.getenv("FEISHU_APP_ID", "")
    ).strip()
    verify_token = (
        feishu_verify_token
        if feishu_verify_token is not None
        else os.getenv("FEISHU_VERIFY_TOKEN", "")
    ).strip()
    encrypt_key = (
        feishu_encrypt_key
        if feishu_encrypt_key is not None
        else os.getenv("FEISHU_ENCRYPT_KEY", "")
    ).strip()
    tenant_key = (
        feishu_tenant_key
        if feishu_tenant_key is not None
        else os.getenv("FEISHU_TENANT_KEY", "")
    ).strip()
    supabase_url = (
        supabase_url
        if supabase_url is not None
        else os.getenv("V9_SUPABASE_URL", "")
    ).strip().rstrip("/")
    supabase_publishable_key = (
        supabase_publishable_key
        if supabase_publishable_key is not None
        else os.getenv("V9_SUPABASE_PUBLISHABLE_KEY", "")
    ).strip()
    invited_signup_enabled = _strict_bool_setting(
        invited_signup_enabled,
        "V9_AUTH_INVITED_SIGNUP_ENABLED",
        setting_name="invited_signup_enabled",
    )
    if invited_signup_enabled:
        raise ValueError("invited_signup_enabled must remain false")
    access_applications_enabled = _strict_bool_setting(
        access_applications_enabled,
        "V9_ACCESS_APPLICATIONS_ENABLED",
        setting_name="access_applications_enabled",
    )
    production_mode = _strict_bool_setting(
        production_mode,
        "V9_PRODUCTION_MODE",
        setting_name="production_mode",
    )
    build_commit = _resolve_build_commit(build_commit)
    if production_mode and build_commit == "development":
        raise ValueError(
            "DEFENSE_TRACKER_BUILD_COMMIT must be a full lowercase Git SHA"
        )
    release_metadata = _release_metadata(build_commit)
    if allowed_origins is None:
        allowed_origins = {
            item.strip()
            for item in os.getenv("V9_ALLOWED_ORIGINS", "").split(",")
            if item.strip()
        }
    normalized_origins: set[str] = set()
    for origin in allowed_origins:
        if origin == "*":
            if production_mode:
                raise ValueError("V9_ALLOWED_ORIGINS must use an exact HTTPS origin")
            continue
        normalized_origins.add(
            _https_origin(origin, setting_name="V9_ALLOWED_ORIGINS")
        )
    allowed_origins = normalized_origins

    public_supabase_config = _public_supabase_config(
        supabase_url,
        supabase_publishable_key,
    )
    if production_mode:
        if not supabase_url or not supabase_publishable_key:
            raise ValueError("Supabase public configuration is required")
        if not supabase_publishable_key.startswith("sb_publishable_"):
            raise ValueError("Supabase publishable key is required")
        if public_supabase_config is None:
            raise ValueError("Supabase URL must be an exact HTTPS origin")
        if not allowed_origins:
            raise ValueError("V9_ALLOWED_ORIGINS requires an exact HTTPS origin")

    if public_supabase_config is not None:
        supabase_url, supabase_publishable_key = public_supabase_config
    readiness_probe = readiness_probe or _default_readiness_probe

    def coordinator_auth(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not legacy_coordinator_enabled:
                return jsonify({
                    "error": "legacy coordinator is disabled; use Supabase RPC"
                }), 410
            if not token:
                return jsonify({"error": "coordinator is not configured"}), 503
            supplied = request.headers.get("Authorization", "")
            expected = f"Bearer {token}"
            if not hmac.compare_digest(supplied, expected):
                return jsonify({"error": "unauthorized"}), 401
            return view(*args, **kwargs)

        return wrapped

    @application.after_request
    def security_headers(response):
        origin = request.headers.get("Origin", "").rstrip("/")
        if origin and origin in allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
            response.headers["Access-Control-Allow-Headers"] = (
                "Authorization, Content-Type"
            )
            response.headers["Access-Control-Allow-Methods"] = (
                "GET, POST, OPTIONS"
            )
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        if production_mode:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        connect_sources = ["'self'"]
        if public_supabase_config is not None:
            parsed_supabase = urlsplit(supabase_url)
            websocket_origin = urlunsplit(
                ("wss", parsed_supabase.netloc, "", "", "")
            )
            connect_sources.extend((supabase_url, websocket_origin))
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
            f"form-action 'self'; connect-src {' '.join(connect_sources)}"
        )
        return response

    @application.get("/health")
    def health():
        return jsonify({
            "status": "ok",
            "mode": "ciphertext-only",
            "sync_backend": (
                "legacy-local" if legacy_coordinator_enabled else "supabase"
            ),
            **release_metadata,
        })

    @application.get("/ready")
    def ready():
        dependency_ready = False
        if public_supabase_config is not None:
            try:
                dependency_ready = bool(
                    readiness_probe(supabase_url, supabase_publishable_key)
                )
            except Exception:
                dependency_ready = False
        return jsonify({
            "status": "ready" if dependency_ready else "not_ready",
            "mode": "ciphertext-only",
            **release_metadata,
        }), 200 if dependency_ready else 503

    @application.get("/api/status")
    def api_status():
        return jsonify({
            "status": "ok",
            "mode": "ciphertext-only",
            "sync_backend": (
                "legacy-local" if legacy_coordinator_enabled else "supabase"
            ),
            **release_metadata,
        })

    @application.get("/")
    def root():
        return redirect("/portal/", code=302)

    @application.get("/portal/")
    def portal():
        return send_from_directory(portal_root, "index.html")

    @application.get("/portal/config.json")
    def portal_config():
        configured = public_supabase_config is not None
        return jsonify({
            "configured": configured,
            "url": supabase_url if configured else None,
            "publishable_key": (
                supabase_publishable_key if configured else None
            ),
            "invited_signup_enabled": False,
            "access_applications_enabled": access_applications_enabled,
            "account_limit": 100,
            "daily_event_limit": 1000,
            "deployment_mode": "mvp",
            **release_metadata,
        })

    @application.get("/favicon.ico")
    def favicon():
        return "", 204

    @application.get("/portal/<path:name>")
    def portal_asset(name):
        response = send_from_directory(portal_root, name)
        if name.endswith((".js", ".mjs")):
            response.mimetype = "application/javascript"
        return response

    @application.post("/api/v9/sync/events")
    @coordinator_auth
    def push_event():
        try:
            event = validate_ciphertext_event(request.get_json(silent=True))
            cursor, created = store.push_event(event)
        except (TypeError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"cursor": cursor, "created": created}), 201 if created else 200

    @application.get("/api/v9/sync/events")
    @coordinator_auth
    def pull_events():
        organization_id = request.args.get("organization_id", "").strip()
        if not organization_id:
            return jsonify({"error": "organization_id is required"}), 400
        try:
            after_cursor = max(0, int(request.args.get("after_cursor", "0")))
            limit = min(500, max(1, int(request.args.get("limit", "200"))))
        except ValueError:
            return jsonify({"error": "invalid cursor or limit"}), 400
        events = store.pull_events(organization_id, after_cursor, limit)
        cursor = events[-1]["cursor"] if events else after_cursor
        return jsonify({"events": events, "cursor": cursor})

    @application.post("/api/v9/tasks")
    @coordinator_auth
    def update_task():
        data = request.get_json(silent=True) or {}
        if set(data).difference({"task_id", "status", "assignee_hash"}):
            return jsonify({"error": "task metadata only"}), 400
        task_id = str(data.get("task_id") or "")
        status = str(data.get("status") or "")
        assignee_hash = str(data.get("assignee_hash") or "")
        if not _TASK_ID.fullmatch(task_id) or status not in _TASK_STATUSES:
            return jsonify({"error": "invalid task metadata"}), 400
        if assignee_hash and (
            len(assignee_hash) != 64
            or any(char not in "0123456789abcdef" for char in assignee_hash)
        ):
            return jsonify({"error": "assignee_hash must be SHA-256"}), 400
        store.put_task(task_id, status, assignee_hash)
        return jsonify({"task_id": task_id, "status": status}), 200

    @application.get("/api/v9/tasks/<task_id>")
    @coordinator_auth
    def get_task(task_id):
        if not _TASK_ID.fullmatch(task_id):
            return jsonify({"error": "invalid task id"}), 400
        task = store.get_task(task_id)
        return (jsonify(task), 200) if task else (
            jsonify({"error": "not found"}),
            404,
        )

    @application.post("/api/feishu/webhook")
    def feishu_webhook():
        if not all((feishu_app_id, verify_token, encrypt_key, tenant_key)):
            return jsonify({"error": "webhook security not configured"}), 503
        if request.content_length is not None and request.content_length > 256 * 1024:
            return jsonify({"error": "webhook body too large"}), 413
        raw = request.get_data(cache=True)
        if len(raw) > 256 * 1024:
            return jsonify({"error": "webhook body too large"}), 413
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "invalid webhook payload"}), 400
        try:
            verify_signed_request(
                request.headers,
                raw,
                signing_key=encrypt_key,
                allow_token_only=False,
            )
            data = decrypt_event_payload(data, encrypt_key=encrypt_key)
        except WebhookRejected:
            return jsonify({"error": "invalid webhook signature"}), 403
        except WebhookMisconfigured:
            return jsonify({"error": "webhook security unavailable"}), 503

        if data.get("type") == "url_verification":
            incoming_token = str(data.get("token") or "")
            if not hmac.compare_digest(incoming_token, verify_token):
                return jsonify({"error": "invalid verification token"}), 403
            challenge = data.get("challenge", "")
            if not isinstance(challenge, str) or len(challenge) > 1024:
                return jsonify({"error": "invalid challenge"}), 400
            return jsonify({"challenge": challenge})

        header = data.get("header")
        if not isinstance(header, dict):
            return jsonify({"error": "invalid webhook event"}), 400
        incoming_token = str(header.get("token") or "")
        if not hmac.compare_digest(incoming_token, verify_token):
            return jsonify({"error": "invalid verification token"}), 403
        try:
            validate_event_identity(
                data,
                expected_app_id=feishu_app_id,
                expected_tenant_key=tenant_key,
                allow_legacy=False,
            )
        except WebhookRejected:
            return jsonify({"error": "invalid webhook identity"}), 403
        except WebhookMisconfigured:
            return jsonify({"error": "webhook identity unavailable"}), 503

        event = data.get("event")
        if not isinstance(event, dict):
            return jsonify({"error": "invalid webhook event"}), 400
        if header.get("event_type") != "im.message.receive_v1":
            return jsonify({"accepted": False})
        message = event.get("message")
        if not isinstance(message, dict):
            return jsonify({"error": "invalid webhook event"}), 400
        event_id = str(header.get("event_id") or "")
        chat_id = str(message.get("chat_id") or "")
        try:
            event_lease = acquire_event_lease(data, allow_legacy=False)
        except WebhookRejected:
            return jsonify({"error": "invalid webhook event"}), 403
        except WebhookMisconfigured:
            return jsonify({"error": "webhook deduplication unavailable"}), 503
        if event_lease is None:
            return jsonify({"accepted": False})

        with event_lease:
            if message.get("message_type") != "text":
                return jsonify({"accepted": False})
            try:
                content = json.loads(str(message.get("content") or "{}"))
            except json.JSONDecodeError:
                content = {}
            command = str(content.get("text") or "").strip()
            parts = command.split()
            if (
                len(parts) != 2
                or parts[0].lower() not in _TASK_ACTIONS
                or not _TASK_ID.fullmatch(parts[1])
                or not chat_id
            ):
                return jsonify({"accepted": False})
            action, task_id = parts[0].lower(), parts[1]
            actor_hash = hashlib.sha256(chat_id.encode()).hexdigest()
            event_hash = hashlib.sha256(event_id.encode()).hexdigest()
            store.record_command(event_hash, action, task_id, actor_hash)
            return jsonify(
                {"accepted": True, "action": action, "task_id": task_id}
            )

    return application


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "8080")))
