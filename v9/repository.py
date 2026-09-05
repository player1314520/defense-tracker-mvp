"""SQLite persistence for encrypted V9 records and sync metadata."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Mapping

from .crypto import RecordEnvelope
from .errors import VersionConflict


RECORD_TYPES = {
    "source",
    "evidence",
    "claim",
    "entity",
    "relation",
    "geo_event",
    "alert_rule",
    "alert",
    "case",
    "job",
    "scenario",
    "document",
    "publication_item",
    "audit_event",
}
RETRY_DELAYS_SECONDS = (1, 5, 30, 120, 600)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None


class V9Repository:
    def __init__(
        self,
        database_path: Path,
        *,
        initialize: bool = True,
        read_only: bool = False,
    ):
        self.database_path = Path(database_path)
        self.read_only = bool(read_only)
        if not self.read_only:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        if initialize:
            if self.read_only:
                raise ValueError("read-only repository cannot initialize schema")
            self._init_schema()
        elif not self.database_path.is_file():
            raise FileNotFoundError(self.database_path)

    def _connect(self) -> sqlite3.Connection:
        if self.read_only:
            uri = f"file:{self.database_path.resolve().as_posix()}?mode=ro"
            conn = sqlite3.connect(uri, timeout=15, uri=True)
        else:
            conn = sqlite3.connect(self.database_path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS organizations(
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    key_version INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS memberships(
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    user_id TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN (
                        'owner','admin','collector','analyst','editor','approver'
                    )),
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    revoked_at TEXT,
                    PRIMARY KEY(organization_id, user_id)
                );
                CREATE TABLE IF NOT EXISTS devices(
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    user_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    public_key BLOB NOT NULL,
                    key_algorithm TEXT CHECK(
                        key_algorithm IS NULL OR
                        key_algorithm IN ('x25519','p256')
                    ),
                    device_kind TEXT CHECK(
                        device_kind IS NULL OR
                        device_kind IN ('desktop','browser')
                    ),
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    revoked_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_devices_org
                    ON devices(organization_id, status);
                CREATE TABLE IF NOT EXISTS key_envelopes(
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    device_id TEXT NOT NULL REFERENCES devices(id),
                    key_version INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(organization_id, device_id, key_version)
                );
                CREATE TABLE IF NOT EXISTS pairing_sessions(
                    session_id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    acting_user_id TEXT NOT NULL,
                    target_user_id TEXT NOT NULL,
                    device_name TEXT NOT NULL,
                    code_hash TEXT NOT NULL UNIQUE,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_pairing_code
                    ON pairing_sessions(code_hash, consumed_at, expires_at);
                CREATE TABLE IF NOT EXISTS recovery_envelopes(
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    key_version INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(organization_id, key_version)
                );
                CREATE TABLE IF NOT EXISTS local_secrets(
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    secret_kind TEXT NOT NULL,
                    secret_id TEXT NOT NULL,
                    key_version INTEGER NOT NULL DEFAULT 0,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(organization_id, secret_kind, secret_id, key_version)
                );
                CREATE TABLE IF NOT EXISTS encrypted_records(
                    record_id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    record_type TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    cloud_version_id TEXT,
                    device_id TEXT NOT NULL REFERENCES devices(id),
                    ciphertext BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    wrapped_data_key BLOB NOT NULL,
                    wrap_nonce BLOB NOT NULL,
                    key_version INTEGER NOT NULL,
                    content_hash TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    deleted INTEGER NOT NULL DEFAULT 0,
                    sync_cursor INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_records_org_type
                    ON encrypted_records(organization_id, record_type, updated_at);
                CREATE TABLE IF NOT EXISTS sync_outbox(
                    event_id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at TEXT,
                    state TEXT NOT NULL DEFAULT 'pending',
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(organization_id, record_id, operation, payload_json)
                );
                CREATE INDEX IF NOT EXISTS idx_outbox_state
                    ON sync_outbox(state, next_attempt_at);
                CREATE TABLE IF NOT EXISTS sync_cursor(
                    organization_id TEXT PRIMARY KEY,
                    remote_cursor INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sync_events(
                    event_id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    remote_cursor INTEGER,
                    applied_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sync_quarantine(
                    organization_id TEXT NOT NULL,
                    remote_cursor INTEGER NOT NULL,
                    event_id TEXT,
                    record_id TEXT,
                    operation TEXT,
                    reason TEXT NOT NULL CHECK(reason IN (
                        'invalid_ciphertext_structure',
                        'ciphertext_authentication_failed',
                        'content_integrity_failed'
                    )),
                    state TEXT NOT NULL DEFAULT 'quarantined' CHECK(state IN (
                        'quarantined','reprocessing','resolved','superseded'
                    )),
                    event_hash TEXT NOT NULL,
                    event_bytes INTEGER NOT NULL,
                    encrypted_event_json TEXT,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    last_retry_at TEXT,
                    resolved_at TEXT,
                    resolution_code TEXT,
                    PRIMARY KEY(organization_id,remote_cursor)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_sync_quarantine_event
                    ON sync_quarantine(organization_id,event_id)
                    WHERE event_id IS NOT NULL;
                CREATE INDEX IF NOT EXISTS idx_sync_quarantine_org_cursor
                    ON sync_quarantine(organization_id,remote_cursor);
                CREATE TABLE IF NOT EXISTS sync_quarantine_audit(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    organization_id TEXT NOT NULL,
                    remote_cursor INTEGER NOT NULL,
                    action TEXT NOT NULL CHECK(action IN (
                        'seen','retry_started','retry_failed',
                        'resolved','superseded'
                    )),
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS initial_snapshot_map(
                    organization_id TEXT NOT NULL,
                    record_id TEXT NOT NULL REFERENCES encrypted_records(record_id),
                    event_id TEXT NOT NULL UNIQUE REFERENCES sync_outbox(event_id),
                    cloud_version_id TEXT NOT NULL,
                    previous_cloud_version_id TEXT,
                    local_version INTEGER NOT NULL,
                    content_hash TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'queued',
                    created_at TEXT NOT NULL,
                    sent_at TEXT,
                    PRIMARY KEY(organization_id, record_id)
                );
                CREATE TABLE IF NOT EXISTS initial_snapshot_sessions(
                    organization_id TEXT PRIMARY KEY,
                    expected_count INTEGER NOT NULL CHECK(expected_count >= 0),
                    manifest_hash TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(
                        state IN ('active','completed','aborted')
                    ),
                    created_at TEXT NOT NULL,
                    completed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS sync_blocks(
                    organization_id TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    base_version_id TEXT,
                    incoming_version_id TEXT NOT NULL,
                    remote_cursor INTEGER,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    resolved_at TEXT,
                    PRIMARY KEY(organization_id, record_id)
                );
                CREATE TABLE IF NOT EXISTS conflicts(
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    local_payload_json TEXT NOT NULL,
                    remote_payload_json TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'open',
                    created_at TEXT NOT NULL,
                    resolved_at TEXT
                );
                CREATE TABLE IF NOT EXISTS local_profile(
                    profile_key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS record_refs(
                    organization_id TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    external_ref TEXT NOT NULL,
                    record_id TEXT NOT NULL REFERENCES encrypted_records(record_id),
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(organization_id, namespace, external_ref)
                );
                """
            )
            membership_columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(memberships)")
            }
            if "revoked_at" not in membership_columns:
                conn.execute("ALTER TABLE memberships ADD COLUMN revoked_at TEXT")
            device_columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(devices)")
            }
            if "key_algorithm" not in device_columns:
                conn.execute(
                    "ALTER TABLE devices ADD COLUMN key_algorithm TEXT"
                )
            if "device_kind" not in device_columns:
                conn.execute(
                    "ALTER TABLE devices ADD COLUMN device_kind TEXT"
                )
            record_columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(encrypted_records)")
            }
            if "cloud_version_id" not in record_columns:
                conn.execute(
                    "ALTER TABLE encrypted_records ADD COLUMN cloud_version_id TEXT"
                )
            snapshot_columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(initial_snapshot_map)")
            }
            if "previous_cloud_version_id" not in snapshot_columns:
                conn.execute(
                    """
                    ALTER TABLE initial_snapshot_map
                    ADD COLUMN previous_cloud_version_id TEXT
                    """
                )
            self._upgrade_outbox_version_ids(conn)

    @staticmethod
    def _is_uuid(value: str) -> bool:
        try:
            return str(uuid.UUID(str(value))) == str(value)
        except (ValueError, AttributeError, TypeError):
            return False

    def _upgrade_outbox_version_ids(self, conn: sqlite3.Connection) -> None:
        """Backfill legacy pending events without exposing or rewriting ciphertext."""
        rows = conn.execute(
            """
            SELECT event_id,organization_id,record_id,payload_json,created_at
            FROM sync_outbox
            WHERE state IN ('pending','retry','manual')
            ORDER BY organization_id,record_id,created_at,event_id
            """
        ).fetchall()
        previous_by_record: dict[tuple[str, str], str | None] = {}
        latest_by_record: dict[tuple[str, str], str] = {}
        for row in rows:
            payload = json.loads(row["payload_json"])
            key = (str(row["organization_id"]), str(row["record_id"]))
            version_id = str(payload.get("version_id") or uuid.uuid4())
            base_version_id = payload.get(
                "base_version_id",
                previous_by_record.get(key),
            )
            payload["version_id"] = version_id
            payload["base_version_id"] = base_version_id
            event_id = str(row["event_id"])
            if not self._is_uuid(event_id):
                event_id = str(uuid.uuid4())
            conn.execute(
                """
                UPDATE sync_outbox
                SET event_id=?,payload_json=?
                WHERE event_id=?
                """,
                (
                    event_id,
                    json.dumps(payload, sort_keys=True),
                    row["event_id"],
                ),
            )
            previous_by_record[key] = version_id
            latest_by_record[key] = version_id
        for (organization_id, record_id), version_id in latest_by_record.items():
            conn.execute(
                """
                UPDATE encrypted_records SET cloud_version_id=?
                WHERE organization_id=? AND record_id=?
                  AND cloud_version_id IS NULL
                """,
                (version_id, organization_id, record_id),
            )

    def create_organization(self, org_id: str, name: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO organizations(id,name,key_version,created_at) VALUES(?,?,1,?)",
                (org_id, name, _now()),
            )

    def get_organization(self, org_id: str) -> dict | None:
        with self._connect() as conn:
            return _dict(conn.execute(
                "SELECT * FROM organizations WHERE id=?", (org_id,)
            ).fetchone())

    def add_membership(self, org_id: str, user_id: str, role: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO memberships(organization_id,user_id,role,status,created_at)
                VALUES(?,?,?,'active',?)
                ON CONFLICT(organization_id,user_id) DO UPDATE SET
                    role=excluded.role,status='active'
                """,
                (org_id, user_id, role, _now()),
            )

    def get_membership(self, org_id: str, user_id: str) -> dict | None:
        with self._connect() as conn:
            return _dict(conn.execute(
                """
                SELECT * FROM memberships
                WHERE organization_id=? AND user_id=? AND status='active'
                """,
                (org_id, user_id),
            ).fetchone())

    def add_device(
        self,
        device_id: str,
        org_id: str,
        user_id: str,
        name: str,
        public_key: bytes,
        *,
        key_algorithm: str | None = None,
        device_kind: str | None = None,
    ) -> None:
        if key_algorithm not in {None, "x25519", "p256"}:
            raise ValueError("unsupported device key algorithm")
        if device_kind not in {None, "desktop", "browser"}:
            raise ValueError("unsupported device kind")
        expected_length = {"x25519": 32, "p256": 65}.get(key_algorithm)
        if expected_length is not None and len(public_key) != expected_length:
            raise ValueError("invalid device public key length")
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO devices(
                    id,organization_id,user_id,name,public_key,
                    key_algorithm,device_kind,status,created_at
                ) VALUES(?,?,?,?,?,?,?,'active',?)
                """,
                (
                    device_id,
                    org_id,
                    user_id,
                    name,
                    public_key,
                    key_algorithm,
                    device_kind,
                    _now(),
                ),
            )

    def get_device(self, device_id: str) -> dict | None:
        with self._connect() as conn:
            return _dict(conn.execute(
                "SELECT * FROM devices WHERE id=?", (device_id,)
            ).fetchone())

    def list_active_devices(self, org_id: str) -> list[dict]:
        with self._connect() as conn:
            return [dict(row) for row in conn.execute(
                """
                SELECT * FROM devices
                WHERE organization_id=? AND status='active'
                ORDER BY created_at
                """,
                (org_id,),
            )]

    def create_pairing_session(
        self,
        session_id: str,
        org_id: str,
        acting_user_id: str,
        target_user_id: str,
        device_name: str,
        code_hash: str,
        expires_at: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO pairing_sessions(
                    session_id,organization_id,acting_user_id,target_user_id,
                    device_name,code_hash,expires_at,created_at
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    session_id,
                    org_id,
                    acting_user_id,
                    target_user_id,
                    device_name,
                    code_hash,
                    expires_at,
                    _now(),
                ),
            )

    def consume_pairing_session(self, code_hash: str) -> dict | None:
        """Atomically consume an unexpired pairing bearer code."""
        now = _now()
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT * FROM pairing_sessions
                WHERE code_hash=? AND consumed_at IS NULL AND expires_at>?
                """,
                (code_hash, now),
            ).fetchone()
            if row is None:
                return None
            result = conn.execute(
                """
                UPDATE pairing_sessions SET consumed_at=?
                WHERE session_id=? AND consumed_at IS NULL
                """,
                (now, row["session_id"]),
            )
            if result.rowcount != 1:
                return None
            item = dict(row)
            item["consumed_at"] = now
            return item

    def put_key_envelope(self, payload: Mapping) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO key_envelopes(
                    id,organization_id,device_id,key_version,payload_json,created_at
                ) VALUES(?,?,?,?,?,?)
                ON CONFLICT(organization_id,device_id,key_version) DO UPDATE SET
                    payload_json=excluded.payload_json
                """,
                (
                    f"env_{uuid.uuid4().hex}",
                    payload["organization_id"],
                    payload["device_id"],
                    int(payload["key_version"]),
                    json.dumps(payload, sort_keys=True),
                    _now(),
                ),
            )

    def list_key_envelopes(
        self, org_id: str, key_version: int | None = None
    ) -> list[dict]:
        query = "SELECT * FROM key_envelopes WHERE organization_id=?"
        params: list = [org_id]
        if key_version is not None:
            query += " AND key_version=?"
            params.append(key_version)
        query += " ORDER BY created_at"
        with self._connect() as conn:
            return [dict(row) for row in conn.execute(query, params)]

    def put_recovery_envelope(self, org_id: str, key_version: int, payload: Mapping) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO recovery_envelopes(
                    organization_id,key_version,payload_json,created_at
                ) VALUES(?,?,?,?)
                ON CONFLICT(organization_id,key_version) DO UPDATE SET
                    payload_json=excluded.payload_json
                """,
                (org_id, key_version, json.dumps(payload, sort_keys=True), _now()),
            )

    def get_recovery_envelope(self, org_id: str, key_version: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT payload_json FROM recovery_envelopes
                WHERE organization_id=? AND key_version=?
                """,
                (org_id, key_version),
            ).fetchone()
        return json.loads(row["payload_json"]) if row else None

    def put_local_secret(
        self,
        org_id: str,
        kind: str,
        secret_id: str,
        key_version: int,
        nonce: bytes,
        ciphertext: bytes,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO local_secrets(
                    organization_id,secret_kind,secret_id,key_version,
                    nonce,ciphertext,created_at
                ) VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(organization_id,secret_kind,secret_id,key_version)
                DO UPDATE SET nonce=excluded.nonce,ciphertext=excluded.ciphertext
                """,
                (org_id, kind, secret_id, key_version, nonce, ciphertext, _now()),
            )

    def get_local_secret(
        self, org_id: str, kind: str, secret_id: str, key_version: int
    ) -> dict | None:
        with self._connect() as conn:
            return _dict(conn.execute(
                """
                SELECT * FROM local_secrets
                WHERE organization_id=? AND secret_kind=? AND secret_id=? AND key_version=?
                """,
                (org_id, kind, secret_id, key_version),
            ).fetchone())

    def put_record(
        self,
        envelope: RecordEnvelope,
        device_id: str,
        *,
        deleted: bool = False,
        enqueue: bool = True,
        version_id: str | None = None,
        base_version_id: str | None = None,
    ) -> None:
        with self._lock, self._connect() as conn:
            self._put_record(
                conn,
                envelope,
                device_id,
                deleted=deleted,
                enqueue=enqueue,
                version_id=version_id,
                base_version_id=base_version_id,
            )

    def put_records_atomically(self, entries: Iterable[Mapping]) -> None:
        """Commit workflow records and their outbox events as one transaction."""
        entries = list(entries)
        if not entries:
            return
        with self._lock, self._connect() as conn:
            for entry in entries:
                envelope = entry.get("envelope")
                if not isinstance(envelope, RecordEnvelope):
                    raise TypeError("atomic record envelope is required")
                self._put_record(
                    conn,
                    envelope,
                    str(entry.get("device_id") or ""),
                    deleted=bool(entry.get("deleted", False)),
                    enqueue=bool(entry.get("enqueue", True)),
                    version_id=entry.get("version_id"),
                    base_version_id=entry.get("base_version_id"),
                    expected_current_version=entry.get(
                        "expected_current_version"
                    ),
                    require_outbox=bool(entry.get("enqueue", True)),
                )

    def _put_record(
        self,
        conn: sqlite3.Connection,
        envelope: RecordEnvelope,
        device_id: str,
        *,
        deleted: bool = False,
        enqueue: bool = True,
        version_id: str | None = None,
        base_version_id: str | None = None,
        expected_current_version: int | None = None,
        require_outbox: bool = False,
    ) -> None:
        version_id = str(version_id or uuid.uuid4())
        if not self._is_uuid(version_id):
            raise ValueError("version_id must be a UUID")
        payload = envelope.to_dict() | {
            "device_id": device_id,
            "deleted": bool(deleted),
            "updated_at": _now(),
            "version_id": version_id,
            "base_version_id": base_version_id,
        }
        if enqueue:
            active_snapshot = conn.execute(
                """
                SELECT 1 FROM initial_snapshot_sessions
                WHERE organization_id=? AND state='active'
                """,
                (envelope.org_id,),
            ).fetchone()
            if active_snapshot is not None:
                raise ValueError(
                    "record writes are frozen during initial snapshot import"
                )
            blocked = conn.execute(
                """
                SELECT 1 FROM sync_blocks
                WHERE organization_id=? AND record_id=?
                  AND resolved_at IS NULL
                """,
                (envelope.org_id, envelope.record_id),
            ).fetchone()
            if blocked is not None:
                raise ValueError(
                    "record sync is blocked pending conflict resolution"
                )
        current = conn.execute(
            """
            SELECT version,cloud_version_id FROM encrypted_records
            WHERE record_id=?
            """,
            (envelope.record_id,),
        ).fetchone()
        if expected_current_version is not None:
            actual_version = int(current["version"]) if current else 0
            if actual_version != int(expected_current_version):
                raise VersionConflict(
                    f"expected {expected_current_version}, current {actual_version}"
                )
        if enqueue and base_version_id is None and current is not None:
            snapshot = conn.execute(
                """
                SELECT cloud_version_id FROM initial_snapshot_map
                WHERE organization_id=? AND record_id=? AND state='queued'
                """,
                (envelope.org_id, envelope.record_id),
            ).fetchone()
            payload["base_version_id"] = (
                snapshot["cloud_version_id"]
                if snapshot is not None
                else current["cloud_version_id"]
            )
        conn.execute(
            """
            INSERT INTO encrypted_records(
                record_id,organization_id,record_type,version,
                cloud_version_id,device_id,
                ciphertext,nonce,wrapped_data_key,wrap_nonce,key_version,
                content_hash,updated_at,deleted
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(record_id) DO UPDATE SET
                organization_id=excluded.organization_id,
                record_type=excluded.record_type,
                version=excluded.version,
                cloud_version_id=excluded.cloud_version_id,
                device_id=excluded.device_id,
                ciphertext=excluded.ciphertext,
                nonce=excluded.nonce,
                wrapped_data_key=excluded.wrapped_data_key,
                wrap_nonce=excluded.wrap_nonce,
                key_version=excluded.key_version,
                content_hash=excluded.content_hash,
                updated_at=excluded.updated_at,
                deleted=excluded.deleted
            """,
            (
                envelope.record_id,
                envelope.org_id,
                envelope.record_type,
                envelope.version,
                version_id,
                device_id,
                envelope.ciphertext,
                envelope.nonce,
                envelope.wrapped_data_key,
                envelope.wrap_nonce,
                envelope.key_version,
                envelope.content_hash,
                payload["updated_at"],
                int(deleted),
            ),
        )
        if enqueue:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO sync_outbox(
                    event_id,organization_id,record_id,operation,payload_json,
                    attempts,state,created_at
                ) VALUES(?,?,?,?,?,0,'pending',?)
                """,
                (
                    str(uuid.uuid4()),
                    envelope.org_id,
                    envelope.record_id,
                    "delete" if deleted else "upsert",
                    json.dumps(payload, sort_keys=True),
                    _now(),
                ),
            )
            if require_outbox and cursor.rowcount != 1:
                raise RuntimeError("required sync outbox event was not inserted")

    def get_record(self, record_id: str) -> dict | None:
        with self._connect() as conn:
            return _dict(conn.execute(
                "SELECT * FROM encrypted_records WHERE record_id=?", (record_id,)
            ).fetchone())

    def list_records(self, org_id: str) -> list[dict]:
        with self._connect() as conn:
            return [dict(row) for row in conn.execute(
                """
                SELECT * FROM encrypted_records
                WHERE organization_id=? ORDER BY updated_at
                """,
                (org_id,),
            )]

    def list_records_by_type(self, org_id: str, record_type: str) -> list[dict]:
        with self._connect() as conn:
            return [dict(row) for row in conn.execute(
                """
                SELECT * FROM encrypted_records
                WHERE organization_id=? AND record_type=? AND deleted=0
                ORDER BY updated_at DESC
                """,
                (org_id, record_type),
            )]

    def get_profile(self, key: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value_json FROM local_profile WHERE profile_key=?",
                (key,),
            ).fetchone()
        return json.loads(row["value_json"]) if row else None

    def put_profile(self, key: str, value: Mapping) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO local_profile(profile_key,value_json,updated_at)
                VALUES(?,?,?)
                ON CONFLICT(profile_key) DO UPDATE SET
                    value_json=excluded.value_json,updated_at=excluded.updated_at
                """,
                (key, json.dumps(value, sort_keys=True), _now()),
            )

    def create_cloud_device_context(
        self,
        *,
        context: Mapping,
        organization_name: str,
        role: str,
        membership_status: str,
        public_key: bytes,
        private_key_nonce: bytes,
        private_key_ciphertext: bytes,
    ) -> dict:
        """Atomically persist a pending cloud device without touching personal."""
        organization_id = str(context["organization_id"])
        user_id = str(context["user_id"])
        device_id = str(context["device_id"])
        key_version = int(context["remote_key_version"])
        if (
            context.get("key_algorithm") != "p256"
            or context.get("device_kind") != "desktop"
            or len(public_key) != 65
        ):
            raise ValueError("cloud desktop P-256 identity required")
        profile_key = f"cloud_device_context:{organization_id}"
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT value_json FROM local_profile WHERE profile_key=?",
                (profile_key,),
            ).fetchone()
            if existing is not None:
                return json.loads(existing["value_json"])
            if conn.execute(
                "SELECT 1 FROM devices WHERE id=?",
                (device_id,),
            ).fetchone():
                raise ValueError("cloud device id collision")
            conn.execute(
                """
                INSERT INTO organizations(id,name,key_version,created_at)
                VALUES(?,?,?,?)
                ON CONFLICT(id) DO NOTHING
                """,
                (
                    organization_id,
                    organization_name,
                    key_version,
                    _now(),
                ),
            )
            conn.execute(
                """
                INSERT INTO memberships(
                    organization_id,user_id,role,status,created_at
                ) VALUES(?,?,?,?,?)
                ON CONFLICT(organization_id,user_id) DO UPDATE SET
                    role=excluded.role,status=excluded.status,
                    revoked_at=NULL
                """,
                (
                    organization_id,
                    user_id,
                    role,
                    membership_status,
                    _now(),
                ),
            )
            conn.execute(
                """
                INSERT INTO devices(
                    id,organization_id,user_id,name,public_key,
                    key_algorithm,device_kind,status,created_at
                ) VALUES(?,?,?,?,?,?,?,'pending',?)
                """,
                (
                    device_id,
                    organization_id,
                    user_id,
                    "云端桌面设备",
                    public_key,
                    "p256",
                    "desktop",
                    _now(),
                ),
            )
            conn.execute(
                """
                INSERT INTO local_secrets(
                    organization_id,secret_kind,secret_id,key_version,
                    nonce,ciphertext,created_at
                ) VALUES(?,'device_private_key',?,0,?,?,?)
                """,
                (
                    organization_id,
                    device_id,
                    private_key_nonce,
                    private_key_ciphertext,
                    _now(),
                ),
            )
            conn.execute(
                """
                INSERT INTO local_profile(profile_key,value_json,updated_at)
                VALUES(?,?,?)
                """,
                (
                    profile_key,
                    json.dumps(dict(context), sort_keys=True),
                    _now(),
                ),
            )
        return dict(context)

    def bind_active_cloud_context(
        self,
        context: Mapping,
        *,
        role: str,
    ) -> dict:
        """Bind an already-unlocked local device to a JWT identity."""
        organization_id = str(context["organization_id"])
        device_id = str(context["device_id"])
        user_id = str(context["user_id"])
        profile_key = f"cloud_device_context:{organization_id}"
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            device = conn.execute(
                """
                SELECT organization_id,status,key_algorithm,device_kind
                FROM devices WHERE id=?
                """,
                (device_id,),
            ).fetchone()
            if (
                device is None
                or device["organization_id"] != organization_id
                or device["status"] != "active"
                or device["key_algorithm"] != "p256"
                or device["device_kind"] != "desktop"
            ):
                raise ValueError("active local desktop P-256 device required")
            conn.execute(
                """
                INSERT INTO memberships(
                    organization_id,user_id,role,status,created_at
                ) VALUES(?,?,?,'active',?)
                ON CONFLICT(organization_id,user_id) DO UPDATE SET
                    role=excluded.role,status='active',revoked_at=NULL
                """,
                (organization_id, user_id, role, _now()),
            )
            conn.execute(
                """
                INSERT INTO local_profile(profile_key,value_json,updated_at)
                VALUES(?,?,?)
                ON CONFLICT(profile_key) DO UPDATE SET
                    value_json=excluded.value_json,
                    updated_at=excluded.updated_at
                """,
                (
                    profile_key,
                    json.dumps(dict(context), sort_keys=True),
                    _now(),
                ),
            )
        return dict(context)

    def activate_cloud_device_context(
        self,
        context: Mapping,
        *,
        key_version: int,
        role: str | None = None,
        org_key_secret: tuple[bytes, bytes] | None = None,
    ) -> dict:
        """Atomically persist an opened org key and activate its cloud context."""
        organization_id = str(context["organization_id"])
        device_id = str(context["device_id"])
        user_id = str(context["user_id"])
        profile_key = f"cloud_device_context:{organization_id}"
        active = dict(context)
        active["status"] = "active"
        active["key_version"] = int(key_version)
        active["remote_key_version"] = int(key_version)
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            saved = conn.execute(
                "SELECT value_json FROM local_profile WHERE profile_key=?",
                (profile_key,),
            ).fetchone()
            device = conn.execute(
                """
                SELECT organization_id,user_id,status,key_algorithm,device_kind
                FROM devices WHERE id=?
                """,
                (device_id,),
            ).fetchone()
            if saved is None or json.loads(saved["value_json"]) != dict(context):
                raise ValueError("cloud device context changed")
            if (
                device is None
                or device["organization_id"] != organization_id
                or device["user_id"] != user_id
                or device["status"] not in {"pending", "active"}
                or device["key_algorithm"] != "p256"
                or device["device_kind"] != "desktop"
            ):
                raise ValueError("cloud device context mismatch")
            membership = conn.execute(
                """
                SELECT role,status FROM memberships
                WHERE organization_id=? AND user_id=?
                """,
                (organization_id, user_id),
            ).fetchone()
            if membership is None:
                raise ValueError("cloud membership is missing")
            effective_role = str(role or membership["role"])
            if effective_role not in {
                "owner",
                "admin",
                "collector",
                "analyst",
                "editor",
                "approver",
            }:
                raise ValueError("invalid cloud membership role")
            if org_key_secret is not None:
                secret_nonce, secret_ciphertext = org_key_secret
                conn.execute(
                    """
                    INSERT INTO local_secrets(
                        organization_id,secret_kind,secret_id,key_version,
                        nonce,ciphertext,created_at
                    ) VALUES(?,'org_key',?,?,?,?,?)
                    """,
                    (
                        organization_id,
                        organization_id,
                        int(key_version),
                        bytes(secret_nonce),
                        bytes(secret_ciphertext),
                        _now(),
                    ),
                )
            elif conn.execute(
                """
                SELECT 1 FROM local_secrets
                WHERE organization_id=? AND secret_kind='org_key'
                  AND secret_id=? AND key_version=?
                """,
                (organization_id, organization_id, int(key_version)),
            ).fetchone() is None:
                raise ValueError("organization key secret is missing")
            conn.execute(
                "UPDATE organizations SET key_version=? WHERE id=?",
                (int(key_version), organization_id),
            )
            conn.execute(
                "UPDATE devices SET status='active',revoked_at=NULL WHERE id=?",
                (device_id,),
            )
            conn.execute(
                """
                UPDATE memberships
                SET role=?,status='active',revoked_at=NULL
                WHERE organization_id=? AND user_id=?
                """,
                (effective_role, organization_id, user_id),
            )
            conn.execute(
                """
                UPDATE local_profile
                SET value_json=?,updated_at=?
                WHERE profile_key=?
                """,
                (
                    json.dumps(active, sort_keys=True),
                    _now(),
                    profile_key,
                ),
            )
        return active

    def refresh_cloud_membership(
        self,
        context: Mapping,
        *,
        role: str,
    ) -> None:
        """Refresh local RBAC only for the JWT-bound active cloud context."""
        organization_id = str(context["organization_id"])
        device_id = str(context["device_id"])
        user_id = str(context["user_id"])
        profile_key = f"cloud_device_context:{organization_id}"
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            saved = conn.execute(
                "SELECT value_json FROM local_profile WHERE profile_key=?",
                (profile_key,),
            ).fetchone()
            device = conn.execute(
                """
                SELECT organization_id,user_id,status,key_algorithm,device_kind
                FROM devices WHERE id=?
                """,
                (device_id,),
            ).fetchone()
            if (
                saved is None
                or json.loads(saved["value_json"]) != dict(context)
                or device is None
                or device["organization_id"] != organization_id
                or device["user_id"] not in {user_id, "local-owner"}
                or device["status"] != "active"
                or device["key_algorithm"] != "p256"
                or device["device_kind"] != "desktop"
            ):
                raise ValueError("active cloud device context mismatch")
            result = conn.execute(
                """
                UPDATE memberships
                SET role=?,status='active',revoked_at=NULL
                WHERE organization_id=? AND user_id=?
                """,
                (role, organization_id, user_id),
            )
            if result.rowcount != 1:
                raise ValueError("cloud membership is missing")

    def upsert_cloud_device_metadata(
        self,
        *,
        organization_id: str,
        device_id: str,
        user_id: str | None,
        public_key: bytes,
        key_algorithm: str,
        device_kind: str | None,
        status: str,
    ) -> None:
        """Mirror non-secret device metadata needed by local record FKs."""
        if key_algorithm not in {"x25519", "p256"}:
            raise ValueError("unsupported remote device key algorithm")
        if device_kind not in {None, "desktop", "browser"}:
            raise ValueError("unsupported remote device kind")
        expected_length = 32 if key_algorithm == "x25519" else 65
        if len(public_key) != expected_length:
            raise ValueError("invalid remote device public key length")
        local_user_id = str(user_id or f"sync-device:{device_id}")
        with self._lock, self._connect() as conn:
            existing = conn.execute(
                "SELECT * FROM devices WHERE id=?",
                (device_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["organization_id"] != organization_id
                    or bytes(existing["public_key"]) != bytes(public_key)
                    or (
                        existing["key_algorithm"] is not None
                        and existing["key_algorithm"] != key_algorithm
                    )
                    or (
                        device_kind is not None
                        and existing["device_kind"] is not None
                        and existing["device_kind"] != device_kind
                    )
                    or (
                        user_id is not None
                        and existing["user_id"] != user_id
                    )
                ):
                    raise ValueError("remote device metadata mismatch")
                conn.execute(
                    """
                    UPDATE devices
                    SET status=?,key_algorithm=?,
                        device_kind=COALESCE(?,device_kind)
                    WHERE id=?
                    """,
                    (status, key_algorithm, device_kind, device_id),
                )
                return
            conn.execute(
                """
                INSERT INTO devices(
                    id,organization_id,user_id,name,public_key,
                    key_algorithm,device_kind,status,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    device_id,
                    organization_id,
                    local_user_id,
                    "云端设备",
                    public_key,
                    key_algorithm,
                    device_kind,
                    status,
                    _now(),
                ),
            )

    def get_record_ref(
        self, org_id: str, namespace: str, external_ref: str
    ) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT record_id FROM record_refs
                WHERE organization_id=? AND namespace=? AND external_ref=?
                """,
                (org_id, namespace, external_ref),
            ).fetchone()
        return str(row["record_id"]) if row else None

    def put_record_ref(
        self,
        org_id: str,
        namespace: str,
        external_ref: str,
        record_id: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO record_refs(
                    organization_id,namespace,external_ref,record_id,created_at
                ) VALUES(?,?,?,?,?)
                """,
                (org_id, namespace, external_ref, record_id, _now()),
            )

    def put_conflict(
        self,
        org_id: str,
        record_id: str,
        reason: str,
        local_payload: Mapping,
        remote_payload: Mapping,
    ) -> str:
        conflict_id = f"conf_{uuid.uuid4().hex}"
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO conflicts(
                    id,organization_id,record_id,reason,local_payload_json,
                    remote_payload_json,state,created_at
                ) VALUES(?,?,?,?,?,?,'open',?)
                """,
                (
                    conflict_id,
                    org_id,
                    record_id,
                    reason,
                    json.dumps(local_payload, sort_keys=True),
                    json.dumps(remote_payload, sort_keys=True),
                    _now(),
                ),
            )
        return conflict_id

    def list_conflicts(self, org_id: str) -> list[dict]:
        with self._connect() as conn:
            return [dict(row) for row in conn.execute(
                """
                SELECT id,organization_id,record_id,reason,state,created_at
                FROM conflicts WHERE organization_id=? ORDER BY created_at
                """,
                (org_id,),
            )]

    def get_outbox_for_record(self, record_id: str) -> list[dict]:
        with self._connect() as conn:
            return [dict(row) for row in conn.execute(
                "SELECT * FROM sync_outbox WHERE record_id=? ORDER BY created_at",
                (record_id,),
            )]

    def list_outbox(self, org_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM sync_outbox
                WHERE organization_id=? AND state IN ('pending','retry')
                  AND (next_attempt_at IS NULL OR next_attempt_at<=?)
                ORDER BY created_at
                """,
                (org_id, _now()),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            result.append(item)
        return result

    @staticmethod
    def _initial_snapshot_ids(
        org_id: str,
        record_id: str,
        local_version: int,
        content_hash: str,
    ) -> tuple[str, str]:
        stable_seed = (
            f"defense-tracker-v9:snapshot:{org_id}:{record_id}:"
            f"{int(local_version)}:{content_hash}"
        )
        return (
            str(uuid.uuid5(uuid.NAMESPACE_URL, stable_seed + ":version")),
            str(uuid.uuid5(uuid.NAMESPACE_URL, stable_seed + ":event")),
        )

    @staticmethod
    def _assert_initial_snapshot_queueable(
        conn: sqlite3.Connection, org_id: str
    ) -> None:
        blocked_events = int(conn.execute(
            """
            SELECT COUNT(*)
            FROM sync_outbox o
            LEFT JOIN initial_snapshot_map m ON m.event_id=o.event_id
            WHERE o.organization_id=?
              AND o.state IN ('pending','retry','manual','conflict')
              AND m.event_id IS NULL
            """,
            (org_id,),
        ).fetchone()[0])
        snapshot_conflicts = int(conn.execute(
            """
            SELECT COUNT(*) FROM initial_snapshot_map
            WHERE organization_id=? AND state='conflict'
            """,
            (org_id,),
        ).fetchone()[0])
        if blocked_events:
            raise ValueError(
                "initial snapshot blocked by "
                f"{blocked_events} unsent local event(s)"
            )
        if snapshot_conflicts:
            raise ValueError(
                "initial snapshot blocked by unresolved cloud conflict"
            )

    def build_initial_snapshot_manifest(self, org_id: str) -> dict:
        """Hash stable ciphertext head identities without decrypting content."""
        with self._lock, self._connect() as conn:
            self._assert_initial_snapshot_queueable(conn, org_id)
            rows = conn.execute(
                """
                SELECT r.record_id,r.version,r.content_hash,
                       m.cloud_version_id,m.local_version AS mapped_version,
                       m.content_hash AS mapped_hash
                FROM encrypted_records r
                LEFT JOIN initial_snapshot_map m
                  ON m.organization_id=r.organization_id
                 AND m.record_id=r.record_id
                WHERE r.organization_id=?
                ORDER BY r.record_id
                """,
                (org_id,),
            ).fetchall()
        lines = []
        for row in rows:
            if row["cloud_version_id"] is not None:
                if (
                    int(row["mapped_version"]) != int(row["version"])
                    or row["mapped_hash"] != row["content_hash"]
                ):
                    raise ValueError(
                        "initial snapshot mapping no longer matches local head"
                    )
                cloud_version_id = str(row["cloud_version_id"])
            else:
                cloud_version_id, _ = self._initial_snapshot_ids(
                    org_id,
                    str(row["record_id"]),
                    int(row["version"]),
                    str(row["content_hash"]),
                )
            lines.append(
                f"{row['record_id']}:{cloud_version_id}:{row['content_hash']}"
            )
        lines.sort()
        manifest_hash = hashlib.sha256(
            "\n".join(lines).encode("utf-8")
        ).hexdigest()
        return {
            "organization_id": org_id,
            "expected_count": len(lines),
            "manifest_hash": manifest_hash,
        }

    def begin_initial_snapshot_session(
        self,
        org_id: str,
        *,
        expected_count: int,
        manifest_hash: str,
    ) -> dict:
        with self._lock, self._connect() as conn:
            current = conn.execute(
                """
                SELECT * FROM initial_snapshot_sessions
                WHERE organization_id=?
                """,
                (org_id,),
            ).fetchone()
            if current is not None and current["state"] == "active":
                if (
                    int(current["expected_count"]) != int(expected_count)
                    or current["manifest_hash"] != manifest_hash
                ):
                    raise ValueError(
                        "local snapshot import manifest mismatch"
                    )
                return dict(current)
            conn.execute(
                """
                INSERT INTO initial_snapshot_sessions(
                    organization_id,expected_count,manifest_hash,state,
                    created_at,completed_at
                ) VALUES(?,?,?,'active',?,NULL)
                ON CONFLICT(organization_id) DO UPDATE SET
                    expected_count=excluded.expected_count,
                    manifest_hash=excluded.manifest_hash,
                    state='active',
                    created_at=excluded.created_at,
                    completed_at=NULL
                """,
                (org_id, int(expected_count), manifest_hash, _now()),
            )
            return dict(conn.execute(
                """
                SELECT * FROM initial_snapshot_sessions
                WHERE organization_id=?
                """,
                (org_id,),
            ).fetchone())

    def has_active_initial_snapshot_session(self, org_id: str) -> bool:
        with self._connect() as conn:
            return conn.execute(
                """
                SELECT 1 FROM initial_snapshot_sessions
                WHERE organization_id=? AND state='active'
                """,
                (org_id,),
            ).fetchone() is not None

    def abort_initial_snapshot_session(
        self, org_id: str, manifest_hash: str
    ) -> None:
        with self._lock, self._connect() as conn:
            result = conn.execute(
                """
                UPDATE initial_snapshot_sessions SET state='aborted'
                WHERE organization_id=? AND manifest_hash=? AND state='active'
                """,
                (org_id, manifest_hash),
            )
            if result.rowcount != 1:
                raise KeyError(org_id)

    def complete_initial_snapshot_session(
        self, org_id: str, manifest_hash: str
    ) -> None:
        with self._lock, self._connect() as conn:
            result = conn.execute(
                """
                UPDATE initial_snapshot_sessions
                SET state='completed',completed_at=?
                WHERE organization_id=? AND manifest_hash=? AND state='active'
                """,
                (_now(), org_id, manifest_hash),
            )
            if result.rowcount != 1:
                current = conn.execute(
                    """
                    SELECT state,manifest_hash FROM initial_snapshot_sessions
                    WHERE organization_id=?
                    """,
                    (org_id,),
                ).fetchone()
                if (
                    current is None
                    or current["state"] != "completed"
                    or current["manifest_hash"] != manifest_hash
                ):
                    raise KeyError(org_id)

    def get_initial_snapshot_completion(self, org_id: str) -> dict:
        """Report whether every locally staged snapshot has been acknowledged."""
        manifest = self.build_initial_snapshot_manifest(org_id)
        with self._lock, self._connect() as conn:
            mapped_count = int(conn.execute(
                """
                SELECT COUNT(*) FROM initial_snapshot_map
                WHERE organization_id=?
                """,
                (org_id,),
            ).fetchone()[0])
            blocking_count = int(conn.execute(
                """
                SELECT COUNT(*)
                FROM initial_snapshot_map m
                LEFT JOIN sync_outbox o ON o.event_id=m.event_id
                WHERE m.organization_id=?
                  AND (
                    m.state IN ('queued','manual','conflict')
                    OR o.state IN ('pending','retry','manual','conflict')
                  )
                """,
                (org_id,),
            ).fetchone()[0])
            unsent_count = int(conn.execute(
                """
                SELECT COUNT(*) FROM initial_snapshot_map
                WHERE organization_id=? AND state<>'sent'
                """,
                (org_id,),
            ).fetchone()[0])
        ready = (
            mapped_count == manifest["expected_count"]
            and blocking_count == 0
            and unsent_count == 0
        )
        return manifest | {
            "mapped_count": mapped_count,
            "blocking_count": blocking_count,
            "unsent_count": unsent_count,
            "ready": ready,
        }

    def queue_initial_snapshot(self, org_id: str) -> dict[str, int]:
        """Explicitly queue current ciphertext heads for a new empty cloud."""
        queued = 0
        already_queued = 0
        skipped_pending = 0
        requeued = 0
        with self._lock, self._connect() as conn:
            self._assert_initial_snapshot_queueable(conn, org_id)
            rows = conn.execute(
                """
                SELECT * FROM encrypted_records
                WHERE organization_id=? ORDER BY record_id
                """,
                (org_id,),
            ).fetchall()
            for row in rows:
                mapping = conn.execute(
                    """
                    SELECT event_id,state FROM initial_snapshot_map
                    WHERE organization_id=? AND record_id=?
                    """,
                    (org_id, row["record_id"]),
                ).fetchone()
                if mapping is not None:
                    outbox = conn.execute(
                        """
                        SELECT state FROM sync_outbox WHERE event_id=?
                        """,
                        (mapping["event_id"],),
                    ).fetchone()
                    if (
                        mapping["state"] != "sent"
                        and outbox is not None
                        and outbox["state"] == "manual"
                    ):
                        conn.execute(
                            """
                            UPDATE sync_outbox
                            SET attempts=0,state='pending',last_error=NULL,
                                next_attempt_at=NULL
                            WHERE event_id=?
                            """,
                            (mapping["event_id"],),
                        )
                        conn.execute(
                            """
                            UPDATE initial_snapshot_map SET state='queued'
                            WHERE event_id=?
                            """,
                            (mapping["event_id"],),
                        )
                        requeued += 1
                        continue
                    already_queued += 1
                    continue
                pending = conn.execute(
                    """
                    SELECT 1 FROM sync_outbox
                    WHERE organization_id=? AND record_id=?
                      AND state IN ('pending','retry','manual')
                    LIMIT 1
                    """,
                    (org_id, row["record_id"]),
                ).fetchone()
                if pending is not None:
                    skipped_pending += 1
                    continue

                cloud_version_id, event_id = self._initial_snapshot_ids(
                    org_id,
                    str(row["record_id"]),
                    int(row["version"]),
                    str(row["content_hash"]),
                )
                envelope = RecordEnvelope.from_mapping(dict(row))
                payload = envelope.to_dict() | {
                    "device_id": row["device_id"],
                    "deleted": bool(row["deleted"]),
                    "updated_at": row["updated_at"],
                    "version_id": cloud_version_id,
                    "base_version_id": None,
                }
                inserted = conn.execute(
                    """
                    INSERT OR IGNORE INTO sync_outbox(
                        event_id,organization_id,record_id,operation,payload_json,
                        attempts,state,created_at
                    ) VALUES(?,?,?,?,?,0,'pending',?)
                    """,
                    (
                        event_id,
                        org_id,
                        row["record_id"],
                        "snapshot",
                        json.dumps(payload, sort_keys=True),
                        _now(),
                    ),
                )
                if inserted.rowcount != 1:
                    already_queued += 1
                    continue
                conn.execute(
                    """
                    INSERT INTO initial_snapshot_map(
                        organization_id,record_id,event_id,cloud_version_id,
                        previous_cloud_version_id,local_version,content_hash,
                        state,created_at
                    ) VALUES(?,?,?,?,?,?,?,'queued',?)
                    """,
                    (
                        org_id,
                        row["record_id"],
                        event_id,
                        cloud_version_id,
                        row["cloud_version_id"],
                        int(row["version"]),
                        row["content_hash"],
                        _now(),
                    ),
                )
                queued += 1
        return {
            "queued": queued,
            "already_queued": already_queued,
            "skipped_pending": skipped_pending,
            "requeued": requeued,
        }

    def has_pending_outbox(self, record_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT 1 FROM sync_outbox
                WHERE record_id=? AND state IN ('pending','retry') LIMIT 1
                """,
                (record_id,),
            ).fetchone()
        return row is not None

    def has_sync_event(self, event_id: str) -> bool:
        with self._connect() as conn:
            return conn.execute(
                "SELECT 1 FROM sync_events WHERE event_id=?", (event_id,)
            ).fetchone() is not None

    def record_sync_event(
        self, event_id: str, org_id: str, remote_cursor: int | None
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO sync_events(
                    event_id,organization_id,remote_cursor,applied_at
                ) VALUES(?,?,?,?)
                """,
                (event_id, org_id, remote_cursor, _now()),
            )
            if remote_cursor is not None:
                conn.execute(
                    """
                    INSERT INTO sync_cursor(organization_id,remote_cursor,updated_at)
                    VALUES(?,?,?)
                    ON CONFLICT(organization_id) DO UPDATE SET
                        remote_cursor=MAX(sync_cursor.remote_cursor,excluded.remote_cursor),
                        updated_at=excluded.updated_at
                    """,
                    (org_id, int(remote_cursor), _now()),
                )

    def quarantine_sync_event(
        self,
        *,
        event_id: str | None,
        organization_id: str,
        record_id: str | None,
        operation: str | None,
        remote_cursor: int,
        reason: str,
        event_hash: str,
        event_bytes: int,
        encrypted_event_json: str | None,
    ) -> None:
        """Atomically audit a rejected ciphertext and advance its cursor."""
        if reason not in {
            "invalid_ciphertext_structure",
            "ciphertext_authentication_failed",
            "content_integrity_failed",
        }:
            raise ValueError("invalid sync quarantine reason")
        if (
            len(event_hash) != 64
            or any(character not in "0123456789abcdef" for character in event_hash)
        ):
            raise ValueError("event_hash must be lowercase SHA-256")
        if int(remote_cursor) < 1 or int(event_bytes) < 0:
            raise ValueError("invalid sync quarantine cursor or size")
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                """
                SELECT event_id,reason,event_hash FROM sync_quarantine
                WHERE organization_id=? AND remote_cursor=?
                """,
                (organization_id, int(remote_cursor)),
            ).fetchone()
            if existing is not None:
                if (
                    existing["event_id"] != event_id
                    or existing["reason"] != reason
                    or existing["event_hash"] != event_hash
                ):
                    raise ValueError("quarantined sync event changed")
                return
            if event_id and conn.execute(
                "SELECT 1 FROM sync_events WHERE event_id=?",
                (event_id,),
            ).fetchone() is not None:
                raise ValueError("applied sync event cannot be quarantined")
            now = _now()
            conn.execute(
                """
                INSERT INTO sync_quarantine(
                    organization_id,remote_cursor,event_id,record_id,operation,
                    reason,state,event_hash,event_bytes,encrypted_event_json,
                    first_seen_at,last_seen_at
                ) VALUES(?,?,?,?,?,?,'quarantined',?,?,?,?,?)
                """,
                (
                    organization_id,
                    int(remote_cursor),
                    event_id,
                    record_id,
                    operation,
                    reason,
                    event_hash,
                    int(event_bytes),
                    encrypted_event_json,
                    now,
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO sync_quarantine_audit(
                    organization_id,remote_cursor,action,reason,created_at
                ) VALUES(?,?,'seen',?,?)
                """,
                (organization_id, int(remote_cursor), reason, now),
            )
            conn.execute(
                """
                INSERT INTO sync_cursor(organization_id,remote_cursor,updated_at)
                VALUES(?,?,?)
                ON CONFLICT(organization_id) DO UPDATE SET
                    remote_cursor=MAX(
                        sync_cursor.remote_cursor,
                        excluded.remote_cursor
                    ),
                    updated_at=excluded.updated_at
                """,
                (organization_id, int(remote_cursor), _now()),
            )

    def list_sync_quarantine(self, org_id: str) -> list[dict]:
        with self._connect() as conn:
            return [dict(row) for row in conn.execute(
                """
                SELECT organization_id,remote_cursor,event_id,record_id,
                       operation,reason,state,event_hash,event_bytes,
                       first_seen_at,last_seen_at,retry_count,last_retry_at,
                       resolved_at,resolution_code
                FROM sync_quarantine
                WHERE organization_id=?
                ORDER BY remote_cursor
                """,
                (org_id,),
            )]

    def count_unresolved_sync_quarantine(self, org_id: str) -> int:
        with self._connect() as conn:
            return int(conn.execute(
                """
                SELECT COUNT(*) FROM sync_quarantine
                WHERE organization_id=?
                  AND state IN ('quarantined','reprocessing')
                """,
                (org_id,),
            ).fetchone()[0])

    def get_sync_cursor(self, org_id: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT remote_cursor FROM sync_cursor WHERE organization_id=?",
                (org_id,),
            ).fetchone()
        return int(row["remote_cursor"]) if row else 0

    def get_sync_status(self, org_id: str) -> dict:
        with self._connect() as conn:
            outbox = dict(conn.execute(
                """
                SELECT state,COUNT(*) FROM sync_outbox
                WHERE organization_id=? GROUP BY state
                """,
                (org_id,),
            ))
            conflicts = dict(conn.execute(
                """
                SELECT state,COUNT(*) FROM conflicts
                WHERE organization_id=? GROUP BY state
                """,
                (org_id,),
            ))
            devices = dict(conn.execute(
                """
                SELECT status,COUNT(*) FROM devices
                WHERE organization_id=? GROUP BY status
                """,
                (org_id,),
            ))
            quarantined = self.count_unresolved_sync_quarantine(org_id)
        return {
            "organization_id": org_id,
            "cursor": self.get_sync_cursor(org_id),
            "outbox": outbox,
            "conflicts": conflicts,
            "devices": devices,
            "quarantined": quarantined,
            "degraded": quarantined > 0,
        }

    def mark_outbox_sent(
        self, event_id: str, remote_cursor: int | None = None
    ) -> None:
        """Acknowledge an upload without advancing the inbound apply cursor."""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT organization_id,record_id,operation,payload_json
                FROM sync_outbox WHERE event_id=?
                """,
                (event_id,),
            ).fetchone()
            if row is None:
                raise KeyError(event_id)
            conn.execute(
                """
                UPDATE sync_outbox
                SET state='sent',last_error=NULL,next_attempt_at=NULL
                WHERE event_id=?
                """,
                (event_id,),
            )
            if row["operation"] == "snapshot":
                payload = json.loads(row["payload_json"])
                conn.execute(
                    """
                    UPDATE initial_snapshot_map
                    SET state='sent',sent_at=?
                    WHERE event_id=?
                    """,
                    (_now(), event_id),
                )
                conn.execute(
                    """
                    UPDATE encrypted_records SET cloud_version_id=?
                    WHERE organization_id=? AND record_id=?
                      AND version=? AND content_hash=?
                    """,
                    (
                        payload["version_id"],
                        row["organization_id"],
                        row["record_id"],
                        int(payload["version"]),
                        payload["content_hash"],
                    ),
                )

    def mark_outbox_conflicted(
        self, event_id: str, remote_cursor: int | None = None
    ) -> dict:
        """Atomically preserve a rejected cloud branch and freeze its base."""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT organization_id,record_id,operation,payload_json
                FROM sync_outbox WHERE event_id=?
                """,
                (event_id,),
            ).fetchone()
            if row is None:
                raise KeyError(event_id)
            payload = json.loads(row["payload_json"])
            base_version_id = payload.get("base_version_id")
            incoming_version_id = str(payload["version_id"])
            conn.execute(
                """
                UPDATE sync_outbox
                SET state='conflict',last_error='cloud branch preserved',
                    next_attempt_at=NULL
                WHERE event_id=?
                """,
                (event_id,),
            )
            if row["operation"] == "snapshot":
                conn.execute(
                    """
                    UPDATE initial_snapshot_map SET state='conflict'
                    WHERE event_id=?
                    """,
                    (event_id,),
                )
            conn.execute(
                """
                UPDATE encrypted_records SET cloud_version_id=?
                WHERE organization_id=? AND record_id=?
                  AND cloud_version_id=?
                """,
                (
                    base_version_id,
                    row["organization_id"],
                    row["record_id"],
                    incoming_version_id,
                ),
            )
            conn.execute(
                """
                INSERT INTO sync_blocks(
                    organization_id,record_id,event_id,operation,
                    base_version_id,incoming_version_id,remote_cursor,
                    reason,created_at,resolved_at
                ) VALUES(?,?,?,?,?,?,?,'cloud_branch_preserved',?,NULL)
                ON CONFLICT(organization_id,record_id) DO UPDATE SET
                    event_id=excluded.event_id,
                    operation=excluded.operation,
                    base_version_id=excluded.base_version_id,
                    incoming_version_id=excluded.incoming_version_id,
                    remote_cursor=excluded.remote_cursor,
                    reason=excluded.reason,
                    created_at=excluded.created_at,
                    resolved_at=NULL
                """,
                (
                    row["organization_id"],
                    row["record_id"],
                    event_id,
                    row["operation"],
                    base_version_id,
                    incoming_version_id,
                    remote_cursor,
                    _now(),
                ),
            )
            return {
                "event_id": event_id,
                "organization_id": row["organization_id"],
                "record_id": row["record_id"],
                "operation": row["operation"],
                "base_version_id": base_version_id,
                "incoming_version_id": incoming_version_id,
                "remote_cursor": remote_cursor,
                "state": "conflict",
            }

    def clear_sync_block(
        self,
        org_id: str,
        record_id: str,
        *,
        cloud_head_version_id: str,
    ) -> None:
        """Record the head chosen by an explicit conflict resolution."""
        if not self._is_uuid(cloud_head_version_id):
            raise ValueError("cloud_head_version_id must be a UUID")
        with self._lock, self._connect() as conn:
            result = conn.execute(
                """
                UPDATE sync_blocks SET resolved_at=?
                WHERE organization_id=? AND record_id=? AND resolved_at IS NULL
                """,
                (_now(), org_id, record_id),
            )
            if result.rowcount != 1:
                raise KeyError(record_id)
            conn.execute(
                """
                UPDATE encrypted_records SET cloud_version_id=?
                WHERE organization_id=? AND record_id=?
                """,
                (cloud_head_version_id, org_id, record_id),
            )

    def get_sync_block(self, org_id: str, record_id: str) -> dict | None:
        with self._connect() as conn:
            return _dict(conn.execute(
                """
                SELECT * FROM sync_blocks
                WHERE organization_id=? AND record_id=?
                """,
                (org_id, record_id),
            ).fetchone())

    def get_conflict(self, conflict_id: str) -> dict | None:
        with self._connect() as conn:
            return _dict(conn.execute(
                "SELECT * FROM conflicts WHERE id=?",
                (conflict_id,),
            ).fetchone())

    def mark_outbox_failed(self, event_id: str, error: str) -> dict:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sync_outbox WHERE event_id=?", (event_id,)
            ).fetchone()
            if row is None:
                raise KeyError(event_id)
            attempts = int(row["attempts"])
            if attempts >= len(RETRY_DELAYS_SECONDS):
                conn.execute(
                    """
                    UPDATE sync_outbox SET state='manual',last_error=?,next_attempt_at=NULL
                    WHERE event_id=?
                    """,
                    (error[:500], event_id),
                )
                if row["operation"] == "snapshot":
                    conn.execute(
                        """
                        UPDATE initial_snapshot_map SET state='manual'
                        WHERE event_id=?
                        """,
                        (event_id,),
                    )
                result = dict(row)
                result.update(
                    state="manual",
                    attempts=attempts,
                    retry_delay_seconds=None,
                    last_error=error[:500],
                )
                return result
            delay = RETRY_DELAYS_SECONDS[attempts]
            next_attempt = datetime.now(timezone.utc) + timedelta(seconds=delay)
            attempts += 1
            conn.execute(
                """
                UPDATE sync_outbox SET
                    attempts=?,state='retry',last_error=?,next_attempt_at=?
                WHERE event_id=?
                """,
                (attempts, error[:500], next_attempt.isoformat(), event_id),
            )
            result = dict(row)
            result.update(
                state="retry",
                attempts=attempts,
                retry_delay_seconds=delay,
                last_error=error[:500],
                next_attempt_at=next_attempt.isoformat(),
            )
            return result

    def apply_key_rotation(
        self,
        org_id: str,
        new_key_version: int,
        records: Iterable[tuple[RecordEnvelope, str, bool]],
        device_envelopes: Iterable[Mapping],
        recovery_envelope: Mapping,
        *,
        revoke_device_id: str | None = None,
        revoke_user_id: str | None = None,
    ) -> None:
        with self._lock, self._connect() as conn:
            active_snapshot = conn.execute(
                """
                SELECT 1 FROM initial_snapshot_sessions
                WHERE organization_id=? AND state='active'
                """,
                (org_id,),
            ).fetchone()
            if active_snapshot is not None:
                raise ValueError(
                    "key rotation is blocked during initial snapshot import"
                )
            if revoke_device_id is not None:
                result = conn.execute(
                    """
                    UPDATE devices SET status='revoked',revoked_at=?
                    WHERE id=? AND organization_id=? AND status='active'
                    """,
                    (_now(), revoke_device_id, org_id),
                )
                if result.rowcount != 1:
                    raise ValueError("device is not active")
            if revoke_user_id is not None:
                result = conn.execute(
                    """
                    UPDATE memberships SET status='revoked',revoked_at=?
                    WHERE organization_id=? AND user_id=? AND status='active'
                    """,
                    (_now(), org_id, revoke_user_id),
                )
                if result.rowcount != 1:
                    raise ValueError("membership is not active")
                conn.execute(
                    """
                    UPDATE devices SET status='revoked',revoked_at=?
                    WHERE organization_id=? AND user_id=? AND status='active'
                    """,
                    (_now(), org_id, revoke_user_id),
                )
            for envelope, device_id, deleted in records:
                conn.execute(
                    """
                    UPDATE encrypted_records SET
                        key_version=?,wrapped_data_key=?,wrap_nonce=?,updated_at=?
                    WHERE record_id=? AND organization_id=?
                    """,
                    (
                        envelope.key_version,
                        envelope.wrapped_data_key,
                        envelope.wrap_nonce,
                        _now(),
                        envelope.record_id,
                        org_id,
                    ),
                )
                payload = envelope.to_dict() | {
                    "device_id": device_id,
                    "deleted": bool(deleted),
                    "updated_at": _now(),
                }
                conn.execute(
                    """
                    INSERT INTO sync_outbox(
                        event_id,organization_id,record_id,operation,payload_json,
                        attempts,state,created_at
                    ) VALUES(?,?,?,?,?,0,'pending',?)
                    """,
                    (
                        f"evt_{uuid.uuid4().hex}",
                        org_id,
                        envelope.record_id,
                        "rewrap",
                        json.dumps(payload, sort_keys=True),
                        _now(),
                    ),
                )
            for payload in device_envelopes:
                conn.execute(
                    """
                    INSERT INTO key_envelopes(
                        id,organization_id,device_id,key_version,payload_json,created_at
                    ) VALUES(?,?,?,?,?,?)
                    """,
                    (
                        f"env_{uuid.uuid4().hex}",
                        org_id,
                        payload["device_id"],
                        new_key_version,
                        json.dumps(payload, sort_keys=True),
                        _now(),
                    ),
                )
            conn.execute(
                """
                INSERT INTO recovery_envelopes(
                    organization_id,key_version,payload_json,created_at
                ) VALUES(?,?,?,?)
                """,
                (
                    org_id,
                    new_key_version,
                    json.dumps(recovery_envelope, sort_keys=True),
                    _now(),
                ),
            )
            conn.execute(
                "UPDATE organizations SET key_version=? WHERE id=?",
                (new_key_version, org_id),
            )
