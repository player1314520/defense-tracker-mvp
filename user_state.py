# -*- coding: utf-8 -*-
"""用户状态上收（三端联动地基）：书签 / 已读 / 预警词 / 要讯历史 → 服务端 SQLite。

此前这些数据全在浏览器 localStorage（news.js/brief.js），换浏览器/设备即丢，
后端与飞书端完全不可见——是三端联动的第一堵墙。本模块把它们收到服务端
data/user_state.sqlite3，前端改为 write-through（localStorage 保留做离线缓存）。

设计沿用 tracking.py 的成熟模式：
- 不 import app（避免循环 import），鉴权由 app.py 注册时注入 `_auth_check` 回调
- 文章身份用 state.canonical_article_id（同文异链归一），服务端计算，前端只传原始 link
- 书签/已读按行存（跨设备天然并集）；要讯历史按条目存并用 revision 做乐观并发
- 旧 kv blob 路由保留一个兼容周期，由条目存储反向同步，不再作为真相源
"""
import os
import json
import sqlite3
import logging
import uuid
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, g

from state import DATA_DIR, canonical_article_id

logger = logging.getLogger(__name__)

user_state_bp = Blueprint("user_state", __name__)

# 鉴权注入点：app.py 注册后设置 user_state._auth_check = <callable>
# 约定：返回 Response 表示拦截，返回 None 表示放行（与 tracking.py 一致）。
_auth_check = None
_bootstrap_config_provider = None
_BUDGET_LEASE_ID = uuid.uuid4().hex


@user_state_bp.before_request
def _user_state_before():
    if _auth_check is not None:
        resp = _auth_check()
        if resp is not None:
            return resp
    return None


USER_STATE_DB_FILE = os.path.join(DATA_DIR, "user_state.sqlite3")
USER_STATE_SCHEMA_VERSION = 3


class StateStoreError(RuntimeError):
    """Stable storage-layer error suitable for HTTP/API translation."""

    def __init__(self, code, message, details=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


def _conn():
    os.makedirs(os.path.dirname(USER_STATE_DB_FILE), exist_ok=True)
    conn = sqlite3.connect(USER_STATE_DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_user_state_db():
    with _conn() as conn:
        conn.executescript("""
        PRAGMA journal_mode=WAL;
        PRAGMA busy_timeout=10000;
        CREATE TABLE IF NOT EXISTS bookmarks(
            aid        TEXT PRIMARY KEY,       -- canonical_article_id(link)
            link       TEXT NOT NULL,
            title      TEXT DEFAULT '',
            source     TEXT DEFAULT '',
            date       TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS read_marks(
            aid     TEXT PRIMARY KEY,
            link    TEXT NOT NULL,
            read_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS alert_keywords(
            term       TEXT PRIMARY KEY,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS kv(
            key        TEXT PRIMARY KEY,       -- 目前仅 'briefResults'
            value_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS schema_migrations(
            version    INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS state_meta(
            singleton      INTEGER PRIMARY KEY CHECK(singleton = 1),
            schema_version INTEGER NOT NULL,
            revision       INTEGER NOT NULL CHECK(revision >= 0),
            updated_at     TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS brief_results(
            item_id    TEXT PRIMARY KEY,
            value_json TEXT NOT NULL,
            sort_order INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS runtime_kv(
            namespace  TEXT NOT NULL,
            key        TEXT NOT NULL,
            value_json TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(namespace, key)
        );
        CREATE TABLE IF NOT EXISTS daily_budgets(
            namespace   TEXT NOT NULL,
            budget_date TEXT NOT NULL,
            daily_limit INTEGER NOT NULL CHECK(daily_limit >= 0),
            reserved    INTEGER NOT NULL DEFAULT 0 CHECK(reserved >= 0),
            confirmed   INTEGER NOT NULL DEFAULT 0 CHECK(confirmed >= 0),
            updated_at  TEXT NOT NULL,
            PRIMARY KEY(namespace, budget_date)
        );
        CREATE TABLE IF NOT EXISTS budget_reservations(
            reservation_id TEXT PRIMARY KEY,
            namespace      TEXT NOT NULL,
            budget_date    TEXT NOT NULL,
            amount         INTEGER NOT NULL CHECK(amount > 0),
            status         TEXT NOT NULL CHECK(status IN ('reserved','confirmed','released')),
            lease_id       TEXT,
            updated_at     TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS rss_runtime(
            feed_id       TEXT PRIMARY KEY,
            snapshot_json TEXT,
            fetched_at    TEXT,
            failure_code  TEXT,
            failed_at     TEXT,
            failure_count INTEGER NOT NULL DEFAULT 0,
            updated_at    TEXT NOT NULL
        );
        """)
        reservation_columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(budget_reservations)").fetchall()
        }
        if "lease_id" not in reservation_columns:
            conn.execute("ALTER TABLE budget_reservations ADD COLUMN lease_id TEXT")
        now = _now()
        conn.executemany(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(?,?)",
            [
                (version, now)
                for version in range(1, USER_STATE_SCHEMA_VERSION + 1)
            ],
        )
        conn.execute(
            "INSERT OR IGNORE INTO state_meta"
            "(singleton, schema_version, revision, updated_at) VALUES(1,?,?,?)",
            (USER_STATE_SCHEMA_VERSION, 0, now),
        )
        conn.execute(
            "UPDATE state_meta SET schema_version=?, updated_at=? WHERE singleton=1",
            (USER_STATE_SCHEMA_VERSION, now),
        )
        _migrate_legacy_brief_results(conn, now)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_dump(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _require_name(value, field):
    text = str(value or "").strip()
    if not text or len(text) > 200:
        raise StateStoreError("INVALID_ARGUMENT", f"{field} 无效", {"field": field})
    return text


def _require_positive_int(value, field, allow_zero=False):
    if isinstance(value, bool) or not isinstance(value, int):
        raise StateStoreError("INVALID_ARGUMENT", f"{field} 必须是整数", {"field": field})
    minimum = 0 if allow_zero else 1
    if value < minimum:
        raise StateStoreError("INVALID_ARGUMENT", f"{field} 超出范围", {"field": field})
    return value


def _migrate_legacy_brief_results(conn, now):
    if conn.execute("SELECT 1 FROM brief_results LIMIT 1").fetchone():
        return
    row = conn.execute("SELECT value_json FROM kv WHERE key='briefResults'").fetchone()
    if not row:
        return
    try:
        values = json.loads(row["value_json"])
    except (TypeError, ValueError):
        return
    if not isinstance(values, list):
        return
    _write_brief_rows(conn, values[:50], now)


def _write_brief_rows(conn, values, now):
    total = len(values)
    for index, item in enumerate(values):
        if not isinstance(item, dict):
            continue
        item_id = str(item.get("id") or "").strip()
        if not item_id:
            continue
        conn.execute(
            "INSERT INTO brief_results(item_id, value_json, sort_order, updated_at) "
            "VALUES(?,?,?,?) ON CONFLICT(item_id) DO UPDATE SET "
            "value_json=excluded.value_json, sort_order=excluded.sort_order, "
            "updated_at=excluded.updated_at",
            (item_id[:200], _json_dump(item), total - index, now),
        )


def _brief_results_from_conn(conn):
    rows = conn.execute(
        "SELECT value_json FROM brief_results ORDER BY sort_order DESC, item_id"
    ).fetchall()
    results = []
    for row in rows:
        try:
            value = json.loads(row["value_json"])
        except (TypeError, ValueError):
            continue
        if isinstance(value, dict):
            results.append(value)
    return results


def _state_from_conn(conn):
    meta = conn.execute(
        "SELECT schema_version, revision FROM state_meta WHERE singleton=1"
    ).fetchone()
    return {
        "schema_version": int(meta["schema_version"]),
        "revision": int(meta["revision"]),
        "brief_results": _brief_results_from_conn(conn),
    }


def _check_expected_revision(current_revision, expected_revision):
    if expected_revision is None:
        return
    if (
        isinstance(expected_revision, bool)
        or not isinstance(expected_revision, int)
        or expected_revision < 0
    ):
        raise StateStoreError(
            "INVALID_REVISION", "expected_revision 必须是非负整数"
        )
    if expected_revision != current_revision:
        raise StateStoreError(
            "REVISION_CONFLICT",
            "状态已被其他窗口更新",
            {
                "expected_revision": expected_revision,
                "current_revision": current_revision,
            },
        )


def _advance_revision(conn, current_revision, now):
    revision = current_revision + 1
    conn.execute(
        "UPDATE state_meta SET revision=?, schema_version=?, updated_at=? "
        "WHERE singleton=1",
        (revision, USER_STATE_SCHEMA_VERSION, now),
    )
    return revision


def _sync_legacy_brief_blob(conn, now):
    values = _brief_results_from_conn(conn)
    conn.execute(
        "INSERT INTO kv(key, value_json, updated_at) VALUES('briefResults',?,?) "
        "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, "
        "updated_at=excluded.updated_at",
        (_json_dump(values), now),
    )


def get_server_migration_version():
    with _conn() as conn:
        row = conn.execute("SELECT MAX(version) AS version FROM schema_migrations").fetchone()
    return int(row["version"] or 0)


def get_user_state():
    with _conn() as conn:
        return _state_from_conn(conn)


def upsert_brief_result(item, expected_revision=None):
    if not isinstance(item, dict):
        raise StateStoreError("INVALID_ARGUMENT", "item 必须是对象", {"field": "item"})
    item_id = _require_name(item.get("id"), "id")
    payload = _json_dump(item)
    if len(payload.encode("utf-8")) > 2_000_000:
        raise StateStoreError("PAYLOAD_TOO_LARGE", "payload 过大")
    now = _now()
    with _conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        current = _state_from_conn(conn)["revision"]
        _check_expected_revision(current, expected_revision)
        order_row = conn.execute(
            "SELECT COALESCE(MAX(sort_order), 0) + 1 AS next_order FROM brief_results"
        ).fetchone()
        conn.execute(
            "INSERT INTO brief_results(item_id, value_json, sort_order, updated_at) "
            "VALUES(?,?,?,?) ON CONFLICT(item_id) DO UPDATE SET "
            "value_json=excluded.value_json, sort_order=excluded.sort_order, "
            "updated_at=excluded.updated_at",
            (item_id, payload, int(order_row["next_order"]), now),
        )
        _advance_revision(conn, current, now)
        _sync_legacy_brief_blob(conn, now)
        return _state_from_conn(conn)


def delete_brief_results(item_ids, expected_revision=None):
    """Delete only the caller's snapshot ids, preserving concurrent additions."""
    if not isinstance(item_ids, list):
        raise StateStoreError(
            "INVALID_ARGUMENT", "item_ids 必须是数组", {"field": "item_ids"}
        )
    normalized = []
    seen = set()
    for value in item_ids:
        item_id = _require_name(value, "item_ids")
        if item_id not in seen:
            seen.add(item_id)
            normalized.append(item_id)
    if not normalized:
        raise StateStoreError(
            "INVALID_ARGUMENT", "item_ids 不能为空", {"field": "item_ids"}
        )
    if len(normalized) > 50:
        raise StateStoreError(
            "INVALID_ARGUMENT", "item_ids 最多 50 项", {"field": "item_ids"}
        )

    now = _now()
    with _conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        current = _state_from_conn(conn)["revision"]
        _check_expected_revision(current, expected_revision)
        placeholders = ",".join("?" for _ in normalized)
        cursor = conn.execute(
            f"DELETE FROM brief_results WHERE item_id IN ({placeholders})",
            normalized,
        )
        if cursor.rowcount:
            _advance_revision(conn, current, now)
            _sync_legacy_brief_blob(conn, now)
        return _state_from_conn(conn)


def replace_brief_results_legacy(values, expected_revision=None):
    if not isinstance(values, list):
        raise StateStoreError("INVALID_ARGUMENT", "value 必须是数组", {"field": "value"})
    values = values[:50]
    payload = _json_dump(values)
    if len(payload.encode("utf-8")) > 2_000_000:
        raise StateStoreError("PAYLOAD_TOO_LARGE", "payload 过大")
    now = _now()
    with _conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        current = _state_from_conn(conn)["revision"]
        _check_expected_revision(current, expected_revision)
        conn.execute("DELETE FROM brief_results")
        _write_brief_rows(conn, values, now)
        _advance_revision(conn, current, now)
        _sync_legacy_brief_blob(conn, now)
        return _state_from_conn(conn)


def set_runtime_value(namespace, key, value):
    namespace = _require_name(namespace, "namespace")
    key = _require_name(key, "key")
    now = _now()
    with _conn() as conn:
        conn.execute(
            "INSERT INTO runtime_kv(namespace, key, value_json, updated_at) "
            "VALUES(?,?,?,?) ON CONFLICT(namespace,key) DO UPDATE SET "
            "value_json=excluded.value_json, updated_at=excluded.updated_at",
            (namespace, key, _json_dump(value), now),
        )
    return value


def get_runtime_value(namespace, key, default=None):
    namespace = _require_name(namespace, "namespace")
    key = _require_name(key, "key")
    with _conn() as conn:
        row = conn.execute(
            "SELECT value_json FROM runtime_kv WHERE namespace=? AND key=?",
            (namespace, key),
        ).fetchone()
    if not row:
        return default
    try:
        return json.loads(row["value_json"])
    except (TypeError, ValueError):
        return default


def _budget_row(conn, namespace, budget_date):
    row = conn.execute(
        "SELECT namespace, budget_date, daily_limit, reserved, confirmed "
        "FROM daily_budgets WHERE namespace=? AND budget_date=?",
        (namespace, budget_date),
    ).fetchone()
    if not row:
        return {
            "namespace": namespace,
            "budget_date": budget_date,
            "daily_limit": None,
            "reserved": 0,
            "confirmed": 0,
        }
    return dict(row)


def get_daily_budget(namespace, budget_date):
    namespace = _require_name(namespace, "namespace")
    budget_date = _require_name(budget_date, "budget_date")
    with _conn() as conn:
        return _budget_row(conn, namespace, budget_date)


def reserve_daily_budget(
    namespace, budget_date, amount, daily_limit, reservation_id
):
    namespace = _require_name(namespace, "namespace")
    budget_date = _require_name(budget_date, "budget_date")
    reservation_id = _require_name(reservation_id, "reservation_id")
    amount = _require_positive_int(amount, "amount")
    daily_limit = _require_positive_int(daily_limit, "daily_limit", allow_zero=True)
    now = _now()
    with _conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            "SELECT namespace, budget_date, amount, status FROM budget_reservations "
            "WHERE reservation_id=?",
            (reservation_id,),
        ).fetchone()
        if existing:
            if (
                existing["namespace"] != namespace
                or existing["budget_date"] != budget_date
                or int(existing["amount"]) != amount
            ):
                raise StateStoreError(
                    "RESERVATION_MISMATCH",
                    "reservation_id 已用于其他预留",
                    {"reservation_id": reservation_id},
                )
            result = _budget_row(conn, namespace, budget_date)
            result["reservation_id"] = reservation_id
            result["reservation_status"] = existing["status"]
            return result

        ledger = _budget_row(conn, namespace, budget_date)
        if ledger["daily_limit"] is None:
            conn.execute(
                "INSERT INTO daily_budgets"
                "(namespace,budget_date,daily_limit,reserved,confirmed,updated_at) "
                "VALUES(?,?,?,?,?,?)",
                (namespace, budget_date, daily_limit, 0, 0, now),
            )
            ledger["daily_limit"] = daily_limit
        elif int(ledger["daily_limit"]) != daily_limit:
            raise StateStoreError(
                "BUDGET_LIMIT_MISMATCH",
                "当日预算上限已固定",
                {
                    "configured_limit": int(ledger["daily_limit"]),
                    "requested_limit": daily_limit,
                },
            )
        if int(ledger["reserved"]) + int(ledger["confirmed"]) + amount > daily_limit:
            raise StateStoreError(
                "BUDGET_EXCEEDED",
                "当日预算不足",
                {
                    "daily_limit": daily_limit,
                    "reserved": int(ledger["reserved"]),
                    "confirmed": int(ledger["confirmed"]),
                    "requested": amount,
                },
            )
        conn.execute(
            "UPDATE daily_budgets SET reserved=reserved+?, updated_at=? "
            "WHERE namespace=? AND budget_date=?",
            (amount, now, namespace, budget_date),
        )
        conn.execute(
            "INSERT INTO budget_reservations"
            "(reservation_id,namespace,budget_date,amount,status,lease_id,updated_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                reservation_id,
                namespace,
                budget_date,
                amount,
                "reserved",
                _BUDGET_LEASE_ID,
                now,
            ),
        )
        result = _budget_row(conn, namespace, budget_date)
        result["reservation_id"] = reservation_id
        result["reservation_status"] = "reserved"
        return result


def _finish_budget_reservation(reservation_id, action, confirmed_amount=None):
    reservation_id = _require_name(reservation_id, "reservation_id")
    now = _now()
    with _conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT namespace, budget_date, amount, status FROM budget_reservations "
            "WHERE reservation_id=?",
            (reservation_id,),
        ).fetchone()
        if not row:
            raise StateStoreError(
                "RESERVATION_NOT_FOUND",
                "预留不存在",
                {"reservation_id": reservation_id},
            )
        if action == "confirm" and row["status"] == "reserved":
            amount = int(row["amount"])
            if confirmed_amount is None:
                settled_amount = amount
            else:
                try:
                    settled_amount = int(confirmed_amount)
                except (TypeError, ValueError) as exc:
                    raise StateStoreError(
                        "INVALID_ARGUMENT", "confirmed_amount 无效"
                    ) from exc
                if settled_amount < 0 or settled_amount > amount:
                    raise StateStoreError(
                        "INVALID_ARGUMENT",
                        "confirmed_amount 必须位于 0 与预留额度之间",
                    )
            conn.execute(
                "UPDATE daily_budgets SET reserved=reserved-?, confirmed=confirmed+?, "
                "updated_at=? WHERE namespace=? AND budget_date=?",
                (amount, settled_amount, now, row["namespace"], row["budget_date"]),
            )
            conn.execute(
                "UPDATE budget_reservations SET amount=?, status='confirmed', updated_at=? "
                "WHERE reservation_id=?",
                (settled_amount, now, reservation_id),
            )
        elif action == "release" and row["status"] == "reserved":
            conn.execute(
                "UPDATE daily_budgets SET reserved=reserved-?, updated_at=? "
                "WHERE namespace=? AND budget_date=?",
                (row["amount"], now, row["namespace"], row["budget_date"]),
            )
            conn.execute(
                "UPDATE budget_reservations SET status='released', updated_at=? "
                "WHERE reservation_id=?",
                (now, reservation_id),
            )
        return _budget_row(conn, row["namespace"], row["budget_date"])


def confirm_daily_budget(reservation_id, amount=None):
    return _finish_budget_reservation(
        reservation_id, "confirm", confirmed_amount=amount
    )


def release_daily_budget(reservation_id):
    return _finish_budget_reservation(reservation_id, "release")


def recover_abandoned_budget_reservations():
    """Atomically release reservations owned by a previous process startup."""
    lease_id = _require_name(_BUDGET_LEASE_ID, "lease_id")
    now = _now()
    with _conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            "SELECT namespace, budget_date, SUM(amount) AS amount, COUNT(*) AS count "
            "FROM budget_reservations WHERE status='reserved' "
            "AND COALESCE(lease_id, '')<>? GROUP BY namespace, budget_date",
            (lease_id,),
        ).fetchall()
        total_amount = 0
        total_count = 0
        for row in rows:
            amount = int(row["amount"])
            ledger = _budget_row(conn, row["namespace"], row["budget_date"])
            if int(ledger["reserved"]) < amount:
                raise StateStoreError(
                    "BUDGET_LEDGER_CORRUPT",
                    "预算预留账本不一致",
                    {
                        "namespace": row["namespace"],
                        "budget_date": row["budget_date"],
                    },
                )
            conn.execute(
                "UPDATE daily_budgets SET reserved=reserved-?, updated_at=? "
                "WHERE namespace=? AND budget_date=?",
                (amount, now, row["namespace"], row["budget_date"]),
            )
            total_amount += amount
            total_count += int(row["count"])
        if total_count:
            conn.execute(
                "UPDATE budget_reservations SET status='released', updated_at=? "
                "WHERE status='reserved' AND COALESCE(lease_id, '')<>?",
                (now, lease_id),
            )
        return {"reservations": total_count, "amount": total_amount}


def _as_utc_datetime(value, field):
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise StateStoreError("INVALID_ARGUMENT", f"{field} 无效") from exc
    else:
        raise StateStoreError("INVALID_ARGUMENT", f"{field} 无效")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def save_rss_last_good(feed_id, snapshot, fetched_at=None):
    feed_id = _require_name(feed_id, "feed_id")
    fetched = _as_utc_datetime(fetched_at, "fetched_at").isoformat()
    now = _now()
    with _conn() as conn:
        conn.execute(
            "INSERT INTO rss_runtime"
            "(feed_id,snapshot_json,fetched_at,failure_code,failed_at,failure_count,updated_at) "
            "VALUES(?,?,?,NULL,NULL,0,?) ON CONFLICT(feed_id) DO UPDATE SET "
            "snapshot_json=excluded.snapshot_json, fetched_at=excluded.fetched_at, "
            "failure_code=NULL, failed_at=NULL, failure_count=0, updated_at=excluded.updated_at",
            (feed_id, _json_dump(snapshot), fetched, now),
        )
    return get_rss_runtime_status(feed_id)


def record_rss_failure(feed_id, failure_code, failed_at=None):
    feed_id = _require_name(feed_id, "feed_id")
    failure_code = _require_name(failure_code, "failure_code")
    failed = _as_utc_datetime(failed_at, "failed_at").isoformat()
    now = _now()
    with _conn() as conn:
        conn.execute(
            "INSERT INTO rss_runtime"
            "(feed_id,snapshot_json,fetched_at,failure_code,failed_at,failure_count,updated_at) "
            "VALUES(?,NULL,NULL,?,?,1,?) ON CONFLICT(feed_id) DO UPDATE SET "
            "failure_code=excluded.failure_code, failed_at=excluded.failed_at, "
            "failure_count=rss_runtime.failure_count+1, updated_at=excluded.updated_at",
            (feed_id, failure_code, failed, now),
        )
    return get_rss_runtime_status(feed_id)


def get_rss_runtime_status(
    feed_id,
    now=None,
    fresh_for_seconds=900,
    offline_after_seconds=86400,
):
    feed_id = _require_name(feed_id, "feed_id")
    fresh_for_seconds = _require_positive_int(
        fresh_for_seconds, "fresh_for_seconds", allow_zero=True
    )
    offline_after_seconds = _require_positive_int(
        offline_after_seconds, "offline_after_seconds", allow_zero=True
    )
    if offline_after_seconds < fresh_for_seconds:
        raise StateStoreError(
            "INVALID_ARGUMENT", "offline_after_seconds 不得小于 fresh_for_seconds"
        )
    with _conn() as conn:
        row = conn.execute(
            "SELECT snapshot_json, fetched_at, failure_code, failed_at, failure_count "
            "FROM rss_runtime WHERE feed_id=?",
            (feed_id,),
        ).fetchone()
    if not row:
        return {
            "feed_id": feed_id,
            "status": "offline",
            "snapshot": None,
            "fetched_at": None,
            "failure": None,
        }
    snapshot = None
    if row["snapshot_json"] is not None:
        try:
            snapshot = json.loads(row["snapshot_json"])
        except (TypeError, ValueError):
            snapshot = None
    fetched_at = row["fetched_at"]
    status = "offline"
    if snapshot is not None and fetched_at:
        age = max(
            0,
            (_as_utc_datetime(now, "now") - _as_utc_datetime(fetched_at, "fetched_at")).total_seconds(),
        )
        if age <= fresh_for_seconds:
            status = "fresh"
        elif age <= offline_after_seconds:
            status = "stale"
    failure = None
    if row["failure_code"]:
        failure = {
            "code": row["failure_code"],
            "failed_at": row["failed_at"],
            "count": int(row["failure_count"]),
        }
    return {
        "feed_id": feed_id,
        "status": status,
        "snapshot": snapshot,
        "fetched_at": fetched_at,
        "failure": failure,
    }


init_user_state_db()
recover_abandoned_budget_reservations()


# ══════════════════════════════════════════════════════════════
# 路由
# ══════════════════════════════════════════════════════════════
@user_state_bp.route("/api/userdata/all", methods=["GET"])
def userdata_all():
    """旧全量接口：兼容一个版本周期，数据仍从条目真相源组装。"""
    with _conn() as conn:
        bookmarks = [dict(r) for r in conn.execute(
            "SELECT link, title, source, date FROM bookmarks ORDER BY created_at DESC")]
        read_links = [r["link"] for r in conn.execute("SELECT link FROM read_marks")]
        alerts = [r["term"] for r in conn.execute(
            "SELECT term FROM alert_keywords ORDER BY created_at")]
        state = _state_from_conn(conn)
    state.update({
        "bookmarks": bookmarks,
        "read_links": read_links,
        "alerts": alerts,
    })
    response = _state_response(state)
    response.headers["Deprecation"] = "true"
    response.headers["Link"] = '</api/userdata/bootstrap>; rel="successor-version"'
    return response


@user_state_bp.route("/api/userdata/bootstrap", methods=["GET"])
def userdata_bootstrap():
    """Return the startup state and a host-provided non-secret config summary."""
    with _conn() as conn:
        bookmarks = [dict(row) for row in conn.execute(
            "SELECT link, title, source, date FROM bookmarks ORDER BY created_at DESC"
        )]
        read_links = [row["link"] for row in conn.execute("SELECT link FROM read_marks")]
        alerts = [row["term"] for row in conn.execute(
            "SELECT term FROM alert_keywords ORDER BY created_at"
        )]
        state = _state_from_conn(conn)
    config = {}
    if callable(_bootstrap_config_provider):
        try:
            provided = _bootstrap_config_provider()
            if isinstance(provided, dict):
                config = provided
        except Exception as exc:
            logger.warning("userdata bootstrap config summary unavailable: %s", exc)
    state.update({
        "bookmarks": bookmarks,
        "read_links": read_links,
        "alerts": alerts,
        "config": config,
    })
    return _state_response(state)


def _expected_revision_from_request(body=None, require_if_match=False):
    raw = request.headers.get("If-Match")
    if require_if_match and (raw is None or not str(raw).strip()):
        raise StateStoreError(
            "PRECONDITION_REQUIRED",
            "缺少 If-Match 头",
            {"header": "If-Match"},
        )
    if raw is None and isinstance(body, dict):
        raw = body.get("expected_revision")
    if raw is None or raw == "":
        return None
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    text = str(raw).strip()
    if text.startswith("W/"):
        text = text[2:].strip()
    if len(text) >= 2 and text[0] == text[-1] == '"':
        text = text[1:-1]
    try:
        return int(text)
    except ValueError as exc:
        raise StateStoreError("INVALID_REVISION", "If-Match 必须是整数 revision") from exc


def _state_response(state, status=200):
    response = jsonify(state)
    response.status_code = status
    response.headers["ETag"] = f'"{state["revision"]}"'
    return response


def _state_error_response(exc):
    status = {
        "REVISION_CONFLICT": 409,
        "PRECONDITION_REQUIRED": 428,
    }.get(exc.code, 400)
    request_id = str(getattr(g, "request_id", "") or uuid.uuid4())
    response = jsonify({
        "error": exc.message,
        "code": exc.code,
        "request_id": request_id,
        "retryable": exc.code == "REVISION_CONFLICT",
        "details": exc.details,
    })
    response.status_code = status
    response.headers["X-Request-ID"] = request_id
    return response


@user_state_bp.route("/api/userdata/brief-results", methods=["GET"])
def userdata_brief_results_get():
    return _state_response(get_user_state())


@user_state_bp.route("/api/userdata/brief-results", methods=["DELETE"])
def userdata_brief_results_delete():
    body = request.get_json(force=True, silent=True) or {}
    try:
        state = delete_brief_results(
            body.get("item_ids"),
            expected_revision=_expected_revision_from_request(
                body, require_if_match=True
            ),
        )
    except StateStoreError as exc:
        return _state_error_response(exc)
    return _state_response(state)


@user_state_bp.route("/api/userdata/brief-results/<item_id>", methods=["PUT", "DELETE"])
def userdata_brief_result_upsert(item_id):
    body = request.get_json(force=True, silent=True) or {}
    if request.method == "DELETE":
        try:
            state = delete_brief_results(
                [item_id],
                expected_revision=_expected_revision_from_request(
                    body, require_if_match=True
                ),
            )
        except StateStoreError as exc:
            return _state_error_response(exc)
        return _state_response(state)
    item = body.get("item") if isinstance(body.get("item"), dict) else body.get("value")
    if not isinstance(item, dict):
        item = dict(body)
        item.pop("expected_revision", None)
    item["id"] = item_id
    try:
        state = upsert_brief_result(
            item,
            expected_revision=_expected_revision_from_request(
                body, require_if_match=True
            ),
        )
    except StateStoreError as exc:
        return _state_error_response(exc)
    return _state_response(state)


@user_state_bp.route("/api/userdata/bookmark", methods=["POST"])
def userdata_bookmark():
    body = request.get_json(force=True, silent=True) or {}
    art = body.get("article") or {}
    link = str(art.get("link") or "").strip()
    if not link:
        return jsonify({"error": "缺少 link"}), 400
    aid = canonical_article_id(link)
    with _conn() as conn:
        if body.get("on", True):
            conn.execute(
                "INSERT INTO bookmarks(aid, link, title, source, date, created_at) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(aid) DO UPDATE SET "
                "title=excluded.title, source=excluded.source, date=excluded.date",
                (aid, link, str(art.get("title") or "")[:500],
                 str(art.get("source") or "")[:200], str(art.get("date") or "")[:64], _now()))
        else:
            conn.execute("DELETE FROM bookmarks WHERE aid=?", (aid,))
    return jsonify({"ok": True, "aid": aid})


@user_state_bp.route("/api/userdata/read", methods=["POST"])
def userdata_read():
    """批量标记已读：{links: [...]}（markAllRead 一次几百条也只打一个请求）。"""
    body = request.get_json(force=True, silent=True) or {}
    links = [str(l).strip() for l in (body.get("links") or []) if str(l).strip()]
    if not links:
        return jsonify({"error": "缺少 links"}), 400
    now = _now()
    with _conn() as conn:
        conn.executemany(
            "INSERT OR IGNORE INTO read_marks(aid, link, read_at) VALUES(?,?,?)",
            [(canonical_article_id(l), l, now) for l in links])
    return jsonify({"ok": True, "count": len(links)})


@user_state_bp.route("/api/userdata/alert", methods=["POST"])
def userdata_alert():
    body = request.get_json(force=True, silent=True) or {}
    term = str(body.get("term") or "").strip().lower()
    if not term:
        return jsonify({"error": "缺少 term"}), 400
    with _conn() as conn:
        if body.get("on", True):
            conn.execute("INSERT OR IGNORE INTO alert_keywords(term, created_at) VALUES(?,?)",
                         (term[:80], _now()))
        else:
            conn.execute("DELETE FROM alert_keywords WHERE term=?", (term,))
    return jsonify({"ok": True})


@user_state_bp.route("/api/userdata/kv/briefResults", methods=["PUT"])
def userdata_brief_results():
    """旧整表同步兼容路由；新客户端应使用 item upsert。"""
    body = request.get_json(force=True, silent=True) or {}
    value = body.get("value")
    try:
        state = replace_brief_results_legacy(
            value, expected_revision=_expected_revision_from_request(body)
        )
    except StateStoreError as exc:
        if exc.code == "PAYLOAD_TOO_LARGE":
            response = _state_error_response(exc)
            response.status_code = 413
            return response
        return _state_error_response(exc)
    state["ok"] = True
    state["count"] = len(state["brief_results"])
    response = _state_response(state)
    response.headers["Deprecation"] = "true"
    response.headers["Link"] = '</api/userdata/brief-results>; rel="successor-version"'
    return response


@user_state_bp.route("/api/userdata/migrate", methods=["POST"])
def userdata_migrate():
    """localStorage → 服务端 一次性迁移（幂等 upsert，重复调用无害）。"""
    body = request.get_json(force=True, silent=True) or {}
    now = _now()
    n_bm = n_rd = n_al = 0
    with _conn() as conn:
        for b in (body.get("bookmarks") or [])[:2000]:
            link = str((b.get("link") if isinstance(b, dict) else b) or "").strip()
            if not link:
                continue
            art = b if isinstance(b, dict) else {}
            conn.execute(
                "INSERT OR IGNORE INTO bookmarks(aid, link, title, source, date, created_at) "
                "VALUES(?,?,?,?,?,?)",
                (canonical_article_id(link), link, str(art.get("title") or "")[:500],
                 str(art.get("source") or "")[:200], str(art.get("date") or "")[:64], now))
            n_bm += 1
        rd = [str(l).strip() for l in (body.get("read") or [])[:20000] if str(l).strip()]
        conn.executemany(
            "INSERT OR IGNORE INTO read_marks(aid, link, read_at) VALUES(?,?,?)",
            [(canonical_article_id(l), l, now) for l in rd])
        n_rd = len(rd)
        for t in (body.get("alerts") or [])[:500]:
            t = str(t).strip().lower()
            if t:
                conn.execute("INSERT OR IGNORE INTO alert_keywords(term, created_at) VALUES(?,?)",
                             (t[:80], now))
                n_al += 1
    logger.info("userdata migrate: bookmarks=%d read=%d alerts=%d", n_bm, n_rd, n_al)
    return jsonify({"ok": True, "bookmarks": n_bm, "read": n_rd, "alerts": n_al})
