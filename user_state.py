# -*- coding: utf-8 -*-
"""用户状态上收（三端联动地基）：书签 / 已读 / 预警词 / 要讯历史 → 服务端 SQLite。

此前这些数据全在浏览器 localStorage（news.js/brief.js），换浏览器/设备即丢，
后端与飞书端完全不可见——是三端联动的第一堵墙。本模块把它们收到服务端
data/user_state.sqlite3，前端改为 write-through（localStorage 保留做离线缓存）。

设计沿用 tracking.py 的成熟模式：
- 不 import app（避免循环 import），鉴权由 app.py 注册时注入 `_auth_check` 回调
- 文章身份用 state.canonical_article_id（同文异链归一），服务端计算，前端只传原始 link
- 书签/已读按行存（跨设备天然并集）；要讯历史整表以 kv blob 存（单写者现实下最稳）
"""
import os
import json
import sqlite3
import logging
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify

from state import DATA_DIR, canonical_article_id

logger = logging.getLogger(__name__)

user_state_bp = Blueprint("user_state", __name__)

# 鉴权注入点：app.py 注册后设置 user_state._auth_check = <callable>
# 约定：返回 Response 表示拦截，返回 None 表示放行（与 tracking.py 一致）。
_auth_check = None


@user_state_bp.before_request
def _user_state_before():
    if _auth_check is not None:
        resp = _auth_check()
        if resp is not None:
            return resp
    return None


USER_STATE_DB_FILE = os.path.join(DATA_DIR, "user_state.sqlite3")


def _conn():
    os.makedirs(os.path.dirname(USER_STATE_DB_FILE), exist_ok=True)
    conn = sqlite3.connect(USER_STATE_DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_user_state_db():
    with _conn() as conn:
        conn.executescript("""
        PRAGMA journal_mode=WAL;
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
        """)


init_user_state_db()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ══════════════════════════════════════════════════════════════
# 路由
# ══════════════════════════════════════════════════════════════
@user_state_bp.route("/api/userdata/all", methods=["GET"])
def userdata_all():
    """启动时一次拉全量（省往返）。read 返回 links 供前端 Set 直接沿用现有键。"""
    with _conn() as conn:
        bookmarks = [dict(r) for r in conn.execute(
            "SELECT link, title, source, date FROM bookmarks ORDER BY created_at DESC")]
        read_links = [r["link"] for r in conn.execute("SELECT link FROM read_marks")]
        alerts = [r["term"] for r in conn.execute(
            "SELECT term FROM alert_keywords ORDER BY created_at")]
        row = conn.execute("SELECT value_json FROM kv WHERE key='briefResults'").fetchone()
    brief_results = None
    if row:
        try:
            brief_results = json.loads(row["value_json"])
        except ValueError:
            brief_results = None
    return jsonify({
        "bookmarks": bookmarks,
        "read_links": read_links,
        "alerts": alerts,
        "brief_results": brief_results,
    })


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
    """要讯历史整表同步（≤50 条，单写者现实下 blob 替换最稳、代码最少）。"""
    body = request.get_json(force=True, silent=True) or {}
    value = body.get("value")
    if not isinstance(value, list):
        return jsonify({"error": "value 必须是数组"}), 400
    payload = json.dumps(value[:50], ensure_ascii=False)
    if len(payload) > 2_000_000:
        return jsonify({"error": "payload 过大"}), 413
    with _conn() as conn:
        conn.execute(
            "INSERT INTO kv(key, value_json, updated_at) VALUES('briefResults',?,?) "
            "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, "
            "updated_at=excluded.updated_at",
            (payload, _now()))
    return jsonify({"ok": True, "count": len(value[:50])})


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
