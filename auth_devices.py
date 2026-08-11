# -*- coding: utf-8 -*-
"""设备 token：单用户多设备鉴权原语（三端联动地基之二）。

此前只有一个全局 ACCESS_TOKEN：无法区分设备、无法单独吊销、泄露即全部重置。
本模块提供 per-device token 的 发放/校验/吊销，为手机/exe/网页各持独立凭证铺路。

- 只依赖标准库 + state（叶子模块，不 import app，无循环依赖）
- 存储：data/user_state.sqlite3 的 device_tokens 表（库内只存 sha256 哈希，
  明文仅发放时返回一次；hint 存明文前 6 位仅供列表识别）
- 强制开关不在这里：AUTH_REQUIRED 仍由 app.py 管（本机阶段默认关，
  上云阶段翻开后 master token 与设备 token 并行有效）
"""
import os
import sqlite3
import secrets
import hashlib
import logging
import threading
import time
from datetime import datetime, timezone

from state import DATA_DIR

logger = logging.getLogger(__name__)

DB_FILE = os.path.join(DATA_DIR, "user_state.sqlite3")

# 校验结果短缓存：免得每个 API 请求都打一次 SQLite（60s TTL，吊销最迟 60s 生效）
_VERIFY_CACHE: dict = {}
_VERIFY_CACHE_TTL = 60
_cache_lock = threading.Lock()


def _conn():
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_device_db():
    with _conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS device_tokens(
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash  TEXT NOT NULL UNIQUE,
            hint        TEXT NOT NULL,            -- 明文前6位，仅列表识别用
            device_name TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            last_seen   TEXT,
            revoked     INTEGER NOT NULL DEFAULT 0
        );
        """)


init_device_db()


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def issue_device_token(device_name: str):
    """发放新设备 token。返回 (明文token, 行id)——明文仅此一次，库里只存哈希。"""
    plaintext = secrets.token_urlsafe(24)
    with _conn() as conn:
        cur = conn.execute(
            "INSERT INTO device_tokens(token_hash, hint, device_name, created_at) "
            "VALUES(?,?,?,?)",
            (_hash(plaintext), plaintext[:6], (device_name or "未命名设备")[:64], _now()))
        dev_id = cur.lastrowid
    logger.info("设备 token 已发放: id=%s name=%s", dev_id, device_name)
    return plaintext, dev_id


def verify_device_token(token: str) -> bool:
    """校验设备 token（未吊销）。带 60s 结果缓存，best-effort 更新 last_seen。"""
    token = (token or "").strip()
    if not token:
        return False
    h = _hash(token)
    now = time.time()
    with _cache_lock:
        hit = _VERIFY_CACHE.get(h)
        if hit and now - hit[1] < _VERIFY_CACHE_TTL:
            return hit[0]
    try:
        with _conn() as conn:
            row = conn.execute(
                "SELECT id FROM device_tokens WHERE token_hash=? AND revoked=0", (h,)).fetchone()
            ok = row is not None
            if ok:
                conn.execute("UPDATE device_tokens SET last_seen=? WHERE id=?",
                             (_now(), row["id"]))
    except sqlite3.Error as e:
        logger.warning("设备 token 校验失败（数据库异常）: %s", e)
        return False
    with _cache_lock:
        _VERIFY_CACHE[h] = (ok, now)
        if len(_VERIFY_CACHE) > 256:  # 防被扫爆
            _VERIFY_CACHE.clear()
    return ok


def list_devices() -> list:
    with _conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT id, hint, device_name, created_at, last_seen, revoked "
            "FROM device_tokens ORDER BY created_at DESC")]


def revoke_device(dev_id: int) -> bool:
    """吊销设备 token（保留记录供审计）。清缓存让吊销即时生效。"""
    with _conn() as conn:
        cur = conn.execute("UPDATE device_tokens SET revoked=1 WHERE id=? AND revoked=0",
                           (dev_id,))
    with _cache_lock:
        _VERIFY_CACHE.clear()
    if cur.rowcount:
        logger.info("设备 token 已吊销: id=%s", dev_id)
    return bool(cur.rowcount)
