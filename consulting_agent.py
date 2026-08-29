# -*- coding: utf-8 -*-
"""Defense consulting Agent core.

This module owns consultation sessions, evidence cards and answer persistence.
It deliberately has no Flask dependency so routes can stay thin.
"""
import hashlib
import json
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

import report_agent
from state import DATA_DIR

CONSULTING_AGENT_DB_FILE = os.path.join(DATA_DIR, "consulting_agent.sqlite3")
MAX_CONSULTING_INSTRUCTION_CHARS = 4096
SOURCE_ARCHIVE_DIR = os.path.join(DATA_DIR, "source_archive")
_DB_LOCK = threading.Lock()

DEFAULT_TARGET_SOURCE_COUNT = 12
MIN_SOURCE_TARGET = 1


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _json_dumps(value) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _json_loads(value, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


def _connect():
    os.makedirs(os.path.dirname(CONSULTING_AGENT_DB_FILE), exist_ok=True)
    conn = sqlite3.connect(CONSULTING_AGENT_DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")      # 多读单写并发，缓解 database is locked
    conn.execute("PRAGMA busy_timeout=10000")     # 写争用自动重试 10s 而非立即报错
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_consulting_agent_db():
    with _DB_LOCK, _connect() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            instruction TEXT NOT NULL,
            topic TEXT NOT NULL DEFAULT '',
            report_goal TEXT NOT NULL DEFAULT '',
            target_source_count INTEGER NOT NULL,
            search_web INTEGER NOT NULL DEFAULT 1,
            plan_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS queries (
            query_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            channel TEXT NOT NULL,
            query_text TEXT NOT NULL,
            result_count INTEGER NOT NULL DEFAULT 0,
            payload_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            FOREIGN KEY(session_id) REFERENCES sessions(session_id)
        );
        CREATE TABLE IF NOT EXISTS evidence (
            evidence_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            title TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT '',
            published_at TEXT NOT NULL DEFAULT '',
            url TEXT NOT NULL DEFAULT '',
            channel TEXT NOT NULL DEFAULT '',
            score INTEGER NOT NULL DEFAULT 0,
            reason TEXT NOT NULL DEFAULT '',
            snippet TEXT NOT NULL DEFAULT '',
            dedup_key TEXT NOT NULL,
            payload_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(session_id, dedup_key),
            FOREIGN KEY(session_id) REFERENCES sessions(session_id)
        );
        CREATE TABLE IF NOT EXISTS answers (
            answer_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            content TEXT NOT NULL,
            model TEXT NOT NULL DEFAULT '',
            source_answer_id TEXT NOT NULL DEFAULT '',
            payload_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            FOREIGN KEY(session_id) REFERENCES sessions(session_id)
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            FOREIGN KEY(session_id) REFERENCES sessions(session_id)
        );
        CREATE TABLE IF NOT EXISTS source_assets (
            asset_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            url TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT '',
            local_path TEXT NOT NULL DEFAULT '',
            text_path TEXT NOT NULL DEFAULT '',
            metadata_path TEXT NOT NULL DEFAULT '',
            checksum TEXT NOT NULL DEFAULT '',
            content_type TEXT NOT NULL DEFAULT '',
            document_type TEXT NOT NULL DEFAULT '',
            word_count INTEGER NOT NULL DEFAULT 0,
            failure_reason TEXT NOT NULL DEFAULT '',
            fetched_at TEXT NOT NULL,
            payload_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(session_id) REFERENCES sessions(session_id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_source_assets_unique
            ON source_assets(session_id, evidence_id, url);
        CREATE TABLE IF NOT EXISTS capture_jobs (
            job_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            target_count INTEGER NOT NULL DEFAULT 0,
            batch_size INTEGER NOT NULL DEFAULT 8,
            max_rounds INTEGER NOT NULL DEFAULT 6,
            crawl_mode TEXT NOT NULL DEFAULT 'steady',
            allow_browser_render INTEGER NOT NULL DEFAULT 1,
            round_no INTEGER NOT NULL DEFAULT 0,
            current_query TEXT NOT NULL DEFAULT '',
            archived_count INTEGER NOT NULL DEFAULT 0,
            partial_count INTEGER NOT NULL DEFAULT 0,
            failed_count INTEGER NOT NULL DEFAULT 0,
            needs_user_input_count INTEGER NOT NULL DEFAULT 0,
            rejected_low_relevance INTEGER NOT NULL DEFAULT 0,
            stop_reason TEXT NOT NULL DEFAULT '',
            payload_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(session_id) REFERENCES sessions(session_id)
        );
        CREATE TABLE IF NOT EXISTS capture_attempts (
            attempt_id TEXT PRIMARY KEY,
            job_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            round_no INTEGER NOT NULL DEFAULT 0,
            query_text TEXT NOT NULL DEFAULT '',
            result_count INTEGER NOT NULL DEFAULT 0,
            archived_delta INTEGER NOT NULL DEFAULT 0,
            partial_delta INTEGER NOT NULL DEFAULT 0,
            failed_delta INTEGER NOT NULL DEFAULT 0,
            needs_user_input_delta INTEGER NOT NULL DEFAULT 0,
            rejected_low_relevance INTEGER NOT NULL DEFAULT 0,
            payload_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            FOREIGN KEY(job_id) REFERENCES capture_jobs(job_id),
            FOREIGN KEY(session_id) REFERENCES sessions(session_id)
        );
        """)
        conn.commit()


def _clean_text(value: str) -> str:
    return report_agent.sanitize_report_text(re.sub(r"\s+", " ", (value or "").strip()))


def _extract_requested_count(instruction: str) -> int | None:
    text = _clean_text(instruction)
    patterns = [
        r"(?:搜集|收集|检索|抓取|找|列出)\s*(\d{1,6})\s*(?:份|条|个)?\s*(?:信息源|证据|资料|来源|文献|智库|报告源|报告)?",
        r"(\d{1,6})\s*(?:份|条|个)\s*(?:信息源|证据|资料|来源|文献|智库|报告源|报告)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return max(MIN_SOURCE_TARGET, int(match.group(1)))
    return None


def _derive_report_goal(instruction: str) -> str:
    text = _clean_text(instruction)
    for goal in ("战略分析报告", "咨询报告", "研究报告", "专题报告", "文献综述", "资料清单"):
        if goal in text:
            return goal
    return "防务信息咨询报告"


def _derive_topic(instruction: str) -> str:
    text = _clean_text(instruction)
    if re.match(r"^(搜集|收集|检索|抓取|找|列出)", text):
        text = re.sub(
            r"^(搜集|收集|检索|抓取|找|列出)\s*(\d{1,6})?\s*(份|条|个)?\s*",
            "",
            text,
        )
    else:
        text = re.sub(r"[，,；;。]?\s*(搜集|收集|检索|抓取|找|列出).*$", "", text)
    text = re.sub(r"[，,；;。]?\s*\d{1,6}\s*(份|条|个)?\s*(信息源|证据|资料|来源|文献|智库|报告源|报告)?.*$", "", text)
    text = re.sub(r"^[请麻烦]*帮[我忙]?(做|写|生成|出)?(一个|一份|1份)?", "", text)
    text = re.sub(r"^(请|麻烦|做|写|生成|出)(一个|一份|1份)?", "", text)
    text = re.sub(r"^(有关|关于|围绕)", "", text)
    text = re.sub(r"(的)?(高价值)?(防务)?(战略)?(深度)?(综合)?(分析)?(咨询)?(研究)?报告", "", text)
    text = re.sub(r"[，。；;,.!！?？：:\-—]+", "", text).strip()
    return text or "综合防务态势"


REGION_MARKERS = {
    "united_states": {
        "zh": ("美国", "美军", "美方"),
        "terms": ("United States", "U.S. military"),
    },
    "nato": {
        "zh": ("北约", "NATO"),
        "terms": ("NATO", "allied defense"),
    },
    "russia": {
        "zh": ("俄罗斯", "俄军", "俄乌", "莫斯科"),
        "terms": ("Russia", "Russian military"),
    },
    "red_sea": {
        "zh": ("红海", "胡塞", "也门", "曼德海峡"),
        "terms": ("Red Sea", "Houthi", "Bab el-Mandeb"),
    },
    "indo_pacific": {
        "zh": ("印太", "印度洋-太平洋", "第一岛链", "第二岛链"),
        "terms": ("Indo-Pacific", "maritime security"),
    },
    "europe": {
        "zh": ("欧洲", "欧盟", "北约欧洲", "德国", "法国", "英国", "波兰"),
        "terms": ("Europe", "European defense"),
    },
    "iran": {
        "zh": ("伊朗", "德黑兰"),
        "terms": ("Iran", "Iranian military"),
    },
    "middle_east": {
        "zh": ("中东", "美以", "以色列", "加沙", "叙利亚", "黎巴嫩"),
        "terms": ("Middle East", "regional security"),
    },
    "taiwan": {
        "zh": ("台海", "台湾", "台湾海峡"),
        "terms": ("Taiwan Strait", "Taiwan"),
    },
    "china": {
        "zh": ("中国", "解放军", "PLA", "南海"),
        "terms": ("China", "PLA"),
    },
    "korea": {
        "zh": ("朝鲜", "韩国", "半岛"),
        "terms": ("Korean Peninsula", "North Korea"),
    },
    "india": {
        "zh": ("印度", "南亚"),
        "terms": ("India", "South Asia"),
    },
}

CAPABILITY_MARKERS = {
    "stockpile_storage": {
        "zh": ("库存", "储备", "存储", "储存", "存量", "弹药库", "武器库", "战备库存"),
        "terms": ("munitions stockpile", "weapons inventory", "munitions storage", "arsenal"),
    },
    "missile_stockpile": {
        "zh": ("导弹存储", "导弹储备", "导弹库存", "导弹弹药库", "导弹存量", "弹药存储", "弹药储备"),
        "terms": ("missile stockpile", "missile arsenal", "missile inventory", "munitions storage", "weapons stockpile"),
    },
    "missile": {
        "zh": ("导弹", "弹道导弹", "巡航导弹", "火箭军"),
        "terms": ("missile", "ballistic missile", "missile force assessment"),
    },
    "uav": {
        "zh": ("无人机", "无人系统", "无人作战", "无人艇"),
        "terms": ("UAV", "unmanned systems", "drone warfare"),
    },
    "naval": {
        "zh": ("海军", "海上力量", "舰队", "海上安全"),
        "terms": ("naval", "maritime forces", "sea power"),
    },
    "air_defense": {
        "zh": ("防空", "防空反导", "导弹防御", "空防"),
        "terms": ("air defense", "missile defense", "integrated air and missile defense"),
    },
    "electronic_warfare": {
        "zh": ("电子战", "电磁", "电磁频谱", "干扰"),
        "terms": ("electronic warfare", "electromagnetic spectrum operations"),
    },
    "nuclear": {
        "zh": ("核力量", "核威慑", "核武器"),
        "terms": ("nuclear forces", "nuclear deterrence"),
    },
    "cyber": {
        "zh": ("网络战", "网络空间", "网络安全"),
        "terms": ("cyber operations", "cyber warfare"),
    },
    "space": {
        "zh": ("太空", "卫星", "反卫星"),
        "terms": ("space security", "counterspace"),
    },
    "doctrine": {
        "zh": ("条令", "作战概念", "作战运用", "手册"),
        "terms": ("doctrine", "operational concept", "field manual"),
    },
    "defense_industry": {
        "zh": ("军工", "工业生产", "产能", "供应链", "生产能力"),
        "terms": ("defense industry", "industrial base", "production capacity"),
    },
    "attrition_consumption": {
        "zh": ("消耗", "战损", "损耗", "消耗率", "补充率", "弹药消耗"),
        "terms": ("attrition", "consumption rate", "expenditure rate", "replacement rate"),
    },
    "deployment_basing": {
        "zh": ("部署", "基地", "驻扎", "前沿部署", "轮换部署"),
        "terms": ("deployment", "basing", "force posture", "forward presence"),
    },
    "readiness": {
        "zh": ("战备", "完好率", "可用率", " readiness", "待命"),
        "terms": ("readiness", "operational availability", "mission capable rate"),
    },
    "procurement": {
        "zh": ("采购", "采办", " acquisition", "装备采购", "项目采购"),
        "terms": ("acquisition", "procurement", "program of record"),
    },
    "logistics": {
        "zh": ("后勤", "保障", "补给", " sustainment", "维修保障"),
        "terms": ("logistics", "sustainment", "supply chain", "maintenance support"),
    },
}

FILE_TYPE_MARKERS = {
    "report": ("报告", "智库", "研究", "评估", "analysis", "report", "assessment"),
    "paper": ("论文", "文献", "paper", "journal", "study"),
    "policy": ("政策", "官方", "白皮书", "policy", "strategy"),
    "doctrine": ("条令", "手册", "manual", "doctrine"),
}


def _marker_hits(text: str, catalog: dict[str, dict]) -> list[dict]:
    lower = (text or "").lower()
    hits = []
    for key, spec in catalog.items():
        zh_hit = any(marker.lower() in lower for marker in spec.get("zh", ()))
        en_hit = any(marker.lower() in lower for marker in spec.get("terms", ()))
        if zh_hit or en_hit:
            hits.append({"key": key, "terms": list(spec.get("terms", ()))})
    return hits


def build_topic_profile(topic: str) -> dict:
    text = _clean_text(topic)
    region_hits = _marker_hits(text, REGION_MARKERS)
    capability_hits = _marker_hits(text, CAPABILITY_MARKERS)
    file_types = []
    lower = text.lower()
    for kind, markers in FILE_TYPE_MARKERS.items():
        if any(marker.lower() in lower for marker in markers):
            file_types.append(kind)
    if not file_types:
        file_types = ["report", "analysis"]
    english_terms = []
    for hit in [*region_hits, *capability_hits]:
        for term in hit.get("terms") or []:
            if term not in english_terms:
                english_terms.append(term)
    region_keys = [hit["key"] for hit in region_hits]
    return {
        "regions": region_keys,
        "capabilities": [hit["key"] for hit in capability_hits],
        "file_types": file_types,
        "languages": ["zh", "en"],
        "english_terms": english_terms,
        "avoid_unrelated_china_fallback": not {"china", "taiwan"}.intersection(region_keys),
    }


def _keywords_for_topic(topic: str) -> list[str]:
    topic = _clean_text(topic)
    profile = build_topic_profile(topic)
    keys = [topic]
    for suffix in ("发展", "态势", "研究", "分析", "报告", "评估"):
        if topic.endswith(suffix) and len(topic) > len(suffix) + 2:
            keys.append(topic[: -len(suffix)])
    region_terms = []
    capability_terms = []
    for key in profile["regions"]:
        region_terms.extend(REGION_MARKERS.get(key, {}).get("terms", ()))
    for key in profile["capabilities"]:
        capability_terms.extend(CAPABILITY_MARKERS.get(key, {}).get("terms", ()))
    if region_terms and capability_terms:
        for region in region_terms[:2]:
            for capability in capability_terms[:12]:
                keys.append(f"{region} {capability}")
                keys.append(f"{region} {capability} assessment")
    elif region_terms:
        keys.extend([f"{region} defense policy report" for region in region_terms[:3]])
    elif capability_terms:
        keys.extend([f"{capability} defense assessment" for capability in capability_terms[:4]])
    for term in profile["english_terms"][:18]:
        keys.append(term)
    keys.extend([
        f"{topic} 智库报告",
        f"{topic} 官方报告",
        f"{topic} 研究论文",
        f"{topic} defense report",
    ])
    deduped = []
    for key in keys:
        key = re.sub(r"\s+", " ", (key or "").strip())
        if key and key not in deduped:
            deduped.append(key)
    return deduped


def _build_plan(topic: str, target_source_count: int, search_web: bool) -> dict:
    channels = ["实时网页抓取具体报告/分析", "系统RSS精品候选", "精选智库目录检索目标", "用户导入素材"]
    if not search_web:
        channels = [c for c in channels if c != "实时网页抓取具体报告/分析"]
    keywords = _keywords_for_topic(topic)
    topic_profile = build_topic_profile(topic)
    return {
        "topic": topic,
        "keywords": keywords,
        "primary_query": " ".join(keywords[:3]),
        "topic_profile": topic_profile,
        "target_source_count": target_source_count,
        "channels": channels,
        "method": "先抓取具体报告/分析来源，再列出智库检索目标，最后形成报告源包",
        "next_queries": [
            f"{keywords[0]} think tank report PDF" if keywords else f"{topic} think tank report PDF",
            f"{keywords[0]} official assessment" if keywords else f"{topic} official assessment",
            f"{keywords[0]} doctrine manual" if "doctrine" in topic_profile.get("file_types", []) else f"{topic} research paper",
        ],
    }


def _session_from_row(row) -> dict:
    return {
        "session_id": row["session_id"],
        "instruction": row["instruction"],
        "topic": row["topic"],
        "report_goal": row["report_goal"],
        "target_source_count": row["target_source_count"],
        "search_web": bool(row["search_web"]),
        "plan": _json_loads(row["plan_json"], {}),
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _evidence_from_row(row) -> dict:
    return {
        "evidence_id": row["evidence_id"],
        "session_id": row["session_id"],
        "title": row["title"],
        "source": row["source"],
        "published_at": row["published_at"],
        "url": row["url"],
        "channel": row["channel"],
        "score": row["score"],
        "reason": row["reason"],
        "snippet": row["snippet"],
        "dedup_key": row["dedup_key"],
        "payload": _json_loads(row["payload_json"], {}),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _answer_from_row(row) -> dict:
    return {
        "answer_id": row["answer_id"],
        "session_id": row["session_id"],
        "kind": row["kind"],
        "content": report_agent.sanitize_report_text(row["content"]),
        "model": row["model"],
        "source_answer_id": row["source_answer_id"],
        "payload": _json_loads(row["payload_json"], {}),
        "created_at": row["created_at"],
    }


def _event_from_row(row) -> dict:
    return {
        "id": row["id"],
        "session_id": row["session_id"],
        "event_type": row["event_type"],
        "payload": _json_loads(row["payload_json"], {}),
        "created_at": row["created_at"],
    }


def _log_event(conn, session_id: str, event_type: str, payload=None):
    conn.execute(
        "INSERT INTO events(session_id, event_type, payload_json, created_at) VALUES (?, ?, ?, ?)",
        (session_id, event_type, _json_dumps(payload or {}), _now()),
    )


def create_session(instruction: str, target_source_count: int | None = None,
                   report_goal: str = "", search_web: bool = True) -> dict:
    if len(str(instruction or "")) > MAX_CONSULTING_INSTRUCTION_CHARS:
        raise ValueError("客户指令超过 4096 字符限制")
    instruction = _clean_text(instruction)
    if not instruction:
        raise ValueError("缺少客户指令")
    topic = _derive_topic(instruction)
    requested = _extract_requested_count(instruction)
    target_source_count = int(target_source_count or requested or DEFAULT_TARGET_SOURCE_COUNT)
    target_source_count = max(MIN_SOURCE_TARGET, target_source_count)
    report_goal = (report_goal or _derive_report_goal(instruction)).strip()
    plan = _build_plan(topic, target_source_count, bool(search_web))
    session_id = _new_id("cs")
    now = _now()
    init_consulting_agent_db()
    with _DB_LOCK, _connect() as conn:
        conn.execute(
            """
            INSERT INTO sessions
            (session_id, instruction, topic, report_goal, target_source_count, search_web, plan_json, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
            """,
            (session_id, instruction, topic, report_goal, target_source_count, 1 if search_web else 0, _json_dumps(plan), now, now),
        )
        _log_event(conn, session_id, "session_created", {"instruction": instruction})
        conn.commit()
    return get_session(session_id)


def get_session(session_id: str) -> dict:
    init_consulting_agent_db()
    with _DB_LOCK, _connect() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,)).fetchone()
    if not row:
        raise KeyError("咨询会话不存在")
    return _session_from_row(row)


def list_sessions(limit: int = 30) -> list[dict]:
    init_consulting_agent_db()
    limit = max(1, min(int(limit or 30), 100))
    with _DB_LOCK, _connect() as conn:
        rows = conn.execute("SELECT * FROM sessions ORDER BY updated_at DESC LIMIT ?", (limit,)).fetchall()
    return [_session_from_row(row) for row in rows]


def _dedup_key(item: dict) -> str:
    basis = (item.get("url") or item.get("link") or "").strip().lower()
    if not basis:
        basis = "|".join([
            item.get("title", ""),
            item.get("source", ""),
            item.get("published_at", "") or item.get("date", ""),
        ]).lower()
    return hashlib.sha256(basis.encode("utf-8", errors="ignore")).hexdigest()[:24]


def _evidence_id(session_id: str, dedup_key: str) -> str:
    return "ce_" + hashlib.sha256(f"{session_id}|{dedup_key}".encode("utf-8", errors="ignore")).hexdigest()[:24]


def upsert_evidence(session_id: str, candidates: list[dict]) -> list[dict]:
    get_session(session_id)
    init_consulting_agent_db()
    ids = []
    now = _now()
    with _DB_LOCK, _connect() as conn:
        for item in candidates or []:
            title = _clean_text(item.get("title", ""))
            if not title:
                continue
            dedup_key = _dedup_key(item)
            evidence_id = _evidence_id(session_id, dedup_key)
            if evidence_id not in ids:
                ids.append(evidence_id)
            snippet = report_agent.sanitize_report_text(item.get("snippet") or item.get("summary") or "")
            payload = {**item}
            if isinstance(item.get("payload"), dict):
                payload.update(item.get("payload") or {})
            conn.execute(
                """
                INSERT INTO evidence
                (evidence_id, session_id, title, source, published_at, url, channel, score, reason, snippet,
                 dedup_key, payload_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id, dedup_key) DO UPDATE SET
                    title=excluded.title,
                    source=excluded.source,
                    published_at=excluded.published_at,
                    url=excluded.url,
                    channel=excluded.channel,
                    score=excluded.score,
                    reason=excluded.reason,
                    snippet=excluded.snippet,
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                (
                    evidence_id,
                    session_id,
                    title,
                    _clean_text(item.get("source") or item.get("source_cn") or ""),
                    _clean_text(item.get("published_at") or item.get("date") or ""),
                    (item.get("url") or item.get("link") or "").strip(),
                    _clean_text(item.get("channel") or item.get("source_type") or "unknown"),
                    int(item.get("score") or item.get("quality_score") or 0),
                    _clean_text(item.get("reason") or "公开来源线索"),
                    snippet,
                    dedup_key,
                    _json_dumps(payload),
                    now,
                    now,
                ),
            )
        conn.execute("UPDATE sessions SET updated_at=? WHERE session_id=?", (now, session_id))
        _log_event(conn, session_id, "evidence_upserted", {"count": len(ids)})
        conn.commit()
    return get_evidence(session_id, ids)


def get_evidence(session_id: str, evidence_ids: list[str] | None = None) -> list[dict]:
    init_consulting_agent_db()
    with _DB_LOCK, _connect() as conn:
        if evidence_ids:
            placeholders = ",".join("?" for _ in evidence_ids)
            rows = conn.execute(
                f"SELECT * FROM evidence WHERE session_id=? AND evidence_id IN ({placeholders})",
                [session_id, *evidence_ids],
            ).fetchall()
            by_id = {row["evidence_id"]: _evidence_from_row(row) for row in rows}
            return [by_id[eid] for eid in evidence_ids if eid in by_id]
        rows = conn.execute(
            "SELECT * FROM evidence WHERE session_id=? ORDER BY score DESC, updated_at DESC",
            (session_id,),
        ).fetchall()
    return [_evidence_from_row(row) for row in rows]


def _asset_from_row(row) -> dict:
    return {
        "asset_id": row["asset_id"],
        "session_id": row["session_id"],
        "evidence_id": row["evidence_id"],
        "url": row["url"],
        "status": row["status"],
        "local_path": row["local_path"],
        "text_path": row["text_path"],
        "metadata_path": row["metadata_path"],
        "checksum": row["checksum"],
        "content_type": row["content_type"],
        "document_type": row["document_type"],
        "word_count": row["word_count"],
        "failure_reason": row["failure_reason"],
        "fetched_at": row["fetched_at"],
        "payload": _json_loads(row["payload_json"], {}),
    }


def _safe_asset_part(value: str, fallback: str = "source") -> str:
    text = re.sub(r'[\\/:*?"<>|\r\n\t]+', "_", (value or "").strip())
    text = re.sub(r"\s+", "_", text).strip("._ ")
    return (text or fallback)[:80]


def _word_count(text: str) -> int:
    latin_words = re.findall(r"[A-Za-z0-9][A-Za-z0-9\-']*", text or "")
    cjk_chars = re.findall(r"[\u4e00-\u9fff]", text or "")
    return len(latin_words) + len(cjk_chars)


def _asset_id(session_id: str, evidence_id: str, url: str) -> str:
    basis = f"{session_id}|{evidence_id}|{url or evidence_id}"
    return "sa_" + hashlib.sha256(basis.encode("utf-8", errors="ignore")).hexdigest()[:24]


def _asset_extension(document_type: str, content_type: str, url: str) -> str:
    doc_type = (document_type or "").lower()
    lower_url = (url or "").lower().split("?", 1)[0]
    if doc_type == "pdf" or "pdf" in (content_type or "").lower() or lower_url.endswith(".pdf"):
        return ".pdf"
    if doc_type in {"doc", "docx"} or lower_url.endswith((".doc", ".docx")):
        return ".docx"
    if doc_type == "html":
        return ".html"
    return ".txt"


def _write_bytes(path: str, data: bytes):
    with open(path, "wb") as f:
        f.write(data)


def _write_text(path: str, text: str):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text or "")


def archive_source_asset(session_id: str, evidence: dict, doc: dict,
                         status: str = "archived", failure_reason: str = "") -> dict:
    """Persist a fetched public source as a local citable asset."""
    get_session(session_id)
    status = (status or "archived").strip()
    if status not in {"archived", "partial", "needs_user_input"}:
        raise ValueError("无效原文资产状态")
    evidence_id = evidence.get("evidence_id") or ""
    if not evidence_id:
        raise ValueError("缺少 evidence_id，无法归档原文")
    url = (doc.get("url") or evidence.get("url") or "").strip()
    if not url:
        raise ValueError("缺少URL，无法归档原文")
    text = report_agent.sanitize_report_text(doc.get("text") or doc.get("snippet") or evidence.get("snippet") or "")
    if status == "archived" and not text.strip():
        raise ValueError("抓取结果没有可提取正文")
    if not text.strip():
        text = report_agent.sanitize_report_text(failure_reason or "正文抽取不足，需人工复核")
    content_type = (doc.get("content_type") or "").strip()
    document_type = (doc.get("document_type") or "html").strip().lower()
    raw_bytes = doc.get("raw_bytes")
    if isinstance(raw_bytes, str):
        raw_bytes = raw_bytes.encode("utf-8", errors="ignore")
    if not isinstance(raw_bytes, (bytes, bytearray)) or not raw_bytes:
        original_text = doc.get("raw_html") or text
        raw_bytes = original_text.encode("utf-8", errors="ignore")
    checksum = hashlib.sha256(bytes(raw_bytes)).hexdigest()
    fetched_at = doc.get("fetched_at") or _now()
    asset_id = _asset_id(session_id, evidence_id, url)
    asset_dir = os.path.join(SOURCE_ARCHIVE_DIR, _safe_asset_part(session_id, "session"), _safe_asset_part(evidence_id, "evidence"))
    os.makedirs(asset_dir, exist_ok=True)
    ext = _asset_extension(document_type, content_type, url)
    local_path = os.path.join(asset_dir, f"original{ext}")
    text_path = os.path.join(asset_dir, "extracted.txt")
    metadata_path = os.path.join(asset_dir, "metadata.json")
    _write_bytes(local_path, bytes(raw_bytes))
    _write_text(text_path, text)
    payload = {k: v for k, v in (doc or {}).items() if k not in {"raw_bytes", "raw_html"}}
    payload.update({
        "title": doc.get("title") or evidence.get("title"),
        "source": evidence.get("source"),
        "url": url,
        "asset_status": status,
        "failure_reason": failure_reason,
        "failure_code": doc.get("failure_code") or "",
        "diagnosis": doc.get("diagnosis") or {},
        "quality_radar": doc.get("quality_radar") or {},
        "extraction_method": doc.get("extraction_method") or "",
    })
    word_count = int(doc.get("word_count") or _word_count(text))
    metadata = {
        "asset_id": asset_id,
        "session_id": session_id,
        "evidence_id": evidence_id,
        "title": payload.get("title") or "",
        "source": evidence.get("source") or "",
        "url": url,
        "status": status,
        "local_path": local_path,
        "text_path": text_path,
        "metadata_path": metadata_path,
        "checksum": checksum,
        "content_type": content_type,
        "document_type": document_type,
        "word_count": word_count,
        "failure_reason": failure_reason,
        "failure_code": payload.get("failure_code") or "",
        "diagnosis": payload.get("diagnosis") or {},
        "quality_radar": payload.get("quality_radar") or {},
        "fetched_at": fetched_at,
    }
    _write_text(metadata_path, _json_dumps(metadata))
    init_consulting_agent_db()
    with _DB_LOCK, _connect() as conn:
        conn.execute(
            "DELETE FROM source_assets WHERE session_id=? AND evidence_id=? AND url=?",
            (session_id, evidence_id, url),
        )
        conn.execute(
            """
            INSERT INTO source_assets
            (asset_id, session_id, evidence_id, url, status, local_path, text_path, metadata_path,
             checksum, content_type, document_type, word_count, failure_reason, fetched_at, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                asset_id, session_id, evidence_id, url, status, local_path, text_path, metadata_path,
                checksum, content_type, document_type, word_count,
                report_agent.sanitize_report_text(failure_reason or "")[:500],
                fetched_at, _json_dumps(payload),
            ),
        )
        _log_event(conn, session_id, "source_asset_archived", {"asset_id": asset_id, "evidence_id": evidence_id, "status": status})
        conn.execute("UPDATE sessions SET updated_at=? WHERE session_id=?", (fetched_at, session_id))
        conn.commit()
    return get_source_asset(asset_id)


def record_source_asset_failure(session_id: str, evidence: dict, reason: str, url: str | None = None,
                                failure_code: str = "", diagnosis: dict | None = None) -> dict:
    get_session(session_id)
    evidence_id = evidence.get("evidence_id") or ""
    url = (url or evidence.get("url") or "").strip()
    if not evidence_id:
        raise ValueError("缺少 evidence_id，无法记录失败")
    asset_id = _asset_id(session_id, evidence_id, url)
    now = _now()
    payload = {
        "title": evidence.get("title") or "",
        "source": evidence.get("source") or "",
        "reason": reason,
        "failure_code": failure_code or "",
        "diagnosis": diagnosis or {},
    }
    init_consulting_agent_db()
    with _DB_LOCK, _connect() as conn:
        conn.execute(
            "DELETE FROM source_assets WHERE session_id=? AND evidence_id=? AND url=?",
            (session_id, evidence_id, url),
        )
        conn.execute(
            """
            INSERT INTO source_assets
            (asset_id, session_id, evidence_id, url, status, local_path, text_path, metadata_path,
             checksum, content_type, document_type, word_count, failure_reason, fetched_at, payload_json)
            VALUES (?, ?, ?, ?, 'failed', '', '', '', '', '', '', 0, ?, ?, ?)
            """,
            (asset_id, session_id, evidence_id, url, report_agent.sanitize_report_text(reason or "抓取失败")[:500], now, _json_dumps(payload)),
        )
        _log_event(conn, session_id, "source_asset_failed", {"asset_id": asset_id, "evidence_id": evidence_id, "reason": reason})
        conn.execute("UPDATE sessions SET updated_at=? WHERE session_id=?", (now, session_id))
        conn.commit()
    return get_source_asset(asset_id)


def get_source_asset(asset_id: str) -> dict:
    init_consulting_agent_db()
    with _DB_LOCK, _connect() as conn:
        row = conn.execute("SELECT * FROM source_assets WHERE asset_id=?", (asset_id,)).fetchone()
    if not row:
        raise KeyError("原文资产不存在")
    return _asset_from_row(row)


def list_source_assets(session_id: str, evidence_ids: list[str] | None = None,
                       status: str | None = None) -> list[dict]:
    init_consulting_agent_db()
    params = [session_id]
    where = ["session_id=?"]
    if evidence_ids:
        placeholders = ",".join("?" for _ in evidence_ids)
        where.append(f"evidence_id IN ({placeholders})")
        params.extend(evidence_ids)
    if status:
        where.append("status=?")
        params.append(status)
    with _DB_LOCK, _connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM source_assets WHERE {' AND '.join(where)} ORDER BY fetched_at DESC",
            params,
        ).fetchall()
    return [_asset_from_row(row) for row in rows]


def source_archive_root(session_id: str) -> str:
    return os.path.join(SOURCE_ARCHIVE_DIR, _safe_asset_part(session_id, "session"))


def capture_asset_counts(session_id: str, target_count: int | None = None) -> dict:
    assets = list_source_assets(session_id)
    counts = {
        "archived_count": 0,
        "partial_count": 0,
        "failed_count": 0,
        "needs_user_input_count": 0,
    }
    for asset in assets:
        status = asset.get("status")
        if status == "archived":
            counts["archived_count"] += 1
        elif status == "partial":
            counts["partial_count"] += 1
        elif status == "needs_user_input":
            counts["needs_user_input_count"] += 1
        elif status == "failed":
            counts["failed_count"] += 1
    target = max(0, int(target_count or 0))
    counts["archive_shortfall"] = max(0, target - counts["archived_count"]) if target else 0
    counts["citable_count"] = counts["archived_count"]
    return counts


def _capture_job_from_row(row, attempts: list[dict] | None = None) -> dict:
    return {
        "job_id": row["job_id"],
        "session_id": row["session_id"],
        "status": row["status"],
        "target_count": row["target_count"],
        "batch_size": row["batch_size"],
        "max_rounds": row["max_rounds"],
        "crawl_mode": row["crawl_mode"],
        "allow_browser_render": bool(row["allow_browser_render"]),
        "round_no": row["round_no"],
        "current_query": row["current_query"],
        "archived_count": row["archived_count"],
        "partial_count": row["partial_count"],
        "failed_count": row["failed_count"],
        "needs_user_input_count": row["needs_user_input_count"],
        "rejected_low_relevance": row["rejected_low_relevance"],
        "stop_reason": row["stop_reason"],
        "payload": _json_loads(row["payload_json"], {}),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "attempts": attempts or [],
    }


def _capture_attempt_from_row(row) -> dict:
    return {
        "attempt_id": row["attempt_id"],
        "job_id": row["job_id"],
        "session_id": row["session_id"],
        "round_no": row["round_no"],
        "query_text": row["query_text"],
        "result_count": row["result_count"],
        "archived_delta": row["archived_delta"],
        "partial_delta": row["partial_delta"],
        "failed_delta": row["failed_delta"],
        "needs_user_input_delta": row["needs_user_input_delta"],
        "rejected_low_relevance": row["rejected_low_relevance"],
        "payload": _json_loads(row["payload_json"], {}),
        "created_at": row["created_at"],
    }


def create_capture_job(session_id: str, target_count: int, batch_size: int = 8,
                       max_rounds: int = 6, crawl_mode: str = "steady",
                       allow_browser_render: bool = True, payload: dict | None = None) -> dict:
    get_session(session_id)
    now = _now()
    job_id = _new_id("cj")
    counts = capture_asset_counts(session_id, target_count)
    init_consulting_agent_db()
    with _DB_LOCK, _connect() as conn:
        conn.execute(
            """
            INSERT INTO capture_jobs
            (job_id, session_id, status, target_count, batch_size, max_rounds, crawl_mode,
             allow_browser_render, round_no, archived_count, partial_count, failed_count,
             needs_user_input_count, rejected_low_relevance, payload_json, created_at, updated_at)
            VALUES (?, ?, 'queued', ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, 0, ?, ?, ?)
            """,
            (
                job_id, session_id, max(1, int(target_count or 1)), max(1, int(batch_size or 8)),
                max(1, int(max_rounds or 6)), crawl_mode or "steady", 1 if allow_browser_render else 0,
                counts["archived_count"], counts["partial_count"], counts["failed_count"],
                counts["needs_user_input_count"], _json_dumps(payload or {}), now, now,
            ),
        )
        _log_event(conn, session_id, "capture_job_created", {"job_id": job_id, "target_count": target_count})
        conn.commit()
    return get_capture_job(session_id, job_id)


def record_capture_attempt(job_id: str, session_id: str, round_no: int, query_text: str,
                           result_count: int = 0, archived_delta: int = 0,
                           partial_delta: int = 0, failed_delta: int = 0,
                           needs_user_input_delta: int = 0, rejected_low_relevance: int = 0,
                           payload: dict | None = None) -> dict:
    init_consulting_agent_db()
    attempt_id = _new_id("ca")
    with _DB_LOCK, _connect() as conn:
        conn.execute(
            """
            INSERT INTO capture_attempts
            (attempt_id, job_id, session_id, round_no, query_text, result_count, archived_delta,
             partial_delta, failed_delta, needs_user_input_delta, rejected_low_relevance, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                attempt_id, job_id, session_id, int(round_no or 0), query_text or "", int(result_count or 0),
                int(archived_delta or 0), int(partial_delta or 0), int(failed_delta or 0),
                int(needs_user_input_delta or 0), int(rejected_low_relevance or 0),
                _json_dumps(payload or {}), _now(),
            ),
        )
        conn.commit()
    attempts = _get_capture_attempts(job_id)
    return attempts[-1]


def update_capture_job(job_id: str, status: str | None = None, round_no: int | None = None,
                       current_query: str | None = None, stop_reason: str | None = None,
                       counts: dict | None = None, payload: dict | None = None) -> dict:
    init_consulting_agent_db()
    counts = counts or {}
    updates = ["updated_at=?"]
    params = [_now()]
    for field, value in (
        ("status", status),
        ("round_no", round_no),
        ("current_query", current_query),
        ("stop_reason", stop_reason),
        ("archived_count", counts.get("archived_count")),
        ("partial_count", counts.get("partial_count")),
        ("failed_count", counts.get("failed_count")),
        ("needs_user_input_count", counts.get("needs_user_input_count")),
        ("rejected_low_relevance", counts.get("rejected_low_relevance")),
    ):
        if value is not None:
            updates.append(f"{field}=?")
            params.append(value)
    if payload is not None:
        updates.append("payload_json=?")
        params.append(_json_dumps(payload))
    params.append(job_id)
    with _DB_LOCK, _connect() as conn:
        conn.execute(f"UPDATE capture_jobs SET {', '.join(updates)} WHERE job_id=?", params)
        conn.commit()
        row = conn.execute("SELECT session_id FROM capture_jobs WHERE job_id=?", (job_id,)).fetchone()
    if not row:
        raise KeyError("采集任务不存在")
    return get_capture_job(row["session_id"], job_id)


def _get_capture_attempts(job_id: str) -> list[dict]:
    init_consulting_agent_db()
    with _DB_LOCK, _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM capture_attempts WHERE job_id=? ORDER BY created_at ASC",
            (job_id,),
        ).fetchall()
    return [_capture_attempt_from_row(row) for row in rows]


def get_capture_job(session_id: str, job_id: str) -> dict:
    init_consulting_agent_db()
    with _DB_LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT * FROM capture_jobs WHERE session_id=? AND job_id=?",
            (session_id, job_id),
        ).fetchone()
    if not row:
        raise KeyError("采集任务不存在")
    return _capture_job_from_row(row, _get_capture_attempts(job_id))


def _thinktank_candidates(session: dict, thinktank_directory: list[dict], limit: int) -> list[dict]:
    project_like = {
        "topic": session.get("topic"),
        "title": session.get("report_goal"),
        "client_request": session.get("instruction"),
    }
    rows = report_agent.build_source_candidates(project_like, thinktank_directory, limit=limit)
    profile = (session.get("plan") or {}).get("topic_profile") or build_topic_profile(session.get("topic") or "")
    rows = [row for row in rows if not _is_unrelated_china_target(row, profile)]
    return [{
        "title": row.get("title", ""),
        "source": row.get("source") or row.get("source_cn") or "智库/报告源",
        "published_at": row.get("date", ""),
        "url": row.get("link", ""),
        "channel": "thinktank_target",
        "score": row.get("quality_score") or 72,
        "reason": "精选智库目录检索目标（尚未抓取具体报告）",
        "snippet": (row.get("summary", "") + " 后续需要进入该站点或实时搜索抓取具体报告/分析。").strip(),
        "payload": row,
    } for row in rows]


def _rss_candidates(rows: list[dict]) -> list[dict]:
    return [{
        "title": row.get("title", ""),
        "source": row.get("source_cn") or row.get("source") or "RSS",
        "published_at": row.get("date", ""),
        "url": row.get("link", ""),
        "channel": "rss",
        "score": row.get("quality_score") or row.get("quality", {}).get("total") or 60,
        "reason": "系统RSS精品候选",
        "snippet": row.get("summary", ""),
        "payload": row,
    } for row in rows or []]


def _imported_candidates(rows: list[dict]) -> list[dict]:
    return [{
        "title": row.get("title") or "用户导入素材",
        "source": row.get("source") or "用户导入",
        "published_at": row.get("published_at") or row.get("date") or "",
        "url": row.get("url") or row.get("link") or "",
        "channel": "imported",
        "score": row.get("score") or 78,
        "reason": "用户导入素材",
        "snippet": row.get("snippet") or row.get("summary") or row.get("body") or "",
        "payload": row,
    } for row in rows or []]


def collect_candidates(session: dict, web_results: list[dict], rss_candidates: list[dict],
                       thinktank_directory: list[dict], imported_items: list[dict] | None = None) -> tuple[list[dict], dict]:
    target = max(MIN_SOURCE_TARGET, int(session.get("target_source_count") or DEFAULT_TARGET_SOURCE_COUNT))
    rows = []
    rows.extend(web_results or [])
    rows.extend(_rss_candidates(rss_candidates or []))
    remaining_for_sources = max(target - len(rows), target)
    rows.extend(_thinktank_candidates(session, thinktank_directory, limit=remaining_for_sources))
    rows.extend(_imported_candidates(imported_items or []))

    seen = set()
    selected = []
    for item in rows:
        key = _dedup_key(item)
        if key in seen:
            continue
        seen.add(key)
        selected.append(item)
        if len(selected) >= target:
            break
    stored = upsert_evidence(session["session_id"], selected)
    channel_counts: dict[str, int] = {}
    for row in stored:
        channel_counts[row["channel"]] = channel_counts.get(row["channel"], 0) + 1
    target_seed_count = sum(1 for row in stored if row.get("channel") == "thinktank_target")
    found_count = len(stored) - target_seed_count
    assets = list_source_assets(session["session_id"])
    archived_count = sum(1 for asset in assets if asset.get("status") == "archived")
    failed_count = sum(1 for asset in assets if asset.get("status") == "failed")
    next_queries = build_report_source_queries(session, thinktank_directory, max_queries=8)
    meta = {
        "target_source_count": target,
        "found_count": found_count,
        "target_seed_count": target_seed_count,
        "archived_count": archived_count,
        "failed_count": failed_count,
        "unresolved_target_count": target_seed_count,
        "shortfall": max(0, target - found_count),
        "archive_shortfall": max(0, target - archived_count),
        "channel_counts": channel_counts,
        "web_enabled_requested": bool(session.get("search_web")),
        "topic_plan": session.get("plan") or {},
        "next_queries": next_queries,
    }
    return stored, meta


def _domain_from_url(url: str) -> str:
    match = re.search(r"https?://(?:www\.)?([^/]+)", url or "")
    return match.group(1) if match else ""


def _is_unrelated_china_target(row: dict, profile: dict) -> bool:
    if not profile.get("avoid_unrelated_china_fallback"):
        return False
    haystack = " ".join([
        row.get("title", ""),
        row.get("summary", ""),
        row.get("source", ""),
        row.get("source_cn", ""),
        row.get("link", ""),
        row.get("url", ""),
    ]).lower()
    china_markers = ("81.cn", "topics/china", "/china", "china research", "pla", "解放军", "中国专题", "中国军事", "台海", "台湾", "南海")
    return any(marker.lower() in haystack for marker in china_markers)


def build_report_source_queries(session: dict, thinktank_directory: list[dict], max_queries: int = 12) -> list[str]:
    topic = session.get("topic") or session.get("instruction") or "defense analysis"
    keywords = session.get("plan", {}).get("keywords") or _keywords_for_topic(topic)
    topic_profile = session.get("plan", {}).get("topic_profile") or build_topic_profile(topic)
    query_bases = []
    for key in keywords[:5] or [topic]:
        if key and key not in query_bases:
            query_bases.append(key)
    queries = []
    for base in query_bases[:3]:
        queries.append(f"{base} think tank report analysis PDF")
    domains = []
    project_like = {
        "topic": topic,
        "title": session.get("report_goal") or "",
        "client_request": session.get("instruction") or "",
    }
    source_rows = report_agent.build_source_candidates(
        project_like,
        thinktank_directory,
        limit=max(max_queries * 2, 12),
    )
    for row in source_rows:
        if _is_unrelated_china_target(row, topic_profile):
            continue
        domain = _domain_from_url(row.get("link") or "")
        if domain and domain not in domains:
            domains.append(domain)
    for domain in domains:
        queries.append(f"site:{domain} {query_bases[0]} report analysis")
        if len(queries) >= max_queries:
            break
    for domain in domains:
        queries.append(f"site:{domain} {query_bases[0]} PDF")
        if len(queries) >= max_queries:
            break
    for base in query_bases[:3]:
        queries.append(f"{base} military assessment report")
        if len(queries) >= max_queries:
            break
    deduped = []
    for query in queries:
        query = _clean_text(query)
        if query and query not in deduped:
            deduped.append(query)
        if len(deduped) >= max_queries:
            break
    return deduped


def _source_pack_counts(evidence: list[dict]) -> tuple[list[dict], list[dict]]:
    fetched = []
    targets = []
    for row in evidence:
        payload = row.get("payload") or {}
        if row.get("channel") == "imported" or payload.get("asset_status") == "archived":
            fetched.append(row)
        elif row.get("channel") == "thinktank_target":
            targets.append(row)
    return fetched, targets


def build_source_pack(session: dict, evidence: list[dict]) -> str:
    fetched, targets = _source_pack_counts(evidence)
    pending_concrete = [
        row for row in evidence
        if row.get("channel") != "thinktank_target"
        and row.get("channel") != "imported"
        and (row.get("payload") or {}).get("asset_status") != "archived"
    ]
    target_count = int(session.get("target_source_count") or 0)
    legacy_fetched_count = sum(1 for row in evidence if row.get("channel") != "thinktank_target")
    concrete_gap = max(0, target_count - len(fetched))
    lines = [
        "# 报告源抓取包",
        "",
        "说明：本资料包用于给后续报告Agent或人工分析师提供可核验来源，不是最终战略分析报告。",
        f"客户指令：{session.get('instruction')}",
        f"主题：{session.get('topic')}",
        f"目标来源数量：{target_count}",
        f"已归档报告/分析来源：{len(fetched)}",
        f"已抓取报告/分析来源：{legacy_fetched_count}（候选口径，正式可引用以已归档为准）",
        f"智库/机构检索目标：{len(targets)}",
        f"仍需补抓具体报告/分析：{concrete_gap}",
        "",
        "## 一、检索计划",
        f"- 交付定位：抓取客户需要的智库报告、政策分析、研究论文、公开评估和防务媒体深度分析。",
        f"- 搜索关键词：{'、'.join((session.get('plan') or {}).get('keywords') or [])}",
        "- 口径边界：智库目录只表示可继续检索的机构入口；只有已落入本地资料库的原文/正文资产或用户导入素材才计入已归档来源。",
        "",
        "## 二、已归档报告/分析来源",
    ]
    if fetched:
        for idx, row in enumerate(fetched, 1):
            lines.extend([
                f"### [{idx}] {row.get('title')}",
                f"- 来源：{row.get('source') or '公开来源'}",
                f"- 渠道：{row.get('channel') or 'unknown'}；评分：{row.get('score') or 0}",
                f"- 时间：{row.get('published_at') or '未知'}",
                f"- 链接：{row.get('url') or '无'}",
                f"- 摘要：{row.get('snippet') or '无摘要'}",
                f"- 推荐理由：{row.get('reason') or '公开来源线索'}",
                "",
            ])
    else:
        lines.append("- 暂无已抓取的具体报告/分析来源。")
        lines.append("")
    if pending_concrete:
        lines.append("## 二点五、候选但未归档来源")
        for idx, row in enumerate(pending_concrete, 1):
            lines.extend([
                f"### [P{idx}] {row.get('title')}",
                f"- 来源：{row.get('source') or '公开来源'}",
                f"- 链接：{row.get('url') or '无'}",
                f"- 状态：尚未落入本地资料库，不能作为正式可引用资产转入报告Agent。",
                f"- 摘要：{row.get('snippet') or '无摘要'}",
                "",
            ])
    lines.append("## 三、智库/机构检索目标")
    if targets:
        for idx, row in enumerate(targets, 1):
            lines.extend([
                f"### [T{idx}] {row.get('title')}",
                f"- 机构：{row.get('source') or '智库/机构'}",
                f"- 入口：{row.get('url') or '无'}",
                f"- 下一步：进入站内检索具体报告、专题分析、PDF、项目页或数据库条目。",
                f"- 说明：{row.get('snippet') or row.get('reason') or '精选智库目录检索目标'}",
                "",
            ])
    else:
        lines.append("- 暂无智库/机构检索目标。")
        lines.append("")
    lines.extend([
        "## 四、缺口与下一步",
        f"- 当前还需要补抓 {concrete_gap} 份具体报告/分析来源。",
        "- 优先补抓对象：官方报告、权威智库PDF、研究论文、国会/审计机构报告、机构专题数据库、防务媒体深度分析。",
        "- 后续可将本资料包转入报告Agent，再进行战略分析报告写作。",
    ])
    return report_agent.sanitize_report_text("\n".join(lines))


def save_answer(session_id: str, content: str, model: str = "", kind: str = "synthesis",
                source_answer_id: str = "", payload: dict | None = None) -> dict:
    get_session(session_id)
    content = report_agent.sanitize_report_text(content or "")
    if not content:
        raise ValueError("报告内容为空")
    if kind not in {"source_pack", "synthesis", "revision"}:
        raise ValueError("无效报告版本类型")
    answer_id = _new_id("ca")
    with _DB_LOCK, _connect() as conn:
        conn.execute(
            """
            INSERT INTO answers(answer_id, session_id, kind, content, model, source_answer_id, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (answer_id, session_id, kind, content, model or "", source_answer_id or "", _json_dumps(payload or {}), _now()),
        )
        conn.execute("UPDATE sessions SET updated_at=? WHERE session_id=?", (_now(), session_id))
        _log_event(conn, session_id, "answer_saved", {"answer_id": answer_id, "kind": kind})
        conn.commit()
    return get_answer(answer_id)


def get_answer(answer_id: str) -> dict:
    init_consulting_agent_db()
    with _DB_LOCK, _connect() as conn:
        row = conn.execute("SELECT * FROM answers WHERE answer_id=?", (answer_id,)).fetchone()
    if not row:
        raise KeyError("资料包不存在")
    return _answer_from_row(row)


def get_answers(session_id: str) -> list[dict]:
    init_consulting_agent_db()
    with _DB_LOCK, _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM answers WHERE session_id=? ORDER BY created_at DESC",
            (session_id,),
        ).fetchall()
    return [_answer_from_row(row) for row in rows]


def get_events(session_id: str) -> list[dict]:
    init_consulting_agent_db()
    with _DB_LOCK, _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM events WHERE session_id=? ORDER BY id ASC",
            (session_id,),
        ).fetchall()
    return [_event_from_row(row) for row in rows]


def get_session_bundle(session_id: str) -> dict:
    return {
        "session": get_session(session_id),
        "evidence": get_evidence(session_id),
        "answers": get_answers(session_id),
        "events": get_events(session_id),
    }


def record_query(session_id: str, channel: str, query_text: str, result_count: int, payload=None):
    get_session(session_id)
    with _DB_LOCK, _connect() as conn:
        conn.execute(
            """
            INSERT INTO queries(query_id, session_id, channel, query_text, result_count, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (_new_id("cq"), session_id, channel, query_text, int(result_count or 0), _json_dumps(payload or {}), _now()),
        )
        _log_event(conn, session_id, "query_recorded", {"channel": channel, "result_count": result_count})
        conn.commit()


def _evidence_lines(evidence: list[dict]) -> str:
    lines = []
    for idx, ev in enumerate(evidence, 1):
        lines.append(
            f"[{idx}] 【{ev.get('channel') or 'source'}｜{ev.get('source') or '公开来源'}】{ev.get('title')}\n"
            f"    时间：{ev.get('published_at') or '未知'}\n"
            f"    链接：{ev.get('url') or '无'}\n"
            f"    可信度：{ev.get('score') or 0}；推荐理由：{ev.get('reason') or '公开来源'}\n"
            f"    摘要：{ev.get('snippet') or '无摘要'}"
        )
    return "\n".join(lines)


def build_synthesis_messages(session: dict, evidence: list[dict], writing_requirements: str = "",
                             output_type: str = "consulting_report") -> list[dict]:
    requirements = writing_requirements.strip() if writing_requirements else "以高价值防务战略咨询报告为目标，结构清晰、判断克制、来源闭环。"
    return [
        {
            "role": "system",
            "content": (
                "你是防务信息咨询Agent，服务客户的战略研究与公开源资料综合。"
                "大模型只负责规划、归纳、比较和写作；不得声称自己完成了未提供的检索。"
                "所有事实性判断必须来自证据池，每个关键判断必须绑定来源编号。"
                "严禁使用“秘密”“机密”“绝密”这三个涉密等级字眼。"
                "证据不足时必须标注来源不足或待后续检索，不得编造机构、日期、数据、链接和引用。"
            ),
        },
        {
            "role": "user",
            "content": (
                f"客户指令：{session.get('instruction')}\n"
                f"主题：{session.get('topic')}\n"
                f"交付目标：{session.get('report_goal')} / {output_type}\n"
                f"目标来源数量：{session.get('target_source_count')}\n"
                f"实际可用证据数量：{len(evidence)}\n"
                "数量口径：不得把目标来源数量说成已找到数量；若实际可用证据少于目标，必须说明缺口。\n\n"
                f"审稿/写作要求：\n{requirements}\n\n"
                f"证据池：\n{_evidence_lines(evidence)}\n\n"
                "请输出中文Markdown，固定包含以下部分：\n"
                "## 目录提纲\n"
                "## 审稿意见\n"
                "## 综合报告\n"
                "## 事实追踪表\n"
                "## 来源附录\n"
                "综合报告必须体现战略问题、能力态势、关键变量、影响研判和后续跟踪。"
            ),
        },
    ]


def build_revision_messages(session: dict, answer: dict, instruction: str) -> list[dict]:
    return [
        {
            "role": "system",
            "content": (
                "你是防务信息咨询Agent的审稿修订模块。仅基于原报告与用户修订要求改写，"
                "保留来源编号和证据边界，严禁使用“秘密”“机密”“绝密”字眼。"
            ),
        },
        {
            "role": "user",
            "content": (
                f"客户原始指令：{session.get('instruction')}\n"
                f"修订要求：{instruction}\n\n"
                f"原报告：\n{answer.get('content')}\n\n"
                "请输出修订后的完整Markdown报告，保留目录提纲、审稿意见、综合报告、事实追踪表、来源附录。"
            ),
        },
    ]
