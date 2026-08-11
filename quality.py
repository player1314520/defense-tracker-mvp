# -*- coding: utf-8 -*-
"""精品候选 100 分制评分 + 本地 SQLite 训练库（从 app.py 纯搬运，零行为变更）。

依赖图：state（共享状态）← quality；并用 `import app` / `from app import RSS_FEEDS` 取
静态源表与可被测试 monkeypatch 的 app 级 seam（局部循环 import：app 加载到本模块 import
点时 RSS_FEEDS / _QUALITY_DB_FILE 已定义，安全）。

⚠ _QUALITY_DB_FILE seam 说明：测试用 monkeypatch.setattr(tracker, "_QUALITY_DB_FILE", ...)
临时改库路径。该常量保留在 app.py，_quality_connect 运行时读 app._QUALITY_DB_FILE，
保证 monkeypatch 仍生效（纯名字绑定会因 app/quality 各自一份而失效）。

⚠ _quality_level 影子说明：app.py 原本有两个同名 `_quality_level`——
本模块内（原阈值 85/72/58/40）与 consult 段（app.py，阈值 90/80/70）。
因后者在原文件中后定义，模块级 `_quality_level` 运行时始终解析为 90/80/70 版，
即 score_quality_candidate 实际走 90/80/70。为零行为变更：本模块保留原 85/72/58/40
定义（历史死代码，不擅自删），并在文件末尾以 90/80/70 版覆盖复刻原运行时影子；
app.py 侧 `_quality_level` 仍由其 consult 段定义提供，保持不变。
"""
import re, os, json, sqlite3, threading, hashlib
from datetime import datetime, timezone, timedelta

from state import cache, cache_lock
import app  # 取可被测试 monkeypatch 的 app 级 seam（_QUALITY_DB_FILE）
from app import RSS_FEEDS


BRIEF_SELECT_RULES = [
    # A类：PLA备战 / 国家战略（最高权重）
    {"weight": 10, "label": "PLA备战", "patterns": [
        r"pla\b|people.s liberation|chinese military|china.s military|中国军队|解放军|人民解放军|中央军委|cmc",
        r"pla navy|plan\b|plaaf|plarf|plassf|rocket force|strategic support|theater command|战区|火箭军",
        r"j-20|j-35|j-16|h-6k|h-20|y-20|z-20|df-41|df-26|df-17|jl-3|type 055|type 075|type 076|fujian.*carrier|福建舰|山东舰|辽宁舰",
        r"military.?civil fusion|civil.?military fusion|军民融合|a2.?ad|anti.?access",
    ]},
    # 美日台对华军事威胁（核心选题）
    {"weight": 10, "label": "对华威胁", "patterns": [
        r"against china|counter china|contain china|deter china|对华|针对中国|遏制中国|威慑中国",
        r"taiwan strait|south china sea|east china sea|台海|南海|东海|钓鱼岛|senkaku|diaoyu",
        r"first island chain|second island chain|第一岛链|第二岛链|岛链",
        r"indopacom|indo.?pacific|印太|quad|aukus|四方|奥库斯",
    ]},
    # 装备部署 / 前沿基地
    {"weight": 9, "label": "装备部署", "patterns": [
        r"deploy|deployment|station|based at|forward.?base|部署|进驻|前沿|前进基地",
        r"f-35|f-22|b-21|b-2|b-1|patriot|thaad|aegis|nmd|gmd|金穹|iron dome|iron beam|sm-\d+|tomahawk|lrasm|prsm|dark eagle",
        r"aircraft carrier|carrier strike group|航母|航空母舰|destroyer|submarine|ssn|ssbn|驱逐舰|核潜艇|潜艇",
        r"hypersonic|高超|hgv|glide vehicle|超音速|超高音速",
    ]},
    # 演训 / 演习
    {"weight": 8, "label": "重大演训", "patterns": [
        r"exercise|drill|wargame|war game|演习|演训|军演|联演|实兵|对抗",
        r"rimpac|talisman|balikatan|keen edge|keen sword|garuda|yama sakura|cope|red flag|cobra gold",
    ]},
    # 颠覆性技术 / 突破
    {"weight": 8, "label": "颠覆技术", "patterns": [
        r"breakthrough|disruptive|revolutionary|game.?chang|unprecedent|突破|颠覆|革命性|首创|首次|全球首",
        r"ai|artificial intelligence|autonomous|unmanned|swarm|人工智能|无人|蜂群|集群",
        r"space.?based|satellite constellation|太空|卫星星座|轨道|orbital",
        r"quantum|biotech|directed energy|laser weapon|rail gun|量子|定向能|激光武器|电磁",
    ]},
    # 核战略
    {"weight": 9, "label": "核战略", "patterns": [
        r"nuclear|warhead|icbm|ssbn|triad|deterrence|核武|核弹|核威慑|核三位一体|洲际|战略核",
    ]},
    # 政策 / 条令条例
    {"weight": 7, "label": "政策条令", "patterns": [
        r"policy|doctrine|white paper|national defense strategy|nds\b|nms\b|posture review|政策|白皮书|条令|国防战略|军事战略|态势评估",
        r"budget|appropriation|procurement|军费|预算|采购|拨款",
    ]},
    # 突发热点
    {"weight": 6, "label": "突发热点", "patterns": [
        r"breaking|urgent|alert|crisis|紧急|突发|危机|冲突|shoot down|strike|attack|missile.*launch|击落|打击|空袭|导弹发射",
    ]},
    # 俄乌 / 热点战场
    {"weight": 5, "label": "热点战场", "patterns": [
        r"russia|ukraine|putin|zelensky|kremlin|moscow|kyiv|俄罗斯|乌克兰|普京|泽连斯基|基辅|莫斯科",
        r"gaza|israel|iran|hamas|hezbollah|houthi|以色列|伊朗|加沙|胡塞|真主党",
        r"north korea|dprk|kim jong|朝鲜|金正恩",
    ]},
]

# 触发词：包含这些词的文章更适合做要讯
BRIEF_BOOST_KEYWORDS = [
    "threat", "warning", "concern", "alarm", "signal", "intelligence", "warn",
    "威胁", "警告", "警惕", "关注", "情报", "信号", "告警", "重大", "首次",
    "deployment", "deploy", "capability", "capacity", "operational",
    "部署", "能力", "列装", "服役", "实战",
]

def score_brief_candidate(article: dict) -> dict:
    """为文章打分，评估其作为要讯选题的价值"""
    title = article.get("title", "")
    summary = article.get("summary", "")
    source = article.get("source", "")
    text = (title + " " + summary + " " + source).lower()

    score = 0
    hits = []
    for rule in BRIEF_SELECT_RULES:
        for pat in rule["patterns"]:
            if re.search(pat, text):
                score += rule["weight"]
                if rule["label"] not in hits:
                    hits.append(rule["label"])
                break

    # 触发词加成
    boost = 0
    for kw in BRIEF_BOOST_KEYWORDS:
        if kw.lower() in text:
            boost += 2
    score += min(boost, 10)

    # Tier 0/1 源加成（顶级情报源）
    tier = article.get("tier", 2)
    if tier == 0:
        score += 8
    elif tier == 1:
        score += 4

    # 标题带"china/pla/中国"强加成
    if re.search(r"china|chinese|pla\b|中国|解放军", title, re.I):
        score += 6

    return {"score": score, "hits": hits}

_QUALITY_DB_LOCK = threading.Lock()
_QUALITY_LEVEL_RANK = {"S": 4, "A": 3, "B": 2, "C": 1, "D": 0}
_QUALITY_FEEDBACK_LABELS = {"accepted", "skipped", "rejected", "generated", "discarded"}

def _quality_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _quality_connect():
    db_file = app._QUALITY_DB_FILE  # 运行时读 app 级路径，保留 monkeypatch(tracker._QUALITY_DB_FILE) 语义
    os.makedirs(os.path.dirname(db_file), exist_ok=True)
    conn = sqlite3.connect(db_file, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_quality_db():
    """初始化本地质量训练库。数据库放在 data/ 下，不进入版本库。"""
    with _QUALITY_DB_LOCK, _quality_connect() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS quality_articles (
            article_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            link TEXT,
            summary TEXT,
            source TEXT,
            source_cn TEXT,
            date TEXT,
            tier INTEGER,
            focus TEXT,
            payload_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS quality_scores (
            article_id TEXT PRIMARY KEY,
            total INTEGER NOT NULL,
            level TEXT NOT NULL,
            source_score REAL NOT NULL,
            topic_score REAL NOT NULL,
            density_score REAL NOT NULL,
            novelty_score REAL NOT NULL,
            writability_score REAL NOT NULL,
            reasons_json TEXT NOT NULL,
            penalties_json TEXT NOT NULL,
            scored_at TEXT NOT NULL,
            FOREIGN KEY(article_id) REFERENCES quality_articles(article_id)
        );
        CREATE TABLE IF NOT EXISTS quality_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            article_id TEXT NOT NULL,
            label TEXT NOT NULL,
            reason_codes_json TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY(article_id) REFERENCES quality_articles(article_id)
        );
        CREATE TABLE IF NOT EXISTS quality_generations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            article_id TEXT NOT NULL,
            brief_chars INTEGER NOT NULL,
            validation_json TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(article_id) REFERENCES quality_articles(article_id)
        );
        CREATE TABLE IF NOT EXISTS quality_source_stats (
            source TEXT PRIMARY KEY,
            accepted INTEGER NOT NULL DEFAULT 0,
            skipped INTEGER NOT NULL DEFAULT 0,
            rejected INTEGER NOT NULL DEFAULT 0,
            generated INTEGER NOT NULL DEFAULT 0,
            discarded INTEGER NOT NULL DEFAULT 0,
            trust_adjust REAL NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        );
        """)
        conn.commit()

def _article_id(article: dict) -> str:
    basis = (article.get("link") or "").strip()
    if not basis:
        basis = "|".join([
            article.get("source", ""),
            article.get("title", ""),
            article.get("date", ""),
        ])
    return hashlib.sha256(basis.encode("utf-8", errors="ignore")).hexdigest()[:20]

def _json_dumps(value) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)

def _quality_upsert_article(conn, article: dict) -> str:
    article_id = article.get("article_id") or _article_id(article)
    payload = dict(article)
    payload["article_id"] = article_id
    conn.execute(
        """
        INSERT INTO quality_articles
        (article_id, title, link, summary, source, source_cn, date, tier, focus, payload_json, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(article_id) DO UPDATE SET
            title=excluded.title,
            link=excluded.link,
            summary=excluded.summary,
            source=excluded.source,
            source_cn=excluded.source_cn,
            date=excluded.date,
            tier=excluded.tier,
            focus=excluded.focus,
            payload_json=excluded.payload_json,
            updated_at=excluded.updated_at
        """,
        (
            article_id,
            article.get("title", ""),
            article.get("link", ""),
            article.get("summary", ""),
            article.get("source", ""),
            article.get("source_cn", ""),
            article.get("date", ""),
            int(article.get("tier") if article.get("tier") not in (None, "") else 2),
            article.get("focus", ""),
            _json_dumps(payload),
            _quality_now(),
        ),
    )
    return article_id

def _quality_level(total: int) -> str:
    if total >= 85:
        return "S"
    if total >= 72:
        return "A"
    if total >= 58:
        return "B"
    if total >= 40:
        return "C"
    return "D"

def _quality_level_allowed(level: str, min_level: str) -> bool:
    min_level = (min_level or "A").upper()
    return _QUALITY_LEVEL_RANK.get(level, 0) >= _QUALITY_LEVEL_RANK.get(min_level, 3)

def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))

def _quality_load_source_stats(conn) -> dict:
    rows = conn.execute("SELECT * FROM quality_source_stats").fetchall()
    return {r["source"]: dict(r) for r in rows}

def _quality_feedback_counts(conn, article_id: str) -> dict:
    rows = conn.execute(
        "SELECT label, COUNT(*) AS cnt FROM quality_feedback WHERE article_id=? GROUP BY label",
        (article_id,),
    ).fetchall()
    return {r["label"]: r["cnt"] for r in rows}

def score_quality_candidate(article: dict, source_stats: dict | None = None,
                            feedback_counts: dict | None = None) -> dict:
    """100分制精品候选评分：质量优先，数量从严。"""
    title = article.get("title", "") or ""
    summary = article.get("summary", "") or ""
    source = article.get("source", "") or ""
    text = f"{title} {summary} {source}".lower()
    source_stats = source_stats or {}
    feedback_counts = feedback_counts or {}
    reasons, penalties = [], []

    # 1) 信源权威 20
    tier = int(article.get("tier") if article.get("tier") not in (None, "") else 2)
    source_score = {0: 19, 1: 15, 2: 10}.get(tier, 7)
    focus = article.get("focus", "general")
    if focus in ("china", "taiwan", "japan", "strategy", "nuclear"):
        source_score += 2
    stat = source_stats.get(source, {})
    source_score += float(stat.get("trust_adjust", 0) or 0)
    source_score = _clamp(source_score, 0, 20)
    if tier <= 1:
        reasons.append("高权威信源")
    if stat.get("generated", 0) or stat.get("accepted", 0):
        reasons.append("该信源历史命中较好")

    # 2) 选题契合 35
    brief_score = score_brief_candidate(article)
    topic_score = min(35.0, brief_score["score"] * 1.25)
    if brief_score["hits"]:
        reasons.append("命中" + "、".join(brief_score["hits"][:3]))
    priority_topic = article.get("priority", {}).get("dim", {}).get("topic")
    if priority_topic:
        topic_score = max(topic_score, min(35.0, float(priority_topic) * 8.5))
    if re.search(r"china|chinese|pla\b|taiwan|japan|中国|解放军|台海|日本", text, re.I):
        topic_score = min(35.0, topic_score + 4)
        reasons.append("贴近对华/周边防务重点")

    # 3) 信息密度 20
    density_score = 0.0
    body_len = len(summary)
    if body_len >= 80:
        density_score += 7
    if body_len >= 180:
        density_score += 4
    if re.search(r"\b\d+[\w-]*\b|[一二三四五六七八九十百千万亿]\d*", title + summary):
        density_score += 4
    if re.search(r"\b[A-Z]{2,}[- ]?\d*[A-Z]?\b|f-\d+|b-\d+|df-\d+|type \d+|j-\d+|055|075|076", title + summary, re.I):
        density_score += 3
    if re.search(r"according|official|report|said|announced|confirmed|据|报道|宣布|证实|披露", text, re.I):
        density_score += 2
    density_score = _clamp(density_score, 0, 20)
    if density_score >= 14:
        reasons.append("信息密度较高")
    if body_len < 60:
        penalties.append("摘要信息偏少")

    # 4) 稀缺/新颖 15
    novelty_score = 0.0
    try:
        age_h = (datetime.now(timezone.utc) - datetime.fromisoformat(article.get("date", ""))).total_seconds() / 3600
        if age_h < 6:
            novelty_score += 6
        elif age_h < 24:
            novelty_score += 4
        elif age_h < 72:
            novelty_score += 2
    except Exception:
        pass
    if re.search(r"first|unprecedented|breakthrough|new|首次|首个|突破|新型|里程碑|首次披露", text, re.I):
        novelty_score += 6
        reasons.append("具备新颖/首次信号")
    if tier <= 1:
        novelty_score += 2
    novelty_score = _clamp(novelty_score, 0, 15)

    # 5) 可写成要讯程度 10
    writability_score = 0.0
    if title and summary:
        writability_score += 3
    if article.get("source") and article.get("date"):
        writability_score += 2
    if article.get("link"):
        writability_score += 1
    if re.search(r"threat|warning|concern|deploy|capability|威胁|警惕|关注|部署|能力|演训|建议", text, re.I):
        writability_score += 3
    if article.get("value_tags"):
        writability_score += 1
    writability_score = _clamp(writability_score, 0, 10)
    if writability_score >= 8:
        reasons.append("适合改写为要讯")

    article_penalty = 0
    if feedback_counts.get("rejected", 0):
        article_penalty += feedback_counts["rejected"] * 18
        penalties.append("该文章曾被标为不符合")
    if feedback_counts.get("discarded", 0):
        article_penalty += feedback_counts["discarded"] * 12
        penalties.append("该文章生成后曾被废弃")
    if feedback_counts.get("skipped", 0):
        article_penalty += min(10, feedback_counts["skipped"] * 4)
        penalties.append("该文章曾被跳过")

    total_raw = source_score + topic_score + density_score + novelty_score + writability_score - article_penalty
    total = int(round(_clamp(total_raw, 0, 100)))
    level = _quality_level(total)
    if not reasons:
        reasons.append("基础防务相关")

    return {
        "total": total,
        "level": level,
        "dims": {
            "source": round(source_score, 1),
            "topic": round(topic_score, 1),
            "density": round(density_score, 1),
            "novelty": round(novelty_score, 1),
            "writability": round(writability_score, 1),
        },
        "reasons": reasons[:5],
        "penalties": penalties[:4],
        "brief_score": brief_score["score"],
        "brief_hits": brief_score["hits"],
        "source_stats": {
            "accepted": int(stat.get("accepted", 0) or 0),
            "rejected": int(stat.get("rejected", 0) or 0),
            "generated": int(stat.get("generated", 0) or 0),
            "trust_adjust": round(float(stat.get("trust_adjust", 0) or 0), 2),
        },
    }

def _quality_store_score(conn, article_id: str, quality: dict):
    dims = quality["dims"]
    conn.execute(
        """
        INSERT INTO quality_scores
        (article_id, total, level, source_score, topic_score, density_score, novelty_score,
         writability_score, reasons_json, penalties_json, scored_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(article_id) DO UPDATE SET
            total=excluded.total,
            level=excluded.level,
            source_score=excluded.source_score,
            topic_score=excluded.topic_score,
            density_score=excluded.density_score,
            novelty_score=excluded.novelty_score,
            writability_score=excluded.writability_score,
            reasons_json=excluded.reasons_json,
            penalties_json=excluded.penalties_json,
            scored_at=excluded.scored_at
        """,
        (
            article_id, quality["total"], quality["level"], dims["source"], dims["topic"],
            dims["density"], dims["novelty"], dims["writability"],
            _json_dumps(quality["reasons"]), _json_dumps(quality["penalties"]), _quality_now(),
        ),
    )

def select_quality_candidates(limit: int = 10, min_level: str = "A",
                              include_prc: bool = False) -> tuple[list, dict]:
    """从当前RSS缓存中选择精品候选，并将评分快照写入本地训练库。"""
    init_quality_db()
    limit = max(1, int(limit or 10))
    min_level = (min_level or "A").upper()
    prc_state_sources = {f["name"] for f in RSS_FEEDS if f.get("is_prc_state")}
    with cache_lock:
        news = list(cache["news"])

    candidates, level_counts = [], {"S": 0, "A": 0, "B": 0, "C": 0, "D": 0}
    with _QUALITY_DB_LOCK, _quality_connect() as conn:
        source_stats = _quality_load_source_stats(conn)
        for art in news:
            if not include_prc and art.get("source") in prc_state_sources:
                continue
            article_id = _quality_upsert_article(conn, art)
            feedback_counts = _quality_feedback_counts(conn, article_id)
            quality = score_quality_candidate(art, source_stats=source_stats, feedback_counts=feedback_counts)
            _quality_store_score(conn, article_id, quality)
            level_counts[quality["level"]] += 1
            if _quality_level_allowed(quality["level"], min_level):
                enriched = {
                    **art,
                    "article_id": article_id,
                    "quality": quality,
                    "quality_score": quality["total"],
                    "quality_level": quality["level"],
                    "quality_reasons": quality["reasons"],
                    "quality_penalties": quality["penalties"],
                    "brief_score": quality["brief_score"],
                    "brief_hits": quality["brief_hits"],
                }
                candidates.append(enriched)
        conn.commit()
    candidates.sort(key=lambda a: (a.get("quality_score", 0), a.get("brief_score", 0)), reverse=True)
    meta = {
        "total_scored": sum(level_counts.values()),
        "level_counts": level_counts,
        "min_level": min_level,
        "limit": limit,
    }
    return candidates[:limit], meta

def retrain_quality_preferences() -> dict:
    """基于人工反馈重算信源偏好权重。v1 不请求外部服务。"""
    init_quality_db()
    with _QUALITY_DB_LOCK, _quality_connect() as conn:
        rows = conn.execute(
            """
            SELECT a.source, f.label, COUNT(*) AS cnt
            FROM quality_feedback f
            JOIN quality_articles a ON a.article_id = f.article_id
            GROUP BY a.source, f.label
            """
        ).fetchall()
        stats = {}
        for r in rows:
            src = r["source"] or "unknown"
            stats.setdefault(src, {"accepted": 0, "skipped": 0, "rejected": 0, "generated": 0, "discarded": 0})
            stats[src][r["label"]] = int(r["cnt"])
        for src, s in stats.items():
            total = sum(s.values()) or 1
            positive = s["accepted"] * 2.0 + s["generated"] * 1.5
            negative = s["rejected"] * 2.0 + s["discarded"] * 2.0 + s["skipped"] * 0.5
            adjust = round(_clamp(((positive - negative) / total) * 5, -5, 5), 2)
            conn.execute(
                """
                INSERT INTO quality_source_stats
                (source, accepted, skipped, rejected, generated, discarded, trust_adjust, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source) DO UPDATE SET
                    accepted=excluded.accepted,
                    skipped=excluded.skipped,
                    rejected=excluded.rejected,
                    generated=excluded.generated,
                    discarded=excluded.discarded,
                    trust_adjust=excluded.trust_adjust,
                    updated_at=excluded.updated_at
                """,
                (src, s["accepted"], s["skipped"], s["rejected"], s["generated"],
                 s["discarded"], adjust, _quality_now()),
            )
        conn.commit()
    return {"sources": len(stats), "feedback": sum(sum(s.values()) for s in stats.values())}

def record_quality_feedback(article_id: str | None, label: str, reason_codes=None,
                            note: str = "", article: dict | None = None) -> dict:
    label = (label or "").strip()
    if label not in _QUALITY_FEEDBACK_LABELS:
        raise ValueError("无效反馈类型")
    reason_codes = reason_codes or []
    if article:
        article_id = article_id or _article_id(article)
    if not article_id:
        raise ValueError("缺少 article_id")
    init_quality_db()
    with _QUALITY_DB_LOCK, _quality_connect() as conn:
        if article:
            article_id = _quality_upsert_article(conn, article)
        elif not conn.execute("SELECT 1 FROM quality_articles WHERE article_id=?", (article_id,)).fetchone():
            raise ValueError("未知文章，请随反馈提交 article")
        conn.execute(
            "INSERT INTO quality_feedback(article_id, label, reason_codes_json, note, created_at) VALUES (?, ?, ?, ?, ?)",
            (article_id, label, _json_dumps(reason_codes), (note or "")[:500], _quality_now()),
        )
        conn.commit()
    stats = retrain_quality_preferences()
    return {"article_id": article_id, "label": label, **stats}

def record_quality_generation(article: dict, brief_text: str, validation: dict | None,
                              status: str = "generated") -> str:
    init_quality_db()
    with _QUALITY_DB_LOCK, _quality_connect() as conn:
        article_id = _quality_upsert_article(conn, article)
        conn.execute(
            "INSERT INTO quality_generations(article_id, brief_chars, validation_json, status, created_at) VALUES (?, ?, ?, ?, ?)",
            (
                article_id,
                len(brief_text or ""),
                _json_dumps(validation or {}),
                status,
                _quality_now(),
            ),
        )
        conn.execute(
            "INSERT INTO quality_feedback(article_id, label, reason_codes_json, note, created_at) VALUES (?, ?, ?, ?, ?)",
            (article_id, "generated", _json_dumps(["auto_generated"]), "自动记录：要讯生成成功", _quality_now()),
        )
        conn.commit()
    retrain_quality_preferences()
    return article_id

def select_brief_candidates(top_n: int = 15, include_prc: bool = False) -> list:
    """选择适合写要讯的候选文章
    include_prc: 是否包含中国官媒源（默认否，避免把官媒宣传写成境外情报）
    """
    candidates, _ = select_quality_candidates(limit=top_n, min_level="A", include_prc=include_prc)
    return candidates

# ── 复刻 app.py 原运行时影子：score_quality_candidate 实际解析到的 _quality_level
# 是 consult 段的 90/80/70 版（见模块 docstring）。这里以同逻辑覆盖上方历史死定义，
# 确保拆分后本模块内的 _quality_level 行为与拆分前运行时完全一致。
def _quality_level(score: int) -> str:
    if score >= 90:
        return "S"
    if score >= 80:
        return "A"
    if score >= 70:
        return "B"
    return "C"

# ══ 选题查重：近 N 天已生成要讯的标题相似度（防连续两天写同一题）══
def _title_tokens(title: str) -> set:
    """标题分词：拉丁词 + 中文 bigram。"""
    t = (title or '').lower()
    latin = set(re.findall(r"[a-z0-9][a-z0-9'-]+", t))
    han = re.findall(r'[一-鿿]', t)
    bigrams = {han[i] + han[i+1] for i in range(len(han) - 1)}
    return latin | bigrams


def find_similar_generations(title: str, days: int = 7, limit: int = 3,
                             threshold: float = 0.42) -> list:
    """返回近 days 天生成记录里与 title 相似度 >= threshold 的选题（Jaccard）。"""
    tokens = _title_tokens(title)
    if not tokens:
        return []
    init_quality_db()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with _QUALITY_DB_LOCK, _quality_connect() as conn:
        rows = conn.execute(
            """SELECT a.title AS title, MAX(g.created_at) AS created_at
               FROM quality_generations g
               JOIN quality_articles a ON a.article_id = g.article_id
               WHERE g.created_at >= ?
               GROUP BY a.title""", (cutoff,)).fetchall()
    out = []
    for r in rows:
        other = _title_tokens(r['title'])
        if not other:
            continue
        j = len(tokens & other) / len(tokens | other)
        if j >= threshold:
            out.append({'title': r['title'], 'created_at': r['created_at'],
                        'similarity': round(j, 2)})
    out.sort(key=lambda x: -x['similarity'])
    return out[:limit]
