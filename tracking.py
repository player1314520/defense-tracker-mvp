# -*- coding: utf-8 -*-
"""追踪清单（Watchlist）：用户自定义关键词/主题 → Supabase 持久化 + 新闻缓存匹配。

数据流：前端 → 本地 Flask (/api/tracking/*) → requests → Supabase PostgREST(HTTPS)。
- 前端从不直连 Supabase：CSP connect-src 只放行 'self'，且密钥只留服务端。
- Supabase 未配置 / 连不上时整个蓝图优雅降级（503 + 明确文案），不影响 app 其它功能。

表结构（见 Supabase migration create_tracking_watchlist）：
  tracked_topics(id, label, keywords[], match_mode, notes, enabled, created_at, updated_at)
  tracked_hits(id, topic_id, article_id, title, source, link, published_at, starred, created_at)

本模块只依赖 state（叶子模块）+ requests + flask，绝不 import app（避免循环 import）。
鉴权走蓝图 before_request 注入回调 `_auth_check`（由 app.py 在注册时塞入）。
"""
import os
import re
import json
import logging

import requests
from flask import Blueprint, request, jsonify

from state import CONFIG_DIR, cache, cache_lock

logger = logging.getLogger(__name__)

tracking_bp = Blueprint("tracking", __name__)

# ── 鉴权注入点：app.py 注册蓝图后设置 tracking._auth_check = <callable>
# 约定：返回 Response 表示拦截（未授权/限流/CSRF 失败），返回 None 表示放行。
_auth_check = None


@tracking_bp.before_request
def _tracking_before():
    if _auth_check is not None:
        resp = _auth_check()
        if resp is not None:
            return resp
    return None


# ══════════════════════════════════════════════════════════════
# Supabase 配置：URL + anon key，存本地 .supabase_config.json（已 gitignore）
# 与 .ai_config.json / .search_config.json 同目录、同「本地私有」定位。
# anon key 是客户端密钥（受 RLS 约束），此处只在服务端使用、不下发浏览器。
# ══════════════════════════════════════════════════════════════
_SB_CONFIG_FILE = os.path.join(CONFIG_DIR, ".supabase_config.json")
_SB = {"url": "", "key": ""}


def _load_supabase_config() -> dict:
    cfg = {
        "url": os.environ.get("SUPABASE_URL", "").strip(),
        "key": os.environ.get("SUPABASE_ANON_KEY", "").strip(),
    }
    if os.path.exists(_SB_CONFIG_FILE):
        try:
            saved = json.load(open(_SB_CONFIG_FILE, encoding="utf-8"))
            for k in ("url", "key"):
                if saved.get(k):
                    cfg[k] = str(saved[k]).strip()
        except Exception as e:
            logger.warning("加载 Supabase 配置失败: %s", e)
    _SB.update(cfg)
    return cfg


_load_supabase_config()


def _sb_ready() -> bool:
    return bool(_SB.get("url") and _SB.get("key"))


def _sb_rest(method: str, path: str, *, params=None, json_body=None,
             prefer: str | None = None, timeout=(6, 15)):
    """薄封装 Supabase PostgREST。抛 requests 异常给上层 _guard 转 503。

    timeout=(连接6s, 读15s)：us-west-2 + GFW 环境下连接偶发超时。ConnectionError /
    ConnectTimeout 表示请求尚未到达服务端 → 安全重试一次（不会重复写入非幂等 POST）；
    ReadTimeout 不重试（请求可能已被处理，重试有重复写入风险）。
    """
    url = _SB["url"].rstrip("/") + "/rest/v1/" + path.lstrip("/")
    headers = {
        "apikey": _SB["key"],
        "Authorization": "Bearer " + _SB["key"],
        "Content-Type": "application/json",
    }
    if prefer:
        headers["Prefer"] = prefer
    last_exc = None
    for _attempt in range(2):  # 首次 + 1 次重试，仅针对连接层错误
        try:
            return requests.request(method, url, headers=headers, params=params,
                                    json=json_body, timeout=timeout)
        except requests.exceptions.ConnectionError as e:  # 含 ConnectTimeout（其子类）
            last_exc = e
            continue
    raise last_exc


def _guard(fn):
    """未配置 → 503 supabase_unconfigured；网络/服务不可达 → 503 supabase_unreachable。"""
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not _sb_ready():
            return jsonify({
                "error": "云端追踪未配置",
                "code": "supabase_unconfigured",
                "hint": "在 .supabase_config.json 填 {url, key}，或设环境变量 SUPABASE_URL / SUPABASE_ANON_KEY",
            }), 503
        try:
            return fn(*args, **kwargs)
        except requests.exceptions.RequestException as e:
            logger.warning("Supabase 请求失败 (%s)", type(e).__name__)
            return jsonify({"error": "云端追踪暂不可达（网络或 Supabase 异常）",
                            "code": "supabase_unreachable"}), 503

    return wrapper


# ══════════════════════════════════════════════════════════════
# 匹配逻辑 —— 判断一条新闻是否命中某个追踪主题。
#
# ┌─────────────────────────────────────────────────────────────┐
# │ 这里是「业务逻辑决策点」，有多种合理做法，欢迎按你的领域直觉改写： │
# │  · 搜哪些字段？（标题权重更高？要不要搜 source_cn？）           │
# │  · 关键词是 any(任一命中) 还是 all(全部命中)？（现按 topic.match_mode）│
# │  · 子串匹配 vs 词边界匹配？中文没有空格，子串更实用；英文可加边界。 │
# │  · 要不要打分排序，而不是布尔命中？                            │
# └─────────────────────────────────────────────────────────────┘
# 当前实现：词边界(英文)/子串(中文) + 标题加权打分 + any/all，命中结果按相关度排序。
# 想再调（同义词、词干、字段权重）就改 _term_matches / _FIELD_WEIGHTS / _match_score。
# ══════════════════════════════════════════════════════════════
_FIELD_WEIGHTS = (("title", 3), ("summary", 1), ("source_cn", 1), ("source", 1))


def _term_matches(term: str, text: str) -> bool:
    """单个关键词是否命中文本。
    · 纯 ASCII 字母数字词 → 词边界匹配（'US' 不会误命中 'focus'，大小写不敏感）
    · 含中文/连字符/空格的词（如 '台海'、'F-35'）→ 大小写不敏感子串（中文无词边界）
    """
    term = term.strip()
    if not term:
        return False
    if term.isascii() and term.replace(" ", "").isalnum():
        return re.search(r"\b" + re.escape(term) + r"\b", text, re.IGNORECASE) is not None
    return term.lower() in text.lower()


# 同义词组：组内任一词命中即视为整组命中（默认两个明显翻译对示例，按需增删/清空）。
# 只放严格等价的词——塞近义/相关词会放大误命中。用户扩展就改这个列表。
_SYNONYM_GROUPS = [
    {"台海", "台湾海峡", "Taiwan Strait"},
    {"高超音速", "hypersonic"},
]
_SYN_INDEX = {w.lower(): g for g in _SYNONYM_GROUPS for w in g}


def _synonyms(term: str) -> list:
    """返回该词的同义词组（含自身）；不在任何组则只返回自身。"""
    grp = _SYN_INDEX.get(term.strip().lower())
    return list(grp) if grp else [term]


def _match_score(topic: dict, article: dict) -> int:
    """命中打分（0=未命中）：标题命中权重(3) > 摘要/来源(1)，用于相关度排序。
    每个关键词连同其同义词组一起匹配（组内任一命中即算该词命中）。
    match_mode='all' 要求每个关键词都至少命中；'any' 任一命中即可。
    """
    keywords = [k.strip() for k in (topic.get("keywords") or []) if k and k.strip()]
    if not keywords:
        return 0
    fields = [(str(article.get(f) or ""), w) for f, w in _FIELD_WEIGHTS]
    per_kw = []  # 每个关键词命中到的最高字段权重（0=该词未命中）
    for kw in keywords:
        terms = _synonyms(kw)
        best = 0
        for text, w in fields:
            if text and any(_term_matches(t, text) for t in terms):
                best = max(best, w)
        per_kw.append(best)
    hits = sum(1 for s in per_kw if s > 0)
    if (topic.get("match_mode") or "any") == "all":
        if hits < len(keywords):
            return 0
    elif hits == 0:
        return 0
    return sum(per_kw)


def topic_matches_article(topic: dict, article: dict) -> bool:
    """是否命中（供列表命中计数 / 过滤用）。"""
    return _match_score(topic, article) > 0


def _news_snapshot() -> list:
    """线程安全地取一份当前新闻缓存的浅拷贝。"""
    with cache_lock:
        return list(cache.get("news") or [])


def _match_articles(topic: dict) -> list:
    """返回命中该 topic 的文章（按相关度分 → 日期倒序），字段裁剪为前端所需。"""
    scored = []
    for a in _news_snapshot():
        s = _match_score(topic, a)
        if s > 0:
            scored.append((s, a))
    scored.sort(key=lambda t: (t[0], str(t[1].get("date") or "")), reverse=True)
    out = []
    for score, a in scored:
        link = a.get("link") or ""
        out.append({
            "article_id": a.get("aid") or link,  # canonical aid 优先（三端稳定身份）
            "title": a.get("title") or "",
            "summary": a.get("summary") or "",
            "source": a.get("source") or "",
            "source_cn": a.get("source_cn") or "",
            "link": link,
            "date": a.get("date") or "",
            "tier": a.get("tier"),
            "score": score,                     # 相关度分（标题命中更高），前端可选用
        })
    return out


# ── 输入清洗 ──────────────────────────────────────────────────
def _clean_topic_payload(body: dict, *, partial: bool = False) -> dict:
    """校验/规整前端传入的 topic 字段。partial=True 用于 PATCH（只取存在的字段）。"""
    out = {}
    if "label" in body or not partial:
        label = str(body.get("label") or "").strip()
        if not label:
            raise ValueError("label 不能为空")
        out["label"] = label[:120]
    if "keywords" in body or not partial:
        kws_raw = body.get("keywords") or []
        if isinstance(kws_raw, str):
            kws_raw = [p for p in kws_raw.replace("，", ",").split(",")]
        keywords = []
        for k in kws_raw:
            k = str(k).strip()
            if k and k not in keywords:
                keywords.append(k[:60])
        out["keywords"] = keywords[:40]
    if "match_mode" in body:
        out["match_mode"] = "all" if str(body.get("match_mode")).lower() == "all" else "any"
    if "notes" in body:
        out["notes"] = str(body.get("notes") or "")[:2000]
    if "enabled" in body:
        out["enabled"] = bool(body.get("enabled"))
    return out


# ══════════════════════════════════════════════════════════════
# 路由
# ══════════════════════════════════════════════════════════════
@tracking_bp.route("/api/tracking/status", methods=["GET"])
def tracking_status():
    """给前端判断该面板可用性；未配置时也返回 200（前端据此显示配置提示）。"""
    if not _sb_ready():
        return jsonify({"configured": False, "reachable": False})
    reachable = True
    detail = ""
    code = ""
    try:
        r = _sb_rest("GET", "tracked_topics", params={"select": "id", "limit": "1"}, timeout=8)
        reachable = r.ok
        if not r.ok:
            detail = f"HTTP {r.status_code}"
    except requests.exceptions.RequestException as e:
        reachable = False
        detail = "云端追踪暂不可达"
        code = "supabase_unreachable"
        logger.warning("Supabase 状态探测失败 (%s)", type(e).__name__)
    payload = {"configured": True, "reachable": reachable, "detail": detail}
    if code:
        payload["code"] = code
    return jsonify(payload)


@tracking_bp.route("/api/tracking/topics", methods=["GET"])
@_guard
def list_topics():
    r = _sb_rest("GET", "tracked_topics",
                 params={"select": "*", "order": "created_at.desc"})
    if not r.ok:
        return jsonify({"error": "读取追踪清单失败", "detail": r.text[:300]}), 502
    topics = r.json()
    news = _news_snapshot()
    # 每个 topic 计算实时命中数（缓存 ≤500 条，topic 通常个位数，成本可接受）
    for t in topics:
        t["match_count"] = sum(1 for a in news if topic_matches_article(t, a))
    return jsonify({"topics": topics, "news_total": len(news)})


@tracking_bp.route("/api/tracking/starred", methods=["GET"])
@_guard
def list_starred():
    """跨所有追踪项列出已收藏(star)的文章，附所属追踪项名称。"""
    r = _sb_rest("GET", "tracked_hits",
                 params={"starred": "eq.true",
                         "select": "*,topic:tracked_topics(label)",
                         "order": "created_at.desc"})
    if not r.ok:
        return jsonify({"error": "读取收藏失败", "detail": r.text[:300]}), 502
    return jsonify({"starred": r.json()})


@tracking_bp.route("/api/tracking/topics", methods=["POST"])
@_guard
def create_topic():
    try:
        payload = _clean_topic_payload(request.get_json(force=True, silent=True) or {})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    r = _sb_rest("POST", "tracked_topics", json_body=payload, prefer="return=representation")
    if not r.ok:
        return jsonify({"error": "创建失败", "detail": r.text[:300]}), 502
    row = r.json()[0] if r.json() else payload
    row["match_count"] = sum(1 for a in _news_snapshot() if topic_matches_article(row, a))
    return jsonify({"topic": row}), 201


@tracking_bp.route("/api/tracking/topics/<tid>", methods=["PATCH"])
@_guard
def update_topic(tid):
    try:
        payload = _clean_topic_payload(request.get_json(force=True, silent=True) or {}, partial=True)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if not payload:
        return jsonify({"error": "无可更新字段"}), 400
    r = _sb_rest("PATCH", "tracked_topics", params={"id": f"eq.{tid}"},
                 json_body=payload, prefer="return=representation")
    if not r.ok:
        return jsonify({"error": "更新失败", "detail": r.text[:300]}), 502
    rows = r.json()
    if not rows:
        return jsonify({"error": "未找到该追踪项"}), 404
    return jsonify({"topic": rows[0]})


@tracking_bp.route("/api/tracking/topics/<tid>", methods=["DELETE"])
@_guard
def delete_topic(tid):
    r = _sb_rest("DELETE", "tracked_topics", params={"id": f"eq.{tid}"},
                 prefer="return=representation")
    if not r.ok:
        return jsonify({"error": "删除失败", "detail": r.text[:300]}), 502
    return jsonify({"deleted": len(r.json() or [])})


@tracking_bp.route("/api/tracking/topics/<tid>/matches", methods=["GET"])
@_guard
def topic_matches(tid):
    r = _sb_rest("GET", "tracked_topics", params={"id": f"eq.{tid}", "select": "*"})
    if not r.ok:
        return jsonify({"error": "读取追踪项失败", "detail": r.text[:300]}), 502
    rows = r.json()
    if not rows:
        return jsonify({"error": "未找到该追踪项"}), 404
    topic = rows[0]
    matches = _match_articles(topic)
    # 标记哪些文章已被用户 star（持久化在 tracked_hits）
    hr = _sb_rest("GET", "tracked_hits",
                  params={"topic_id": f"eq.{tid}", "starred": "eq.true", "select": "article_id"})
    starred_ids = {h["article_id"] for h in hr.json()} if hr.ok else set()
    for m in matches:
        m["starred"] = m["article_id"] in starred_ids
    return jsonify({"topic": topic, "matches": matches, "count": len(matches)})


@tracking_bp.route("/api/tracking/topics/<tid>/star", methods=["POST"])
@_guard
def star_hit(tid):
    body = request.get_json(force=True, silent=True) or {}
    starred = bool(body.get("starred", True))
    art = body.get("article") or {}
    article_id = str(art.get("article_id") or art.get("aid") or art.get("link") or "").strip()
    if not article_id:
        return jsonify({"error": "缺少 article_id/link"}), 400
    if not starred:
        r = _sb_rest("DELETE", "tracked_hits",
                     params={"topic_id": f"eq.{tid}", "article_id": f"eq.{article_id}"})
        if not r.ok:
            return jsonify({"error": "取消收藏失败", "detail": r.text[:300]}), 502
        return jsonify({"starred": False})
    row = {
        "topic_id": tid,
        "article_id": article_id,
        "title": str(art.get("title") or "")[:500],
        "source": str(art.get("source") or "")[:200],
        "link": str(art.get("link") or article_id)[:1000],
        "published_at": str(art.get("date") or "")[:64],
        "starred": True,
    }
    # upsert：唯一约束 (topic_id, article_id)，冲突则合并
    r = _sb_rest("POST", "tracked_hits", json_body=row,
                 prefer="resolution=merge-duplicates,return=representation")
    if not r.ok:
        return jsonify({"error": "收藏失败", "detail": r.text[:300]}), 502
    return jsonify({"starred": True})
