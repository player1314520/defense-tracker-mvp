"""Transparent source-signal indices for the V9 situation overview."""
from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Iterable


REGIONS = (
    {
        "id": "taiwan",
        "name": "台湾",
        "name_en": "TAIWAN STRAIT",
        "class_name": "danger",
        "terms": ("台湾", "台海", "taiwan", "strait"),
        "focus": ("china", "taiwan"),
    },
    {
        "id": "west_pacific",
        "name": "西太平洋",
        "name_en": "W. PACIFIC",
        "class_name": "watch",
        "terms": (
            "西太",
            "太平洋",
            "日本",
            "菲律宾",
            "关岛",
            "pacific",
            "japan",
            "philipp",
            "guam",
            "carrier",
        ),
        "focus": ("japan", "navy", "usa"),
    },
    {
        "id": "indo_pacific",
        "name": "印太整体",
        "name_en": "INDO-PACIFIC",
        "class_name": "watch",
        "terms": (
            "印太",
            "亚太",
            "印度洋",
            "indo-pacific",
            "asia-pacific",
            "alliance",
            "australia",
        ),
        "focus": ("china", "japan", "usa", "india", "australia"),
    },
    {
        "id": "space_ems",
        "name": "空天电磁",
        "name_en": "SPACE / EMS",
        "class_name": "space",
        "terms": (
            "太空",
            "卫星",
            "电磁",
            "电子战",
            "网络",
            "pnt",
            "space",
            "satellite",
            "electromagnetic",
            "electronic warfare",
            "cyber",
        ),
        "focus": ("space", "cyber", "air"),
    },
)


def _parse_datetime(value) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value or "").strip()
        if not text:
            return None
        parsed = None
        for parser in (
            lambda: datetime.fromisoformat(text.replace("Z", "+00:00")),
            lambda: datetime.strptime(text, "%Y/%m/%d %H:%M:%S"),
            lambda: datetime.strptime(text, "%Y-%m-%d %H:%M:%S"),
        ):
            try:
                parsed = parser()
                break
            except ValueError:
                continue
        if parsed is None:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _stars(article: dict) -> float:
    priority = article.get("priority") or {}
    try:
        return max(0.0, min(10.0, float(priority.get("stars") or 0)))
    except (TypeError, ValueError):
        return 0.0


def _source_weight(article: dict) -> float:
    try:
        tier = int(article.get("tier") or 3)
    except (TypeError, ValueError):
        tier = 3
    return 1.0 if tier <= 1 else 0.82 if tier == 2 else 0.65


def _topic_key(article: dict) -> str:
    text = f"{article.get('title', '')} {article.get('summary', '')}".lower()
    topics = (
        ("taiwan", ("台湾", "台海", "taiwan", "strait")),
        ("carrier", ("航母", "舰艇", "carrier", "navy", "fleet")),
        ("space", ("太空", "卫星", "space", "satellite", "pnt")),
        ("cyber", ("网络", "电磁", "电子战", "cyber", "electromagnetic")),
        ("missile", ("导弹", "火箭", "missile", "rocket")),
    )
    for key, terms in topics:
        if any(term in text for term in terms):
            return key
    words = re.findall(r"[a-z]{4,}|[\u4e00-\u9fff]{2,}", text)
    return words[0] if words else "general"


def _matches(article: dict, region: dict) -> bool:
    text = " ".join(
        str(article.get(key) or "")
        for key in ("title", "summary", "region", "region_en", "focus")
    ).lower()
    focus = str(article.get("focus") or "").lower()
    return any(term in text for term in region["terms"]) or focus in region["focus"]


def _age_label(hours: float) -> str:
    if hours < 1:
        return "即时"
    if hours < 24:
        return f"{max(1, int(hours))}小时前"
    return f"{max(1, int(hours // 24))}天前"


def calculate_situation(
    articles: Iterable[dict], *, now: datetime | None = None
) -> dict:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    prepared = []
    for article in articles:
        published_at = _parse_datetime(article.get("date"))
        if published_at is None:
            continue
        age_hours = max(0.0, (now - published_at).total_seconds() / 3600)
        if age_hours > 72:
            continue
        item = dict(article)
        item["_published_at"] = published_at
        item["_age_hours"] = age_hours
        item["_topic"] = _topic_key(item)
        prepared.append(item)

    topic_sources: dict[str, set[str]] = {}
    for article in prepared:
        topic_sources.setdefault(article["_topic"], set()).add(
            str(article.get("source") or "未知来源")
        )

    regions = []
    for definition in REGIONS:
        matches = [item for item in prepared if _matches(item, definition)]
        sources = {str(item.get("source") or "未知来源") for item in matches}
        evidence = []
        raw_signal = 0.0
        for article in matches:
            source_weight = _source_weight(article)
            time_decay = math.exp(-article["_age_hours"] / 36.0)
            priority_factor = 0.4 + 0.6 * (_stars(article) / 10.0)
            corroboration = min(
                1.3,
                1.0 + 0.1 * (len(topic_sources[article["_topic"]]) - 1),
            )
            contribution = (
                source_weight * time_decay * priority_factor * corroboration
            )
            raw_signal += contribution
            evidence.append(
                {
                    "article_id": str(
                        article.get("aid") or article.get("link") or ""
                    ),
                    "title": str(article.get("title") or "无标题"),
                    "source": str(article.get("source") or "未知来源"),
                    "url": str(article.get("link") or ""),
                    "published_at": article["_published_at"].isoformat(),
                    "components": {
                        "source_weight": round(source_weight, 4),
                        "time_decay": round(time_decay, 4),
                        "priority_factor": round(priority_factor, 4),
                        "corroboration_factor": round(corroboration, 4),
                        "contribution": round(contribution, 4),
                    },
                }
            )
        evidence.sort(
            key=lambda item: item["components"]["contribution"], reverse=True
        )
        ready = len(evidence) >= 3 and len(sources) >= 2
        score = (
            min(100, round(100 * (1 - math.exp(-raw_signal / 3.8))))
            if ready
            else None
        )
        regions.append(
            {
                "id": definition["id"],
                "name": definition["name"],
                "name_en": definition["name_en"],
                "class_name": definition["class_name"],
                "status": "ready" if ready else "insufficient",
                "label": "态势指数" if ready else "证据不足",
                "score": score,
                "delta": None,
                "evidence_count": len(evidence),
                "source_count": len(sources),
                "updated_at": max(
                    (item["published_at"] for item in evidence), default=None
                ),
                "headline": evidence[0]["title"] if evidence else "暂无可追溯信号",
                "evidence": evidence[:12],
                "formula": {
                    "name": "signal_strength_v1",
                    "source_weight": "tier1=1.00, tier2=0.82, other=0.65",
                    "time_decay": "exp(-age_hours/36)",
                    "priority_factor": "0.4 + 0.6 × stars/10",
                    "corroboration": "每增加一个独立同主题来源 +10%，上限 1.30",
                    "score": "100 × (1 - exp(-signal/3.8))",
                    "minimum_evidence": "至少3条证据且2个独立来源",
                },
            }
        )

    wire = sorted(
        prepared,
        key=lambda item: (
            _stars(item),
            -item["_age_hours"],
            str(item.get("aid") or ""),
        ),
        reverse=True,
    )[:3]
    return {
        "generated_at": now.isoformat(),
        "window_hours": 72,
        "regions": regions,
        "wire": [
            {
                "article_id": str(item.get("aid") or item.get("link") or ""),
                "title": str(item.get("title") or "无标题"),
                "source": str(item.get("source") or "未知来源"),
                "url": str(item.get("link") or ""),
                "priority": _stars(item),
                "age_label": _age_label(item["_age_hours"]),
            }
            for item in wire
        ],
    }
