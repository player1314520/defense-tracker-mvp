from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable


SEVERITIES = {"low", "medium", "high", "critical"}


def _parse_datetime(value) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _unique_text(values, *, lowercase: bool = False) -> list[str]:
    if isinstance(values, str):
        values = [values]
    result = []
    seen = set()
    for value in values or []:
        text = str(value or "").strip()
        if lowercase:
            text = text.lower()
        marker = text.casefold()
        if text and marker not in seen:
            result.append(text)
            seen.add(marker)
    return result


def normalize_alert_rule(value: dict) -> dict:
    name = str(value.get("name") or "").strip()
    keywords = _unique_text(value.get("keywords"), lowercase=True)
    if not name:
        raise ValueError("规则名称不能为空")
    if not keywords:
        raise ValueError("至少需要一个关键词")
    min_stars = int(value.get("min_stars", 0))
    if not 0 <= min_stars <= 10:
        raise ValueError("最低星级必须在 0 到 10 之间")
    severity = str(value.get("severity") or "medium").strip().lower()
    if severity not in SEVERITIES:
        raise ValueError("无效严重度")
    return {
        "name": name[:80],
        "enabled": bool(value.get("enabled", True)),
        "keywords": keywords[:30],
        "min_stars": min_stars,
        "sources": _unique_text(value.get("sources"))[:30],
        "severity": severity,
    }


def evaluate_alert_rules(
    rules: Iterable[dict],
    articles: Iterable[dict],
    *,
    now: datetime | None = None,
) -> dict:
    now_utc = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    end_hour = now_utc.replace(minute=0, second=0, microsecond=0)
    start_hour = end_hour - timedelta(hours=23)
    rhythm = [
        {
            "hour": (start_hour + timedelta(hours=offset)).isoformat(),
            "count": 0,
        }
        for offset in range(24)
    ]
    normalized = []
    for raw in rules:
        try:
            normalized.append(
                {
                    **normalize_alert_rule(raw.get("content", raw)),
                    "record_id": raw.get("record_id"),
                }
            )
        except (TypeError, ValueError):
            continue

    hits = []
    for article in articles:
        published = _parse_datetime(article.get("date"))
        if published is None or published < start_hour or published > now_utc:
            continue
        haystack = " ".join(
            str(article.get(key) or "") for key in ("title", "summary")
        ).lower()
        source = str(
            article.get("source_cn") or article.get("source") or ""
        ).strip()
        stars = int((article.get("priority") or {}).get("stars") or 0)
        for rule in normalized:
            if not rule["enabled"] or stars < rule["min_stars"]:
                continue
            if rule["sources"] and source.casefold() not in {
                item.casefold() for item in rule["sources"]
            }:
                continue
            matched = [word for word in rule["keywords"] if word in haystack]
            if not matched:
                continue
            bucket = int((published.replace(minute=0, second=0, microsecond=0) - start_hour).total_seconds() // 3600)
            if 0 <= bucket < 24:
                rhythm[bucket]["count"] += 1
            hits.append(
                {
                    "article_id": str(
                        article.get("aid") or article.get("link") or ""
                    ),
                    "title": str(article.get("title") or "无标题"),
                    "source": source,
                    "published_at": published.isoformat(),
                    "rule_id": rule["record_id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "matched_keywords": matched,
                }
            )
    hits.sort(key=lambda item: item["published_at"], reverse=True)
    return {"total_hits": len(hits), "hits": hits, "rhythm": rhythm}
