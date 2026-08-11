# -*- coding: utf-8 -*-
from datetime import datetime, timezone


NOW = datetime(2026, 7, 25, 10, 0, tzinfo=timezone.utc)


def _article(aid, title, source, *, hours_ago, stars=7, tier=1, region="🇹🇼 台湾"):
    published = NOW.timestamp() - hours_ago * 3600
    return {
        "aid": aid,
        "title": title,
        "source": source,
        "link": f"https://example.test/{aid}",
        "date": datetime.fromtimestamp(published, timezone.utc).isoformat(),
        "priority": {"stars": stars, "score_raw": stars},
        "tier": tier,
        "region": region,
        "focus": "china",
        "summary": "source-backed summary",
    }


def test_situation_index_is_source_traceable_and_deterministic():
    from v9.situation import calculate_situation

    articles = [
        _article("a1", "台海联合演训频度上升", "Source A", hours_ago=2, stars=9),
        _article("a2", "台湾周边海空活动更新", "Source B", hours_ago=7, stars=7),
        _article("a3", "台海后勤保障动向", "Source C", hours_ago=18, stars=6),
    ]
    result = calculate_situation(articles, now=NOW)
    taiwan = next(item for item in result["regions"] if item["id"] == "taiwan")

    assert taiwan["status"] == "ready"
    assert 0 <= taiwan["score"] <= 100
    assert taiwan["evidence_count"] == 3
    assert taiwan["source_count"] == 3
    assert taiwan["updated_at"]
    assert taiwan["formula"]["name"] == "signal_strength_v1"
    assert all(
        {"source_weight", "time_decay", "priority_factor", "contribution"}
        <= set(item["components"])
        for item in taiwan["evidence"]
    )
    assert calculate_situation(articles, now=NOW)["regions"] == result["regions"]


def test_situation_shows_insufficient_evidence_instead_of_fake_score():
    from v9.situation import calculate_situation

    result = calculate_situation(
        [_article("a1", "台海单一消息", "Only Source", hours_ago=1)],
        now=NOW,
    )
    taiwan = next(item for item in result["regions"] if item["id"] == "taiwan")

    assert taiwan["status"] == "insufficient"
    assert taiwan["score"] is None
    assert taiwan["label"] == "证据不足"
    assert taiwan["evidence_count"] == 1


def test_wire_uses_real_high_priority_articles():
    from v9.situation import calculate_situation

    articles = [
        _article("low", "低优先消息", "A", hours_ago=1, stars=2),
        _article("high", "高优先消息", "B", hours_ago=5, stars=9),
        _article("mid", "中优先消息", "C", hours_ago=2, stars=6),
    ]
    result = calculate_situation(articles, now=NOW)

    assert result["wire"][0]["article_id"] == "high"
    assert {item["article_id"] for item in result["wire"]} <= {
        "low",
        "mid",
        "high",
    }
