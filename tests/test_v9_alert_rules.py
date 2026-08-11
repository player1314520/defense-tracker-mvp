# -*- coding: utf-8 -*-
from datetime import datetime, timezone


def test_alert_rule_normalization_and_matching_builds_24h_rhythm():
    from v9.alerts import evaluate_alert_rules, normalize_alert_rule

    rule = normalize_alert_rule(
        {
            "name": "台海高优先级",
            "keywords": [" Taiwan ", "台海", "TAIWAN"],
            "min_stars": 7,
            "sources": ["Source A"],
            "severity": "high",
        }
    )
    news = [
        {
            "aid": "a1",
            "title": "Taiwan exercise expands",
            "summary": "",
            "source": "Source A",
            "date": "2026-07-25T08:15:00+00:00",
            "priority": {"stars": 8},
        },
        {
            "aid": "a2",
            "title": "Taiwan background",
            "summary": "",
            "source": "Source A",
            "date": "2026-07-25T09:15:00+00:00",
            "priority": {"stars": 4},
        },
        {
            "aid": "a3",
            "title": "Taiwan note",
            "summary": "",
            "source": "Other",
            "date": "2026-07-25T10:15:00+00:00",
            "priority": {"stars": 9},
        },
    ]

    result = evaluate_alert_rules(
        [rule],
        news,
        now=datetime(2026, 7, 25, 12, tzinfo=timezone.utc),
    )

    assert rule["keywords"] == ["taiwan", "台海"]
    assert result["total_hits"] == 1
    assert result["hits"][0]["article_id"] == "a1"
    assert len(result["rhythm"]) == 24
    assert sum(bucket["count"] for bucket in result["rhythm"]) == 1


def test_disabled_rule_and_old_article_do_not_trigger():
    from v9.alerts import evaluate_alert_rules, normalize_alert_rule

    disabled = normalize_alert_rule(
        {"name": "disabled", "keywords": ["missile"], "enabled": False}
    )
    old_news = [
        {
            "aid": "old",
            "title": "missile",
            "source": "Source",
            "date": "2026-07-23T08:00:00+00:00",
            "priority": {"stars": 10},
        }
    ]

    result = evaluate_alert_rules(
        [disabled],
        old_news,
        now=datetime(2026, 7, 25, 12, tzinfo=timezone.utc),
    )

    assert result["total_hits"] == 0
    assert all(bucket["count"] == 0 for bucket in result["rhythm"])


def test_single_string_keyword_is_not_split_into_characters():
    from v9.alerts import normalize_alert_rule

    rule = normalize_alert_rule({"name": "single", "keywords": "carrier"})

    assert rule["keywords"] == ["carrier"]


def test_alert_rules_are_encrypted_and_versioned(tmp_path):
    from v9.service import V9Service

    service = V9Service(tmp_path / "v9.sqlite3", tmp_path / ".master")
    context = service.get_or_create_personal_context()
    created = service.save_alert_rule(
        context,
        {
            "name": "航母动向",
            "keywords": ["carrier"],
            "min_stars": 6,
            "severity": "medium",
        },
    )

    assert "航母动向".encode("utf-8") not in service.database_path.read_bytes()
    listed = service.list_alert_rules(context)
    assert listed[0]["record_id"] == created["record_id"]
    assert listed[0]["content"]["name"] == "航母动向"
    assert listed[0]["version"] == 1

    updated = service.save_alert_rule(
        context,
        {
            "record_id": created["record_id"],
            "version": 1,
            "name": "航母高优先级",
            "keywords": ["carrier"],
            "min_stars": 8,
            "severity": "high",
        },
    )
    assert updated["version"] == 2
    assert service.list_alert_rules(context)[0]["content"]["min_stars"] == 8
