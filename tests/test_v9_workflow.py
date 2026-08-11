# -*- coding: utf-8 -*-
from datetime import datetime, timezone

import pytest

from v9.errors import VersionConflict
from v9.workflow import apply_case_changes


def _service(tmp_path):
    from v9.service import V9Service

    service = V9Service(tmp_path / "v9.sqlite3", tmp_path / ".master")
    return service, service.get_or_create_personal_context()


def _article():
    return {
        "aid": "news-1",
        "title": "Carrier movement near Taiwan",
        "summary": "公开来源摘要",
        "source": "Source A",
        "link": "https://example.test/news-1",
        "date": datetime.now(timezone.utc).isoformat(),
        "priority": {"stars": 9},
        "region": "台湾",
    }


def test_rule_hit_materializes_encrypted_alert_with_evidence_once(tmp_path):
    service, context = _service(tmp_path)
    rule = service.save_alert_rule(
        context,
        {
            "name": "台海航母",
            "keywords": ["carrier", "taiwan"],
            "min_stars": 7,
            "severity": "high",
        },
    )
    rules = service.list_alert_rules(context)

    first = service.materialize_rule_hits(context, rules, [_article()])
    second = service.materialize_rule_hits(context, rules, [_article()])

    assert first["created"] == 1
    assert second["created"] == 0
    alerts = service.list_alerts(context)
    assert len(alerts) == 1
    assert alerts[0]["content"]["status"] == "new"
    assert len(alerts[0]["content"]["evidence_ids"]) == 1
    assert alerts[0]["content"]["rule_id"] == rule["record_id"]
    raw = service.database_path.read_bytes()
    assert "Carrier movement near Taiwan".encode() not in raw
    assert "公开来源摘要".encode() not in raw


def test_alert_to_case_keeps_evidence_and_case_conclusions_require_citations(tmp_path):
    service, context = _service(tmp_path)
    service.save_alert_rule(
        context,
        {
            "name": "carrier",
            "keywords": ["carrier"],
            "severity": "high",
        },
    )
    service.materialize_rule_hits(
        context, service.list_alert_rules(context), [_article()]
    )
    alert = service.list_alerts(context)[0]

    converted = service.triage_alert(
        context,
        alert["record_id"],
        action="convert_case",
        expected_version=alert["version"],
    )
    case = service.list_cases(context)[0]

    assert converted["case_id"] == case["record_id"]
    assert case["content"]["evidence_ids"] == alert["content"]["evidence_ids"]
    with pytest.raises(ValueError, match="证据"):
        service.update_case(
            context,
            case["record_id"],
            expected_version=case["version"],
            changes={"conclusions": [{"text": "无引用结论", "evidence_ids": []}]},
        )

    updated = service.update_case(
        context,
        case["record_id"],
        expected_version=case["version"],
        changes={
            "conclusions": [
                {
                    "text": "带证据的分析结论",
                    "evidence_ids": case["content"]["evidence_ids"],
                    "confidence": 0.7,
                }
            ]
        },
    )
    assert updated["version"] == 2
    case = service.list_cases(context)[0]
    conclusion = case["content"]["conclusions"][0]
    assert conclusion["epistemic_status"] == "inference"
    assert conclusion["confidence"] is None
    assert conclusion["confidence_status"] == "evidence_insufficient"


def test_case_conclusion_ids_are_stable_and_claim_links_are_normalized():
    current = {
        "title": "示例案件",
        "status": "investigating",
        "evidence_ids": ["evidence-1", "evidence-2"],
        "conclusions": [
            {
                "text": "旧数据中的结论",
                "evidence_ids": ["evidence-1", "evidence-2"],
                "confidence": 0.6,
            }
        ],
    }

    normalized = apply_case_changes(current, {})
    conclusion_id = normalized["conclusions"][0]["conclusion_id"]
    assert conclusion_id

    updated = apply_case_changes(
        normalized,
        {
            "conclusions": [
                {
                    **normalized["conclusions"][0],
                    "text": "修订后的结论",
                    "claim_ids": [" claim-1 ", "claim-1", "claim-2"],
                }
            ]
        },
    )
    conclusion = updated["conclusions"][0]
    assert conclusion["conclusion_id"] == conclusion_id
    assert conclusion["claim_ids"] == ["claim-1", "claim-2"]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("source_weight", 1.01, "source_weight"),
        ("time_decay", float("nan"), "time_decay"),
        ("independent_source_count", -1, "independent_source_count"),
        ("counter_evidence_count", -1, "counter_evidence_count"),
    ],
)
def test_case_confidence_inputs_reject_invalid_values(field, value, message):
    with pytest.raises(ValueError, match=message):
        apply_case_changes(
            {
                "title": "示例案件",
                "status": "investigating",
                "evidence_ids": ["evidence-1", "evidence-2"],
                "conclusions": [],
            },
            {
                "conclusions": [
                    {
                        "text": "待校准结论",
                        "evidence_ids": ["evidence-1", "evidence-2"],
                        "confidence": 0.7,
                        "confidence_inputs": {
                            "source_weight": 0.8,
                            "time_decay": 0.9,
                            "independent_source_count": 2,
                            "counter_evidence_count": 0,
                            field: value,
                        },
                    }
                ]
            },
        )


def test_case_confidence_requires_two_independent_sources():
    result = apply_case_changes(
        {
            "title": "示例案件",
            "status": "investigating",
            "evidence_ids": ["evidence-1", "evidence-2"],
            "conclusions": [
                {
                    "text": "两条材料来自同一独立来源",
                    "evidence_ids": ["evidence-1", "evidence-2"],
                    "confidence": 0.7,
                    "confidence_inputs": {
                        "source_weight": 0.8,
                        "time_decay": 0.9,
                        "independent_source_count": 1,
                        "counter_evidence_count": 0,
                    },
                }
            ],
        },
        {},
    )

    conclusion = result["conclusions"][0]
    assert conclusion["confidence"] is None
    assert conclusion["confidence_status"] == "evidence_insufficient"
    assert conclusion["confidence_inputs"]["independent_source_count"] == 1


def test_case_does_not_infer_independent_sources_from_evidence_count():
    result = apply_case_changes(
        {
            "title": "示例案件",
            "status": "investigating",
            "evidence_ids": ["evidence-1", "evidence-2"],
            "conclusions": [
                {
                    "text": "来源独立性尚未核实",
                    "evidence_ids": ["evidence-1", "evidence-2"],
                    "confidence": 0.7,
                }
            ],
        },
        {},
    )

    conclusion = result["conclusions"][0]
    assert conclusion["confidence"] is None
    assert conclusion["confidence_status"] == "evidence_insufficient"
    assert conclusion["confidence_inputs"]["independent_source_count"] == 0


def test_human_calibration_history_is_append_only_and_normalized():
    existing_history = [
        {
            "actor": "analyst-1",
            "time": "2026-07-20T08:00:00+00:00",
            "old": 0.4,
            "new": 0.5,
            "reason": "第一次人工复核",
        }
    ]
    current = apply_case_changes(
        {
            "title": "示例案件",
            "status": "review",
            "evidence_ids": ["evidence-1", "evidence-2"],
            "conclusions": [
                {
                    "text": "待人工校准结论",
                    "evidence_ids": ["evidence-1", "evidence-2"],
                    "confidence": 0.5,
                    "confidence_inputs": {
                        "independent_source_count": 2,
                    },
                    "human_calibration_history": existing_history,
                }
            ],
        },
        {},
    )
    conclusion_id = current["conclusions"][0]["conclusion_id"]

    updated = apply_case_changes(
        current,
        {
            "conclusions": [
                {
                    **current["conclusions"][0],
                    "human_calibration_history": [{"actor": "forged"}],
                    "human_calibration": {
                        "actor": " analyst-2 ",
                        "time": "2026-07-26T09:30:00Z",
                        "old": "0.5",
                        "new": 0.65,
                        "reason": " 补充独立来源后复核 ",
                    },
                }
            ]
        },
    )

    history = updated["conclusions"][0]["human_calibration_history"]
    assert updated["conclusions"][0]["conclusion_id"] == conclusion_id
    assert history[0] == existing_history[0]
    assert history[1] == {
        "actor": "analyst-2",
        "time": "2026-07-26T09:30:00+00:00",
        "old": 0.5,
        "new": 0.65,
        "reason": "补充独立来源后复核",
    }

    unchanged = apply_case_changes(updated, {})
    assert (
        unchanged["conclusions"][0]["human_calibration_history"]
        == history
    )


def test_human_calibration_requires_old_and_new_values():
    with pytest.raises(ValueError, match="human_calibration.old"):
        apply_case_changes(
            {
                "title": "示例案件",
                "status": "review",
                "evidence_ids": ["evidence-1", "evidence-2"],
                "conclusions": [],
            },
            {
                "conclusions": [
                    {
                        "text": "待人工校准结论",
                        "evidence_ids": ["evidence-1", "evidence-2"],
                        "confidence_inputs": {
                            "independent_source_count": 2,
                        },
                        "human_calibration": {
                            "actor": "analyst-2",
                            "time": "2026-07-26T09:30:00Z",
                            "new": 0.65,
                            "reason": "补充独立来源后复核",
                        },
                    }
                ]
            },
        )


def test_stale_alert_conversion_does_not_create_orphan_case(tmp_path):
    service, context = _service(tmp_path)
    service.save_alert_rule(
        context,
        {"name": "carrier", "keywords": ["carrier"], "severity": "high"},
    )
    service.materialize_rule_hits(
        context, service.list_alert_rules(context), [_article()]
    )
    alert = service.list_alerts(context)[0]

    with pytest.raises(VersionConflict):
        service.triage_alert(
            context,
            alert["record_id"],
            action="convert_case",
            expected_version=alert["version"] + 1,
        )

    assert service.list_cases(context) == []


def test_graph_relations_distinguish_epistemic_status_and_require_evidence(tmp_path):
    service, context = _service(tmp_path)
    evidence = service.archive_news_evidence(context, _article())
    first = service.create_graph_entity(
        context,
        {
            "name": "示例航母",
            "kind": "platform",
            "epistemic_status": "source_claim",
            "evidence_ids": [evidence["record_id"]],
            "aliases": "示例别名",
        },
    )
    second = service.create_graph_entity(
        context,
        {
            "name": "示例海域",
            "kind": "location",
            "epistemic_status": "fact",
            "evidence_ids": [evidence["record_id"]],
        },
    )

    with pytest.raises(ValueError, match="证据"):
        service.create_graph_relation(
            context,
            {
                "subject_id": first["record_id"],
                "object_id": second["record_id"],
                "predicate": "部署于",
                "epistemic_status": "inference",
                "evidence_ids": [],
            },
        )

    service.create_graph_relation(
        context,
        {
            "subject_id": first["record_id"],
            "object_id": second["record_id"],
            "predicate": "可能部署于",
            "epistemic_status": "inference",
            "evidence_ids": [evidence["record_id"]],
        },
    )
    graph = service.get_graph(context)
    carrier = next(
        item
        for item in graph["entities"]
        if item["content"]["name"] == "示例航母"
    )
    assert carrier["content"]["aliases"] == ["示例别名"]
    assert graph["relations"][0]["content"]["epistemic_status"] == "inference"


def test_claim_links_evidence_conclusions_and_paragraphs(tmp_path):
    service, context = _service(tmp_path)
    evidence = service.archive_news_evidence(context, _article())
    claim = service.create_claim(
        context,
        {
            "statement": "来源称某航母正在相关海域活动",
            "epistemic_status": "source_claim",
            "evidence_ids": [evidence["record_id"]],
            "counter_evidence_ids": [],
            "conclusion_ids": ["conclusion-1"],
            "paragraph_refs": ["paragraph-1"],
            "source_health": "healthy",
            "evidence_updated_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    stored = service.list_claims(context)[0]
    assert stored["record_id"] == claim["record_id"]
    assert stored["content"]["evidence_ids"] == [evidence["record_id"]]
    assert stored["content"]["conclusion_ids"] == ["conclusion-1"]
    assert stored["content"]["paragraph_refs"] == ["paragraph-1"]
    assert stored["content"]["source_health"] == "healthy"
    assert stored["content"]["confidence_status"] == "evidence_insufficient"


def test_case_references_are_type_checked_and_calibration_identity_is_server_bound(
    tmp_path,
):
    service, context = _service(tmp_path)
    service.save_alert_rule(
        context,
        {"name": "carrier", "keywords": ["carrier"], "severity": "high"},
    )
    service.materialize_rule_hits(
        context, service.list_alert_rules(context), [_article()]
    )
    alert = service.list_alerts(context)[0]
    service.triage_alert(
        context,
        alert["record_id"],
        action="convert_case",
        expected_version=alert["version"],
    )
    case = service.list_cases(context)[0]
    first_evidence_id = case["content"]["evidence_ids"][0]
    second_evidence = service.archive_news_evidence(
        context,
        {
            **_article(),
            "aid": "news-2",
            "title": "Independent corroborating report",
            "link": "https://example.test/news-2",
        },
    )
    evidence_ids = [first_evidence_id, second_evidence["record_id"]]
    claim = service.create_claim(
        context,
        {
            "statement": "两项公开来源支持同一活动判断",
            "epistemic_status": "source_claim",
            "evidence_ids": evidence_ids,
        },
    )

    with pytest.raises(ValueError, match="evidence"):
        service.update_case(
            context,
            case["record_id"],
            expected_version=case["version"],
            changes={"contradictory_evidence_ids": [claim["record_id"]]},
        )

    conclusion = {
        "text": "经两项独立来源印证的分析判断",
        "epistemic_status": "inference",
        "evidence_ids": evidence_ids,
        "counter_evidence_ids": [claim["record_id"]],
        "claim_ids": [claim["record_id"]],
        "confidence": 0.7,
        "confidence_inputs": {"independent_source_count": 2},
    }
    with pytest.raises(ValueError, match="evidence"):
        service.update_case(
            context,
            case["record_id"],
            expected_version=case["version"],
            changes={
                "evidence_ids": evidence_ids,
                "conclusions": [conclusion],
            },
        )

    conclusion["counter_evidence_ids"] = [second_evidence["record_id"]]
    conclusion["claim_ids"] = [first_evidence_id]
    with pytest.raises(ValueError, match="claim"):
        service.update_case(
            context,
            case["record_id"],
            expected_version=case["version"],
            changes={
                "evidence_ids": evidence_ids,
                "conclusions": [conclusion],
            },
        )

    conclusion["claim_ids"] = [claim["record_id"]]
    conclusion["human_calibration"] = {
        "actor": "forged-user",
        "time": "2000-01-01T00:00:00Z",
        "old": 0.5,
        "new": 0.7,
        "reason": "补充独立来源后人工复核",
    }
    service.update_case(
        context,
        case["record_id"],
        expected_version=case["version"],
        changes={
            "evidence_ids": evidence_ids,
            "conclusions": [conclusion],
        },
    )
    updated_case = service.list_cases(context)[0]
    history = updated_case["content"]["conclusions"][0][
        "human_calibration_history"
    ]
    assert history[-1]["actor"] == context["user_id"]
    assert history[-1]["time"] != "2000-01-01T00:00:00+00:00"
    assert datetime.fromisoformat(history[-1]["time"]).tzinfo is not None


def test_geo_events_validate_coordinates_and_keep_source_status(tmp_path):
    service, context = _service(tmp_path)
    evidence = service.archive_news_evidence(context, _article())
    with pytest.raises(ValueError, match="经纬度"):
        service.create_geo_event(
            context,
            {
                "title": "invalid",
                "latitude": 95,
                "longitude": 181,
                "epistemic_status": "fact",
                "evidence_ids": [evidence["record_id"]],
            },
        )
    with pytest.raises(ValueError, match="有限数字"):
        service.create_geo_event(
            context,
            {
                "title": "invalid nan",
                "latitude": float("nan"),
                "longitude": 122,
                "epistemic_status": "fact",
                "evidence_ids": [evidence["record_id"]],
            },
        )

    service.create_geo_event(
        context,
        {
            "title": "来源声明位置",
            "latitude": 23.5,
            "longitude": 122.0,
            "kind": "naval",
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "epistemic_status": "source_claim",
            "evidence_ids": [evidence["record_id"]],
        },
    )
    events = service.list_geo_events(context, hours=120)
    assert events[0]["content"]["epistemic_status"] == "source_claim"
    assert events[0]["content"]["evidence_ids"] == [evidence["record_id"]]

    with pytest.raises(ValueError, match="entity"):
        service.create_geo_event(
            context,
            {
                "title": "错误关联类型",
                "latitude": 23.5,
                "longitude": 122.0,
                "epistemic_status": "source_claim",
                "evidence_ids": [evidence["record_id"]],
                "entity_ids": [evidence["record_id"]],
            },
        )
