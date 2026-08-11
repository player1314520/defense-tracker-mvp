# -*- coding: utf-8 -*-
from datetime import datetime, timezone

import pytest


def _service(tmp_path):
    from v9.service import V9Service

    service = V9Service(tmp_path / "v9.sqlite3", tmp_path / ".master")
    return service, service.get_or_create_personal_context()


def _evidence(service, context):
    return service.archive_news_evidence(
        context,
        {
            "aid": "p4-evidence",
            "title": "公开来源证据",
            "summary": "仅供状态机测试",
            "source": "Source A",
            "link": "https://example.test/p4",
            "date": datetime.now(timezone.utc).isoformat(),
            "priority": {"stars": 8},
        },
    )


def _control(service, context, job, action, **value):
    result = service.control_agent_job(
        context,
        job["record_id"],
        action=action,
        expected_version=job["version"],
        value=value,
    )
    return service.list_agent_jobs(context)[0] | {
        "transition": result["transition"]
    }


def test_agent_job_persists_phases_and_both_human_gates(tmp_path):
    service, context = _service(tmp_path)
    evidence = _evidence(service, context)
    job = service.create_agent_job(
        context,
        {
            "template": "rapid_assessment",
            "title": "台海航母活动快速研判",
            "evidence_ids": [evidence["record_id"]],
        },
    )
    assert job["version"] == 1
    current = service.list_agent_jobs(context)[0]
    assert current["content"]["state"] == "queued"
    assert current["content"]["phase"] == "collect"

    current = _control(service, context, current, "start")
    assert current["content"]["state"] == "running"
    for expected_phase in ("close_read", "outline"):
        current = _control(service, context, current, "advance")
        assert current["content"]["phase"] == expected_phase
    current = _control(service, context, current, "advance")
    assert current["content"]["state"] == "waiting_user"
    assert current["content"]["gate"] == "outline"

    current = _control(service, context, current, "approve_outline")
    assert current["content"]["phase"] == "draft"
    assert current["content"]["state"] == "running"
    current = _control(service, context, current, "advance")
    assert current["content"]["phase"] == "verify"
    current = _control(service, context, current, "advance")
    assert current["content"]["state"] == "waiting_user"
    assert current["content"]["gate"] == "release"
    current = _control(service, context, current, "approve_release")
    assert current["content"]["state"] == "succeeded"
    assert current["content"]["progress"] == 100

    raw = service.database_path.read_bytes()
    assert "台海航母活动快速研判".encode() not in raw


def test_failed_agent_job_has_explicit_type_and_can_resume(tmp_path):
    service, context = _service(tmp_path)
    evidence = _evidence(service, context)
    service.create_agent_job(
        context,
        {
            "template": "deep_research",
            "title": "专题深挖",
            "evidence_ids": [evidence["record_id"]],
        },
    )
    current = service.list_agent_jobs(context)[0]
    current = _control(service, context, current, "start")

    with pytest.raises(ValueError, match="失败类型"):
        _control(
            service,
            context,
            current,
            "fail",
            error_type="unknown",
            message="bad",
        )

    current = _control(
        service,
        context,
        current,
        "fail",
        error_type="ai_timeout",
        message="本地模型超时",
    )
    assert current["content"]["state"] == "failed"
    assert current["content"]["error"]["type"] == "ai_timeout"
    phase = current["content"]["phase"]
    current = _control(service, context, current, "resume")
    assert current["content"]["state"] == "queued"
    assert current["content"]["phase"] == phase


def test_local_phase_executor_advances_and_encrypts_output(tmp_path):
    service, context = _service(tmp_path)
    evidence = _evidence(service, context)
    service.create_agent_job(
        context,
        {
            "template": "rapid_assessment",
            "title": "本地执行",
            "evidence_ids": [evidence["record_id"]],
        },
    )
    current = service.list_agent_jobs(context)[0]
    current = _control(service, context, current, "start")
    observed = {}

    def executor(payload):
        observed.update(payload)
        return "阶段输出引用 [E1]"

    result = service.execute_agent_job_phase(
        context,
        current["record_id"],
        expected_version=current["version"],
        executor=executor,
    )
    updated = service.list_agent_jobs(context)[0]
    assert result["execution_error"] is None
    assert updated["content"]["phase"] == "close_read"
    assert updated["content"]["stage_outputs"]["collect"] == "阶段输出引用 [E1]"
    assert observed["execution_scope"] == "unlocked_desktop_only"
    assert observed["evidence"][0]["record_id"] == evidence["record_id"]
    assert "阶段输出引用".encode() not in service.database_path.read_bytes()


def test_local_phase_executor_failure_is_typed_and_recoverable(tmp_path):
    service, context = _service(tmp_path)
    evidence = _evidence(service, context)
    service.create_agent_job(
        context,
        {
            "template": "rapid_assessment",
            "title": "超时任务",
            "evidence_ids": [evidence["record_id"]],
        },
    )
    current = _control(
        service, context, service.list_agent_jobs(context)[0], "start"
    )

    def timeout(_payload):
        raise TimeoutError("local model timeout")

    result = service.execute_agent_job_phase(
        context,
        current["record_id"],
        expected_version=current["version"],
        executor=timeout,
    )
    updated = service.list_agent_jobs(context)[0]
    assert result["execution_error"]["type"] == "ai_timeout"
    assert updated["content"]["state"] == "failed"
    resumed = _control(service, context, updated, "resume")
    assert resumed["content"]["state"] == "queued"


def test_scenario_keeps_three_branches_and_separate_team_outputs(tmp_path):
    service, context = _service(tmp_path)
    evidence = _evidence(service, context)
    created = service.create_scenario(
        context,
        {
            "title": "台海未来 72 小时",
            "question": "公开来源信号可能如何演化？",
            "evidence_ids": [evidence["record_id"]],
            "assumptions": ["当前公开来源报道持续有效"],
        },
    )
    scenario = service.list_scenarios(context)[0]
    assert created["version"] == 1
    assert scenario["content"]["classification"] == "scenario_inference"
    assert set(scenario["content"]["branches"]) == {
        "baseline",
        "escalation",
        "deescalation",
    }

    updated = service.update_scenario(
        context,
        scenario["record_id"],
        expected_version=scenario["version"],
        changes={
            "branches": {
                "baseline": {
                    "summary": "维持当前节奏",
                    "triggers": ["未出现新增部署"],
                    "indicators": ["公开航迹"],
                    "counter_evidence_ids": [evidence["record_id"]],
                    "confidence": 0.55,
                },
                "escalation": {
                    "summary": "活动强度上升",
                    "triggers": ["新增高价值平台"],
                    "indicators": ["兵力增量"],
                    "counter_evidence_ids": [],
                    "confidence": 0.3,
                },
                "deescalation": {
                    "summary": "活动强度下降",
                    "triggers": ["兵力撤离"],
                    "indicators": ["航迹减少"],
                    "counter_evidence_ids": [],
                    "confidence": 0.15,
                },
            },
            "team_outputs": {
                "red": {
                    "text": "升级路径论证",
                    "evidence_ids": [evidence["record_id"]],
                },
                "blue": {
                    "text": "缓和路径论证",
                    "evidence_ids": [evidence["record_id"]],
                },
                "judge": {
                    "text": "三分支仍需持续观察",
                    "evidence_ids": [evidence["record_id"]],
                },
            },
        },
    )
    assert updated["version"] == 2
    value = service.list_scenarios(context)[0]["content"]
    assert value["team_outputs"]["red"]["text"] == "升级路径论证"
    assert value["team_outputs"]["blue"]["text"] == "缓和路径论证"
    assert value["team_outputs"]["judge"]["text"] == "三分支仍需持续观察"
    assert value["classification"] == "scenario_inference"


def test_scenario_rejects_outputs_without_citations(tmp_path):
    service, context = _service(tmp_path)
    evidence = _evidence(service, context)
    service.create_scenario(
        context,
        {
            "title": "情景",
            "question": "会如何变化？",
            "evidence_ids": [evidence["record_id"]],
        },
    )
    scenario = service.list_scenarios(context)[0]
    with pytest.raises(ValueError, match="证据"):
        service.update_scenario(
            context,
            scenario["record_id"],
            expected_version=scenario["version"],
            changes={
                "team_outputs": {
                    "red": {"text": "无引用输出", "evidence_ids": []}
                }
            },
        )
