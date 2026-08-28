"""Local-only agent job state machine and evidence-bound scenario records."""
from __future__ import annotations

import math
from datetime import datetime, timezone

from .workflow import record_ids


JOB_TEMPLATES = {
    "rapid_assessment": "快速研判",
    "deep_research": "专题深挖",
    "scenario_simulation": "情景推演",
    "brief_draft": "要讯成稿",
}
JOB_STATES = {
    "queued",
    "running",
    "waiting_user",
    "succeeded",
    "failed",
    "cancelled",
}
JOB_PHASES = ("collect", "close_read", "outline", "draft", "verify")
JOB_FAILURE_TYPES = {
    "source_unavailable",
    "network_error",
    "ai_timeout",
    "ai_rejected",
    "validation_error",
    "storage_error",
    "interrupted",
}
SCENARIO_BRANCHES = ("baseline", "escalation", "deescalation")
SCENARIO_TEAMS = ("red", "blue", "judge")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _text(value, name: str, limit: int = 5000, *, required: bool = True) -> str:
    result = str(value or "").strip()
    if required and not result:
        raise ValueError(f"{name}不能为空")
    return result[:limit]


def _string_list(value, name: str, *, limit: int = 200) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise ValueError(f"{name}必须是列表")
    result = []
    for item in value:
        text = str(item or "").strip()
        if text:
            result.append(text[:1000])
    return result[:limit]


def _confidence(value) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise ValueError("置信度必须是 0 到 1 的数字") from None
    if not math.isfinite(result):
        raise ValueError("置信度必须是有限数字")
    return max(0.0, min(1.0, result))


def new_agent_job(value: dict) -> dict:
    template = str(value.get("template") or "").strip()
    if template not in JOB_TEMPLATES:
        raise ValueError("无效智能体任务模板")
    if template == "brief_draft":
        raise ValueError("要讯成稿须使用写作室中的要讯专用生成与来源校验流程")
    now = _now()
    return {
        "template": template,
        "template_name": JOB_TEMPLATES[template],
        "title": _text(value.get("title"), "任务标题", 300),
        "instructions": _text(
            value.get("instructions"), "任务要求", 5000, required=False
        ),
        "evidence_ids": record_ids(
            value.get("evidence_ids"), required=True
        ),
        "state": "queued",
        "phase": "collect",
        "gate": None,
        "progress": 0,
        "stage_outputs": {},
        "error": None,
        "created_at": now,
        "updated_at": now,
        "history": [
            {"at": now, "event": "created", "state": "queued", "phase": "collect"}
        ],
        "execution_scope": "unlocked_desktop_only",
    }


def transition_agent_job(current: dict, action: str, value: dict | None = None) -> tuple[dict, dict]:
    value = value or {}
    action = str(action or "").strip().lower()
    result = dict(current)
    if result.get("template") == "brief_draft":
        raise ValueError("要讯成稿须使用写作室中的要讯专用生成与来源校验流程")
    state = str(result.get("state") or "")
    phase = str(result.get("phase") or "")
    if state not in JOB_STATES or phase not in JOB_PHASES:
        raise ValueError("智能体任务状态损坏")
    if state == "succeeded":
        raise ValueError("已完成任务不能再次变更")

    if action == "start":
        if state != "queued":
            raise ValueError("只有排队任务可以启动")
        result["state"] = "running"
        result["progress"] = max(5, int(result.get("progress") or 0))
    elif action == "advance":
        if state != "running":
            raise ValueError("只有运行中任务可以推进")
        output = value.get("output")
        if output is not None:
            outputs = dict(result.get("stage_outputs") or {})
            outputs[phase] = _text(
                output, "阶段输出", 20000, required=False
            )
            result["stage_outputs"] = outputs
        if phase == "outline":
            result["state"] = "waiting_user"
            result["gate"] = "outline"
            result["progress"] = 55
        elif phase == "verify":
            result["state"] = "waiting_user"
            result["gate"] = "release"
            result["progress"] = 95
        else:
            next_phase = JOB_PHASES[JOB_PHASES.index(phase) + 1]
            result["phase"] = next_phase
            result["progress"] = {
                "close_read": 30,
                "outline": 50,
                "draft": 70,
                "verify": 90,
            }[next_phase]
    elif action == "approve_outline":
        if state != "waiting_user" or result.get("gate") != "outline":
            raise ValueError("任务当前不在大纲人工闸门")
        result["state"] = "running"
        result["phase"] = "draft"
        result["gate"] = None
        result["progress"] = 70
    elif action == "approve_release":
        if state != "waiting_user" or result.get("gate") != "release":
            raise ValueError("任务当前不在签发前人工闸门")
        result["state"] = "succeeded"
        result["gate"] = None
        result["progress"] = 100
    elif action == "fail":
        if state in {"failed", "cancelled"}:
            raise ValueError("终止状态任务不能重复失败")
        error_type = str(value.get("error_type") or "").strip()
        if error_type not in JOB_FAILURE_TYPES:
            raise ValueError("无效失败类型")
        result["state"] = "failed"
        result["error"] = {
            "type": error_type,
            "message": _text(
                value.get("message") or error_type,
                "失败说明",
                1000,
            ),
            "at": _now(),
        }
    elif action == "resume":
        if state != "failed":
            raise ValueError("只有失败任务可以恢复")
        result["state"] = "queued"
        result["error"] = None
    elif action == "cancel":
        if state in {"failed", "cancelled"}:
            raise ValueError("任务已经终止")
        result["state"] = "cancelled"
        result["gate"] = None
    else:
        raise ValueError("无效智能体任务动作")

    now = _now()
    result["updated_at"] = now
    history = list(result.get("history") or [])
    transition = {
        "at": now,
        "event": action,
        "state": result["state"],
        "phase": result["phase"],
        "gate": result.get("gate"),
    }
    history.append(transition)
    result["history"] = history[-500:]
    return result, transition


def _empty_branch() -> dict:
    return {
        "summary": "",
        "triggers": [],
        "indicators": [],
        "counter_evidence_ids": [],
        "confidence": 0.0,
    }


def _normalize_branch(value: dict | None) -> dict:
    value = value or {}
    if not isinstance(value, dict):
        raise ValueError("情景分支必须是对象")
    return {
        "summary": _text(
            value.get("summary"), "分支摘要", 5000, required=False
        ),
        "triggers": _string_list(value.get("triggers"), "触发器"),
        "indicators": _string_list(value.get("indicators"), "观察指标"),
        "counter_evidence_ids": record_ids(
            value.get("counter_evidence_ids")
        ),
        "confidence": _confidence(value.get("confidence", 0)),
    }


def _empty_team_output() -> dict:
    return {"text": "", "evidence_ids": []}


def _normalize_team_output(value: dict | None, name: str) -> dict:
    value = value or {}
    if not isinstance(value, dict):
        raise ValueError(f"{name}输出必须是对象")
    text = _text(value.get("text"), f"{name}输出", 20000, required=False)
    evidence_ids = record_ids(
        value.get("evidence_ids"), required=bool(text)
    )
    return {"text": text, "evidence_ids": evidence_ids}


def new_scenario(value: dict) -> dict:
    now = _now()
    return {
        "title": _text(value.get("title"), "推演标题", 300),
        "question": _text(value.get("question"), "推演问题", 2000),
        "classification": "scenario_inference",
        "evidence_ids": record_ids(
            value.get("evidence_ids"), required=True
        ),
        "assumptions": _string_list(value.get("assumptions"), "假设"),
        "observables": _string_list(value.get("observables"), "观察指标"),
        "branches": {
            branch: _empty_branch() for branch in SCENARIO_BRANCHES
        },
        "team_outputs": {
            team: _empty_team_output() for team in SCENARIO_TEAMS
        },
        "created_at": now,
        "updated_at": now,
    }


def apply_scenario_changes(current: dict, changes: dict) -> dict:
    result = dict(current)
    for field in ("title", "question", "evidence_ids", "assumptions", "observables"):
        if field in changes:
            result[field] = changes[field]
    result["title"] = _text(result.get("title"), "推演标题", 300)
    result["question"] = _text(result.get("question"), "推演问题", 2000)
    result["classification"] = "scenario_inference"
    result["evidence_ids"] = record_ids(
        result.get("evidence_ids"), required=True
    )
    result["assumptions"] = _string_list(result.get("assumptions"), "假设")
    result["observables"] = _string_list(
        result.get("observables"), "观察指标"
    )

    branches = {
        branch: dict((result.get("branches") or {}).get(branch) or _empty_branch())
        for branch in SCENARIO_BRANCHES
    }
    branch_changes = changes.get("branches")
    if branch_changes is not None:
        if not isinstance(branch_changes, dict):
            raise ValueError("情景分支必须是对象")
        unknown = set(branch_changes) - set(SCENARIO_BRANCHES)
        if unknown:
            raise ValueError("仅允许基准、升级、缓和三类分支")
        for branch, value in branch_changes.items():
            branches[branch] = value
    result["branches"] = {
        branch: _normalize_branch(branches[branch])
        for branch in SCENARIO_BRANCHES
    }

    outputs = {
        team: dict(
            (result.get("team_outputs") or {}).get(team)
            or _empty_team_output()
        )
        for team in SCENARIO_TEAMS
    }
    output_changes = changes.get("team_outputs")
    if output_changes is not None:
        if not isinstance(output_changes, dict):
            raise ValueError("推演角色输出必须是对象")
        unknown = set(output_changes) - set(SCENARIO_TEAMS)
        if unknown:
            raise ValueError("仅允许红队、蓝队和裁判输出")
        for team, value in output_changes.items():
            outputs[team] = value
    result["team_outputs"] = {
        team: _normalize_team_output(outputs[team], team)
        for team in SCENARIO_TEAMS
    }
    result["updated_at"] = _now()
    return result
