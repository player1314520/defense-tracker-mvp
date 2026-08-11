from __future__ import annotations

import copy
import math
import uuid
from datetime import datetime, timezone


EPISTEMIC_STATUSES = {
    "fact",
    "source_claim",
    "inference",
    "scenario_assumption",
}
ALERT_ACTIONS = {"claim", "snooze", "escalate", "close", "convert_case"}
CASE_STATUSES = {"open", "investigating", "review", "issued", "closed"}


def _text(value, name: str, limit: int = 500) -> str:
    result = str(value or "").strip()
    if not result:
        raise ValueError(f"{name}不能为空")
    return result[:limit]


def record_ids(values, *, required: bool = False) -> list[str]:
    if isinstance(values, str):
        values = [values]
    result = []
    seen = set()
    for value in values or []:
        record_id = str(value or "").strip()
        if record_id and record_id not in seen:
            result.append(record_id)
            seen.add(record_id)
    if required and not result:
        raise ValueError("必须关联至少一条证据")
    return result[:200]


def epistemic_status(value) -> str:
    status = str(value or "").strip().lower()
    if status not in EPISTEMIC_STATUSES:
        raise ValueError(
            "认知状态必须是 fact、source_claim、inference "
            "或 scenario_assumption"
        )
    return status


def _confidence(value) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise ValueError("置信度必须是 0 到 1 的数字") from None
    if not math.isfinite(result):
        raise ValueError("置信度必须是有限数字")
    return max(0.0, min(1.0, result))


def _confidence_input(value, name: str) -> float | None:
    if value is None or value == "":
        return None
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} 必须是 0 到 1 的数字") from None
    if not math.isfinite(result) or not 0.0 <= result <= 1.0:
        raise ValueError(f"{name} 必须是 0 到 1 的有限数字")
    return result


def _nonnegative_count(value, name: str, *, default: int) -> int:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        raise ValueError(f"{name} 必须是非负整数")
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} 必须是非负整数") from None
    if (
        not math.isfinite(numeric)
        or numeric < 0
        or not numeric.is_integer()
    ):
        raise ValueError(f"{name} 必须是非负整数")
    return int(numeric)


def _normalize_calibration(value: dict) -> dict:
    if not isinstance(value, dict):
        raise ValueError("human_calibration 必须是对象")
    timestamp = _text(
        value.get("time"), "human_calibration.time", 80
    )
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(
            "human_calibration.time 必须是 ISO 8601 时间"
        ) from None
    if parsed.tzinfo is None:
        raise ValueError("human_calibration.time 必须包含时区")
    old_confidence = _confidence_input(
        value.get("old"), "human_calibration.old"
    )
    new_confidence = _confidence_input(
        value.get("new"), "human_calibration.new"
    )
    if old_confidence is None:
        raise ValueError("human_calibration.old 不能为空")
    if new_confidence is None:
        raise ValueError("human_calibration.new 不能为空")
    return {
        "actor": _text(
            value.get("actor"), "human_calibration.actor", 200
        ),
        "time": parsed.isoformat(),
        "old": old_confidence,
        "new": new_confidence,
        "reason": _text(
            value.get("reason"), "human_calibration.reason", 1000
        ),
    }


def normalize_entity(value: dict) -> dict:
    aliases = value.get("aliases") or []
    if isinstance(aliases, str):
        aliases = [aliases]
    return {
        "name": _text(value.get("name"), "实体名称", 200),
        "kind": _text(value.get("kind") or "unknown", "实体类型", 80),
        "epistemic_status": epistemic_status(value.get("epistemic_status")),
        "evidence_ids": record_ids(value.get("evidence_ids"), required=True),
        "aliases": [
            str(item).strip()[:200]
            for item in aliases
            if str(item).strip()
        ][:50],
        "attributes": value.get("attributes")
        if isinstance(value.get("attributes"), dict)
        else {},
    }


def normalize_relation(value: dict) -> dict:
    return {
        "subject_id": _text(value.get("subject_id"), "关系起点", 80),
        "object_id": _text(value.get("object_id"), "关系终点", 80),
        "predicate": _text(value.get("predicate"), "关系名称", 160),
        "epistemic_status": epistemic_status(value.get("epistemic_status")),
        "evidence_ids": record_ids(value.get("evidence_ids"), required=True),
        "occurred_at": str(value.get("occurred_at") or ""),
        "confidence": _confidence(value.get("confidence", 0.5)),
    }


def normalize_claim(value: dict) -> dict:
    evidence_ids = record_ids(value.get("evidence_ids"), required=True)
    counter_evidence_ids = record_ids(value.get("counter_evidence_ids"))
    return {
        "statement": _text(value.get("statement"), "主张", 5000),
        "epistemic_status": epistemic_status(
            value.get("epistemic_status") or "source_claim"
        ),
        "evidence_ids": evidence_ids,
        "counter_evidence_ids": counter_evidence_ids,
        "conclusion_ids": record_ids(value.get("conclusion_ids")),
        "paragraph_refs": record_ids(value.get("paragraph_refs")),
        "source_health": str(value.get("source_health") or "unknown")[:30],
        "evidence_updated_at": str(value.get("evidence_updated_at") or ""),
        "confidence_status": (
            "calibrated" if len(evidence_ids) >= 2 else "evidence_insufficient"
        ),
    }


def normalize_geo_event(value: dict) -> dict:
    try:
        latitude = float(value.get("latitude"))
        longitude = float(value.get("longitude"))
    except (TypeError, ValueError):
        raise ValueError("经纬度必须是数字") from None
    if not math.isfinite(latitude) or not math.isfinite(longitude):
        raise ValueError("经纬度必须是有限数字")
    if not -90 <= latitude <= 90 or not -180 <= longitude <= 180:
        raise ValueError("经纬度超出有效范围")
    occurred_at = str(
        value.get("occurred_at") or datetime.now(timezone.utc).isoformat()
    )
    try:
        datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("事件时间必须是 ISO 8601 格式") from None
    return {
        "title": _text(value.get("title"), "事件标题", 300),
        "kind": str(value.get("kind") or "event").strip()[:80],
        "latitude": latitude,
        "longitude": longitude,
        "occurred_at": occurred_at,
        "epistemic_status": epistemic_status(value.get("epistemic_status")),
        "evidence_ids": record_ids(value.get("evidence_ids"), required=True),
        "entity_ids": record_ids(value.get("entity_ids")),
        "alert_id": str(value.get("alert_id") or "").strip() or None,
        "case_id": str(value.get("case_id") or "").strip() or None,
    }


def new_case_from_alert(alert_id: str, alert: dict) -> dict:
    return {
        "title": _text(alert.get("title") or "告警转案件", "案件标题", 300),
        "status": "open",
        "source_alert_id": alert_id,
        "evidence_ids": record_ids(alert.get("evidence_ids"), required=True),
        "hypotheses": [],
        "tasks": [],
        "timeline": [
            {
                "kind": "created_from_alert",
                "at": datetime.now(timezone.utc).isoformat(),
                "alert_id": alert_id,
            }
        ],
        "conclusions": [],
        "contradictory_evidence_ids": [],
    }


def apply_case_changes(current: dict, changes: dict) -> dict:
    if current.get("status") == "issued":
        raise ValueError("已签发案件不能直接覆盖，必须先走撤回流程")
    current_conclusions = [
        item
        for item in current.get("conclusions") or []
        if isinstance(item, dict)
    ]
    current_by_id = {
        str(item.get("conclusion_id") or "").strip(): item
        for item in current_conclusions
        if str(item.get("conclusion_id") or "").strip()
    }
    result = dict(current)
    for field in (
        "title",
        "status",
        "evidence_ids",
        "hypotheses",
        "tasks",
        "timeline",
        "conclusions",
        "contradictory_evidence_ids",
    ):
        if field in changes:
            result[field] = changes[field]
    if result.get("status") not in CASE_STATUSES:
        raise ValueError("无效案件状态")
    result["title"] = _text(result.get("title"), "案件标题", 300)
    result["evidence_ids"] = record_ids(
        result.get("evidence_ids"), required=True
    )
    result["contradictory_evidence_ids"] = record_ids(
        result.get("contradictory_evidence_ids")
    )
    conclusions = []
    seen_conclusion_ids = set()
    for index, conclusion in enumerate(result.get("conclusions") or []):
        if not isinstance(conclusion, dict):
            raise ValueError("案件结论格式无效")
        conclusion_id = str(
            conclusion.get("conclusion_id") or ""
        ).strip()[:100]
        previous = current_by_id.get(conclusion_id)
        if previous is None and index < len(current_conclusions):
            previous = current_conclusions[index]
        if not conclusion_id and previous is not None:
            conclusion_id = str(
                previous.get("conclusion_id") or ""
            ).strip()[:100]
        conclusion_id = conclusion_id or str(uuid.uuid4())
        if conclusion_id in seen_conclusion_ids:
            raise ValueError("案件结论 ID 不能重复")
        seen_conclusion_ids.add(conclusion_id)

        evidence_ids = record_ids(
            conclusion.get("evidence_ids"), required=True
        )
        counter_evidence_ids = record_ids(
            conclusion.get("counter_evidence_ids")
        )
        confidence_inputs = conclusion.get("confidence_inputs")
        if not isinstance(confidence_inputs, dict):
            confidence_inputs = {}
        source_weight = _confidence_input(
            confidence_inputs.get(
                "source_weight", conclusion.get("source_weight")
            ),
            "source_weight",
        )
        time_decay = _confidence_input(
            confidence_inputs.get(
                "time_decay", conclusion.get("time_decay")
            ),
            "time_decay",
        )
        independent_source_count = _nonnegative_count(
            confidence_inputs.get(
                "independent_source_count",
                confidence_inputs.get(
                    "corroboration_count",
                    conclusion.get("independent_source_count"),
                ),
            ),
            "independent_source_count",
            default=0,
        )
        counter_evidence_count = _nonnegative_count(
            confidence_inputs.get(
                "counter_evidence_count",
                conclusion.get("counter_evidence_count"),
            ),
            "counter_evidence_count",
            default=len(counter_evidence_ids),
        )
        enough_evidence = (
            len(evidence_ids) >= 2 and independent_source_count >= 2
        )
        raw_confidence = conclusion.get("confidence")
        confidence = (
            _confidence(raw_confidence)
            if enough_evidence
            and raw_confidence is not None
            and raw_confidence != ""
            else None
        )

        history = []
        if previous is not None and isinstance(
            previous.get("human_calibration_history"), list
        ):
            history = copy.deepcopy(
                previous["human_calibration_history"]
            )
        calibration = conclusion.get("human_calibration")
        if calibration is None:
            calibration = confidence_inputs.get("human_calibration")
        if calibration is not None:
            history.append(_normalize_calibration(calibration))

        normalized = {
            **conclusion,
            "conclusion_id": conclusion_id,
            "text": _text(conclusion.get("text"), "案件结论", 5000),
            "epistemic_status": epistemic_status(
                conclusion.get("epistemic_status") or "inference"
            ),
            "evidence_ids": evidence_ids,
            "counter_evidence_ids": counter_evidence_ids,
            "claim_ids": record_ids(conclusion.get("claim_ids")),
            "confidence": confidence,
            "confidence_status": (
                "calibrated"
                if confidence is not None
                else (
                    "awaiting_calibration"
                    if enough_evidence
                    else "evidence_insufficient"
                )
            ),
            "confidence_inputs": {
                "source_weight": source_weight,
                "corroboration_count": len(evidence_ids),
                "independent_source_count": independent_source_count,
                "time_decay": time_decay,
                "counter_evidence_count": counter_evidence_count,
                "human_calibration_note": str(
                    confidence_inputs.get(
                        "human_calibration_note",
                        conclusion.get("human_calibration_note") or "",
                    )
                )[:1000],
            },
            "human_calibration_history": history,
        }
        normalized.pop("human_calibration", None)
        conclusions.append(normalized)
    result["conclusions"] = conclusions
    return result
