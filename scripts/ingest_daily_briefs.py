# -*- coding: utf-8 -*-
"""Deterministically validate and persist five Codex-authored daily briefs."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import app as tracker  # noqa: E402


_MAX_INPUT_BYTES = 8 * 1024 * 1024


class _CliArgumentError(ValueError):
    pass


class _JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise _CliArgumentError(message)


def _emit(stdout, payload: dict) -> None:
    stdout.write(json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ) + "\n")


def _safe_success(result: dict) -> dict:
    return {
        "status": "ok",
        "idempotent": result.get("idempotent") is True,
        "edition_date": result.get("edition_date"),
        "ingest_mode": result.get("ingest_mode"),
        "recovery_date": result.get("recovery_date"),
        "count": result.get("count"),
        "output_dir": os.path.basename(str(result.get("output_dir") or "")),
        "documents": [
            os.path.basename(str(path)) for path in (result.get("documents") or [])
        ],
        "content_sha256": result.get("content_sha256"),
    }


def _parser() -> argparse.ArgumentParser:
    parser = _JsonArgumentParser(
        description="校验并原子落盘 Codex 已写好的当日5篇防务要讯",
    )
    parser.add_argument("input_json", help="UTF-8 JSON 输入文件")
    parser.add_argument(
        "--output-root",
        help="输出根目录；默认使用应用的每日自动要讯目录",
    )
    parser.add_argument(
        "--recovery-date",
        help="显式恢复近7天内的漏跑日期（YYYY-MM-DD），必须与输入edition_date一致",
    )
    return parser


def main(argv=None, *, stdout=None) -> int:
    stdout = stdout or sys.stdout
    try:
        args = _parser().parse_args(argv)
    except _CliArgumentError:
        _emit(stdout, {
            "status": "failed",
            "error": {"code": "invalid_arguments", "message": "要讯落盘命令参数无效"},
        })
        return 2
    try:
        input_path = Path(args.input_json)
        if input_path.stat().st_size > _MAX_INPUT_BYTES:
            raise ValueError("input_too_large")
        with input_path.open("r", encoding="utf-8-sig") as handle:
            payload = json.load(handle)
    except (OSError, ValueError, TypeError):
        _emit(stdout, {
            "status": "failed",
            "error": {"code": "invalid_input", "message": "无法读取有效的要讯JSON输入"},
        })
        return 2

    try:
        result = tracker.ingest_codex_daily_briefs(
            payload,
            expected_count=5,
            output_root=args.output_root,
            recovery_date=args.recovery_date,
        )
    except tracker.DailyBriefIngestError as exc:
        _emit(stdout, {
            "status": "failed",
            "error": {"code": exc.code, "message": exc.safe_message},
        })
        return 1
    except Exception:
        _emit(stdout, {
            "status": "failed",
            "error": {"code": "internal_error", "message": "要讯落盘发生内部错误"},
        })
        return 1

    _emit(stdout, _safe_success(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
