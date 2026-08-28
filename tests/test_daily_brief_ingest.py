import hashlib
import io
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import app as tracker


def _payload(edition_date="2026-08-15"):
    return {
        "edition_date": edition_date,
        "expected_count": 5,
        "briefs": [
            {
                "brief": f"brief-{index}",
                "source_material": {
                    "material_text": f"source material {index}",
                    "source_name": f"source-{index}",
                    "source_title": f"source title {index}",
                    "publication_date": "2026-08-14",
                    "publication_date_verified": True,
                    "url": f"https://example.test/{index}",
                },
            }
            for index in range(1, 6)
        ],
    }


@pytest.fixture
def ingest_stubs(monkeypatch):
    source_calls = []
    validation_calls = []
    history_calls = []
    build_calls = []

    def source_context(**kwargs):
        source_calls.append(kwargs)
        publication_date = kwargs.get("publication_date")
        return {
            **kwargs,
            "publication_date": (
                datetime.fromisoformat(publication_date) if publication_date else None
            ),
            "source_aliases": [],
        }

    def validate(brief, *, source_context=None):
        validation_calls.append((brief, source_context))
        index = int(str(brief).split("-", 1)[1].split("-", 1)[0])
        return {
            "valid": True,
            "errors": [],
            "parsed": {
                "event_time": "2026年8月14日",
                "value_point": f"value-{index}",
                "title": f"title-{index}",
                "body": f"body-{index}",
                "source": f"source-{index}",
                "reporter": "报送人：           电话：",
            },
        }

    def find_similar(title, days=7):
        history_calls.append((title, days))
        return []

    def build_one(parsed):
        build_calls.append(("single", parsed["title"]))
        return io.BytesIO(f"docx:{parsed['title']}".encode("utf-8"))

    def build_compiled(parsed_list):
        build_calls.append(("compiled", len(parsed_list)))
        return io.BytesIO(b"compiled-docx")

    monkeypatch.setattr(tracker, "DOCX_AVAILABLE", True)
    monkeypatch.setattr(tracker, "_brief_source_context", source_context)
    monkeypatch.setattr(tracker, "_validate_brief_text", validate)
    monkeypatch.setattr(tracker, "find_similar_generations", find_similar)
    monkeypatch.setattr(tracker, "_build_brief_docx", build_one)
    monkeypatch.setattr(tracker, "_build_brief_docx_compiled", build_compiled)
    return {
        "source_calls": source_calls,
        "validation_calls": validation_calls,
        "history_calls": history_calls,
        "build_calls": build_calls,
    }


def test_ingest_codex_daily_briefs_writes_atomic_six_docx_package(
    tmp_path, ingest_stubs,
):
    now = datetime(2026, 8, 14, 16, 30, tzinfo=timezone.utc)

    result = tracker.ingest_codex_daily_briefs(
        _payload(), output_root=str(tmp_path), now=now,
    )

    final_dir = tmp_path / "20260815"
    documents = sorted(final_dir.glob("*.docx"))
    assert result["status"] == "ok"
    assert result["idempotent"] is False
    assert result["edition_date"] == "2026-08-15"
    assert result["count"] == 5
    assert Path(result["output_dir"]) == final_dir
    assert len(documents) == 6
    assert (final_dir / "要讯汇编_20260815_共5篇.docx").is_file()
    assert len(ingest_stubs["source_calls"]) == 5
    assert len(ingest_stubs["validation_calls"]) == 5
    assert ingest_stubs["history_calls"] == [
        (f"title-{index}", 7) for index in range(1, 6)
    ]

    manifest = json.loads((final_dir / ".codex-ingest.json").read_text(encoding="utf-8"))
    assert manifest["content_sha256"] == result["content_sha256"]
    assert len(manifest["documents"]) == 6
    for entry in manifest["documents"]:
        path = final_dir / entry["name"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"]


def test_ingest_recovery_date_writes_explicitly_dated_package(
    tmp_path, ingest_stubs,
):
    now = datetime(2026, 8, 19, 9, 0)
    payload = _payload("2026-08-15")

    result = tracker.ingest_codex_daily_briefs(
        payload,
        output_root=str(tmp_path),
        now=now,
        recovery_date="2026-08-15",
    )

    final_dir = tmp_path / "20260815"
    assert result["status"] == "ok"
    assert result["ingest_mode"] == "recovery"
    assert result["recovery_date"] == "2026-08-15"
    assert Path(result["output_dir"]) == final_dir
    assert (final_dir / "要讯汇编_20260815_共5篇.docx").is_file()

    manifest = json.loads((final_dir / ".codex-ingest.json").read_text(encoding="utf-8"))
    assert manifest["edition_date"] == "2026-08-15"
    assert manifest["ingest_mode"] == "recovery"
    assert manifest["recovery_date"] == "2026-08-15"
    assert manifest["created_at"].startswith("2026-08-19T09:00:00")


def test_ingest_recovery_accepts_exactly_seven_days_ago(
    tmp_path, ingest_stubs,
):
    result = tracker.ingest_codex_daily_briefs(
        _payload("2026-08-12"),
        output_root=str(tmp_path),
        now=datetime(2026, 8, 19, 9, 0),
        recovery_date="2026-08-12",
    )

    assert result["ingest_mode"] == "recovery"
    assert (tmp_path / "20260812" / "要讯汇编_20260812_共5篇.docx").is_file()


@pytest.mark.parametrize(
    ("edition_date", "recovery_date", "code"),
    [
        ("2026-08-15", "2026-08-14", "recovery_date_mismatch"),
        ("2026-08-19", "2026-08-19", "recovery_date_not_past"),
        ("2026-08-20", "2026-08-20", "recovery_date_not_past"),
        ("2026-08-11", "2026-08-11", "recovery_date_out_of_window"),
        ("2026-08-15", "2026-8-15", "invalid_recovery_date"),
    ],
)
def test_ingest_recovery_rejects_mismatch_nonpast_and_out_of_window_before_writes(
    tmp_path, ingest_stubs, edition_date, recovery_date, code,
):
    with pytest.raises(tracker.DailyBriefIngestError) as caught:
        tracker.ingest_codex_daily_briefs(
            _payload(edition_date),
            output_root=str(tmp_path),
            now=datetime(2026, 8, 19, 9, 0),
            recovery_date=recovery_date,
        )

    assert caught.value.code == code
    assert not tmp_path.exists() or list(tmp_path.iterdir()) == []


def test_ingest_same_content_is_idempotent_without_rebuilding(
    tmp_path, ingest_stubs, monkeypatch,
):
    payload = _payload()
    now = datetime(2026, 8, 15, 9, 0)
    first = tracker.ingest_codex_daily_briefs(
        payload, output_root=str(tmp_path), now=now,
    )
    before = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (tmp_path / "20260815").iterdir()
    }

    monkeypatch.setattr(
        tracker,
        "_build_brief_docx",
        lambda parsed: (_ for _ in ()).throw(AssertionError("must not rebuild")),
    )
    monkeypatch.setattr(
        tracker,
        "_build_brief_docx_compiled",
        lambda parsed: (_ for _ in ()).throw(AssertionError("must not rebuild")),
    )
    second = tracker.ingest_codex_daily_briefs(
        payload, output_root=str(tmp_path), now=now,
    )

    after = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (tmp_path / "20260815").iterdir()
    }
    assert second["status"] == "ok"
    assert second["idempotent"] is True
    assert second["content_sha256"] == first["content_sha256"]
    assert after == before


def test_ingest_same_date_different_content_fails_closed(
    tmp_path, ingest_stubs,
):
    now = datetime(2026, 8, 15, 9, 0)
    tracker.ingest_codex_daily_briefs(
        _payload(), output_root=str(tmp_path), now=now,
    )
    before = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (tmp_path / "20260815").iterdir()
    }
    changed = _payload()
    changed["briefs"][0]["brief"] = "brief-1-changed"

    with pytest.raises(tracker.DailyBriefIngestError) as caught:
        tracker.ingest_codex_daily_briefs(
            changed, output_root=str(tmp_path), now=now,
        )

    after = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (tmp_path / "20260815").iterdir()
    }
    assert caught.value.code == "edition_conflict"
    assert after == before


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda payload: payload.update(expected_count=4), "invalid_count"),
        (lambda payload: payload["briefs"].pop(), "invalid_count"),
        (lambda payload: payload.update(edition_date="2026-08-14"), "date_mismatch"),
    ],
)
def test_ingest_rejects_wrong_count_or_shanghai_date_before_writes(
    tmp_path, ingest_stubs, mutate, code,
):
    payload = _payload()
    mutate(payload)

    with pytest.raises(tracker.DailyBriefIngestError) as caught:
        tracker.ingest_codex_daily_briefs(
            payload,
            output_root=str(tmp_path),
            now=datetime(2026, 8, 14, 16, 30, tzinfo=timezone.utc),
        )

    assert caught.value.code == code
    assert not tmp_path.exists() or list(tmp_path.iterdir()) == []


def test_ingest_rejects_batch_and_history_duplicates_before_writes(
    tmp_path, ingest_stubs, monkeypatch,
):
    payload = _payload()

    original_validate = tracker._validate_brief_text

    def duplicate_title(brief, *, source_context=None):
        result = original_validate(brief, source_context=source_context)
        if brief == "brief-2":
            result["parsed"]["title"] = "title-1"
        return result

    monkeypatch.setattr(tracker, "_validate_brief_text", duplicate_title)
    with pytest.raises(tracker.DailyBriefIngestError) as batch_error:
        tracker.ingest_codex_daily_briefs(
            payload, output_root=str(tmp_path), now=datetime(2026, 8, 15, 9),
        )
    assert batch_error.value.code == "duplicate_title"
    assert not (tmp_path / "20260815").exists()

    monkeypatch.setattr(tracker, "_validate_brief_text", original_validate)
    monkeypatch.setattr(
        tracker,
        "find_similar_generations",
        lambda title, days=7: [{"title": title}] if title == "title-3" else [],
    )
    with pytest.raises(tracker.DailyBriefIngestError) as history_error:
        tracker.ingest_codex_daily_briefs(
            payload, output_root=str(tmp_path), now=datetime(2026, 8, 15, 9),
        )
    assert history_error.value.code == "recent_duplicate"
    assert not (tmp_path / "20260815").exists()


def test_ingest_validation_build_and_write_failures_leave_no_final_package(
    tmp_path, ingest_stubs, monkeypatch,
):
    payload = _payload()
    now = datetime(2026, 8, 15, 9)

    original_validate = tracker._validate_brief_text

    def reject_fourth(brief, *, source_context=None):
        result = original_validate(brief, source_context=source_context)
        if brief == "brief-4":
            result.update(valid=False, errors=["invalid brief"])
        return result

    monkeypatch.setattr(tracker, "_validate_brief_text", reject_fourth)
    with pytest.raises(tracker.DailyBriefIngestError) as validation_error:
        tracker.ingest_codex_daily_briefs(
            payload, output_root=str(tmp_path), now=now,
        )
    assert validation_error.value.code == "validation_failed"
    assert not (tmp_path / "20260815").exists()

    monkeypatch.setattr(tracker, "_validate_brief_text", original_validate)
    monkeypatch.setattr(
        tracker,
        "_build_brief_docx_compiled",
        lambda parsed: (_ for _ in ()).throw(OSError("build failed")),
    )
    with pytest.raises(tracker.DailyBriefIngestError) as build_error:
        tracker.ingest_codex_daily_briefs(
            payload, output_root=str(tmp_path), now=now,
        )
    assert build_error.value.code == "document_build_failed"
    assert not (tmp_path / "20260815").exists()
    assert not [path for path in tmp_path.iterdir() if path.name.startswith(".20260815-")]

    monkeypatch.setattr(
        tracker,
        "_build_brief_docx_compiled",
        lambda parsed: io.BytesIO(b"compiled-docx"),
    )
    original_write = tracker._write_daily_brief_ingest_file
    writes = []

    def fail_third(path, content):
        writes.append(path)
        if len(writes) == 3:
            raise OSError("write failed")
        return original_write(path, content)

    monkeypatch.setattr(tracker, "_write_daily_brief_ingest_file", fail_third)
    with pytest.raises(tracker.DailyBriefIngestError) as write_error:
        tracker.ingest_codex_daily_briefs(
            payload, output_root=str(tmp_path), now=now,
        )
    assert write_error.value.code == "package_write_failed"
    assert not (tmp_path / "20260815").exists()
    assert not [path for path in tmp_path.iterdir() if path.name.startswith(".20260815-")]


def test_ingest_cli_prints_one_safe_json_line(monkeypatch, tmp_path):
    from scripts import ingest_daily_briefs as cli

    input_path = tmp_path / "input.json"
    input_path.write_text(json.dumps(_payload(), ensure_ascii=False), encoding="utf-8")
    local_output = tmp_path / "private" / "20260815"
    monkeypatch.setattr(
        cli.tracker,
        "ingest_codex_daily_briefs",
        lambda payload, expected_count=5, output_root=None, recovery_date=None: {
            "status": "ok",
            "idempotent": False,
            "edition_date": "2026-08-15",
            "ingest_mode": "recovery",
            "recovery_date": recovery_date,
            "count": 5,
            "output_dir": str(local_output),
            "documents": [str(local_output / f"{index}.docx") for index in range(6)],
            "content_sha256": "a" * 64,
        },
    )
    stdout = io.StringIO()

    exit_code = cli.main(
        [str(input_path), "--recovery-date", "2026-08-15"], stdout=stdout,
    )

    lines = stdout.getvalue().splitlines()
    assert exit_code == 0
    assert len(lines) == 1
    result = json.loads(lines[0])
    assert result["status"] == "ok"
    assert result["ingest_mode"] == "recovery"
    assert result["recovery_date"] == "2026-08-15"
    assert result["output_dir"] == "20260815"
    assert str(tmp_path) not in lines[0]


def test_ingest_cli_returns_nonzero_safe_json_for_unexpected_failure(
    monkeypatch, tmp_path,
):
    from scripts import ingest_daily_briefs as cli

    input_path = tmp_path / "input.json"
    input_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        cli.tracker,
        "ingest_codex_daily_briefs",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("secret-value")),
    )
    stdout = io.StringIO()

    exit_code = cli.main([str(input_path)], stdout=stdout)

    lines = stdout.getvalue().splitlines()
    assert exit_code != 0
    assert len(lines) == 1
    result = json.loads(lines[0])
    assert result == {
        "status": "failed",
        "error": {"code": "internal_error", "message": "要讯落盘发生内部错误"},
    }
    assert "secret-value" not in lines[0]


def test_ingest_cli_argument_error_is_also_one_json_line():
    from scripts import ingest_daily_briefs as cli

    stdout = io.StringIO()

    exit_code = cli.main([], stdout=stdout)

    lines = stdout.getvalue().splitlines()
    assert exit_code != 0
    assert len(lines) == 1
    assert json.loads(lines[0]) == {
        "status": "failed",
        "error": {"code": "invalid_arguments", "message": "要讯落盘命令参数无效"},
    }
