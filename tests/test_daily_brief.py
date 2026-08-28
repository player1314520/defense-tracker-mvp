from datetime import datetime, timezone
from pathlib import Path

import pytest

import app as tracker


def _daily_valid_brief():
    hat = (
        "据美国防务新闻报道，美军8月14日在西太平洋组织联合演训，投入水面舰艇、战机和无人侦察平台，"
        "重点检验跨域指挥、远程火力协同及前沿保障能力，并宣布后续将扩大盟军参与范围和演训频次。"
    )
    body = (
        hat
        + "（1）演训强化美军跨域兵力协同和前沿快速集结能力，将增加我周边海空方向的常态化戒备压力。"
        + "（2）盟军扩大参与将推动情报共享、基地保障和武器接口进一步整合，压缩地区危机管控空间。"
        + "（3）相关安排反映美方试图以高频演训塑造长期军事存在，需研判其后续兵力部署和作战概念变化。"
        + "建议持续跟踪美军联合演训的兵力规模、课目设置、盟军参与，针对性加强海空预警、联合指挥、远程拒止能力建设。"
    )
    return "\n".join([
        "事件时间：2026年8月14日",
        "价 值 点：相关演训强化美军跨域协同与前沿存在，对我周边海空安全形成持续压力。",
        "",
        "美军联合演训动向值得关注",
        "",
        body,
        "",
        "（信息来源：美国防务新闻8月14日发文《美军在西太平洋组织联合演训》）",
        "报送人：           电话：",
    ])

def _daily_article(index=1):
    return {
        "title": f"candidate-{index}",
        "summary": "美国防务新闻2026年8月14日报道，美军8月14日在西太平洋组织联合演训。",
        "source": "Defense News",
        "source_cn": "美国防务新闻",
        "link": f"https://example.test/{index}",
        "date": "2026-08-14T00:00:00+00:00",
        "publication_date_verified": True,
    }

def test_brief_docx_removes_generator_metadata():
    from docx import Document

    parsed = tracker._parse_brief_text(_daily_valid_brief())
    documents = [
        Document(tracker._build_brief_docx(parsed)),
        Document(tracker._build_brief_docx_compiled([parsed])),
    ]

    for document in documents:
        assert document.core_properties.author == ""
        assert document.core_properties.last_modified_by == ""

def test_load_email_config_from_gmail_env(monkeypatch, tmp_path):
    monkeypatch.setattr(tracker, "_EMAIL_CONFIG_FILE", str(tmp_path / ".email_config.json"), raising=False)
    monkeypatch.setenv("GMAIL_SMTP_USER", "sender@example.test")
    monkeypatch.setenv("GMAIL_APP_PASSWORD", "app-password")
    monkeypatch.setenv("EMAIL_TO", "daily-one@example.test; daily-two@example.test")

    config = tracker._load_email_config()

    assert config["enabled"] is True
    assert config["smtp_host"] == "smtp.gmail.com"
    assert config["smtp_port"] == 465
    assert config["smtp_user"] == "sender@example.test"
    assert config["smtp_password"] == "app-password"
    assert config["from_addr"] == "sender@example.test"
    assert config["to_addrs"] == ["daily-one@example.test", "daily-two@example.test"]


def test_run_daily_brief_job_saves_to_desktop_folder_without_email_by_default(monkeypatch, tmp_path):
    now = datetime(2026, 6, 4, 22, 0, 0)
    articles = [_daily_article(i) for i in range(1, 8)]
    sent = []

    monkeypatch.setattr(tracker, "_DAILY_BRIEF_OUTPUT_ROOT", str(tmp_path / "Desktop" / "每日自动要讯"), raising=False)
    monkeypatch.setattr(tracker, "refresh_news", lambda: None)
    monkeypatch.setattr(tracker, "select_brief_candidates", lambda top_n, include_prc=False: articles[:top_n])
    monkeypatch.setattr(tracker, "find_similar_generations", lambda title, days=7: [])
    monkeypatch.setattr(tracker, "EMAIL_CONFIG", {
        "enabled": True,
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 465,
        "smtp_user": "sender@example.test",
        "smtp_password": "app-password",
        "from_addr": "sender@example.test",
        "to_addrs": ["daily@example.test"],
    }, raising=False)

    def fake_generate(article, output_dir=None, now=None):
        path = Path(output_dir) / f"{article['title']}.docx"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"docx")
        return {
            "brief": _daily_valid_brief(),
            "saved_to": str(path),
            "source_article": article,
            "validation": {"valid": True, "errors": []},
        }

    def fake_send(summary, attachment_paths, email_config=None):
        sent.append({"summary": summary, "attachment_paths": attachment_paths, "email_config": email_config})
        return {"sent": True, "to": email_config["to_addrs"]}

    monkeypatch.setattr(tracker, "_generate_brief_for_article", fake_generate, raising=False)
    monkeypatch.setattr(tracker, "_send_daily_brief_email", fake_send, raising=False)

    result = tracker.run_daily_brief_job(now=now)

    daily_dir = tmp_path / "Desktop" / "每日自动要讯" / "20260604"
    compiled_path = daily_dir / "要讯汇编_20260604_共5篇.docx"

    assert result["status"] == "ok"
    assert result["count"] == 5
    assert result["output_dir"] == str(daily_dir)
    assert result["compiled_path"] == str(compiled_path)
    assert compiled_path.exists()
    assert len(list(daily_dir.glob("candidate-*.docx"))) == 5
    assert result["email"] == {"sent": False, "reason": "email_disabled"}
    assert sent == []


def test_generate_brief_validation_failure_does_not_persist(monkeypatch, tmp_path):
    monkeypatch.setattr(tracker, "AI_CONFIG", {"api_key": "configured", "model": "test-model"})
    monkeypatch.setattr(tracker, "_call_ai", lambda messages, temperature=0.4: "invalid brief")
    monkeypatch.setattr(
        tracker,
        "_validate_brief_text",
        lambda brief, **kwargs: {"valid": False, "errors": ["body too short"], "parsed": {}},
    )

    persisted = []
    recorded = []
    monkeypatch.setattr(
        tracker,
        "_persist_brief_to_disk",
        lambda *args, **kwargs: persisted.append((args, kwargs)),
    )
    monkeypatch.setattr(
        tracker,
        "record_quality_generation",
        lambda *args, **kwargs: recorded.append((args, kwargs)),
    )

    with pytest.raises(ValueError, match="body too short"):
        tracker._generate_brief_for_article(
            {"title": "candidate", "source": "Unit Test", "link": "https://example.test/1"},
            output_dir=str(tmp_path),
            now=datetime(2026, 8, 14, 22, 0, 0),
        )

    assert persisted == []
    assert recorded == []
    assert list(tmp_path.iterdir()) == []

def test_run_daily_brief_job_uses_seven_day_dedupe_and_fails_closed_when_short(monkeypatch, tmp_path):
    now = datetime(2026, 8, 14, 22, 0, 0)
    articles = [
        {"title": "duplicate topic", "source": "Unit Test", "link": "https://example.test/duplicate"},
        {"title": "unique topic", "source": "Unit Test", "link": "https://example.test/unique"},
    ]
    dedupe_calls = []

    monkeypatch.setattr(tracker, "_DAILY_BRIEF_OUTPUT_ROOT", str(tmp_path / "daily"), raising=False)
    monkeypatch.setattr(tracker, "refresh_news", lambda: None)
    monkeypatch.setattr(tracker, "select_brief_candidates", lambda top_n, include_prc=False: articles)

    def fake_find(title, days=7):
        dedupe_calls.append((title, days))
        return [{"title": title, "similarity": 1.0}] if title == "duplicate topic" else []

    def fake_generate(article, output_dir=None, now=None):
        return {
            "brief": "valid brief",
            "saved_to": str(Path(output_dir) / "unique.docx"),
            "source_article": article,
            "validation": {"valid": True, "errors": []},
        }

    monkeypatch.setattr(tracker, "find_similar_generations", fake_find)
    monkeypatch.setattr(tracker, "_generate_brief_for_article", fake_generate)
    monkeypatch.setattr(
        tracker,
        "_write_daily_compiled_docx",
        lambda briefs, output_dir, now=None: str(Path(output_dir) / "compiled.docx"),
    )

    result = tracker.run_daily_brief_job(count=2, now=now)

    assert dedupe_calls == [("duplicate topic", 7), ("unique topic", 7)]
    assert result["status"] == "partial"
    assert result["count"] == 1
    assert result["requested_count"] == 2
    assert result["skipped_duplicates"][0]["title"] == "duplicate topic"
    assert any(error["stage"] == "selection" for error in result["errors"])

def test_run_daily_brief_job_rejects_invalid_generation_result(monkeypatch, tmp_path):
    article = {"title": "candidate", "source": "Unit Test", "link": "https://example.test/1"}
    monkeypatch.setattr(tracker, "_DAILY_BRIEF_OUTPUT_ROOT", str(tmp_path / "daily"), raising=False)
    monkeypatch.setattr(tracker, "refresh_news", lambda: None)
    monkeypatch.setattr(tracker, "select_brief_candidates", lambda top_n, include_prc=False: [article])
    monkeypatch.setattr(tracker, "find_similar_generations", lambda title, days=7: [])
    monkeypatch.setattr(
        tracker,
        "_generate_brief_for_article",
        lambda article, output_dir=None, now=None: {
            "brief": "invalid brief",
            "saved_to": "must-not-be-published.docx",
            "source_article": article,
            "validation": {"valid": False, "errors": ["invalid format"]},
        },
    )
    compile_calls = []
    monkeypatch.setattr(
        tracker,
        "_write_daily_compiled_docx",
        lambda *args, **kwargs: compile_calls.append((args, kwargs)),
    )

    result = tracker.run_daily_brief_job(count=1, now=datetime(2026, 8, 14, 22, 0, 0))

    assert result["status"] == "failed"
    assert result["count"] == 0
    assert result["compiled_path"] == ""
    assert any(error["stage"] == "validation" for error in result["errors"])
    assert compile_calls == []

def test_run_daily_brief_job_reports_compile_exception(monkeypatch, tmp_path):
    article = {"title": "candidate", "source": "Unit Test", "link": "https://example.test/1"}
    monkeypatch.setattr(tracker, "_DAILY_BRIEF_OUTPUT_ROOT", str(tmp_path / "daily"), raising=False)
    monkeypatch.setattr(tracker, "refresh_news", lambda: None)
    monkeypatch.setattr(tracker, "select_brief_candidates", lambda top_n, include_prc=False: [article])
    monkeypatch.setattr(tracker, "find_similar_generations", lambda title, days=7: [])
    monkeypatch.setattr(
        tracker,
        "_generate_brief_for_article",
        lambda article, output_dir=None, now=None: {
            "brief": "valid brief",
            "saved_to": str(Path(output_dir) / "candidate.docx"),
            "source_article": article,
            "validation": {"valid": True, "errors": []},
        },
    )

    def fail_compile(*args, **kwargs):
        raise OSError("compiled write failed")

    monkeypatch.setattr(tracker, "_write_daily_compiled_docx", fail_compile)

    result = tracker.run_daily_brief_job(count=1, now=datetime(2026, 8, 14, 22, 0, 0))

    assert result["status"] == "partial"
    assert result["count"] == 1
    assert result["compiled_path"] == ""
    assert any(
        error["stage"] == "compile" and "compiled write failed" in error["error"]
        for error in result["errors"]
    )

def test_daily_brief_date_is_derived_in_asia_shanghai(monkeypatch, tmp_path):
    monkeypatch.setattr(tracker, "_DAILY_BRIEF_OUTPUT_ROOT", str(tmp_path / "daily"), raising=False)

    utc_time = datetime(2026, 8, 14, 16, 30, tzinfo=timezone.utc)

    assert tracker._daily_brief_output_dir(utc_time) == str(tmp_path / "daily" / "20260815")
    assert tracker._daily_brief_now(utc_time).isoformat().endswith("+08:00")

def test_write_daily_compiled_docx_does_not_swallow_build_exception(monkeypatch, tmp_path):
    monkeypatch.setattr(tracker, "DOCX_AVAILABLE", True)
    monkeypatch.setattr(
        tracker,
        "_validate_brief_text",
        lambda brief, **kwargs: {
            "valid": True,
            "errors": [],
            "parsed": tracker._parse_brief_text(_daily_valid_brief()),
        },
    )
    monkeypatch.setattr(
        tracker,
        "_build_brief_docx_compiled",
        lambda parsed_list: (_ for _ in ()).throw(OSError("build failed")),
    )

    with pytest.raises(OSError, match="build failed"):
        tracker._write_daily_compiled_docx(
            [{"brief": "brief", "source_article": {"title": "candidate"}}],
            str(tmp_path),
            now=datetime(2026, 8, 14, 22, 0, 0),
        )

def test_write_daily_compiled_docx_revalidates_before_creating_output(monkeypatch, tmp_path):
    monkeypatch.setattr(tracker, "DOCX_AVAILABLE", True)

    with pytest.raises(ValueError, match="汇编第1篇要讯校验未通过"):
        tracker._write_daily_compiled_docx(
            [{"brief": "invalid brief", "source_article": _daily_article()}],
            str(tmp_path / "compiled"),
            now=datetime(2026, 8, 14, 22, 0, 0),
        )

    assert not (tmp_path / "compiled").exists()

def test_add_background_jobs_registers_only_refresh_by_default(monkeypatch):
    monkeypatch.delenv("ENABLE_LEGACY_AI_DAILY_BRIEF", raising=False)
    jobs = []

    class FakeScheduler:
        def add_job(self, func, trigger, **kwargs):
            jobs.append({"func": func, "trigger": trigger, **kwargs})

    tracker.add_background_jobs(FakeScheduler())

    assert jobs[0]["func"] is tracker.refresh_news
    assert jobs[0]["trigger"] == "interval"
    assert jobs[0]["minutes"] == 30
    assert jobs[0]["id"] == "refresh"

    assert len(jobs) == 1

def test_add_background_jobs_registers_legacy_daily_brief_only_when_explicitly_enabled(monkeypatch):
    monkeypatch.setenv("ENABLE_LEGACY_AI_DAILY_BRIEF", "1")
    jobs = []

    class FakeScheduler:
        def add_job(self, func, trigger, **kwargs):
            jobs.append({"func": func, "trigger": trigger, **kwargs})

    tracker.add_background_jobs(FakeScheduler())

    assert jobs[0]["func"] is tracker.refresh_news
    assert jobs[1]["func"] is tracker.run_daily_brief_job
    assert jobs[1]["trigger"] == "cron"
    assert jobs[1]["hour"] == 22
    assert jobs[1]["minute"] == 0
    assert jobs[1]["timezone"] == "Asia/Shanghai"
    assert jobs[1]["id"] == "daily_brief_2200"
    assert jobs[1]["max_instances"] == 1

@pytest.mark.parametrize(
    ("force", "run_scheduler"),
    [(True, None), (False, "1")],
    ids=["forced-dev-start", "run-scheduler-env"],
)
def test_scheduler_start_keeps_legacy_daily_brief_disabled_by_default(
    monkeypatch, force, run_scheduler
):
    monkeypatch.delenv("ENABLE_LEGACY_AI_DAILY_BRIEF", raising=False)
    if run_scheduler is None:
        monkeypatch.delenv("RUN_SCHEDULER", raising=False)
    else:
        monkeypatch.setenv("RUN_SCHEDULER", run_scheduler)

    jobs = []
    started = []
    refresh_threads = []

    class FakeScheduler:
        def __init__(self, daemon):
            assert daemon is True

        def add_job(self, func, trigger, **kwargs):
            jobs.append({"func": func, "trigger": trigger, **kwargs})

        def start(self):
            started.append(True)

    class FakeThread:
        def __init__(self, *, target, daemon):
            assert daemon is True
            refresh_threads.append(target)

        def start(self):
            return None

    monkeypatch.setattr(tracker, "BackgroundScheduler", FakeScheduler)
    monkeypatch.setattr(tracker.threading, "Thread", FakeThread)
    monkeypatch.setattr(tracker.app, "_scheduler_started", False, raising=False)

    tracker._start_scheduler_once(force=force)

    assert started == [True]
    assert refresh_threads == [tracker.refresh_news]
    assert [job["id"] for job in jobs] == ["refresh"]
