from datetime import datetime
from pathlib import Path

import app as tracker


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
    articles = [
        {"title": f"candidate-{i}", "source": "Unit Test", "link": f"https://example.test/{i}"}
        for i in range(1, 8)
    ]
    sent = []

    monkeypatch.setattr(tracker, "_DAILY_BRIEF_OUTPUT_ROOT", str(tmp_path / "Desktop" / "每日自动要讯"), raising=False)
    monkeypatch.setattr(tracker, "refresh_news", lambda: None)
    monkeypatch.setattr(tracker, "select_brief_candidates", lambda top_n, include_prc=False: articles[:top_n])
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
            "brief": f"brief for {article['title']}",
            "saved_to": str(path),
            "source_article": {"title": article["title"], "source": article["source"], "link": article["link"]},
            "validation": {"ok": True},
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


def test_add_background_jobs_registers_refresh_and_daily_brief():
    jobs = []

    class FakeScheduler:
        def add_job(self, func, trigger, **kwargs):
            jobs.append({"func": func, "trigger": trigger, **kwargs})

    tracker.add_background_jobs(FakeScheduler())

    assert jobs[0]["func"] is tracker.refresh_news
    assert jobs[0]["trigger"] == "interval"
    assert jobs[0]["minutes"] == 30
    assert jobs[0]["id"] == "refresh"
    assert jobs[1]["func"] is tracker.run_daily_brief_job
    assert jobs[1]["trigger"] == "cron"
    assert jobs[1]["hour"] == 22
    assert jobs[1]["minute"] == 0
    assert jobs[1]["id"] == "daily_brief_2200"
    assert jobs[1]["max_instances"] == 1
