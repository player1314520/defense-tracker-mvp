# -*- coding: utf-8 -*-
"""Phase 2 自主取证端点：搜索未配时优雅降级（不硬凑，明确报缺口）。"""
import app as tracker
import report_agent
import consulting_agent
import search_adapters


def _login(client, csrf="csrf-test-token"):
    client.set_cookie(tracker.AUTH_COOKIE, tracker.ACCESS_TOKEN)
    client.set_cookie(tracker.CSRF_COOKIE, csrf)
    return csrf


def test_autonomous_collect_degrades_gracefully_without_search(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    monkeypatch.setattr(consulting_agent, "CONSULTING_AGENT_DB_FILE", str(tmp_path / "consult.sqlite3"))
    monkeypatch.setattr(consulting_agent, "SOURCE_ARCHIVE_DIR", str(tmp_path / "source_archive"), raising=False)
    # 模拟联网搜索禁用/无结果：每轮空手而归（确定性、不打真实网络；public_web 无 key 也能抓，故须 mock）
    monkeypatch.setattr(search_adapters, "search_web_multi",
                        lambda *a, **k: ([], {"deduped_count": 0, "search_calls": 0,
                                              "provider_stats": {}, "queries": [], "rejected_low_relevance": 0}))
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login(client)

    proj = client.post(
        "/api/agent/projects",
        json={"request": "帮我做一个南海军力评估报告，搜集6份信息源"},
        headers={tracker.CSRF_HEADER: csrf},
    ).get_json()["project"]

    resp = client.post(
        f"/api/agent/projects/{proj['project_id']}/autonomous_collect",
        json={"target": 6, "max_rounds": 2},
        headers={tracker.CSRF_HEADER: csrf},
    )
    data = resp.get_json()

    assert resp.status_code == 200
    assert data["ok"] is True
    assert data["session_id"].startswith("cs")     # 已起 consulting 会话
    assert data["imported_count"] == 0             # 无搜索→无归档→无导入
    assert data["gap"] == 6
    assert "缺口未补齐" in data["gap_note"]          # 明确报缺口，绝不硬凑


def test_autonomous_collect_unknown_project_errors(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    monkeypatch.setattr(consulting_agent, "CONSULTING_AGENT_DB_FILE", str(tmp_path / "consult.sqlite3"))
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login(client)

    resp = client.post(
        "/api/agent/projects/rp_does_not_exist/autonomous_collect",
        json={"target": 3},
        headers={tracker.CSRF_HEADER: csrf},
    )
    assert resp.status_code >= 400
