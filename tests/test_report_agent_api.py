from datetime import datetime, timezone

import app as tracker
import report_agent


def _login_cookies(client, csrf="csrf-test-token"):
    client.set_cookie(tracker.AUTH_COOKIE, tracker.ACCESS_TOKEN)
    client.set_cookie(tracker.CSRF_COOKIE, csrf)
    return csrf


def _candidate():
    return {
        "article_id": "api-article-001",
        "title": "解放军台海联合演训值得警惕",
        "summary": "公开报道显示，解放军近日围绕台海方向组织联合演训。",
        "source": "Unit Source",
        "source_cn": "测试信源",
        "link": "https://example.test/api-article-001",
        "date": datetime.now(timezone.utc).isoformat(),
        "quality_score": 88,
        "quality_level": "S",
        "quality_reasons": ["高权威信源"],
        "brief_hits": ["PLA备战"],
    }


def test_agent_project_create_requires_csrf_and_accepts_valid(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login_cookies(client)

    blocked = client.post("/api/agent/projects", json={"request": "帮我做一个台海军力平衡报告"})
    assert blocked.status_code == 403

    ok = client.post(
        "/api/agent/projects",
        json={"request": "帮我做一个台海军力平衡报告"},
        headers={tracker.CSRF_HEADER: csrf},
    )
    data = ok.get_json()

    assert ok.status_code == 200
    assert data["project"]["title"] == "台海军力平衡战略分析报告"
    assert data["project"]["topic"] == "台海军力平衡"
    assert data["project"]["report_type"] == "strategic"
    assert data["project"]["target_count"] == 12


def test_agent_collect_imports_quality_candidates(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    monkeypatch.setattr(tracker, "select_quality_candidates", lambda **kwargs: ([_candidate()], {"total_scored": 1}))
    monkeypatch.setattr(tracker, "THINK_TANK_DIRECTORY", [
        {
            "id": "pla_research",
            "category": "PLA专项研究机构",
            "sites": [
                {
                    "name": "RAND China Research",
                    "name_cn": "兰德中国研究",
                    "url": "https://www.rand.org/topics/china.html",
                    "desc_cn": "中国军事现代化与联合作战能力报告",
                    "desc_en": "China military modernization reports",
                }
            ],
        }
    ])
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login_cookies(client)
    project = report_agent.create_project("军事现代化战略分析报告", "strategic", topic="军事现代化")

    resp = client.post(
        f"/api/agent/projects/{project['project_id']}/collect",
        json={"limit": 5, "min_level": "A"},
        headers={tracker.CSRF_HEADER: csrf},
    )
    data = resp.get_json()

    assert resp.status_code == 200
    assert data["total"] == 2
    assert data["evidence"][0]["source"] == "Unit Source"
    assert data["evidence"][0]["quality_score"] == 88
    assert any(ev["source_type"] == "智库/报告源" for ev in data["evidence"])
    assert data["meta"]["total_scored"] == 1
    assert data["meta"]["source_seeds"] == 1


def test_agent_collect_uses_large_requested_sources_by_default(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    monkeypatch.setattr(tracker, "select_quality_candidates", lambda **kwargs: ([], {"total_scored": 0}))
    monkeypatch.setattr(tracker, "THINK_TANK_DIRECTORY", [{
        "id": "pla_research",
        "category": "PLA专项研究机构",
        "sites": [
            {
                "name": f"Source {i}",
                "name_cn": f"报告源{i}",
                "url": f"https://example.test/source-{i}",
                "desc_cn": "台海军力平衡长期研究报告",
                "desc_en": "Taiwan balance report",
            }
            for i in range(130)
        ],
    }])
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login_cookies(client)

    created = client.post(
        "/api/agent/projects",
        json={"request": "帮我做一个台海军力平衡报告，搜集120份信息源"},
        headers={tracker.CSRF_HEADER: csrf},
    )
    project = created.get_json()["project"]
    resp = client.post(
        f"/api/agent/projects/{project['project_id']}/collect",
        json={"min_level": "A"},
        headers={tracker.CSRF_HEADER: csrf},
    )
    data = resp.get_json()

    assert project["target_count"] == 120
    assert resp.status_code == 200
    assert data["total"] == 120
    assert data["meta"]["source_seeds"] == 120


def test_agent_collect_keeps_total_at_requested_count_when_sources_and_rss_overlap(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    rss_candidates = [
        {
            **_candidate(),
            "article_id": f"rss-{i}",
            "title": f"RSS信息源{i}",
            "link": f"https://example.test/rss-{i}",
        }
        for i in range(10)
    ]
    monkeypatch.setattr(tracker, "select_quality_candidates", lambda **kwargs: (rss_candidates, {"total_scored": 10}))
    monkeypatch.setattr(tracker, "THINK_TANK_DIRECTORY", [{
        "id": "pla_research",
        "category": "PLA专项研究机构",
        "sites": [
            {
                "name": f"Source {i}",
                "name_cn": f"报告源{i}",
                "url": f"https://example.test/source-{i}",
                "desc_cn": "台海军力平衡长期研究报告",
                "desc_en": "Taiwan balance report",
            }
            for i in range(30)
        ],
    }])
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login_cookies(client)

    created = client.post(
        "/api/agent/projects",
        json={"request": "帮我做一个台海军力平衡报告，搜集20份信息源"},
        headers={tracker.CSRF_HEADER: csrf},
    )
    project = created.get_json()["project"]
    resp = client.post(
        f"/api/agent/projects/{project['project_id']}/collect",
        json={"min_level": "A"},
        headers={tracker.CSRF_HEADER: csrf},
    )
    data = resp.get_json()

    assert resp.status_code == 200
    assert project["target_count"] == 20
    assert data["total"] == 20
    assert data["meta"]["source_seeds"] == 10


def test_agent_draft_uses_mocked_ai_and_records_draft(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    old_config = dict(tracker.AI_CONFIG)
    tracker.AI_CONFIG.update({"api_key": "unit-key", "model": "unit-model"})
    calls = []

    def fake_call_ai(messages, temperature=None, max_tokens=None):
        calls.append({"messages": messages, "temperature": temperature, "max_tokens": max_tokens})
        return "## 核心判断\n台海方向联合演训值得持续跟踪。\n\n## 来源附录\n- Unit Source"

    monkeypatch.setattr(tracker, "_call_ai", fake_call_ai)
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login_cookies(client)
    project = report_agent.create_project("台海战略分析报告", "strategic")
    evidence = report_agent.upsert_project_evidence(project["project_id"], [_candidate()])

    try:
        resp = client.post(
            f"/api/agent/projects/{project['project_id']}/draft",
            json={"evidence_ids": [evidence[0]["evidence_id"]], "voice": "strategic_analysis"},
            headers={tracker.CSRF_HEADER: csrf},
        )
    finally:
        tracker.AI_CONFIG.clear()
        tracker.AI_CONFIG.update(old_config)

    data = resp.get_json()
    assert resp.status_code == 200
    assert calls and calls[0]["temperature"] == 0.4
    assert data["draft"]["kind"] == "draft"
    assert "核心判断" in data["draft"]["content"]
    assert "防务战略分析报告" in calls[0]["messages"][0]["content"]


def test_agent_draft_uses_large_token_budget_for_ten_thousand_word_request(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    old_config = dict(tracker.AI_CONFIG)
    tracker.AI_CONFIG.update({"api_key": "unit-key", "model": "unit-model", "max_tokens": 1024})
    calls = []

    def fake_call_ai(messages, temperature=None, max_tokens=None):
        calls.append({"messages": messages, "temperature": temperature, "max_tokens": max_tokens})
        return "# 完整报告\n" + ("战略研判" * 2600)

    monkeypatch.setattr(tracker, "_call_ai", fake_call_ai)
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login_cookies(client)
    project = report_agent.create_project(
        "",
        "strategic",
        client_request="帮我做一个台海军力平衡报告，报告要1万字",
    )
    evidence = report_agent.upsert_project_evidence(project["project_id"], [_candidate()])

    try:
        resp = client.post(
            f"/api/agent/projects/{project['project_id']}/draft",
            json={
                "evidence_ids": [evidence[0]["evidence_id"]],
                "review_notes": "正文不少于10000字，严禁出现秘密、机密、绝密字眼",
            },
            headers={tracker.CSRF_HEADER: csrf},
        )
    finally:
        tracker.AI_CONFIG.clear()
        tracker.AI_CONFIG.update(old_config)

    data = resp.get_json()
    prompt = "\n".join(m["content"] for m in calls[0]["messages"])

    assert resp.status_code == 200
    assert calls[0]["max_tokens"] >= 12000
    assert "10000" in prompt
    assert data["draft"]["payload"]["target_word_count"] == 10000
    assert data["draft"]["payload"]["word_count"] >= 10000


def test_agent_draft_requires_ai_config(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    old_config = dict(tracker.AI_CONFIG)
    tracker.AI_CONFIG["api_key"] = ""
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login_cookies(client)
    project = report_agent.create_project("台海日报", "daily")
    evidence = report_agent.upsert_project_evidence(project["project_id"], [_candidate()])

    try:
        resp = client.post(
            f"/api/agent/projects/{project['project_id']}/draft",
            json={"evidence_ids": [evidence[0]["evidence_id"]]},
            headers={tracker.CSRF_HEADER: csrf},
        )
    finally:
        tracker.AI_CONFIG.clear()
        tracker.AI_CONFIG.update(old_config)

    assert resp.status_code == 400
    assert "AI API Key" in resp.get_json()["error"]


def test_agent_draft_job_status_endpoint_returns_done_draft(monkeypatch, tmp_path):
    """草稿改为 job 队列后：POST 入队、GET draft_jobs 轮询到 done 并带回草稿。"""
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    old_config = dict(tracker.AI_CONFIG)
    tracker.AI_CONFIG.update({"api_key": "unit-key", "model": "unit-model"})
    monkeypatch.setattr(tracker, "_call_ai",
                        lambda messages, temperature=None, max_tokens=None: "## 核心判断\n台海方向值得跟踪。")
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login_cookies(client)
    project = report_agent.create_project("台海战略分析报告", "strategic")
    evidence = report_agent.upsert_project_evidence(project["project_id"], [_candidate()])
    try:
        resp = client.post(
            f"/api/agent/projects/{project['project_id']}/draft",
            json={"evidence_ids": [evidence[0]["evidence_id"]]},
            headers={tracker.CSRF_HEADER: csrf},
        )
        data = resp.get_json()
        job_id = data["job"]["job_id"]
        poll = client.get(
            f"/api/agent/projects/{project['project_id']}/draft_jobs/{job_id}",
            headers={tracker.CSRF_HEADER: csrf},
        )
    finally:
        tracker.AI_CONFIG.clear()
        tracker.AI_CONFIG.update(old_config)

    assert resp.status_code == 200
    assert data["job"]["status"] == "done"
    pdata = poll.get_json()
    assert poll.status_code == 200
    assert pdata["job"]["job_id"] == job_id
    assert pdata["job"]["status"] == "done"
    assert "核心判断" in pdata["draft"]["content"]


def test_agent_draft_job_keeps_first_draft_when_expansion_fails(monkeypatch, tmp_path):
    """数据丢失止血：扩写(第二次AI调用)失败时，首稿仍已落盘并可取回，job 标记 failed。"""
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    old_config = dict(tracker.AI_CONFIG)
    tracker.AI_CONFIG.update({"api_key": "unit-key", "model": "unit-model", "max_tokens": 1024})
    calls = {"n": 0}

    def fake_call_ai(messages, temperature=None, max_tokens=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return "# 首版草稿\n" + ("研判" * 50)   # 短稿，低于1万字目标 → 触发扩写
        raise RuntimeError("扩写调用超时/被杀")       # 第二次(扩写)失败

    monkeypatch.setattr(tracker, "_call_ai", fake_call_ai)
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login_cookies(client)
    project = report_agent.create_project("台海报告", "strategic", client_request="报告要1万字")
    evidence = report_agent.upsert_project_evidence(project["project_id"], [_candidate()])
    try:
        resp = client.post(
            f"/api/agent/projects/{project['project_id']}/draft",
            json={"evidence_ids": [evidence[0]["evidence_id"]]},
            headers={tracker.CSRF_HEADER: csrf},
        )
    finally:
        tracker.AI_CONFIG.clear()
        tracker.AI_CONFIG.update(old_config)

    data = resp.get_json()
    assert resp.status_code == 200
    assert calls["n"] == 2                          # 首稿 + 扩写两次调用都发生
    assert data["job"]["status"] == "failed"         # 扩写失败 → job 标记失败
    assert data["draft"] is not None                 # 但首稿已保住、可取回
    assert "首版草稿" in data["draft"]["content"]
    assert len(report_agent.get_project_drafts(project["project_id"])) >= 1


def test_agent_export_docx_requires_draft_and_downloads(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login_cookies(client)
    project = report_agent.create_project("台海日报", "daily")

    missing = client.post(
        f"/api/agent/projects/{project['project_id']}/export_docx",
        json={},
        headers={tracker.CSRF_HEADER: csrf},
    )
    assert missing.status_code == 400

    draft = report_agent.save_draft(project["project_id"], "draft", "台海日报正文", model="unit-model")
    ok = client.post(
        f"/api/agent/projects/{project['project_id']}/export_docx",
        json={"draft_id": draft["draft_id"]},
        headers={tracker.CSRF_HEADER: csrf},
    )

    assert ok.status_code == 200
    assert ok.mimetype == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    assert ok.data[:2] == b"PK"


def test_agent_export_docx_blocks_short_draft_when_target_word_count_is_large(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login_cookies(client)
    project = report_agent.create_project(
        "",
        "strategic",
        client_request="帮我做一个台海军力平衡报告，报告要1万字",
    )
    draft = report_agent.save_draft(
        project["project_id"],
        "draft",
        "短报告正文",
        model="unit-model",
        payload={"target_word_count": 10000, "word_count": 5, "word_count_ok": False},
    )

    resp = client.post(
        f"/api/agent/projects/{project['project_id']}/export_docx",
        json={"draft_id": draft["draft_id"]},
        headers={tracker.CSRF_HEADER: csrf},
    )

    assert resp.status_code == 400
    assert "低于目标字数" in resp.get_json()["error"]
