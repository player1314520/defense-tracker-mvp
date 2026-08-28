from datetime import datetime, timezone

import pytest

import app as tracker
import report_agent


@pytest.fixture(autouse=True)
def _reset_request_rate_state():
    """Keep API tests independent from requests made by earlier test modules."""
    with tracker._rate_lock:
        tracker._rate_store.clear()
    yield
    with tracker._rate_lock:
        tracker._rate_store.clear()


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


def _institution_candidate(index, domain):
    return {
        "article_id": f"institution-source-{index}",
        "title": f"机构公开来源 {index}",
        "summary": f"第 {index} 条可追溯公开来源摘要。",
        "source": f"Institution {index}",
        "source_cn": f"机构来源 {index}",
        "link": f"https://{domain}/reports/source-{index}",
        "date": datetime.now(timezone.utc).isoformat(),
        "quality_score": 90,
        "quality_level": "S",
        "quality_reasons": ["机构公开来源"],
        "asset_status": "archived",
        "asset_id": f"asset-{index}",
        "text": f"第 {index} 条已归档、可引用的公开原文正文。",
    }


def _ready_institution_content():
    return """# 机构开源情报整编包

## 信息清单
- 来源一 [1]
- 来源二 [2]
- 来源三 [3]
- 来源四 [4]
- 来源五 [5]
- 来源六 [6]
- 来源七 [7]

## 专题报告
### 短消息一
已核实事实：公开材料显示相关能力建设持续推进 [1][2]。

### 短消息二
多源印证：机构报告对部署节奏给出一致观察 [3][4]。

### 短消息三
分析判断：现有证据支持继续跟踪训练与保障活动 [5][6][7]。

## 事实来源追溯表
- 已核实事实对应来源 [1][2][3]
- 多源印证对应来源 [4][5]
- 分析判断对应来源 [6][7]

## 不确定性与证据边界
公开材料存在时间差，后续变化仍需持续核验。

## 诚实边界
1. 不能替代非公开情报核验。
2. 不能证明未披露的内部决策。
3. 不能保证公开网页后续持续可访问。
"""


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


def test_agent_preflight_requires_csrf(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    _login_cookies(client)
    project = report_agent.create_project("台海交付预检", "strategic")

    blocked = client.post(
        f"/api/agent/projects/{project['project_id']}/preflight",
        json={},
    )

    assert blocked.status_code == 403
    assert "CSRF" in blocked.get_json()["error"]


def test_agent_preflight_returns_ready_payload(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login_cookies(client)
    project = report_agent.create_project("机构公开源情报整编包", "institution_pack")
    domains = [
        "defense.gov",
        "congress.gov",
        "gao.gov",
        "rand.org",
        "csis.org",
        "iiss.org",
        "sipri.org",
    ]
    evidence = report_agent.upsert_project_evidence(
        project["project_id"],
        [_institution_candidate(i, domain) for i, domain in enumerate(domains, 1)],
    )
    draft = report_agent.save_draft(
        project["project_id"], "draft", "待替换的旧正文", model="unit-model"
    )

    resp = client.post(
        f"/api/agent/projects/{project['project_id']}/preflight",
        json={
            "draft_id": draft["draft_id"],
            "content": _ready_institution_content(),
            "evidence_ids": [item["evidence_id"] for item in evidence],
        },
        headers={tracker.CSRF_HEADER: csrf},
    )
    data = resp.get_json()

    assert resp.status_code == 200
    assert data["ok"] is True
    assert data["preflight"]["ok"] is True
    assert data["preflight"]["status"] == "ready"
    assert all(check["ok"] for check in data["preflight"]["checks"])


def test_agent_preflight_defaults_to_latest_non_outline_draft(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    captured = {}

    def fake_preflight(project, draft, evidence):
        captured.update({"project": project, "draft": draft, "evidence": evidence})
        return {"ok": True, "status": "ready", "checks": []}

    monkeypatch.setattr(report_agent, "build_delivery_preflight", fake_preflight, raising=False)
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login_cookies(client)
    project = report_agent.create_project("台海交付预检", "strategic")
    evidence = report_agent.upsert_project_evidence(project["project_id"], [_candidate()])
    report_draft = report_agent.save_draft(
        project["project_id"], "draft", "可交付正文", model="unit-model"
    )
    report_agent.save_draft(project["project_id"], "outline", "最新大纲", model="unit-model")

    resp = client.post(
        f"/api/agent/projects/{project['project_id']}/preflight",
        json={"evidence_ids": [evidence[0]["evidence_id"]]},
        headers={tracker.CSRF_HEADER: csrf},
    )

    assert resp.status_code == 200
    assert captured["draft"]["draft_id"] == report_draft["draft_id"]
    assert captured["evidence"][0]["evidence_id"] == evidence[0]["evidence_id"]


def test_agent_preflight_returns_blocked_status_for_missing_sources(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login_cookies(client)
    project = report_agent.create_project("机构公开源情报整编包", "institution_pack")
    draft = report_agent.save_draft(
        project["project_id"], "draft", _ready_institution_content(), model="unit-model"
    )

    resp = client.post(
        f"/api/agent/projects/{project['project_id']}/preflight",
        json={"draft_id": draft["draft_id"]},
        headers={tracker.CSRF_HEADER: csrf},
    )
    data = resp.get_json()
    checks = {check["id"]: check for check in data["preflight"]["checks"]}

    assert resp.status_code == 200
    assert data["ok"] is True
    assert data["preflight"]["ok"] is False
    assert data["preflight"]["status"] == "blocked"
    assert checks["sources"]["ok"] is False


def test_agent_preflight_returns_blocked_status_for_missing_body(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login_cookies(client)
    project = report_agent.create_project("机构公开源情报整编包", "institution_pack")
    domains = [
        "defense.gov",
        "congress.gov",
        "gao.gov",
        "rand.org",
        "csis.org",
        "iiss.org",
        "sipri.org",
    ]
    candidates = [_institution_candidate(i, domain) for i, domain in enumerate(domains, 1)]
    candidates[0].update({"asset_status": "metadata_only", "asset_id": "", "text": ""})
    evidence = report_agent.upsert_project_evidence(project["project_id"], candidates)

    resp = client.post(
        f"/api/agent/projects/{project['project_id']}/preflight",
        json={
            "content": _ready_institution_content(),
            "evidence_ids": [item["evidence_id"] for item in evidence],
        },
        headers={tracker.CSRF_HEADER: csrf},
    )
    data = resp.get_json()
    checks = {check["id"]: check for check in data["preflight"]["checks"]}

    assert resp.status_code == 200
    assert data["ok"] is True
    assert data["preflight"]["ok"] is False
    assert data["preflight"]["status"] == "blocked"
    assert checks["content"]["ok"] is False


def test_agent_preflight_rejects_draft_from_another_project(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login_cookies(client)
    project = report_agent.create_project("当前项目", "strategic")
    other_project = report_agent.create_project("其他项目", "strategic")
    other_draft = report_agent.save_draft(
        other_project["project_id"], "draft", "其他项目正文", model="unit-model"
    )

    resp = client.post(
        f"/api/agent/projects/{project['project_id']}/preflight",
        json={"draft_id": other_draft["draft_id"]},
        headers={tracker.CSRF_HEADER: csrf},
    )

    assert resp.status_code == 400
    assert "草稿不属于当前项目" in resp.get_json()["error"]


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


def test_agent_export_docx_uses_selected_institution_evidence(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login_cookies(client)
    project = report_agent.create_project("机构公开源情报整编包", "institution_pack")
    domains = [
        "defense.gov",
        "congress.gov",
        "gao.gov",
        "rand.org",
        "csis.org",
        "iiss.org",
        "sipri.org",
        "army.mil",
    ]
    evidence = report_agent.upsert_project_evidence(
        project["project_id"],
        [_institution_candidate(i, domain) for i, domain in enumerate(domains, 1)],
    )
    draft = report_agent.save_draft(
        project["project_id"], "draft", _ready_institution_content(), model="unit-model"
    )

    resp = client.post(
        f"/api/agent/projects/{project['project_id']}/export_docx",
        json={
            "draft_id": draft["draft_id"],
            "evidence_ids": [item["evidence_id"] for item in evidence[:7]],
        },
        headers={tracker.CSRF_HEADER: csrf},
    )

    assert resp.status_code == 200
    assert resp.mimetype == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    assert resp.data[:2] == b"PK"


def test_agent_empty_evidence_selection_stays_empty_for_preflight_and_export(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login_cookies(client)
    project = report_agent.create_project("机构公开源情报整编包", "institution_pack")
    domains = [
        "defense.gov",
        "congress.gov",
        "gao.gov",
        "rand.org",
        "csis.org",
        "iiss.org",
        "sipri.org",
    ]
    report_agent.upsert_project_evidence(
        project["project_id"],
        [_institution_candidate(i, domain) for i, domain in enumerate(domains, 1)],
    )
    draft = report_agent.save_draft(
        project["project_id"], "draft", _ready_institution_content(), model="unit-model"
    )

    preflight = client.post(
        f"/api/agent/projects/{project['project_id']}/preflight",
        json={"draft_id": draft["draft_id"], "evidence_ids": []},
        headers={tracker.CSRF_HEADER: csrf},
    )
    export = client.post(
        f"/api/agent/projects/{project['project_id']}/export_docx",
        json={"draft_id": draft["draft_id"], "evidence_ids": []},
        headers={tracker.CSRF_HEADER: csrf},
    )
    preflight_data = preflight.get_json()

    assert preflight.status_code == 200
    assert preflight_data["preflight"]["status"] == "blocked"
    assert preflight_data["preflight"]["counts"]["evidence"] == 0
    assert export.status_code == 400
    assert "证据数量为0条" in export.get_json()["error"]


def test_agent_missing_evidence_ids_keeps_legacy_full_set_for_preflight_and_export(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login_cookies(client)
    project = report_agent.create_project("机构公开源情报整编包", "institution_pack")
    domains = [
        "defense.gov",
        "congress.gov",
        "gao.gov",
        "rand.org",
        "csis.org",
        "iiss.org",
        "sipri.org",
    ]
    report_agent.upsert_project_evidence(
        project["project_id"],
        [_institution_candidate(i, domain) for i, domain in enumerate(domains, 1)],
    )
    draft = report_agent.save_draft(
        project["project_id"], "draft", _ready_institution_content(), model="unit-model"
    )

    preflight = client.post(
        f"/api/agent/projects/{project['project_id']}/preflight",
        json={"draft_id": draft["draft_id"]},
        headers={tracker.CSRF_HEADER: csrf},
    )
    export = client.post(
        f"/api/agent/projects/{project['project_id']}/export_docx",
        json={"draft_id": draft["draft_id"]},
        headers={tracker.CSRF_HEADER: csrf},
    )

    assert preflight.status_code == 200
    assert preflight.get_json()["preflight"]["status"] == "ready"
    assert export.status_code == 200
    assert export.data[:2] == b"PK"


def test_agent_export_docx_rejects_unknown_evidence_id(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login_cookies(client)
    project = report_agent.create_project("台海日报", "daily")
    draft = report_agent.save_draft(project["project_id"], "draft", "台海日报正文", model="unit-model")

    resp = client.post(
        f"/api/agent/projects/{project['project_id']}/export_docx",
        json={"draft_id": draft["draft_id"], "evidence_ids": ["unknown-evidence-id"]},
        headers={tracker.CSRF_HEADER: csrf},
    )

    assert resp.status_code == 404
    assert "证据不存在或不属于当前项目" in resp.get_json()["error"]


def test_agent_export_docx_rejects_evidence_from_another_project(monkeypatch, tmp_path):
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(tmp_path / "agent.sqlite3"))
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = _login_cookies(client)
    project = report_agent.create_project("当前项目", "daily")
    other_project = report_agent.create_project("其他项目", "daily")
    other_evidence = report_agent.upsert_project_evidence(other_project["project_id"], [_candidate()])
    draft = report_agent.save_draft(project["project_id"], "draft", "当前项目正文", model="unit-model")

    resp = client.post(
        f"/api/agent/projects/{project['project_id']}/export_docx",
        json={
            "draft_id": draft["draft_id"],
            "evidence_ids": [other_evidence[0]["evidence_id"]],
        },
        headers={tracker.CSRF_HEADER: csrf},
    )

    assert resp.status_code == 404
    assert "证据不存在或不属于当前项目" in resp.get_json()["error"]


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
