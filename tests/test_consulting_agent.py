from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

import consulting_agent
import search_adapters


def _rss_candidate(idx=1):
    return {
        "article_id": f"rss-{idx}",
        "title": f"台海无人系统动态 {idx}",
        "summary": "公开报道显示，相关力量正在强化无人系统与跨域感知能力。",
        "source": "Defense News",
        "source_cn": "Defense News",
        "link": f"https://example.test/rss-{idx}",
        "date": datetime.now(timezone.utc).isoformat(),
        "quality_score": 82,
        "quality_level": "A",
        "quality_reasons": ["贴近防务战略分析主题"],
    }


@pytest.fixture()
def consult_db(monkeypatch, tmp_path):
    db_file = tmp_path / "consulting_agent.sqlite3"
    monkeypatch.setattr(consulting_agent, "CONSULTING_AGENT_DB_FILE", str(db_file))
    return db_file


def test_create_session_parses_instruction_and_requested_source_count(consult_db):
    session = consulting_agent.create_session(
        "帮我做一个有关台海无人系统发展的战略分析报告，搜集20份文献和智库报告",
        search_web=True,
    )

    assert session["topic"] == "台海无人系统发展"
    assert session["target_source_count"] == 20
    assert session["report_goal"] == "战略分析报告"
    assert session["search_web"] is True
    assert "台海无人系统" in session["plan"]["keywords"]
    assert session["plan"]["target_source_count"] == 20


def test_create_session_rejects_overlong_instruction_before_regex_parsing(
    consult_db, monkeypatch,
):
    monkeypatch.setattr(
        consulting_agent,
        "_derive_topic",
        lambda _value: pytest.fail("overlong instructions must not reach topic regexes"),
    )

    with pytest.raises(ValueError, match="4096"):
        consulting_agent.create_session("x" * 4097)


def test_create_session_parses_search_only_instruction_topic(consult_db):
    session = consulting_agent.create_session("搜集3份RAND台海无人系统智库报告")

    assert session["topic"] == "RAND台海无人系统智库"
    assert session["target_source_count"] == 3
    assert "RAND台海无人系统" in session["plan"]["primary_query"]


def test_topic_planner_understands_missile_stockpile_storage_queries(consult_db):
    session = consulting_agent.create_session("搜索关于美国导弹存储的智库报告")
    queries = consulting_agent.build_report_source_queries(session, [], max_queries=12)
    joined = "\n".join([*session["plan"].get("keywords", []), *queries]).lower()

    assert "united states" in joined or "u.s." in joined
    assert "missile" in joined
    assert any(term in joined for term in ("stockpile", "arsenal", "inventory", "storage", "munitions"))
    assert "missile defense assessment" not in session["plan"]["primary_query"].lower()


@pytest.mark.parametrize(
    "instruction, expected_terms",
    [
        ("搜集美国弹药库存与储备报告", ("united states", "munitions stockpile")),
        ("搜集北约弹药产能和工业基础报告", ("nato", "production capacity")),
        ("搜集俄罗斯无人机库存与战损消耗报告", ("russia", "attrition")),
        ("搜集印太导弹部署与基地报告", ("indo-pacific", "deployment")),
        ("搜集欧洲防空战备 readiness 报告", ("europe", "readiness")),
        ("搜集美国防务采购 acquisition 报告", ("united states", "acquisition")),
        ("搜集中东军事后勤保障报告", ("middle east", "logistics")),
    ],
)
def test_topic_planner_expands_general_research_intents(consult_db, instruction, expected_terms):
    session = consulting_agent.create_session(instruction)
    queries = consulting_agent.build_report_source_queries(session, [], max_queries=16)
    joined = "\n".join([*session["plan"].get("keywords", []), *queries]).lower()

    for term in expected_terms:
        assert term in joined


def test_topic_planner_generates_generic_bilingual_queries_without_china_fallback(consult_db):
    cases = [
        ("俄罗斯电子战能力评估报告，搜集20份资料", ("russia", "electronic warfare")),
        ("红海无人机袭击与海上安全研究，搜集20份资料", ("red sea", "uav")),
        ("印太海上力量竞争战略分析报告，搜集20份资料", ("indo-pacific", "naval")),
        ("欧洲防空工业生产能力报告，搜集20份资料", ("europe", "air defense")),
    ]
    directory = [
        {
            "id": "china_zone",
            "category": "中国专题",
            "sites": [
                {"name": "RAND China", "url": "https://www.rand.org/topics/china.html", "desc_cn": "中国军事现代化"},
                {"name": "81.cn", "url": "https://www.81.cn/", "desc_cn": "中国军队新闻"},
            ],
        },
        {
            "id": "global_media",
            "category": "全球防务研究",
            "sites": [
                {"name": "IISS", "url": "https://www.iiss.org/", "desc_cn": "全球军力平衡与地区安全研究"},
                {"name": "RUSI", "url": "https://www.rusi.org/", "desc_cn": "欧洲安全、海上安全、无人系统和电子战研究"},
            ],
        },
    ]

    for instruction, expected_terms in cases:
        session = consulting_agent.create_session(instruction)
        plan = session["plan"]
        queries = consulting_agent.build_report_source_queries(session, directory, max_queries=10)
        joined = "\n".join([*plan.get("keywords", []), *queries]).lower()

        assert all(term in joined for term in expected_terms)
        assert "site:81.cn" not in joined
        assert "site:rand.org/topics/china" not in joined
        assert plan["topic_profile"]["capabilities"]
        assert plan["topic_profile"]["regions"]


def test_upsert_evidence_preserves_metadata_dedupes_and_sanitizes(consult_db):
    session = consulting_agent.create_session("帮我做一个台海无人系统报告，搜集3份来源")
    rows = consulting_agent.upsert_evidence(session["session_id"], [
        {
            "title": "台海无人系统研究",
            "source": "RAND",
            "published_at": "2026-06-01",
            "url": "https://example.test/report",
            "channel": "web",
            "score": 91,
            "reason": "高权威智库报告",
            "snippet": "严禁出现绝密、机密、秘密等标识。",
        },
        {
            "title": "重复标题",
            "source": "RAND",
            "published_at": "2026-06-02",
            "url": "https://example.test/report",
            "channel": "thinktank",
            "score": 80,
            "reason": "重复来源",
            "snippet": "公开源资料",
        },
    ])

    assert len(rows) == 1
    assert rows[0]["title"] == "重复标题"
    assert rows[0]["source"] == "RAND"
    assert rows[0]["channel"] == "thinktank"
    assert rows[0]["score"] == 80
    assert "绝密" not in rows[0]["snippet"]
    assert rows[0]["dedup_key"]


def test_archive_source_asset_writes_metadata_text_and_original(monkeypatch, tmp_path, consult_db):
    archive_dir = tmp_path / "source_archive"
    monkeypatch.setattr(consulting_agent, "SOURCE_ARCHIVE_DIR", str(archive_dir), raising=False)
    session = consulting_agent.create_session("搜集1份俄罗斯电子战报告")
    evidence = consulting_agent.upsert_evidence(session["session_id"], [{
        "title": "Russia electronic warfare assessment",
        "source": "RUSI",
        "url": "https://example.test/russia-ew.html",
        "channel": "web",
        "score": 90,
        "snippet": "待抓取正文",
    }])[0]

    asset = consulting_agent.archive_source_asset(
        session["session_id"],
        evidence,
        {
            "title": "Russia electronic warfare assessment",
            "url": evidence["url"],
            "text": "This public report discusses Russian electronic warfare capabilities.",
            "snippet": "Russian electronic warfare capabilities.",
            "document_type": "html",
            "content_type": "text/html",
            "word_count": 8,
            "raw_bytes": b"<html><body>Russian electronic warfare capabilities.</body></html>",
            "is_fetched_original": True,
        },
    )
    assets = consulting_agent.list_source_assets(session["session_id"])

    assert asset["status"] == "archived"
    assert Path(asset["local_path"]).exists()
    assert Path(asset["text_path"]).exists()
    assert json.loads(Path(asset["metadata_path"]).read_text(encoding="utf-8"))["evidence_id"] == evidence["evidence_id"]
    assert assets[0]["checksum"] == asset["checksum"]
    assert "electronic warfare" in Path(asset["text_path"]).read_text(encoding="utf-8")


def test_partial_source_asset_is_saved_but_not_counted_as_archived(monkeypatch, tmp_path, consult_db):
    archive_dir = tmp_path / "source_archive"
    monkeypatch.setattr(consulting_agent, "SOURCE_ARCHIVE_DIR", str(archive_dir), raising=False)
    session = consulting_agent.create_session("搜集1份欧洲防空生产报告")
    evidence = consulting_agent.upsert_evidence(session["session_id"], [{
        "title": "European air defense production PDF",
        "source": "Think Tank",
        "url": "https://example.test/air-defense.pdf",
        "channel": "web",
        "score": 88,
        "snippet": "PDF原件可下载，但正文抽取不足。",
    }])[0]

    asset = consulting_agent.archive_source_asset(
        session["session_id"],
        evidence,
        {
            "title": evidence["title"],
            "url": evidence["url"],
            "text": "short text",
            "snippet": "short text",
            "document_type": "pdf",
            "content_type": "application/pdf",
            "word_count": 2,
            "raw_bytes": b"%PDF-1.4 partial",
            "is_fetched_original": True,
        },
        status="partial",
        failure_reason="正文抽取不足，需人工复核",
    )
    counts = consulting_agent.capture_asset_counts(session["session_id"], target_count=1)

    assert asset["status"] == "partial"
    assert Path(asset["local_path"]).exists()
    assert counts["archived_count"] == 0
    assert counts["partial_count"] == 1
    assert counts["archive_shortfall"] == 1


def test_capture_job_persists_progress_and_attempts(consult_db):
    session = consulting_agent.create_session("搜集50份红海无人机报告")

    job = consulting_agent.create_capture_job(
        session["session_id"],
        target_count=50,
        batch_size=8,
        max_rounds=6,
        crawl_mode="steady",
        allow_browser_render=True,
    )
    consulting_agent.record_capture_attempt(
        job["job_id"],
        session["session_id"],
        round_no=1,
        query_text="Red Sea UAV think tank report PDF",
        result_count=10,
        archived_delta=2,
        partial_delta=1,
        failed_delta=1,
        needs_user_input_delta=1,
        rejected_low_relevance=3,
        payload={"provider": "public_web"},
    )
    updated = consulting_agent.update_capture_job(
        job["job_id"],
        status="completed",
        round_no=1,
        current_query="Red Sea UAV think tank report PDF",
        stop_reason="max_rounds_reached",
        counts={
            "archived_count": 2,
            "partial_count": 1,
            "failed_count": 1,
            "needs_user_input_count": 1,
            "rejected_low_relevance": 3,
        },
    )

    loaded = consulting_agent.get_capture_job(session["session_id"], job["job_id"])
    assert updated["status"] == "completed"
    assert loaded["archived_count"] == 2
    assert loaded["partial_count"] == 1
    assert loaded["needs_user_input_count"] == 1
    assert loaded["attempts"][0]["query_text"] == "Red Sea UAV think tank report PDF"


def test_same_source_url_can_exist_in_different_sessions(consult_db):
    first = consulting_agent.create_session("帮我做一个台海报告，搜集1份来源")
    second = consulting_agent.create_session("帮我做一个印太报告，搜集1份来源")
    candidate = {
        "title": "RAND China Research",
        "source": "RAND",
        "url": "https://example.test/shared-source",
        "channel": "thinktank_target",
        "score": 80,
        "reason": "精选智库目录检索目标",
    }

    one = consulting_agent.upsert_evidence(first["session_id"], [candidate])
    two = consulting_agent.upsert_evidence(second["session_id"], [candidate])

    assert len(one) == 1
    assert len(two) == 1
    assert one[0]["dedup_key"] == two[0]["dedup_key"]
    assert one[0]["evidence_id"] != two[0]["evidence_id"]


def test_collect_candidates_honors_requested_count_without_upper_cap(consult_db):
    session = consulting_agent.create_session("帮我做一个台海报告，搜集120份信息源")
    web_results = [
        {
            "title": f"Web source {i}",
            "source": "Web",
            "url": f"https://example.test/web-{i}",
            "snippet": "公开网页资料",
            "channel": "web",
            "score": 70,
        }
        for i in range(90)
    ]
    rss_results = [_rss_candidate(i) for i in range(20)]
    thinktank_directory = [{
        "category": "PLA专项研究机构",
        "sites": [
            {
                "name": f"Think Tank {i}",
                "name_cn": f"智库{i}",
                "url": f"https://example.test/tank-{i}",
                "desc_cn": "台海长期研究报告",
            }
            for i in range(30)
        ],
    }]

    collected, meta = consulting_agent.collect_candidates(
        session,
        web_results=web_results,
        rss_candidates=rss_results,
        thinktank_directory=thinktank_directory,
        imported_items=[],
    )

    assert len(collected) == 120
    assert meta["target_source_count"] == 120
    assert meta["found_count"] == 110
    assert meta["target_seed_count"] == 10
    assert meta["shortfall"] == 10
    assert meta["channel_counts"]["web"] == 90
    assert meta["channel_counts"]["rss"] == 20
    assert meta["channel_counts"]["thinktank_target"] == 10


def test_thinktank_directory_targets_do_not_pretend_to_be_fetched_reports(consult_db):
    session = consulting_agent.create_session("帮我做一个台海报告，搜集20份智库分析报告")
    directory = [{
        "category": "PLA专项研究机构",
        "sites": [
            {
                "name": f"Think Tank {i}",
                "name_cn": f"智库{i}",
                "url": f"https://example.test/tank-{i}",
                "desc_cn": "台海长期研究报告",
            }
            for i in range(25)
        ],
    }]

    collected, meta = consulting_agent.collect_candidates(
        session,
        web_results=[],
        rss_candidates=[],
        thinktank_directory=directory,
        imported_items=[],
    )

    assert len(collected) == 20
    assert meta["found_count"] == 0
    assert meta["target_seed_count"] == 20
    assert meta["shortfall"] == 20
    assert {row["channel"] for row in collected} == {"thinktank_target"}
    assert all("检索目标" in row["reason"] for row in collected)


def test_build_synthesis_messages_require_source_bound_claims(consult_db):
    session = consulting_agent.create_session("帮我做一个台海无人系统报告，搜集2份来源")
    evidence = consulting_agent.upsert_evidence(session["session_id"], [
        {
            "title": "台海无人系统研究",
            "source": "RAND",
            "published_at": "2026-06-01",
            "url": "https://example.test/report",
            "channel": "web",
            "score": 91,
            "reason": "高权威智库报告",
            "snippet": "公开源资料。",
        }
    ])

    messages = consulting_agent.build_synthesis_messages(session, evidence, "突出审稿意见")
    prompt = "\n".join(m["content"] for m in messages)

    assert "防务信息咨询Agent" in prompt
    assert "每个关键判断必须绑定来源编号" in prompt
    assert "实际可用证据数量：1" in prompt
    assert "不得把目标来源数量说成已找到数量" in prompt
    assert "严禁使用“秘密”“机密”“绝密”" in prompt
    assert "台海无人系统研究" in prompt


def test_build_source_pack_is_retrieval_deliverable_not_report_writing(consult_db):
    session = consulting_agent.create_session("帮我做一个台海无人系统报告，搜集3份智库分析")
    evidence = consulting_agent.upsert_evidence(session["session_id"], [
        {
            "title": "台海无人系统研究",
            "source": "RAND",
            "published_at": "2026-06-01",
            "url": "https://example.test/report",
            "channel": "web",
            "score": 91,
            "reason": "实时网页搜索结果",
            "snippet": "公开源资料。",
        },
        {
            "title": "CSIS：台海专题库",
            "source": "CSIS",
            "url": "https://example.test/csis",
            "channel": "thinktank_target",
            "score": 80,
            "reason": "精选智库目录检索目标",
            "snippet": "后续需要进入站内抓取具体报告。",
        },
    ])

    pack = consulting_agent.build_source_pack(session, evidence)

    assert "# 报告源抓取包" in pack
    assert "已抓取报告/分析来源：1" in pack
    assert "智库/机构检索目标：1" in pack
    assert "不是最终战略分析报告" in pack
    assert "https://example.test/report" in pack


def test_build_report_source_queries_targets_reports_and_thinktanks(consult_db):
    session = consulting_agent.create_session("帮我做一个台海无人系统报告，搜集20份智库分析")
    directory = [{
        "category": "PLA专项研究机构",
        "sites": [
            {"name": "RAND", "url": "https://www.rand.org/topics/china.html", "desc_cn": "中国军事现代化"},
            {"name": "CSIS", "url": "https://www.csis.org/programs/china-power-project", "desc_cn": "中国力量"},
        ],
    }]

    queries = consulting_agent.build_report_source_queries(session, directory, max_queries=5)

    assert any("report" in query.lower() or "analysis" in query.lower() for query in queries)
    assert any("site:rand.org" in query for query in queries)
    assert any("site:csis.org" in query for query in queries)


def test_iran_missile_queries_do_not_fall_back_to_china_sites(consult_db):
    session = consulting_agent.create_session("伊朗导弹作战运用战例梳理战略分析报告，搜集50份资料")
    directory = [
        {
            "id": "china_zone",
            "category": "中国防务智库",
            "sites": [
                {"name": "81.cn", "url": "https://www.81.cn/", "desc_cn": "中国军队新闻"},
                {"name": "RAND China", "url": "https://www.rand.org/topics/china.html", "desc_cn": "中国军事现代化"},
            ],
        },
        {
            "id": "missile_mideast_research",
            "category": "导弹与中东安全研究",
            "sites": [
                {"name": "CSIS Missile Threat", "url": "https://missilethreat.csis.org/", "desc_cn": "伊朗弹道导弹与导弹武器库评估"},
                {"name": "Washington Institute", "url": "https://www.washingtoninstitute.org/", "desc_cn": "伊朗与中东安全政策分析"},
            ],
        },
    ]

    queries = consulting_agent.build_report_source_queries(session, directory, max_queries=8)
    joined = "\n".join(queries).lower()

    assert "iran" in joined
    assert "missile" in joined
    assert "site:81.cn" not in joined
    assert "site:rand.org/topics/china" not in joined
    assert any("site:missilethreat.csis.org" in query for query in queries)


def test_tavily_adapter_reports_disabled_without_api_key(monkeypatch):
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    monkeypatch.setenv("SEARCH_PROVIDER", "tavily")

    status = search_adapters.search_status()

    assert status["web_search_enabled"] is True
    assert status["provider"] == "public_web"
    assert status["providers"]["public_web"]["enabled"] is True
    assert "基础联网搜索" in status["message"]


def test_ai_page_is_consulting_agent_workbench_not_chat_cards():
    html = (Path(__file__).resolve().parents[1] / "templates" / "index.html").read_text(encoding="utf-8")

    assert "防务报告源抓取 Agent" in html
    assert "Agent 实际功能" in html
    assert 'id="consultInstruction"' in html
    assert 'id="consultEvidenceList"' in html
    assert 'id="consultSourcePackBody"' in html
    assert 'id="searchStatusPanel"' in html
    assert 'id="searchTavilyKey"' in html
    assert "<summary>高级搜索配置</summary>" in html
    assert "一键搜集并归档至目标" in html
    assert "整理报告源包" in html
    assert "导出资料包" in html
    assert "转入报告Agent" in html
    assert "生成综合报告" not in html
    assert "ai-features-grid" not in html
