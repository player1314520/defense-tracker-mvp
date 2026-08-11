from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

import pytest

import report_agent

if report_agent.DOCX_AVAILABLE:
    from docx import Document
    from docx.enum.text import WD_PARAGRAPH_ALIGNMENT
    from docx.oxml.ns import qn


def _candidate(title="台海方向联合演训值得警惕"):
    return {
        "article_id": "article-001",
        "title": title,
        "summary": "公开报道显示，相关部队围绕台海方向组织联合演训，检验远程火力和体系支撑能力。",
        "source": "Jamestown China Brief",
        "source_cn": "詹姆斯敦中国简报",
        "link": "https://example.test/article-001",
        "date": datetime.now(timezone.utc).isoformat(),
        "quality_score": 91,
        "quality_level": "S",
        "quality_reasons": ["高权威信源", "贴近对华/周边防务重点"],
        "brief_hits": ["PLA备战", "对华威胁"],
    }


@pytest.fixture()
def agent_db(monkeypatch, tmp_path):
    db_file = tmp_path / "report_agent.sqlite3"
    monkeypatch.setattr(report_agent, "REPORT_AGENT_DB_FILE", str(db_file))
    return db_file


def test_create_project_uses_report_type_defaults_and_records_event(agent_db):
    project = report_agent.create_project(
        title="台海态势日报",
        report_type="strategic",
        topic="台海",
    )

    assert project["title"] == "台海态势日报"
    assert project["report_type"] == "strategic"
    assert project["target_count"] == 12
    assert project["time_window_days"] == 14
    assert project["voice"] == "strategic_analysis"

    bundle = report_agent.get_project_bundle(project["project_id"])
    assert bundle["project"]["project_id"] == project["project_id"]
    assert bundle["events"][0]["event_type"] == "project_created"


def test_create_project_from_client_request_derives_strategy_title(agent_db):
    project = report_agent.create_project(
        title="",
        report_type="strategic",
        client_request="帮我做一个台海军力平衡报告",
    )

    assert project["title"] == "台海军力平衡战略分析报告"
    assert project["topic"] == "台海军力平衡"
    assert project["client_request"] == "帮我做一个台海军力平衡报告"


def test_create_project_extracts_requested_source_count_without_upper_cap(agent_db):
    project = report_agent.create_project(
        title="",
        report_type="strategic",
        client_request="帮我做一个台海军力平衡报告，搜集120份信息源",
    )

    assert project["target_count"] == 120
    assert project["title"] == "台海军力平衡战略分析报告"


def test_upsert_evidence_preserves_quality_source_link_and_dedup_id(agent_db):
    project = report_agent.create_project("专题短报", "short_topic", topic="六代机")

    first = report_agent.upsert_project_evidence(project["project_id"], [_candidate()])
    second = report_agent.upsert_project_evidence(project["project_id"], [_candidate(title="标题更新")])

    assert len(first) == 1
    assert second[0]["evidence_id"] == first[0]["evidence_id"]
    assert second[0]["title"] == "标题更新"
    assert second[0]["source"] == "Jamestown China Brief"
    assert second[0]["link"] == "https://example.test/article-001"
    assert second[0]["quality_score"] == 91
    assert second[0]["quality_level"] == "S"
    assert "高权威信源" in second[0]["quality_reasons"]


def test_build_messages_and_save_draft(agent_db):
    project = report_agent.create_project("台海战略分析报告", "strategic", topic="台海")
    evidence = report_agent.upsert_project_evidence(project["project_id"], [_candidate()])

    outline_messages = report_agent.build_outline_messages(project, evidence)
    assert outline_messages[0]["role"] == "system"
    assert "防务战略分析报告" in outline_messages[0]["content"]
    assert "不是要讯" in outline_messages[0]["content"]
    assert "目录提纲" in outline_messages[1]["content"]
    assert "台海方向联合演训值得警惕" in outline_messages[1]["content"]

    draft = report_agent.save_draft(
        project["project_id"],
        kind="draft",
        content="## 核心判断\n台海方向联合演训值得持续跟踪。",
        model="unit-test-model",
    )

    assert draft["kind"] == "draft"
    assert draft["model"] == "unit-test-model"
    bundle = report_agent.get_project_bundle(project["project_id"])
    assert bundle["drafts"][0]["draft_id"] == draft["draft_id"]
    assert any(e["event_type"] == "draft_saved" for e in bundle["events"])


def test_draft_messages_include_sod_writing_requirements(agent_db, monkeypatch, tmp_path):
    spec_file = tmp_path / "defensetracker_sod_writing.md"
    spec_file.write_text(
        "# DefenseTracker SOD写作要求\n"
        "必须采用技术—能力—规则三维分析框架。\n"
        "每段遵循PARA结构，并建立FACT-DATA-CITE证据链。",
        encoding="utf-8",
    )
    monkeypatch.setattr(report_agent, "REPORT_AGENT_WRITING_SPEC_FILE", str(spec_file), raising=False)
    project = report_agent.create_project("台海战略分析报告", "strategic", topic="台海")
    evidence = report_agent.upsert_project_evidence(project["project_id"], [_candidate()])

    messages = report_agent.build_draft_messages(project, evidence)
    prompt = "\n".join(m["content"] for m in messages)

    assert "DefenseTracker" in prompt
    assert "技术—能力—规则" in prompt
    assert "PARA" in prompt
    assert "FACT-DATA-CITE" in prompt


def test_agent_ui_uses_complete_report_button():
    html = (Path(__file__).resolve().parents[1] / "templates" / "index.html").read_text(encoding="utf-8")

    assert 'onclick="agentGenerateDraft()">生成完整报告</button>' in html


def test_report_rules_markdown_records_forbidden_classification_terms():
    path = Path(__file__).resolve().parents[1] / "docs" / "报告Agent写作导出规范.md"

    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert "秘密" in text
    assert "机密" in text
    assert "绝密" in text
    assert "导出前必须阻断" in text


def test_extract_target_word_count_and_sanitize_forbidden_terms():
    assert report_agent.extract_target_word_count("报告要1万字") == 10000
    assert report_agent.extract_target_word_count("生成一万字") == 10000
    assert report_agent.extract_target_word_count("正文不少于12000字") == 12000

    cleaned = report_agent.sanitize_report_text("绝密报告：这是机密材料和秘密来源。")

    assert "绝密" not in cleaned
    assert "机密" not in cleaned
    assert "秘密" not in cleaned
    assert "报告" in cleaned


def test_assert_report_exportable_ignores_word_count_in_body():
    """回归：报告正文里的'可扩写至8000字'不应被当成目标字数而阻断导出。
    字数目标只应来自用户意图（client_request / payload.target_word_count），不从生成的正文解析。"""
    draft = {
        "payload": {},  # 用户未设任何目标字数
        "content": "本报告分析中国高超声速武器发展态势。可进一步扩写至8000字的完整版本。",
    }
    project = {"client_request": "分析中国高超声速武器发展态势"}  # 无任何字数要求
    quality = report_agent.assert_report_exportable(draft, project)  # 不应抛"低于目标字数"
    assert quality["target_word_count"] == 0

    # 反向保证：用户在 payload 显式设了目标字数时，短稿仍被正确阻断导出
    blocked = {"payload": {"target_word_count": 8000}, "content": "太短。"}
    with pytest.raises(ValueError):
        report_agent.assert_report_exportable(blocked, {"client_request": ""})


def test_markdown_hr_not_treated_as_table():
    """回归：含 | 的正文行后跟纯 --- 水平线，不应被误判为 markdown 表格而吞掉正文。"""
    blocks = report_agent._markdown_blocks("某系统 A|B 说明如下。\n---\n下一段正文。")
    assert all(b.get("type") != "table" for b in blocks)   # --- 是水平线不是表分隔行
    assert any("A|B" in str(b) for b in blocks)             # 含 | 的正文未被表格吞掉
    # 正向保证：带 | 分隔行的真表格仍被正确解析为表格
    real = report_agent._markdown_blocks("| 维度 | 研判 |\n|---|---|\n| 技术 | 领先 |")
    assert any(b.get("type") == "table" for b in real)


@pytest.mark.skipif(not report_agent.DOCX_AVAILABLE, reason="python-docx 未安装")
def test_build_report_docx_uses_defensetracker_paper_format(agent_db):
    project = report_agent.create_project("台海军力平衡战略分析报告", "strategic", topic="台海")
    draft = report_agent.save_draft(
        project["project_id"],
        "draft",
        "\n".join([
            "# 台海军力平衡战略分析报告",
            "## 摘要",
            "本文基于公开源资料，围绕技术—能力—规则三维框架评估台海军力平衡，严禁使用绝密、机密、秘密等等级标识。",
            "## 第一章  技术—能力—规则三维分析框架",
            "### 1.1 技术维度",
            "关键判断必须具备FACT-DATA-CITE证据链，并避免单源孤证。",
            "| 维度 | 研判 |",
            "|---|---|",
            "| 技术 | 关键装备迭代加快 |",
            "| 能力 | 跨域杀伤链更完整 |",
        ]),
        model="unit-test-model",
    )
    evidence = report_agent.upsert_project_evidence(project["project_id"], [_candidate()])

    buf = report_agent.build_report_docx(project, draft, evidence)
    doc = Document(BytesIO(buf.getvalue()))
    section = doc.sections[0]
    texts = [p.text.strip() for p in doc.paragraphs if p.text.strip()]
    table_texts = [cell.text.strip() for table in doc.tables for row in table.rows for cell in row.cells if cell.text.strip()]
    header_texts = [p.text.strip() for sec in doc.sections for p in sec.header.paragraphs if p.text.strip()]

    assert round(section.top_margin.cm, 1) == 3.7
    assert round(section.bottom_margin.cm, 1) == 3.5
    assert round(section.left_margin.cm, 1) == 2.8
    assert round(section.right_margin.cm, 1) == 2.6
    assert texts[0] == "台海军力平衡战略分析报告"
    assert not any("绝密" in text or "机密" in text or "秘密" in text for text in texts)
    assert any("研究报告" in text for text in texts)
    assert "目          录" in texts
    assert any("DefenseTracker SOD/SOP" in text for text in texts + table_texts + header_texts)
    assert any("第一章  技术—能力—规则三维分析框架" in text for text in texts)
    assert any("附录A：来源索引" in text for text in texts)
    assert len(doc.tables) >= 3
    matrix = next(table for table in doc.tables if table.cell(0, 0).text == "维度")
    assert matrix.cell(1, 1).text == "关键装备迭代加快"
    source_index = next(table for table in doc.tables if table.cell(0, 0).text == "序号")
    assert source_index.cell(0, 2).text == "资料标题"

    title_run = doc.paragraphs[0].runs[0]
    assert title_run._element.rPr.rFonts.get(qn("w:eastAsia")) == "方正小标宋简体"
    assert title_run.font.size.pt == 26
    assert doc.paragraphs[0].alignment == WD_PARAGRAPH_ALIGNMENT.CENTER

    body_para = next(p for p in doc.paragraphs if p.text.startswith("本文基于公开源资料"))
    assert body_para.alignment == WD_PARAGRAPH_ALIGNMENT.JUSTIFY
    assert body_para.paragraph_format.first_line_indent is not None


def test_build_source_candidates_from_thinktank_directory(agent_db):
    directory = [
        {
            "id": "pla_research",
            "category": "PLA专项研究机构",
            "sites": [
                {
                    "name": "RAND China Research",
                    "name_cn": "兰德中国研究",
                    "url": "https://www.rand.org/topics/china.html",
                    "desc_cn": "军事现代化深度报告",
                    "desc_en": "China military modernization reports",
                }
            ],
        }
    ]
    project = report_agent.create_project("军事现代化战略分析报告", "strategic", topic="军事现代化")

    candidates = report_agent.build_source_candidates(project, directory, limit=5)

    assert candidates
    assert candidates[0]["source_type"] == "智库/报告源"
    assert candidates[0]["source"] == "RAND China Research"
    assert candidates[0]["quality_level"] == "A"
    assert "军事现代化" in candidates[0]["summary"]


def test_build_source_candidates_filters_china_sources_for_iran_missile_topic(agent_db):
    directory = [
        {
            "id": "china_zone",
            "category": "中国防务智库",
            "sites": [
                {
                    "name": "RAND China Research",
                    "name_cn": "兰德中国研究",
                    "url": "https://www.rand.org/topics/china.html",
                    "desc_cn": "中国军事现代化与台海军力评估",
                    "desc_en": "China military modernization reports",
                }
            ],
        },
        {
            "id": "missile_mideast_research",
            "category": "导弹与中东安全研究",
            "sites": [
                {
                    "name": "CSIS Missile Threat",
                    "name_cn": "CSIS导弹威胁项目",
                    "url": "https://missilethreat.csis.org/",
                    "desc_cn": "伊朗弹道导弹、巡航导弹与导弹作战能力评估",
                    "desc_en": "Iran ballistic missile and missile force assessments",
                }
            ],
        },
    ]
    project = report_agent.create_project(
        title="伊朗导弹作战运用战例梳理战略分析报告",
        report_type="strategic",
        topic="伊朗导弹作战运用战例梳理",
    )

    candidates = report_agent.build_source_candidates(project, directory, limit=5)

    assert candidates
    assert candidates[0]["source"] == "CSIS Missile Threat"
    assert all("China" not in row["source"] for row in candidates)


def test_build_source_candidates_honors_large_requested_source_count(agent_db):
    directory = [{
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
    }]
    project = report_agent.create_project(
        title="",
        report_type="strategic",
        client_request="帮我做一个台海军力平衡报告，搜集120份信息源",
    )

    candidates = report_agent.build_source_candidates(project, directory, limit=project["target_count"])

    assert len(candidates) == 120


def test_compose_evidence_verdict_varies_by_signal():
    ev_topic = {
        "source_type": "公开信息",
        "quality_level": "S",
        "dims": {"source": 15, "topic": 34, "density": 8, "novelty": 4, "writability": 6},
        "brief_hits": ["PLA备战", "对华威胁"],
        "date": "",
    }
    ev_density = {
        "source_type": "公开信息",
        "quality_level": "A",
        "dims": {"source": 10, "topic": 12, "density": 19, "novelty": 2, "writability": 3},
        "brief_hits": [],
        "date": "",
    }
    v_topic = report_agent._compose_evidence_verdict(ev_topic)
    v_density = report_agent._compose_evidence_verdict(ev_density)

    assert v_topic and v_density
    assert v_topic != v_density                       # 逐条拼装，非死模板
    assert len(v_topic) <= 40 and len(v_density) <= 40
    assert "契合选题" in v_topic                        # 最高维=topic
    assert "命中" in v_topic
    assert "信息密度" in v_density                      # 最高维=density


def test_compose_evidence_verdict_thinktank_without_dims():
    ev = {
        "source_type": "智库/报告源",
        "quality_level": "A",
        "quality_reasons": ["智库/报告源", "PLA专项研究机构"],
        "brief_hits": [],
        "date": "",
    }
    verdict = report_agent._compose_evidence_verdict(ev)
    assert "权威智库源" in verdict
    assert "PLA专项研究机构" in verdict                  # 类别带入，可区分不同智库卡


def test_evidence_row_surfaces_dims_and_verdict(agent_db):
    project = report_agent.create_project("台海态势", "strategic", topic="台海")
    candidate = {
        "article_id": "art-dims-1",
        "title": "台海联合演训检验体系支撑值得关注",
        "summary": "公开报道显示相关部队组织联合演训，检验远程火力与体系支撑。",
        "source": "Jamestown China Brief",
        "date": datetime.now(timezone.utc).isoformat(),
        "quality_score": 88,
        "quality_level": "A",
        "quality_reasons": ["高权威信源"],
        "brief_hits": ["PLA备战"],
        # select_quality_candidates 会把完整 quality blob 挂进候选 → payload
        "quality": {
            "total": 88,
            "level": "A",
            "dims": {"source": 17, "topic": 30, "density": 15, "novelty": 6, "writability": 8},
            "reasons": ["高权威信源"],
            "penalties": [],
        },
    }
    report_agent.upsert_project_evidence(project["project_id"], [candidate])
    evidence = report_agent.get_project_evidence(project["project_id"])

    assert len(evidence) == 1
    ev = evidence[0]
    assert ev["dims"]["topic"] == 30                    # 5 维经 payload 透出到证据行
    assert ev["verdict_line"]
    assert "命中" in ev["verdict_line"]


def test_build_source_candidates_uses_level_fn_when_provided(agent_db):
    directory = [{
        "id": "pla_research",
        "category": "PLA专项研究机构",
        "sites": [{
            "name": "RAND China Research",
            "name_cn": "兰德中国研究",
            "url": "https://www.rand.org/topics/china.html",
            "desc_cn": "军事现代化深度报告",
            "desc_en": "China military modernization reports",
        }],
    }]
    project = report_agent.create_project("军事现代化战略分析报告", "strategic", topic="军事现代化")

    def _lvl(score):
        return "S" if score >= 90 else "A" if score >= 80 else "B"

    with_fn = report_agent.build_source_candidates(project, directory, limit=5, level_fn=_lvl)
    without_fn = report_agent.build_source_candidates(project, directory, limit=5)

    assert with_fn[0]["quality_level"] == _lvl(with_fn[0]["quality_score"])   # 分数驱动，非硬编码
    assert without_fn[0]["quality_level"] == "A"                              # 默认保持不变


def test_evidence_surfaces_multi_source_corroboration(agent_db):
    project = report_agent.create_project("南海态势", "strategic", topic="南海")
    multi = {
        "article_id": "art-corrob-multi",
        "title": "多国海军南海方向演训动态汇总",
        "summary": "多家外媒同步报道相关海军活动。",
        "source": "Reuters",
        "date": datetime.now(timezone.utc).isoformat(),
        "quality_score": 80, "quality_level": "A",
        "quality_reasons": ["高权威信源"], "brief_hits": ["对华威胁"],
        "_sources": ["Reuters", "USNI News", "Naval News"],   # _dedup_articles 跨源合并结果
    }
    single = {
        "article_id": "art-corrob-single",
        "title": "某单一来源披露的装备动态",
        "summary": "仅单一来源报道。",
        "source": "SomeBlog",
        "date": datetime.now(timezone.utc).isoformat(),
        "quality_score": 60, "quality_level": "C",
        "quality_reasons": [], "brief_hits": [],
        "_sources": ["SomeBlog"],
    }
    report_agent.upsert_project_evidence(project["project_id"], [multi, single])
    ev = {e["title"]: e for e in report_agent.get_project_evidence(project["project_id"])}

    assert ev["多国海军南海方向演训动态汇总"]["corroboration_count"] == 3
    assert set(ev["多国海军南海方向演训动态汇总"]["corroborating_sources"]) == {"Reuters", "USNI News", "Naval News"}
    assert ev["某单一来源披露的装备动态"]["corroboration_count"] == 1


def test_thinktank_source_has_no_corroboration(agent_db):
    directory = [{
        "id": "pla_research", "category": "PLA专项研究机构",
        "sites": [{"name": "RAND China Research", "name_cn": "兰德中国研究",
                   "url": "https://www.rand.org/topics/china.html",
                   "desc_cn": "军事现代化", "desc_en": "reports"}],
    }]
    project = report_agent.create_project("军力评估", "strategic", topic="军力评估")
    cands = report_agent.build_source_candidates(project, directory, limit=3)
    report_agent.upsert_project_evidence(project["project_id"], cands)
    ev = report_agent.get_project_evidence(project["project_id"])

    assert ev[0]["corroboration_count"] == 0   # 智库目录源无跨源合并信息，不适用


def test_estimate_reading_minutes():
    assert report_agent.estimate_reading_minutes(0) == 1
    assert report_agent.estimate_reading_minutes(500) == 1
    assert report_agent.estimate_reading_minutes(9000) == 18


def test_build_newspaper_front_matter_extracts_structure():
    project = {"report_type": "strategic", "topic": "台海军力平衡", "voice": "newspaper"}
    content = (
        "# 台海军力平衡战略分析报告\n\n"
        "## 执行摘要\n本报告综述当前态势……\n\n"
        "## 核心判断\n"
        "1. 判断一：区域拒止能力显著增强，值得警惕。\n"
        "2. 判断二：联合作战体系加速成型。\n\n"
        "## 战略影响研判\n……\n\n"
        "## 来源附录\n……\n"
    )
    fm = report_agent.build_newspaper_front_matter(project, content, issue_date="2026.07.03")

    assert fm["issue"] == "VOL.2026.07.03"
    assert "战略分析报告" in fm["byline"] and "台海军力平衡" in fm["byline"]
    assert fm["reading_minutes"] >= 1
    assert fm["toc"] == ["执行摘要", "核心判断", "战略影响研判", "来源附录"]
    assert fm["section_count"] == 4
    assert len(fm["cards"]) == 2
    assert "区域拒止能力显著增强" in fm["cards"][0]


def test_bundle_attaches_newspaper_when_report_draft_exists(agent_db):
    project = report_agent.create_project("台海态势", "strategic", topic="台海", voice="newspaper")
    pid = project["project_id"]
    report_agent.save_draft(
        pid, "draft",
        "# 台海报告\n\n## 执行摘要\n概述。\n\n## 核心判断\n1. 判断一：形势严峻值得关注。\n",
    )
    bundle = report_agent.get_project_bundle(pid)

    assert "newspaper" in bundle
    assert bundle["newspaper"]["active"] is True
    assert "执行摘要" in bundle["newspaper"]["toc"]
    assert bundle["newspaper"]["reading_minutes"] >= 1


@pytest.mark.skipif(not report_agent.DOCX_AVAILABLE, reason="python-docx 未安装")
def test_docx_masthead_only_for_newspaper_voice(agent_db):
    from docx import Document

    def _all_text(buf):
        d = Document(buf)
        parts = [p.text for p in d.paragraphs]
        for t in d.tables:
            for row in t.rows:
                for cell in row.cells:
                    parts.append(cell.text)
        return "\n".join(parts)

    content = (
        "# 台海报告\n\n## 执行摘要\n概述若干。\n\n## 核心判断\n"
        "1. 判断一：区域态势严峻值得警惕。\n2. 判断二：联合体系加速成型。\n\n## 来源附录\n略。\n"
    )
    # newspaper voice → title page 带 masthead + 判断卡
    np = report_agent.create_project("台海报纸式", "strategic", topic="台海", voice="newspaper")
    report_agent.save_draft(np["project_id"], "draft", content)
    np_draft = report_agent.get_project_drafts(np["project_id"])[0]
    np_text = _all_text(report_agent.build_report_docx(np, np_draft))
    assert "VOL." in np_text
    assert "预计阅读" in np_text
    assert "核心判断卡" in np_text

    # 默认 strategic voice → 无 masthead（不影响既有版式）
    st = report_agent.create_project("台海常规", "strategic", topic="台海")
    report_agent.save_draft(st["project_id"], "draft", content)
    st_draft = report_agent.get_project_drafts(st["project_id"])[0]
    st_text = _all_text(report_agent.build_report_docx(st, st_draft))
    assert "预计阅读" not in st_text
    assert "核心判断卡" not in st_text
