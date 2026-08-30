import copy
import importlib
import sys
from io import BytesIO

import pytest

import app as tracker
import feishu_bot


def _load_feishu_cloud(monkeypatch):
    monkeypatch.setenv("FEISHU_APP_ID", "brief_rules_test")
    monkeypatch.setenv("FEISHU_APP_SECRET", "brief_rules_secret")
    monkeypatch.delenv("FEISHU_VERIFY_TOKEN", raising=False)
    monkeypatch.delenv("FEISHU_PUSH_CHAT_ID", raising=False)
    sys.modules.pop("feishu_cloud", None)
    return importlib.import_module("feishu_cloud")


def _valid_parsed():
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
    return {
        "event_time": "2026年8月14日",
        "value_point": "相关演训强化美军跨域协同与前沿存在，对我周边海空安全形成持续压力。",
        "title": "美军联合演训动向值得关注",
        "body": body,
        "source": "（信息来源：美国防务新闻8月14日发文《美军在西太平洋组织联合演训》）",
        "reporter": "报送人：           电话：",
    }


def _valid_text(parsed=None):
    parsed = parsed or _valid_parsed()
    return "\n".join([
        f"事件时间：{parsed['event_time']}",
        f"价 值 点：{parsed['value_point']}",
        "",
        parsed["title"],
        "",
        parsed["body"],
        "",
        parsed["source"],
        parsed["reporter"],
    ])


def _errors(parsed):
    return tracker._validate_brief(parsed)["errors"]


def test_brief_writing_rules_accept_compliant_text():
    result = tracker._validate_brief(_valid_parsed())

    assert result["valid"] is True
    assert result["errors"] == []
    assert 80 <= result["metrics"]["hat_chars"] <= 120
    assert result["metrics"]["numbered_uses_periods"] is True
    assert result["metrics"]["source_attribution_matches"] is True


@pytest.mark.parametrize("event_time", ["近期", "2026年8月", "2026年2月30日"])
def test_event_time_must_be_a_specific_valid_date(event_time):
    parsed = _valid_parsed()
    parsed["event_time"] = event_time

    assert _errors(parsed)
    assert any("事件时间" in error for error in _errors(parsed))


def test_event_time_month_and_day_must_match_hat_facts():
    parsed = _valid_parsed()
    parsed["event_time"] = "2039年1月1日"

    assert any("必须在帽段" in error for error in _errors(parsed))


def test_value_point_must_not_copy_title():
    parsed = _valid_parsed()
    parsed["value_point"] = parsed["title"] + "。"

    assert any("价值点不得复制标题" in error for error in _errors(parsed))

    parsed["value_point"] = "美军联合演训动向。"
    assert any("价值点不得复制标题" in error for error in _errors(parsed))


@pytest.mark.parametrize(
    "title",
    [
        "美军联合演训，动向值得关注",
        "美军在西太平洋持续扩大多国联合演训动向值得关注",
    ],
)
def test_title_must_be_moderate_and_have_no_comma(title):
    parsed = _valid_parsed()
    parsed["title"] = title

    assert _errors(parsed)
    if "，" in title:
        assert any("标题不得含" in error for error in _errors(parsed))
    if len(title) > 15:
        assert any("8-15字" in error for error in _errors(parsed))


def test_numbered_layers_must_use_periods():
    parsed = _valid_parsed()
    parsed["body"] = parsed["body"].replace("。（2）", "；（2）")

    assert any("各层之间必须用句号" in error for error in _errors(parsed))


def test_unnumbered_layers_may_use_chinese_semicolons():
    parsed = _valid_parsed()
    parsed["body"] = (
        parsed["body"]
        .replace("（1）", "", 1)
        .replace("。（2）", "；", 1)
        .replace("。（3）", "；", 1)
    )

    result = tracker._validate_brief(parsed)
    assert result["valid"] is True
    assert result["metrics"]["structure_style"] == "semicolon"
    assert result["metrics"]["semicolon_uses_layers"] is True


def test_unnumbered_layers_must_not_be_empty():
    parsed = _valid_parsed()
    hat, rest = parsed["body"].split("（1）", 1)
    suggestion = "建议" + rest.split("建议", 1)[1]
    parsed["body"] = hat + "；；仅第三层分析。" + suggestion

    assert any("无编号正文" in error for error in _errors(parsed))


def test_unnumbered_multi_sentence_hat_is_accepted():
    parsed = _valid_parsed()
    parsed["body"] = (
        parsed["body"]
        .replace("组织联合演训，投入", "组织联合演训。此次投入", 1)
        .replace("（1）", "", 1)
        .replace("。（2）", "；", 1)
        .replace("。（3）", "；", 1)
    )

    result = tracker._validate_brief(parsed)
    assert result["valid"] is True, result["errors"]
    assert result["metrics"]["structure_style"] == "semicolon"


def test_body_attribution_must_match_information_source():
    parsed = _valid_parsed()
    parsed["body"] = parsed["body"].replace("据美国防务新闻", "据路透社", 1)

    assert any("与信息来源行不一致" in error for error in _errors(parsed))


def test_secondary_attribution_must_also_be_listed_as_source():
    parsed = _valid_parsed()
    parsed["body"] = parsed["body"].replace(
        "。（2）",
        "。路透社称，盟军将扩大参与。（2）",
        1,
    )

    assert any("路透社" in error and "信息来源行" in error for error in _errors(parsed))


@pytest.mark.parametrize(
    "phrase",
    ["根据路透社消息，盟军将扩大参与。", "消息人士向路透社表示，盟军将扩大参与。"],
)
def test_common_secondary_source_phrases_must_be_listed(phrase):
    parsed = _valid_parsed()
    parsed["body"] = parsed["body"].replace("。（2）", f"。{phrase}（2）", 1)

    assert any("路透社" in error and "信息来源行" in error for error in _errors(parsed))


def test_body_attribution_keeps_publication_date_in_source_line_only():
    parsed = _valid_parsed()
    parsed["body"] = parsed["body"].replace("据美国防务新闻报道", "据美国防务新闻8月14日报道", 1)

    assert any("发文日期只写在信息来源行" in error for error in _errors(parsed))


def test_public_account_fallback_uses_no_date_in_attribution():
    parsed = _valid_parsed()
    parsed["body"] = parsed["body"].replace("据美国防务新闻报道", "据军情观察公众号报道", 1)
    parsed["source"] = "（信息来源：军情观察公众号8月14日发文《西太平洋联合演训动向》）"

    assert tracker._validate_brief(parsed)["valid"] is True

    dated = copy.deepcopy(parsed)
    dated["body"] = dated["body"].replace("据军情观察公众号报道", "据军情观察公众号8月14日报道", 1)
    assert any("发文日期只写在信息来源行" in error for error in _errors(dated))


@pytest.mark.parametrize("reporter", ["", "报送人：张三 电话：13800138000"])
def test_reporter_line_must_exist_and_remain_blank(reporter):
    parsed = _valid_parsed()
    parsed["reporter"] = reporter

    errors = _errors(parsed)
    assert errors
    assert any("报送人" in error for error in errors)


def test_parser_does_not_invent_missing_reporter_line():
    parsed = _valid_parsed()
    brief = "\n".join([
        f"事件时间：{parsed['event_time']}",
        f"价 值 点：{parsed['value_point']}",
        "",
        parsed["title"],
        "",
        parsed["body"],
        "",
        parsed["source"],
    ])

    result = tracker._validate_brief_text(brief)
    assert result["valid"] is False
    assert any("缺少报送人" in error for error in result["errors"])


def test_parser_rejects_content_after_reporter_line():
    result = tracker._validate_brief_text(_valid_text() + "\n附注：不应出现")

    assert result["valid"] is False
    assert any("不得附加" in error for error in result["errors"])


def test_source_context_binds_event_and_publication_dates_to_material():
    parsed = _valid_parsed()
    context = tracker._brief_source_context(
        material_text=(
            "美国防务新闻2026年8月14日报道，美军8月14日在西太平洋组织联合演训。"
        ),
        source_name="美国防务新闻",
        source_title="美军在西太平洋组织联合演训",
        publication_date="2026-08-14",
        publication_date_verified=True,
    )
    valid = tracker._validate_brief(parsed, source_context=context)
    assert valid["valid"] is True, valid["errors"]
    assert valid["metrics"]["event_date_supported_by_material"] is True
    assert valid["metrics"]["publication_date_matches_material"] is True

    fabricated = copy.deepcopy(parsed)
    fabricated["event_time"] = "2039年1月1日"
    fabricated["body"] = fabricated["body"].replace("8月14日", "1月1日", 1)
    errors = tracker._validate_brief(fabricated, source_context=context)["errors"]
    assert any("原始素材" in error and "事件时间" in error for error in errors)

    wrong_publication = tracker._brief_source_context(
        material_text=context["material_text"],
        source_name="美国防务新闻",
        source_title="美军在西太平洋组织联合演训",
        publication_date="2026-08-15",
        publication_date_verified=True,
    )
    errors = tracker._validate_brief(parsed, source_context=wrong_publication)["errors"]
    assert any("发布日期不一致" in error for error in errors)


def test_article_date_is_not_treated_as_verified_without_explicit_marker():
    parsed = _valid_parsed()
    article = {
        "title": "美军在西太平洋组织联合演训",
        "summary": "美国防务新闻称，美军8月14日在西太平洋组织联合演训。",
        "source_cn": "美国防务新闻",
        "date": "2026-08-14",
    }

    context = tracker._brief_source_context_from_article(article)
    result = tracker._validate_brief(parsed, source_context=context)

    assert context["publication_date_verified"] is False
    assert any("缺少可核实的发文日期" in error for error in result["errors"])


def test_cloud_validator_accepts_semicolon_in_hat_and_at_least_three_layers(monkeypatch):
    feishu_cloud = _load_feishu_cloud(monkeypatch)
    parsed = _valid_parsed()
    hat, rest = parsed["body"].split("（1）", 1)
    hat = hat.replace("投入水面舰艇、战机和无人侦察平台，", "投入水面舰艇、战机和无人侦察平台；")
    layers, suggestion = rest.split("建议", 1)
    layers = layers.replace("。（2）", "；").replace("。（3）", "；")
    body = hat + layers + "；还需关注相关保障节点变化。建议" + suggestion
    brief = "\n".join([
        f"事件时间：{parsed['event_time']}",
        f"价 值 点：{parsed['value_point']}",
        "",
        parsed["title"],
        "",
        body,
        "",
        parsed["source"],
        parsed["reporter"],
    ])

    result = feishu_cloud._validate_brief_text(brief)
    assert result["valid"] is True, result["errors"]


def test_cloud_validator_binds_dates_and_source_to_evidence(monkeypatch):
    feishu_cloud = _load_feishu_cloud(monkeypatch)
    parsed = _valid_parsed()
    evidence = feishu_cloud._brief_evidence(
        material_text="Defense News 2026年8月14日报道，美军8月14日在西太平洋组织联合演训。",
        source_name="Defense News",
        source_title="US military holds Western Pacific drill",
        publication_date="2026-08-14",
        publication_date_verified=True,
        url="https://www.defensenews.com/example",
    )
    valid = feishu_cloud._validate_brief_text(_valid_text(parsed), evidence=evidence)
    assert valid["valid"] is True, valid["errors"]

    fabricated = copy.deepcopy(parsed)
    fabricated["event_time"] = "2039年1月1日"
    fabricated["body"] = fabricated["body"].replace("8月14日", "1月1日", 1)
    errors = feishu_cloud._validate_brief_text(
        _valid_text(fabricated), evidence=evidence,
    )["errors"]
    assert any("事件时间未在原始素材" in error for error in errors)


@pytest.mark.parametrize(
    "body_suffix, reporter, expected_error",
    [
        ("；；仅第三层分析。", "报送人：           电话：", "无编号正文"),
        (None, "报送人：张三 电话：13800138000", "报送人和电话"),
        (None, "", "缺少报送人电话行"),
    ],
)
def test_cloud_validator_rejects_empty_layers_and_reporter_pii(
    monkeypatch, body_suffix, reporter, expected_error,
):
    feishu_cloud = _load_feishu_cloud(monkeypatch)
    parsed = _valid_parsed()
    body = parsed["body"]
    if body_suffix is not None:
        hat, rest = body.split("（1）", 1)
        body = hat + body_suffix + "建议" + rest.split("建议", 1)[1]
    brief = "\n".join([
        f"事件时间：{parsed['event_time']}",
        f"价 值 点：{parsed['value_point']}",
        "",
        parsed["title"],
        "",
        body,
        "",
        parsed["source"],
        reporter,
    ])

    result = feishu_cloud._validate_brief_text(brief)
    assert result["valid"] is False
    assert any(expected_error in error for error in result["errors"])


def test_multiple_sources_must_be_complete_and_use_chinese_semicolon():
    parsed = _valid_parsed()
    parsed["source"] = (
        "（信息来源：美国防务新闻8月14日发文《美军在西太平洋组织联合演训》；"
        "路透社8月14日发文《盟军扩大西太平洋演训》）"
    )
    assert tracker._validate_brief(parsed)["valid"] is True

    parsed["source"] = parsed["source"].replace("；", ";")
    assert any("中文分号" in error for error in _errors(parsed))

    parsed["source"] = (
        "（信息来源：路透社8月14日发文《盟军扩大西太平洋演训》；"
        "美国防务新闻8月14日发文《美军在西太平洋组织联合演训》）"
    )
    assert any("信息来源第一条" in error for error in _errors(parsed))

    parsed["source"] = "（信息来源：美国防务新闻发文《美军在西太平洋组织联合演训》）"
    assert any("每条均须写成" in error for error in _errors(parsed))


def test_prompt_builders_include_latest_writing_gates():
    article = {
        "title": "Test",
        "summary": "Summary",
        "source": "Defense News",
        "source_cn": "美国防务新闻",
        "region": "美国",
        "date": "2026-08-14T00:00:00+00:00",
        "link": "https://example.com/article",
    }
    rss_prompt = tracker._build_brief_user_prompt(article)
    imported_prompt = tracker._build_brief_user_prompt_imported(
        title="Test",
        body="Summary",
        source="美国防务新闻",
        pub_date="2026-08-14",
    )
    prompts = [tracker.SYSTEM_PROMPT_BRIEF_WRITE, rss_prompt, imported_prompt]

    for prompt in prompts:
        assert "价值点" in prompt and "复制标题" in prompt
        assert "8-15字" in prompt
        assert "公众号" in prompt and "第一信源" in prompt
        assert "3-4行" in prompt
        assert "多个来源" in prompt or "其他来源" in prompt
        assert "不得" in prompt and "发文日期" in prompt
        assert "分号" in prompt

    for prompt in (rss_prompt, imported_prompt):
        assert '"据美国防务新闻报道，"' in prompt
        assert "据美国防务新闻08月14日报道" not in prompt


def test_web_generation_does_not_persist_invalid_output(monkeypatch):
    invalid_brief = """事件时间：近期
价 值 点：测试

标题，值得关注

据外媒报道，内容过短。
（信息来源：外媒发文《测试》）
报送人：           电话："""
    persisted = []
    monkeypatch.setitem(tracker.AI_CONFIG, "api_key", "test-key")
    monkeypatch.setattr(tracker, "_call_ai", lambda *args, **kwargs: invalid_brief)
    monkeypatch.setattr(tracker, "_persist_brief_to_disk", lambda *args, **kwargs: persisted.append(True))

    trusted_article = {
        "title": "Test",
        "summary": "Summary",
        "source": "Defense News",
        "source_cn": "美国防务新闻",
        "date": "2026-08-14T00:00:00+00:00",
        "publication_date_verified": True,
        "link": "https://example.com/article",
    }
    monkeypatch.setitem(tracker.cache, "news", [trusted_article])
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = "brief-rules-csrf"
    client.set_cookie(tracker.CSRF_COOKIE, csrf)
    response = client.post(
        "/api/brief/generate",
        json={
            "article": {"link": trusted_article["link"]}
        },
        headers={tracker.CSRF_HEADER: csrf},
    )

    assert response.status_code == 422
    assert "要讯校验未通过" in response.get_json()["error"]
    assert persisted == []


def test_docx_export_blocks_invalid_manual_edits():
    invalid_brief = """事件时间：近期
价 值 点：测试

标题，值得关注

据外媒报道，内容过短。
（信息来源：外媒发文《测试》）
报送人：           电话："""
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = "brief-export-csrf"
    client.set_cookie(tracker.CSRF_COOKIE, csrf)

    response = client.post(
        "/api/brief/export_docx",
        json={"brief": invalid_brief},
        headers={tracker.CSRF_HEADER: csrf},
    )

    assert response.status_code == 422
    assert "要讯校验未通过" in response.get_json()["error"]


@pytest.mark.parametrize("endpoint", [
    "/api/brief/export_docx",
    "/api/brief/export_docx_compiled",
])
def test_docx_exports_reject_oversized_text_without_internal_error(endpoint):
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = "brief-export-limit-csrf"
    client.set_cookie(tracker.CSRF_COOKIE, csrf)
    context = tracker._brief_source_context(
        material_text="美国防务新闻2026年8月14日报道，美军组织联合演训。",
        source_name="美国防务新闻",
        source_title="美军组织联合演训",
        publication_date="2026-08-14",
        publication_date_verified=True,
    )
    evidence = tracker._brief_seal_source_context(context)
    oversized = "x" * (tracker.MAX_BRIEF_TEXT_CHARS + 1)
    payload = {"brief": oversized, "source_evidence": evidence}
    if endpoint.endswith("_compiled"):
        payload = {"briefs": [payload]}

    response = client.post(
        endpoint,
        json=payload,
        headers={tracker.CSRF_HEADER: csrf},
    )

    assert response.status_code == 422
    body = response.get_json()
    assert "16 KiB" in str(body)


@pytest.mark.parametrize("endpoint", [
    "/api/brief/export_docx",
    "/api/brief/export_docx_compiled",
    "/api/brief/validate",
])
def test_brief_endpoints_do_not_reflect_unexpected_validation_exception(
    monkeypatch, endpoint
):
    private_detail = (
        "validation failed at C:\\Users\\private\\brief.key "
        "https://private.example.test/?token=secret\r\nTRACEBACK"
    )

    def reject_text(_brief):
        raise ValueError(private_detail)

    monkeypatch.setattr(tracker, "_enforce_brief_text_limits", reject_text)
    monkeypatch.setattr(tracker, "_brief_open_source_evidence", lambda _value: {})
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = "brief-validation-exception-csrf"
    client.set_cookie(tracker.CSRF_COOKIE, csrf)

    payload = {"brief": "non-empty", "source_evidence": {}}
    if endpoint.endswith("_compiled"):
        payload = {"briefs": [payload]}

    response = client.post(
        endpoint,
        json=payload,
        headers={tracker.CSRF_HEADER: csrf},
    )

    assert response.status_code == 422
    if endpoint.endswith("_compiled"):
        assert response.get_json() == {
            "error": "要讯汇编校验未通过",
            "invalid_items": [{"index": 1, "errors": ["请求参数无效"]}],
        }
    else:
        assert response.get_json() == {
            "error": "要讯校验未通过: 请求参数无效"
        }
    response_text = response.get_data(as_text=True)
    assert private_detail not in response_text
    assert "private.example.test" not in response_text
    assert "TRACEBACK" not in response_text


@pytest.mark.parametrize(
    "override,expected_error",
    [
        ({"body": "x" * (tracker.MAX_BRIEF_LINE_CHARS + 1)}, "4 KiB"),
        ({"body": ["not", "text"]}, "必须是字符串"),
    ],
)
def test_docx_export_rejects_unsafe_structured_overrides(
    override, expected_error
):
    brief = """事件时间：近期
价 值 点：测试

标题值得关注

据外媒报道，内容过短。
（信息来源：外媒8月14日发文《测试》）
报送人：           电话："""
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = "brief-export-override-limit-csrf"
    client.set_cookie(tracker.CSRF_COOKIE, csrf)
    context = tracker._brief_source_context(
        material_text="美国防务新闻2026年8月14日报道，美军组织联合演训。",
        source_name="美国防务新闻",
        source_title="美军组织联合演训",
        publication_date="2026-08-14",
        publication_date_verified=True,
    )
    evidence = tracker._brief_seal_source_context(context)

    response = client.post(
        "/api/brief/export_docx",
        json={"brief": brief, "source_evidence": evidence, **override},
        headers={tracker.CSRF_HEADER: csrf},
    )

    assert response.status_code == 422
    assert expected_error in response.get_json()["error"]


@pytest.mark.parametrize("payload", [{"brief": ["not", "text"]}, []])
def test_docx_export_rejects_non_object_or_non_string_brief(payload):
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = "brief-export-json-shape-csrf"
    client.set_cookie(tracker.CSRF_COOKIE, csrf)

    response = client.post(
        "/api/brief/export_docx",
        json=payload,
        headers={tracker.CSRF_HEADER: csrf},
    )

    assert response.status_code in {400, 422}
    assert response.status_code != 500


def test_docx_export_requires_untampered_server_signed_source_evidence():
    context = tracker._brief_source_context(
        material_text="美国防务新闻2026年8月14日报道，美军8月14日在西太平洋组织联合演训。",
        source_name="美国防务新闻",
        source_title="美军在西太平洋组织联合演训",
        publication_date="2026-08-14",
        publication_date_verified=True,
    )
    evidence = tracker._brief_seal_source_context(context)
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = "brief-evidence-csrf"
    client.set_cookie(tracker.CSRF_COOKIE, csrf)

    valid = client.post(
        "/api/brief/export_docx",
        json={"brief": _valid_text(), "source_evidence": evidence},
        headers={tracker.CSRF_HEADER: csrf},
    )
    assert valid.status_code == 200

    tampered = copy.deepcopy(evidence)
    tampered["payload"]["material_text"] = "伪造材料称2039年1月1日发生事件。"
    rejected = client.post(
        "/api/brief/export_docx",
        json={"brief": _valid_text(), "source_evidence": tampered},
        headers={tracker.CSRF_HEADER: csrf},
    )
    assert rejected.status_code == 422
    assert "被修改" in rejected.get_json()["error"]


def test_client_supplied_source_article_cannot_self_certify_fabricated_event_date():
    fabricated = copy.deepcopy(_valid_parsed())
    fabricated["event_time"] = "2039年1月1日"
    fabricated["body"] = fabricated["body"].replace("8月14日", "1月1日", 1)
    tracker.app.config["TESTING"] = True
    client = tracker.app.test_client()
    csrf = "brief-forged-context-csrf"
    client.set_cookie(tracker.CSRF_COOKIE, csrf)

    response = client.post(
        "/api/brief/export_docx",
        json={
            "brief": _valid_text(fabricated),
            "source_article": {
                "source_cn": "美国防务新闻",
                "summary": "伪造摘要称2039年1月1日发生事件。",
                "date": "2026-08-14",
                "publication_date_verified": True,
            },
        },
        headers={tracker.CSRF_HEADER: csrf},
    )

    assert response.status_code == 422
    assert "服务器签发" in response.get_json()["error"]


def test_generate_resolves_source_facts_only_from_server_cache(monkeypatch):
    trusted_article = {
        "title": "美军在西太平洋组织联合演训",
        "summary": "美国防务新闻2026年8月14日报道，美军8月14日在西太平洋组织联合演训。",
        "source": "Defense News",
        "source_cn": "美国防务新闻",
        "date": "2026-08-14T00:00:00+00:00",
        "publication_date_verified": True,
        "link": "https://example.com/trusted-brief-source",
    }
    monkeypatch.setitem(tracker.cache, "news", [trusted_article])
    monkeypatch.setitem(tracker.AI_CONFIG, "api_key", "test-key")
    monkeypatch.setattr(tracker, "_call_ai", lambda *args, **kwargs: _valid_text())
    monkeypatch.setattr(tracker, "_persist_brief_to_disk", lambda *args, **kwargs: "")
    monkeypatch.setattr(tracker, "record_quality_generation", lambda *args, **kwargs: "trusted-id")
    client = tracker.app.test_client()
    csrf = "trusted-article-csrf"
    client.set_cookie(tracker.CSRF_COOKIE, csrf)

    response = client.post(
        "/api/brief/generate",
        json={
            "article": {
                "link": trusted_article["link"],
                "summary": "伪造摘要称2039年1月1日发生事件。",
                "source_cn": "伪造来源",
                "date": "2039-01-01",
                "publication_date_verified": True,
            }
        },
        headers={tracker.CSRF_HEADER: csrf},
    )

    assert response.status_code == 200, response.get_json()
    payload = response.get_json()
    assert payload["source_article"]["source_cn"] == "美国防务新闻"
    assert payload["source_article"]["date"] == trusted_article["date"]
    assert "2039" not in payload["source_evidence"]["payload"]["material_text"]
    assert payload["source_evidence"]["payload"]["origin"] == "rss_cache"


def test_trusted_source_can_be_resolved_by_server_article_id_only(monkeypatch):
    trusted_article = {
        "title": "Article ID only",
        "summary": "Server-owned summary",
        "source": "Defense News",
        "date": "2026-08-14T00:00:00+00:00",
        "publication_date_verified": True,
        "link": "https://example.com/article-id-only",
    }
    article_id = tracker._article_id(trusted_article)
    monkeypatch.setitem(tracker.cache, "news", [trusted_article])

    resolved = tracker._resolve_trusted_brief_article({"article_id": article_id})

    assert resolved["article_id"] == article_id
    assert resolved["summary"] == "Server-owned summary"


def test_quality_database_row_cannot_be_used_as_trusted_source(monkeypatch, tmp_path):
    poisoned = {
        "title": "Poisoned quality row",
        "summary": "Client-controlled database content",
        "source": "Untrusted",
        "date": "2039-01-01",
        "link": "https://example.com/quality-only",
    }
    monkeypatch.setattr(tracker, "_QUALITY_DB_FILE", str(tmp_path / "quality.sqlite3"))
    article_id = tracker.record_quality_generation(poisoned, "draft", {}, "generated")
    monkeypatch.setitem(tracker.cache, "news", [])

    with pytest.raises(tracker._BriefArticleStaleError):
        tracker._resolve_trusted_brief_article({"article_id": article_id})


def test_generate_rejects_unknown_or_conflicting_article_before_ai(monkeypatch):
    first = {
        "title": "First",
        "summary": "First summary",
        "source": "Defense News",
        "date": "2026-08-14T00:00:00+00:00",
        "publication_date_verified": True,
        "link": "https://example.com/first",
    }
    second = {**first, "title": "Second", "link": "https://example.com/second"}
    first["aid"] = tracker.canonical_article_id(first["link"])
    second["aid"] = tracker.canonical_article_id(second["link"])
    monkeypatch.setitem(tracker.cache, "news", [first, second])
    monkeypatch.setitem(tracker.AI_CONFIG, "api_key", "test-key")
    ai_calls = []
    monkeypatch.setattr(tracker, "_call_ai", lambda *args, **kwargs: ai_calls.append(True))
    client = tracker.app.test_client()
    csrf = "article-conflict-csrf"
    client.set_cookie(tracker.CSRF_COOKIE, csrf)
    headers = {tracker.CSRF_HEADER: csrf}

    unknown = client.post(
        "/api/brief/generate",
        json={"article": {"link": "https://example.com/unknown"}},
        headers=headers,
    )
    conflict = client.post(
        "/api/brief/generate",
        json={"article": {"aid": first["aid"], "link": second["link"]}},
        headers=headers,
    )

    assert unknown.status_code == 409
    assert conflict.status_code == 400
    assert ai_calls == []


def test_explicit_batch_rejects_unknown_article_before_streaming(monkeypatch):
    monkeypatch.setitem(tracker.cache, "news", [])
    monkeypatch.setitem(tracker.AI_CONFIG, "api_key", "test-key")
    ai_calls = []
    monkeypatch.setattr(tracker, "_call_ai", lambda *args, **kwargs: ai_calls.append(True))
    client = tracker.app.test_client()
    csrf = "batch-stale-csrf"
    client.set_cookie(tracker.CSRF_COOKIE, csrf)

    response = client.post(
        "/api/brief/batch",
        json={"articles": [{"link": "https://example.com/not-cached"}]},
        headers={tracker.CSRF_HEADER: csrf},
    )

    assert response.status_code == 409
    assert response.mimetype == "application/json"
    assert ai_calls == []


def test_brief_evidence_key_survives_normal_process_restart(monkeypatch, tmp_path):
    key_file = tmp_path / ".brief_evidence.key"
    monkeypatch.delenv("BRIEF_EVIDENCE_SIGNING_KEY", raising=False)
    monkeypatch.setattr(tracker, "_BRIEF_EVIDENCE_KEY_FILE", str(key_file))
    monkeypatch.setattr(tracker, "_BRIEF_EVIDENCE_SIGNING_KEY", None)
    context = tracker._brief_source_context(
        material_text="美国防务新闻2026年8月14日报道，美军8月14日组织联合演训。",
        source_name="美国防务新闻",
        source_title="美军在西太平洋组织联合演训",
        publication_date="2026-08-14",
        publication_date_verified=True,
        origin="rss_cache",
    )
    evidence = tracker._brief_seal_source_context(context)

    monkeypatch.setattr(tracker, "_BRIEF_EVIDENCE_SIGNING_KEY", None)
    reopened = tracker._brief_open_source_evidence(evidence)

    assert reopened["source_name"] == "美国防务新闻"
    assert reopened["origin"] == "rss_cache"
    assert key_file.read_text(encoding="ascii").strip()


def test_validate_endpoint_rejects_edited_facts_against_signed_source(monkeypatch):
    context = tracker._brief_source_context(
        material_text="美国防务新闻2026年8月14日报道，美军8月14日在西太平洋组织联合演训。",
        source_name="美国防务新闻",
        source_title="美军在西太平洋组织联合演训",
        publication_date="2026-08-14",
        publication_date_verified=True,
        origin="rss_cache",
    )
    evidence = tracker._brief_seal_source_context(context)
    edited = copy.deepcopy(_valid_parsed())
    edited["event_time"] = "2039年1月1日"
    edited["body"] = edited["body"].replace("8月14日", "1月1日", 1)
    client = tracker.app.test_client()
    csrf = "brief-validate-csrf"
    client.set_cookie(tracker.CSRF_COOKIE, csrf)

    response = client.post(
        "/api/brief/validate",
        json={"brief": _valid_text(edited), "source_evidence": evidence},
        headers={tracker.CSRF_HEADER: csrf},
    )

    assert response.status_code == 422
    assert "原始素材" in response.get_json()["error"]


def test_imported_source_text_is_not_written_to_quality_training_db(monkeypatch):
    quality_calls = []
    monkeypatch.setitem(tracker.AI_CONFIG, "api_key", "test-key")
    monkeypatch.setattr(tracker, "_check_rate", lambda *args, **kwargs: True)
    monkeypatch.setattr(tracker, "_call_ai", lambda *args, **kwargs: _valid_text())
    monkeypatch.setattr(tracker, "_persist_brief_to_disk", lambda *args, **kwargs: "")
    monkeypatch.setattr(
        tracker,
        "record_quality_generation",
        lambda *args, **kwargs: quality_calls.append(args),
    )
    client = tracker.app.test_client()
    csrf = "import-privacy-csrf"
    client.set_cookie(tracker.CSRF_COOKIE, csrf)

    response = client.post(
        "/api/brief/import_text",
        json={
            "title": "美军在西太平洋组织联合演训",
            "text": "美国防务新闻2026年8月14日报道，美军8月14日在西太平洋组织联合演训，并披露跨域协同和保障安排。",
            "source": "美国防务新闻",
            "pub_date": "2026-08-14",
        },
        headers={tracker.CSRF_HEADER: csrf},
    )

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["article_id"].startswith("import-")
    assert quality_calls == []


@pytest.mark.parametrize(
    "private_path",
    (
        "C:" + r"\Users\placeholder\DefenseTracker\brief.docx",
        "/home/private-user/DefenseTracker/brief.docx",
    ),
)
def test_public_brief_saved_name_is_cross_platform_basename(private_path):
    assert tracker._public_brief_saved_name(private_path) == "brief.docx"


def test_brief_validation_rejects_oversized_text_before_regex_parsing(monkeypatch):
    monkeypatch.setattr(
        tracker,
        "_parse_brief_text",
        lambda _value: pytest.fail("oversized brief must not reach parsers"),
    )

    with pytest.raises(ValueError, match="16 KiB"):
        tracker._validate_brief_text("x" * (tracker.MAX_BRIEF_TEXT_CHARS + 1))
    with pytest.raises(ValueError, match="4 KiB"):
        tracker._validate_brief_text("x" * (tracker.MAX_BRIEF_LINE_CHARS + 1))


def test_brief_parser_enforces_central_size_limits_when_called_directly():
    with pytest.raises(ValueError, match="16 KiB"):
        tracker._parse_brief_text("x" * (tracker.MAX_BRIEF_TEXT_CHARS + 1))
    with pytest.raises(ValueError, match="4 KiB"):
        tracker._parse_brief_text("x" * (tracker.MAX_BRIEF_LINE_CHARS + 1))


def test_brief_source_parser_handles_entries_without_backtracking_regex():
    entries, invalid, raw = tracker._parse_brief_source_entries(
        "（信息来源：美国防务新闻8月14日发文《联合演训动态》；"
        "路透社8月15日发文《盟军后续部署》）"
    )

    assert invalid == []
    assert raw.endswith("《盟军后续部署》")
    assert entries == [
        {"name": "美国防务新闻", "month": 8, "day": 14, "title": "联合演训动态"},
        {"name": "路透社", "month": 8, "day": 15, "title": "盟军后续部署"},
    ]


def test_brief_json_and_sse_responses_hide_absolute_saved_path(monkeypatch, tmp_path):
    private_path = tmp_path / "private-user" / "brief.docx"
    trusted_article = {
        "title": "美军在西太平洋组织联合演训",
        "summary": "美国防务新闻2026年8月14日报道，美军8月14日在西太平洋组织联合演训。",
        "source": "Defense News",
        "source_cn": "美国防务新闻",
        "date": "2026-08-14T00:00:00+00:00",
        "publication_date_verified": True,
        "link": "https://example.com/private-path-test",
    }
    monkeypatch.setitem(tracker.cache, "news", [trusted_article])
    monkeypatch.setitem(tracker.AI_CONFIG, "api_key", "test-key")
    monkeypatch.setattr(tracker, "_check_rate", lambda *args, **kwargs: True)
    monkeypatch.setattr(tracker, "_call_ai", lambda *args, **kwargs: _valid_text())
    monkeypatch.setattr(
        tracker, "_persist_brief_to_disk", lambda *args, **kwargs: str(private_path)
    )
    monkeypatch.setattr(
        tracker, "record_quality_generation", lambda *args, **kwargs: "article-id"
    )
    client = tracker.app.test_client()
    csrf = "saved-path-csrf"
    client.set_cookie(tracker.CSRF_COOKIE, csrf)
    headers = {tracker.CSRF_HEADER: csrf}

    generated = client.post(
        "/api/brief/generate",
        json={"article": {"link": trusted_article["link"]}},
        headers=headers,
    )
    streamed = client.post(
        "/api/brief/batch",
        json={"count": 1, "articles": [{"link": trusted_article["link"]}]},
        headers=headers,
    )

    assert generated.status_code == 200, generated.get_json()
    assert generated.get_json()["saved_to"] == "brief.docx"
    stream_text = streamed.get_data(as_text=True)
    assert '"saved_to": "brief.docx"' in stream_text
    assert str(private_path.parent) not in generated.get_data(as_text=True)
    assert str(private_path.parent) not in stream_text


def test_import_text_response_hides_absolute_saved_path(monkeypatch, tmp_path):
    private_path = tmp_path / "private-user" / "imported.docx"
    monkeypatch.setitem(tracker.AI_CONFIG, "api_key", "test-key")
    monkeypatch.setattr(tracker, "_check_rate", lambda *args, **kwargs: True)
    monkeypatch.setattr(tracker, "_call_ai", lambda *args, **kwargs: _valid_text())
    monkeypatch.setattr(
        tracker, "_persist_brief_to_disk", lambda *args, **kwargs: str(private_path)
    )
    client = tracker.app.test_client()
    csrf = "import-saved-path-csrf"
    client.set_cookie(tracker.CSRF_COOKIE, csrf)

    response = client.post(
        "/api/brief/import_text",
        json={
            "title": "美军在西太平洋组织联合演训",
            "text": "美国防务新闻2026年8月14日报道，美军8月14日在西太平洋组织联合演训，并披露跨域协同和保障安排。",
            "source": "美国防务新闻",
            "pub_date": "2026-08-14",
        },
        headers={tracker.CSRF_HEADER: csrf},
    )

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["saved_to"] == "imported.docx"
    assert str(private_path.parent) not in response.get_data(as_text=True)


def test_import_url_and_file_responses_hide_absolute_saved_path(
    monkeypatch, tmp_path
):
    private_path = tmp_path / "private-user" / "imported.docx"
    extracted = {
        "title": "美军在西太平洋组织联合演训",
        "body": "美国防务新闻2026年8月14日报道，美军8月14日在西太平洋组织联合演训，并披露跨域协同和保障安排。",
        "source": "美国防务新闻",
        "pub_date": "2026-08-14",
    }
    monkeypatch.setitem(tracker.AI_CONFIG, "api_key", "test-key")
    monkeypatch.setattr(tracker, "_check_rate", lambda *args, **kwargs: True)
    monkeypatch.setattr(tracker, "_call_ai", lambda *args, **kwargs: _valid_text())
    monkeypatch.setattr(tracker, "_is_ssrf_safe", lambda *_args: (True, ""))
    monkeypatch.setattr(tracker, "_extract_url_content", lambda *_args: extracted)
    monkeypatch.setattr(tracker, "_extract_file_text", lambda *_args: extracted)
    monkeypatch.setattr(
        tracker, "_persist_brief_to_disk", lambda *args, **kwargs: str(private_path)
    )
    client = tracker.app.test_client()
    csrf = "import-url-file-saved-path-csrf"
    client.set_cookie(tracker.CSRF_COOKIE, csrf)
    headers = {tracker.CSRF_HEADER: csrf}

    from_url = client.post(
        "/api/brief/import_url",
        json={"url": "https://example.test/report"},
        headers=headers,
    )
    from_file = client.post(
        "/api/brief/import_file",
        data={
            "file": (BytesIO(b"source"), "report.txt"),
            "source": "美国防务新闻",
            "pub_date": "2026-08-14",
        },
        headers=headers,
        content_type="multipart/form-data",
    )

    for response in (from_url, from_file):
        assert response.status_code == 200, response.get_json()
        assert response.get_json()["saved_to"] == "imported.docx"
        assert str(private_path.parent) not in response.get_data(as_text=True)


def test_import_url_ssrf_rejection_is_fixed_public_error_and_never_fetches(
    monkeypatch,
):
    private_reason = (
        "resolved 169.254.169.254 via private resolver id=internal-7"
    )
    monkeypatch.setattr(tracker, "_check_rate", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        tracker,
        "_is_ssrf_safe",
        lambda *_args: (False, private_reason),
    )
    monkeypatch.setattr(
        tracker,
        "_extract_url_content",
        lambda *_args, **_kwargs: pytest.fail(
            "an SSRF-rejected URL must never reach the fetcher"
        ),
    )
    client = tracker.app.test_client()
    csrf = "import-url-ssrf-csrf"
    client.set_cookie(tracker.CSRF_COOKIE, csrf)

    response = client.post(
        "/api/brief/import_url",
        json={"url": "http://169.254.169.254/latest/meta-data"},
        headers={tracker.CSRF_HEADER: csrf},
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": "URL不安全，已拒绝访问"}
    assert private_reason not in response.get_data(as_text=True)


def test_brief_api_error_does_not_echo_or_log_absolute_path(
    monkeypatch, tmp_path, caplog
):
    private_path = tmp_path / "private-user" / "failed.docx"
    trusted_article = {
        "title": "美军在西太平洋组织联合演训",
        "summary": "美国防务新闻2026年8月14日报道，美军8月14日在西太平洋组织联合演训。",
        "source": "Defense News",
        "source_cn": "美国防务新闻",
        "date": "2026-08-14T00:00:00+00:00",
        "publication_date_verified": True,
        "link": "https://example.com/private-error-test",
    }
    monkeypatch.setitem(tracker.cache, "news", [trusted_article])
    monkeypatch.setitem(tracker.AI_CONFIG, "api_key", "test-key")
    monkeypatch.setattr(tracker, "_check_rate", lambda *args, **kwargs: True)

    def fail(*args, **kwargs):
        raise OSError(f"cannot write {private_path}")

    monkeypatch.setattr(tracker, "_call_ai", fail)
    client = tracker.app.test_client()
    csrf = "brief-error-path-csrf"
    client.set_cookie(tracker.CSRF_COOKIE, csrf)

    with caplog.at_level("ERROR", logger=tracker.logger.name):
        response = client.post(
            "/api/brief/generate",
            json={"article": {"link": trusted_article["link"]}},
            headers={tracker.CSRF_HEADER: csrf},
        )
        streamed = client.post(
            "/api/brief/batch",
            json={"count": 1, "articles": [{"link": trusted_article["link"]}]},
            headers={tracker.CSRF_HEADER: csrf},
        )

    assert response.status_code == 500
    assert str(private_path) not in response.get_data(as_text=True)
    assert str(private_path) not in streamed.get_data(as_text=True)
    assert str(private_path) not in caplog.text


def test_local_feishu_stops_before_card_and_docx_for_invalid_brief(monkeypatch):
    invalid_brief = """事件时间：近期
价 值 点：测试

标题，值得关注

据外媒报道，内容过短。
（信息来源：外媒发文《测试》）
报送人：           电话："""
    sent_cards = []
    docx_calls = []
    monkeypatch.setitem(tracker.AI_CONFIG, "api_key", "test-key")
    monkeypatch.setattr(tracker, "_call_ai", lambda *args, **kwargs: invalid_brief)
    monkeypatch.setattr(feishu_bot, "send_text", lambda *args, **kwargs: None)
    monkeypatch.setattr(feishu_bot, "send_card", lambda _chat_id, card: sent_cards.append(card))
    monkeypatch.setattr(feishu_bot, "_generate_brief_docx", lambda *args, **kwargs: docx_calls.append(True))

    feishu_bot._process_async("test-chat", "这是一段长度超过三十字的用户导入素材，用于验证不合规要讯不会被发送或导出。")

    assert len(sent_cards) == 1
    assert "未通过写作规范" in str(sent_cards[0])
    assert docx_calls == []


def test_docx_section_parsers_never_fill_missing_event_time_with_today(monkeypatch):
    incomplete = _valid_text().replace("事件时间：2026年8月14日\n", "", 1)
    cloud = _load_feishu_cloud(monkeypatch)

    with pytest.raises(ValueError, match="结构不完整"):
        feishu_bot._parse_brief_sections(incomplete)
    with pytest.raises(ValueError, match="结构不完整"):
        cloud._parse_brief_sections(incomplete)
