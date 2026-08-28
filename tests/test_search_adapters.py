import pytest

import search_adapters


def _clear_search_env(monkeypatch):
    for name in [
        "SEARCH_PROVIDER",
        "TAVILY_API_KEY",
        "BRAVE_SEARCH_API_KEY",
        "SERPAPI_API_KEY",
    ]:
        monkeypatch.delenv(name, raising=False)


def test_search_status_reports_provider_matrix_without_keys(monkeypatch):
    _clear_search_env(monkeypatch)

    status = search_adapters.search_status(config={})

    assert status["online_search_enabled"] is True
    assert status["web_search_enabled"] is True
    assert status["provider"] == "public_web"
    assert status["providers"]["public_web"]["enabled"] is True
    assert status["site_crawl_enabled"] is True
    assert status["rss_aux_enabled"] is True
    assert status["providers"]["tavily"]["enabled"] is False
    assert status["providers"]["brave"]["enabled"] is False
    assert status["providers"]["serpapi"]["enabled"] is False
    assert "基础联网搜索" in status["message"]


def test_public_web_search_is_used_without_api_key(monkeypatch):
    _clear_search_env(monkeypatch)

    def fake_public(query, limit, **kwargs):
        return [
            {
                "title": "RAND report on Taiwan unmanned systems",
                "source": "RAND",
                "url": "https://www.rand.org/report.pdf",
                "snippet": "Think tank report.",
            }
        ]

    monkeypatch.setattr(search_adapters, "_search_public_web", fake_public)

    rows, meta = search_adapters.search_web_multi(
        ["taiwan unmanned systems think tank report"],
        target_count=1,
        config={},
        include_pdf=False,
        include_doctrine=False,
    )

    assert len(rows) == 1
    assert rows[0]["provider"] == "public_web"
    assert meta["provider_stats"]["public_web"]["returned"] == 1


def test_search_status_enables_tavily_from_runtime_config(monkeypatch):
    _clear_search_env(monkeypatch)

    status = search_adapters.search_status(config={"tavily_api_key": "tv-test"})

    assert status["online_search_enabled"] is True
    assert status["web_search_enabled"] is True
    assert status["provider"] == "tavily"
    assert status["providers"]["tavily"]["enabled"] is True
    assert status["default_providers"][0] == "tavily"


def test_multi_provider_search_dedupes_and_honors_large_target(monkeypatch):
    def fake_provider(provider_name):
        def _fake(query, limit, **kwargs):
            return [
                {
                    "title": f"Defense report {i}",
                    "source": provider_name.upper(),
                    "url": f"https://example.test/report-{i}.pdf",
                    "snippet": "Think tank PDF report",
                    "published_at": "2026-06-01",
                    "provider": provider_name,
                    "query": query,
                    "rank": i + 1,
                }
                for i in range(limit)
            ]

        return _fake

    monkeypatch.setattr(search_adapters, "_search_tavily", fake_provider("tavily"))
    monkeypatch.setattr(search_adapters, "_search_brave", fake_provider("brave"))
    monkeypatch.setattr(search_adapters, "_search_serpapi", fake_provider("serpapi"))

    rows, meta = search_adapters.search_web_multi(
        ["taiwan unmanned systems report"],
        target_count=80,
        providers=["tavily", "brave", "serpapi"],
        config={
            "tavily_api_key": "tv",
            "brave_api_key": "brave",
            "serpapi_api_key": "serp",
        },
    )

    assert len(rows) == 80
    assert meta["target_count"] == 80
    assert meta["deduped_count"] == 80
    assert meta["provider_errors"] == {}
    assert {row["document_type"] for row in rows} == {"pdf"}
    assert all(row["provider"] in {"tavily", "brave", "serpapi"} for row in rows)


def test_multi_provider_search_records_provider_errors_without_aborting(monkeypatch):
    def failing_provider(query, limit, **kwargs):
        raise RuntimeError("quota exhausted")

    def ok_provider(query, limit, **kwargs):
        return [
            {
                "title": "Official doctrine PDF",
                "source": "Defense.gov",
                "url": "https://media.defense.gov/example.pdf",
                "snippet": "Public doctrine document",
                "provider": "brave",
                "query": query,
                "rank": 1,
            }
        ]

    monkeypatch.setattr(search_adapters, "_search_tavily", failing_provider)
    monkeypatch.setattr(search_adapters, "_search_brave", ok_provider)

    rows, meta = search_adapters.search_web_multi(
        ["site:defense.gov doctrine filetype:pdf"],
        target_count=5,
        providers=["tavily", "brave"],
        config={"tavily_api_key": "tv", "brave_api_key": "brave"},
        include_pdf=False,
        include_doctrine=False,
    )

    assert len(rows) == 1
    assert "tavily" in meta["provider_errors"]
    assert meta["provider_stats"]["brave"]["returned"] == 1


def test_relevance_filter_uses_chinese_region_and_capability_terms(monkeypatch):
    def fake_public(query, limit, **kwargs):
        return [
            {
                "title": "2023 Russian cyber and information warfare assessment",
                "source": "consilium.europa.eu",
                "url": "https://example.test/russia-information-warfare",
                "snippet": "This analysis examines Russia's cyber and information warfare in Ukraine.",
            },
            {
                "title": "Russia electronic warfare force assessment",
                "source": "Defense Technical Information Center",
                "url": "https://example.test/russia-ew.pdf",
                "snippet": "Assessment of Russian electronic warfare capabilities and spectrum operations.",
            },
        ]

    monkeypatch.setattr(search_adapters, "_search_public_web", fake_public)

    rows, meta = search_adapters.search_web_multi(
        ["俄罗斯电子战智库 report analysis PDF"],
        target_count=2,
        config={},
        include_pdf=False,
        include_doctrine=False,
        enforce_relevance=True,
    )

    assert [row["title"] for row in rows] == ["Russia electronic warfare force assessment"]
    assert meta["rejected_low_relevance"] == 1


def test_relevance_filter_relaxes_when_everything_would_be_empty(monkeypatch):
    def fake_public(query, limit, **kwargs):
        return [
            {
                "title": "Missile defense procurement source page",
                "source": "Defense Institute",
                "url": "https://example.test/missile-defense-source",
                "snippet": "A source page that is only partially aligned with the query.",
            }
        ]

    monkeypatch.setattr(search_adapters, "_search_public_web", fake_public)

    rows, meta = search_adapters.search_web_multi(
        ["伊朗导弹库存 think tank report analysis PDF"],
        target_count=1,
        config={},
        include_pdf=False,
        include_doctrine=False,
        enforce_relevance=True,
    )

    assert len(rows) == 1
    assert rows[0]["relaxed_fallback"] is True
    assert rows[0]["payload"]["relaxed_fallback"] is True
    assert meta["relaxed_fallback_count"] == 1


def test_extract_html_document_returns_citable_source_card():
    doc = search_adapters.extract_html_document(
        "https://example.test/report",
        """
        <html><head><title>Strategic Report</title></head>
        <body><article><h1>Strategic Report</h1>
        <p>This public think tank report discusses unmanned systems and force design.</p>
        <p>It contains enough body text for source extraction.</p>
        </article></body></html>
        """,
    )

    assert doc["title"] == "Strategic Report"
    assert doc["document_type"] == "html"
    assert doc["is_fetched_original"] is True
    assert "unmanned systems" in doc["text"]
    assert doc["word_count"] >= 10


def test_relevance_filter_gates_pure_chinese_narrow_topic(monkeypatch):
    """纯中文窄主题查询（marker 表未覆盖）也应被相关性门槛过滤，
    不再因 _query_focus_terms 为空而对所有结果放行（噪声直接通过）。"""
    def fake_public(query, limit, **kwargs):
        return [
            {
                "title": "DF-17 hypersonic glide vehicle assessment",
                "source": "CSIS",
                "url": "https://example.test/hypersonic-df17",
                "snippet": "Hypersonic boost-glide vehicle analysis.",
            },
            {
                "title": "Generic defense industry weekly roundup",
                "source": "某防务博客",
                "url": "https://example.test/generic-news",
                "snippet": "Unrelated general defense news with no specific topic.",
            },
        ]

    monkeypatch.setattr(search_adapters, "_search_public_web", fake_public)

    rows, meta = search_adapters.search_web_multi(
        ["高超声速武器"],
        target_count=2,
        config={},
        include_pdf=False,
        include_doctrine=False,
        enforce_relevance=True,
    )

    titles = [r["title"] for r in rows]
    assert "DF-17 hypersonic glide vehicle assessment" in titles
    # 与高超声速无关的噪声不再被放行
    assert "Generic defense industry weekly roundup" not in titles
    assert meta["rejected_low_relevance"] >= 1


def test_domain_from_url_strips_www_prefix_only():
    # www. 前缀正确剥离
    assert search_adapters._domain_from_url("https://www.wto.org/x") == "wto.org"
    # 以 w 开头但非 www. 的域名不得被误删首字母（旧 lstrip("www.") 的 bug：weapons.gov→eapons.gov）
    assert search_adapters._domain_from_url("https://weapons.gov/report") == "weapons.gov"
    assert search_adapters._domain_from_url("https://warfare.example.com/a") == "warfare.example.com"
    assert search_adapters._domain_from_url("https://rand.org/x") == "rand.org"


def test_extract_url_rechecks_each_redirect_hop_for_ssrf(monkeypatch):
    """extract_url 必须禁用自动重定向并对每一跳重新做 SSRF 校验，
    302 跳私有/云元数据地址应在连接前被拦（修复重定向绕过 SSRF）。"""
    seen = []

    class _Resp:
        def __init__(self, status, headers=None):
            self.status_code = status
            self.headers = headers or {}

        def close(self):
            pass

    def fake_get(url, **kwargs):
        seen.append(url)
        assert kwargs.get("allow_redirects") is False  # 关键：不得自动跟随重定向
        if "start" in url:
            return _Resp(302, {"Location": "http://169.254.169.254/latest/meta-data/"})
        return _Resp(200)

    monkeypatch.setattr(
        search_adapters,
        "_ssrf_http_session",
        lambda: type("FakeSession", (), {"get": lambda self, url, **kwargs: fake_get(url, **kwargs)})(),
    )
    monkeypatch.setattr(search_adapters, "_validate_connected_peer", lambda _response: None)

    def ssrf_check(u):
        if "169.254" in u or "127.0.0.1" in u or "localhost" in u:
            return False, "解析到私有/本地地址"
        return True, ""

    with pytest.raises(RuntimeError) as exc:
        search_adapters.extract_url("http://public.test/start", ssrf_check=ssrf_check)

    assert "不安全" in str(exc.value)
    # 重定向目标在发起连接前即被拦下，fake_get 不会以 169.254 地址被二次调用
    assert seen == ["http://public.test/start"]


def test_extract_url_rejects_private_or_unverifiable_connected_peer(monkeypatch):
    class _Resp:
        status_code = 200
        headers = {}

        def close(self):
            pass

    monkeypatch.setattr(
        search_adapters,
        "_ssrf_http_session",
        lambda: type("FakeSession", (), {"get": lambda self, *args, **kwargs: _Resp()})(),
    )
    check = lambda _url: (True, "")

    monkeypatch.setattr(search_adapters, "_connected_peer_ip", lambda _response: "10.0.0.9")
    with pytest.raises(RuntimeError, match="重绑定到私有地址"):
        search_adapters._safe_stream_get(
            "https://public.test/report", {}, 1, check,
        )

    monkeypatch.setattr(
        search_adapters,
        "_connected_peer_ip",
        lambda _response: (_ for _ in ()).throw(RuntimeError("无法核验远端连接地址")),
    )
    with pytest.raises(RuntimeError, match="无法核验远端连接地址"):
        search_adapters._safe_stream_get(
            "https://public.test/report", {}, 1, check,
        )


def test_extract_url_accepts_public_peer_and_validates_every_redirect_hop(monkeypatch):
    seen_urls = []
    validated_responses = []

    class _Resp:
        def __init__(self, status, location=""):
            self.status_code = status
            self.headers = {"Location": location} if location else {}

        def close(self):
            pass

    responses = iter([
        _Resp(302, "/second"),
        _Resp(302, "https://cdn.public.test/final"),
        _Resp(200),
    ])

    def fake_get(url, **kwargs):
        seen_urls.append(url)
        assert kwargs["allow_redirects"] is False
        return next(responses)

    monkeypatch.setattr(
        search_adapters,
        "_ssrf_http_session",
        lambda: type("FakeSession", (), {"get": lambda self, url, **kwargs: fake_get(url, **kwargs)})(),
    )

    def public_peer(response):
        validated_responses.append(response)
        return "93.184.216.34"

    monkeypatch.setattr(search_adapters, "_connected_peer_ip", public_peer)
    response = search_adapters._safe_stream_get(
        "https://public.test/start", {}, 1, lambda _url: (True, ""),
    )

    assert response.status_code == 200
    assert seen_urls == [
        "https://public.test/start",
        "https://public.test/second",
        "https://cdn.public.test/final",
    ]
    assert len(validated_responses) == 3


def test_extract_transport_is_proxy_free_and_render_fallback_is_disabled(monkeypatch):
    monkeypatch.setattr(search_adapters._SSRF_HTTP_LOCAL, "session", None, raising=False)

    assert search_adapters._ssrf_http_session().trust_env is False
    with pytest.raises(RuntimeError, match="浏览器渲染兜底已禁用"):
        search_adapters.extract_url_rendered("https://example.test/report")
