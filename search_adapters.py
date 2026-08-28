# -*- coding: utf-8 -*-
"""Search and extraction adapters for the defense source-capture Agent.

LLM calls do not search facts. This module owns live search provider calls,
normalization, dedupe and public document extraction.
"""
from __future__ import annotations

import os
import re
import ipaddress
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import parse_qs, unquote, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from document_safety import extract_docx_text_safe, extract_pdf_text_isolated

try:
    import trafilatura
except ImportError:  # pragma: no cover - dependency is optional at runtime
    trafilatura = None

PROVIDER_PUBLIC_WEB = "public_web"
PROVIDER_TAVILY = "tavily"
PROVIDER_BRAVE = "brave"
PROVIDER_SERPAPI = "serpapi"
API_PROVIDERS = (PROVIDER_TAVILY, PROVIDER_BRAVE, PROVIDER_SERPAPI)
PROVIDERS = (PROVIDER_PUBLIC_WEB, PROVIDER_TAVILY, PROVIDER_BRAVE, PROVIDER_SERPAPI)
DEFAULT_PROVIDER = PROVIDER_PUBLIC_WEB
DUCKDUCKGO_HTML_ENDPOINT = "https://duckduckgo.com/html/"
DUCKDUCKGO_LITE_ENDPOINT = "https://lite.duckduckgo.com/lite/"
TAVILY_ENDPOINT = "https://api.tavily.com/search"
BRAVE_WEB_ENDPOINT = "https://api.search.brave.com/res/v1/web/search"
BRAVE_NEWS_ENDPOINT = "https://api.search.brave.com/res/v1/news/search"
SERPAPI_ENDPOINT = "https://serpapi.com/search.json"


class _ApiKeyQueryRedactionFilter(logging.Filter):
    """Remove query-string credentials from urllib3 diagnostic records."""

    _PATTERN = re.compile(r"(?i)(api_key=)[^&\s\"']+")

    def filter(self, record: logging.LogRecord) -> bool:
        rendered = record.getMessage()
        redacted = self._PATTERN.sub(r"\1[REDACTED]", rendered)
        if redacted != rendered:
            record.msg = redacted
            record.args = ()
        return True


_urllib3_logger = logging.getLogger("urllib3.connectionpool")
if not any(isinstance(item, _ApiKeyQueryRedactionFilter) for item in _urllib3_logger.filters):
    _urllib3_logger.addFilter(_ApiKeyQueryRedactionFilter())


class ProviderRequestError(RuntimeError):
    """Stable provider error that never embeds request URLs or credentials."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _provider_error_code(exc: BaseException) -> str:
    if isinstance(exc, ProviderRequestError):
        return exc.code
    if isinstance(exc, requests.Timeout):
        return "UPSTREAM_TIMEOUT"
    if isinstance(exc, requests.HTTPError):
        status = getattr(getattr(exc, "response", None), "status_code", None)
        if status in {401, 403}:
            return "UPSTREAM_AUTH"
        if status == 429:
            return "UPSTREAM_RATE_LIMIT"
        if isinstance(status, int) and 400 <= status < 500:
            return "UPSTREAM_REJECTED"
        return "UPSTREAM_UNAVAILABLE"
    if isinstance(exc, requests.RequestException):
        return "UPSTREAM_UNAVAILABLE"
    if isinstance(exc, (ValueError, TypeError, KeyError)):
        return "UPSTREAM_INVALID_RESPONSE"
    return "PROVIDER_FAILURE"

_PROVIDER_ROLES = {
    PROVIDER_PUBLIC_WEB: "基础联网搜索",
    PROVIDER_TAVILY: "主搜索",
    PROVIDER_BRAVE: "备用搜索",
    PROVIDER_SERPAPI: "可选增强",
}

_THINKTANK_DOMAINS = (
    "rand.org",
    "csis.org",
    "iiss.org",
    "rusi.org",
    "cnas.org",
    "brookings.edu",
    "cfr.org",
    "stimson.org",
    "atlanticcouncil.org",
    "sipri.org",
    "jamestown.org",
    "hudson.org",
    "heritage.org",
    "aei.org",
)

_OFFICIAL_DOMAINS = (
    ".gov",
    ".mil",
    "nato.int",
    "mod.go.jp",
    "gov.uk",
    "europa.eu",
    "defence.gov.au",
)

_LOW_VALUE_SOURCE_DOMAINS = (
    "zhihu.com",
    "baike.baidu.com",
    "wikipedia.org",
    "quora.com",
    "reddit.com",
)

_GENERIC_QUERY_TERMS = {
    "site", "filetype", "pdf", "html", "think", "tank", "report", "reports",
    "analysis", "assessment", "assessments", "study", "studies", "research",
    "defense", "defence", "military", "official", "policy", "policies",
    "manual", "doctrine", "strategic", "security", "source", "sources",
}

_ZH_QUERY_FOCUS = (
    ("美国", ("united", "states")),
    ("美军", ("united", "states", "military")),
    ("北约", ("nato", "allied")),
    ("俄罗斯", ("russia",)),
    ("俄军", ("russia",)),
    ("红海", ("red", "sea")),
    ("印太", ("indo", "pacific")),
    ("欧洲", ("europe",)),
    ("伊朗", ("iran",)),
    ("台海", ("taiwan", "strait")),
    ("台湾", ("taiwan",)),
    ("中国", ("china",)),
    ("无人机", ("uav", "drone", "unmanned")),
    ("无人系统", ("uav", "drone", "unmanned")),
    ("电子战", ("electronic", "warfare")),
    ("电磁", ("electromagnetic", "spectrum")),
    ("防空", ("air", "defense")),
    ("反导", ("missile", "defense")),
    ("导弹", ("missile",)),
    ("存储", ("storage", "stockpile", "inventory", "arsenal")),
    ("储备", ("stockpile", "inventory", "arsenal")),
    ("库存", ("stockpile", "inventory", "arsenal")),
    ("海军", ("naval",)),
    ("海上力量", ("naval", "maritime")),
    ("核力量", ("nuclear",)),
    ("网络", ("cyber",)),
    ("太空", ("space",)),
    ("军工", ("defense", "industry")),
    ("生产能力", ("production", "capacity")),
    ("产能", ("production", "capacity")),
    ("工业基础", ("industrial", "base")),
    ("消耗", ("attrition", "consumption", "expenditure")),
    ("战损", ("attrition", "losses")),
    ("损耗", ("attrition", "losses")),
    ("部署", ("deployment", "posture", "basing")),
    ("基地", ("basing", "base")),
    ("战备", ("readiness", "availability")),
    ("完好率", ("readiness", "availability")),
    ("采购", ("acquisition", "procurement")),
    ("采办", ("acquisition", "procurement")),
    ("后勤", ("logistics", "sustainment")),
    ("保障", ("sustainment", "logistics")),
    ("条令", ("doctrine",)),
)


def _clean_query(query: str) -> str:
    text = re.sub(r"\s+", " ", (query or "").strip())
    return text[:380]


def _config_value(config: dict | None, *keys: str) -> str:
    config = config or {}
    for key in keys:
        value = config.get(key)
        if value:
            return str(value).strip()
    for key in keys:
        env_value = os.environ.get(key.upper(), "")
        if env_value:
            return env_value.strip()
    return ""


def _provider_keys(config: dict | None = None) -> dict[str, str]:
    return {
        PROVIDER_TAVILY: _config_value(config, "tavily_api_key", "TAVILY_API_KEY"),
        PROVIDER_BRAVE: _config_value(config, "brave_api_key", "brave_search_api_key", "BRAVE_SEARCH_API_KEY"),
        PROVIDER_SERPAPI: _config_value(config, "serpapi_api_key", "SERPAPI_API_KEY"),
    }


def _provider() -> str:
    provider = (os.environ.get("SEARCH_PROVIDER") or DEFAULT_PROVIDER).strip().lower()
    return provider if provider in PROVIDERS else DEFAULT_PROVIDER


def search_status(config: dict | None = None) -> dict:
    keys = _provider_keys(config)
    provider_rows = {
        PROVIDER_PUBLIC_WEB: {
            "enabled": True,
            "role": _PROVIDER_ROLES[PROVIDER_PUBLIC_WEB],
            "configured": True,
            "message": "免配置公共网页搜索可用",
        }
    }
    for provider in API_PROVIDERS:
        enabled = bool(keys.get(provider))
        provider_rows[provider] = {
            "enabled": enabled,
            "role": _PROVIDER_ROLES[provider],
            "configured": enabled,
            "message": f"{_PROVIDER_ROLES[provider]}已配置" if enabled else f"{_PROVIDER_ROLES[provider]}未配置API key",
        }
    enabled_api_providers = [p for p in API_PROVIDERS if provider_rows[p]["enabled"]]
    requested_defaults = (config or {}).get("default_providers") or []
    requested_enabled = [
        p for p in requested_defaults if p in PROVIDERS and provider_rows[p]["enabled"]
    ]
    default_providers = requested_enabled or (enabled_api_providers + [PROVIDER_PUBLIC_WEB] if enabled_api_providers else [PROVIDER_PUBLIC_WEB])
    if PROVIDER_PUBLIC_WEB not in default_providers:
        default_providers.append(PROVIDER_PUBLIC_WEB)
    online_enabled = True
    selected_provider = default_providers[0] if default_providers else _provider()
    message = (
        "联网搜索已启用：" + " / ".join(_PROVIDER_ROLES[p] for p in default_providers)
        if enabled_api_providers
        else "基础联网搜索已启用；增强搜索API未配置时覆盖度会下降，但客户无需先配置即可搜集公开来源"
    )
    return {
        "provider": selected_provider,
        "default_providers": default_providers,
        "providers": provider_rows,
        "online_search_enabled": online_enabled,
        "web_search_enabled": online_enabled,  # backward-compatible field
        "enhanced_search_enabled": bool(enabled_api_providers),
        "site_crawl_enabled": True,
        "rss_aux_enabled": True,
        "message": message,
    }


def detect_document_type(url: str, content_type: str = "") -> str:
    lower_url = (url or "").lower().split("?", 1)[0]
    lower_type = (content_type or "").lower()
    if "pdf" in lower_type or lower_url.endswith(".pdf"):
        return "pdf"
    if "word" in lower_type or lower_url.endswith((".doc", ".docx")):
        return "docx"
    if lower_url.endswith((".xls", ".xlsx", ".csv")):
        return "table"
    return "html"


def _domain_from_url(url: str) -> str:
    try:
        netloc = urlparse(url or "").netloc.lower()
        # 用前缀剥离而非 lstrip：lstrip("www.") 会按字符集 {w,.} 误删 weapons.gov→eapons.gov、wto.org→to.org
        return netloc[4:] if netloc.startswith("www.") else netloc
    except Exception:
        return ""


def _canonical_url(url: str) -> str:
    if not url:
        return ""
    parsed = urlparse(url.strip())
    netloc = parsed.netloc.lower()
    path = re.sub(r"/+$", "", parsed.path or "/")
    return urlunparse((parsed.scheme.lower() or "https", netloc, path, "", parsed.query, ""))


def _dedupe_key(item: dict) -> str:
    url = _canonical_url(item.get("url") or item.get("link") or "")
    if url:
        return f"url:{url}"
    title = re.sub(r"\s+", " ", (item.get("title") or "").strip().lower())
    source = re.sub(r"\s+", " ", (item.get("source") or "").strip().lower())
    return f"title:{source}|{title}"


def _normalize_topic_term(term: str) -> str:
    term = (term or "").lower().strip()
    if term.startswith("russian"):
        return "russia"
    if term.startswith("iranian"):
        return "iran"
    if term.startswith("european"):
        return "europe"
    if len(term) > 4 and term.endswith("s") and not term.endswith(("ss", "is", "us")):
        return term[:-1]
    return term


def _normalize_relevance_text(text: str) -> str:
    text = (text or "").lower()
    replacements = {
        r"\brussian\b": "russia",
        r"\biranian\b": "iran",
        r"\beuropean\b": "europe",
    }
    for pattern, repl in replacements.items():
        text = re.sub(pattern, repl, text)
    return text


def _query_focus_terms(query: str) -> list[str]:
    raw_query = query or ""
    query = re.sub(r"\b(site|filetype):\S+", " ", raw_query.lower())
    terms = []
    for marker, mapped_terms in _ZH_QUERY_FOCUS:
        if marker in raw_query:
            for term in mapped_terms:
                term = _normalize_topic_term(term)
                if term and term not in _GENERIC_QUERY_TERMS and term not in terms:
                    terms.append(term)
    for word in re.findall(r"[a-z][a-z\-]{3,}", query):
        word = _normalize_topic_term(word)
        if word and word not in _GENERIC_QUERY_TERMS and word not in terms:
            terms.append(word)
    return terms[:10]


def _required_topic_groups(query: str) -> list[tuple[tuple[str, ...], ...]]:
    query_lower = (query or "").lower()
    groups: list[tuple[tuple[str, ...], ...]] = []
    if "电子战" in query or "electronic warfare" in query_lower:
        groups.append((("electronic", "electromagnetic"), ("warfare", "spectrum")))
    if "电磁" in query or "electromagnetic spectrum" in query_lower:
        groups.append((("electromagnetic", "spectrum"),))
    if "防空" in query or "air defense" in query_lower:
        groups.append((("air", "aerial"), ("defense", "defence")))
    if "无人机" in query or "无人系统" in query or "uav" in query_lower or "unmanned" in query_lower:
        groups.append((("uav", "drone", "unmanned"),))
    if "海军" in query or "海上力量" in query or "naval" in query_lower:
        groups.append((("naval", "maritime", "sea power"),))
    if "导弹" in query or "missile" in query_lower:
        groups.append((("missile", "ballistic"),))
    if (
        "存储" in query or "储备" in query or "库存" in query
        or "stockpile" in query_lower or "arsenal" in query_lower
        or "inventory" in query_lower or "storage" in query_lower
    ):
        groups.append((("stockpile", "arsenal", "inventory", "storage", "munitions"),))
    if (
        "产能" in query or "工业基础" in query
        or "production capacity" in query_lower or "industrial base" in query_lower
    ):
        groups.append((("production", "industrial"), ("capacity", "base")))
    if (
        "消耗" in query or "战损" in query or "损耗" in query
        or "attrition" in query_lower or "consumption" in query_lower
        or "expenditure" in query_lower
    ):
        groups.append((("attrition", "consumption", "expenditure", "losses"),))
    if "部署" in query or "基地" in query or "deployment" in query_lower or "basing" in query_lower:
        groups.append((("deployment", "basing", "posture", "presence", "base"),))
    if "战备" in query or "readiness" in query_lower or "availability" in query_lower:
        groups.append((("readiness", "availability", "mission capable"),))
    if "采购" in query or "采办" in query or "acquisition" in query_lower or "procurement" in query_lower:
        groups.append((("acquisition", "procurement", "program"),))
    if "后勤" in query or "保障" in query or "logistics" in query_lower or "sustainment" in query_lower:
        groups.append((("logistics", "sustainment", "supply", "maintenance"),))
    if "高超声速" in query or "高超音速" in query or "hypersonic" in query_lower:
        groups.append((("hypersonic", "boost-glide", "scramjet"),))
    if (
        "卫星" in query or "侦察" in query or "遥感" in query
        or "satellite" in query_lower or "reconnaissance" in query_lower
        or "isr" in query_lower or "remote sensing" in query_lower
    ):
        groups.append((("satellite", "reconnaissance", "isr", "remote sensing", "surveillance"),))
    if "弹药" in query or "炮弹" in query or "ammunition" in query_lower or "munition" in query_lower:
        groups.append((("ammunition", "munition", "shell", "ordnance"),))
    return groups


def _result_relevance_score(row: dict) -> int:
    query = row.get("query") or ""
    terms = _query_focus_terms(query)
    groups = _required_topic_groups(query)
    haystack = " ".join([
        row.get("title") or "",
        row.get("source") or "",
        row.get("snippet") or "",
        row.get("url") or "",
    ]).lower()
    haystack = _normalize_relevance_text(haystack)
    # topic 硬门槛先过：即使 terms 为空（纯中文窄主题，如高超声速/卫星侦察），也用
    # 中文主题词→英文同义组判别，杜绝"terms 为空即对所有结果放行"导致的相关性过滤失效
    for group in groups:
        if not all(any(term in haystack for term in alternatives) for alternatives in group):
            return 0
    if not terms:
        # 有可识别主题且已过门槛 → 相关；无任何可判别特征 → 0，交给 relaxed_fallback 低置信兜底，
        # 而不是把知乎/百科等噪声当相关全部放行
        return 1 if groups else 0
    matches = sum(1 for term in terms if term in haystack)
    if len(terms) >= 3 and matches < 2:
        return 0
    if len(terms) <= 2 and matches < 1:
        return 0
    phrase_requirements = (
        ("red sea", ("red", "sea")),
        ("indo-pacific", ("indo", "pacific")),
    )
    query_lower = (row.get("query") or "").lower()
    for phrase, parts in phrase_requirements:
        if phrase in query_lower and not all(part in haystack for part in parts):
            return 0
    return matches


def _score_result(item: dict) -> int:
    if item.get("score"):
        try:
            raw = float(item["score"])
            return int(raw * 100) if raw <= 1 else int(raw)
        except Exception:
            pass
    url = item.get("url") or ""
    title = (item.get("title") or "").lower()
    snippet = (item.get("snippet") or "").lower()
    domain = _domain_from_url(url)
    score = 68
    if any(domain.endswith(d) or d in domain for d in _THINKTANK_DOMAINS):
        score += 12
    if any(domain.endswith(d) or d in domain for d in _OFFICIAL_DOMAINS):
        score += 13
    if any(domain.endswith(d) or d in domain for d in _LOW_VALUE_SOURCE_DOMAINS):
        score -= 24
    if detect_document_type(url) == "pdf":
        score += 7
    if any(word in title + " " + snippet for word in ("report", "assessment", "analysis", "study", "doctrine", "manual")):
        score += 6
    return max(1, min(100, score))


def _normalize_result(item: dict, provider: str, query: str, rank: int) -> dict:
    url = item.get("url") or item.get("link") or ""
    title = item.get("title") or url or "联网搜索结果"
    source = item.get("source") or item.get("displayed_link") or _domain_from_url(url) or "Web"
    document_type = item.get("document_type") or detect_document_type(url, item.get("content_type", ""))
    score = _score_result({**item, "url": url})
    raw_content = item.get("raw_content")
    normalized = {
        "title": title,
        "source": source,
        "published_at": item.get("published_at") or item.get("published_date") or item.get("date") or "",
        "url": url,
        "channel": "web",
        "score": score,
        "reason": item.get("reason") or f"{_PROVIDER_ROLES.get(provider, provider)}联网搜索结果",
        "snippet": item.get("snippet") or item.get("content") or item.get("description") or "",
        "provider": provider,
        "query": query,
        "rank": rank,
        "document_type": document_type,
        "is_fetched_original": False,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
    }
    if raw_content:
        normalized["raw_content"] = raw_content
    normalized["payload"] = {
        "provider": provider,
        "query": query,
        "rank": rank,
        "document_type": document_type,
        "is_fetched_original": False,
    }
    return normalized


def _enabled_providers(providers: list[str] | None, config: dict | None) -> list[str]:
    status = search_status(config)
    requested = providers or status.get("default_providers") or []
    return [
        p for p in requested
        if p in PROVIDERS and status["providers"][p]["enabled"]
    ]


def search_web(query: str, limit: int = 10, **kwargs) -> list[dict]:
    """Backward-compatible single-query web search wrapper."""
    rows, _meta = search_web_multi([query], target_count=limit, **kwargs)
    return rows


def search_web_multi(
    queries: list[str] | tuple[str, ...] | str,
    target_count: int = 10,
    providers: list[str] | None = None,
    config: dict | None = None,
    include_pdf: bool = True,
    include_news: bool = True,
    include_doctrine: bool = True,
    domains: list[str] | None = None,
    **kwargs,
) -> tuple[list[dict], dict]:
    """Run multiple live search providers and return deduped normalized rows."""
    if isinstance(queries, str):
        queries = [queries]
    target = max(1, int(target_count or 10))
    query_list = []
    for query in queries or []:
        cleaned = _clean_query(query)
        if cleaned and cleaned not in query_list:
            query_list.append(cleaned)
    if domains:
        for domain in domains:
            domain = re.sub(r"^https?://", "", str(domain or "").strip()).strip("/")
            if domain:
                for base in list(query_list)[:3] or ["defense report"]:
                    query_list.append(_clean_query(f"site:{domain} {base}"))
    if include_pdf:
        for base in list(query_list)[:4]:
            pdf_query = _clean_query(f"{base} filetype:pdf")
            if pdf_query not in query_list:
                query_list.append(pdf_query)
    if include_doctrine:
        for base in list(query_list)[:2]:
            doctrine_query = _clean_query(f"{base} doctrine manual report")
            if doctrine_query not in query_list:
                query_list.append(doctrine_query)
    if not query_list:
        query_list = ["defense think tank report"]

    status = search_status(config)
    enabled = _enabled_providers(providers, config)
    provider_stats = {
        provider: {"queries": 0, "returned": 0, "accepted": 0}
        for provider in (providers or status.get("default_providers") or PROVIDERS)
        if provider in PROVIDERS
    }
    provider_errors: dict[str, str] = {}
    if not enabled:
        return [], {
            "target_count": target,
            "queries": query_list,
            "provider_stats": provider_stats,
            "provider_errors": {},
            "deduped_count": 0,
            "search_calls": 0,
            "search_status": status,
        }

    keys = _provider_keys(config)
    searchers: dict[str, Callable] = {
        PROVIDER_PUBLIC_WEB: _search_public_web,
        PROVIDER_TAVILY: _search_tavily,
        PROVIDER_BRAVE: _search_brave,
        PROVIDER_SERPAPI: _search_serpapi,
    }
    raw_rows = []
    per_call_limit = max(target, int(kwargs.get("per_call_limit") or 10))
    max_provider_queries = max(1, int(kwargs.get("max_provider_queries") or 6))
    search_tasks: list[tuple[str, str]] = []
    for provider in enabled:
        query_cap = 3 if provider == PROVIDER_PUBLIC_WEB else max_provider_queries
        for query in query_list[:query_cap]:
            provider_stats.setdefault(provider, {"queries": 0, "returned": 0, "accepted": 0})
            provider_stats[provider]["queries"] += 1
            search_tasks.append((provider, query))

    # 预算回调（app 侧注入，模块保持不 import app）：可抛异常在任何 provider HTTP 前中止
    on_search_calls = kwargs.get("on_search_calls")
    if on_search_calls is not None and search_tasks:
        on_search_calls(len(search_tasks))

    def _run(provider: str, query: str):
        try:
            rows = searchers[provider](
                query,
                limit=per_call_limit,
                api_key=keys.get(provider),
                include_news=include_news,
                include_raw_content=kwargs.get("include_raw_content", False),
                search_depth=kwargs.get("search_depth") or "advanced",
                timeout=kwargs.get("timeout") or (5 if provider == PROVIDER_PUBLIC_WEB else 10),
            )
        except Exception as exc:
            # requests.HTTPError may include the fully prepared URL.  SerpAPI
            # carries its key in that URL, so only a fixed code may cross this
            # boundary into API responses, persistence, or logs.
            raise ProviderRequestError(_provider_error_code(exc)) from None
        return provider, query, rows

    workers = max(1, min(int(kwargs.get("search_workers") or 6), len(search_tasks), 10))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_run, provider, query): (provider, query) for provider, query in search_tasks}
        for future in as_completed(futures):
            provider, query = futures[future]
            try:
                _provider, _query, rows = future.result()
                provider_stats[provider]["returned"] += len(rows)
                for idx, row in enumerate(rows, 1):
                    raw_rows.append(_normalize_result(row, provider, query, idx))
            except Exception as exc:
                provider_errors[provider] = _provider_error_code(exc)

    seen = set()
    deduped = []
    rejected_rows = []
    rejected_low_relevance = 0
    enforce_relevance = bool(kwargs.get("enforce_relevance"))
    for row in sorted(raw_rows, key=lambda r: (r.get("score") or 0, -int(r.get("rank") or 0)), reverse=True):
        key = _dedupe_key(row)
        if key in seen:
            continue
        relevance = _result_relevance_score(row)
        row["topic_relevance"] = relevance
        if enforce_relevance and relevance <= 0:
            rejected_low_relevance += 1
            rejected_rows.append(row)
            continue
        seen.add(key)
        deduped.append(row)
        provider_stats[row["provider"]]["accepted"] += 1
        if len(deduped) >= target:
            break
    relaxed_fallback_count = 0
    if enforce_relevance and not deduped and rejected_rows and kwargs.get("allow_relaxed_fallback", True) is not False:
        for row in sorted(rejected_rows, key=lambda r: (r.get("score") or 0, -int(r.get("rank") or 0)), reverse=True):
            key = _dedupe_key(row)
            if key in seen:
                continue
            domain = _domain_from_url(row.get("url") or "")
            if any(domain.endswith(d) or d in domain for d in _LOW_VALUE_SOURCE_DOMAINS):
                continue
            row["relaxed_fallback"] = True
            row["reason"] = f"{row.get('reason') or '联网搜索结果'}；严格相关性不足，列为低置信候选"
            row.setdefault("payload", {})
            row["payload"]["relaxed_fallback"] = True
            seen.add(key)
            deduped.append(row)
            relaxed_fallback_count += 1
            provider_stats[row["provider"]]["accepted"] += 1
            if len(deduped) >= target:
                break

    return deduped, {
        "target_count": target,
        "queries": query_list,
        "provider_stats": provider_stats,
        "provider_errors": provider_errors,
        "deduped_count": len(deduped),
        "search_calls": len(search_tasks),
        "rejected_low_relevance": rejected_low_relevance,
        "relaxed_fallback_count": relaxed_fallback_count,
        "search_status": status,
    }


def _search_tavily(query: str, limit: int = 10, **kwargs) -> list[dict]:
    api_key = (kwargs.get("api_key") or os.environ.get("TAVILY_API_KEY") or "").strip()
    if not api_key:
        return []
    payload = {
        "query": _clean_query(query),
        "max_results": max(1, int(limit or 10)),
        "search_depth": kwargs.get("search_depth") or "basic",
        "include_answer": False,
        "include_raw_content": bool(kwargs.get("include_raw_content")),
        "include_images": False,
        "topic": kwargs.get("topic") or "general",
    }
    resp = requests.post(
        TAVILY_ENDPOINT,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json=payload,
        timeout=int(kwargs.get("timeout") or 6),
    )
    resp.raise_for_status()
    data = resp.json()
    return [
        {
            "title": item.get("title") or item.get("url") or "",
            "source": item.get("source") or _domain_from_url(item.get("url") or ""),
            "published_at": item.get("published_date") or "",
            "url": item.get("url") or "",
            "snippet": item.get("content") or item.get("snippet") or "",
            "score": item.get("score"),
            "raw_content": item.get("raw_content"),
        }
        for item in data.get("results") or []
    ][: max(1, int(limit or 10))]


def _unwrap_duckduckgo_url(url: str) -> str:
    if not url:
        return ""
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    if "uddg" in query and query["uddg"]:
        return unquote(query["uddg"][0])
    return url


def _parse_public_search_html(html: str, limit: int) -> list[dict]:
    soup = BeautifulSoup(html or "", "html.parser")
    rows = []
    for node in soup.select(".result, tr"):
        link = node.select_one(".result__a") or node.select_one("a[href]")
        if not link:
            continue
        url = _unwrap_duckduckgo_url(link.get("href") or "")
        if not url.startswith(("http://", "https://")):
            continue
        snippet_node = node.select_one(".result__snippet") or node.select_one(".result-snippet")
        title = link.get_text(" ", strip=True)
        snippet = snippet_node.get_text(" ", strip=True) if snippet_node else ""
        rows.append({
            "title": title or url,
            "source": _domain_from_url(url) or "Public Web",
            "published_at": "",
            "url": url,
            "snippet": snippet,
            "reason": "免配置公共网页搜索结果",
        })
        if len(rows) >= limit:
            break
    return rows


def _search_public_web(query: str, limit: int = 10, **kwargs) -> list[dict]:
    """No-key public web search fallback used by the simple customer flow."""
    limit = max(1, min(int(limit or 10), 50))
    headers = {
        "User-Agent": "Mozilla/5.0 DefenseTrackerSourceAgent/1.0",
        "Accept": "text/html,application/xhtml+xml",
    }
    params = {"q": _clean_query(query), "kl": "us-en"}
    resp = requests.get(
        DUCKDUCKGO_HTML_ENDPOINT,
        params=params,
        headers=headers,
        timeout=int(kwargs.get("timeout") or 20),
    )
    resp.raise_for_status()
    rows = _parse_public_search_html(resp.text, limit)
    if rows:
        return rows
    lite_resp = requests.get(
        DUCKDUCKGO_LITE_ENDPOINT,
        params=params,
        headers=headers,
        timeout=int(kwargs.get("timeout") or 20),
    )
    lite_resp.raise_for_status()
    return _parse_public_search_html(lite_resp.text, limit)


def _search_brave(query: str, limit: int = 10, **kwargs) -> list[dict]:
    api_key = (kwargs.get("api_key") or os.environ.get("BRAVE_SEARCH_API_KEY") or "").strip()
    if not api_key:
        return []
    params = {
        "q": _clean_query(query),
        "count": max(1, min(int(limit or 10), 20)),
        "text_decorations": "false",
        "search_lang": "en",
    }
    headers = {"Accept": "application/json", "X-Subscription-Token": api_key}
    resp = requests.get(BRAVE_WEB_ENDPOINT, params=params, headers=headers, timeout=int(kwargs.get("timeout") or 20))
    resp.raise_for_status()
    data = resp.json()
    rows = []
    for item in (data.get("web") or {}).get("results") or []:
        rows.append({
            "title": item.get("title") or item.get("url") or "",
            "source": item.get("profile", {}).get("name") or _domain_from_url(item.get("url") or ""),
            "published_at": item.get("age") or "",
            "url": item.get("url") or "",
            "snippet": item.get("description") or "",
        })
    if kwargs.get("include_news"):
        try:
            news_resp = requests.get(
                BRAVE_NEWS_ENDPOINT,
                params={**params, "count": max(1, min(int(limit or 10), 20))},
                headers=headers,
                timeout=int(kwargs.get("timeout") or 20),
            )
            news_resp.raise_for_status()
            for item in (news_resp.json().get("results") or []):
                rows.append({
                    "title": item.get("title") or item.get("url") or "",
                    "source": item.get("source") or _domain_from_url(item.get("url") or ""),
                    "published_at": item.get("age") or item.get("page_age") or "",
                    "url": item.get("url") or "",
                    "snippet": item.get("description") or "",
                })
        except Exception:
            pass
    return rows[: max(1, int(limit or 10))]


def _search_serpapi(query: str, limit: int = 10, **kwargs) -> list[dict]:
    api_key = (kwargs.get("api_key") or os.environ.get("SERPAPI_API_KEY") or "").strip()
    if not api_key:
        return []
    params = {
        "engine": "google",
        "q": _clean_query(query),
        "api_key": api_key,
        "num": max(1, min(int(limit or 10), 100)),
    }
    try:
        resp = requests.get(SERPAPI_ENDPOINT, params=params, timeout=int(kwargs.get("timeout") or 20))
    except Exception as exc:
        raise ProviderRequestError(_provider_error_code(exc)) from None
    status = int(getattr(resp, "status_code", 0) or 0)
    if status in {401, 403}:
        resp.close()
        raise ProviderRequestError("UPSTREAM_AUTH")
    if status == 429:
        resp.close()
        raise ProviderRequestError("UPSTREAM_RATE_LIMIT")
    if 400 <= status < 500:
        resp.close()
        raise ProviderRequestError("UPSTREAM_REJECTED")
    if status >= 500:
        resp.close()
        raise ProviderRequestError("UPSTREAM_UNAVAILABLE")
    try:
        data = resp.json()
    except Exception:
        resp.close()
        raise ProviderRequestError("UPSTREAM_INVALID_RESPONSE") from None
    resp.close()
    if not isinstance(data, dict):
        raise ProviderRequestError("UPSTREAM_INVALID_RESPONSE")
    rows = []
    for item in data.get("organic_results") or []:
        rows.append({
            "title": item.get("title") or item.get("link") or "",
            "source": item.get("source") or item.get("displayed_link") or _domain_from_url(item.get("link") or ""),
            "published_at": item.get("date") or "",
            "url": item.get("link") or "",
            "snippet": item.get("snippet") or "",
        })
    for item in data.get("news_results") or []:
        rows.append({
            "title": item.get("title") or item.get("link") or "",
            "source": item.get("source") or _domain_from_url(item.get("link") or ""),
            "published_at": item.get("date") or "",
            "url": item.get("link") or "",
            "snippet": item.get("snippet") or "",
        })
    return rows[: max(1, int(limit or 10))]


def _word_count(text: str) -> int:
    latin_words = re.findall(r"[A-Za-z0-9][A-Za-z0-9\-']*", text or "")
    cjk_chars = re.findall(r"[\u4e00-\u9fff]", text or "")
    return len(latin_words) + len(cjk_chars)


def extract_html_document(url: str, html: str, max_chars: int = 60000) -> dict:
    soup = BeautifulSoup(html or "", "html.parser")
    for tag in soup(["script", "style", "noscript", "iframe", "svg"]):
        tag.decompose()
    title = ""
    if soup.title and soup.title.string:
        title = soup.title.string.strip()
    h1 = soup.find("h1")
    if h1 and h1.get_text(strip=True):
        title = h1.get_text(" ", strip=True)
    text = ""
    if trafilatura:
        try:
            text = trafilatura.extract(html, url=url, include_comments=False, include_tables=True) or ""
        except Exception:
            text = ""
    if not text:
        body = soup.find("article") or soup.find("main") or soup.body or soup
        text = body.get_text("\n", strip=True)
    text = re.sub(r"\n{3,}", "\n\n", text or "").strip()[:max_chars]
    return {
        "title": title or _domain_from_url(url) or "HTML文档",
        "url": url,
        "text": text,
        "snippet": text[:700],
        "document_type": "html",
        "word_count": _word_count(text),
        "is_fetched_original": True,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }


def extract_pdf_document(url: str, content: bytes, max_pages: int = 30, max_chars: int = 60000) -> dict:
    extracted = extract_pdf_text_isolated(
        content,
        max_pages=max(1, int(max_pages or 30)),
        max_chars=max_chars,
    )
    text = re.sub(r"\n{3,}", "\n\n", extracted).strip()[:max_chars]
    title = os.path.basename(urlparse(url).path) or "PDF文档"
    return {
        "title": title,
        "url": url,
        "text": text,
        "snippet": text[:700],
        "document_type": "pdf",
        "word_count": _word_count(text),
        "is_fetched_original": True,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }


def extract_docx_document(url: str, content: bytes, max_chars: int = 60000) -> dict:
    extracted = extract_docx_text_safe(content, max_chars=max_chars, include_tables=True)
    text = re.sub(r"\n{3,}", "\n\n", extracted).strip()[:max_chars]
    title = os.path.basename(urlparse(url).path) or "DOCX文档"
    return {
        "title": title,
        "url": url,
        "text": text,
        "snippet": text[:700],
        "document_type": "docx",
        "word_count": _word_count(text),
        "is_fetched_original": True,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }


def _read_limited_response(resp: requests.Response, max_bytes: int) -> bytes:
    content_length = resp.headers.get("Content-Length")
    if content_length:
        try:
            if int(content_length) > max_bytes:
                raise RuntimeError(f"文件过大（{int(content_length) // 1024 // 1024}MB），已跳过自动归档")
        except ValueError:
            pass
    chunks = []
    total = 0
    for chunk in resp.iter_content(chunk_size=65536):
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            raise RuntimeError(f"文件超过 {max_bytes // 1024 // 1024}MB，已跳过自动归档")
        chunks.append(chunk)
    return b"".join(chunks)


# ── SSRF 防护 ────────────────────────────────────────────────────────
# search_adapters 不能 import app（循环依赖），由 app.py 启动时注入
# set_ssrf_check(_is_ssrf_safe)。注入后 extract_url 对首跳及每个重定向目标
# 做 DNS 预检，并在连接建立后核验真实 peer IP；浏览器渲染兜底因无法核验
# Chromium 的实际 peer IP 而 fail closed。
_SSRF_CHECK: "Callable[[str], tuple] | None" = None
MAX_EXTRACT_REDIRECTS = 5


def set_ssrf_check(fn: "Callable[[str], tuple] | None") -> None:
    """注入 SSRF 校验回调；签名 fn(url) -> (ok: bool, reason: str)。"""
    global _SSRF_CHECK
    _SSRF_CHECK = fn


def _resolve_ssrf_check(override):
    return override if override is not None else _SSRF_CHECK


_EXTRACT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/126.0 Safari/537.36 DefenseTrackerSourceAgent/1.0",
    "Accept": "text/html,application/xhtml+xml,application/pdf;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}


_SSRF_HTTP_LOCAL = threading.local()


def _ssrf_http_session() -> requests.Session:
    session = getattr(_SSRF_HTTP_LOCAL, "session", None)
    if session is None:
        session = requests.Session()
        session.trust_env = False
        _SSRF_HTTP_LOCAL.session = session
    return session


def _connected_peer_ip(resp: requests.Response) -> str:
    raw = getattr(resp, "raw", None)
    candidates = [
        getattr(getattr(raw, "_connection", None), "sock", None),
        getattr(
            getattr(getattr(getattr(raw, "_fp", None), "fp", None), "raw", None),
            "_sock",
            None,
        ),
    ]
    for candidate in candidates:
        if candidate is None:
            continue
        try:
            peer = candidate.getpeername()
            if peer and peer[0]:
                return str(peer[0])
        except (AttributeError, OSError, TypeError):
            continue
    raise RuntimeError("无法核验远端连接地址")


def _validate_connected_peer(resp: requests.Response) -> None:
    peer = ipaddress.ip_address(_connected_peer_ip(resp))
    if (
        peer.is_loopback or peer.is_private or peer.is_link_local
        or peer.is_multicast or peer.is_reserved or peer.is_unspecified
    ):
        try:
            resp.close()
        except Exception:
            pass
        raise RuntimeError(f"连接被重绑定到私有地址: {peer}")


def _safe_stream_get(url, headers, timeout, ssrf_check):
    """逐跳 SSRF 复检 + 禁用自动重定向的流式 GET（对齐 app.py:_safe_get_once）。"""
    current = url
    for redirect_idx in range(MAX_EXTRACT_REDIRECTS + 1):
        ok, reason = ssrf_check(current)
        if not ok:
            raise RuntimeError(f"URL不安全: {reason}")
        resp = _ssrf_http_session().get(
            current, timeout=timeout, stream=True,
            allow_redirects=False, headers=headers,
        )
        try:
            _validate_connected_peer(resp)
        except Exception:
            try:
                resp.close()
            except Exception:
                pass
            raise
        if 300 <= resp.status_code < 400:
            location = resp.headers.get("Location")
            resp.close()
            if not location:
                return resp
            if redirect_idx >= MAX_EXTRACT_REDIRECTS:
                raise RuntimeError(f"重定向超过 {MAX_EXTRACT_REDIRECTS} 次")
            current = urljoin(current, location)
            continue
        return resp
    raise RuntimeError(f"重定向超过 {MAX_EXTRACT_REDIRECTS} 次")


def extract_url(url: str, timeout: int = 10, max_chars: int = 60000, ssrf_check=None, **kwargs) -> dict:
    max_bytes = int(kwargs.get("max_bytes") or 18 * 1024 * 1024)
    check = _resolve_ssrf_check(ssrf_check)
    if check is None:
        raise RuntimeError("SSRF校验器未配置，拒绝联网归档")
    resp = _safe_stream_get(url, _EXTRACT_HEADERS, timeout, check)
    # 用 try/finally 确保流式响应在任何异常路径（raise_for_status/超限/解析失败）都被关闭，
    # 否则大批量采集时未读完的连接会悬挂到 GC，耗尽连接池/句柄。
    try:
        resp.raise_for_status()
        content_type = resp.headers.get("Content-Type", "")
        doc_type = detect_document_type(url, content_type)
        content = _read_limited_response(resp, max_bytes=max_bytes)
        if doc_type == "pdf":
            doc = extract_pdf_document(url, content, max_chars=max_chars)
            doc.update({"content_type": content_type, "raw_bytes": content})
            return doc
        if doc_type == "docx":
            doc = extract_docx_document(url, content, max_chars=max_chars)
            doc.update({"content_type": content_type, "raw_bytes": content})
            return doc
        encoding = resp.encoding or "utf-8"
        text = content.decode(encoding, errors="replace")
        doc = extract_html_document(url, text, max_chars=max_chars)
        doc.update({"content_type": content_type, "raw_bytes": content, "raw_html": text[:max_chars]})
        return doc
    finally:
        resp.close()


def extract_url_rendered(url: str, timeout: int = 8, max_chars: int = 60000, ssrf_check=None, **kwargs) -> dict:
    """Fail closed until the browser transport can prove the connected peer IP."""
    raise RuntimeError("浏览器渲染兜底已禁用：无法核验实际连接地址")
