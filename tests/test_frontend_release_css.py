# -*- coding: utf-8 -*-
"""Release regressions for the K4 desktop CSS candidate."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from bs4 import BeautifulSoup


ROOT = Path(__file__).resolve().parents[1]
CSS_DIR = ROOT / "static" / "css"
TEMPLATE = ROOT / "templates" / "index.html"
CONSULTING_JS = ROOT / "static" / "js" / "ai.js"
MINIMUM_DESKTOP_VIEWPORT = {"width": 1024, "height": 700}

# These selectors render punctuation or icons rather than readable copy.  Ink4
# remains available for that non-text decoration only.
INK4_DECORATION_SELECTORS = (
    ".china-mini-tag + .china-mini-tag::before",
    ".ed-dot",
    ".ed-bm",
    ".trk-star",
    ".wb-step-arrow",
)


def _css_rules(source: str):
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    for match in re.finditer(r"([^{}]+)\{([^{}]*)\}", source):
        yield match.group(1).strip(), match.group(2)


def _uses_ink4_as_text_color(declarations: str) -> bool:
    return bool(
        re.search(
            r"(?:^|;)\s*color\s*:\s*var\(--ink4\)\s*(?:!important\s*)?(?:;|$)",
            declarations,
            flags=re.IGNORECASE,
        )
    )


def _relative_luminance(hex_color: str) -> float:
    channels = [int(hex_color[index : index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [
        value / 12.92
        if value <= 0.04045
        else ((value + 0.055) / 1.055) ** 2.4
        for value in channels
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast_ratio(first: str, second: str) -> float:
    first_luminance = _relative_luminance(first)
    second_luminance = _relative_luminance(second)
    lighter = max(first_luminance, second_luminance)
    darker = min(first_luminance, second_luminance)
    return (lighter + 0.05) / (darker + 0.05)


def _token_hex(tokens: str, name: str) -> str:
    match = re.search(rf"{re.escape(name)}\s*:\s*(#[0-9A-Fa-f]{{6}})\s*;", tokens)
    assert match, f"missing hexadecimal token {name}"
    return match.group(1)


def _edge_executable() -> Path | None:
    candidates = (
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
    )
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def _write_agent_fixture(path: Path) -> None:
    template = BeautifulSoup(TEMPLATE.read_text(encoding="utf-8"), "html.parser")
    agent_tab = template.select_one("#tab-content-agent")
    assert agent_tab is not None
    agent_tab.attrs.pop("hidden", None)
    agent_tab["class"] = [*agent_tab.get("class", []), "active"]

    style_links = []
    for link in template.select('link[rel="stylesheet"][href^="/static/css/"]'):
        stylesheet = ROOT / link["href"].lstrip("/")
        style_links.append(f'<link rel="stylesheet" href="{stylesheet.as_uri()}">')

    path.write_text(
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        + "".join(style_links)
        + "</head><body>"
        '<div class="v9-classification"><span>非 密</span><span>·</span><span>演 示 数 据</span><span>／／</span><span>UNCLASSIFIED · DEMO</span></div>'
        '<header class="topbar"><div class="topbar-left"><div class="ed-mark"><span>追</span></div><div class="ed-title-wrap"><span class="logo">防务数据追踪系统</span><span class="tagline">DEFENSE COMMAND HUB · V9</span></div></div><div class="topbar-right"><button class="v9-action">队列</button><button class="v9-action">检索</button><button class="v9-action">账户</button></div></header>'
        '<div class="v9-wire"><span class="v9-wire-label"><i></i>WIRE · 电讯</span><div class="v9-wire-track"><span>等待真实高优先级情报</span></div><div class="v9-runtime-stats"></div></div>'
        '<main class="v9-workspace"><aside class="v9-rail"><nav class="tab-nav"><div class="v9-nav-group"><span class="v9-nav-label">情 报 网</span><button class="tab-btn active"><em>06</em><span>案件工作区</span></button></div></nav></aside><section class="v9-stage">'
        + str(agent_tab)
        + "</section></main></body></html>",
        encoding="utf-8",
    )


def test_minimum_desktop_has_an_empty_case_compaction_rule():
    styles = (CSS_DIR / "agent.css").read_text(encoding="utf-8")

    assert "@media (max-width: 1260px) and (max-height: 760px)" in styles
    assert (
        "#tab-content-agent .v9-case-grid:has(#v9CaseList .v9-panel-loading):has(#v9CaseDetail .v9-panel-loading)"
        in styles
    )
    assert re.search(r"v9-case-grid:has\([^{}]+\)\s*\{[^{}]*min-height:\s*(?:1[0-8]\d|[1-9]?\d)px", styles)


def test_agent_mvp_cta_is_visible_at_1024_by_700(tmp_path):
    playwright = pytest.importorskip("playwright.sync_api")
    browser_executable = _edge_executable()
    if browser_executable is None:
        pytest.skip("Edge/Chrome is required for the Windows desktop layout regression")

    fixture = tmp_path / "agent-min-window.html"
    _write_agent_fixture(fixture)

    with playwright.sync_playwright() as runtime:
        browser = runtime.chromium.launch(
            executable_path=str(browser_executable),
            headless=True,
            args=["--allow-file-access-from-files"],
        )
        page = browser.new_page(viewport=MINIMUM_DESKTOP_VIEWPORT)
        page.goto(fixture.as_uri(), wait_until="load")
        geometry = page.locator("#agentMvpRunBtn").evaluate(
            """element => {
                const button = element.getBoundingClientRect();
                const cases = document.querySelector('.v9-case-grid').getBoundingClientRect();
                return {
                    buttonTop: button.top,
                    buttonBottom: button.bottom,
                    buttonHeight: button.height,
                    caseHeight: cases.height,
                    viewportHeight: window.innerHeight,
                };
            }"""
        )
        browser.close()

    assert geometry["buttonHeight"] >= 40, geometry
    assert geometry["buttonTop"] >= 0, geometry
    assert geometry["buttonBottom"] <= geometry["viewportHeight"], geometry


def test_ink4_is_reserved_for_non_text_decoration():
    offenders = []
    for stylesheet in sorted(CSS_DIR.glob("*.css")):
        source = stylesheet.read_text(encoding="utf-8")
        for selectors, declarations in _css_rules(source):
            if not _uses_ink4_as_text_color(declarations):
                continue
            selector_list = [selector.strip() for selector in selectors.split(",")]
            if all(
                any(marker in selector for marker in INK4_DECORATION_SELECTORS)
                for selector in selector_list
            ):
                continue
            offenders.append(f"{stylesheet.name}: {selectors}")

    assert not offenders, "ink4 is used for readable text:\n" + "\n".join(offenders)


def test_small_text_replacement_token_meets_aa_on_all_surfaces():
    tokens = (CSS_DIR / "tokens.css").read_text(encoding="utf-8")
    text_color = _token_hex(tokens, "--ink2")
    surfaces = {
        name: _token_hex(tokens, name)
        for name in ("--bg", "--panel", "--card", "--cardh")
    }

    ratios = {
        name: _contrast_ratio(text_color, background)
        for name, background in surfaces.items()
    }
    assert min(ratios.values()) >= 4.5, ratios


def test_browser_consulting_ui_uses_asset_ids_not_host_paths():
    source = CONSULTING_JS.read_text(encoding="utf-8")

    for private_field in (
        "source_archive_path",
        "local_path",
        "text_path",
        "metadata_path",
    ):
        assert private_field not in source
    assert "download_url" in source


def test_external_material_links_use_protocol_allowlist():
    expectations = {
        "agent.js": ["safeExternalUrl(ev.link)"],
        "brief.js": [
            "safeExternalUrl(a.link)",
            "safeExternalUrl(r.article.link)",
        ],
        "ai.js": [
            "safeExternalUrl(asset.url)",
            "safeExternalUrl(src.url || ev.url)",
            "safeExternalUrl(ev.url)",
            "safeExternalUrl(article.link)",
        ],
    }
    for filename, needles in expectations.items():
        source = (ROOT / "static" / "js" / filename).read_text(encoding="utf-8")
        for needle in needles:
            assert needle in source
