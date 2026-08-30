# -*- coding: utf-8 -*-
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from v9.desktop_smoke import (
    DesktopSmokeEvidenceStore,
    normalize_desktop_smoke_renderer,
    validate_desktop_smoke_evidence,
)

COMMIT = "a" * 40
ROOT = Path(__file__).resolve().parents[1]


def _valid():
    return {"schema": 1, "http_status": 200, "pathname": "/",
            "workspace_ready": True, "version": "9.0.0", "display_version": "V9",
            "release_tag": "v9.0.0", "build_commit": COMMIT}


def _store():
    return DesktopSmokeEvidenceStore("9.0.0", "V9", "v9.0.0", COMMIT)


def _validate(payload):
    return validate_desktop_smoke_evidence(
        payload, expected_version="9.0.0", expected_display_version="V9",
        expected_release_tag="v9.0.0", expected_build_commit=COMMIT)


def test_validation_accepts_only_exact_eight_field_release_identity():
    assert _validate(_valid()) == _valid()
    assert _validate(dict(_valid(), extra="rejected")) is None


@pytest.mark.parametrize("field,value", [
    ("schema", True), ("http_status", 302), ("pathname", "/login"),
    ("workspace_ready", False), ("version", "8.0.0"), ("display_version", "V8"),
    ("release_tag", "v8.0.0"), ("build_commit", "A" * 40),
])
def test_validation_rejects_wrong_or_malformed_fields(field, value):
    payload = _valid(); payload[field] = value
    assert _validate(payload) is None


def test_renderer_normalization_is_allowlisted_and_stable():
    assert normalize_desktop_smoke_renderer(" WebView2 ") == "edgechromium"
    assert normalize_desktop_smoke_renderer("edge-chromium") == "edgechromium"
    assert normalize_desktop_smoke_renderer("CEF") == "cef"
    assert normalize_desktop_smoke_renderer("mshtml") == "mshtml"
    assert normalize_desktop_smoke_renderer("arbitrary") is None
    assert normalize_desktop_smoke_renderer(1) is None


def test_store_requires_renderer_and_is_thread_safe_first_valid_idempotent():
    store = _store()
    assert store.submit(_valid()) is False
    assert store.set_renderer("webview2") == "edgechromium"
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(store.submit, [_valid() for _ in range(32)]))
    assert all(results)
    assert store.renderer == "edgechromium"
    assert store.snapshot() == _valid()
    snapshot = store.snapshot(); snapshot["version"] = "mutated"
    assert store.snapshot() == _valid()
    assert store.submit(dict(_valid(), version="bad")) is False
    with pytest.raises(ValueError, match="already bound"):
        store.set_renderer("cef")


def test_store_reports_mshtml_but_rejects_its_evidence():
    store = _store()
    assert store.set_renderer("mshtml") == "mshtml"
    assert store.renderer == "mshtml"
    assert store.submit(_valid()) is False
    assert store.snapshot() is None


def test_renderer_beacon_is_same_origin_post_without_bridge_or_harness_token():
    script = (ROOT / "static/js/v9-desktop-release-smoke.js").read_text(encoding="utf-8")
    assert "fetch('/api/status'" in script
    assert "'/_internal/v9/desktop-release-smoke'" in script
    assert "method: 'POST'" in script
    assert "attempt < 5" in script
    assert "submitted.status === 204" in script
    assert "setTimeout" in script
    assert "'X-CSRF-Token': payload.csrf_token" in script
    assert "document.querySelector('main.v9-workspace')" in script
    for forbidden in ("run_js", "evaluate_js", "window.pywebview", "postMessage",
                      "X-Defense-Tracker-Smoke", "DEFENSE_TRACKER_SMOKE_TOKEN"):
        assert forbidden not in script
