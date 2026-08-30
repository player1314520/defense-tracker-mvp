# -*- coding: utf-8 -*-
import json

import pytest

from v9.desktop_smoke import (
    DESKTOP_SMOKE_SCRIPT,
    start_desktop_smoke_probe,
    validate_desktop_smoke_evidence,
)


COMMIT = "a" * 40


def _valid_evidence() -> dict[str, object]:
    return {
        "schema": 1,
        "http_status": 200,
        "pathname": "/",
        "workspace_ready": True,
        "version": "9.0.0",
        "display_version": "V9",
        "release_tag": "v9.0.0",
        "build_commit": COMMIT,
    }


def _validate(payload):
    return validate_desktop_smoke_evidence(
        payload,
        expected_version="9.0.0",
        expected_display_version="V9",
        expected_release_tag="v9.0.0",
        expected_build_commit=COMMIT,
    )


def test_desktop_smoke_validation_accepts_only_the_exact_release_identity():
    expected = _valid_evidence()
    assert _validate(expected) == expected

    unexpected = dict(expected, extra="must-not-be-persisted")
    assert _validate(unexpected) is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema", True),
        ("http_status", 302),
        ("pathname", "/login"),
        ("workspace_ready", False),
        ("version", "8.0.0"),
        ("display_version", "V8"),
        ("release_tag", "v8.0.0"),
        ("build_commit", "A" * 40),
    ],
)
def test_desktop_smoke_validation_rejects_wrong_or_malformed_fields(field, value):
    payload = _valid_evidence()
    payload[field] = value
    assert _validate(payload) is None


def test_desktop_smoke_probe_uses_csp_safe_return_value_and_emits_once():
    payload = _valid_evidence()
    accepted = []

    class FakeWindow:
        def __init__(self):
            self.results = [None, "not-json", json.dumps(payload)]
            self.scripts = []

        def run_js(self, script):
            self.scripts.append(script)
            return self.results.pop(0)

    window = FakeWindow()
    thread = start_desktop_smoke_probe(
        window,
        evidence_sink=accepted.append,
        expected_version="9.0.0",
        expected_display_version="V9",
        expected_release_tag="v9.0.0",
        expected_build_commit=COMMIT,
        timeout_seconds=1,
        retry_seconds=0.01,
    )
    thread.join(timeout=2)

    assert not thread.is_alive()
    assert accepted == [payload]
    assert window.scripts == [
        DESKTOP_SMOKE_SCRIPT,
        DESKTOP_SMOKE_SCRIPT,
        DESKTOP_SMOKE_SCRIPT,
    ]
    assert "fetch('/api/status'" in DESKTOP_SMOKE_SCRIPT
    assert "document.querySelector('main.v9-workspace')" in DESKTOP_SMOKE_SCRIPT
    assert "JSON.stringify" in DESKTOP_SMOKE_SCRIPT
    assert "window.pywebview" not in DESKTOP_SMOKE_SCRIPT
    assert "eval(" not in DESKTOP_SMOKE_SCRIPT
    assert "X-Defense-Tracker-Smoke" not in DESKTOP_SMOKE_SCRIPT


def test_desktop_smoke_probe_never_emits_wrong_release_identity():
    payload = dict(_valid_evidence(), build_commit="b" * 40)
    accepted = []

    class FakeWindow:
        def run_js(self, _script):
            return json.dumps(payload)

    thread = start_desktop_smoke_probe(
        FakeWindow(),
        evidence_sink=accepted.append,
        expected_version="9.0.0",
        expected_display_version="V9",
        expected_release_tag="v9.0.0",
        expected_build_commit=COMMIT,
        timeout_seconds=0.03,
        retry_seconds=0.005,
    )
    thread.join(timeout=1)

    assert not thread.is_alive()
    assert accepted == []


def test_desktop_smoke_probe_rejects_non_callable_evidence_sink():
    with pytest.raises(TypeError, match="must be callable"):
        start_desktop_smoke_probe(
            object(),
            evidence_sink=None,
            expected_version="9.0.0",
            expected_display_version="V9",
            expected_release_tag="v9.0.0",
            expected_build_commit=COMMIT,
        )
