# -*- coding: utf-8 -*-
"""CSP-safe authenticated desktop release smoke probe."""

from __future__ import annotations

import re
import threading
import time
from typing import Any, Callable


_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_EVIDENCE_FIELDS = (
    "schema",
    "http_status",
    "pathname",
    "workspace_ready",
    "version",
    "display_version",
    "release_tag",
    "build_commit",
)

# pywebview.evaluate_js wraps source in eval, which the application's strict CSP
# correctly blocks. run_js executes this source as-is and reports through
# pywebview's CSP-compatible State bridge.
DESKTOP_SMOKE_SCRIPT = r"""
(function () {
  fetch('/api/status', {
    credentials: 'same-origin', cache: 'no-store'
  }).then(function (response) {
    return response.json().catch(function () { return {}; }).then(function (payload) {
      if (!window.pywebview || !window.pywebview.state) {
        return;
      }
      window.pywebview.state.desktopSmokeEvidence = {
        schema: 1,
        http_status: response.status,
        pathname: window.location.pathname,
        workspace_ready: Boolean(document.querySelector('main.v9-workspace')),
        version: payload.version || '',
        display_version: payload.display_version || '',
        release_tag: payload.release_tag || '',
        build_commit: payload.build_commit || ''
      };
    });
  }).catch(function () {});
})();
"""


def validate_desktop_smoke_evidence(
    result: Any,
    *,
    expected_version: str,
    expected_display_version: str,
    expected_release_tag: str,
    expected_build_commit: str,
) -> dict[str, object] | None:
    """Return an allowlisted release-bound payload, or reject it."""
    if _SHA_RE.fullmatch(expected_build_commit) is None:
        raise ValueError("desktop smoke expected commit must be a full lowercase Git SHA")
    if not isinstance(result, dict) or set(result) != set(_EVIDENCE_FIELDS):
        return None
    if type(result["schema"]) is not int or result["schema"] != 1:
        return None
    if type(result["http_status"]) is not int or result["http_status"] != 200:
        return None
    if type(result["workspace_ready"]) is not bool or not result["workspace_ready"]:
        return None
    expected_strings = {
        "pathname": "/",
        "version": expected_version,
        "display_version": expected_display_version,
        "release_tag": expected_release_tag,
        "build_commit": expected_build_commit,
    }
    if any(
        type(result[field]) is not str or result[field] != expected
        for field, expected in expected_strings.items()
    ):
        return None
    return {field: result[field] for field in _EVIDENCE_FIELDS}


def start_desktop_smoke_probe(
    window,
    *,
    evidence_sink: Callable[[dict[str, object]], None],
    expected_version: str,
    expected_display_version: str,
    expected_release_tag: str,
    expected_build_commit: str,
    timeout_seconds: float = 45,
    retry_seconds: float = 0.5,
) -> threading.Thread:
    """Start a fail-closed WebView probe and return its daemon thread."""
    if not callable(evidence_sink):
        raise TypeError("desktop smoke evidence sink must be callable")
    if _SHA_RE.fullmatch(expected_build_commit) is None:
        raise ValueError("desktop smoke expected commit must be a full lowercase Git SHA")
    if timeout_seconds <= 0 or retry_seconds <= 0:
        raise ValueError("desktop smoke timing values must be positive")

    accepted = threading.Event()
    write_lock = threading.Lock()

    def receive_desktop_smoke_state(event_type, key, result):
        if event_type != "change" or key != "desktopSmokeEvidence":
            return
        if accepted.is_set():
            return
        normalized = validate_desktop_smoke_evidence(
            result,
            expected_version=expected_version,
            expected_display_version=expected_display_version,
            expected_release_tag=expected_release_tag,
            expected_build_commit=expected_build_commit,
        )
        if normalized is None:
            return
        with write_lock:
            if accepted.is_set():
                return
            # The desktop process never accepts or writes a caller-supplied path.
            # The release harness retrieves this allowlisted payload over an
            # authenticated loopback-only endpoint and owns evidence persistence.
            evidence_sink(dict(normalized))
            accepted.set()

    window.state += receive_desktop_smoke_state

    def _probe() -> None:
        deadline = time.monotonic() + timeout_seconds
        while not accepted.is_set() and time.monotonic() < deadline:
            try:
                window.run_js(DESKTOP_SMOKE_SCRIPT)
            except Exception:
                if accepted.wait(retry_seconds):
                    return
                continue
            accepted.wait(retry_seconds)

    thread = threading.Thread(target=_probe, daemon=True)
    thread.start()
    return thread
