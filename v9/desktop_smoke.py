# -*- coding: utf-8 -*-
"""CSP-safe authenticated desktop release smoke probe."""

from __future__ import annotations

import json
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
# correctly blocks. run_js executes this source as-is. The async fetch stores an
# allowlisted candidate in the page; a later poll returns its JSON string through
# WebView2 ExecuteScriptAsync without relying on pywebview's postMessage bridge.
DESKTOP_SMOKE_SCRIPT = r"""
(function () {
  var evidenceKey = '__defenseTrackerReleaseSmokeEvidenceV1';
  var pendingKey = '__defenseTrackerReleaseSmokePendingV1';
  if (window[evidenceKey]) {
    return JSON.stringify(window[evidenceKey]);
  }
  if (window[pendingKey]) {
    return '';
  }
  window[pendingKey] = true;
  fetch('/api/status', {
    credentials: 'same-origin', cache: 'no-store'
  }).then(function (response) {
    return response.json().catch(function () { return {}; }).then(function (payload) {
      var workspaceReady = Boolean(document.querySelector('main.v9-workspace'));
      if (!response.ok || !workspaceReady || window.location.pathname !== '/') {
        window[pendingKey] = false;
        return;
      }
      window[evidenceKey] = {
        schema: 1,
        http_status: response.status,
        pathname: window.location.pathname,
        workspace_ready: workspaceReady,
        version: payload.version || '',
        display_version: payload.display_version || '',
        release_tag: payload.release_tag || '',
        build_commit: payload.build_commit || ''
      };
    });
  }).catch(function () { window[pendingKey] = false; });
  return '';
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

    def _probe() -> None:
        deadline = time.monotonic() + timeout_seconds
        while not accepted.is_set() and time.monotonic() < deadline:
            try:
                serialized = window.run_js(DESKTOP_SMOKE_SCRIPT)
            except Exception:
                if accepted.wait(retry_seconds):
                    return
                continue
            if isinstance(serialized, str) and 0 < len(serialized) <= 4096:
                try:
                    result = json.loads(serialized)
                except (TypeError, ValueError):
                    result = None
                normalized = validate_desktop_smoke_evidence(
                    result,
                    expected_version=expected_version,
                    expected_display_version=expected_display_version,
                    expected_release_tag=expected_release_tag,
                    expected_build_commit=expected_build_commit,
                )
                if normalized is not None:
                    with write_lock:
                        if not accepted.is_set():
                            # The desktop process never accepts or writes a
                            # caller-supplied path. The release harness retrieves
                            # this exact allowlist through its authenticated,
                            # process-owned loopback endpoint.
                            evidence_sink(dict(normalized))
                            accepted.set()
                    return
            accepted.wait(retry_seconds)

    thread = threading.Thread(target=_probe, daemon=True)
    thread.start()
    return thread
