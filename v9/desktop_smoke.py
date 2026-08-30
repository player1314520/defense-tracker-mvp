# -*- coding: utf-8 -*-
"""Authenticated, same-origin desktop release smoke beacon primitives."""

from __future__ import annotations

import re
import threading
from typing import Any


DESKTOP_SMOKE_ENDPOINT = "/_internal/v9/desktop-release-smoke"
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_EVIDENCE_FIELDS = (
    "schema", "http_status", "pathname", "workspace_ready", "version",
    "display_version", "release_tag", "build_commit",
)
_RENDERER_ALIASES = {
    "edgechromium": "edgechromium",
    "edge-chromium": "edgechromium",
    "webview2": "edgechromium",
    "cef": "cef",
    "qtwebengine": "qtwebengine",
    "mshtml": "mshtml",
}


def normalize_desktop_smoke_renderer(renderer: Any) -> str | None:
    """Normalize a known pywebview renderer name; reject arbitrary values."""
    if type(renderer) is not str:
        return None
    return _RENDERER_ALIASES.get(renderer.strip().lower())


def validate_desktop_smoke_evidence(
    result: Any, *, expected_version: str, expected_display_version: str,
    expected_release_tag: str, expected_build_commit: str,
) -> dict[str, object] | None:
    """Return a normalized exact eight-field payload bound to this release."""
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
        "pathname": "/", "version": expected_version,
        "display_version": expected_display_version,
        "release_tag": expected_release_tag,
        "build_commit": expected_build_commit,
    }
    if any(type(result[field]) is not str or result[field] != expected
           for field, expected in expected_strings.items()):
        return None
    return {field: result[field] for field in _EVIDENCE_FIELDS}


class DesktopSmokeEvidenceStore:
    """Thread-safe first-valid store for one exact renderer/release observation."""

    def __init__(self, expected_version: str, expected_display_version: str,
                 expected_release_tag: str, expected_build_commit: str) -> None:
        if _SHA_RE.fullmatch(expected_build_commit) is None:
            raise ValueError("desktop smoke expected commit must be a full lowercase Git SHA")
        self._expected = {
            "expected_version": expected_version,
            "expected_display_version": expected_display_version,
            "expected_release_tag": expected_release_tag,
            "expected_build_commit": expected_build_commit,
        }
        self._lock = threading.Lock()
        self._renderer: str | None = None
        self._evidence: dict[str, object] | None = None

    def set_renderer(self, renderer: Any) -> str:
        normalized = normalize_desktop_smoke_renderer(renderer)
        if normalized is None:
            raise ValueError("unsupported desktop smoke renderer")
        with self._lock:
            if self._renderer is not None and self._renderer != normalized:
                raise ValueError("desktop smoke renderer is already bound")
            self._renderer = normalized
        return normalized

    @property
    def renderer(self) -> str | None:
        with self._lock:
            return self._renderer

    def submit(self, payload: Any) -> bool:
        normalized = validate_desktop_smoke_evidence(payload, **self._expected)
        if normalized is None:
            return False
        with self._lock:
            if self._renderer != "edgechromium":
                return False
            if self._evidence is None:
                self._evidence = normalized
                return True
            return self._evidence == normalized

    def snapshot(self) -> dict[str, object] | None:
        with self._lock:
            if self._evidence is None:
                return None
            return dict(self._evidence)
