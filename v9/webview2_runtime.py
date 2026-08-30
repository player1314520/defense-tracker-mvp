"""Offline WebView2 Evergreen Runtime registration preflight.

The Windows desktop build uses pywebview 6.1's x64 registry locations, but
parses versions strictly so malformed registrations cannot enable a renderer.
"""

from __future__ import annotations

from dataclasses import dataclass
import sys
from typing import Any, Optional, Tuple


WEBVIEW2_CLIENT_ID = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
WEBVIEW2_CLIENT_PATH = (
    rf"SOFTWARE\Microsoft\EdgeUpdate\Clients\{WEBVIEW2_CLIENT_ID}"
)
MINIMUM_WEBVIEW2_VERSION = (86, 0, 622, 0)


@dataclass(frozen=True)
class WebView2RuntimeDetection:
    """Fail-closed result from the local WebView2 registration check."""

    supported: bool
    registered: bool
    compatible: bool
    reason: str
    version: Optional[Tuple[int, int, int, int]]
    version_text: Optional[str]
    source: Optional[str]
    minimum_version: Tuple[int, int, int, int] = MINIMUM_WEBVIEW2_VERSION


def _parse_version(value: Any) -> Optional[Tuple[int, int, int, int]]:
    if not isinstance(value, str):
        return None

    parts = value.split(".")
    if len(parts) != 4:
        return None
    if any(
        not part or not part.isascii() or not part.isdecimal()
        for part in parts
    ):
        return None

    try:
        parsed = (
            int(parts[0], 10),
            int(parts[1], 10),
            int(parts[2], 10),
            int(parts[3], 10),
        )
    except ValueError:
        return None

    return parsed


def _read_registration(
    registry: Any,
    root: Any,
    access: int,
) -> Tuple[bool, Any]:
    try:
        with registry.OpenKey(root, WEBVIEW2_CLIENT_PATH, 0, access) as key:
            try:
                value, _ = registry.QueryValueEx(key, "pv")
            except (OSError, ValueError, TypeError):
                return True, None
    except (OSError, ValueError, TypeError):
        return False, None

    return True, value


def detect_webview2_runtime(
    *,
    platform_name: Optional[str] = None,
    registry_module: Any = None,
) -> WebView2RuntimeDetection:
    """Detect a compatible x64 WebView2 registration without network I/O.

    ``platform_name`` and ``registry_module`` are injectable to keep all
    branches deterministic in tests. Production callers should omit both.
    """

    current_platform = sys.platform if platform_name is None else platform_name
    if current_platform != "win32":
        return WebView2RuntimeDetection(
            supported=False,
            registered=False,
            compatible=False,
            reason="unsupported-platform",
            version=None,
            version_text=None,
            source=None,
        )

    registry = registry_module
    if registry is None:
        try:
            import winreg as registry  # type: ignore[no-redef]
        except ImportError:
            return WebView2RuntimeDetection(
                supported=True,
                registered=False,
                compatible=False,
                reason="registry-unavailable",
                version=None,
                version_text=None,
                source=None,
            )

    locations = (
        ("hkcu", registry.HKEY_CURRENT_USER, registry.KEY_READ),
        (
            "hklm-32",
            registry.HKEY_LOCAL_MACHINE,
            registry.KEY_READ | registry.KEY_WOW64_32KEY,
        ),
    )

    registered_entries = []
    valid_entries = []
    for source, root, access in locations:
        registered, raw_version = _read_registration(registry, root, access)
        if not registered:
            continue

        registered_entries.append((source, raw_version))
        parsed = _parse_version(raw_version)
        if parsed is not None:
            valid_entries.append((parsed, source, raw_version))

    if valid_entries:
        version, source, version_text = max(valid_entries, key=lambda item: item[0])
        compatible = version >= MINIMUM_WEBVIEW2_VERSION
        return WebView2RuntimeDetection(
            supported=True,
            registered=True,
            compatible=compatible,
            reason="compatible" if compatible else "too-old",
            version=version,
            version_text=version_text,
            source=source,
        )

    if registered_entries:
        source, _ = registered_entries[0]
        return WebView2RuntimeDetection(
            supported=True,
            registered=True,
            compatible=False,
            reason="invalid-version",
            version=None,
            version_text=None,
            source=source,
        )

    return WebView2RuntimeDetection(
        supported=True,
        registered=False,
        compatible=False,
        reason="not-registered",
        version=None,
        version_text=None,
        source=None,
    )


__all__ = [
    "MINIMUM_WEBVIEW2_VERSION",
    "WEBVIEW2_CLIENT_ID",
    "WEBVIEW2_CLIENT_PATH",
    "WebView2RuntimeDetection",
    "detect_webview2_runtime",
]
