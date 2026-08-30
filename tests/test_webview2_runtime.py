from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from v9.webview2_runtime import (
    MINIMUM_WEBVIEW2_VERSION,
    WEBVIEW2_CLIENT_ID,
    detect_webview2_runtime,
)


class _FakeKey:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class _FakeWinreg:
    HKEY_LOCAL_MACHINE = "HKLM"
    HKEY_CURRENT_USER = "HKCU"
    KEY_READ = 0x20019
    KEY_WOW64_32KEY = 0x0200

    def __init__(self, values=None):
        self.values = values or {}
        self.open_calls = []

    def OpenKey(self, root, path, reserved, access):
        self.open_calls.append((root, path, reserved, access))
        lookup = (root, path)
        if lookup not in self.values:
            raise FileNotFoundError(path)
        return _FakeKey(self.values[lookup])

    @staticmethod
    def QueryValueEx(key, name):
        assert name == "pv"
        if isinstance(key.value, BaseException):
            raise key.value
        return key.value, 1


CLIENT_PATH = rf"SOFTWARE\Microsoft\EdgeUpdate\Clients\{WEBVIEW2_CLIENT_ID}"


def _detect(values=None):
    registry = _FakeWinreg(values)
    result = detect_webview2_runtime(platform_name="win32", registry_module=registry)
    return result, registry


def test_non_windows_result_is_explicit_and_does_not_touch_registry():
    registry = _FakeWinreg(
        {(_FakeWinreg.HKEY_CURRENT_USER, CLIENT_PATH): "151.0.4129.107"}
    )

    result = detect_webview2_runtime(platform_name="linux", registry_module=registry)

    assert result.supported is False
    assert result.registered is False
    assert result.compatible is False
    assert result.reason == "unsupported-platform"
    assert result.version is None
    assert result.version_text is None
    assert result.source is None
    assert result.minimum_version == MINIMUM_WEBVIEW2_VERSION
    assert registry.open_calls == []


def test_missing_registry_keys_fail_closed_and_query_both_supported_locations():
    result, registry = _detect()

    assert result.supported is True
    assert result.registered is False
    assert result.compatible is False
    assert result.reason == "not-registered"
    assert [call[0] for call in registry.open_calls] == ["HKCU", "HKLM"]
    assert registry.open_calls[0][3] == _FakeWinreg.KEY_READ
    assert registry.open_calls[1][3] == (
        _FakeWinreg.KEY_READ | _FakeWinreg.KEY_WOW64_32KEY
    )
    assert all(call[1] == CLIENT_PATH for call in registry.open_calls)


@pytest.mark.parametrize(
    "malformed",
    [
        "86.0.622",
        "86.0.622.0.1",
        "86.0.-1.0",
        " 86.0.622.0",
        "86.0.622.0 ",
        "86.0.六二二.0",
        "v86.0.622.0",
        "",
        None,
        8606220,
    ],
)
def test_malformed_registered_versions_fail_closed(malformed):
    result, _ = _detect({("HKCU", CLIENT_PATH): malformed})

    assert result.supported is True
    assert result.registered is True
    assert result.compatible is False
    assert result.reason == "invalid-version"
    assert result.version is None
    assert result.version_text is None
    assert result.source == "hkcu"


@pytest.mark.parametrize("version", ["0.0.0.0", "85.999.9999.9999", "86.0.621.999"])
def test_stale_runtime_is_reported_but_rejected(version):
    result, _ = _detect({("HKCU", CLIENT_PATH): version})

    assert result.registered is True
    assert result.compatible is False
    assert result.reason == "too-old"
    assert result.version == tuple(int(part) for part in version.split("."))
    assert result.version_text == version
    assert result.source == "hkcu"


@pytest.mark.parametrize("version", ["86.0.622.0", "151.0.4129.107"])
def test_hkcu_compatible_runtime_is_accepted(version):
    result, registry = _detect({("HKCU", CLIENT_PATH): version})

    assert result.supported is True
    assert result.registered is True
    assert result.compatible is True
    assert result.reason == "compatible"
    assert result.version == tuple(int(part) for part in version.split("."))
    assert result.version_text == version
    assert result.source == "hkcu"
    assert len(registry.open_calls) == 2


def test_hklm_32_bit_view_compatible_runtime_is_accepted():
    result, registry = _detect({("HKLM", CLIENT_PATH): "151.0.4129.107"})

    assert result.compatible is True
    assert result.source == "hklm-32"
    hklm_call = next(call for call in registry.open_calls if call[0] == "HKLM")
    assert hklm_call[3] & _FakeWinreg.KEY_WOW64_32KEY


def test_valid_machine_runtime_wins_over_malformed_user_registration():
    result, _ = _detect(
        {
            ("HKCU", CLIENT_PATH): "broken",
            ("HKLM", CLIENT_PATH): "151.0.4129.107",
        }
    )

    assert result.compatible is True
    assert result.source == "hklm-32"
    assert result.version_text == "151.0.4129.107"


def test_highest_valid_version_is_reported_when_neither_is_compatible():
    result, _ = _detect(
        {
            ("HKCU", CLIENT_PATH): "85.0.1.0",
            ("HKLM", CLIENT_PATH): "85.0.2.0",
        }
    )

    assert result.compatible is False
    assert result.reason == "too-old"
    assert result.source == "hklm-32"
    assert result.version_text == "85.0.2.0"


def test_detection_result_is_immutable():
    result, _ = _detect({("HKCU", CLIENT_PATH): "151.0.4129.107"})

    with pytest.raises(FrozenInstanceError):
        result.compatible = False
