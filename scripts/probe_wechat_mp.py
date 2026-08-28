"""Read-only, machine-readable WeChat Official Account credential probe."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from wechat_publisher import (  # noqa: E402
    CredentialVaultError,
    WeChatApiClient,
    WechatCredentialVault,
)
from wechat_runtime import (  # noqa: E402
    RuntimeSecurityError,
    ensure_secure_directory,
    resolve_runtime_paths,
)


_OUTPUT_FIELDS = (
    "status",
    "token_ok",
    "draft_count_ok",
    "total_count",
    "cover_ok",
    "cover_kind",
    "code",
    "category",
)
_SAFE_STATUSES = frozenset({"OK", "BLOCKED", "FAILED"})
_SAFE_CATEGORIES = frozenset(
    {
        "OK",
        "CONFIG",
        "IP_ALLOWLIST",
        "PERMISSION",
        "TOKEN",
        "MATERIAL",
        "TRANSIENT",
        "QUOTA",
        "UNKNOWN",
    }
)
_SAFE_CODES = frozenset(
    {
        "OK",
        "CONFIG_MISSING",
        "CREDENTIAL_VAULT_ERROR",
        "RUNTIME_SECURITY_ERROR",
        "MATERIAL_TOO_LARGE",
        "INVALID_IMAGE",
        "HTTP_ERROR",
        "REQUEST_ERROR",
        "UNEXPECTED_RESPONSE",
        "UNKNOWN",
        "40002",
        "40013",
        "41002",
        "41004",
        "43002",
        "40125",
        "40164",
        "45035",
        "61004",
        "48001",
        "48004",
        "89503",
        "89506",
        "89507",
        "40001",
        "40014",
        "42001",
        "40007",
        "-1",
        "45009",
        "45011",
    }
)


def _result(*, status: str, code: str, category: str) -> dict[str, Any]:
    return {
        "status": status,
        "token_ok": False,
        "draft_count_ok": False,
        "total_count": None,
        "cover_ok": False,
        "cover_kind": None,
        "code": code,
        "category": category,
    }


def _sanitize_result(payload: Mapping[str, Any]) -> dict[str, Any]:
    status = payload.get("status")
    code = payload.get("code")
    category = payload.get("category")
    total_count = payload.get("total_count")
    cover_kind = payload.get("cover_kind")
    return {
        "status": status if status in _SAFE_STATUSES else "FAILED",
        "token_ok": payload.get("token_ok") is True,
        "draft_count_ok": payload.get("draft_count_ok") is True,
        "total_count": (
            total_count
            if isinstance(total_count, int) and not isinstance(total_count, bool) and total_count >= 0
            else None
        ),
        "cover_ok": payload.get("cover_ok") is True,
        "cover_kind": cover_kind if cover_kind in {"png", "jpeg"} else None,
        "code": code if code in _SAFE_CODES else "UNKNOWN",
        "category": category if category in _SAFE_CATEGORIES else "UNKNOWN",
    }


def _emit(payload: Mapping[str, Any]) -> None:
    safe = _sanitize_result(payload)
    assert tuple(safe) == _OUTPUT_FIELDS
    print(json.dumps(safe, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        description="Read-only WeChat MP token, draft-count, and cover-material probe"
    )


def main(
    argv: list[str] | None = None,
    environment: Mapping[str, str] | None = None,
) -> int:
    _parser().parse_args(argv)
    environment = os.environ if environment is None else environment

    try:
        paths = resolve_runtime_paths(environment)
        ensure_secure_directory(paths.runtime_dir)
        credentials = WechatCredentialVault(paths.vault_path).load() or {}
    except RuntimeSecurityError:
        _emit(
            _result(
                status="BLOCKED",
                code="RUNTIME_SECURITY_ERROR",
                category="CONFIG",
            )
        )
        return 2
    except (CredentialVaultError, OSError):
        _emit(
            _result(
                status="BLOCKED",
                code="CREDENTIAL_VAULT_ERROR",
                category="CONFIG",
            )
        )
        return 2

    required = ("app_id", "app_secret", "thumb_media_id")
    if any(not isinstance(credentials.get(name), str) or not credentials[name].strip() for name in required):
        _emit(_result(status="BLOCKED", code="CONFIG_MISSING", category="CONFIG"))
        return 2

    try:
        client = WeChatApiClient(credentials["app_id"], credentials["app_secret"])
        result = client.probe_account(credentials["thumb_media_id"])
    except Exception:
        # Exception text is deliberately discarded because transports can echo secrets.
        _emit(_result(status="FAILED", code="UNKNOWN", category="UNKNOWN"))
        return 3

    _emit(result)
    return 0 if result.get("status") == "OK" else 3


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="strict")
    raise SystemExit(main())
