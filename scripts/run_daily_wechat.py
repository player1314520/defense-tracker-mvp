"""Machine-readable entry point for the daily WeChat publication job."""

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
    ApiError,
    ApprovalError,
    CredentialVaultError,
    IdempotencyConflict,
    ManifestError,
    PublicationLedger,
    PublicationService,
    WeChatApiClient,
    WechatCredentialVault,
    compute_manifest_hashes,
    validate_manifest,
)
from wechat_runtime import (  # noqa: E402
    LedgerMigrationError,
    RuntimeSecurityError,
    ensure_private_file,
    ensure_secure_directory,
    migrate_legacy_ledger,
    prepare_secure_ledger_directory,
    resolve_runtime_paths,
    validate_secure_directory,
)


LEGACY_LEDGER_PATH = REPO_ROOT / "素材库" / "每日新闻" / "wechat_publications.sqlite3"


def _emit(payload: Mapping[str, Any]) -> None:
    print(json.dumps(dict(payload), ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _load_runtime_credentials(
    environment: Mapping[str, str], *, vault_path: Path | None = None
) -> dict[str, str]:
    source = str(environment.get("WECHAT_CREDENTIAL_SOURCE", "vault")).strip().lower()
    if source == "environment":
        mapping = {
            "app_id": environment.get("WECHAT_MP_APP_ID", ""),
            "app_secret": environment.get("WECHAT_MP_APP_SECRET", ""),
            "thumb_media_id": environment.get("WECHAT_THUMB_MEDIA_ID", ""),
            "approval_public_key": environment.get("WECHAT_APPROVAL_PUBLIC_KEY", ""),
        }
        return {name: value for name, value in mapping.items() if value}
    if source not in {"", "vault"}:
        raise CredentialVaultError("unsupported credential source")
    try:
        vault = WechatCredentialVault(vault_path) if vault_path is not None else WechatCredentialVault()
        return vault.load() or {}
    except RuntimeSecurityError:
        raise
    except CredentialVaultError:
        raise
    except Exception as exc:
        raise CredentialVaultError("credential vault is unavailable") from exc


def _load_issue(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ManifestError("content file does not exist")
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ManifestError("content file exceeds 2 MiB")
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError("content file is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ManifestError("content JSON must be an object")
    return payload


def issue_to_manifest(
    issue: Mapping[str, Any], action: str, environment: Mapping[str, str]
) -> dict[str, Any]:
    """Normalize the stable issue JSON contract into a publication manifest."""

    if action == "publish":
        delivery = "publish"
    elif action == "mass-send":
        delivery = "mass"
    else:
        delivery = str(issue.get("delivery") or "mass")
        if delivery == "mass-send":
            delivery = "mass"

    raw_sources = issue.get("sources", issue.get("source_urls", []))
    sources: list[dict[str, Any]] = []
    if isinstance(raw_sources, list):
        for item in raw_sources:
            if isinstance(item, str) and item.strip():
                sources.append({"url": item.strip()})
            elif isinstance(item, Mapping):
                sources.append(dict(item))

    manifest: dict[str, Any] = {
        "channel": str(issue.get("channel") or "wechat_official"),
        "publication_date": str(issue.get("edition_date") or issue.get("publication_date") or ""),
        "edition": str(issue.get("edition") or "daily"),
        "delivery": delivery,
        "article": {
            "title": issue.get("title"),
            "author": issue.get("author", ""),
            "digest": issue.get("digest"),
            "content": issue.get("content_html", issue.get("content")),
            "content_source_url": issue.get("content_source_url", ""),
            "thumb_media_id": issue.get("thumb_media_id")
            or environment.get("WECHAT_THUMB_MEDIA_ID", ""),
        },
        "sources": sources,
    }
    if isinstance(issue.get("approval"), Mapping):
        manifest["approval"] = dict(issue["approval"])
    return manifest


def _prepare(manifest: Mapping[str, Any], ledger: PublicationLedger) -> dict[str, Any]:
    validate_manifest(manifest, require_thumb=False)
    blockers = []
    if not str((manifest.get("article") or {}).get("thumb_media_id") or "").strip():
        blockers.append("THUMB_MEDIA_ID_MISSING")
    record = ledger.reserve(
        manifest,
        state="review_pending",
        allow_review_update=True,
    )
    hashes = compute_manifest_hashes(manifest)
    return {
        "status": "REVIEW_PENDING",
        "state": record["state"],
        "channel": manifest["channel"],
        "edition_date": manifest["publication_date"],
        "edition": manifest["edition"],
        "delivery": manifest["delivery"],
        **hashes,
        "requires_approval": manifest["delivery"] in {"publish", "mass"},
        "blockers": blockers,
        "delivery_verified": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prepare or deliver one daily WeChat issue")
    parser.add_argument("--content", required=True, type=Path, help="UTF-8 issue JSON path")
    parser.add_argument(
        "--action",
        required=True,
        choices=("prepare", "draft", "publish", "mass-send"),
    )
    parser.add_argument(
        "--ledger",
        type=Path,
        default=None,
        help="SQLite ledger path (contains no credentials)",
    )
    parser.add_argument("--poll-attempts", type=int, default=3)
    return parser


def main(argv: list[str] | None = None, environment: Mapping[str, str] | None = None) -> int:
    environment = os.environ if environment is None else environment
    args = _parser().parse_args(argv)
    try:
        paths = resolve_runtime_paths(environment, ledger_override=args.ledger)
        ensure_secure_directory(paths.runtime_dir)
        if paths.ledger_path.parent != paths.runtime_dir:
            if paths.ledger_path.parent.exists():
                validate_secure_directory(paths.ledger_path.parent)
            else:
                prepare_secure_ledger_directory(paths.ledger_path.parent)
        issue = _load_issue(args.content)
        manifest = issue_to_manifest(issue, args.action, environment)
        credentials = _load_runtime_credentials(environment, vault_path=paths.vault_path)
        if not manifest["article"].get("thumb_media_id"):
            manifest["article"]["thumb_media_id"] = credentials.get("thumb_media_id", "")

        if args.action == "prepare":
            if paths.ledger_is_default:
                migrate_legacy_ledger(LEGACY_LEDGER_PATH, paths.ledger_path)
            ledger = PublicationLedger(paths.ledger_path)
            _emit(_prepare(manifest, ledger))
            return 0

        missing = [
            name
            for name, field in (
                ("WECHAT_MP_APP_ID", "app_id"),
                ("WECHAT_MP_APP_SECRET", "app_secret"),
            )
            if not credentials.get(field)
        ]
        if missing:
            _emit(
                {
                    "status": "BLOCKED",
                    "code": "CONFIG_MISSING",
                    "missing": missing,
                    "delivery_verified": False,
                }
            )
            return 2
        if not manifest["article"].get("thumb_media_id"):
            _emit(
                {
                    "status": "BLOCKED",
                    "code": "THUMB_MEDIA_ID_MISSING",
                    "delivery_verified": False,
                }
            )
            return 2

        public_action = args.action in {"publish", "mass-send"}
        if public_action and not _truthy(environment.get("WECHAT_PUBLISH_ENABLED")):
            _emit(
                {
                    "status": "BLOCKED",
                    "code": "PUBLISH_DISABLED",
                    "delivery_verified": False,
                }
            )
            return 2

        if paths.ledger_is_default:
            migrate_legacy_ledger(LEGACY_LEDGER_PATH, paths.ledger_path)
        ledger = PublicationLedger(paths.ledger_path)
        client = WeChatApiClient(
            credentials["app_id"],
            credentials["app_secret"],
        )
        service = PublicationService(
            client,
            ledger,
            publish_enabled=public_action,
            approval_public_key=credentials.get("approval_public_key"),
            poll_attempts=args.poll_attempts,
        )
        result = service.run(manifest)
        if args.action == "draft" and result.get("draft_media_id"):
            result["status"] = "DRAFT_STAGED"
            exit_code = 0
        else:
            result["status"] = str(result["state"]).upper()
            exit_code = 0 if result["state"] in {"drafted", "published", "delivered"} else 3
        _emit(result)
        return exit_code
    except (ManifestError, IdempotencyConflict) as exc:
        _emit(
            {
                "status": "BLOCKED",
                "code": type(exc).__name__.upper(),
                "message": str(exc),
                "delivery_verified": False,
            }
        )
        return 2
    except ApprovalError as exc:
        _emit(
            {
                "status": "BLOCKED",
                "code": "APPROVAL_INVALID",
                "message": str(exc),
                "delivery_verified": False,
            }
        )
        return 2
    except CredentialVaultError:
        _emit(
            {
                "status": "BLOCKED",
                "code": "CREDENTIAL_VAULT_ERROR",
                "delivery_verified": False,
            }
        )
        return 2
    except RuntimeSecurityError:
        _emit(
            {
                "status": "BLOCKED",
                "code": "RUNTIME_SECURITY_ERROR",
                "delivery_verified": False,
            }
        )
        return 2
    except LedgerMigrationError:
        _emit(
            {
                "status": "BLOCKED",
                "code": "LEDGER_MIGRATION_ERROR",
                "delivery_verified": False,
            }
        )
        return 2
    except ApiError as exc:
        _emit(
            {
                "status": "FAILED",
                "code": "WECHAT_API_ERROR",
                "message": str(exc),
                "delivery_verified": False,
            }
        )
        return 3
    except Exception:
        # No traceback or exception text: neither is a stable machine contract,
        # and third-party exceptions may contain request secrets.
        _emit(
            {
                "status": "FAILED",
                "code": "INTERNAL_ERROR",
                "delivery_verified": False,
            }
        )
        return 3


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="strict")
    raise SystemExit(main())
