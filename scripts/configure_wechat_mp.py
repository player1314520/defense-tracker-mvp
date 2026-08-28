"""Interactively store WeChat credentials in the current-user DPAPI vault."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover - fail-closed branch depends on runtime packaging
    serialization = None
    Ed25519PublicKey = None


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from wechat_publisher import CredentialVaultError, WechatCredentialVault  # noqa: E402
from wechat_runtime import (  # noqa: E402
    RuntimeSecurityError,
    ensure_secure_directory,
    resolve_runtime_paths,
)


def _emit(payload: dict[str, object]) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Store WeChat MP credentials with Windows current-user DPAPI"
    )
    parser.add_argument(
        "--approval-public-key-file",
        type=Path,
        default=None,
        help="Ed25519 approval public-key PEM; never supply a private key",
    )
    args = parser.parse_args(argv)

    try:
        paths = resolve_runtime_paths()
        ensure_secure_directory(paths.runtime_dir)
    except RuntimeSecurityError:
        _emit({"status": "BLOCKED", "code": "RUNTIME_SECURITY_ERROR"})
        return 2

    credentials = {
        "app_id": getpass.getpass("公众号 AppID（不回显）: ").strip(),
        "app_secret": getpass.getpass("公众号 AppSecret（不回显）: ").strip(),
        "thumb_media_id": getpass.getpass("永久封面素材 media_id（不回显）: ").strip(),
    }
    missing = [name for name, value in credentials.items() if not value]
    if missing:
        _emit({"status": "BLOCKED", "code": "INPUT_MISSING", "missing": missing})
        return 2
    if args.approval_public_key_file is not None:
        try:
            if args.approval_public_key_file.stat().st_size > 16 * 1024:
                raise ValueError("public key file is too large")
            public_key_pem = args.approval_public_key_file.read_text(encoding="ascii")
            if "PRIVATE KEY" in public_key_pem:
                raise ValueError("private keys are forbidden")
            if serialization is None or Ed25519PublicKey is None:
                raise ValueError("asymmetric verification is unavailable")
            parsed_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
            if not isinstance(parsed_key, Ed25519PublicKey):
                raise ValueError("approval public key must use Ed25519")
            credentials["approval_public_key"] = public_key_pem
        except (OSError, UnicodeError, TypeError, ValueError):
            _emit({"status": "BLOCKED", "code": "APPROVAL_PUBLIC_KEY_INVALID"})
            return 2
    try:
        vault = WechatCredentialVault(paths.vault_path)
        vault.save(credentials)
    except RuntimeSecurityError:
        _emit({"status": "BLOCKED", "code": "RUNTIME_SECURITY_ERROR"})
        return 2
    except (CredentialVaultError, OSError, ValueError):
        _emit({"status": "BLOCKED", "code": "CREDENTIAL_VAULT_ERROR"})
        return 2
    _emit({"status": "CONFIGURED", "vault": Path(vault.path).name})
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="strict")
    raise SystemExit(main())
