#!/usr/bin/env python3
"""Export one ciphertext-only MVP owner bootstrap manifest.

The owner and Supabase session identifiers are derived from the desktop's
validated in-memory session. They are intentionally not command-line inputs.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from state import CONFIG_DIR, DATA_DIR, VAULT_DIR  # noqa: E402
from v9.service import V9Service  # noqa: E402
from v9.supabase_client import (  # noqa: E402
    SessionVault,
    SupabaseHttpClient,
    SupabaseSessionManager,
    SupabaseSettings,
)


MANIFEST_FIELDS = frozenset({
    "schema_version",
    "organization_id",
    "owner_user_id",
    "session_id",
    "name_ciphertext",
    "name_nonce",
    "device_id",
    "device_public_key",
    "device_name_ciphertext",
    "device_name_nonce",
    "key_algorithm",
    "device_kind",
})


def _current_windows_user_sid() -> str:
    identity = subprocess.run(
        ["whoami", "/user", "/fo", "csv", "/nh"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    match = re.search(r"S-\d(?:-\d+)+", identity.stdout or "")
    if identity.returncode != 0 or match is None:
        raise PermissionError("current Windows user SID is unavailable")
    return match.group(0)


def _harden_windows_private_file(path: Path) -> None:
    sid = _current_windows_user_sid()
    hardened = subprocess.run(
        [
            "icacls",
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"*{sid}:F",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if hardened.returncode != 0:
        raise PermissionError("owner manifest ACL hardening failed")


def _harden_private_file(path: Path) -> None:
    if os.name != "nt":
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        if stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise PermissionError("owner manifest permissions are not private")
        return
    _harden_windows_private_file(path)


def _supabase_config_path() -> Path:
    candidates: list[Path] = []
    explicit = os.environ.get("DEFENSE_TRACKER_SUPABASE_CONFIG", "").strip()
    if explicit:
        candidates.append(Path(explicit).expanduser())
    local_app_data = os.environ.get("LOCALAPPDATA", "").strip()
    if local_app_data:
        candidates.append(
            Path(local_app_data)
            / "DefenseTracker"
            / "config"
            / ".supabase_v9_config.json"
        )
    candidates.append(Path(CONFIG_DIR) / ".supabase_v9_config.json")
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved.is_file():
            return resolved
    raise FileNotFoundError("Supabase V9 configuration is not available")


def _authenticated_cloud_session() -> SupabaseSessionManager:
    config_path = _supabase_config_path()
    settings = SupabaseSettings.load(config_path)
    runtime_root = config_path.parent.parent
    return SupabaseSessionManager(
        settings,
        SessionVault(runtime_root / "vault"),
        SupabaseHttpClient(settings),
    )


def write_owner_manifest_atomic(
    manifest: Mapping[str, object],
    destination: Path | str,
) -> Path:
    """Atomically create a private manifest and refuse to overwrite a file."""
    payload = dict(manifest)
    if set(payload) != MANIFEST_FIELDS:
        raise ValueError("invalid owner bootstrap manifest fields")
    if (
        payload.get("schema_version") != 1
        or payload.get("key_algorithm") != "p256"
        or payload.get("device_kind") != "desktop"
    ):
        raise ValueError("invalid owner bootstrap manifest contract")

    target = Path(destination).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    encoded = (
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=target.parent,
    )
    temporary = Path(temporary_name)
    published = False
    try:
        if os.name != "nt" and hasattr(os, "fchmod"):
            os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
        else:
            # Apply the owner-only DACL before any sensitive metadata is written.
            _harden_private_file(temporary)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            _harden_private_file(temporary)
        os.link(temporary, target)
        published = True
        _harden_private_file(target)
    except Exception:
        if published:
            target.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    return target


def export_authenticated_owner_manifest(destination: Path | str) -> Path:
    """Build from local secrets plus the validated session, then write once."""
    service = V9Service(
        Path(DATA_DIR) / "v9.sqlite3",
        Path(VAULT_DIR) / ".v9_local_master.key",
    )
    personal = service.get_personal_context()
    if personal is None:
        raise RuntimeError("personal workspace must be initialized first")
    if service.personal_recovery_pending():
        raise RuntimeError("personal recovery acknowledgement is required")
    manifest = service.build_mvp_owner_bootstrap_manifest(
        personal,
        authenticated_session=_authenticated_cloud_session(),
    )
    return write_owner_manifest_atomic(manifest, destination)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Export a one-time ciphertext-only MVP owner bootstrap manifest"
        )
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="new manifest path; an existing path is never overwritten",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    written = export_authenticated_owner_manifest(args.output)
    print(f"Owner bootstrap manifest written: {written}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
