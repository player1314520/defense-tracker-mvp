"""Privacy-bounded local diagnostic package generation."""
from __future__ import annotations

import io
import json
import platform
import sqlite3
import sys
import zipfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


_CONFIG_NAMES = (
    ".access_token",
    ".ai_config.json",
    ".feishu_config.json",
    ".supabase_config.json",
    ".supabase_v9_config.json",
    ".search_config.json",
    ".email_config.json",
)


def _database_health(database_path: Path, organization_id: str) -> dict:
    with closing(sqlite3.connect(database_path)) as conn:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        record_counts = dict(conn.execute(
            """
            SELECT record_type,COUNT(*) FROM encrypted_records
            WHERE organization_id=? GROUP BY record_type
            """,
            (organization_id,),
        ))
        outbox_counts = dict(conn.execute(
            """
            SELECT state,COUNT(*) FROM sync_outbox
            WHERE organization_id=? GROUP BY state
            """,
            (organization_id,),
        ))
        conflict_counts = dict(conn.execute(
            """
            SELECT state,COUNT(*) FROM conflicts
            WHERE organization_id=? GROUP BY state
            """,
            (organization_id,),
        ))
    return {
        "integrity": integrity,
        "record_counts": record_counts,
        "outbox_counts": outbox_counts,
        "conflict_counts": conflict_counts,
    }


def build_diagnostic_bundle(
    *,
    database_path: Path,
    organization_id: str,
    config_dir: Path,
    logs_dir: Path,
    release_manifest_path: Path | None = None,
) -> bytes:
    config_dir = Path(config_dir)
    logs_dir = Path(logs_dir)
    log_files = [
        path for path in logs_dir.glob("*.log")
        if path.is_file()
    ] if logs_dir.is_dir() else []
    release = {}
    if release_manifest_path and Path(release_manifest_path).is_file():
        raw = json.loads(
            Path(release_manifest_path).read_text(encoding="utf-8-sig")
        )
        release = {
            key: raw.get(key)
            for key in ("schema", "product", "version", "built_at", "commit", "python")
        }
    documents = {
        "runtime.json": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "platform": platform.system(),
            "platform_release": platform.release(),
            "python": platform.python_version(),
            "frozen": bool(getattr(sys, "frozen", False)),
        },
        "database-health.json": _database_health(
            Path(database_path), organization_id
        ),
        "configuration-presence.json": {
            name: (config_dir / name).is_file() for name in _CONFIG_NAMES
        },
        "log-metadata.json": {
            "file_count": len(log_files),
            "total_bytes": sum(path.stat().st_size for path in log_files),
            "contents_included": False,
        },
        "release.json": release,
        "privacy-policy.json": {
            "excluded": [
                "record ciphertext and plaintext",
                "log contents",
                "credentials and key material",
                "local paths, host name and user name",
                "attachments and source documents",
            ]
        },
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in documents.items():
            archive.writestr(
                name,
                json.dumps(
                    content,
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                ),
            )
    return output.getvalue()
