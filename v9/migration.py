"""Non-destructive import of selected legacy business records into V9."""
from __future__ import annotations

import base64
import os
import sqlite3
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


LEGACY_TABLES = {
    "user_state.sqlite3": {
        "bookmarks": "source",
        "read_marks": "source",
        "alert_keywords": "alert_rule",
        "kv": "document",
    },
    "report_agent.sqlite3": {
        "projects": "document",
        "evidence": "evidence",
        "drafts": "document",
    },
    "consulting_agent.sqlite3": {
        "sessions": "evidence",
        "evidence": "evidence",
        "answers": "document",
        "source_assets": "evidence",
    },
    "quality_training.sqlite3": {
        "quality_articles": "evidence",
        "quality_generations": "document",
    },
}


def _json_safe(value):
    if isinstance(value, bytes):
        return {"base64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _backup_sqlite(source: Path) -> Path:
    backup = source.with_name(source.name + ".pre-v9.bak")
    if backup.exists():
        return backup
    backup.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(
        prefix=f".{backup.name}.",
        suffix=".migrating",
        dir=str(backup.parent),
    )
    os.close(handle)
    temporary = Path(temporary_name)
    try:
        with closing(sqlite3.connect(source)) as source_db, closing(
            sqlite3.connect(temporary)
        ) as target_db:
            source_db.backup(target_db)
            if target_db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise RuntimeError("legacy backup integrity check failed")
            target_db.commit()
        try:
            temporary.replace(backup)
        except FileExistsError:
            pass
        return backup
    finally:
        temporary.unlink(missing_ok=True)


def _row_key(conn: sqlite3.Connection, table: str, row: sqlite3.Row) -> str:
    primary_keys = [
        item["name"]
        for item in conn.execute(f'PRAGMA table_info("{table}")')
        if item["pk"]
    ]
    if primary_keys:
        return "|".join(str(row[key]) for key in primary_keys)
    return str(row["__v9_rowid__"])


def migrate_legacy_database(
    service,
    context: dict,
    source: Path,
    table_map: dict[str, str],
) -> dict:
    source = Path(source)
    if not source.is_file():
        return {"database": source.name, "created": 0, "skipped": 0, "backup": None}
    backup = _backup_sqlite(source)
    created = 0
    skipped = 0
    organization_id = str(context["organization_id"])
    with closing(
        sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True)
    ) as conn:
        conn.row_factory = sqlite3.Row
        existing_tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        for table, record_type in table_map.items():
            if table not in existing_tables:
                continue
            namespace = f"legacy-v1:{source.name}:{table}"
            rows = conn.execute(
                f'SELECT rowid AS __v9_rowid__, * FROM "{table}"'
            )
            for row in rows:
                external_ref = _row_key(conn, table, row)
                if service.repository.get_record_ref(
                    organization_id, namespace, external_ref
                ):
                    skipped += 1
                    continue
                payload = {
                    key: _json_safe(row[key])
                    for key in row.keys()
                    if key != "__v9_rowid__"
                }
                record = service.create_record(
                    organization_id,
                    str(context["user_id"]),
                    str(context["device_id"]),
                    record_type,
                    {
                        "legacy_import": {
                            "database": source.name,
                            "table": table,
                            "row_key": external_ref,
                            "migrated_at": datetime.now(timezone.utc).isoformat(),
                        },
                        "payload": payload,
                    },
                )
                service.repository.put_record_ref(
                    organization_id,
                    namespace,
                    external_ref,
                    record["record_id"],
                )
                created += 1
    return {
        "database": source.name,
        "created": created,
        "skipped": skipped,
        "backup": str(backup),
    }


def migrate_default_legacy_databases(service, context: dict, data_dir: Path) -> dict:
    marker_name = "legacy_migration_v1_complete"
    marker = service.repository.get_profile(marker_name)
    if (
        marker
        and marker.get("organization_id") == context.get("organization_id")
    ):
        return {
            "created": 0,
            "skipped": 0,
            "failed": 0,
            "databases": [],
            "already_complete": True,
        }
    results = []
    for database_name, table_map in LEGACY_TABLES.items():
        try:
            results.append(migrate_legacy_database(
                service,
                context,
                Path(data_dir) / database_name,
                table_map,
            ))
        except (OSError, sqlite3.DatabaseError, RuntimeError, ValueError) as exc:
            results.append({
                "database": database_name,
                "created": 0,
                "skipped": 0,
                "backup": None,
                "error": type(exc).__name__,
            })
    summary = {
        "created": sum(item["created"] for item in results),
        "skipped": sum(item["skipped"] for item in results),
        "failed": sum("error" in item for item in results),
        "databases": results,
    }
    if summary["failed"] == 0:
        service.repository.put_profile(
            marker_name,
            {
                "organization_id": context["organization_id"],
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "created": summary["created"],
            },
        )
    return summary
