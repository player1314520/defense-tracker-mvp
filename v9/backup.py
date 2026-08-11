"""Integrity-checked SQLite backup and non-overwriting restore helpers."""
from __future__ import annotations

import os
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path


def _integrity(path: Path) -> bool:
    with closing(sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)) as conn:
        return conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def backup_database(source: Path, destination: Path) -> Path:
    source = Path(source).resolve()
    destination = Path(destination).resolve()
    if source == destination:
        raise ValueError("backup destination must differ from source")
    if not source.is_file():
        raise FileNotFoundError(source)
    if destination.exists():
        raise FileExistsError(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".backup",
        dir=str(destination.parent),
    )
    os.close(handle)
    temporary = Path(temporary_name)
    try:
        with closing(sqlite3.connect(source)) as source_db, closing(
            sqlite3.connect(temporary)
        ) as target_db:
            source_db.backup(target_db)
            target_db.commit()
        if not _integrity(temporary):
            raise RuntimeError("backup integrity check failed")
        temporary.replace(destination)
        return destination
    finally:
        temporary.unlink(missing_ok=True)


def restore_database(backup: Path, destination: Path) -> Path:
    backup = Path(backup).resolve()
    destination = Path(destination).resolve()
    if not _integrity(backup):
        raise RuntimeError("backup integrity check failed")
    return backup_database(backup, destination)
