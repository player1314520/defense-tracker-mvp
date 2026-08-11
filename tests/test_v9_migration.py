# -*- coding: utf-8 -*-
import hashlib
import sqlite3


def test_legacy_migration_backs_up_encrypts_and_is_idempotent(tmp_path):
    from v9.migration import migrate_legacy_database
    from v9.service import V9Service

    source = tmp_path / "user_state.sqlite3"
    with sqlite3.connect(source) as conn:
        conn.execute(
            """
            CREATE TABLE bookmarks(
                aid TEXT PRIMARY KEY,link TEXT,title TEXT,source TEXT,date TEXT,
                created_at TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO bookmarks VALUES(?,?,?,?,?,?)",
            (
                "article-1",
                "https://example.test/1",
                "Legacy title",
                "Legacy source",
                "2026-07-25",
                "2026-07-25T00:00:00+00:00",
            ),
        )
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    service = V9Service(tmp_path / "v9.sqlite3", tmp_path / ".master")
    context = service.get_or_create_personal_context()

    first = migrate_legacy_database(
        service, context, source, {"bookmarks": "source"}
    )
    second = migrate_legacy_database(
        service, context, source, {"bookmarks": "source"}
    )

    assert first["created"] == 1
    assert second == {
        "database": "user_state.sqlite3",
        "created": 0,
        "skipped": 1,
        "backup": first["backup"],
    }
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    backup = source.with_name("user_state.sqlite3.pre-v9.bak")
    assert backup.is_file()
    with sqlite3.connect(backup) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    record_id = service.repository.get_record_ref(
        context["organization_id"],
        "legacy-v1:user_state.sqlite3:bookmarks",
        "article-1",
    )
    record = service.read_record(
        context["organization_id"], context["user_id"], record_id
    )
    assert record["content"]["payload"]["title"] == "Legacy title"


def test_default_migration_sets_success_marker_and_skips_future_scan(tmp_path):
    from v9.migration import migrate_default_legacy_databases
    from v9.service import V9Service

    service = V9Service(tmp_path / "v9.sqlite3", tmp_path / ".master")
    context = service.get_or_create_personal_context()
    first = migrate_default_legacy_databases(service, context, tmp_path)
    second = migrate_default_legacy_databases(service, context, tmp_path)

    assert first["failed"] == 0
    assert second["already_complete"] is True
    assert second["databases"] == []
