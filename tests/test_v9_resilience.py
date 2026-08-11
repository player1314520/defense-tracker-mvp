# -*- coding: utf-8 -*-
import io
import logging
import sqlite3
import zipfile

import pytest


def _service(tmp_path):
    from v9.service import V9Service

    service = V9Service(tmp_path / "v9.sqlite3", tmp_path / "config" / ".master")
    return service, service.get_or_create_personal_context()


def test_ciphertext_database_backup_restores_without_overwriting(tmp_path):
    from v9.backup import backup_database, restore_database
    from v9.service import V9Service

    service, context = _service(tmp_path)
    created = service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "evidence",
        {"body": "encrypted backup body"},
    )
    backup = backup_database(
        service.database_path, tmp_path / "backups" / "v9.sqlite3"
    )
    restored = restore_database(backup, tmp_path / "restored" / "v9.sqlite3")
    restored_service = V9Service(restored, service.local_master_key_path)
    record = restored_service.read_record(
        context["organization_id"], context["user_id"], created["record_id"]
    )

    assert record["content"]["body"] == "encrypted backup body"
    with pytest.raises(FileExistsError):
        restore_database(backup, restored)


def test_service_creates_integrity_checked_local_backup(tmp_path):
    service, context = _service(tmp_path)
    service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "evidence",
        {"body": "encrypted"},
    )
    result = service.create_local_backup(
        context["organization_id"], context["user_id"]
    )
    destination = service.database_path.parent / "backups" / result["filename"]

    assert result["ciphertext_database"] is True
    assert result["plaintext_included"] is False
    assert result["bytes"] == destination.stat().st_size
    with sqlite3.connect(destination) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_wrong_local_master_key_fails_closed(tmp_path):
    from cryptography.exceptions import InvalidTag
    from v9.backup import backup_database
    from v9.service import V9Service

    service, context = _service(tmp_path)
    service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "evidence",
        {"body": "not recoverable with wrong local key"},
    )
    copied = backup_database(service.database_path, tmp_path / "copied.sqlite3")
    locked = V9Service(copied, tmp_path / "wrong" / ".master")

    with pytest.raises(InvalidTag):
        locked.read_record(
            context["organization_id"],
            context["user_id"],
            service.export_outbox(context["organization_id"])[0]["record_id"],
        )


def test_write_failure_does_not_corrupt_existing_record(tmp_path, monkeypatch):
    service, context = _service(tmp_path)
    created = service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "case",
        {"title": "stable"},
    )

    def disk_full(*args, **kwargs):
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(service.repository, "put_record", disk_full)
    with pytest.raises(sqlite3.OperationalError, match="disk is full"):
        service.update_record(
            context["organization_id"],
            context["user_id"],
            context["device_id"],
            created["record_id"],
            expected_version=1,
            content={"title": "must not commit"},
        )
    record = service.read_record(
        context["organization_id"],
        context["user_id"],
        created["record_id"],
    )
    assert record["version"] == 1
    assert record["content"]["title"] == "stable"


def test_diagnostic_bundle_excludes_bodies_keys_paths_and_log_contents(tmp_path):
    service, context = _service(tmp_path)
    secret_body = "DIAGNOSTIC_BODY_MUST_NOT_LEAK"
    service.create_record(
        context["organization_id"],
        context["user_id"],
        context["device_id"],
        "evidence",
        {"body": secret_body},
    )
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "app.log").write_text(
        "Bearer diagnostic-secret-token " + secret_body,
        encoding="utf-8",
    )
    bundle = service.export_diagnostic_bundle(
        context["organization_id"], context["user_id"]
    )
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        names = set(archive.namelist())
        combined = b"\n".join(archive.read(name) for name in names)

    assert names == {
        "runtime.json",
        "database-health.json",
        "configuration-presence.json",
        "log-metadata.json",
        "release.json",
        "privacy-policy.json",
    }
    assert secret_body.encode() not in combined
    assert b"diagnostic-secret-token" not in combined
    assert str(tmp_path).encode() not in combined
    assert b"record_counts" in combined


def test_diagnostic_bundle_accepts_powershell_utf8_bom_manifest(tmp_path):
    from v9.diagnostics import build_diagnostic_bundle

    service, context = _service(tmp_path)
    manifest = tmp_path / "release-manifest.json"
    manifest.write_text(
        '{"schema":1,"product":"DefenseTracker","version":"V9","commit":"abc"}',
        encoding="utf-8-sig",
    )
    bundle = build_diagnostic_bundle(
        database_path=service.database_path,
        organization_id=context["organization_id"],
        config_dir=tmp_path / "config",
        logs_dir=tmp_path / "logs",
        release_manifest_path=manifest,
    )
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        release = archive.read("release.json")

    assert b"DefenseTracker" in release
    assert b"abc" in release


def test_default_log_filter_redacts_credentials():
    from v9.redaction import SecretRedactionFilter

    record = logging.LogRecord(
        "test",
        logging.INFO,
        __file__,
        1,
        "Authorization Bearer abcdefghijklmnop api_key=sk-secretvalue",
        (),
        None,
    )
    assert SecretRedactionFilter().filter(record) is True
    rendered = record.getMessage()
    assert "abcdefghijklmnop" not in rendered
    assert "sk-secretvalue" not in rendered
    assert rendered.count("[REDACTED]") == 2
