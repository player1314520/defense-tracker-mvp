# -*- coding: utf-8 -*-
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from threading import Event, Lock


def test_personal_recovery_code_survives_restart_until_acknowledged(tmp_path):
    from v9.service import V9Service

    database = tmp_path / "v9.sqlite3"
    master_key = tmp_path / ".master"
    service = V9Service(database, master_key)
    first = service.get_or_create_personal_context()
    restarted = V9Service(database, master_key)
    second = restarted.get_or_create_personal_context()

    assert first["recovery_code"]
    assert second["recovery_code"] == first["recovery_code"]
    assert first["organization_id"] == second["organization_id"]
    assert first["device_id"] == second["device_id"]
    assert restarted.personal_recovery_pending() is True
    assert first["recovery_code"].encode("utf-8") not in database.read_bytes()
    assert first["recovery_code"].encode("utf-8") not in master_key.read_bytes()

    acknowledged = restarted.acknowledge_personal_recovery(
        first["organization_id"]
    )

    assert acknowledged["recovery_acknowledged"] is True
    assert restarted.personal_recovery_pending() is False
    assert "recovery_code" not in restarted.get_or_create_personal_context()
    persisted = restarted.repository.get_profile(
        "default_personal_recovery_state"
    )
    assert persisted["state"] == "acknowledged"
    assert "ciphertext" not in persisted
    assert "nonce" not in persisted


def test_personal_recovery_guard_serializes_separate_service_instances(
    tmp_path,
):
    from v9.service import V9Service

    database = tmp_path / "v9.sqlite3"
    master_key = tmp_path / ".master"
    first = V9Service(database, master_key)
    second = V9Service(database, master_key)
    holding = Event()
    release = Event()

    def hold_first_guard():
        with first._personal_recovery_guard():
            holding.set()
            assert release.wait(5)

    with ThreadPoolExecutor(max_workers=2) as executor:
        holder = executor.submit(hold_first_guard)
        assert holding.wait(5)
        creator = executor.submit(second.get_or_create_personal_context)
        try:
            creator.result(timeout=0.15)
        except TimeoutError:
            pass
        else:
            raise AssertionError("cross-instance recovery guard did not block")
        release.set()
        holder.result(timeout=5)
        created = creator.result(timeout=5)

    resumed = first.get_or_create_personal_context()
    assert resumed["organization_id"] == created["organization_id"]
    assert resumed["recovery_code"] == created["recovery_code"]


def test_first_master_key_creation_is_atomic_across_service_instances(
    tmp_path,
    monkeypatch,
):
    from v9.service import V9Service

    master_key = tmp_path / ".master"
    original_write = V9Service._write_master_key_payload
    write_calls = []
    calls_lock = Lock()
    second_writer = Event()
    start = Event()

    def delayed_write(path, payload):
        with calls_lock:
            write_calls.append(bytes(payload))
            position = len(write_calls)
        if position == 1:
            second_writer.wait(1)
        else:
            second_writer.set()
        original_write(path, payload)

    monkeypatch.setattr(
        V9Service,
        "_write_master_key_payload",
        staticmethod(delayed_write),
    )

    def construct(database_name):
        assert start.wait(5)
        return V9Service(tmp_path / database_name, master_key)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(construct, "first.sqlite3")
        second_future = executor.submit(construct, "second.sqlite3")
        start.set()
        first = first_future.result(timeout=10)
        second = second_future.result(timeout=10)

    assert len(write_calls) == 1
    assert first._master_key == second._master_key


def test_reading_empty_evidence_does_not_consume_recovery_code(tmp_path):
    from flask import Flask

    from v9.api import create_blueprint
    from v9.service import V9Service

    service = V9Service(tmp_path / "v9.sqlite3", tmp_path / ".master")
    app = Flask(__name__)
    app.register_blueprint(create_blueprint(lambda: service))

    response = app.test_client().get("/api/v9/evidence")

    assert response.status_code == 400
    assert "X-V9-Context-Mode" in response.get_json()["error"]
    assert service.get_personal_context() is None
    assert service.get_or_create_personal_context()["recovery_code"]


def test_news_archive_is_encrypted_deduplicated_and_traceable(tmp_path):
    from v9.service import V9Service

    service = V9Service(tmp_path / "v9.sqlite3", tmp_path / ".master")
    context = service.get_or_create_personal_context()
    article = {
        "aid": "article-1",
        "title": "真实来源标题",
        "source": "Source A",
        "link": "https://example.test/article-1",
        "date": "2026-07-25T08:00:00+00:00",
        "summary": "来源摘要",
        "priority": {"stars": 8},
        "region": "🇹🇼 台湾",
    }

    first = service.archive_news_evidence(context, article)
    second = service.archive_news_evidence(context, article)

    assert first["created"] is True
    assert second["created"] is False
    assert first["record_id"] == second["record_id"]
    assert "真实来源标题".encode() not in service.database_path.read_bytes()
    evidence = service.list_evidence(context)
    assert evidence[0]["content"]["provenance"]["url"] == article["link"]
    assert evidence[0]["content"]["citation_status"] == "unreviewed"
