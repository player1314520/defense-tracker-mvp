from datetime import datetime, timezone
from io import BytesIO
from types import SimpleNamespace
import threading
import zipfile

import pytest
import app as tracker
from upload_safety import UploadValidationError
from werkzeug.datastructures import FileStorage


def _article(title="persisted"):
    return {
        "title": title,
        "link": f"https://example.test/{title}",
        "source": "test",
        "date": datetime.now(timezone.utc).isoformat(),
        "priority": {"stars": 3},
    }


def _isolated_cache(monkeypatch):
    cache = {
        "news": [],
        "last_update": None,
        "fetch_errors": [],
        "fetch_stats": {},
    }
    monkeypatch.setattr(tracker, "cache", cache)
    monkeypatch.setattr(tracker, "cache_lock", threading.RLock())
    return cache


def test_refresh_news_persists_only_successful_last_good_snapshot(monkeypatch):
    cache = _isolated_cache(monkeypatch)
    saved = []
    monkeypatch.setattr(tracker, "RSS_FEEDS", [{"name": "feed-a"}])
    monkeypatch.setattr(tracker, "fetch_feed", lambda feed: [_article()])
    monkeypatch.setattr(
        tracker.user_state,
        "save_rss_last_good",
        lambda feed_id, snapshot, fetched_at=None: saved.append(
            (feed_id, snapshot, fetched_at)
        ),
    )

    tracker.refresh_news()

    assert cache["news"][0]["title"] == "persisted"
    assert cache["freshness"] == "fresh"
    assert saved[0][0] == "aggregate"
    assert saved[0][1]["news"][0]["title"] == "persisted"
    assert saved[0][2] == cache["last_update"]


def test_empty_refresh_keeps_last_good_and_records_failure(monkeypatch):
    cache = _isolated_cache(monkeypatch)
    cache.update({"news": [_article("old")], "last_update": "old-time"})
    failures = []
    monkeypatch.setattr(tracker, "RSS_FEEDS", [{"name": "feed-a"}])
    monkeypatch.setattr(tracker, "fetch_feed", lambda feed: [])
    monkeypatch.setattr(
        tracker.user_state,
        "save_rss_last_good",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("empty refresh must not replace last-good snapshot")
        ),
    )
    monkeypatch.setattr(
        tracker.user_state,
        "record_rss_failure",
        lambda feed_id, code, failed_at=None: failures.append((feed_id, code)),
    )

    tracker.refresh_news()

    assert cache["news"][0]["title"] == "old"
    assert cache["last_update"] == "old-time"
    assert cache["freshness"] == "stale"
    assert failures == [("aggregate", "RSS_REFRESH_EMPTY")]


def test_startup_loads_last_successful_rss_snapshot(monkeypatch):
    cache = _isolated_cache(monkeypatch)
    monkeypatch.setattr(
        tracker.user_state,
        "get_rss_runtime_status",
        lambda feed_id: {
            "feed_id": feed_id,
            "status": "stale",
            "snapshot": {
                "news": [_article("restored")],
                "last_update": "2026-08-31T00:00:00+00:00",
                "fetch_errors": ["feed-b"],
                "fetch_stats": {"feed-a": 1},
                "dup_removed": 2,
            },
            "fetched_at": "2026-08-31T00:00:00+00:00",
            "failure": None,
        },
    )

    assert tracker._load_persisted_news_snapshot() is True
    assert cache["news"][0]["title"] == "restored"
    assert cache["freshness"] == "stale"
    assert cache["dup_removed"] == 2


def test_uploaded_docx_extension_cannot_bypass_magic_validation():
    upload = FileStorage(stream=BytesIO(b"plain text"), filename="report.docx")

    try:
        tracker._extract_file_text(upload)
    except UploadValidationError as exc:
        assert exc.code == "DOCX_MAGIC_MISMATCH"
    else:
        raise AssertionError("fake DOCX must be rejected")


def test_upload_parent_defers_docx_structure_validation_to_worker(monkeypatch):
    output = BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("_rels/.rels", b"<Relationships/>")
        archive.writestr("word/document.xml", b"<w:document/>")
        archive.writestr("word/media/bomb.bin", b"0" * 200_000)
    payload = output.getvalue()
    observed = {}

    def fake_isolated(kind, raw, filename, **kwargs):
        observed.update(kind=kind, raw=raw, filename=filename, kwargs=kwargs)
        return {"title": "isolated", "text": "worker validated"}

    monkeypatch.setattr(tracker, "parse_document_isolated", fake_isolated)
    upload = FileStorage(stream=BytesIO(payload), filename="report.docx")

    result = tracker._extract_file_text(upload)

    assert result["body"] == "worker validated"
    assert observed["kind"] == "docx"
    assert observed["raw"] == payload


def test_upload_parser_timeout_has_stable_error(monkeypatch):
    monkeypatch.setattr(
        tracker,
        "parse_document_isolated",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            tracker.IsolatedDocumentParseError(
                "DOCUMENT_PARSE_TIMEOUT", "terminated"
            )
        ),
    )

    try:
        tracker._run_upload_parser("docx", b"payload", "slow.docx", timeout=0.01)
    except UploadValidationError as exc:
        assert exc.code == "UPLOAD_PARSE_TIMEOUT"
    else:
        raise AssertionError("parse timeout must be rejected")


def test_import_file_returns_structured_magic_error(monkeypatch):
    monkeypatch.setitem(tracker.AI_CONFIG, "api_key", "session-test-key")
    client = tracker.app.test_client()
    client.set_cookie(tracker.CSRF_COOKIE, "csrf-upload")

    response = client.post(
        "/api/brief/import_file",
        headers={tracker.CSRF_HEADER: "csrf-upload"},
        data={
            "source": "test source",
            "pub_date": "2026-08-31",
            "file": (BytesIO(b"not-a-docx"), "fake.docx"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["code"] == "DOCX_MAGIC_MISMATCH"
    assert payload["retryable"] is False
    assert payload["request_id"] == response.headers["X-Request-ID"]


def test_import_file_parser_queue_full_returns_retryable_service_error(monkeypatch):
    monkeypatch.setitem(tracker.AI_CONFIG, "api_key", "session-test-key")
    monkeypatch.setattr(
        tracker,
        "validate_upload_envelope",
        lambda *args, **kwargs: SimpleNamespace(kind="docx"),
    )
    monkeypatch.setattr(
        tracker,
        "parse_document_isolated",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            tracker.IsolatedDocumentParseError(
                "DOCUMENT_PARSE_QUEUE_FULL",
                "文档解析队列已满，请稍后重试",
                details={"retry_after": 5},
            )
        ),
    )
    client = tracker.app.test_client()
    client.set_cookie(tracker.CSRF_COOKIE, "csrf-upload")

    response = client.post(
        "/api/brief/import_file",
        headers={tracker.CSRF_HEADER: "csrf-upload"},
        data={
            "source": "test source",
            "pub_date": "2026-08-31",
            "file": (BytesIO(b"PK\x03\x04safe-envelope"), "safe.docx"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "5"
    payload = response.get_json()
    assert payload["code"] == "DOCUMENT_PARSE_QUEUE_FULL"
    assert payload["retryable"] is True


def test_upload_parser_isolation_failure_is_not_downgraded_to_validation(monkeypatch):
    monkeypatch.setattr(
        tracker,
        "parse_document_isolated",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            tracker.IsolatedDocumentParseError(
                "DOCUMENT_PARSER_ISOLATION_FAILED", "隔离环境不可用"
            )
        ),
    )

    with pytest.raises(tracker.IsolatedDocumentParseError) as caught:
        tracker._run_upload_parser("docx", b"payload", "safe.docx")

    assert caught.value.code == "DOCUMENT_PARSER_ISOLATION_FAILED"
