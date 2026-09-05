# -*- coding: utf-8 -*-
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import sqlite3
import threading

import pytest
from flask import Flask

import user_state


@pytest.fixture()
def state_db(tmp_path, monkeypatch):
    database = tmp_path / "user_state.sqlite3"
    monkeypatch.setattr(user_state, "USER_STATE_DB_FILE", str(database))
    user_state.init_user_state_db()
    return database


def test_state_schema_revision_and_legacy_replace_are_persistent(state_db):
    initial = user_state.get_user_state()
    assert initial["schema_version"] == user_state.USER_STATE_SCHEMA_VERSION
    assert initial["revision"] == 0
    assert initial["brief_results"] == []

    replaced = user_state.replace_brief_results_legacy(
        [{"id": "brief-1", "brief": "first"}], expected_revision=0
    )
    assert replaced["revision"] == 1
    assert replaced["brief_results"] == [{"id": "brief-1", "brief": "first"}]

    user_state.init_user_state_db()
    reopened = user_state.get_user_state()
    assert reopened == replaced
    assert user_state.get_server_migration_version() == user_state.USER_STATE_SCHEMA_VERSION
    with sqlite3.connect(state_db) as conn:
        versions = [
            row[0]
            for row in conn.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            )
        ]
    assert versions == list(range(1, user_state.USER_STATE_SCHEMA_VERSION + 1))


def test_server_migration_imports_the_legacy_brief_blob(tmp_path, monkeypatch):
    database = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(database) as conn:
        conn.execute(
            "CREATE TABLE kv(key TEXT PRIMARY KEY, value_json TEXT NOT NULL, updated_at TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO kv(key,value_json,updated_at) VALUES('briefResults',?,?)",
            (json.dumps([{"id": "legacy-1", "brief": "kept"}]), "legacy-time"),
        )

    monkeypatch.setattr(user_state, "USER_STATE_DB_FILE", str(database))
    user_state.init_user_state_db()

    assert user_state.get_user_state() == {
        "schema_version": user_state.USER_STATE_SCHEMA_VERSION,
        "revision": 0,
        "brief_results": [{"id": "legacy-1", "brief": "kept"}],
    }


def test_item_upsert_rejects_stale_expected_revision_without_mutation(state_db):
    first = user_state.upsert_brief_result(
        {"id": "brief-1", "brief": "first"}, expected_revision=0
    )

    with pytest.raises(user_state.StateStoreError) as caught:
        user_state.upsert_brief_result(
            {"id": "brief-2", "brief": "second"}, expected_revision=0
        )

    assert caught.value.code == "REVISION_CONFLICT"
    assert caught.value.details == {"expected_revision": 0, "current_revision": 1}
    assert user_state.get_user_state() == first


def test_http_if_match_returns_stable_conflict_and_etag(state_db, monkeypatch):
    app = Flask(__name__)
    monkeypatch.setattr(user_state, "_auth_check", None)
    app.register_blueprint(user_state.user_state_bp)
    client = app.test_client()

    created = client.put(
        "/api/userdata/brief-results/brief-1",
        headers={"If-Match": '"0"'},
        json={"item": {"id": "ignored", "brief": "first"}},
    )
    assert created.status_code == 200
    assert created.headers["ETag"] == '"1"'

    conflict = client.put(
        "/api/userdata/brief-results/brief-2",
        headers={"If-Match": '"0"'},
        json={"item": {"id": "brief-2", "brief": "second"}},
    )
    assert conflict.status_code == 409
    payload = conflict.get_json()
    assert payload == {
        "error": "状态已被其他窗口更新",
        "code": "REVISION_CONFLICT",
        "request_id": payload["request_id"],
        "retryable": True,
        "details": {"expected_revision": 0, "current_revision": 1},
    }
    assert conflict.headers["X-Request-ID"] == payload["request_id"]


def test_new_item_write_requires_if_match_header_even_when_body_has_revision(
    state_db, monkeypatch
):
    app = Flask(__name__)
    monkeypatch.setattr(user_state, "_auth_check", None)
    app.register_blueprint(user_state.user_state_bp)

    response = app.test_client().put(
        "/api/userdata/brief-results/brief-1",
        json={"item": {"brief": "must not be written"}, "expected_revision": 0},
    )

    assert response.status_code == 428
    payload = response.get_json()
    assert payload == {
        "error": "缺少 If-Match 头",
        "code": "PRECONDITION_REQUIRED",
        "request_id": payload["request_id"],
        "retryable": False,
        "details": {"header": "If-Match"},
    }
    assert response.headers["X-Request-ID"] == payload["request_id"]
    assert user_state.get_user_state()["brief_results"] == []


def test_bootstrap_returns_schema_revision_state_and_safe_config_summary(
    state_db, monkeypatch
):
    app = Flask(__name__)
    monkeypatch.setattr(user_state, "_auth_check", None)
    monkeypatch.setattr(
        user_state,
        "_bootstrap_config_provider",
        lambda: {
            "version": "9.0.0-rc.1",
            "ai": {"enabled": True, "model": "safe-model"},
        },
        raising=False,
    )
    app.register_blueprint(user_state.user_state_bp)

    response = app.test_client().get("/api/userdata/bootstrap")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["schema_version"] == user_state.USER_STATE_SCHEMA_VERSION
    assert payload["revision"] == 0
    assert payload["brief_results"] == []
    assert payload["config"] == {
        "version": "9.0.0-rc.1",
        "ai": {"enabled": True, "model": "safe-model"},
    }
    assert response.headers["ETag"] == '"0"'


def test_legacy_all_reads_item_store_and_is_marked_deprecated(state_db, monkeypatch):
    user_state.upsert_brief_result(
        {"id": "canonical", "brief": "kept"}, expected_revision=0
    )
    with sqlite3.connect(state_db) as conn:
        conn.execute(
            "UPDATE kv SET value_json=? WHERE key='briefResults'",
            (json.dumps([{"id": "stale", "brief": "must not leak"}]),),
        )

    app = Flask(__name__)
    monkeypatch.setattr(user_state, "_auth_check", None)
    app.register_blueprint(user_state.user_state_bp)
    response = app.test_client().get("/api/userdata/all")

    assert response.status_code == 200
    assert response.get_json()["brief_results"] == [
        {"id": "canonical", "brief": "kept"}
    ]
    assert response.headers["Deprecation"] == "true"
    assert response.headers["Link"] == (
        '</api/userdata/bootstrap>; rel="successor-version"'
    )


def test_two_windows_upsert_different_items_without_lost_update(state_db):
    barrier = threading.Barrier(2)

    def add_item(item_id):
        barrier.wait()
        return user_state.upsert_brief_result(
            {"id": item_id, "brief": item_id}, expected_revision=None
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(add_item, ("brief-a", "brief-b")))

    current = user_state.get_user_state()
    assert current["revision"] == 2
    assert {item["id"] for item in current["brief_results"]} == {
        "brief-a",
        "brief-b",
    }
    assert sorted(result["revision"] for result in results) == [1, 2]


def test_delete_one_requires_current_revision_and_preserves_other_items(state_db):
    first = user_state.upsert_brief_result(
        {"id": "brief-a", "brief": "first"}, expected_revision=0
    )
    second = user_state.upsert_brief_result(
        {"id": "brief-b", "brief": "second"},
        expected_revision=first["revision"],
    )

    with pytest.raises(user_state.StateStoreError) as caught:
        user_state.delete_brief_results(["brief-a"], expected_revision=1)

    assert caught.value.code == "REVISION_CONFLICT"
    assert user_state.get_user_state() == second

    deleted = user_state.delete_brief_results(
        ["brief-a"], expected_revision=second["revision"]
    )
    assert deleted["revision"] == 3
    assert deleted["brief_results"] == [{"id": "brief-b", "brief": "second"}]


def test_clear_snapshot_does_not_delete_item_added_by_another_window(state_db):
    first = user_state.upsert_brief_result(
        {"id": "old-a", "brief": "a"}, expected_revision=0
    )
    second = user_state.upsert_brief_result(
        {"id": "old-b", "brief": "b"}, expected_revision=first["revision"]
    )
    concurrent = user_state.upsert_brief_result(
        {"id": "new-window", "brief": "kept"},
        expected_revision=second["revision"],
    )

    with pytest.raises(user_state.StateStoreError) as caught:
        user_state.delete_brief_results(
            ["old-a", "old-b"], expected_revision=second["revision"]
        )
    assert caught.value.code == "REVISION_CONFLICT"

    cleared = user_state.delete_brief_results(
        ["old-a", "old-b"], expected_revision=concurrent["revision"]
    )
    assert cleared["brief_results"] == [{"id": "new-window", "brief": "kept"}]


def test_http_delete_one_and_snapshot_clear_return_updated_etag(state_db, monkeypatch):
    app = Flask(__name__)
    monkeypatch.setattr(user_state, "_auth_check", None)
    app.register_blueprint(user_state.user_state_bp)
    client = app.test_client()

    created_a = client.put(
        "/api/userdata/brief-results/brief-a",
        headers={"If-Match": '"0"'},
        json={"item": {"brief": "a"}},
    )
    created_b = client.put(
        "/api/userdata/brief-results/brief-b",
        headers={"If-Match": created_a.headers["ETag"]},
        json={"item": {"brief": "b"}},
    )

    deleted = client.delete(
        "/api/userdata/brief-results/brief-a",
        headers={"If-Match": created_b.headers["ETag"]},
    )
    assert deleted.status_code == 200
    assert deleted.headers["ETag"] == '"3"'
    assert [item["id"] for item in deleted.get_json()["brief_results"]] == ["brief-b"]

    cleared = client.delete(
        "/api/userdata/brief-results",
        headers={"If-Match": deleted.headers["ETag"]},
        json={"item_ids": ["brief-b"]},
    )
    assert cleared.status_code == 200
    assert cleared.headers["ETag"] == '"4"'
    assert cleared.get_json()["brief_results"] == []


def test_runtime_kv_is_namespaced_and_json_persistent(state_db):
    user_state.set_runtime_value("rss", "feed-a", {"enabled": True})
    user_state.set_runtime_value("budget", "feed-a", {"enabled": False})

    assert user_state.get_runtime_value("rss", "feed-a") == {"enabled": True}
    assert user_state.get_runtime_value("budget", "feed-a") == {"enabled": False}
    assert user_state.get_runtime_value("rss", "missing", default={"missing": True}) == {
        "missing": True
    }


def test_budget_reservation_is_transactional_and_never_exceeds_limit(state_db):
    barrier = threading.Barrier(2)

    def reserve(reservation_id):
        barrier.wait()
        try:
            return user_state.reserve_daily_budget(
                namespace="ai",
                budget_date="2026-08-31",
                amount=6,
                daily_limit=10,
                reservation_id=reservation_id,
            )
        except user_state.StateStoreError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(reserve, ("request-a", "request-b")))

    assert sum(isinstance(result, dict) for result in results) == 1
    assert results.count("BUDGET_EXCEEDED") == 1
    ledger = user_state.get_daily_budget("ai", "2026-08-31")
    assert ledger["reserved"] == 6
    assert ledger["confirmed"] == 0
    assert ledger["reserved"] + ledger["confirmed"] <= ledger["daily_limit"]

    winning = next(result for result in results if isinstance(result, dict))
    confirmed = user_state.confirm_daily_budget(winning["reservation_id"])
    assert confirmed["reserved"] == 0
    assert confirmed["confirmed"] == 6
    assert user_state.release_daily_budget(winning["reservation_id"]) == confirmed


def test_reserved_budget_can_be_released_and_reused(state_db):
    user_state.reserve_daily_budget("ai", "2026-08-31", 10, 10, "request-a")
    released = user_state.release_daily_budget("request-a")
    assert released["reserved"] == 0
    assert released["confirmed"] == 0

    reused = user_state.reserve_daily_budget("ai", "2026-08-31", 10, 10, "request-b")
    assert reused["reserved"] == 10


def test_budget_confirmation_can_settle_below_reserved_amount(state_db):
    user_state.reserve_daily_budget(
        "ai_tokens", "2026-08-31", 100, 1000, "request-partial"
    )

    settled = user_state.confirm_daily_budget("request-partial", amount=23)

    assert settled["reserved"] == 0
    assert settled["confirmed"] == 23


def test_startup_releases_only_reservations_from_previous_process_lease(
    state_db, monkeypatch
):
    monkeypatch.setattr(user_state, "_BUDGET_LEASE_ID", "previous-process")
    user_state.reserve_daily_budget("ai", "2026-08-31", 4, 10, "abandoned")
    user_state.reserve_daily_budget("ai", "2026-08-31", 3, 10, "confirmed")
    user_state.confirm_daily_budget("confirmed")

    monkeypatch.setattr(user_state, "_BUDGET_LEASE_ID", "restarted-process")
    recovered = user_state.recover_abandoned_budget_reservations()

    assert recovered == {"reservations": 1, "amount": 4}
    ledger = user_state.get_daily_budget("ai", "2026-08-31")
    assert ledger["reserved"] == 0
    assert ledger["confirmed"] == 3
    assert user_state.recover_abandoned_budget_reservations() == {
        "reservations": 0,
        "amount": 0,
    }

    reused = user_state.reserve_daily_budget("ai", "2026-08-31", 7, 10, "after-restart")
    assert reused["reserved"] == 7
    assert reused["confirmed"] == 3


def test_rss_last_good_snapshot_tracks_failure_and_freshness(state_db):
    fetched_at = datetime(2026, 8, 31, 0, 0, tzinfo=timezone.utc)
    user_state.save_rss_last_good(
        "feed-a", [{"id": "article-1"}], fetched_at=fetched_at
    )

    fresh = user_state.get_rss_runtime_status(
        "feed-a",
        now=fetched_at + timedelta(seconds=30),
        fresh_for_seconds=60,
        offline_after_seconds=300,
    )
    assert fresh["status"] == "fresh"
    assert fresh["snapshot"] == [{"id": "article-1"}]
    assert fresh["failure"] is None

    user_state.record_rss_failure(
        "feed-a", "HTTP_TIMEOUT", failed_at=fetched_at + timedelta(seconds=90)
    )
    stale = user_state.get_rss_runtime_status(
        "feed-a",
        now=fetched_at + timedelta(seconds=120),
        fresh_for_seconds=60,
        offline_after_seconds=300,
    )
    assert stale["status"] == "stale"
    assert stale["failure"]["code"] == "HTTP_TIMEOUT"
    assert stale["failure"]["count"] == 1

    offline = user_state.get_rss_runtime_status(
        "feed-a",
        now=fetched_at + timedelta(seconds=301),
        fresh_for_seconds=60,
        offline_after_seconds=300,
    )
    assert offline["status"] == "offline"


def test_rss_without_last_good_is_offline(state_db):
    status = user_state.get_rss_runtime_status("missing-feed")
    assert status == {
        "feed_id": "missing-feed",
        "status": "offline",
        "snapshot": None,
        "fetched_at": None,
        "failure": None,
    }
