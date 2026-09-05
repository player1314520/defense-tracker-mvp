# -*- coding: utf-8 -*-
"""Phase 0.5 AI 成本闸单测：日调用/日token上限 + kill-switch。"""
import pytest

import app


@pytest.fixture(autouse=True)
def isolated_budget_db(tmp_path, monkeypatch):
    monkeypatch.setattr(
        app.user_state, "USER_STATE_DB_FILE", str(tmp_path / "user_state.sqlite3")
    )
    app.user_state.init_user_state_db()
    _reset_budget()
    _reset_search_budget()


def _reset_budget():
    app._AI_BUDGET.update(date=app._ai_today(), calls=0, tokens=0)


def test_ai_budget_reserve_blocks_after_call_cap(monkeypatch):
    monkeypatch.setattr(app, "AI_DAILY_MAX_CALLS", 3)
    monkeypatch.setattr(app, "AI_DAILY_MAX_TOKENS", 10_000_000)
    monkeypatch.delenv("AI_KILL_SWITCH", raising=False)
    _reset_budget()

    for _ in range(3):
        app._ai_budget_reserve(100)               # 额度内
    with pytest.raises(app.AIBudgetExceeded):
        app._ai_budget_reserve(100)               # 第 4 次超日调用上限
    _reset_budget()


def test_ai_budget_reserve_blocks_on_token_cap(monkeypatch):
    monkeypatch.setattr(app, "AI_DAILY_MAX_CALLS", 1000)
    monkeypatch.setattr(app, "AI_DAILY_MAX_TOKENS", 500)
    monkeypatch.delenv("AI_KILL_SWITCH", raising=False)
    _reset_budget()

    app._ai_budget_reserve(500)                   # 用满 token 预算
    with pytest.raises(app.AIBudgetExceeded):
        app._ai_budget_reserve(1)                 # 已达 token 上限
    _reset_budget()


def test_ai_budget_kill_switch(monkeypatch):
    monkeypatch.setattr(app, "AI_DAILY_MAX_CALLS", 1000)
    monkeypatch.setattr(app, "AI_DAILY_MAX_TOKENS", 10_000_000)
    monkeypatch.setenv("AI_KILL_SWITCH", "1")
    _reset_budget()

    with pytest.raises(app.AIBudgetExceeded):
        app._ai_budget_reserve(1)                 # kill-switch 直接拦截
    monkeypatch.delenv("AI_KILL_SWITCH", raising=False)
    _reset_budget()


def test_ai_budget_snapshot_shape(monkeypatch):
    monkeypatch.delenv("AI_KILL_SWITCH", raising=False)
    _reset_budget()

    snap = app._ai_budget_snapshot()
    assert set(snap) >= {"date", "calls", "max_calls", "tokens", "max_tokens", "kill_switch"}
    assert snap["calls"] == 0
    assert snap["kill_switch"] is False


def test_ai_budget_survives_memory_reset_and_can_release_or_confirm(monkeypatch):
    monkeypatch.setattr(app, "AI_DAILY_MAX_CALLS", 5)
    monkeypatch.setattr(app, "AI_DAILY_MAX_TOKENS", 1000)
    reservations = app._ai_budget_reserve(100)
    _reset_budget()

    persisted = app._ai_budget_snapshot()
    assert persisted["calls"] == 1
    assert persisted["tokens"] == 100

    app._ai_budget_release(reservations)
    assert app._ai_budget_snapshot()["calls"] == 0
    confirmed = app._ai_budget_reserve(200)
    app._ai_budget_confirm(confirmed)
    assert app._ai_budget_snapshot()["calls"] == 1
    assert app._ai_budget_snapshot()["tokens"] == 200


def test_failed_ai_request_releases_reserved_budget(monkeypatch):
    import requests

    monkeypatch.setattr(app, "AI_DAILY_MAX_CALLS", 5)
    monkeypatch.setattr(app, "AI_DAILY_MAX_TOKENS", 1000)
    monkeypatch.setitem(app.AI_CONFIG, "api_key", "session-test-key")
    monkeypatch.setitem(app.AI_CONFIG, "provider", "deepseek")
    monkeypatch.setitem(app.AI_CONFIG, "model", "deepseek-v4-flash")
    monkeypatch.setitem(
        app.AI_CONFIG,
        "base_url",
        "https://api.deepseek.com",
    )
    monkeypatch.setitem(app.AI_CONFIG, "max_tokens", 100)
    monkeypatch.setattr(
        app.search_adapters,
        "safe_request",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            requests.ConnectionError("offline")
        ),
    )

    with pytest.raises(requests.ConnectionError):
        app._call_ai([{"role": "user", "content": "test"}])

    assert app._ai_budget_snapshot()["calls"] == 0
    assert app._ai_budget_snapshot()["tokens"] == 0


def test_ai_budget_includes_prompt_tokens_before_transport(monkeypatch):
    monkeypatch.setattr(app, "AI_DAILY_MAX_CALLS", 5)
    monkeypatch.setattr(app, "AI_DAILY_MAX_TOKENS", 200)
    monkeypatch.setitem(app.AI_CONFIG, "api_key", "session-test-key")
    monkeypatch.setitem(app.AI_CONFIG, "provider", "deepseek")
    monkeypatch.setitem(app.AI_CONFIG, "model", "deepseek-v4-flash")
    monkeypatch.setitem(app.AI_CONFIG, "base_url", "https://api.deepseek.com")
    monkeypatch.setitem(app.AI_CONFIG, "max_tokens", 20)
    called = []
    monkeypatch.setattr(
        app.search_adapters,
        "safe_request",
        lambda *args, **kwargs: called.append((args, kwargs)),
    )

    with pytest.raises(app.AIBudgetExceeded):
        app._call_ai([{"role": "user", "content": "A" * 1000}])

    assert called == []
    assert app._ai_budget_snapshot()["calls"] == 0
    assert app._ai_budget_snapshot()["tokens"] == 0


def test_ai_budget_settles_to_provider_usage_when_available(monkeypatch):
    class Response:
        status_code = 200

        def raise_for_status(self):
            return None

        def close(self):
            return None

        def json(self):
            return {
                "choices": [{"message": {"content": "ok"}}],
                "usage": {
                    "prompt_tokens": 7,
                    "completion_tokens": 5,
                    "total_tokens": 12,
                },
            }

    monkeypatch.setattr(app, "AI_DAILY_MAX_CALLS", 5)
    monkeypatch.setattr(app, "AI_DAILY_MAX_TOKENS", 1000)
    monkeypatch.setitem(app.AI_CONFIG, "api_key", "session-test-key")
    monkeypatch.setitem(app.AI_CONFIG, "provider", "deepseek")
    monkeypatch.setitem(app.AI_CONFIG, "model", "deepseek-v4-flash")
    monkeypatch.setitem(app.AI_CONFIG, "base_url", "https://api.deepseek.com")
    monkeypatch.setitem(app.AI_CONFIG, "max_tokens", 100)
    monkeypatch.setattr(
        app.search_adapters, "safe_request", lambda *args, **kwargs: Response()
    )

    assert app._call_ai([{"role": "user", "content": "small prompt"}]) == "ok"
    assert app._ai_budget_snapshot()["calls"] == 1
    assert app._ai_budget_snapshot()["tokens"] == 12


def _reset_search_budget():
    app._SEARCH_BUDGET.update(date=app._ai_today(), calls=0)


def test_search_budget_reserve_blocks_over_cap(monkeypatch):
    monkeypatch.setattr(app, "SEARCH_DAILY_MAX_CALLS", 5)
    monkeypatch.delenv("SEARCH_KILL_SWITCH", raising=False)
    _reset_search_budget()

    app._search_budget_reserve(3)                 # 3
    app._search_budget_reserve(2)                 # 5 == 上限，仍允许
    with pytest.raises(app.SearchBudgetExceeded):
        app._search_budget_reserve(1)             # 6 > 5，拦截
    _reset_search_budget()


def test_search_kill_switch(monkeypatch):
    monkeypatch.setattr(app, "SEARCH_DAILY_MAX_CALLS", 1000)
    monkeypatch.setenv("SEARCH_KILL_SWITCH", "1")
    _reset_search_budget()

    with pytest.raises(app.SearchBudgetExceeded):
        app._search_budget_reserve(1)             # kill-switch 直接拦截
    monkeypatch.delenv("SEARCH_KILL_SWITCH", raising=False)
    _reset_search_budget()
