# -*- coding: utf-8 -*-
"""Phase 0.5 AI 成本闸单测：日调用/日token上限 + kill-switch。"""
import pytest

import app


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
