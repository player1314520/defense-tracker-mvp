# -*- coding: utf-8 -*-
"""Regression contract for the PostgreSQL push-event block label."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BROKEN_MIGRATION = (
    ROOT
    / "supabase"
    / "migrations"
    / "202607300019_v9_sync_ciphertext_constraints.sql"
)
FIX_MIGRATION = (
    ROOT
    / "supabase"
    / "migrations"
    / "202607300020_v9_push_runtime_fix.sql"
)


def _function(source: str) -> str:
    start = source.index(
        "create or replace function public.push_record_event(p_event jsonb)"
    )
    end = min(
        source.find(marker, start)
        for marker in (
            "\ncreate or replace function public.pull_sync_events(",
            "\nrevoke all on function public.push_record_event(jsonb)",
        )
        if source.find(marker, start) >= 0
    )
    return source[start:end]


def _compact(value: str) -> str:
    return " ".join(value.lower().split())


def test_runtime_fix_labels_the_plpgsql_block_before_qualifying_local_event_id():
    source = FIX_MIGRATION.read_text(encoding="utf-8").lower()
    function = _function(source)

    assert "<<push_record_event_block>>" in function
    assert (
        "where e.event_id = push_record_event_block.event_id"
        in function
    )
    assert "push_record_event.event_id" not in function


def test_runtime_fix_preserves_019_push_semantics_except_for_block_label():
    broken = _function(BROKEN_MIGRATION.read_text(encoding="utf-8"))
    expected = broken.replace(
        "as $$\ndeclare",
        "as $$\n<<push_record_event_block>>\ndeclare",
        1,
    ).replace(
        "push_record_event.event_id",
        "push_record_event_block.event_id",
    )
    fixed = _function(FIX_MIGRATION.read_text(encoding="utf-8"))

    assert _compact(fixed) == _compact(expected)


def test_runtime_fix_is_transactional_and_restores_authenticated_only_grant():
    source = _compact(FIX_MIGRATION.read_text(encoding="utf-8"))

    assert source.startswith("-- ")
    assert " begin; " in f" {source} "
    assert source.endswith("commit;")
    assert (
        "revoke all on function public.push_record_event(jsonb) "
        "from public, anon, authenticated;"
    ) in source
    assert (
        "grant execute on function public.push_record_event(jsonb) "
        "to authenticated;"
    ) in source
