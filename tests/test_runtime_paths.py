# -*- coding: utf-8 -*-
"""P0 runtime layout and non-destructive legacy migration tests."""
from pathlib import Path


def test_frozen_windows_layout_uses_local_app_data(tmp_path):
    import state

    layout = state.resolve_runtime_layout(
        frozen=True,
        platform="win32",
        environ={"LOCALAPPDATA": str(tmp_path)},
        project_root=tmp_path / "project",
    )

    root = tmp_path / "DefenseTracker"
    assert layout.root == root
    assert layout.config == root / "config"
    assert layout.data == root / "data"
    assert layout.vault == root / "vault"
    assert layout.logs == root / "logs"


def test_explicit_runtime_home_overrides_platform_default(tmp_path):
    import state

    custom_root = tmp_path / "portable-runtime"
    layout = state.resolve_runtime_layout(
        frozen=True,
        platform="win32",
        environ={
            "LOCALAPPDATA": str(tmp_path / "ignored"),
            "DEFENSE_TRACKER_HOME": str(custom_root),
        },
        project_root=tmp_path / "project",
    )

    assert layout.root == custom_root
    assert layout.config == custom_root / "config"
    assert layout.data == custom_root / "data"
    assert layout.vault == custom_root / "vault"
    assert layout.logs == custom_root / "logs"


def test_source_checkout_keeps_legacy_project_layout(tmp_path):
    import state

    project_root = tmp_path / "project"
    layout = state.resolve_runtime_layout(
        frozen=False,
        platform="win32",
        environ={},
        project_root=project_root,
    )

    assert layout.root == project_root
    assert layout.config == project_root
    assert layout.data == project_root / "data"
    assert layout.vault == project_root / "素材库"
    assert layout.logs == project_root / "logs"


def test_legacy_migration_copies_missing_items_without_overwrite(tmp_path):
    import state

    legacy = tmp_path / "legacy"
    target = tmp_path / "runtime"
    layout = state.RuntimeLayout(
        root=target,
        config=target / "config",
        data=target / "data",
        vault=target / "vault",
        logs=target / "logs",
    )
    legacy.mkdir()
    (legacy / ".ai_config.json").write_text("legacy-secret-value", encoding="utf-8")
    (legacy / ".access_token").write_text("legacy-token-value", encoding="utf-8")
    (legacy / "data").mkdir()
    (legacy / "data" / "user_state.sqlite3").write_bytes(b"legacy-db")
    (legacy / "素材库").mkdir()
    (legacy / "素材库" / "sample.txt").write_text("sample body", encoding="utf-8")

    layout.config.mkdir(parents=True)
    (layout.config / ".ai_config.json").write_text("keep-existing", encoding="utf-8")

    result = state.migrate_legacy_runtime(legacy, layout)

    assert (layout.config / ".ai_config.json").read_text(encoding="utf-8") == "keep-existing"
    assert (layout.config / ".access_token").read_text(encoding="utf-8") == "legacy-token-value"
    assert (layout.data / "user_state.sqlite3").read_bytes() == b"legacy-db"
    assert (layout.vault / "sample.txt").read_text(encoding="utf-8") == "sample body"
    assert result["copied"] == 3
    manifest = Path(result["manifest"]).read_text(encoding="utf-8")
    assert "legacy-token-value" not in manifest
    assert "legacy-secret-value" not in manifest
    assert ".access_token" in manifest

