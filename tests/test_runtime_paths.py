# -*- coding: utf-8 -*-
"""P0 runtime layout and non-destructive legacy migration tests."""
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest


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
    assert str(legacy) not in manifest
    assert '"source_kind": "legacy-runtime"' in manifest
    assert ".access_token" in manifest


def test_supabase_config_selection_uses_only_fixed_runtime_config(tmp_path):
    import state

    config_dir = tmp_path / "runtime" / "config"
    configured = config_dir / ".supabase_v9_config.json"
    ignored = tmp_path / "explicit" / ".supabase_v9_config.json"
    for candidate in (configured, ignored):
        candidate.parent.mkdir(parents=True, exist_ok=True)
        candidate.write_text("{}", encoding="utf-8")
    environ = {
        "DEFENSE_TRACKER_SUPABASE_CONFIG": str(ignored),
        "LOCALAPPDATA": str(tmp_path / "local-app-data"),
    }

    assert state.resolve_supabase_config_path(
        environ=environ,
        config_dir=config_dir,
    ) == configured.absolute()
    configured.unlink()
    assert state.resolve_supabase_config_path(
        environ=environ,
        config_dir=config_dir,
    ) is None


def test_supabase_config_selection_rejects_linked_config(tmp_path):
    import state

    config_dir = tmp_path / "runtime" / "config"
    config_dir.mkdir(parents=True)
    outside = tmp_path / ".supabase_v9_config.json"
    outside.write_text("{}", encoding="utf-8")
    linked = config_dir / ".supabase_v9_config.json"
    try:
        linked.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(RuntimeError, match="unsafe legacy Supabase vault entry"):
        state.resolve_supabase_config_path(environ={}, config_dir=config_dir)


def test_supabase_vault_migration_rejects_noncanonical_config_name(tmp_path):
    import state

    config_path = tmp_path / "config" / "attacker-selected.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("{}", encoding="utf-8")

    with pytest.raises(RuntimeError, match="unsafe legacy Supabase vault entry"):
        state.migrate_legacy_supabase_vault(
            config_path,
            tmp_path / "canonical-vault",
        )


def test_supabase_vault_migration_copies_only_vault_files_and_keeps_sources(
    tmp_path,
):
    import state

    config_path = (
        tmp_path / "selected-runtime" / "config" / ".supabase_v9_config.json"
    )
    config_path.parent.mkdir(parents=True)
    config_path.write_text("{}", encoding="utf-8")
    legacy_vault = config_path.parent.parent / "vault"
    legacy_vault.mkdir()
    source_payloads = {
        "supabase-session.vault": b"legacy-session",
        "supabase-pkce.vault": b"legacy-pkce",
    }
    for filename, payload in source_payloads.items():
        (legacy_vault / filename).write_bytes(payload)
    (legacy_vault / "unrelated-secret.txt").write_bytes(b"must-not-copy")
    canonical_vault = tmp_path / "canonical-vault"

    result = state.migrate_legacy_supabase_vault(
        config_path,
        canonical_vault,
    )

    assert result == {"copied": 2, "skipped_existing": 0}
    for filename, payload in source_payloads.items():
        assert (canonical_vault / filename).read_bytes() == payload
        assert (legacy_vault / filename).read_bytes() == payload
    assert not (canonical_vault / "unrelated-secret.txt").exists()
    assert not list(canonical_vault.glob("*.migrating"))
    assert str(tmp_path) not in repr(result)

    (legacy_vault / "supabase-session.vault").write_bytes(b"newer-legacy")
    repeated = state.migrate_legacy_supabase_vault(
        config_path,
        canonical_vault,
    )
    assert repeated == {"copied": 0, "skipped_existing": 2}
    assert (
        canonical_vault / "supabase-session.vault"
    ).read_bytes() == b"legacy-session"


def test_supabase_vault_migration_refuses_symlink_source(
    tmp_path,
):
    import state

    config_path = tmp_path / "selected" / "config" / ".supabase_v9_config.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("{}", encoding="utf-8")
    legacy_vault = config_path.parent.parent / "vault"
    legacy_vault.mkdir()
    outside = tmp_path / "outside.vault"
    outside.write_bytes(b"outside")
    linked = legacy_vault / "supabase-session.vault"
    try:
        linked.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(RuntimeError, match="unsafe legacy Supabase vault entry"):
        state.migrate_legacy_supabase_vault(
            config_path,
            tmp_path / "canonical",
        )
    assert outside.read_bytes() == b"outside"


def test_supabase_vault_migration_refuses_non_regular_source(tmp_path):
    import state

    config_path = tmp_path / "selected" / "config" / ".supabase_v9_config.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("{}", encoding="utf-8")
    legacy_vault = config_path.parent.parent / "vault"
    legacy_vault.mkdir()
    (legacy_vault / "supabase-session.vault").mkdir()

    with pytest.raises(RuntimeError, match="unsafe legacy Supabase vault entry"):
        state.migrate_legacy_supabase_vault(
            config_path,
            tmp_path / "canonical",
        )


def test_supabase_vault_migration_refuses_windows_reparse_file(
    tmp_path,
    monkeypatch,
):
    import state

    config_path = tmp_path / "selected" / "config" / ".supabase_v9_config.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("{}", encoding="utf-8")
    legacy_vault = config_path.parent.parent / "vault"
    legacy_vault.mkdir()
    source = legacy_vault / "supabase-session.vault"
    source.write_bytes(b"legacy")
    real_lstat = Path.lstat

    def reparse_lstat(path):
        current = real_lstat(path)
        if path == source:
            return SimpleNamespace(
                st_mode=stat.S_IFREG | 0o600,
                st_file_attributes=0x400,
            )
        return current

    monkeypatch.setattr(Path, "lstat", reparse_lstat)

    with pytest.raises(RuntimeError, match="unsafe legacy Supabase vault entry"):
        state.migrate_legacy_supabase_vault(
            config_path,
            tmp_path / "canonical",
        )


def test_supabase_vault_atomic_publish_never_overwrites_racing_destination(
    tmp_path,
    monkeypatch,
):
    import state

    config_path = tmp_path / "selected" / "config" / ".supabase_v9_config.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("{}", encoding="utf-8")
    legacy_vault = config_path.parent.parent / "vault"
    legacy_vault.mkdir()
    (legacy_vault / "supabase-session.vault").write_bytes(b"legacy")
    canonical = tmp_path / "canonical"

    def race_winner(_source, destination):
        Path(destination).write_bytes(b"winner")
        raise FileExistsError

    monkeypatch.setattr(state.os, "link", race_winner)

    result = state.migrate_legacy_supabase_vault(config_path, canonical)

    assert result == {"copied": 0, "skipped_existing": 1}
    assert (canonical / "supabase-session.vault").read_bytes() == b"winner"
    assert (legacy_vault / "supabase-session.vault").read_bytes() == b"legacy"
    assert not list(canonical.glob("*.migrating"))


def test_supabase_vault_migration_redacts_private_paths_from_os_errors(
    tmp_path,
    monkeypatch,
):
    import state

    config_path = tmp_path / "selected" / "config" / ".supabase_v9_config.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("{}", encoding="utf-8")
    legacy_vault = config_path.parent.parent / "vault"
    legacy_vault.mkdir()
    source = legacy_vault / "supabase-session.vault"
    source.write_bytes(b"legacy")

    real_open = state.os.open

    def deny_open(path, flags, *args):
        if Path(path) == source:
            raise PermissionError(13, "synthetic denial", str(source))
        return real_open(path, flags, *args)

    monkeypatch.setattr(state.os, "open", deny_open)

    with pytest.raises(RuntimeError) as failure:
        state.migrate_legacy_supabase_vault(
            config_path,
            tmp_path / "canonical",
        )
    assert str(tmp_path) not in str(failure.value)


def test_supabase_vault_migration_does_not_resurrect_cleared_session(
    tmp_path,
):
    import state

    config_path = tmp_path / "selected" / "config" / ".supabase_v9_config.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("{}", encoding="utf-8")
    legacy_vault = config_path.parent.parent / "vault"
    legacy_vault.mkdir()
    for filename in ("supabase-session.vault", "supabase-pkce.vault"):
        (legacy_vault / filename).write_bytes(f"legacy-{filename}".encode())
    canonical = tmp_path / "canonical"
    assert state.migrate_legacy_supabase_vault(
        config_path,
        canonical,
    ) == {"copied": 2, "skipped_existing": 0}

    for filename in ("supabase-session.vault", "supabase-pkce.vault"):
        (canonical / filename).unlink()

    repeated = state.migrate_legacy_supabase_vault(config_path, canonical)

    assert repeated == {"copied": 0, "skipped_existing": 0}
    for filename in ("supabase-session.vault", "supabase-pkce.vault"):
        assert not (canonical / filename).exists()
        assert (legacy_vault / filename).is_file()

