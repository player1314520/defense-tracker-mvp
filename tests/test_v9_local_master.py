# -*- coding: utf-8 -*-
from pathlib import Path
import zipfile


def test_legacy_v9_master_key_is_copied_to_vault_not_config(tmp_path):
    import state

    legacy = tmp_path / "legacy"
    legacy.mkdir()
    (legacy / ".v9_local_master.key").write_bytes(b"x" * 32)
    runtime = tmp_path / "runtime"
    layout = state.RuntimeLayout(
        root=runtime,
        config=runtime / "config",
        data=runtime / "data",
        vault=runtime / "vault",
        logs=runtime / "logs",
    )

    result = state.migrate_legacy_runtime(legacy, layout)

    assert (layout.vault / ".v9_local_master.key").read_bytes() == b"x" * 32
    assert not (layout.config / ".v9_local_master.key").exists()
    assert result["copied"] == 1


def test_existing_runtime_config_master_key_is_migrated_to_vault(tmp_path):
    import state

    legacy = tmp_path / "legacy"
    legacy.mkdir()
    runtime = tmp_path / "runtime"
    layout = state.RuntimeLayout(
        root=runtime,
        config=runtime / "config",
        data=runtime / "data",
        vault=runtime / "vault",
        logs=runtime / "logs",
    )
    layout.config.mkdir(parents=True)
    (layout.config / ".v9_local_master.key").write_bytes(b"y" * 32)

    state.migrate_legacy_runtime(legacy, layout)

    assert (layout.vault / ".v9_local_master.key").read_bytes() == b"y" * 32


def test_release_paths_reject_master_key_and_all_key_suffixes(tmp_path):
    from scripts.make_release_zip import should_include

    root = tmp_path / "release"
    root.mkdir()
    master_key = root / ".v9_local_master.key"
    signing_key = root / "unexpected-private.key"
    detached_signature = root / "DefenseTracker.exe.sig"
    for path in (master_key, signing_key, detached_signature):
        path.write_bytes(b"test")

    assert not should_include(master_key, root)
    assert not should_include(signing_key, root)
    assert should_include(detached_signature, root)

    build_script = (
        Path(__file__).resolve().parents[1] / "scripts" / "Build-AndShip.ps1"
    ).read_text(encoding="utf-8")
    assert '".v9_local_master.key"' in build_script
    assert '".key"' in build_script


def test_release_zip_uses_git_tracked_allowlist_and_excludes_private_trees():
    source = (
        Path(__file__).resolve().parents[1] / "scripts" / "make_release_zip.py"
    ).read_text(encoding="utf-8")

    assert '"ls-files", "-z"' in source
    assert '"归档"' in source
    assert '".search_config.json"' in source
    assert '".email_config.json"' in source


def test_release_zip_contains_no_untracked_archive_or_key_files(tmp_path):
    from scripts.make_release_zip import make_release_zip

    project_root = Path(__file__).resolve().parents[1]
    output = tmp_path / "source-release.zip"
    count = make_release_zip(project_root, output)

    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
    assert count == len(names)
    assert not any("归档" in name for name in names)
    assert not any(name.lower().endswith(".key") for name in names)
    assert not any(".v9_local_master.key" in name for name in names)
