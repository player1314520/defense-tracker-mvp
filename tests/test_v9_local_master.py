# -*- coding: utf-8 -*-
import os
from pathlib import Path
import subprocess
import time
import zipfile

import pytest


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


def _commit_index(project_root: Path, message: str = "release fixture") -> str:
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=DefenseTracker test",
            "-c",
            "user.email=defense-tracker-test@users.noreply.github.com",
            "commit",
            "-q",
            "-m",
            message,
        ],
        cwd=project_root,
        check=True,
    )
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _release_repo(tmp_path: Path, *extra_files: str) -> tuple[Path, str]:
    import scripts.make_release_zip as release_zip

    project_root = tmp_path / "source"
    project_root.mkdir()
    for relative in release_zip.REQUIRED_RELEASE_FILES | set(extra_files):
        path = project_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("reviewed commit content", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=project_root, check=True)
    subprocess.run(["git", "add", "--", "."], cwd=project_root, check=True)
    return project_root, _commit_index(project_root)


def _archive_member(expected_sha: str, relative: str) -> str:
    return f"DefenseTracker-source-{expected_sha}/{relative}"


def test_release_zip_uses_exact_commit_tree_and_excludes_private_trees():
    source = (
        Path(__file__).resolve().parents[1] / "scripts" / "make_release_zip.py"
    ).read_text(encoding="utf-8")

    assert '"ls-tree"' in source
    assert '"--full-tree"' in source
    assert '"cat-file", "blob"' in source
    assert '"--expected-sha"' in source
    assert '"归档"' in source
    assert '".search_config.json"' in source
    assert '".email_config.json"' in source


def test_release_zip_contains_no_untracked_archive_or_key_files(tmp_path):
    import scripts.make_release_zip as release_zip

    project_root, expected_sha = _release_repo(tmp_path, "README.md")
    (project_root / ".v9_local_master.key").write_text("private", encoding="utf-8")
    (project_root / ".search_config.json").write_text("private", encoding="utf-8")
    archive_dir = project_root / "归档"
    archive_dir.mkdir()
    (archive_dir / "private.txt").write_text("private", encoding="utf-8")
    output = tmp_path / "source-release.zip"

    count = release_zip.make_release_zip(
        project_root, output, expected_sha=expected_sha
    )

    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
    assert count == len(names)
    assert not any("归档" in name for name in names)
    assert not any(name.lower().endswith(".key") for name in names)
    assert not any(".v9_local_master.key" in name for name in names)
    assert any(name.endswith("/protected_secrets.py") for name in names)
    assert any(name.endswith("/pinned_http.py") for name in names)
    assert any(name.endswith("/static/js/credential-notice.js") for name in names)
    assert any(name.endswith("/static/css/credential-notice.css") for name in names)


def test_release_zip_reads_reviewed_commit_despite_staged_and_worktree_divergence(
    tmp_path,
):
    import scripts.make_release_zip as release_zip

    project_root, expected_sha = _release_repo(tmp_path, "docs/tracked.txt")
    (project_root / "docs" / "tracked.txt").write_text(
        "staged content must not ship",
        encoding="utf-8",
    )
    subprocess.run(
        ["git", "add", "--", "docs/tracked.txt"], cwd=project_root, check=True
    )
    (project_root / "docs" / "tracked.txt").write_text(
        "unstaged content must not ship",
        encoding="utf-8",
    )
    output = tmp_path / "source-release.zip"

    release_zip.make_release_zip(project_root, output, expected_sha=expected_sha)

    with zipfile.ZipFile(output) as archive:
        payload = archive.read(_archive_member(expected_sha, "docs/tracked.txt"))
    assert payload == b"reviewed commit content"


def test_release_zip_does_not_probe_missing_required_worktree_file(tmp_path):
    from scripts.make_release_zip import make_release_zip

    project_root, expected_sha = _release_repo(tmp_path)
    (project_root / "protected_secrets.py").unlink()
    output = tmp_path / "source-release.zip"

    make_release_zip(project_root, output, expected_sha=expected_sha)

    with zipfile.ZipFile(output) as archive:
        assert archive.read(
            _archive_member(expected_sha, "protected_secrets.py")
        ) == b"reviewed commit content"


def test_release_zip_refuses_required_runtime_dependency_missing_from_commit(tmp_path):
    from scripts.make_release_zip import REQUIRED_RELEASE_FILES, make_release_zip

    project_root = tmp_path / "source"
    project_root.mkdir()
    for relative in REQUIRED_RELEASE_FILES - {"pinned_http.py"}:
        path = project_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("release fixture", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=project_root, check=True)
    subprocess.run(["git", "add", "--", "."], cwd=project_root, check=True)
    expected_sha = _commit_index(project_root)
    output = tmp_path / "must-not-exist.zip"

    with pytest.raises(RuntimeError, match="pinned_http.py"):
        make_release_zip(project_root, output, expected_sha=expected_sha)

    assert not output.exists()


def test_release_zip_refuses_non_commit_and_unresolvable_expected_sha(tmp_path):
    import scripts.make_release_zip as release_zip

    project_root, expected_sha = _release_repo(tmp_path)
    blob_sha = subprocess.run(
        ["git", "hash-object", "-w", "--stdin"],
        cwd=project_root,
        input=b"not a commit",
        capture_output=True,
        check=True,
    ).stdout.decode("ascii").strip()

    with pytest.raises(RuntimeError, match="full 40-hex"):
        release_zip.validate_expected_commit(project_root, expected_sha[:12])
    with pytest.raises(RuntimeError, match="does not exist"):
        release_zip.validate_expected_commit(project_root, "f" * 40)
    with pytest.raises(RuntimeError, match="not a commit"):
        release_zip.validate_expected_commit(project_root, blob_sha)


def test_release_zip_refuses_commit_symlink_without_reading_worktree(
    monkeypatch,
    tmp_path,
):
    import scripts.make_release_zip as release_zip

    project_root, _original_sha = _release_repo(tmp_path)
    blob = subprocess.run(
        ["git", "hash-object", "-w", "--stdin"],
        cwd=project_root,
        input=b"outside-sensitive-file.txt",
        capture_output=True,
        check=True,
    ).stdout.decode("ascii").strip()
    subprocess.run(
        [
            "git",
            "update-index",
            "--add",
            "--cacheinfo",
            f"120000,{blob},docs/tracked-link.txt",
        ],
        cwd=project_root,
        check=True,
    )
    expected_sha = _commit_index(project_root, "commit unsafe symlink")
    output = tmp_path / "must-not-exist.zip"

    def refuses_worktree_probe(_self):
        raise AssertionError("commit archive reached worktree file probing")

    monkeypatch.setattr(Path, "is_file", refuses_worktree_probe)
    monkeypatch.setattr(Path, "is_symlink", refuses_worktree_probe)

    with pytest.raises(RuntimeError, match="docs/tracked-link.txt"):
        release_zip.make_release_zip(
            project_root, output, expected_sha=expected_sha
        )

    assert not output.exists()


def test_release_zip_ignores_git_replace_objects(tmp_path):
    import scripts.make_release_zip as release_zip

    project_root, expected_sha = _release_repo(tmp_path, "docs/tracked.txt")
    original = subprocess.run(
        ["git", "rev-parse", ":docs/tracked.txt"],
        cwd=project_root,
        capture_output=True,
        check=True,
        text=True,
    ).stdout.strip()
    replacement = subprocess.run(
        ["git", "hash-object", "-w", "--stdin"],
        cwd=project_root,
        input=b"replacement content must not ship",
        capture_output=True,
        check=True,
    ).stdout.decode("ascii").strip()
    subprocess.run(
        ["git", "replace", original, replacement],
        cwd=project_root,
        check=True,
    )
    output = tmp_path / "source-release.zip"

    release_zip.make_release_zip(project_root, output, expected_sha=expected_sha)

    with zipfile.ZipFile(output) as archive:
        payload = archive.read(_archive_member(expected_sha, "docs/tracked.txt"))
    assert payload == b"reviewed commit content"


def test_release_zip_clears_ambient_git_repository_overrides(monkeypatch, tmp_path):
    import scripts.make_release_zip as release_zip

    project_root, expected_sha = _release_repo(tmp_path)
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "poisoned-git-dir"))
    output = tmp_path / "source-release.zip"

    release_zip.make_release_zip(project_root, output, expected_sha=expected_sha)

    assert zipfile.is_zipfile(output)


def test_release_zip_replaces_output_path_without_following_hardlinks(tmp_path):
    import scripts.make_release_zip as release_zip

    project_root, expected_sha = _release_repo(tmp_path)
    victim = tmp_path / "must-remain-unchanged.bin"
    victim.write_bytes(b"do not overwrite this file")
    output = tmp_path / "source-release.zip"
    try:
        os.link(victim, output)
    except OSError as exc:
        pytest.skip(f"hard links unavailable on this test volume: {exc}")

    release_zip.make_release_zip(project_root, output, expected_sha=expected_sha)

    assert victim.read_bytes() == b"do not overwrite this file"
    assert zipfile.is_zipfile(output)
    assert not list(tmp_path.glob(".source-release.zip.*.tmp"))


@pytest.mark.parametrize(
    "relative",
    [
        r"..\escape.txt",
        "../escape.txt",
        "/absolute.txt",
        "C:/absolute.txt",
        "docs/./ambiguous.txt",
        "docs//ambiguous.txt",
        "docs/file.txt.",
        "docs/file.txt ",
        "docs/a:b.txt",
        "docs/CON.txt",
    ],
)
def test_release_zip_rejects_unsafe_git_member_paths(relative):
    from scripts.make_release_zip import validate_git_release_path

    with pytest.raises(RuntimeError, match="unsafe Git path"):
        validate_git_release_path(relative)


def test_release_zip_rejects_windows_casefold_member_collisions(tmp_path):
    from scripts.make_release_zip import prepare_release_entries

    root = tmp_path / "source"
    root.mkdir()
    entries = [
        ("docs/Report.txt", "a" * 40, "100644"),
        ("DOCS/report.TXT", "b" * 40, "100644"),
    ]

    with pytest.raises(RuntimeError, match="duplicate archive member"):
        prepare_release_entries(root, entries)


def test_release_zip_is_reproducible_and_uses_commit_timestamp(tmp_path):
    import scripts.make_release_zip as release_zip

    project_root, expected_sha = _release_repo(tmp_path, "docs/tracked.txt")
    checkout = tmp_path / "other-checkout-name"
    subprocess.run(
        ["git", "clone", "-q", "--no-hardlinks", str(project_root), str(checkout)],
        check=True,
    )
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"

    release_zip.make_release_zip(project_root, first, expected_sha=expected_sha)
    release_zip.make_release_zip(checkout, second, expected_sha=expected_sha)

    assert first.read_bytes() == second.read_bytes()
    epoch = int(
        subprocess.run(
            ["git", "show", "-s", "--format=%ct", expected_sha],
            cwd=project_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    expected_time = list(time.gmtime(epoch)[:6])
    expected_time[-1] -= expected_time[-1] % 2
    with zipfile.ZipFile(first) as archive:
        assert {item.date_time for item in archive.infolist()} == {
            tuple(expected_time)
        }
        assert all(
            item.filename.startswith(f"DefenseTracker-source-{expected_sha}/")
            for item in archive.infolist()
        )


def test_release_zip_clears_git_trace_side_effects(monkeypatch, tmp_path):
    import scripts.make_release_zip as release_zip

    project_root, expected_sha = _release_repo(tmp_path)
    trace = tmp_path / "must-not-create-git-trace.log"
    trace2 = tmp_path / "must-not-create-git-trace2.json"
    monkeypatch.setenv("GIT_TRACE", str(trace))
    monkeypatch.setenv("GIT_TRACE2_EVENT", str(trace2))
    output = tmp_path / "source-release.zip"

    release_zip.make_release_zip(project_root, output, expected_sha=expected_sha)

    assert zipfile.is_zipfile(output)
    assert not trace.exists()
    assert not trace2.exists()
