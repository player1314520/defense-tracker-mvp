"""Executable contracts for atomic host-side deployment release state."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "deploy" / "mvp" / "bin" / "release-state.py"


def load_helper():
    spec = importlib.util.spec_from_file_location("defense_release_state", HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def portal_release(seed: str) -> dict[str, str]:
    return {
        "image": f"registry.example.invalid/defense/portal@sha256:{seed * 64}",
        "release_sha": seed * 40,
        "wire_compatibility": "mvp-wire-v1",
        "source_manifest_sha256": seed * 64,
    }


def backend_release(seed: str) -> dict[str, str]:
    return {
        "release_sha": seed * 40,
        "source_manifest_sha256": seed * 64,
        "wire_compatibility": "mvp-wire-v1",
        "migration_policy": "expand-contract",
        "function_digest": seed * 64,
        "supabase_upstream_sha": seed * 40,
    }


def test_portal_state_keeps_old_generation_until_atomic_replace(monkeypatch, tmp_path):
    helper = load_helper()
    state_dir = tmp_path / "release-state"
    helper.prepare_state_dir(state_dir)
    old = portal_release("a")
    new = portal_release("b")
    helper.promote_portal(state_dir, old)

    real_replace = helper.os.replace

    def crash_before_replace(source, destination):
        if Path(destination).name == helper.PORTAL_STATE_NAME:
            raise OSError("simulated power loss before atomic replace")
        return real_replace(source, destination)

    monkeypatch.setattr(helper.os, "replace", crash_before_replace)
    with pytest.raises(OSError, match="simulated power loss"):
        helper.promote_portal(state_dir, new)

    # A reader can still observe only the complete old generation.
    state = helper.load_portal_state(state_dir)
    assert state["generation"] == 1
    assert state["current"] == old
    assert state["previous"] is None

    monkeypatch.setattr(helper.os, "replace", real_replace)
    helper.promote_portal(state_dir, new)
    state = helper.load_portal_state(state_dir)
    assert state["generation"] == 2
    assert state["current"] == new
    assert state["previous"] == old
    assert [item["generation"] for item in state["history"]] == [1]


def test_backend_state_is_one_complete_atomic_six_tuple(tmp_path):
    helper = load_helper()
    state_dir = tmp_path / "release-state"
    helper.prepare_state_dir(state_dir)
    old = backend_release("c")
    new = backend_release("d")

    helper.commit_backend(state_dir, old)
    helper.commit_backend(state_dir, new)

    state = helper.load_backend_state(state_dir)
    assert state["generation"] == 2
    assert state["active"] == new
    assert state["history"] == [{"generation": 1, "active": old}]
    assert not any(state_dir.glob("backend.*"))


def test_backend_state_keeps_old_six_tuple_when_replace_never_happens(
    monkeypatch, tmp_path
):
    helper = load_helper()
    state_dir = tmp_path / "release-state"
    helper.prepare_state_dir(state_dir)
    old = backend_release("3")
    new = backend_release("4")
    helper.commit_backend(state_dir, old)
    real_replace = helper.os.replace

    def crash_before_replace(source, destination):
        if Path(destination).name == helper.BACKEND_STATE_NAME:
            raise OSError("simulated backend commit interruption")
        return real_replace(source, destination)

    monkeypatch.setattr(helper.os, "replace", crash_before_replace)
    with pytest.raises(OSError, match="backend commit interruption"):
        helper.commit_backend(state_dir, new)

    state = helper.load_backend_state(state_dir)
    assert state["generation"] == 1
    assert state["active"] == old


@pytest.mark.parametrize(
    ("filename", "payload", "loader"),
    (
        (
            "portal-state.json",
            {
                "schema": 1,
                "kind": "portal-release-state",
                "generation": 1,
                "current": portal_release("e") | {"unexpected": "field"},
                "previous": None,
                "history": [],
            },
            "load_portal_state",
        ),
        (
            "backend-state.json",
            {
                "schema": 1,
                "kind": "backend-release-state",
                "generation": 1,
                "active": backend_release("f") | {"release_sha": "not-a-sha"},
                "history": [],
            },
            "load_backend_state",
        ),
    ),
)
def test_state_readers_reject_tampered_or_non_schema_content(
    tmp_path, filename, payload, loader
):
    helper = load_helper()
    state_dir = tmp_path / "release-state"
    helper.prepare_state_dir(state_dir)
    target = state_dir / filename
    target.write_text(json.dumps(payload), encoding="utf-8")
    if os.name == "posix":
        target.chmod(0o600)
    with pytest.raises(helper.StateError):
        getattr(helper, loader)(state_dir)


def test_state_reader_rejects_symbolic_link(tmp_path):
    helper = load_helper()
    state_dir = tmp_path / "release-state"
    helper.prepare_state_dir(state_dir)
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    try:
        (state_dir / helper.PORTAL_STATE_NAME).symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are unavailable on this test host")

    with pytest.raises(helper.StateError, match="symbolic link"):
        helper.load_portal_state(state_dir)


def test_posix_permission_validator_rejects_group_or_world_access(tmp_path):
    helper = load_helper()
    target = tmp_path / "state.json"
    target.write_text("{}", encoding="utf-8")

    # Force the POSIX branch so this security contract is executable on Windows CI too.
    with pytest.raises(helper.StateError, match="permissions"):
        helper.assert_secure_regular_file(
            target,
            expected_mode=0o600,
            enforce_posix_permissions=True,
            observed_mode=0o644,
        )


def test_state_directory_rejects_root_and_existing_symlink(tmp_path):
    helper = load_helper()
    with pytest.raises(helper.StateError, match="too broad"):
        helper.prepare_state_dir(Path(tmp_path.anchor))

    real_dir = tmp_path / "real"
    real_dir.mkdir()
    link_dir = tmp_path / "linked"
    try:
        link_dir.symlink_to(real_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are unavailable on this test host")
    with pytest.raises(helper.StateError, match="symbolic link"):
        helper.prepare_state_dir(link_dir)


def test_legacy_migration_is_once_only_and_never_guesses_incomplete_state(tmp_path):
    helper = load_helper()
    state_dir = tmp_path / "release-state"
    helper.prepare_state_dir(state_dir)
    old = portal_release("1")
    legacy = {
        "current.image": old["image"],
        "current.sha": old["release_sha"],
        "current.wire": old["wire_compatibility"],
        "current.manifest": old["source_manifest_sha256"],
    }
    for name, value in legacy.items():
        path = state_dir / name
        path.write_text(value + "\n", encoding="utf-8")
        if os.name == "posix":
            path.chmod(0o600)

    assert helper.migrate_legacy_portal(state_dir) is True
    assert helper.load_portal_state(state_dir)["current"] == old
    assert helper.migrate_legacy_portal(state_dir) is False
    assert all((state_dir / name).exists() for name in legacy)  # evidence retained

    incomplete_dir = tmp_path / "incomplete"
    helper.prepare_state_dir(incomplete_dir)
    path = incomplete_dir / "backend.sha"
    path.write_text("2" * 40 + "\n", encoding="utf-8")
    if os.name == "posix":
        path.chmod(0o600)
    with pytest.raises(helper.StateError, match="incomplete"):
        helper.migrate_legacy_backend(incomplete_dir)


def test_durable_markers_prevent_legacy_portal_and_backend_resurrection(tmp_path):
    helper = load_helper()
    state_dir = tmp_path / "release-state"
    helper.prepare_state_dir(state_dir)
    old_portal = portal_release("1")
    portal_legacy = {
        "current.image": old_portal["image"],
        "current.sha": old_portal["release_sha"],
        "current.wire": old_portal["wire_compatibility"],
        "current.manifest": old_portal["source_manifest_sha256"],
    }
    old_backend = backend_release("2")
    backend_legacy = {
        "backend.sha": old_backend["release_sha"],
        "backend.manifest": old_backend["source_manifest_sha256"],
        "backend.wire": old_backend["wire_compatibility"],
        "backend.policy": old_backend["migration_policy"],
        "backend.functions": old_backend["function_digest"],
        "backend.upstream": old_backend["supabase_upstream_sha"],
    }
    for name, value in (portal_legacy | backend_legacy).items():
        path = state_dir / name
        path.write_text(value + "\n", encoding="utf-8")
        if os.name == "posix":
            path.chmod(0o600)

    assert helper.migrate_legacy_portal(state_dir) is True
    assert helper.migrate_legacy_backend(state_dir) is True
    helper.promote_portal(state_dir, portal_release("3"))
    helper.commit_backend(state_dir, backend_release("4"))

    (state_dir / helper.PORTAL_STATE_NAME).unlink()
    with pytest.raises(helper.StateError, match="retained Portal legacy state"):
        helper.migrate_legacy_portal(state_dir)
    (state_dir / helper.BACKEND_STATE_NAME).unlink()
    with pytest.raises(helper.StateError, match="retained backend legacy state"):
        helper.migrate_legacy_backend(state_dir)


def test_first_migration_crash_resumes_only_the_marker_bound_legacy_state(
    monkeypatch, tmp_path
):
    helper = load_helper()
    state_dir = tmp_path / "release-state"
    helper.prepare_state_dir(state_dir)
    old = portal_release("5")
    for name, value in {
        "current.image": old["image"],
        "current.sha": old["release_sha"],
        "current.wire": old["wire_compatibility"],
        "current.manifest": old["source_manifest_sha256"],
    }.items():
        path = state_dir / name
        path.write_text(value + "\n", encoding="utf-8")
        if os.name == "posix":
            path.chmod(0o600)

    real_replace = helper.os.replace

    def crash_before_state(source, destination):
        if Path(destination).name == helper.PORTAL_STATE_NAME:
            raise OSError("simulated migration interruption")
        return real_replace(source, destination)

    monkeypatch.setattr(helper.os, "replace", crash_before_state)
    with pytest.raises(OSError, match="migration interruption"):
        helper.migrate_legacy_portal(state_dir)
    assert (state_dir / helper.PORTAL_MIGRATION_MARKER_NAME).is_file()
    monkeypatch.setattr(helper.os, "replace", real_replace)
    assert helper.migrate_legacy_portal(state_dir) is True
    assert helper.load_portal_state(state_dir)["current"] == old
    marker = helper._load_migration_marker(state_dir, helper.PORTAL_STATE_NAME)
    assert marker is not None and marker["established"] is True


def test_marker_digest_detects_state_substitution(tmp_path):
    helper = load_helper()
    state_dir = tmp_path / "release-state"
    helper.prepare_state_dir(state_dir)
    helper.promote_portal(state_dir, portal_release("6"))
    target = state_dir / helper.PORTAL_STATE_NAME
    payload = json.loads(target.read_text(encoding="utf-8"))
    payload["current"] = portal_release("7")
    target.write_text(json.dumps(payload), encoding="utf-8")
    if os.name == "posix":
        target.chmod(0o600)
    with pytest.raises(helper.StateError, match="durable marker"):
        helper.load_portal_state(state_dir)


def test_portal_switch_intent_is_durable_and_requires_observed_runtime(tmp_path):
    helper = load_helper()
    state_dir = tmp_path / "release-state"
    helper.prepare_state_dir(state_dir)
    old = portal_release("8")
    new = portal_release("9")
    helper.promote_portal(state_dir, old)
    helper.begin_portal_intent(state_dir, "promote", new)

    with pytest.raises(helper.StateError, match="unresolved Portal switch intent"):
        helper.assert_portal_intent_clear(state_dir)
    with pytest.raises(helper.StateError, match="does not match.*target"):
        helper.complete_portal_intent(state_dir, old["image"])
    helper.abort_portal_intent(state_dir, old["image"])
    helper.assert_portal_intent_clear(state_dir)

    helper.begin_portal_intent(state_dir, "promote", new)
    committed = helper.complete_portal_intent(state_dir, new["image"])
    assert committed["current"] == new
    assert not (state_dir / helper.PORTAL_INTENT_NAME).exists()


def test_completed_switch_with_stale_journal_reconciles_only_from_committed_state(
    monkeypatch, tmp_path
):
    helper = load_helper()
    state_dir = tmp_path / "release-state"
    helper.prepare_state_dir(state_dir)
    old = portal_release("a")
    new = portal_release("b")
    helper.promote_portal(state_dir, old)
    helper.begin_portal_intent(state_dir, "promote", new)
    real_remove = helper._remove_secure_file

    def crash_before_journal_cleanup(directory, filename):
        if filename == helper.PORTAL_INTENT_NAME:
            raise OSError("simulated cleanup interruption")
        return real_remove(directory, filename)

    monkeypatch.setattr(helper, "_remove_secure_file", crash_before_journal_cleanup)
    with pytest.raises(OSError, match="cleanup interruption"):
        helper.complete_portal_intent(state_dir, new["image"])
    assert helper.load_portal_state(state_dir)["current"] == new
    assert (state_dir / helper.PORTAL_INTENT_NAME).is_file()

    monkeypatch.setattr(helper, "_remove_secure_file", real_remove)
    recovered = helper.complete_portal_intent(state_dir, new["image"])
    assert recovered["current"] == new
    assert recovered["previous"] == old
    assert not (state_dir / helper.PORTAL_INTENT_NAME).exists()


def test_completed_rollback_with_stale_journal_is_idempotent_and_transition_bound(
    monkeypatch, tmp_path
):
    helper = load_helper()
    state_dir = tmp_path / "release-state"
    helper.prepare_state_dir(state_dir)
    previous = portal_release("c")
    current = portal_release("d")
    helper.promote_portal(state_dir, previous)
    helper.promote_portal(state_dir, current)
    intent = helper.begin_portal_intent(state_dir, "rollback", previous)
    real_remove = helper._remove_secure_file

    def crash_before_journal_cleanup(directory, filename):
        if filename == helper.PORTAL_INTENT_NAME:
            raise OSError("simulated rollback cleanup interruption")
        return real_remove(directory, filename)

    monkeypatch.setattr(helper, "_remove_secure_file", crash_before_journal_cleanup)
    with pytest.raises(OSError, match="rollback cleanup interruption"):
        helper.complete_portal_intent(state_dir, previous["image"])
    committed = helper.load_portal_state(state_dir)
    assert committed["current"] == previous
    assert committed["previous"] == current
    assert (state_dir / helper.PORTAL_INTENT_NAME).is_file()

    forged = json.loads(json.dumps(committed))
    forged["history"][-1]["previous"] = portal_release("e")
    assert helper._committed_portal_intent_matches(forged, intent) is False

    monkeypatch.setattr(helper, "_remove_secure_file", real_remove)
    recovered = helper.complete_portal_intent(state_dir, previous["image"])
    assert recovered == committed
    assert not (state_dir / helper.PORTAL_INTENT_NAME).exists()


def test_initial_switch_resumes_after_state_write_before_marker_established(
    monkeypatch, tmp_path
):
    helper = load_helper()
    state_dir = tmp_path / "release-state"
    helper.prepare_state_dir(state_dir)
    target = portal_release("f")
    helper.begin_portal_intent(state_dir, "promote", target)
    real_replace = helper.os.replace

    def crash_before_established_marker(source, destination):
        destination_path = Path(destination)
        if (
            destination_path.name == helper.PORTAL_MIGRATION_MARKER_NAME
            and (state_dir / helper.PORTAL_STATE_NAME).exists()
        ):
            raise OSError("simulated marker establishment interruption")
        return real_replace(source, destination)

    monkeypatch.setattr(helper.os, "replace", crash_before_established_marker)
    with pytest.raises(OSError, match="marker establishment interruption"):
        helper.complete_portal_intent(state_dir, target["image"])
    raw_marker = helper._load_migration_marker(state_dir, helper.PORTAL_STATE_NAME)
    assert raw_marker is not None and raw_marker["established"] is False
    assert (state_dir / helper.PORTAL_STATE_NAME).is_file()
    assert (state_dir / helper.PORTAL_INTENT_NAME).is_file()

    monkeypatch.setattr(helper.os, "replace", real_replace)
    committed = helper.complete_portal_intent(state_dir, target["image"])
    assert committed["current"] == target
    assert helper.load_portal_state(state_dir) == committed
    assert not (state_dir / helper.PORTAL_INTENT_NAME).exists()


def test_rollback_intent_must_target_the_retained_previous_release(tmp_path):
    helper = load_helper()
    state_dir = tmp_path / "release-state"
    helper.prepare_state_dir(state_dir)
    old = portal_release("c")
    current = portal_release("d")
    helper.promote_portal(state_dir, old)
    helper.promote_portal(state_dir, current)
    with pytest.raises(helper.StateError, match="not the retained previous"):
        helper.begin_portal_intent(state_dir, "rollback", portal_release("e"))
    helper.begin_portal_intent(state_dir, "rollback", old)
    committed = helper.complete_portal_intent(state_dir, old["image"])
    assert committed["current"] == old
    assert committed["previous"] == current


def test_shells_use_single_generation_documents_not_torn_field_files():
    release = (ROOT / "deploy/mvp/bin/release.sh").read_text(encoding="utf-8")
    rollback = (ROOT / "deploy/mvp/bin/rollback.sh").read_text(encoding="utf-8")
    installer = (ROOT / "deploy/mvp/bin/install-supabase-app.sh").read_text(
        encoding="utf-8"
    )
    verifier = (ROOT / "deploy/mvp/bin/verify-supabase-app.sh").read_text(
        encoding="utf-8"
    )
    recovery = (ROOT / "deploy/mvp/bin/recover-portal-switch.sh").read_text(
        encoding="utf-8"
    )

    for script in (release, rollback, installer, verifier):
        assert "release-state.py" in script
    assert "portal-state.json" in release
    assert "portal-state.json" in rollback
    assert "backend-state.json" in installer
    assert "backend-state.json" in verifier
    for legacy_name in (
        "current.image",
        "current.sha",
        "previous.image",
        "backend.sha",
        "backend.wire",
        "backend.functions",
    ):
        assert f'"$state_dir/{legacy_name}"' not in release
        assert f'"$state_dir/{legacy_name}"' not in rollback
        assert f'"$MVP_RELEASE_STATE_DIR/{legacy_name}"' not in installer
        assert f'"$MVP_RELEASE_STATE_DIR/{legacy_name}"' not in verifier

    for script in (release, rollback):
        assert "portal-intent-check" in script
        assert "running Portal image differs from authoritative release state" in script
        assert "running Portal commit differs from authoritative release state" in script
        assert "DEFENSE_TRACKER_BUILD_COMMIT" in script
        assert script.index("portal-intent-begin") < script.index("docker compose", script.index("portal-intent-begin"))
        assert script.index("probe-public.py") < script.index("portal-intent-complete")
        assert "portal-intent-abort" in script
    assert "docker inspect --format '{{.Config.Image}}'" in recovery
    assert "verify-supabase-app.sh" in recovery
    assert "probe-public.py" in recovery
    assert "portal-intent-complete" in recovery
    assert "portal-intent-abort" in recovery
    assert "running Portal commit differs from the switch intent target" in recovery
    assert "running Portal commit differs from the switch intent source" in recovery
    assert 'probe-public.py" "$config_file" "$expected_sha"' in recovery
    assert "--timeout 30 portal edge" in recovery
    assert recovery.index("--timeout 30 portal edge") < recovery.rindex(
        "portal-intent-abort"
    )


@pytest.mark.skipif(os.name == "nt", reason="flock and /proc fd identity are Linux gates")
def test_deployment_lock_blocks_parallel_writer_and_allows_inherited_child(tmp_path):
    helper = ROOT / "deploy/mvp/bin/deployment-lock.sh"
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    holder = subprocess.Popen(
        [
            "/bin/sh",
            "-c",
            '. "$1"; acquire_mvp_deployment_lock "$2"; '
            'printf ready; exec sleep 10',
            "lock-holder",
            str(helper),
            str(state_dir),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.read(5) == "ready"
        blocked = subprocess.run(
            [
                "/bin/sh",
                "-c",
                '. "$1"; acquire_mvp_deployment_lock "$2"',
                "lock-contender",
                str(helper),
                str(state_dir),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        assert blocked.returncode == 75
    finally:
        holder.terminate()
        holder.wait(timeout=5)

    nested = subprocess.run(
        [
            "/bin/sh",
            "-c",
            '. "$1"; acquire_mvp_deployment_lock "$2"; '
            '/bin/sh -c \'. "$1"; acquire_mvp_deployment_lock "$2"\' child "$1" "$2"',
            "lock-parent",
            str(helper),
            str(state_dir),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    assert nested.returncode == 0, nested.stderr


def test_release_state_cli_round_trip_matches_shell_usage(tmp_path):
    state_dir = tmp_path / "release-state"
    first = portal_release("7")
    second = portal_release("8")

    def run(*arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(HELPER), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )

    run("prepare", str(state_dir))
    run(
        "portal-promote",
        str(state_dir),
        first["image"],
        first["release_sha"],
        first["wire_compatibility"],
        first["source_manifest_sha256"],
    )
    run(
        "portal-promote",
        str(state_dir),
        second["image"],
        second["release_sha"],
        second["wire_compatibility"],
        second["source_manifest_sha256"],
    )
    assert run("get", "portal", str(state_dir), "current.release_sha").stdout.strip() == (
        second["release_sha"]
    )
    run("portal-rollback", str(state_dir))
    assert run("get", "portal", str(state_dir), "current.release_sha").stdout.strip() == (
        first["release_sha"]
    )
