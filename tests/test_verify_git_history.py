# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from scripts.verify_git_history import (
    EXPECTED_EMAIL,
    EXPECTED_NAME,
    verify_repository,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_git_history.py"
GITLEAKS_SHA256 = "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"


def git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    process = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        text=True,
        encoding="utf-8",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    return process.stdout.strip()


def commit(
    repo: Path,
    message: str,
    *,
    name: str,
    email: str,
    committer_name: str | None = None,
    committer_email: str | None = None,
) -> str:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_NAME": name,
            "GIT_AUTHOR_EMAIL": email,
            "GIT_COMMITTER_NAME": committer_name or name,
            "GIT_COMMITTER_EMAIL": committer_email or email,
        }
    )
    git(repo, "commit", "--allow-empty", "-q", "-m", message, env=environment)
    return git(repo, "rev-parse", "HEAD")


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    return repo


def test_pre_baseline_legacy_identity_is_tolerated_and_not_returned(tmp_path):
    repo = make_repo(tmp_path)
    baseline = commit(
        repo,
        "legacy baseline",
        name="Legacy Person",
        email="legacy-private@example.invalid",
    )
    commit(repo, "release metadata is clean", name=EXPECTED_NAME, email=EXPECTED_EMAIL)
    assert verify_repository(repo, baseline=baseline) == []


def test_post_baseline_identity_path_and_secret_are_reported_only_as_codes(tmp_path):
    repo = make_repo(tmp_path)
    baseline = commit(repo, "baseline", name="Legacy Person", email="old@example.invalid")
    bad_email = "private-person@example.invalid"
    # Assemble the sensitive-pattern fixture at runtime so the public tree
    # scanner does not contain a literal local-user path of its own.
    local_path = "F:" + r"\HuaweiMoveData" + r"\Users\example\private.txt"
    fake_secret = "github_pat_" + "A" * 30
    bad_identity_commit = commit(
        repo,
        "identity regression",
        name="Private Person",
        email=bad_email,
    )
    path_commit = commit(
        repo,
        f"remove trace {local_path}",
        name=EXPECTED_NAME,
        email=EXPECTED_EMAIL,
    )
    secret_commit = commit(
        repo,
        f"rotate token {fake_secret}",
        name=EXPECTED_NAME,
        email=EXPECTED_EMAIL,
    )
    findings = verify_repository(repo, baseline=baseline)
    assert {(item.commit, item.code) for item in findings} == {
        (bad_identity_commit, "author-identity"),
        (bad_identity_commit, "committer-identity"),
        (path_commit, "local-path-in-message"),
        (secret_commit, "secret-pattern-in-message"),
    }
    rendered = "\n".join(f"{item.commit[:12]} {item.code}" for item in findings)
    for sensitive in (bad_email, local_path, fake_secret, "old@example.invalid"):
        assert sensitive not in rendered

    process = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--repo",
            str(repo),
            "--baseline",
            baseline,
        ],
        check=False,
        text=True,
        encoding="utf-8",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.returncode == 1
    assert process.stderr == ""
    for sensitive in (bad_email, local_path, fake_secret, "old@example.invalid"):
        assert sensitive not in process.stdout


def test_clean_post_baseline_commits_pass_cli(tmp_path):
    repo = make_repo(tmp_path)
    baseline = commit(repo, "baseline", name="Old Identity", email="old@example.invalid")
    commit(repo, "prepare public release", name=EXPECTED_NAME, email=EXPECTED_EMAIL)
    process = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--repo",
            str(repo),
            "--baseline",
            baseline,
        ],
        check=False,
        text=True,
        encoding="utf-8",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.returncode == 0
    assert process.stdout.strip() == "git-history: PASS"
    assert process.stderr == ""


def test_community_noreply_author_and_github_merge_committer_are_allowed(tmp_path):
    repo = make_repo(tmp_path)
    baseline = commit(repo, "baseline", name="Old Identity", email="old@example.invalid")
    commit(
        repo,
        "document a community fix",
        name="community-user",
        email="12345+community-user@users.noreply.github.com",
        committer_name="GitHub",
        committer_email="noreply@github.com",
    )

    assert verify_repository(repo, baseline=baseline) == []


def test_maintainer_alias_cannot_bypass_the_prescribed_noreply_identity(tmp_path):
    repo = make_repo(tmp_path)
    baseline = commit(repo, "baseline", name="Old Identity", email="old@example.invalid")
    bad = commit(
        repo,
        "use an obsolete maintainer alias",
        name=EXPECTED_NAME,
        email="player1314520@users.noreply.github.com",
    )

    assert {(item.commit, item.code) for item in verify_repository(repo, baseline=baseline)} == {
        (bad, "author-identity"),
        (bad, "committer-identity"),
    }


def test_ci_and_candidate_repeat_exact_redacted_full_history_scan():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    candidate = (
        ROOT / ".github" / "workflows" / "v9-signed-candidate.yml"
    ).read_text(encoding="utf-8")
    for workflow in (ci, candidate):
        assert 'GITLEAKS_VERSION: "8.30.1"' in workflow
        assert GITLEAKS_SHA256 in workflow
        assert "fetch-depth: 0" in workflow
        assert "gitleaks/releases/download/v${GITLEAKS_VERSION}" in workflow
        assert "sha256sum --check --strict" in workflow
        assert "gitleaks\" git --redact --no-banner --exit-code 1" in workflow
        assert '--log-opts="--all"' in workflow
        assert "scripts/verify_git_history.py" in workflow
        assert "sensitive findings are intentionally not printed" in workflow
    assert '--revision "${RELEASE_SHA}"' in candidate
    assert "DEFENSE_TRACKER_EPHEMERAL_RUNNER_MODE" in candidate
