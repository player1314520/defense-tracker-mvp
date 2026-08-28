# -*- coding: utf-8 -*-
"""Require all six named CI checks to succeed for one exact GitHub commit."""

from __future__ import annotations

import argparse
import json
import os
import re
import urllib.request


REQUIRED_CHECKS = {
    "Public tree policy",
    "Python 3.11 (ubuntu-latest)",
    "Python 3.11 (windows-latest)",
    "JavaScript tests and reproducible bundles",
    "Supabase Edge Functions",
    "MVP deployment assets",
}
GITHUB_ACTIONS_APP_ID = 15368
EXPECTED_WORKFLOW_PATH = ".github/workflows/ci.yml"
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def load_check_runs(repository: str, sha: str, token: str) -> list[dict[str, object]]:
    url = f"https://api.github.com/repos/{repository}/commits/{sha}/check-runs?per_page=100&filter=latest"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "DefenseTracker-release-gate",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.load(response)
    runs = payload.get("check_runs")
    if not isinstance(runs, list):
        raise ValueError("GitHub check-runs response is malformed")
    return runs


def verify(
    check_runs: list[dict[str, object]], *, repository: str | None = None
) -> int | None:
    by_name: dict[str, dict[str, object]] = {}
    duplicate_names: set[str] = set()
    for run in check_runs:
        name = run.get("name")
        if isinstance(name, str) and name in REQUIRED_CHECKS:
            if name in by_name:
                duplicate_names.add(name)
            by_name[name] = run
    missing = sorted(REQUIRED_CHECKS.difference(by_name))
    failed = sorted(
        name
        for name, run in by_name.items()
        if run.get("status") != "completed" or run.get("conclusion") != "success"
    )
    if missing or failed or duplicate_names:
        raise ValueError(
            "Required CI checks are not green "
            f"(missing={missing}, failed={failed}, duplicates={sorted(duplicate_names)})"
        )
    if repository is None:
        return None
    if REPOSITORY_RE.fullmatch(repository) is None:
        raise ValueError("Repository name is malformed")
    details_re = re.compile(
        rf"^https://github\.com/{re.escape(repository)}/actions/runs/([1-9][0-9]*)/job/[1-9][0-9]*$"
    )
    workflow_run_ids: set[int] = set()
    check_suite_ids: set[int] = set()
    for name, run in by_name.items():
        app = run.get("app")
        if not isinstance(app, dict) or app.get("id") != GITHUB_ACTIONS_APP_ID or app.get("slug") != "github-actions":
            raise ValueError(f"Required CI check has an untrusted publisher: {name}")
        details_url = run.get("details_url")
        match = details_re.fullmatch(details_url) if isinstance(details_url, str) else None
        if match is None:
            raise ValueError(f"Required CI check has an untrusted details URL: {name}")
        workflow_run_ids.add(int(match.group(1)))
        suite = run.get("check_suite")
        suite_id = suite.get("id") if isinstance(suite, dict) else None
        if not isinstance(suite_id, int) or suite_id <= 0:
            raise ValueError(f"Required CI check lacks a trusted suite: {name}")
        check_suite_ids.add(suite_id)
    if len(workflow_run_ids) != 1 or len(check_suite_ids) != 1:
        raise ValueError("Required CI checks do not belong to one workflow run and suite")
    return next(iter(workflow_run_ids))


def load_workflow_run(repository: str, run_id: int, token: str) -> dict[str, object]:
    url = f"https://api.github.com/repos/{repository}/actions/runs/{run_id}"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "DefenseTracker-release-gate",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise ValueError("GitHub workflow-run response is malformed")
    return payload


def verify_workflow_run(
    workflow_run: dict[str, object], *, repository: str, sha: str, run_id: int
) -> None:
    repo = workflow_run.get("repository")
    repo_name = repo.get("full_name") if isinstance(repo, dict) else None
    expected = {
        "id": run_id,
        "head_sha": sha,
        "head_branch": "main",
        "path": EXPECTED_WORKFLOW_PATH,
        "event": "push",
        "status": "completed",
        "conclusion": "success",
    }
    mismatches = [key for key, value in expected.items() if workflow_run.get(key) != value]
    if repo_name != repository:
        mismatches.append("repository.full_name")
    if mismatches:
        raise ValueError(f"Required CI workflow provenance mismatch: {sorted(mismatches)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    args = parser.parse_args()
    if not args.token:
        raise SystemExit("GITHUB_TOKEN is required")
    if REPOSITORY_RE.fullmatch(args.repository) is None or SHA_RE.fullmatch(args.sha) is None:
        raise SystemExit("repository or sha is malformed")
    run_id = verify(
        load_check_runs(args.repository, args.sha, args.token),
        repository=args.repository,
    )
    assert run_id is not None
    verify_workflow_run(
        load_workflow_run(args.repository, run_id, args.token),
        repository=args.repository,
        sha=args.sha,
        run_id=run_id,
    )
    print("required-ci-checks: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
