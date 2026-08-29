# -*- coding: utf-8 -*-
"""Require the protected CI and CodeQL checks for one exact GitHub commit."""

from __future__ import annotations

import argparse
from collections.abc import Callable
import json
import os
import re
import urllib.request


REQUIRED_CI_CHECKS = frozenset(
    {
        "Public tree policy",
        "Python 3.11 (ubuntu-latest)",
        "Python 3.11 (windows-latest)",
        "JavaScript tests and reproducible bundles",
        "Supabase Edge Functions",
        "MVP deployment assets",
    }
)
REQUIRED_CODEQL_CHECKS = frozenset(
    {
        "Analyze (actions)",
        "Analyze (javascript-typescript)",
        "Analyze (python)",
    }
)
REQUIRED_CHECKS = REQUIRED_CI_CHECKS | REQUIRED_CODEQL_CHECKS
GITHUB_ACTIONS_APP_ID = 15368
EXPECTED_CI_WORKFLOW_PATH = ".github/workflows/ci.yml"
# GitHub CodeQL Default Setup is represented by a dynamic workflow rather than
# a repository-owned workflow file. Pin both values returned by the Actions API
# so a similarly named job from any other workflow cannot satisfy the gate.
EXPECTED_CODEQL_WORKFLOW_PATH = "dynamic/github-code-scanning/codeql"
EXPECTED_CODEQL_EVENT = "dynamic"
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
WorkflowRunLoader = Callable[[int], dict[str, object]]


def load_check_runs(repository: str, sha: str, token: str) -> list[dict[str, object]]:
    all_runs: list[dict[str, object]] = []
    seen_run_ids: set[int] = set()
    expected_total: int | None = None
    page = 1
    while True:
        url = (
            f"https://api.github.com/repos/{repository}/commits/{sha}/check-runs"
            f"?per_page=100&filter=latest&page={page}"
        )
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
            raise ValueError("GitHub check-runs response is malformed")
        runs = payload.get("check_runs")
        total_count = payload.get("total_count")
        if (
            not isinstance(runs, list)
            or type(total_count) is not int
            or total_count < 0
        ):
            raise ValueError("GitHub check-runs response is malformed")
        if expected_total is None:
            expected_total = total_count
        elif total_count != expected_total:
            raise ValueError("GitHub check-runs pagination changed during verification")
        for run in runs:
            run_id = run.get("id") if isinstance(run, dict) else None
            if type(run_id) is not int or run_id <= 0 or run_id in seen_run_ids:
                raise ValueError("GitHub check-runs pagination is inconsistent")
            seen_run_ids.add(run_id)
            all_runs.append(run)
        if len(all_runs) == expected_total:
            return all_runs
        if len(all_runs) > expected_total or not runs:
            raise ValueError("GitHub check-runs pagination is incomplete")
        page += 1


def _verify_required_check_set(
    check_runs: list[dict[str, object]],
    *,
    required_checks: frozenset[str] = REQUIRED_CHECKS,
    group_name: str = "protected",
) -> None:
    by_name: dict[str, dict[str, object]] = {}
    duplicate_names: set[str] = set()
    for run in check_runs:
        name = run.get("name")
        if isinstance(name, str) and name in required_checks:
            if name in by_name:
                duplicate_names.add(name)
            by_name[name] = run
    missing = sorted(required_checks.difference(by_name))
    failed = sorted(
        name
        for name, run in by_name.items()
        if run.get("status") != "completed" or run.get("conclusion") != "success"
    )
    if missing or failed or duplicate_names:
        raise ValueError(
            f"Required {group_name} checks are not green "
            f"(missing={missing}, failed={failed}, duplicates={sorted(duplicate_names)})"
        )


def _group_required_check_suites(
    check_runs: list[dict[str, object]], *, repository: str
) -> dict[tuple[int, int], list[dict[str, object]]]:
    if REPOSITORY_RE.fullmatch(repository) is None:
        raise ValueError("Repository name is malformed")
    details_re = re.compile(
        rf"^https://github\.com/{re.escape(repository)}/actions/runs/([1-9][0-9]*)/job/[1-9][0-9]*$"
    )
    suites: dict[tuple[int, int], list[dict[str, object]]] = {}
    for run in check_runs:
        name = run.get("name")
        if not isinstance(name, str) or name not in REQUIRED_CHECKS:
            continue
        app = run.get("app")
        if (
            not isinstance(app, dict)
            or app.get("id") != GITHUB_ACTIONS_APP_ID
            or app.get("slug") != "github-actions"
        ):
            raise ValueError(f"Required CI check has an untrusted publisher: {name}")
        details_url = run.get("details_url")
        match = details_re.fullmatch(details_url) if isinstance(details_url, str) else None
        if match is None:
            raise ValueError(f"Required CI check has an untrusted details URL: {name}")
        suite = run.get("check_suite")
        suite_id = suite.get("id") if isinstance(suite, dict) else None
        if not isinstance(suite_id, int) or suite_id <= 0:
            raise ValueError(f"Required CI check lacks a trusted suite: {name}")
        key = (int(match.group(1)), suite_id)
        suites.setdefault(key, []).append(run)
    return suites


def _select_exact_workflow_suite(
    suites: dict[tuple[int, int], list[dict[str, object]]],
    *,
    repository: str,
    sha: str,
    workflow_run_loader: WorkflowRunLoader,
    workflow_runs: dict[int, dict[str, object]],
    required_checks: frozenset[str],
    workflow_path: str,
    event: str,
    group_name: str,
) -> tuple[tuple[int, int], list[dict[str, object]]]:
    exact_suites: list[tuple[tuple[int, int], list[dict[str, object]]]] = []
    for key, suite_runs in suites.items():
        if not any(run.get("name") in required_checks for run in suite_runs):
            continue
        run_id, suite_id = key
        if run_id not in workflow_runs:
            workflow_runs[run_id] = workflow_run_loader(run_id)
        try:
            verify_workflow_run(
                workflow_runs[run_id],
                repository=repository,
                sha=sha,
                run_id=run_id,
                check_suite_id=suite_id,
                workflow_path=workflow_path,
                event=event,
            )
        except ValueError:
            continue
        exact_suites.append((key, suite_runs))
    if len(exact_suites) != 1:
        raise ValueError(
            f"Required {group_name} checks need exactly one successful "
            f"{event} {group_name} suite for the release SHA "
            f"(found={len(exact_suites)})"
        )
    return exact_suites[0]


def _verify_workflow_check_set(
    selected_runs: list[dict[str, object]],
    *,
    required_checks: frozenset[str],
    group_name: str,
) -> None:
    unexpected = sorted(
        {
            str(run.get("name"))
            for run in selected_runs
            if run.get("name") in REQUIRED_CHECKS
            and run.get("name") not in required_checks
        }
    )
    if unexpected:
        raise ValueError(
            f"Required {group_name} suite contains checks from another workflow: "
            f"{unexpected}"
        )
    _verify_required_check_set(
        selected_runs,
        required_checks=required_checks,
        group_name=group_name,
    )


def verify(
    check_runs: list[dict[str, object]],
    *,
    repository: str | None = None,
    sha: str | None = None,
    workflow_run_loader: WorkflowRunLoader | None = None,
) -> int:
    if repository is None or sha is None or workflow_run_loader is None:
        raise ValueError(
            "repository, sha and workflow_run_loader are required for provenance verification"
        )
    if SHA_RE.fullmatch(sha) is None:
        raise ValueError("Release SHA is malformed")
    suites = _group_required_check_suites(check_runs, repository=repository)
    workflow_runs: dict[int, dict[str, object]] = {}
    ci_key, ci_runs = _select_exact_workflow_suite(
        suites,
        repository=repository,
        sha=sha,
        workflow_run_loader=workflow_run_loader,
        workflow_runs=workflow_runs,
        required_checks=REQUIRED_CI_CHECKS,
        workflow_path=EXPECTED_CI_WORKFLOW_PATH,
        event="push",
        group_name="CI",
    )
    codeql_key, codeql_runs = _select_exact_workflow_suite(
        suites,
        repository=repository,
        sha=sha,
        workflow_run_loader=workflow_run_loader,
        workflow_runs=workflow_runs,
        required_checks=REQUIRED_CODEQL_CHECKS,
        workflow_path=EXPECTED_CODEQL_WORKFLOW_PATH,
        event=EXPECTED_CODEQL_EVENT,
        group_name="CodeQL",
    )

    if ci_key == codeql_key:
        raise ValueError("CI and CodeQL checks must come from distinct workflow suites")
    _verify_workflow_check_set(
        ci_runs,
        required_checks=REQUIRED_CI_CHECKS,
        group_name="CI",
    )
    _verify_workflow_check_set(
        codeql_runs,
        required_checks=REQUIRED_CODEQL_CHECKS,
        group_name="CodeQL",
    )
    return ci_key[0]


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
    workflow_run: dict[str, object],
    *,
    repository: str,
    sha: str,
    run_id: int,
    check_suite_id: int | None = None,
    workflow_path: str = EXPECTED_CI_WORKFLOW_PATH,
    event: str = "push",
) -> None:
    repo = workflow_run.get("repository")
    repo_name = repo.get("full_name") if isinstance(repo, dict) else None
    expected = {
        "id": run_id,
        "head_sha": sha,
        "head_branch": "main",
        "path": workflow_path,
        "event": event,
        "status": "completed",
        "conclusion": "success",
    }
    if check_suite_id is not None:
        expected["check_suite_id"] = check_suite_id
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
    verify(
        load_check_runs(args.repository, args.sha, args.token),
        repository=args.repository,
        sha=args.sha,
        workflow_run_loader=lambda candidate_run_id: load_workflow_run(
            args.repository, candidate_run_id, args.token
        ),
    )
    print("required-ci-checks: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
