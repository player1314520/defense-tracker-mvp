# -*- coding: utf-8 -*-
"""Verify release-era privacy-safe Git identities and commit metadata.

Commits at or before the fixed public-release baseline are deliberately outside
the identity policy and are never rendered by this tool. The maintainer's own
commits must use the prescribed identity; community authors and committers must
use GitHub noreply addresses. GitHub's merge service is allowed as a committer.
Failures report only a commit prefix and a finding code, never the offending
metadata value.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


RELEASE_BASELINE = "5402cb5b6b05540315f24ba82014551644113805"
EXPECTED_NAME = "player1314520"
EXPECTED_EMAIL = "168609221+player1314520@users.noreply.github.com"
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
GITHUB_NOREPLY_RE = re.compile(
    r"^[A-Za-z0-9._+\-\[\]]+@users\.noreply\.github\.com$",
    re.IGNORECASE,
)
GITHUB_MERGE_COMMITTERS = {
    ("GitHub", "noreply@github.com"),
    ("web-flow", "noreply@github.com"),
}

LOCAL_PATH_RULES = (
    re.compile(r"(?i)(?<![A-Za-z0-9])[A-Z]:[\\/]"),
    re.compile(r"(?i)(?<![A-Za-z0-9])(?:/Users/|/home/|/private/var/|file://)"),
    re.compile(r"(?i)(?<![A-Za-z0-9])\\\\[^\\\s]+\\[^\\\s]+"),
    re.compile(r"(?i)(?:%USERPROFILE%|\$HOME|\$env:USERPROFILE)"),
)
SECRET_RULES = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgh[oprsu]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\b"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9_./+\-=]{12,}"
    ),
)


@dataclass(frozen=True)
class Finding:
    commit: str
    code: str


def _identity_allowed(name: str, email: str, *, role: str) -> bool:
    identity = (name, email)
    expected = (EXPECTED_NAME, EXPECTED_EMAIL)
    if name == EXPECTED_NAME or email == EXPECTED_EMAIL:
        return identity == expected
    if role == "committer" and identity in GITHUB_MERGE_COMMITTERS:
        return True
    return bool(name.strip()) and GITHUB_NOREPLY_RE.fullmatch(email) is not None


def _git(repo: Path, *arguments: str) -> bytes:
    process = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        raise ValueError("Git history could not be inspected safely")
    return process.stdout


def _resolve_commit(repo: Path, revision: str) -> str:
    resolved = _git(repo, "rev-parse", "--verify", f"{revision}^{{commit}}")
    value = resolved.decode("ascii", errors="strict").strip()
    if FULL_SHA_RE.fullmatch(value) is None:
        raise ValueError("Git revision did not resolve to a full commit ID")
    return value


def _metadata(repo: Path, commit: str) -> tuple[str, str, str, str, str]:
    payload = _git(
        repo,
        "show",
        "--no-patch",
        "--format=%an%x00%ae%x00%cn%x00%ce%x00%B",
        commit,
    )
    fields = payload.decode("utf-8", errors="replace").split("\x00", 4)
    if len(fields) != 5:
        raise ValueError("Git commit metadata is malformed")
    return tuple(field.rstrip("\r\n") for field in fields)  # type: ignore[return-value]


def verify_repository(
    repo: Path,
    *,
    baseline: str = RELEASE_BASELINE,
    revision: str = "HEAD",
) -> list[Finding]:
    repo = repo.resolve()
    baseline_commit = _resolve_commit(repo, baseline)
    revision_commit = _resolve_commit(repo, revision)
    ancestor = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", baseline_commit, revision_commit],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if ancestor.returncode != 0:
        raise ValueError("Release baseline is not an ancestor of the requested revision")
    commits = _git(repo, "rev-list", "--reverse", f"{baseline_commit}..{revision_commit}")
    findings: list[Finding] = []
    for raw_commit in commits.decode("ascii", errors="strict").splitlines():
        commit = raw_commit.strip()
        if FULL_SHA_RE.fullmatch(commit) is None:
            raise ValueError("Git history returned an invalid commit ID")
        author_name, author_email, committer_name, committer_email, message = _metadata(
            repo, commit
        )
        if not _identity_allowed(author_name, author_email, role="author"):
            findings.append(Finding(commit, "author-identity"))
        if not _identity_allowed(committer_name, committer_email, role="committer"):
            findings.append(Finding(commit, "committer-identity"))
        if any(rule.search(message) for rule in LOCAL_PATH_RULES):
            findings.append(Finding(commit, "local-path-in-message"))
        if any(rule.search(message) for rule in SECRET_RULES):
            findings.append(Finding(commit, "secret-pattern-in-message"))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--baseline", default=RELEASE_BASELINE)
    parser.add_argument("--revision", default="HEAD")
    args = parser.parse_args()
    try:
        findings = verify_repository(
            args.repo,
            baseline=args.baseline,
            revision=args.revision,
        )
    except (OSError, UnicodeError, ValueError):
        print("git-history: FAIL (history-unavailable)")
        return 1
    if findings:
        for finding in findings:
            print(f"git-history: FAIL {finding.commit[:12]} {finding.code}")
        return 1
    print("git-history: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
