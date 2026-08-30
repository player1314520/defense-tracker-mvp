# -*- coding: utf-8 -*-
"""GitHub Environment approval contexts are exact, canonical byte bindings."""

from __future__ import annotations

import hashlib
import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.github_environment_approval import (
    APPROVAL_MODE,
    REVIEW_MODEL,
    canonical_json_bytes,
    create_approval_context,
    load_approval_context,
    validate_approval_context,
    write_approval_context,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "player1314520/defense-tracker-mvp"
WORKFLOW_REF = (
    f"{REPOSITORY}/.github/workflows/v9-signed-candidate.yml@refs/heads/main"
)
RELEASE_COMMIT = "a" * 40
SUBJECT_SHA256 = "b" * 64


def _context(**overrides: object):
    values: dict[str, object] = {
        "environment": "v9-trusted-signing",
        "repository": REPOSITORY,
        "workflow_ref": WORKFLOW_REF,
        "release_commit": RELEASE_COMMIT,
        "run_id": 123456789,
        "run_attempt": 2,
        "job": "prepare-installer-review",
        "subject_kind": "compliance-evidence",
        "subject_sha256": SUBJECT_SHA256,
        "generated_at_utc": "2026-08-30T12:34:56Z",
    }
    values.update(overrides)
    return create_approval_context(**values)  # type: ignore[arg-type]


def test_context_is_exact_canonical_utf8_without_actor_identity(tmp_path: Path):
    context = _context()
    output = tmp_path / "approval-context.json"
    write_approval_context(output, context)

    expected_keys = {
        "schema",
        "approval_mode",
        "review_model",
        "environment",
        "repository",
        "workflow_ref",
        "release_commit",
        "run_id",
        "run_attempt",
        "job",
        "subject_kind",
        "subject_sha256",
        "generated_at_utc",
    }
    assert set(context.as_dict()) == expected_keys
    assert context.schema == 1
    assert context.approval_mode == APPROVAL_MODE == "github-environment"
    assert context.review_model == REVIEW_MODEL == "single-maintainer-audited"
    assert "approved_by" not in context.as_dict()
    assert "GITHUB_ACTOR" not in output.read_text(encoding="utf-8")
    assert output.read_bytes() == canonical_json_bytes(context.as_dict())
    assert output.read_bytes().endswith(b"\n")
    assert b"\r" not in output.read_bytes()

    loaded = load_approval_context(
        output,
        expected_environment="v9-trusted-signing",
        expected_repository=REPOSITORY,
        expected_workflow_ref=WORKFLOW_REF,
        expected_release_commit=RELEASE_COMMIT,
        expected_run_id=123456789,
        expected_run_attempt=2,
        expected_job="prepare-installer-review",
        expected_subject_kind="compliance-evidence",
        expected_subject_sha256=SUBJECT_SHA256,
    )
    assert loaded == context


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("environment", "v9-installer-signing-review"),
        ("repository", "player1314520/another-repository"),
        (
            "workflow_ref",
            f"{REPOSITORY}/.github/workflows/v9-stable-release.yml@refs/heads/main",
        ),
        ("release_commit", "c" * 40),
        ("run_id", 987654321),
        ("run_attempt", 3),
        ("job", "different-job"),
        ("subject_kind", "installer-review-request"),
        ("subject_sha256", "d" * 64),
    ],
)
def test_validate_rejects_each_expected_binding_mismatch(field: str, expected: object):
    with pytest.raises(ValueError, match=field):
        validate_approval_context(_context().as_dict(), **{f"expected_{field}": expected})


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"repository": "https://github.com/owner/repo"}, "repository"),
        ({"repository": "owner/.git"}, "repository"),
        (
            {
                "workflow_ref": "another/repo/.github/workflows/release.yml@refs/heads/main"
            },
            "workflow_ref",
        ),
        (
            {
                "workflow_ref": f"{REPOSITORY}/.github/workflows/../release.yml@refs/heads/main"
            },
            "workflow_ref",
        ),
        ({"workflow_ref": f"{REPOSITORY}/release.yml@refs/heads/main"}, "workflow_ref"),
        ({"release_commit": "A" * 40}, "release_commit"),
        ({"subject_sha256": "B" * 64}, "subject_sha256"),
        ({"environment": "v9 trusted signing"}, "environment"),
        ({"job": "prepare/review"}, "job"),
        ({"run_id": True}, "run_id"),
        ({"run_attempt": 0}, "run_attempt"),
        ({"subject_kind": "release"}, "subject_kind"),
        ({"generated_at_utc": "2026-08-30T12:34:56+00:00"}, "generated_at_utc"),
        ({"generated_at_utc": "2026-02-30T12:34:56Z"}, "generated_at_utc"),
    ],
)
def test_create_rejects_malformed_identifiers(overrides: dict[str, object], message: str):
    with pytest.raises(ValueError, match=message):
        _context(**overrides)


def test_load_rejects_noncanonical_duplicate_and_extra_fields(tmp_path: Path):
    context = _context().as_dict()
    path = tmp_path / "approval.json"

    path.write_text(json.dumps(context, indent=2), encoding="utf-8")
    with pytest.raises(ValueError, match="canonical"):
        load_approval_context(path)

    path.write_bytes(b"\xef\xbb\xbf" + canonical_json_bytes(context))
    with pytest.raises(ValueError, match="valid JSON"):
        load_approval_context(path)

    duplicate = canonical_json_bytes(context).replace(
        b'"run_id":123456789', b'"run_id":123456789,"run_id":123456789'
    )
    path.write_bytes(duplicate)
    with pytest.raises(ValueError, match="duplicate"):
        load_approval_context(path)

    context["approved_by"] = "maintainer"
    path.write_bytes(canonical_json_bytes(context))
    with pytest.raises(ValueError, match="fields differ"):
        load_approval_context(path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema", True, "schema"),
        ("schema", 2, "schema"),
        ("approval_mode", "actor-assertion", "approval_mode"),
        ("review_model", "independent-review", "review_model"),
    ],
)
def test_fixed_schema_and_review_semantics_cannot_be_relabelled(
    field: str, value: object, message: str
):
    payload = _context().as_dict()
    payload[field] = value
    with pytest.raises(ValueError, match=message):
        validate_approval_context(payload)


def test_write_refuses_to_replace_existing_context(tmp_path: Path):
    output = tmp_path / "approval-context.json"
    output.write_bytes(b"existing")

    with pytest.raises(ValueError, match="could not be created"):
        write_approval_context(output, _context())
    assert output.read_bytes() == b"existing"


def test_create_cli_hashes_subject_and_emits_only_neutral_status(tmp_path: Path):
    subject = tmp_path / "compliance-evidence.json"
    subject.write_bytes(b'{"stable_release_eligible":true}\n')
    output = tmp_path / "approval-context.json"
    expected_subject_sha256 = hashlib.sha256(subject.read_bytes()).hexdigest()

    result = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "scripts" / "github_environment_approval.py"),
            "create",
            "--environment",
            "v9-trusted-signing",
            "--repository",
            REPOSITORY,
            "--workflow-ref",
            WORKFLOW_REF,
            "--release-commit",
            RELEASE_COMMIT,
            "--run-id",
            "123456789",
            "--run-attempt",
            "2",
            "--job",
            "prepare-installer-review",
            "--subject-kind",
            "compliance-evidence",
            "--subject",
            str(subject),
            "--generated-at-utc",
            "2026-08-30T12:34:56Z",
            "--output",
            str(output),
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "github-environment-approval: GENERATED\n"
    assert "player1314520" not in result.stdout
    loaded = load_approval_context(
        output,
        expected_subject_sha256=expected_subject_sha256,
        expected_subject_kind="compliance-evidence",
    )
    assert loaded.repository == REPOSITORY


def test_compliance_verifier_binds_context_and_github_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.syspath_prepend(str(PROJECT_ROOT / "scripts"))
    verifier = importlib.import_module("verify_compliance_evidence")
    captured: dict[str, object] = {}

    def fake_load(path: Path, **kwargs: object):
        captured["path"] = path
        captured.update(kwargs)
        return {}, {}, {}

    monkeypatch.setattr(verifier, "load_compliance_evidence", fake_load)
    paths = {
        name: tmp_path / name
        for name in (
            "evidence.json",
            "application-signing-request.json",
            "components.json",
            "application",
            "packages.txt",
            "THIRD_PARTY_NOTICES.md",
        )
    }
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "verify_compliance_evidence.py",
            "--evidence",
            str(paths["evidence.json"]),
            "--application-signing-request",
            str(paths["application-signing-request.json"]),
            "--expected-application-signing-request-sha256",
            "f" * 64,
            "--component-inventory",
            str(paths["components.json"]),
            "--application-root",
            str(paths["application"]),
            "--expected-sha256",
            SUBJECT_SHA256,
            "--commit",
            RELEASE_COMMIT,
            "--source-tree",
            "c" * 40,
            "--publisher",
            "DefenseTracker Community",
            "--packages-file",
            str(paths["packages.txt"]),
            "--third-party-notices",
            str(paths["THIRD_PARTY_NOTICES.md"]),
            "--runtime-lock-sha256",
            "d" * 64,
            "--build-lock-sha256",
            "e" * 64,
            "--verified-at-utc",
            "2026-08-30T12:35:00Z",
            "--github-repository",
            REPOSITORY,
            "--github-workflow-ref",
            WORKFLOW_REF,
            "--github-run-id",
            "123456789",
            "--github-run-attempt",
            "2",
        ],
    )

    assert verifier.main() == 0
    assert captured["application_signing_request_path"] == paths[
        "application-signing-request.json"
    ].resolve()
    assert captured["expected_application_signing_request_sha256"] == "f" * 64
    assert captured["expected_repository"] == REPOSITORY
    assert captured["expected_workflow_ref"] == WORKFLOW_REF
    assert captured["expected_run_id"] == 123456789
    assert captured["expected_run_attempt"] == 2
    assert captured["expected_sha256"] == SUBJECT_SHA256
    assert captured["commit"] == RELEASE_COMMIT
    assert capsys.readouterr().out == "compliance-evidence-pre-sign: PASS\n"


def test_compliance_verifier_has_no_actor_or_detached_signature_inputs():
    source = (PROJECT_ROOT / "scripts" / "verify_compliance_evidence.py").read_text(
        encoding="utf-8"
    )

    assert "--approval-context" not in source
    assert "--application-signing-request" in source
    assert "--evidence-signature" not in source
    assert "--reviewer-registry" not in source
    assert 'os.environ.get("GITHUB_ACTOR")' not in source
    assert "--github-actor" not in source
