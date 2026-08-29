from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_WORKFLOW = ROOT / ".github" / "workflows" / "v9-signed-candidate.yml"
STABLE_WORKFLOW = ROOT / ".github" / "workflows" / "v9-stable-release.yml"


def _job_block(source: str, job: str, next_job: str | None = None) -> str:
    start = source.index(f"  {job}:\n")
    if next_job is None:
        return source[start:]
    end = source.index(f"  {next_job}:\n", start)
    return source[start:end]


def test_signing_isolation_gate_fails_before_any_credentialed_job():
    workflow = CANDIDATE_WORKFLOW.read_text(encoding="utf-8")
    gate = _job_block(workflow, "signing-isolation-gate", "verify-release-request")

    assert workflow.index("permissions: {}") < workflow.index("jobs:")
    assert "runs-on: ubuntu-24.04" in gate
    assert "permissions: {}" in gate
    assert '"schema":"defense-tracker/signing-isolation-blocker/v1"' in gate
    assert '"status":"blocked"' in gate
    assert '"code":"SIGNING_ISOLATION_NOT_PROVISIONED"' in gate
    assert "exit 78" in gate
    for forbidden in (
        "environment:",
        "self-hosted",
        "secrets.",
        "id-token: write",
        "Azure/login@",
        "actions/upload-artifact@",
    ):
        assert forbidden not in gate


def test_all_signing_environments_and_logins_are_downstream_of_failed_gate():
    workflow = CANDIDATE_WORKFLOW.read_text(encoding="utf-8")
    request = _job_block(workflow, "verify-release-request", "verify-source")
    verify = _job_block(workflow, "verify-source", "prepare-installer-review")
    prepare = _job_block(
        workflow, "prepare-installer-review", "finalize-signed-candidate"
    )
    finalize = _job_block(workflow, "finalize-signed-candidate")

    assert "      - signing-isolation-gate" in verify
    assert "needs: signing-isolation-gate" in request
    assert "      - verify-release-request" in verify
    assert "      - signing-isolation-gate" in prepare
    assert "      - verify-release-request" in prepare
    assert "      - verify-source" in prepare
    assert "      - prepare-installer-review" in finalize
    assert "environment: v9-trusted-signing" in prepare
    assert "environment: v9-installer-signing-review" in finalize
    assert "Azure/login@" in prepare
    assert "Azure/login@" in finalize
    assert workflow.index("exit 78") < workflow.index("environment: v9-trusted-signing")
    assert workflow.index("exit 78") < workflow.index(
        "environment: v9-installer-signing-review"
    )
    assert workflow.index("exit 78") < workflow.index("Azure/login@")
    assert "if: ${{ always() }}" not in prepare
    assert "if: ${{ always() }}" not in finalize


def test_protected_main_sha_is_resolved_before_any_checkout_or_source_execution():
    workflow = CANDIDATE_WORKFLOW.read_text(encoding="utf-8")
    request = _job_block(workflow, "verify-release-request", "verify-source")
    downstream = workflow[workflow.index("  verify-source:\n") :]

    assert "inputs:" not in workflow[: workflow.index("permissions: {}")]
    assert "inputs.release_sha" not in workflow
    assert "actions/checkout@" not in request
    assert 'expected_repository = "player1314520/defense-tracker-mvp"' in request
    assert "git/ref/heads/main" in request
    assert 'protected_main_sha != os.environ["WORKFLOW_SHA"]' in request
    assert "trusted_sha: ${{ steps.resolve.outputs.trusted_sha }}" in request
    assert "ref: ${{ needs.verify-release-request.outputs.trusted_sha }}" in downstream
    assert workflow.index("  verify-release-request:\n") < workflow.index(
        "actions/checkout@"
    )


def test_failed_candidate_run_cannot_satisfy_stable_release_provenance():
    candidate = CANDIDATE_WORKFLOW.read_text(encoding="utf-8")
    stable = STABLE_WORKFLOW.read_text(encoding="utf-8")

    assert "actions/upload-artifact@" not in _job_block(
        candidate, "signing-isolation-gate", "verify-release-request"
    )
    assert "$candidate.conclusion -ne 'success'" in stable
    assert "$candidate.path -ne '.github/workflows/v9-signed-candidate.yml'" in stable
    assert "run-id: ${{ inputs.candidate_run_id }}" in stable
    assert "name: DefenseTracker-v9.0.0-${{ inputs.release_sha }}" in stable
