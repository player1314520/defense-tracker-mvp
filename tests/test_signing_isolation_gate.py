from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PREPARATION = ROOT / ".github" / "workflows" / "v9-release-preparation.yml"
APPLICATION = ROOT / ".github" / "workflows" / "v9-application-signing.yml"
INSTALLER = ROOT / ".github" / "workflows" / "v9-signed-candidate.yml"
STABLE = ROOT / ".github" / "workflows" / "v9-stable-release.yml"


def _job(source: str, name: str, next_name: str | None = None) -> str:
    start = source.index(f"  {name}:\n")
    if next_name is None:
        return source[start:]
    return source[start : source.index(f"  {next_name}:\n", start)]


def test_release_chain_has_no_self_hosted_or_permanent_blocker():
    for path in (PREPARATION, APPLICATION, INSTALLER, STABLE):
        source = path.read_text(encoding="utf-8")
        assert "permissions: {}" in source[: source.index("jobs:")]
        assert "runs-on: [self-hosted" not in source
        assert "runs-on: self-hosted" not in source
        assert "signing-isolation-gate" not in source
        assert "SIGNING_ISOLATION_NOT_PROVISIONED" not in source
        assert "exit 78" not in source
    assert APPLICATION.read_text().count("runs-on: windows-2022") == 3
    assert INSTALLER.read_text().count("runs-on: windows-2022") == 2


def test_each_signer_is_independent_exact_input_dispatch_after_public_request():
    application = APPLICATION.read_text(encoding="utf-8")
    installer = INSTALLER.read_text(encoding="utf-8")
    preparation = PREPARATION.read_text(encoding="utf-8")
    for source in (application, installer):
        dispatch = source[: source.index("permissions: {}")]
        assert "workflow_dispatch:" in dispatch
        assert "run_id:" in dispatch
        assert "artifact" in dispatch and "digest" in dispatch
        assert "signing_request_sha256:" in dispatch
        assert "release_sha:" in dispatch
    assert "application-signing-request.json" in preparation
    assert "installer-signing-request.json" in application
    assert "environment:\n      name: v9-trusted-signing" in application
    assert "url: https://github.com/${{ github.repository }}/actions/runs/${{ inputs.preparation_run_id }}" in application
    assert "environment:\n      name: v9-installer-signing-review" in installer
    assert "url: https://github.com/${{ github.repository }}/actions/runs/${{ inputs.application_run_id }}" in installer


def test_signer_jobs_never_checkout_or_execute_project_build_code():
    application = APPLICATION.read_text(encoding="utf-8")
    installer = INSTALLER.read_text(encoding="utf-8")
    app_signer = _job(application, "sign-application", "prepare-unsigned-installer")
    installer_signer = _job(installer, "sign-installer", "finalize-signed-candidate")
    forbidden = (
        "actions/checkout@",
        "actions/setup-python@",
        "pip ",
        "scripts\\",
        "ISCC",
        "7z.exe",
        "Defender",
        "Start-Process",
    )
    for signer in (app_signer, installer_signer):
        for token in forbidden:
            assert token not in signer
        assert "SIGNTOOL_EXE sign" in signer
        assert "Get-FileHash $env:TARGET_PATH" in signer
        assert "publisher-policy.json" in signer
        assert "approved" in signer
        assert "RELEASE_ARTIFACT_AGE_IDENTITY" in signer


def test_python_release_scripts_run_only_after_hash_locked_bootstrap():
    application = APPLICATION.read_text(encoding="utf-8")
    stable = STABLE.read_text(encoding="utf-8")
    app_verify = _job(application, "verify-preparation-and-compliance", "sign-application")
    stable_verify = _job(stable, "verify-promotion", "publish-stable-release")

    for job, first_script in (
        (app_verify, ".\\scripts\\Verify-ApplicationSigningPreparation.ps1"),
        (stable_verify, "python scripts\\verify_release_checks.py"),
    ):
        install = job.index(
            "python -m pip install --disable-pip-version-check --require-hashes "
            "--only-binary=:all: -r requirements.bootstrap.lock"
        )
        check = job.index("python -m pip check", install)
        assert install < check < job.index(first_script)

    app_signer = _job(application, "sign-application", "prepare-unsigned-installer")
    installer = INSTALLER.read_text(encoding="utf-8")
    installer_signer = _job(installer, "sign-installer", "finalize-signed-candidate")
    for signer in (app_signer, installer_signer):
        assert "requirements.bootstrap.lock" not in signer
        assert "python -m pip" not in signer


def test_signers_pin_provider_policy_before_any_digicert_authentication():
    application = APPLICATION.read_text(encoding="utf-8")
    installer = INSTALLER.read_text(encoding="utf-8")
    app_signer = _job(application, "sign-application", "prepare-unsigned-installer")
    installer_signer = _job(installer, "sign-installer", "finalize-signed-candidate")
    for signer in (app_signer, installer_signer):
        policy_gate = signer.index("$providerPolicy.sm_host")
        materialize = signer.index("DIGICERT_SIGNING_CERT_FILE_B64")
        authenticate = signer.index("DIGICERT_SM_API_KEY")
        assert policy_gate < materialize < authenticate
        assert "$providerPolicy.key_alias" in signer
        assert "$providerPolicy.certificate_file_sha256" in signer
        assert "DIGICERT_CERTIFICATE_FILE_SHA256" in signer
        assert "VALIDATED_DIGICERT_KEY_ALIAS" in signer
        assert "public certificate differs from" in signer
        assert "1.3.6.1.4.1.311.97.1.0" in signer
        assert "1.3.6.1.4.1.311.10.3.13" in signer
        assert "timestamp_verified_at_utc" in signer
        assert "digicert_sm_host" in signer
        assert "digicert_key_alias" in signer


def test_finalizer_receives_exact_cross_workflow_receipt_identities():
    installer = INSTALLER.read_text(encoding="utf-8")
    finalizer = _job(installer, "finalize-signed-candidate")
    for parameter in (
        "ExpectedApplicationSigningReceiptSha256",
        "ExpectedInstallerSigningReceiptSha256",
        "ExpectedApplicationRunId",
        "ExpectedApplicationRunAttempt",
        "ExpectedPublisherPolicySha256",
    ):
        assert f"-{parameter}" in finalizer


def test_age_identity_is_step_scoped_and_deleted():
    for path in (APPLICATION, INSTALLER, STABLE):
        source = path.read_text(encoding="utf-8")
        assert "secrets.RELEASE_ARTIFACT_AGE_IDENTITY" in source
        assert "DEFENSE_TRACKER_CANDIDATE_AGE_IDENTITY" not in source
        for block in source.split("CANDIDATE_AGE_IDENTITY:")[1:]:
            step = block.split("\n      - name:", 1)[0]
            assert "Remove-Item" in step


def test_public_binary_artifacts_are_age_encrypted():
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (PREPARATION, APPLICATION, INSTALLER, STABLE)
    )
    assert "candidate-transport-request.json" in combined
    assert "candidate-transport-receipt.json" in combined
    assert "--encrypt --recipients-file" in combined or "Protect-ReleaseArtifact.ps1" in combined
    assert "candidate-envelope\\*" in combined
    assert "path: ${{ env.OUTPUT_ROOT }}\\release-assets\\*" not in combined
    assert "path: dist/candidates" not in combined


def test_stable_release_is_read_only_verify_then_publish_only():
    stable = STABLE.read_text(encoding="utf-8")
    verify = _job(stable, "verify-promotion", "publish-stable-release")
    publish = _job(stable, "publish-stable-release")
    assert "contents: write" not in verify
    assert "promotion-request.json" in verify
    assert "needs: verify-promotion" in publish
    assert "environment:\n      name: v9-production-release" in publish
    assert "contents: write" in publish
    assert "actions/checkout@" not in publish
    assert "actions/setup-python@" not in publish
    assert "scripts\\" not in publish
    assert "PROMOTION_REQUEST_SHA256" in publish
    assert "immutable-releases" in publish
    assert "gh release create" in publish
    assert "published.immutable-ne$true" in publish
    assert "candidate_artifact_digest-cne$env:CANDIDATE_ARTIFACT_DIGEST" in publish
    assert "candidate_run_attempt-cne$env:CANDIDATE_RUN_ATTEMPT" in publish
    assert "deployment_evidence_run_id-cne$env:DEPLOYMENT_EVIDENCE_RUN_ID" in publish
    assert "deployment_evidence_run_attempt-cne$env:DEPLOYMENT_EVIDENCE_RUN_ATTEMPT" in publish
    assert "portal_image_digest-cne$env:PORTAL_IMAGE_DIGEST" in publish
    assert "portal_image_run_id-cne$env:PORTAL_IMAGE_RUN_ID" in publish
    assert "portal_image_run_attempt-cne$env:PORTAL_IMAGE_RUN_ATTEMPT" in publish
    assert "Candidate source artifact digest changed before publication" in publish


def test_stable_promotion_binds_exact_production_run_attempts_and_schema():
    stable = STABLE.read_text(encoding="utf-8")
    dispatch = stable[: stable.index("permissions: {}")]
    verify = _job(stable, "verify-promotion", "publish-stable-release")
    publish = _job(stable, "publish-stable-release")
    for name in (
        "deployment_evidence_run_attempt",
        "portal_image_run_attempt",
    ):
        assert f"      {name}:" in dispatch
        assert name in verify
        assert name in publish
    assert "([string]$run.run_attempt) -cne ([string]$spec.attempt)" in verify
    assert "The artifact API has no run_attempt field" in verify
    assert "created_at" in verify and "updated_at" in verify and "run_started_at" in verify
    assert "Promotion request schema has unexpected or missing fields" in publish
    assert "Promotion request asset schema is malformed" in publish
