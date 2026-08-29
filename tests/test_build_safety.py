# -*- coding: utf-8 -*-
"""P0 build scripts must remain deterministic and secret-free."""
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_builder_has_no_installer_or_user_data_preservation():
    source = (PROJECT_ROOT / "scripts" / "build_app.py").read_text(encoding="utf-8")

    assert '"pip", "install"' not in source
    assert "KEEP_FILES" not in source
    assert "KEEP_DIRS" not in source
    assert ".access_token" not in source
    assert ".ai_config.json" not in source
    assert "素材库" not in source
    assert "input(" not in source


def test_builder_targets_staging_and_never_replaces_release():
    source = (PROJECT_ROOT / "scripts" / "build_app.py").read_text(encoding="utf-8")

    assert "--distpath" in source
    assert "release-staging" in source
    assert 'os.path.join(BASE, "dist")' not in source


def test_build_gate_requires_isolated_python_and_full_release_checks():
    source = (PROJECT_ROOT / "scripts" / "Build-AndShip.ps1").read_text(
        encoding="utf-8-sig"
    )

    assert ".venv-build" in source
    assert "Get-ArtifactSafetyFindings" in source
    assert "Assert-WindowsPeFile" in source
    assert "release-manifest.json" in source
    assert "DEFENSE_TRACKER_SMOKE_EVIDENCE" in source
    assert "workspace_ready" in source
    assert "http_status" in source and "-eq 200" in source
    assert "Invoke-InstallerLifecycleSmokeTest" in source
    assert "Invoke-LegacyMigrationSmokeTest" in source
    assert "DEFENSE_TRACKER_COMPLIANCE_EVIDENCE" in source
    assert "DEFENSE_TRACKER_COMPLIANCE_SIGNATURE" in source
    assert "DEFENSE_TRACKER_COMPLIANCE_EVIDENCE_SHA256" in source
    assert source.index("verify_compliance_evidence.py") < source.index(
        "Invoke-SignAndVerify $stagedExe"
    )
    assert "portable-authenticated-workspace" in (
        PROJECT_ROOT / "scripts" / "finalize_release_assets.py"
    ).read_text(encoding="utf-8")
    assert "MainWindowTitle" in source
    launcher = (PROJECT_ROOT / "launcher.py").read_text(encoding="utf-8")
    assert "(49231, 49232, 49233, 49234, 49235)" in launcher
    assert "5000..5019" not in source + launcher
    assert '("releases\\" + $version.release_tag)' in source


def test_signed_candidate_is_two_stage_and_never_signs_installer_in_stage_a():
    stage_a = (PROJECT_ROOT / "scripts" / "Build-AndShip.ps1").read_text(
        encoding="utf-8-sig"
    )
    stage_b = (
        PROJECT_ROOT / "scripts" / "Finalize-SignedCandidate.ps1"
    ).read_text(encoding="utf-8-sig")

    assert "Single-stage signed release builds are disabled" in stage_a
    candidate_start = stage_a.index("if ($CandidateOnly) {", stage_a.index("$stagedInstaller"))
    candidate_end = stage_a.index("\n        return", candidate_start)
    candidate_block = stage_a[candidate_start:candidate_end]
    assert "authenticode_digest.py" in candidate_block
    assert "--require-state unsigned" in candidate_block
    assert "installer-review-request.json" in candidate_block
    assert "generate_installer_review_request.py" in candidate_block
    assert "candidate-preparations" in candidate_block
    assert "Invoke-SignAndVerify $stagedInstaller" not in candidate_block
    assert "package_release_assets.py" not in candidate_block
    assert candidate_block.index("$resolvedSevenZip x") < candidate_block.index(
        "generate_installer_review_request.py"
    )

    assert "Copy-Item -LiteralPath $unsignedInstaller -Destination $signedInstaller" in stage_b
    assert "Invoke-SignAndVerify $signedInstaller" in stage_b
    assert "Invoke-SignAndVerify $unsignedInstaller" not in stage_b
    assert "Application and installer reviews must use distinct registered Ed25519 keys" in stage_b
    pre_review = stage_b.index("installer_review.py') pre-sign")
    sign_installer = stage_b.index("$installerSignature = Invoke-SignAndVerify")
    post_review = stage_b.index("installer_review.py') post-sign")
    package = stage_b.index("package_release_assets.py")
    assert pre_review < sign_installer < post_review < package
    assert stage_b.index("Assert-PreparationBundle") < pre_review
    assert stage_b.index("--require-state signed", sign_installer) < post_review
    assert stage_b.index("Invoke-InstallerLifecycleSmokeTest", post_review) < package
    for binding in (
        "--installer-review-evidence",
        "--installer-review-signature",
        "--installer-reviewer-registry",
        "--unsigned-installer",
        "--installer-payload-root",
        "--application-reviewer-key-id",
    ):
        assert binding in stage_b


def test_candidate_workflow_separates_application_and_installer_trust_environments():
    workflow = (
        PROJECT_ROOT / ".github" / "workflows" / "v9-signed-candidate.yml"
    ).read_text(encoding="utf-8")

    assert "prepare-installer-review:" in workflow
    assert "finalize-signed-candidate:" in workflow
    assert (
        "needs:\n"
        "      - signing-isolation-gate\n"
        "      - verify-release-request\n"
        "      - prepare-installer-review"
    ) in workflow
    assert "environment: v9-trusted-signing" in workflow
    assert "environment: v9-installer-signing-review" in workflow
    assert "defense-v9-candidate-ephemeral" in workflow
    assert "defense-v9-installer-ephemeral" in workflow
    assert "actions/download-artifact@" in workflow
    assert "gh attestation verify" in workflow
    assert "DEFENSE_TRACKER_INSTALLER_REVIEW_EVIDENCE" in workflow
    assert "DEFENSE_TRACKER_INSTALLER_REVIEW_SIGNATURE" in workflow
    assert "DEFENSE_TRACKER_INSTALLER_REVIEW_EVIDENCE_SHA256" in workflow
    assert "      DEFENSE_TRACKER_PREPARATION_ARTIFACT_NAME: ${{ env." not in workflow
    workflow_lines = workflow.splitlines()
    preparation_root = (
        "PREPARATION_ROOT: ${{ runner.temp }}\\DefenseTracker-v9-preparation"
    )
    assert f"      {preparation_root}" not in workflow_lines
    assert workflow_lines.count(f"          {preparation_root}") == 2
    assert workflow.index("Attest candidate build provenance") < workflow.index(
        "Retain candidate preparation bundle"
    )
    assert workflow.index("Verify preparation run and every attested file") < workflow.index(
        "Finalize independently reviewed installer candidate"
    )


def test_build_environment_preparation_is_explicit_and_separate():
    source = (PROJECT_ROOT / "scripts" / "Prepare-BuildEnv.ps1").read_text(
        encoding="utf-8-sig"
    )

    assert ".venv-build" in source
    assert "requirements.build.lock" in source
    assert "scripts/build_app.py" not in source


def test_desktop_uses_ephemeral_webview_and_early_pdf_worker_dispatch():
    source = (PROJECT_ROOT / "launcher.py").read_text(encoding="utf-8")

    assert "private_mode=True" in source
    assert source.index("--defense-tracker-pdf-worker") < source.index("from app import")
    assert '"--pdf-worker-output"' in source
