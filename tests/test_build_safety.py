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


def test_new_runtime_modules_are_scoped_to_the_builds_that_use_them():
    builder = (PROJECT_ROOT / "scripts" / "build_app.py").read_text(
        encoding="utf-8"
    )
    server_dockerfile = (PROJECT_ROOT / "deploy" / "Dockerfile").read_text(
        encoding="utf-8"
    )
    server_dockerignore = (
        PROJECT_ROOT / "deploy" / "Dockerfile.dockerignore"
    ).read_text(encoding="utf-8")
    portal_context = (
        PROJECT_ROOT / "scripts" / "prepare_mvp_portal_context.py"
    ).read_text(encoding="utf-8")

    for module in (
        "desktop_single_instance",
        "isolated_document_parser",
        "upload_safety",
        "user_state",
    ):
        assert f'"{module}"' in builder

    for module in (
        "isolated_document_parser.py",
        "upload_safety.py",
        "user_state.py",
    ):
        assert module in server_dockerfile
        assert f"!{module}" in server_dockerignore

    assert "desktop_single_instance.py" not in server_dockerfile
    assert "!desktop_single_instance.py" not in server_dockerignore
    for module in (
        "desktop_single_instance.py",
        "isolated_document_parser.py",
        "upload_safety.py",
        "user_state.py",
    ):
        assert module not in portal_context


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
    assert "DEFENSE_TRACKER_COMPLIANCE_EVIDENCE_SHA256" in source
    assert "Legacy in-process signing is removed" in source
    assert "Invoke-SignAndVerify" not in source
    assert "PrepareUnsignedApplicationBundle" in source
    assert "signing_exchange.py" in source
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

    assert "Legacy in-process signing is removed" in stage_a
    assert "Invoke-SignAndVerify" not in stage_a + stage_b
    assert "signing_exchange.py') verify-return" in stage_b
    assert stage_b.count("--expected-job") == 2
    assert "Get-ReleasePublisherPolicy" in stage_b
    assert "Assert-ReleaseSignerCertificatePolicy" in stage_b
    assert "Invoke-InstallerLifecycleSmokeTest" in stage_b
    assert stage_b.index("--portable-inventory-only") < stage_b.index("Expand-Archive")
    package = stage_b.index("package_release_assets.py")
    assert stage_b.index("verify-return") < package
    for binding in (
        "--application-signing-request",
        "--application-signing-receipt",
        "--installer-signing-request",
        "--installer-signing-receipt",
        "--installer-review-request",
        "--installer-payload-root",
    ):
        assert binding in stage_b
    assert "--compliance-approval-context" not in stage_b


def test_candidate_workflow_separates_application_and_installer_trust_environments():
    application = (
        PROJECT_ROOT / ".github" / "workflows" / "v9-application-signing.yml"
    ).read_text(encoding="utf-8")
    installer = (
        PROJECT_ROOT / ".github" / "workflows" / "v9-signed-candidate.yml"
    ).read_text(encoding="utf-8")

    assert "sign-application:" in application
    assert "prepare-unsigned-installer:" in application
    assert "name: v9-trusted-signing" in application
    assert "name: v9-candidate-processing" in application
    assert "sign-installer:" in installer
    assert "finalize-signed-candidate:" in installer
    assert "name: v9-installer-signing-review" in installer
    assert "name: v9-candidate-processing" in installer
    assert "RELEASE_ARTIFACT_AGE_IDENTITY" in application + installer
    assert "application-signing-request.json" in application
    assert "installer-signing-request.json" in application + installer
    assert "actions/download-artifact@" in application + installer
    assert "candidate-transport-request.json" in application + installer
    assert "self-hosted" not in application + installer
    assert "github_environment_approval.py create" not in application + installer


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
