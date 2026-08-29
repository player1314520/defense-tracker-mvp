from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_shared_certificate_policy_pins_full_identity_and_bounded_rotation():
    policy = _read("scripts/ReleaseCertificatePolicy.ps1")

    assert "[ValidateRange(1, 4)][int]$MaximumCount = 4" in policy
    assert "ConvertTo-NormalizedX500Name" in policy
    assert "a CN-only name is rejected" in policy
    assert "Get-CertificateSpkiSha256" in policy
    assert "ExportSubjectPublicKeyInfo" in policy
    assert "Subject/SPKI is outside the protected ordered allowlist" in policy
    assert "Issuer/root allowlists must contain one shared pin" in policy
    assert "RevocationMode]::Online" in policy
    assert "RequireCodeSigningEku" in policy
    assert "root_sha256 = Get-CertificateSha256" in policy


def test_stable_authenticode_gate_uses_shared_pins_and_hash_pinned_signtool():
    verifier = _read("scripts/Verify-ReleaseAuthenticode.ps1")

    for parameter in (
        "ExpectedSignToolSha256",
        "ExpectedSignerSubjects",
        "ExpectedSignerSpkiSha256",
        "ExpectedSignerIssuers",
        "ExpectedSignerRootSha256",
    ):
        assert f"[Parameter(Mandatory = $true)][string]${parameter}" in verifier
    assert ". (Join-Path $PSScriptRoot 'ReleaseCertificatePolicy.ps1')" in verifier
    assert "Get-ReleaseCertificatePolicy" in verifier
    assert "Assert-ReleaseSignerCertificatePolicy" in verifier
    assert "Get-FileHash -LiteralPath $tool -Algorithm SHA256" in verifier
    assert "Installer and portable application were not signed by the same pinned identity" in verifier
    assert "Assert-TrustedCertificateChain $signature.TimeStamperCertificate" in verifier


def test_finalizer_pins_digicert_public_certificate_and_reuses_identity_policy():
    finalizer = _read("scripts/Finalize-SignedCandidate.ps1")

    for variable in (
        "DEFENSE_TRACKER_DIGICERT_CERT_FILE_SHA256",
        "DEFENSE_TRACKER_EXPECTED_SIGNER_SUBJECTS",
        "DEFENSE_TRACKER_EXPECTED_SIGNER_SPKI_SHA256",
        "DEFENSE_TRACKER_EXPECTED_SIGNER_ISSUERS",
        "DEFENSE_TRACKER_EXPECTED_SIGNER_ROOT_SHA256",
    ):
        assert variable in finalizer
    assert "Assert-DigiCertCertificateFilePolicy" in finalizer
    assert "Get-ReleaseCertificatePolicy" in finalizer
    assert "Assert-ReleaseSignerCertificatePolicy" in finalizer
    assert "Application and installer were not signed by the same pinned certificate identity" in finalizer
    assert "function Assert-CertificateChain" not in finalizer


def test_stable_workflow_requires_protected_certificate_policy_inputs():
    workflow = _read(".github/workflows/v9-stable-release.yml")

    for variable in (
        "DEFENSE_TRACKER_SIGNTOOL_SHA256",
        "DEFENSE_TRACKER_EXPECTED_SIGNER_SUBJECTS",
        "DEFENSE_TRACKER_EXPECTED_SIGNER_SPKI_SHA256",
        "DEFENSE_TRACKER_EXPECTED_SIGNER_ISSUERS",
        "DEFENSE_TRACKER_EXPECTED_SIGNER_ROOT_SHA256",
    ):
        assert f"{variable}: ${{{{ vars.{variable} }}}}" in workflow
    assert "-ExpectedSignToolSha256 $env:DEFENSE_TRACKER_SIGNTOOL_SHA256" in workflow
    assert "-ExpectedSignerSubjects $env:DEFENSE_TRACKER_EXPECTED_SIGNER_SUBJECTS" in workflow
    assert "-ExpectedSignerSpkiSha256 $env:DEFENSE_TRACKER_EXPECTED_SIGNER_SPKI_SHA256" in workflow
    assert "-ExpectedSignerIssuers $env:DEFENSE_TRACKER_EXPECTED_SIGNER_ISSUERS" in workflow
    assert "-ExpectedSignerRootSha256 $env:DEFENSE_TRACKER_EXPECTED_SIGNER_ROOT_SHA256" in workflow


def test_stable_release_rechecks_fixed_remote_bytes_around_immutability():
    workflow = _read(".github/workflows/v9-stable-release.yml")
    fixed_names = (
        "DefenseTracker-Setup-v9.0.0-windows-x64.exe",
        "DefenseTracker-v9.0.0-windows-x64-portable.zip",
        "DefenseTracker-v9.0.0.spdx.json",
        "SHA256SUMS.txt",
        "THIRD_PARTY_NOTICES.md",
        "release-manifest.json",
    )
    for name in fixed_names:
        assert workflow.count(f'"{name}"') == 1

    draft_create = workflow.index("gh release create $tag --draft")
    draft_api = workflow.index("Assert-RemoteReleaseAssets $draft 'draft'")
    draft_download = workflow.index("Assert-DownloadedReleaseAssets $tag 'draft'")
    publish = workflow.index("gh release edit $tag --draft=false --latest")
    before_api = workflow.index(
        "Assert-RemoteReleaseAssets $publishedBeforeImmutableCheck"
    )
    before_download = workflow.index(
        "Assert-DownloadedReleaseAssets $tag 'published-before-immutable-check'"
    )
    immutable = workflow.index("$publishedBeforeImmutableCheck.immutable -ne $true")
    after_api = workflow.index(
        "Assert-RemoteReleaseAssets $publishedAfterImmutableCheck"
    )
    after_download = workflow.index(
        "Assert-DownloadedReleaseAssets $tag 'published-after-immutable-check'"
    )
    assert (
        draft_create
        < draft_api
        < draft_download
        < publish
        < before_api
        < before_download
        < immutable
        < after_api
        < after_download
    )
    assert "[string]$asset.digest -cne [string]$expected.digest" in workflow
    assert "Get-FileHash -LiteralPath $path -Algorithm SHA256" in workflow


def test_release_security_document_states_non_atomic_unique_writer_boundary():
    document = _read("docs/V9_STABLE_RELEASE_SECURITY.md")

    assert "唯一 writer" in document
    assert "不是" in document or "没有" in document
    assert "immutable" in document
    assert "补丁版本" in document
    assert document.count("- ") >= 9
