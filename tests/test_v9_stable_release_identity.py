from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_shared_certificate_policy_uses_provider_specific_durable_identity():
    policy = _read("scripts/ReleaseCertificatePolicy.ps1")

    assert "[ValidateRange(1, 4)][int]$MaximumCount = 4" in policy
    assert "ConvertTo-NormalizedX500Name" in policy
    assert "a CN-only name is rejected" in policy
    assert "Get-CertificateSpkiSha256" in policy
    assert "ExportSubjectPublicKeyInfo" in policy
    assert "Get-ReleasePublisherPolicy" in policy
    assert "Azure Artifact Signing durable identity EKU is missing" in policy
    assert "1.3.6.1.4.1.311.97.1.0" in policy
    assert "1.3.6.1.4.1.311.10.3.13" in policy
    assert "leaf SPKI is evidence only" in policy
    assert "DigiCert signer certificate Subject/SPKI is outside" in policy
    assert "Issuer/root allowlists must contain one shared pin" in policy
    assert "RevocationMode]::Online" in policy
    assert "RequireCodeSigningEku" in policy
    assert "root_sha256 = Get-CertificateSha256" in policy


def test_stable_authenticode_gate_uses_committed_policy_and_hash_pinned_signtool():
    verifier = _read("scripts/Verify-ReleaseAuthenticode.ps1")

    for parameter in (
        "PolicyPath",
        "ExpectedSignToolSha256",
    ):
        assert f"[Parameter(Mandatory = $true)][string]${parameter}" in verifier
    assert "[string]$SigningProvider" in verifier
    assert ". (Join-Path $PSScriptRoot 'ReleaseCertificatePolicy.ps1')" in verifier
    assert "Get-ReleasePublisherPolicy" in verifier
    assert "Assert-ReleaseSignerCertificatePolicy" in verifier
    assert "Get-FileHash -LiteralPath $tool -Algorithm SHA256" in verifier
    assert "durable Publisher EKU" in verifier
    assert "pinned certificate identity" in verifier
    assert "leaf_spki_policy -ceq 'record-only'" in verifier
    assert "Assert-TrustedCertificateChain $signature.TimeStamperCertificate" in verifier


def test_finalizer_pins_digicert_public_certificate_and_reuses_identity_policy():
    finalizer = _read("scripts/Finalize-SignedCandidate.ps1")

    assert "ExpectedPublisherPolicySha256" in finalizer
    assert "ExpectedApplicationSigningReceiptSha256" in finalizer
    assert "ExpectedInstallerSigningReceiptSha256" in finalizer
    assert "Get-ReleasePublisherPolicy" in finalizer
    assert "Assert-ReleaseSignerCertificatePolicy" in finalizer
    assert "DigiCert certificates differ across stages" in finalizer
    assert "digicert_sm_host" in finalizer and "digicert_key_alias" in finalizer
    assert "Invoke-SignAndVerify" not in finalizer
    assert "function Assert-CertificateChain" not in finalizer


def test_stage_a_build_reuses_full_certificate_policy_before_any_signing():
    stage_a = _read("scripts/Build-AndShip.ps1")

    for variable in (
        "DEFENSE_TRACKER_DIGICERT_CERT_FILE_SHA256",
        "DEFENSE_TRACKER_EXPECTED_SIGNER_SUBJECTS",
        "DEFENSE_TRACKER_EXPECTED_SIGNER_SPKI_SHA256",
        "DEFENSE_TRACKER_EXPECTED_SIGNER_ISSUERS",
        "DEFENSE_TRACKER_EXPECTED_SIGNER_ROOT_SHA256",
    ):
        assert variable in stage_a
    assert ". (Join-Path $PSScriptRoot 'ReleaseCertificatePolicy.ps1')" in stage_a

    assert "Legacy in-process signing is removed" in stage_a
    assert "Invoke-SignAndVerify" not in stage_a
    assert "Get-ReleasePublisherPolicy" in stage_a
    assert "PrepareUnsignedApplicationBundle" in stage_a
    assert "signing_exchange.py') create-request" in stage_a
    assert "function Assert-CertificateChain" not in stage_a


def test_stage_a_digicert_identity_and_file_hash_fail_before_signing():
    stage_a = _read("scripts/Build-AndShip.ps1")

    assert "Legacy in-process signing is removed" in stage_a
    assert stage_a.index("if ($RequireSignedInstaller -or $CandidateOnly)") < stage_a.index(
        "function Get-Sha256"
    )
    assert "Invoke-SignAndVerify" not in stage_a


def test_stable_workflow_uses_committed_publisher_policy_not_mutable_identity_vars():
    workflow = _read(".github/workflows/v9-stable-release.yml")

    for obsolete_variable in (
        "DEFENSE_TRACKER_EXPECTED_SIGNER_SUBJECTS",
        "DEFENSE_TRACKER_EXPECTED_SIGNER_SPKI_SHA256",
        "DEFENSE_TRACKER_EXPECTED_SIGNER_ISSUERS",
        "DEFENSE_TRACKER_EXPECTED_SIGNER_ROOT_SHA256",
    ):
        assert f"vars.{obsolete_variable}" not in workflow
    assert (
        ".\\scripts\\Initialize-GitHubHostedReleaseTools.ps1 -Mode VerificationOnly"
        in workflow
    )
    assert "release\\publisher-policy.json" in workflow
    assert "-PolicyPath .\\release\\publisher-policy.json" in workflow
    assert "-SigningProvider $policy.active_provider" in workflow
    assert "-ExpectedSignToolSha256 $env:DEFENSE_TRACKER_SIGNTOOL_SHA256" in workflow


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
        assert name in workflow

    verify = workflow.index("verify-promotion:")
    promotion = workflow.index("promotion-request.json", verify)
    publish_job = workflow.index("publish-stable-release:")
    draft_create = workflow.index("gh release create", publish_job)
    publish = workflow.index("gh release edit", draft_create)
    immutable = workflow.index("published.immutable-ne$true", publish)
    assert verify < promotion < publish_job < draft_create < publish < immutable
    assert "Get-FileHash $local.FullName -Algorithm SHA256" in workflow
    assert "item.digest-cne$digest" in workflow
    assert "Resolve-RemoteTagCommit" in workflow
    assert "Release tag already exists and will never be reused" not in workflow


def test_stable_release_only_resumes_its_exact_unchanged_draft():
    workflow = _read(".github/workflows/v9-stable-release.yml")

    assert "Invoke-WebRequest -SkipHttpErrorCheck" in workflow
    assert "DefenseTracker-Stable-Workflow: .github/workflows/v9-stable-release.yml" in workflow
    assert "release.draft-eq$true" in workflow
    assert "release.tag_name-cne$tag" in workflow
    assert "release.target_commitish-cne$env:RELEASE_SHA" in workflow
    assert "release.author.login-cne'github-actions[bot]'" in workflow
    assert "Existing draft lacks the exact workflow ownership and input binding" in workflow
    assert "contains an unapproved asset" in workflow
    assert 'remote mismatch: $($item.name)' in workflow
    assert "A release tag exists without the exact resumable draft" in workflow
    assert "Assert-RemoteAssets $release $false 'Draft'" in workflow
    assert "Where-Object{$remoteNames -cnotcontains $_.Name}" in workflow
    assert "&gh @uploadArgs" in workflow
    assert "--clobber" not in workflow
    assert "Assert-RemoteAssets $release $true 'Draft'" in workflow
    assert "draftTagResponse.StatusCode-eq200" in workflow
    assert "draftTagResponse.StatusCode-ne404" in workflow
    assert "elseif($release.draft-eq$false)" in workflow
    assert "Assert-RemoteAssets $published $true 'Published'" in workflow


def test_release_security_document_states_non_atomic_unique_writer_boundary():
    document = _read("docs/V9_STABLE_RELEASE_SECURITY.md")

    assert "唯一 writer" in document
    assert "不是" in document or "没有" in document
    assert "immutable" in document
    assert "补丁版本" in document
    assert document.count("- ") >= 4
