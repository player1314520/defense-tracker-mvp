import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "release" / "publisher-policy.json"


def _run_powershell(source: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            source,
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def test_committed_publisher_policy_is_explicitly_pending_without_fake_identity():
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))

    assert policy["schema_version"] == 1
    assert policy["status"] == "pending"
    assert policy["publisher"] is None
    assert policy["active_provider"] is None
    assert set(policy["providers"]) == {
        "AzureArtifactSigning",
        "DigiCertKeyLocker",
    }
    azure = policy["providers"]["AzureArtifactSigning"]
    assert azure["status"] == "pending"
    assert azure["endpoint"] is None
    assert azure["account_name"] is None
    assert azure["certificate_profile_name"] is None
    assert azure["expected_subjects"] == []
    assert azure["expected_issuers"] == []
    assert azure["expected_root_sha256"] == []
    assert azure["durable_identity_eku"] is None
    assert azure["leaf_spki_policy"] == "record-only"
    assert "expected_spki_sha256" not in azure
    digicert = policy["providers"]["DigiCertKeyLocker"]
    assert digicert["status"] == "pending"
    assert digicert["sm_host"] is None
    assert digicert["key_alias"] is None
    assert digicert["certificate_file_sha256"] is None
    assert digicert["expected_spki_sha256"] == []
    assert digicert["leaf_spki_policy"] == "required-pin"


def test_policy_schema_encodes_distinct_azure_and_digicert_identity_models():
    schema = json.loads(
        (ROOT / "release" / "publisher-policy.schema.json").read_text(
            encoding="utf-8"
        )
    )

    serialized = json.dumps(schema, sort_keys=True)
    assert "record-only" in serialized
    assert "required-pin" in serialized
    assert "durable_identity_eku" in serialized
    assert "certificate_file_sha256" in serialized
    assert "sm_host" in serialized
    assert "key_alias" in serialized
    assert "1.3.6.1.4.1.311.97.1.0" in serialized
    assert "1.3.6.1.5.5.7.3.3" in serialized



def test_pending_policy_fails_closed_before_provider_configuration_is_used():
    command = (
        ". .\\scripts\\ReleaseCertificatePolicy.ps1; "
        "Get-ReleasePublisherPolicy -Path .\\release\\publisher-policy.json "
        "-SigningProvider AzureArtifactSigning"
    )
    result = _run_powershell(command)

    assert result.returncode != 0
    assert "pending" in (result.stderr + result.stdout).lower()


def test_azure_policy_binds_exact_account_profile_and_endpoint_metadata(tmp_path: Path):
    policy = {
        "$schema": "./publisher-policy.schema.json",
        "schema_version": 1,
        "status": "approved",
        "publisher": "Example Test Publisher",
        "active_provider": "AzureArtifactSigning",
        "providers": {
            "AzureArtifactSigning": {
                "status": "approved",
                "endpoint": "https://eus.codesigning.azure.net/",
                "account_name": "example-test-account",
                "certificate_profile_name": "example-test-profile",
                "expected_subjects": [
                    "CN=Example Test Publisher, O=Example Test Organization"
                ],
                "expected_issuers": [
                    "CN=Example Test Issuer, O=Example Test CA"
                ],
                "expected_root_sha256": ["a" * 64],
                "durable_identity_eku": (
                    "1.3.6.1.4.1.311.97.990309390.766961637.194916062.941502583"
                ),
                "public_trust_eku": "1.3.6.1.4.1.311.97.1.0",
                "code_signing_eku": "1.3.6.1.5.5.7.3.3",
                "forbidden_test_eku": "1.3.6.1.4.1.311.10.3.13",
                "leaf_spki_policy": "record-only",
            },
            "DigiCertKeyLocker": {
                "status": "pending",
                "sm_host": None,
                "key_alias": None,
                "certificate_file_sha256": None,
                "expected_subjects": [],
                "expected_spki_sha256": [],
                "expected_issuers": [],
                "expected_root_sha256": [],
                "code_signing_eku": "1.3.6.1.5.5.7.3.3",
                "leaf_spki_policy": "required-pin",
            },
        },
    }
    policy_path = tmp_path / "policy.json"
    metadata_path = tmp_path / "metadata.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    metadata_path.write_text(
        json.dumps(
            {
                "Endpoint": "https://eus.codesigning.azure.net/",
                "CodeSigningAccountName": "example-test-account",
                "CertificateProfileName": "example-test-profile",
                "CorrelationId": "owner/repo/1/1/" + "b" * 40,
            }
        ),
        encoding="utf-8",
    )
    command = (
        ". .\\scripts\\ReleaseCertificatePolicy.ps1; "
        f"$p = Get-ReleasePublisherPolicy -Path '{policy_path}' "
        "-SigningProvider AzureArtifactSigning "
        f"-AzureMetadataPath '{metadata_path}'; "
        "$e = Get-ReleasePublisherPolicyEvidence $p; "
        "if ($p.azure.account_name -cne 'example-test-account' -or "
        "$e.azure_account_name -cne 'example-test-account' -or "
        "$e.leaf_spki_policy -cne 'record-only') { exit 9 }"
    )
    result = _run_powershell(command)
    assert result.returncode == 0, result.stderr + result.stdout

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["CodeSigningAccountName"] = "different-account"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    result = _run_powershell(command)
    assert result.returncode != 0
    assert "metadata" in (result.stderr + result.stdout).lower()


def test_digicert_policy_binds_sm_host_key_alias_and_certificate_hash(tmp_path: Path):
    policy = {
        "$schema": "./publisher-policy.schema.json",
        "schema_version": 1,
        "status": "approved",
        "publisher": "Example Test Publisher",
        "active_provider": "DigiCertKeyLocker",
        "providers": {
            "AzureArtifactSigning": {
                "status": "pending",
                "endpoint": None,
                "account_name": None,
                "certificate_profile_name": None,
                "expected_subjects": [],
                "expected_issuers": [],
                "expected_root_sha256": [],
                "durable_identity_eku": None,
                "public_trust_eku": "1.3.6.1.4.1.311.97.1.0",
                "code_signing_eku": "1.3.6.1.5.5.7.3.3",
                "forbidden_test_eku": "1.3.6.1.4.1.311.10.3.13",
                "leaf_spki_policy": "record-only",
            },
            "DigiCertKeyLocker": {
                "status": "approved",
                "sm_host": "https://clientauth.example.test/",
                "key_alias": "example-test-key",
                "certificate_file_sha256": "b" * 64,
                "expected_subjects": [
                    "CN=Example Test Publisher, O=Example Test Organization"
                ],
                "expected_spki_sha256": ["c" * 64],
                "expected_issuers": [
                    "CN=Example Test Issuer, O=Example Test CA"
                ],
                "expected_root_sha256": ["d" * 64],
                "code_signing_eku": "1.3.6.1.5.5.7.3.3",
                "leaf_spki_policy": "required-pin",
            },
        },
    }
    policy_path = tmp_path / "digicert-policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    command = (
        ". .\\scripts\\ReleaseCertificatePolicy.ps1; "
        f"$p = Get-ReleasePublisherPolicy -Path '{policy_path}' "
        "-SigningProvider DigiCertKeyLocker "
        "-DigiCertSmHost 'https://clientauth.example.test/' "
        "-DigiCertKeyAlias 'example-test-key'; "
        "$e = Get-ReleasePublisherPolicyEvidence $p; "
        "if ($e.digicert_sm_host -cne 'https://clientauth.example.test/' -or "
        "$e.digicert_key_alias -cne 'example-test-key' -or "
        "$p.digicert.certificate_file_sha256 -cne ('b' * 64)) { exit 9 }"
    )
    result = _run_powershell(command)
    assert result.returncode == 0, result.stderr + result.stdout

    wrong_host = command.replace(
        "-DigiCertSmHost 'https://clientauth.example.test/'",
        "-DigiCertSmHost 'https://different.example.test/'",
    )
    result = _run_powershell(wrong_host)
    assert result.returncode != 0
    assert "sm host" in (result.stderr + result.stdout).lower()

    wrong_alias = command.replace(
        "-DigiCertKeyAlias 'example-test-key'",
        "-DigiCertKeyAlias 'different-test-key'",
    )
    result = _run_powershell(wrong_alias)
    assert result.returncode != 0
    assert "key alias" in (result.stderr + result.stdout).lower()


def test_azure_accepts_rotated_leaf_spki_but_digicert_does_not():
    script = r"""
$ErrorActionPreference = 'Stop'
. .\scripts\ReleaseCertificatePolicy.ps1

function New-TestCertificate([string[]]$Ekus) {
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=Example Test Publisher, O=Example Test Organization',
        $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $oids = New-Object System.Security.Cryptography.OidCollection
    foreach ($oid in $Ekus) { $null = $oids.Add([System.Security.Cryptography.Oid]::new($oid)) }
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids, $true)
    )
    $certificate = $request.CreateSelfSigned(
        [DateTimeOffset]::UtcNow.AddMinutes(-1),
        [DateTimeOffset]::UtcNow.AddHours(1)
    )
    return [ordered]@{ certificate = $certificate; key = $rsa }
}

$durable = '1.3.6.1.4.1.311.97.990309390.766961637.194916062.941502583'
$ekus = @('1.3.6.1.5.5.7.3.3', '1.3.6.1.4.1.311.97.1.0', $durable)
$first = New-TestCertificate $ekus
$rotated = New-TestCertificate $ekus
$subject = ConvertTo-NormalizedX500Name $first.certificate.SubjectName
$issuer = ConvertTo-NormalizedX500Name 'CN=Example Test Issuer, O=Example Test CA'
$root = 'a' * 64
function Assert-TrustedCertificateChain { return [ordered]@{ issuer_subject = $issuer; root_sha256 = $root } }

try {
    $azure = [ordered]@{
        provider = 'AzureArtifactSigning'; publisher = 'Example Test Publisher'
        subjects = @($subject); issuers = @($issuer); root_sha256 = @($root)
        spki_sha256 = @(); leaf_spki_policy = 'record-only'
        required_eku_oids = @('1.3.6.1.5.5.7.3.3', '1.3.6.1.4.1.311.97.1.0', $durable)
        forbidden_eku_oids = @('1.3.6.1.4.1.311.10.3.13')
        azure = [ordered]@{ durable_identity_eku = $durable }
    }
    $firstIdentity = Assert-ReleaseSignerCertificatePolicy $first.certificate $azure
    $rotatedIdentity = Assert-ReleaseSignerCertificatePolicy $rotated.certificate $azure
    if ($firstIdentity.spki_sha256 -ceq $rotatedIdentity.spki_sha256) { throw 'Test keys did not rotate.' }
    if ($rotatedIdentity.leaf_spki_policy -cne 'record-only') { throw 'Azure SPKI policy is wrong.' }

    $digicert = [ordered]@{
        provider = 'DigiCertKeyLocker'; publisher = 'Example Test Publisher'
        subjects = @($subject); issuers = @($issuer); root_sha256 = @($root)
        spki_sha256 = @(Get-CertificateSpkiSha256 $first.certificate)
        leaf_spki_policy = 'required-pin'; required_eku_oids = @('1.3.6.1.5.5.7.3.3')
        forbidden_eku_oids = @(); digicert = [ordered]@{ certificate_file_sha256 = ('b' * 64) }
    }
    $null = Assert-ReleaseSignerCertificatePolicy $first.certificate $digicert
    $failed = $false
    try { $null = Assert-ReleaseSignerCertificatePolicy $rotated.certificate $digicert } catch { $failed = $true }
    if (-not $failed) { throw 'DigiCert accepted an unpinned rotated SPKI.' }
} finally {
    $first.certificate.Dispose(); $first.key.Dispose()
    $rotated.certificate.Dispose(); $rotated.key.Dispose()
}
"""
    result = _run_powershell(script)
    assert result.returncode == 0, result.stderr + result.stdout


def test_azure_rejects_public_trust_test_lifetime_eku():
    source = (ROOT / "scripts" / "ReleaseCertificatePolicy.ps1").read_text(
        encoding="utf-8-sig"
    )

    assert "1.3.6.1.4.1.311.97.1.0" in source
    assert "1.3.6.1.4.1.311.10.3.13" in source
    assert "durable identity EKU" in source
    assert "leaf SPKI is evidence only" in source

    script = r"""
$ErrorActionPreference = 'Stop'
. .\scripts\ReleaseCertificatePolicy.ps1
function New-TestCertificate([string[]]$Ekus) {
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=Example Test Publisher, O=Example Test Organization', $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $oids = New-Object System.Security.Cryptography.OidCollection
    foreach ($oid in $Ekus) { $null = $oids.Add([System.Security.Cryptography.Oid]::new($oid)) }
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids, $true)
    )
    return [ordered]@{
        certificate = $request.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddHours(1)
        )
        key = $rsa
    }
}
$durable = '1.3.6.1.4.1.311.97.990309390.766961637.194916062.941502583'
$missing = New-TestCertificate @('1.3.6.1.5.5.7.3.3', '1.3.6.1.4.1.311.97.1.0')
$testProfile = New-TestCertificate @(
    '1.3.6.1.5.5.7.3.3', '1.3.6.1.4.1.311.97.1.0', $durable,
    '1.3.6.1.4.1.311.10.3.13'
)
$issuer = ConvertTo-NormalizedX500Name 'CN=Example Test Issuer, O=Example Test CA'
$root = 'a' * 64
function Assert-TrustedCertificateChain { return [ordered]@{ issuer_subject = $issuer; root_sha256 = $root } }
$policy = [ordered]@{
    provider = 'AzureArtifactSigning'; publisher = 'Example Test Publisher'
    subjects = @(ConvertTo-NormalizedX500Name $missing.certificate.SubjectName)
    issuers = @($issuer); root_sha256 = @($root); spki_sha256 = @()
    leaf_spki_policy = 'record-only'
    required_eku_oids = @('1.3.6.1.5.5.7.3.3', '1.3.6.1.4.1.311.97.1.0', $durable)
    forbidden_eku_oids = @('1.3.6.1.4.1.311.10.3.13')
    azure = [ordered]@{ durable_identity_eku = $durable }
}
try {
    foreach ($certificate in @($missing.certificate, $testProfile.certificate)) {
        $failed = $false
        try { $null = Assert-ReleaseSignerCertificatePolicy $certificate $policy } catch { $failed = $true }
        if (-not $failed) { throw 'Azure certificate bypassed an EKU gate.' }
    }
} finally {
    $missing.certificate.Dispose(); $missing.key.Dispose()
    $testProfile.certificate.Dispose(); $testProfile.key.Dispose()
}
"""
    result = _run_powershell(script)
    assert result.returncode == 0, result.stderr + result.stdout


def test_stable_verifier_uses_committed_provider_specific_policy():
    source = (ROOT / "scripts" / "Verify-ReleaseAuthenticode.ps1").read_text(
        encoding="utf-8-sig"
    )

    assert "[string]$PolicyPath" in source
    assert "[string]$SigningProvider" in source
    assert "Get-ReleasePublisherPolicy" in source
    assert "Get-ReleasePublisherPolicyEvidence" in (
        ROOT / "scripts" / "ReleaseCertificatePolicy.ps1"
    ).read_text(encoding="utf-8-sig")
    assert "ExpectedSignerSpkiSha256" not in source
    assert "leaf_spki_policy -ceq 'record-only'" in source
    assert "durable_identity_eku" in source
    assert "$ExpectedManifestIdentity.publisher_policy" in source
    assert "publisher_policy_sha256" in source
    assert "azure_metadata_sha256" in source
    assert "digicert_sm_host" in source
    assert "digicert_key_alias" in source
