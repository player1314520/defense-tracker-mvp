#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$AssetRoot,
    [Parameter(Mandatory = $true)][string]$PolicyPath,
    [Parameter(Mandatory = $true)]
    [ValidateSet('AzureArtifactSigning', 'DigiCertKeyLocker')]
    [string]$SigningProvider,
    [Parameter(Mandatory = $true)][string]$SignToolPath,
    [Parameter(Mandatory = $true)][string]$ExpectedSignToolSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot 'ReleaseCertificatePolicy.ps1')
$root = [System.IO.Path]::GetFullPath($AssetRoot)
$tool = [System.IO.Path]::GetFullPath($SignToolPath)
if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw "Asset root is missing." }
if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw "SignTool is missing." }
if ($ExpectedSignToolSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    (Get-FileHash -LiteralPath $tool -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSignToolSha256) {
    throw 'Protected SignTool identity is missing or invalid.'
}
$policy = Get-ReleasePublisherPolicy -Path $PolicyPath -SigningProvider $SigningProvider
$publisherName = [string]$policy.publisher
$manifestPath = Join-Path $root "release-manifest.json"
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'Release manifest is missing.' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$version = [string]$manifest.version.semantic_version
if ($version -cnotmatch '^\d+\.\d+\.\d+$' -or
    [string]$manifest.signature.publisher -cne $publisherName -or
    [string]$manifest.signature.provider -cne $SigningProvider -or
    [string]$manifest.signature.publisher_policy_sha256 -cne [string]$policy.policy_sha256) {
    throw 'Release manifest version, provider, Publisher, or Publisher-policy hash is invalid.'
}
$installer = Join-Path $root "DefenseTracker-Setup-v$version-windows-x64.exe"
$portable = Join-Path $root "DefenseTracker-v$version-windows-x64-portable.zip"

function Assert-SignedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$ExpectedManifestIdentity
    )
    & $tool verify /pa /all /v /tw $Path
    if ($LASTEXITCODE -ne 0) { throw "SignTool rejected $Path." }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or
        $null -eq $signature.TimeStamperCertificate) {
        throw "Authenticode or timestamp validation failed for $Path."
    }
    $simpleName = $signature.SignerCertificate.GetNameInfo(
        [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
        $false
    )
    if ($simpleName -cne $publisherName) { throw "Unexpected Authenticode Publisher." }
    $identity = Assert-ReleaseSignerCertificatePolicy $signature.SignerCertificate $policy
    $manifestPolicy = $ExpectedManifestIdentity.publisher_policy
    if ($null -eq $manifestPolicy -or
        [string]$manifestPolicy.sha256 -cne [string]$policy.policy_sha256 -or
        [string]$manifestPolicy.leaf_spki_policy -cne $identity.leaf_spki_policy) {
        throw 'Artifact Publisher-policy evidence differs from the committed policy.'
    }
    if ([string]$ExpectedManifestIdentity.provider -cne $SigningProvider -or
        [string]$ExpectedManifestIdentity.publisher -cne $publisherName -or
        [string]$ExpectedManifestIdentity.signer_subject -cne $identity.normalized_subject -or
        [string]$ExpectedManifestIdentity.signer_spki_sha256 -cne $identity.spki_sha256 -or
        [string]$ExpectedManifestIdentity.signer_issuer_subject -cne $identity.issuer_subject -or
        [string]$ExpectedManifestIdentity.signer_root_sha256 -cne $identity.root_sha256) {
        throw 'Authenticode signer identity differs from the release manifest evidence.'
    }
    if ($SigningProvider -eq 'AzureArtifactSigning') {
        if ([string]$manifestPolicy.durable_identity_eku -cne $identity.durable_identity_eku -or
            [string]$manifestPolicy.azure_endpoint -cne [string]$policy.azure.endpoint -or
            [string]$manifestPolicy.azure_account_name -cne [string]$policy.azure.account_name -or
            [string]$manifestPolicy.azure_certificate_profile_name -cne
                [string]$policy.azure.certificate_profile_name -or
            [string]$manifestPolicy.azure_metadata_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $null -ne $manifestPolicy.digicert_sm_host -or
            $null -ne $manifestPolicy.digicert_key_alias) {
            throw 'Azure account/profile/endpoint/durable-identity provenance differs from committed policy.'
        }
    } elseif ($null -ne $manifestPolicy.durable_identity_eku -or
        $null -ne $manifestPolicy.azure_endpoint -or
        $null -ne $manifestPolicy.azure_account_name -or
        $null -ne $manifestPolicy.azure_certificate_profile_name -or
        $null -ne $manifestPolicy.azure_metadata_sha256 -or
        [string]$manifestPolicy.digicert_sm_host -cne [string]$policy.digicert.sm_host -or
        [string]$manifestPolicy.digicert_key_alias -cne [string]$policy.digicert.key_alias) {
        throw 'DigiCert receipt has missing, mismatched, or unexpected Publisher-policy provenance.'
    }
    $null = Assert-TrustedCertificateChain $signature.TimeStamperCertificate
    return $identity
}

$installerIdentity = Assert-SignedFile $installer $manifest.signatures.installer
$temporaryParent = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd("\") + "\"
$extractRoot = Join-Path $temporaryParent ("defensetracker-release-verify-" + [guid]::NewGuid().ToString("N"))
try {
    New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null
    Expand-Archive -LiteralPath $portable -DestinationPath $extractRoot
    $portableIdentity = Assert-SignedFile `
        (Join-Path $extractRoot "DefenseTracker\DefenseTracker.exe") `
        $manifest.signatures.application
    if ($policy.leaf_spki_policy -ceq 'record-only') {
        if ($portableIdentity.durable_identity_eku -cne $installerIdentity.durable_identity_eku) {
            throw 'Azure installer and portable application do not share the durable Publisher EKU.'
        }
    } elseif ($portableIdentity.normalized_subject -cne $installerIdentity.normalized_subject -or
        $portableIdentity.spki_sha256 -cne $installerIdentity.spki_sha256 -or
        $portableIdentity.issuer_subject -cne $installerIdentity.issuer_subject -or
        $portableIdentity.root_sha256 -cne $installerIdentity.root_sha256) {
        throw 'DigiCert installer and portable application do not share the pinned certificate identity.'
    }
} finally {
    if (Test-Path -LiteralPath $extractRoot -PathType Container) {
        $resolved = [System.IO.Path]::GetFullPath($extractRoot)
        if (-not $resolved.StartsWith($temporaryParent) -or
            [System.IO.Path]::GetFileName($resolved) -notmatch '^defensetracker-release-verify-[0-9a-f]{32}$') {
            throw "Refusing to remove unexpected verification directory."
        }
        Get-ChildItem -LiteralPath $resolved -Force -Recurse | Select-Object FullName,Length | Out-Null
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
Write-Host "release-authenticode: PASS"
