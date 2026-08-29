#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$AssetRoot,
    [Parameter(Mandatory = $true)][string]$PublisherName,
    [Parameter(Mandatory = $true)][string]$SignToolPath,
    [Parameter(Mandatory = $true)][string]$ExpectedSignToolSha256,
    [Parameter(Mandatory = $true)][string]$ExpectedSignerSubjects,
    [Parameter(Mandatory = $true)][string]$ExpectedSignerSpkiSha256,
    [Parameter(Mandatory = $true)][string]$ExpectedSignerIssuers,
    [Parameter(Mandatory = $true)][string]$ExpectedSignerRootSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot 'ReleaseCertificatePolicy.ps1')
$root = [System.IO.Path]::GetFullPath($AssetRoot)
$tool = [System.IO.Path]::GetFullPath($SignToolPath)
if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw "Asset root is missing." }
if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw "SignTool is missing." }
if ([string]::IsNullOrWhiteSpace($PublisherName) -or
    $ExpectedSignToolSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    (Get-FileHash -LiteralPath $tool -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSignToolSha256) {
    throw 'Protected Publisher or SignTool identity is missing or invalid.'
}
$policy = Get-ReleaseCertificatePolicy `
    -ExpectedSignerSubjects $ExpectedSignerSubjects `
    -ExpectedSignerSpkiSha256 $ExpectedSignerSpkiSha256 `
    -ExpectedSignerIssuers $ExpectedSignerIssuers `
    -ExpectedSignerRootSha256 $ExpectedSignerRootSha256
$manifestPath = Join-Path $root "release-manifest.json"
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'Release manifest is missing.' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$version = $manifest.version.semantic_version
if ($version -cnotmatch '^\d+\.\d+\.\d+$' -or
    [string]$manifest.signature.publisher -cne $PublisherName) {
    throw 'Release manifest version or Publisher differs from protected configuration.'
}
$installer = Join-Path $root "DefenseTracker-Setup-v$version-windows-x64.exe"
$portable = Join-Path $root "DefenseTracker-v$version-windows-x64-portable.zip"

function Assert-SignedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedManifestSubject
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
    if ($simpleName -cne $PublisherName) { throw "Unexpected Authenticode Publisher." }
    $identity = Assert-ReleaseSignerCertificatePolicy $signature.SignerCertificate $policy
    $manifestSubject = ConvertTo-NormalizedX500Name $ExpectedManifestSubject
    if ($identity.normalized_subject -cne $manifestSubject) {
        throw 'Authenticode signer Subject differs from the signed release manifest.'
    }
    $null = Assert-TrustedCertificateChain $signature.TimeStamperCertificate
    return $identity
}

$installerIdentity = Assert-SignedFile $installer ([string]$manifest.signatures.installer.signer_subject)
$temporaryParent = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd("\") + "\"
$extractRoot = Join-Path $temporaryParent ("defensetracker-release-verify-" + [guid]::NewGuid().ToString("N"))
try {
    New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null
    Expand-Archive -LiteralPath $portable -DestinationPath $extractRoot
    $portableIdentity = Assert-SignedFile `
        (Join-Path $extractRoot "DefenseTracker\DefenseTracker.exe") `
        ([string]$manifest.signatures.application.signer_subject)
    if ($portableIdentity.normalized_subject -cne $installerIdentity.normalized_subject -or
        $portableIdentity.spki_sha256 -cne $installerIdentity.spki_sha256 -or
        $portableIdentity.issuer_subject -cne $installerIdentity.issuer_subject -or
        $portableIdentity.root_sha256 -cne $installerIdentity.root_sha256) {
        throw 'Installer and portable application were not signed by the same pinned identity.'
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
