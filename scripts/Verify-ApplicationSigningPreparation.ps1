<#
.SYNOPSIS
Verifies an unsigned application bundle and reviewed compliance evidence.

.DESCRIPTION
Runs before a signing Environment is entered. It does not create an approval
context and does not read any signing credential. The public request SHA is the
dispatch anchor; the request binds every payload byte and exact build material.
#>

#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedReleaseSha,

    [Parameter(Mandatory = $true)]
    [string]$BundleRoot,

    [Parameter(Mandatory = $true)]
    [string]$SigningRequest,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedSigningRequestSha256,

    [Parameter(Mandatory = $true)]
    [string]$ComplianceEvidence,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedComplianceEvidenceSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedPublisherPolicySha256,

    [string]$OutputReceipt,

    [string]$ExpectedRepository = $env:GITHUB_REPOSITORY,
    [string]$ExpectedPreparationRunId = $env:SOURCE_RUN_ID,
    [string]$ExpectedPreparationRunAttempt = $env:SOURCE_RUN_ATTEMPT
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$bundleFull = [System.IO.Path]::GetFullPath($BundleRoot)
$publicRequest = [System.IO.Path]::GetFullPath($SigningRequest)
$complianceFull = [System.IO.Path]::GetFullPath($ComplianceEvidence)
if (-not (Test-Path -LiteralPath $bundleFull -PathType Container) -or
    -not (Test-Path -LiteralPath $publicRequest -PathType Leaf) -or
    -not (Test-Path -LiteralPath $complianceFull -PathType Leaf)) {
    throw 'Application preparation bundle, request, or compliance evidence is absent.'
}
if ($ExpectedRepository -cnotmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or
    $ExpectedPreparationRunId -cnotmatch '^[1-9][0-9]{0,19}$' -or
    $ExpectedPreparationRunAttempt -cnotmatch '^[1-9][0-9]{0,9}$') {
    throw 'Expected preparation provenance is malformed.'
}
$internalRequest = Join-Path $bundleFull 'signing-request.json'
if (-not (Test-Path -LiteralPath $internalRequest -PathType Leaf) -or
    (Get-Sha256 $publicRequest) -cne $ExpectedSigningRequestSha256 -or
    (Get-Sha256 $internalRequest) -cne $ExpectedSigningRequestSha256 -or
    -not [System.Linq.Enumerable]::SequenceEqual(
        [byte[]][System.IO.File]::ReadAllBytes($publicRequest),
        [byte[]][System.IO.File]::ReadAllBytes($internalRequest)
    )) {
    throw 'Internal and public application signing requests are not the exact dispatched bytes.'
}
if ((Get-Sha256 $complianceFull) -cne $ExpectedComplianceEvidenceSha256) {
    throw 'Compliance evidence differs from its dispatch SHA-256.'
}

$request = Get-Content -LiteralPath $internalRequest -Raw | ConvertFrom-Json
$publisher = [string]$request.release.publisher
$sourceTree = [string]$request.release.source_tree
$expectedWorkflowRef = "$ExpectedRepository/.github/workflows/v9-release-preparation.yml@refs/heads/main"
$evidenceRoot = Join-Path $bundleFull 'evidence'
$applicationRoot = Join-Path $bundleFull 'payload\DefenseTracker'
$componentInventory = Join-Path $evidenceRoot 'unsigned-component-inventory.json'
$packages = Join-Path $evidenceRoot 'installed-packages.txt'
$markerPath = Join-Path $evidenceRoot 'build-environment.json'
$runtimeLock = Join-Path $evidenceRoot 'requirements.runtime.lock'
$buildLock = Join-Path $evidenceRoot 'requirements.build.lock'
$bootstrapLock = Join-Path $evidenceRoot 'requirements.bootstrap.lock'
$policyPath = Join-Path $evidenceRoot 'publisher-policy.json'
$versionPath = Join-Path $evidenceRoot 'version.json'
foreach ($path in @(
    $componentInventory,$packages,$markerPath,$runtimeLock,$buildLock,
    $bootstrapLock,$policyPath,$versionPath
)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'Application signing request material is missing from the bundle.'
    }
}
if ((Get-Sha256 $policyPath) -cne $ExpectedPublisherPolicySha256 -or
    (Get-Sha256 (Join-Path $projectRoot 'release\publisher-policy.json')) -cne
        $ExpectedPublisherPolicySha256) {
    throw 'Bundled and committed Publisher policies differ from the dispatch SHA-256.'
}
foreach ($name in @(
    'requirements.runtime.lock','requirements.build.lock','requirements.bootstrap.lock','version.json'
)) {
    if ((Get-Sha256 (Join-Path $evidenceRoot $name)) -cne
        (Get-Sha256 (Join-Path $projectRoot $name))) {
        throw "Bundled source material differs from protected source: $name"
    }
}
$marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
if ($marker.schema -ne 1 -or $marker.python_hash_verified -ne $true -or
    [string]$marker.python_source_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
    [string]$marker.python_source_sha256 -cne [string]$marker.python_expected_sha256) {
    throw 'Bundled build Python was not hash-pinned.'
}

$requestVerification = if ([string]::IsNullOrWhiteSpace($OutputReceipt)) {
    Join-Path (Split-Path $bundleFull -Parent) 'application-request-verification.json'
} else {
    [System.IO.Path]::GetFullPath($OutputReceipt) + '.request.json'
}
& python `
    (Join-Path $projectRoot 'scripts\signing_exchange.py') verify-request `
    --bundle-root $bundleFull `
    --request $internalRequest `
    --expected-request-sha256 $ExpectedSigningRequestSha256 `
    --expected-subject-kind application `
    --expected-release-commit $ExpectedReleaseSha `
    --expected-publisher $publisher `
    --expected-repository $ExpectedRepository `
    --expected-workflow-ref $expectedWorkflowRef `
    --expected-run-id $ExpectedPreparationRunId `
    --expected-run-attempt $ExpectedPreparationRunAttempt `
    --expected-job prepare-unsigned-application `
    --material-sha256 "python-source=$([string]$marker.python_source_sha256)" `
    --material "build-environment=$markerPath" `
    --material "installed-packages=$packages" `
    --material "bootstrap-lock=$bootstrapLock" `
    --material "runtime-lock=$runtimeLock" `
    --material "build-lock=$buildLock" `
    --material "component-inventory=$componentInventory" `
    --material "publisher-policy=$policyPath" `
    --material "version=$versionPath" `
    --output $requestVerification
if ($LASTEXITCODE -ne 0) { throw 'Unsigned application request verification failed.' }

$verifiedAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$complianceReceipt = if ([string]::IsNullOrWhiteSpace($OutputReceipt)) {
    Join-Path (Split-Path $bundleFull -Parent) 'application-compliance-verification.json'
} else {
    [System.IO.Path]::GetFullPath($OutputReceipt)
}
& python `
    (Join-Path $projectRoot 'scripts\verify_compliance_evidence.py') `
    --evidence $complianceFull `
    --application-signing-request $internalRequest `
    --expected-application-signing-request-sha256 $ExpectedSigningRequestSha256 `
    --component-inventory $componentInventory `
    --application-root $applicationRoot `
    --expected-sha256 $ExpectedComplianceEvidenceSha256 `
    --commit $ExpectedReleaseSha `
    --source-tree $sourceTree `
    --publisher $publisher `
    --packages-file $packages `
    --third-party-notices (Join-Path $projectRoot 'THIRD_PARTY_NOTICES.md') `
    --runtime-lock-sha256 (Get-Sha256 $runtimeLock) `
    --build-lock-sha256 (Get-Sha256 $buildLock) `
    --verified-at-utc $verifiedAt `
    --github-repository $ExpectedRepository `
    --github-workflow-ref $expectedWorkflowRef `
    --github-run-id $ExpectedPreparationRunId `
    --github-run-attempt $ExpectedPreparationRunAttempt `
    --output-receipt $complianceReceipt
if ($LASTEXITCODE -ne 0) { throw 'Pre-Environment compliance verification failed.' }

Write-Host "application-request-verification=$requestVerification"
Write-Host "application-compliance-verification=$complianceReceipt"
