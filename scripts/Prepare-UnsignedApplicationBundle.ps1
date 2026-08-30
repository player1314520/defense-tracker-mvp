<#
.SYNOPSIS
Builds the exact unsigned application and emits a canonical signing request.

.DESCRIPTION
This credentialless stage consumes the committed Publisher policy but never a
signing identity. It writes only an already-decrypted local bundle and a
redaction-safe public request. Encryption and artifact transport are owned by
the workflow.
#>

#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedReleaseSha,

    [Parameter(Mandatory = $true)]
    [string]$OutputRoot,

    [string]$PublisherPolicyPath = (Join-Path $PSScriptRoot '..\release\publisher-policy.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
. (Join-Path $PSScriptRoot 'ReleaseCertificatePolicy.ps1')

foreach ($name in @(
    'AZURE_CLIENT_ID','AZURE_TENANT_ID','AZURE_CLIENT_SECRET',
    'DIGICERT_SM_API_KEY','SM_API_KEY','SM_CLIENT_CERT_PASSWORD',
    'DEFENSE_TRACKER_AZURE_SIGNING_DLIB','DEFENSE_TRACKER_AZURE_SIGNING_METADATA',
    'DEFENSE_TRACKER_DIGICERT_KEY_ALIAS','DEFENSE_TRACKER_DIGICERT_CERT_FILE'
)) {
    if (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
        throw "Unsigned application preparation refuses signing credential/provider material: $name"
    }
}

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$outputFull = [System.IO.Path]::GetFullPath($OutputRoot)
$projectPrefix = $projectRoot.TrimEnd('\') + '\'
if ($outputFull.StartsWith($projectPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Credentialless output must be outside the clean source worktree.'
}
$policyFull = [System.IO.Path]::GetFullPath($PublisherPolicyPath)
if (-not (Test-Path -LiteralPath $policyFull -PathType Leaf)) {
    throw 'Committed Publisher policy is missing.'
}
try {
    $policyDocument = Get-Content -LiteralPath $policyFull -Raw | ConvertFrom-Json -ErrorAction Stop
} catch {
    throw 'Committed Publisher policy is not valid JSON.'
}
$provider = [string]$policyDocument.active_provider
if ($provider -notin @('AzureArtifactSigning','DigiCertKeyLocker')) {
    throw 'Committed Publisher policy has no approved active provider.'
}
$policy = Get-ReleasePublisherPolicy -Path $policyFull -SigningProvider $provider
if ([string]::IsNullOrWhiteSpace([string]$policy.publisher)) {
    throw 'Committed Publisher policy has no verified legal Publisher.'
}

& (Join-Path $PSScriptRoot 'Build-AndShip.ps1') `
    -ExpectedReleaseSha $ExpectedReleaseSha `
    -PrepareUnsignedApplicationBundle `
    -CredentiallessOutputRoot $outputFull `
    -PublisherName ([string]$policy.publisher) `
    -PublisherPolicyPath $policyFull
if ($LASTEXITCODE -ne 0) { throw 'Credentialless application build failed.' }

$bundle = Join-Path $outputFull 'application-unsigned-bundle'
$request = Join-Path $outputFull 'application-signing-request.json'
if (-not (Test-Path -LiteralPath $bundle -PathType Container) -or
    -not (Test-Path -LiteralPath $request -PathType Leaf)) {
    throw 'Credentialless application build did not produce the fixed outputs.'
}
Write-Host "application-bundle=$bundle"
Write-Host "application-signing-request=$request"
