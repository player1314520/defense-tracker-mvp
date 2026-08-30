#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PolicyPath,
    [Parameter(Mandatory = $true)]
    [ValidateSet('AzureArtifactSigning', 'DigiCertKeyLocker')]
    [string]$SigningProvider,
    [string]$AzureMetadataPath,
    [string]$DigiCertSmHost,
    [string]$DigiCertKeyAlias
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseCertificatePolicy.ps1')

$arguments = @{
    Path = $PolicyPath
    SigningProvider = $SigningProvider
}
if ($SigningProvider -eq 'AzureArtifactSigning') {
    if ([string]::IsNullOrWhiteSpace($AzureMetadataPath)) {
        throw 'Azure Artifact Signing policy validation requires the exact signing metadata file.'
    }
    $arguments.AzureMetadataPath = $AzureMetadataPath
} else {
    if ([string]::IsNullOrWhiteSpace($DigiCertSmHost) -or
        [string]::IsNullOrWhiteSpace($DigiCertKeyAlias)) {
        throw 'DigiCert Publisher policy validation requires the runtime SM host and key alias.'
    }
    $arguments.DigiCertSmHost = $DigiCertSmHost
    $arguments.DigiCertKeyAlias = $DigiCertKeyAlias
}
$policy = Get-ReleasePublisherPolicy @arguments
if ($SigningProvider -eq 'AzureArtifactSigning' -and
    [string]$policy.azure.metadata_sha256 -cnotmatch '^[0-9a-f]{64}$') {
    throw 'Azure Artifact Signing metadata provenance was not bound.'
}
Write-Host "publisher-policy: PASS provider=$SigningProvider policy_sha256=$($policy.policy_sha256)"
