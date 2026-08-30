<#
.SYNOPSIS
Encrypts a release-candidate directory into a strict three-file public envelope.

.DESCRIPTION
The public envelope contains only an age ciphertext plus canonical, secret-free
request and receipt JSON. It never creates or accepts a private identity.
#>

#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$AgeExecutable,
    [Parameter(Mandatory = $true)][string]$ExpectedAgeExecutableSha256,
    [Parameter(Mandatory = $true)][string]$PlaintextRoot,
    [string]$RecipientFile = $(Join-Path $PSScriptRoot '..\release\candidate-transport-recipient.txt'),
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][string]$ArtifactName,
    [Parameter(Mandatory = $true)][string]$Repository,
    [Parameter(Mandatory = $true)][string]$ReleaseCommit,
    [Parameter(Mandatory = $true)][string]$RunId,
    [Parameter(Mandatory = $true)][string]$RunAttempt,
    [string]$TemporaryDirectory = $(if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { [System.IO.Path]::GetTempPath() } else { $env:RUNNER_TEMP })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ReleaseArtifactCrypto.psm1') -Force

Protect-ReleaseArtifact @PSBoundParameters
Write-Host '[OK] Encrypted release artifact envelope created.'
