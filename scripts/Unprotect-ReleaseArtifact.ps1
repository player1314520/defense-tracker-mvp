<#
.SYNOPSIS
Validates, decrypts, and safely expands a three-file release envelope.

.DESCRIPTION
The identity must come from a step-scoped temporary file materialized from the
v9-candidate-processing Environment secret RELEASE_ARTIFACT_AGE_IDENTITY. Pass
-RemoveIdentityFile to make this helper delete that exact regular file in its
finally block; callers should also retain an independent always() cleanup step.
#>

#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$AgeExecutable,
    [Parameter(Mandatory = $true)][string]$ExpectedAgeExecutableSha256,
    [Parameter(Mandatory = $true)][string]$EnvelopeDirectory,
    [Parameter(Mandatory = $true)][string]$IdentityFile,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [string]$ExpectedRepository = '',
    [string]$ExpectedReleaseCommit = '',
    [string]$ExpectedRunId = '',
    [string]$ExpectedRunAttempt = '',
    [switch]$RemoveIdentityFile,
    [string]$TemporaryDirectory = $(if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { [System.IO.Path]::GetTempPath() } else { $env:RUNNER_TEMP })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ReleaseArtifactCrypto.psm1') -Force

Unprotect-ReleaseArtifact @PSBoundParameters
Write-Host '[OK] Release artifact envelope verified and decrypted.'
