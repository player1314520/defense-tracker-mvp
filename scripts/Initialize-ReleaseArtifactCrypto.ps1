<#
.SYNOPSIS
Bootstraps the hash-pinned official age binary on GitHub-hosted Windows.

.DESCRIPTION
Downloads the official age v1.3.2 Windows amd64 archive, verifies its pinned
SHA-256 before extraction, and exports only the age executable path and observed
executable hash. This script never creates a key.
#>

#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$GitHubEnvironmentFile = $env:GITHUB_ENV,
    [string]$RunnerTemporaryDirectory = $env:RUNNER_TEMP
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ageVersion = '1.3.2'
$ageArchiveSha256 = 'f48d8f8f9ebe903ab5027ed067652f2cc1db94bc206976430133b905dcd8e8c7'
$ageArchiveUri = 'https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-windows-amd64.zip'

function Assert-PlainValue {
    param([string]$Name, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Contains("`r") -or $Value.Contains("`n")) {
        throw "$Name is missing or contains a line break."
    }
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Export-GitHubEnvironmentValue {
    param([string]$Name, [string]$Value)
    if ($Name -cnotmatch '^[A-Z][A-Z0-9_]+$') { throw 'Invalid environment variable name.' }
    Assert-PlainValue -Name $Name -Value $Value
    [System.IO.File]::AppendAllText(
        $script:environmentFile,
        "$Name=$Value`n",
        [System.Text.UTF8Encoding]::new($false)
    )
}

if ($env:GITHUB_ACTIONS -cne 'true' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
    $env:RUNNER_OS -cne 'Windows') {
    throw 'age bootstrap is restricted to an ephemeral GitHub-hosted Windows runner.'
}
Assert-PlainValue -Name 'GITHUB_ENV' -Value $GitHubEnvironmentFile
Assert-PlainValue -Name 'RUNNER_TEMP' -Value $RunnerTemporaryDirectory
$runnerTemp = [System.IO.Path]::GetFullPath($RunnerTemporaryDirectory)
$script:environmentFile = [System.IO.Path]::GetFullPath($GitHubEnvironmentFile)
if (-not (Test-Path -LiteralPath $runnerTemp -PathType Container) -or
    -not (Test-Path -LiteralPath (Split-Path -Parent $script:environmentFile) -PathType Container)) {
    throw 'GitHub runner paths are invalid.'
}
$toolRoot = Join-Path $runnerTemp "defense-tracker-age-v$ageVersion"
if (Test-Path -LiteralPath $toolRoot) { throw 'The one-use age tool directory already exists.' }
[System.IO.Directory]::CreateDirectory($toolRoot) | Out-Null
$archivePath = Join-Path $toolRoot 'age.zip'
$expandedRoot = Join-Path $toolRoot 'expanded'
try {
    Invoke-WebRequest -UseBasicParsing -Uri $ageArchiveUri -OutFile $archivePath
    if ((Get-Sha256 -Path $archivePath) -cne $ageArchiveSha256) {
        throw 'Downloaded age archive does not match the pinned SHA-256.'
    }
    [System.IO.Directory]::CreateDirectory($expandedRoot) | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($archivePath, $expandedRoot)
    $matches = @(
        Get-ChildItem -LiteralPath $expandedRoot -Filter 'age.exe' -File -Recurse |
            Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 }
    )
    if ($matches.Count -ne 1) { throw 'Pinned age archive did not contain exactly one age.exe.' }
    $ageExecutable = $matches[0].FullName
    $versionOutput = (& $ageExecutable '--version' 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $versionOutput -cne "v$ageVersion") {
        throw 'Extracted age executable did not report the pinned version.'
    }
    Export-GitHubEnvironmentValue -Name 'DEFENSE_TRACKER_AGE' -Value $ageExecutable
    Export-GitHubEnvironmentValue -Name 'DEFENSE_TRACKER_AGE_SHA256' -Value (Get-Sha256 -Path $ageExecutable)
} catch {
    if (Test-Path -LiteralPath $toolRoot) { [System.IO.Directory]::Delete($toolRoot, $true) }
    throw
}

Write-Host '[OK] Hash-pinned age release transport tool is ready.'
