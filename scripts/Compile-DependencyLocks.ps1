<#
.SYNOPSIS
Recompiles all Python lock files for their exact release platforms.

.DESCRIPTION
Requires a preinstalled, explicitly pinned uv executable. The script writes
only lock files and never installs project dependencies.
#>

#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$UvPath = $env:DEFENSE_TRACKER_UV,
    [string]$ExcludeNewer = "2026-08-28T00:00:00Z"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))

if ([string]::IsNullOrWhiteSpace($UvPath)) {
    throw "Set DEFENSE_TRACKER_UV to a preinstalled uv 0.9.27 executable."
}
$resolvedUv = [System.IO.Path]::GetFullPath($UvPath)
if (-not (Test-Path -LiteralPath $resolvedUv -PathType Leaf)) {
    throw "Configured uv executable does not exist."
}
$uvVersion = (& $resolvedUv --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $uvVersion -notmatch '^uv 0\.9\.27(?:\s|$)') {
    throw "Dependency lock compiler must be exactly uv 0.9.27; got '$uvVersion'."
}

$compileCommand = "powershell -File scripts/Compile-DependencyLocks.ps1"
$cacheRoot = Join-Path $projectRoot "build\uv-lock-cache"
New-Item -ItemType Directory -Path $cacheRoot -Force | Out-Null

function Invoke-LockCompile {
    param(
        [Parameter(Mandatory = $true)][string]$InputFile,
        [Parameter(Mandatory = $true)][string]$OutputFile,
        [Parameter(Mandatory = $true)][string]$Platform
    )
    & $resolvedUv pip compile $InputFile `
        --cache-dir $cacheRoot `
        --python-version 3.11 `
        --python-platform $Platform `
        --exclude-newer $ExcludeNewer `
        --generate-hashes `
        --no-annotate `
        --custom-compile-command $compileCommand `
        --output-file $OutputFile
    if ($LASTEXITCODE -ne 0) {
        throw "Lock compilation failed for $InputFile."
    }
    $source = [System.IO.File]::ReadAllText((Join-Path $projectRoot $OutputFile))
    if ($source -notmatch '--hash=sha256:[0-9a-f]{64}') {
        throw "Compiled lock has no SHA-256 hashes: $OutputFile"
    }
}

Push-Location $projectRoot
try {
    Invoke-LockCompile "requirements.runtime.in" "requirements.runtime.lock" `
        "x86_64-pc-windows-msvc"
    Invoke-LockCompile "requirements.build.in" "requirements.build.lock" `
        "x86_64-pc-windows-msvc"
    Invoke-LockCompile "requirements.bootstrap.in" "requirements.bootstrap.lock" `
        "x86_64-pc-windows-msvc"
    Invoke-LockCompile "deploy/requirements.cloud.in" "deploy/requirements.cloud.txt" `
        "x86_64-manylinux_2_36"
} finally {
    Pop-Location
}
Write-Host "[OK] Windows x64 and Linux x64 SHA-256 lock files were rebuilt."
