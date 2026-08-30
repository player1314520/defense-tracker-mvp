<#
.SYNOPSIS
Recompiles all Python lock files for their exact release platforms.

.DESCRIPTION
Uses an explicitly supplied uv executable or downloads the official pinned uv
release plus its official checksum into a temporary directory. The script
writes only lock files and never installs uv or project dependencies globally.
#>

#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$UvPath = $env:DEFENSE_TRACKER_UV,
    [string]$UvVersion = "0.9.27",
    [string]$ExcludeNewer = "2026-08-28T00:00:00Z"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$temporaryUvRoot = $null

function Get-OfficialUv {
    param([Parameter(Mandatory = $true)][string]$Version)

    if ($Version -ne "0.9.27") {
        throw "The lock compiler is approved only for uv 0.9.27."
    }
    $isWindowsHost = $env:OS -eq "Windows_NT"
    $asset = if ($isWindowsHost) {
        "uv-x86_64-pc-windows-msvc.zip"
    } else {
        "uv-x86_64-unknown-linux-gnu.tar.gz"
    }
    $approvedHashes = @{
        "uv-x86_64-pc-windows-msvc.zip" = `
            "c3bf465d5f2b93c836f369aec9f3fa8350843f24abd5f710bb74e72440b82898"
        "uv-x86_64-unknown-linux-gnu.tar.gz" = `
            "8636e693ea0e05f5f4294b161f816c4d8df065267fdb0405cfb84c8e326991fa"
    }
    $releaseBase = "https://github.com/astral-sh/uv/releases/download/$Version"
    $tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    $script:temporaryUvRoot = [System.IO.Path]::GetFullPath((Join-Path `
        $tempBase ("defense-tracker-uv-" + [guid]::NewGuid().ToString("N"))))
    if (-not $script:temporaryUvRoot.StartsWith(
        $tempBase,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Temporary uv directory escaped the operating-system temp root."
    }
    New-Item -ItemType Directory -Path $script:temporaryUvRoot | Out-Null
    $archive = Join-Path $script:temporaryUvRoot $asset
    $checksum = "$archive.sha256"
    Invoke-WebRequest -UseBasicParsing -Uri "$releaseBase/$asset" -OutFile $archive
    Invoke-WebRequest -UseBasicParsing -Uri "$releaseBase/$asset.sha256" `
        -OutFile $checksum

    $checksumText = [System.IO.File]::ReadAllText($checksum).Trim()
    if ($checksumText -notmatch '(?i)^(?<hash>[0-9a-f]{64})(?:\s+.*)?$') {
        throw "Official uv checksum file has an unexpected format."
    }
    $expectedHash = $Matches.hash.ToLowerInvariant()
    if ($expectedHash -ne $approvedHashes[$asset]) {
        throw "Official uv checksum does not match the reviewed release checksum."
    }
    $actualHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "Official uv archive checksum verification failed."
    }

    if ($isWindowsHost) {
        Expand-Archive -LiteralPath $archive -DestinationPath $script:temporaryUvRoot
        return (Join-Path $script:temporaryUvRoot "uv.exe")
    }
    & tar -xzf $archive -C $script:temporaryUvRoot uv
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to extract the official uv archive."
    }
    return (Join-Path $script:temporaryUvRoot "uv")
}

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

try {
    if ([string]::IsNullOrWhiteSpace($UvPath)) {
        $UvPath = Get-OfficialUv -Version $UvVersion
    }
    $resolvedUv = [System.IO.Path]::GetFullPath($UvPath)
    if (-not (Test-Path -LiteralPath $resolvedUv -PathType Leaf)) {
        throw "Configured uv executable does not exist."
    }
    $resolvedUvVersion = (& $resolvedUv --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $resolvedUvVersion -notmatch '^uv 0\.9\.27(?:\s|$)') {
        throw "Dependency lock compiler must be exactly uv 0.9.27; got '$resolvedUvVersion'."
    }

    $compileCommand = "powershell -File scripts/Compile-DependencyLocks.ps1"
    $cacheRoot = Join-Path $projectRoot "build\uv-lock-cache"
    New-Item -ItemType Directory -Path $cacheRoot -Force | Out-Null

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
        Invoke-LockCompile "deploy/requirements.server-build.in" "deploy/requirements.server-build.txt" `
            "x86_64-manylinux_2_36"
        Invoke-LockCompile "deploy/requirements.server.in" "deploy/requirements.server.txt" `
            "x86_64-manylinux_2_36"
        Invoke-LockCompile "requirements.ci-linux.in" "requirements.ci-linux.lock" `
            "x86_64-manylinux_2_36"
        Invoke-LockCompile "requirements.ci-windows.in" "requirements.ci-windows.lock" `
            "x86_64-pc-windows-msvc"
        Invoke-LockCompile "requirements.ci-deployment.in" `
            "requirements.ci-deployment.lock" "x86_64-manylinux_2_36"
    } finally {
        Pop-Location
    }
} finally {
    if ($null -ne $temporaryUvRoot -and
        (Test-Path -LiteralPath $temporaryUvRoot -PathType Container)) {
        $tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        $resolvedTemporaryUvRoot = [System.IO.Path]::GetFullPath($temporaryUvRoot)
        if ($resolvedTemporaryUvRoot.StartsWith(
            $tempBase,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -and [System.IO.Path]::GetFileName($resolvedTemporaryUvRoot).StartsWith(
            "defense-tracker-uv-",
            [System.StringComparison]::Ordinal
        )) {
            $null = @(Get-ChildItem -LiteralPath $resolvedTemporaryUvRoot -Force)
            Remove-Item -LiteralPath $resolvedTemporaryUvRoot -Recurse -Force
        } else {
            throw "Refusing to remove an unverified temporary uv directory."
        }
    }
}
Write-Host "[OK] Release and CI SHA-256 lock files were rebuilt."
