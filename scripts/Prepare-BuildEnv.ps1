<#
.SYNOPSIS
Creates a fresh, one-use, hash-locked Windows desktop build environment.

.DESCRIPTION
The environment is deleted and recreated on every invocation. All bootstrap
and application dependencies are pinned and SHA-256 verified. sgmllib3k and
proxy-tools are the two pure-Python sdist exceptions because their publishers
provide no wheels; both are hash-pinned and built without an isolated
dependency download.
#>

#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$PythonExecutable = $env:DEFENSE_TRACKER_BUILD_PYTHON,
    [string]$ExpectedPythonSha256 = $env:DEFENSE_TRACKER_BUILD_PYTHON_SHA256,
    [switch]$RequireExpectedPythonHash
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$venvRoot = Join-Path $projectRoot ".venv-build"
$venvPython = Join-Path $venvRoot "Scripts\python.exe"
$buildLock = Join-Path $projectRoot "requirements.build.lock"
$bootstrapLock = Join-Path $projectRoot "requirements.bootstrap.lock"
$evidenceRoot = Join-Path $projectRoot "build\release-evidence"
$markerPath = Join-Path $venvRoot ".build-environment.json"

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

foreach ($required in @($buildLock, $bootstrapLock)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Hash-locked build requirement file is missing: $required"
    }
    $content = [System.IO.File]::ReadAllText($required)
    if ($content -notmatch '--hash=sha256:[0-9a-f]{64}') {
        throw "Requirement lock does not contain SHA-256 hashes: $required"
    }
}

if ([string]::IsNullOrWhiteSpace($PythonExecutable)) {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($null -eq $pythonCommand) {
        throw "Set DEFENSE_TRACKER_BUILD_PYTHON to a preinstalled CPython 3.11 x64 executable."
    }
    $PythonExecutable = $pythonCommand.Source
}
$resolvedPython = [System.IO.Path]::GetFullPath($PythonExecutable)
if (-not (Test-Path -LiteralPath $resolvedPython -PathType Leaf)) {
    throw "Configured build Python does not exist."
}
$pythonSourceSha256 = Get-Sha256 -Path $resolvedPython
$pythonHashVerified = $false
if (-not [string]::IsNullOrWhiteSpace($ExpectedPythonSha256)) {
    if ($ExpectedPythonSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "Expected build Python SHA-256 must be 64 lowercase hexadecimal characters."
    }
    if ($pythonSourceSha256 -cne $ExpectedPythonSha256) {
        throw "Configured build Python SHA-256 does not match the trusted value."
    }
    $pythonHashVerified = $true
} elseif ($RequireExpectedPythonHash) {
    throw "Signed candidate preparation requires DEFENSE_TRACKER_BUILD_PYTHON_SHA256."
}
$factsJson = & $resolvedPython -c (
    "import json,platform,sys; print(json.dumps({" +
    "'implementation':platform.python_implementation()," +
    "'major':sys.version_info.major,'minor':sys.version_info.minor," +
    "'bits':platform.architecture()[0]}))"
)
if ($LASTEXITCODE -ne 0) { throw "Unable to inspect configured build Python." }
$pythonFacts = $factsJson | ConvertFrom-Json
if (
    $pythonFacts.implementation -ne "CPython" -or
    $pythonFacts.major -ne 3 -or $pythonFacts.minor -ne 11 -or
    $pythonFacts.bits -ne "64bit"
) {
    throw "Desktop release requires CPython 3.11 x64 exactly."
}

$resolvedVenv = [System.IO.Path]::GetFullPath($venvRoot)
$expectedVenv = [System.IO.Path]::GetFullPath((Join-Path $projectRoot ".venv-build"))
if ($resolvedVenv -ne $expectedVenv -or -not $resolvedVenv.StartsWith($projectRoot)) {
    throw "Refusing to replace unexpected build environment: $resolvedVenv"
}
if (Test-Path -LiteralPath $resolvedVenv -PathType Container) {
    New-Item -ItemType Directory -Path $evidenceRoot -Force | Out-Null
    $inventory = Join-Path $evidenceRoot (
        "previous-build-environment-" + [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ") + ".json"
    )
    Get-ChildItem -LiteralPath $resolvedVenv -Force -Recurse |
        Select-Object FullName, Length, LastWriteTimeUtc |
        ConvertTo-Json -Depth 3 |
        Set-Content -LiteralPath $inventory -Encoding UTF8
    Remove-Item -LiteralPath $resolvedVenv -Recurse -Force
}

Write-Host "[ENV] Creating fresh CPython 3.11 x64 environment: $venvRoot"
& $resolvedPython -m venv $venvRoot
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
    throw "Unable to create the isolated build environment."
}

Push-Location $projectRoot
try {
    & $venvPython -m pip install --disable-pip-version-check `
        --require-hashes --only-binary=:all: --requirement $bootstrapLock
    if ($LASTEXITCODE -ne 0) { throw "Hash-locked bootstrap installation failed." }

    & $venvPython -m pip install --disable-pip-version-check `
        --require-hashes --only-binary=:all: --no-binary=sgmllib3k,proxy-tools `
        --no-build-isolation --requirement $buildLock
    if ($LASTEXITCODE -ne 0) { throw "Hash-locked build dependency installation failed." }
    & $venvPython -m pip check
    if ($LASTEXITCODE -ne 0) { throw "Build environment dependency check failed." }

    $freeze = (& $venvPython -m pip freeze --all --disable-pip-version-check | Out-String).Trim()
    $freezePath = Join-Path $venvRoot ".installed-packages.txt"
    [System.IO.File]::WriteAllText(
        $freezePath,
        $freeze + "`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    $marker = [ordered]@{
        schema = 1
        prepared_at_utc = [DateTime]::UtcNow.ToString("o")
        consumed_at_utc = $null
        python = (& $venvPython --version 2>&1 | Out-String).Trim()
        python_source_sha256 = $pythonSourceSha256
        python_expected_sha256 = if ($pythonHashVerified) { $ExpectedPythonSha256 } else { $null }
        python_hash_verified = $pythonHashVerified
        architecture = "x64"
        bootstrap_lock_sha256 = Get-Sha256 -Path $bootstrapLock
        build_lock_sha256 = Get-Sha256 -Path $buildLock
        installed_packages_sha256 = Get-Sha256 -Path $freezePath
    }
    $marker | ConvertTo-Json -Depth 3 |
        Set-Content -LiteralPath $markerPath -Encoding UTF8
    & $venvPython -m PyInstaller --version
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller is unavailable in the prepared environment." }
} finally {
    Pop-Location
}

Write-Host "[OK] Fresh one-use hash-locked build environment is ready."
