<#
.SYNOPSIS
Creates the isolated, pinned desktop build environment.

.DESCRIPTION
This is the only build workflow step allowed to install packages. It writes
only to .venv-build and never launches PyInstaller or changes release output.
#>

#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$Recreate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$venvRoot = Join-Path $projectRoot ".venv-build"
$venvPython = Join-Path $venvRoot "Scripts\python.exe"
$lockFile = Join-Path $projectRoot "requirements.build.lock"

if (-not (Test-Path -LiteralPath $lockFile -PathType Leaf)) {
    throw "Pinned build requirements are missing: $lockFile"
}

if ($Recreate -and (Test-Path -LiteralPath $venvRoot -PathType Container)) {
    $resolvedVenv = [System.IO.Path]::GetFullPath($venvRoot)
    $expectedVenv = [System.IO.Path]::GetFullPath(
        (Join-Path $projectRoot ".venv-build")
    )
    if ($resolvedVenv -ne $expectedVenv -or -not $resolvedVenv.StartsWith($projectRoot)) {
        throw "Refusing to remove unexpected build environment: $resolvedVenv"
    }
    Get-ChildItem -LiteralPath $resolvedVenv -Force |
        Select-Object FullName |
        Format-Table -AutoSize
    Remove-Item -LiteralPath $resolvedVenv -Recurse -Force
}

if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
    if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
        throw "Python launcher 'py' was not found on PATH."
    }
    Write-Host "[ENV] Creating isolated environment: $venvRoot"
    & py -3 -m venv $venvRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to create .venv-build (exit $LASTEXITCODE)."
    }
}

Write-Host "[ENV] Installing pinned build dependencies inside .venv-build only."
Push-Location $projectRoot
try {
    & $venvPython -m pip install --disable-pip-version-check --requirement $lockFile
    if ($LASTEXITCODE -ne 0) {
        throw "Pinned dependency installation failed (exit $LASTEXITCODE)."
    }
    & $venvPython -m pip check
    if ($LASTEXITCODE -ne 0) {
        throw "Build environment dependency check failed."
    }
    & $venvPython -c "import sys; print('[ENV] Python:', sys.executable)"
    & $venvPython -m PyInstaller --version
} finally {
    Pop-Location
}

Write-Host "[OK] Build environment is ready. No application build was started."
