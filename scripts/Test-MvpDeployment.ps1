<#
.SYNOPSIS
Runs local static validation for the MVP deployment and release assets.

.DESCRIPTION
Docker Compose validation is attempted only when Docker Compose v2 is already
available. The script does not install tools, build images, start containers,
deploy remotely or touch real secrets.
#>

#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$composeFile = Join-Path $projectRoot "deploy\mvp\docker-compose.production.yml"
$exampleEnv = Join-Path $projectRoot "deploy\mvp\production.env.example"
$testFile = Join-Path $projectRoot "tests\test_mvp_deployment_assets.py"

Push-Location $projectRoot
try {
    & py -3 -m pytest $testFile -q
    if ($LASTEXITCODE -ne 0) { throw "MVP deployment static tests failed." }

    & py -3 -m py_compile `
        (Join-Path $projectRoot "deploy\mvp\bin\probe-public.py") `
        (Join-Path $projectRoot "scripts\prepare_mvp_portal_context.py")
    if ($LASTEXITCODE -ne 0) { throw "MVP deployment Python syntax validation failed." }

    $bash = Get-Command bash -ErrorAction SilentlyContinue
    $bashPath = if ($null -ne $bash) { $bash.Source } else { $null }
    if ($null -eq $bashPath) {
        $git = Get-Command git -ErrorAction SilentlyContinue
        if ($null -ne $git) {
            $gitRoot = Split-Path (Split-Path $git.Source -Parent) -Parent
            foreach ($candidate in @(
                (Join-Path $gitRoot "bin\bash.exe"),
                (Join-Path $gitRoot "usr\bin\bash.exe")
            )) {
                if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                    $bashPath = $candidate
                    break
                }
            }
        }
    }
    if ($null -ne $bashPath) {
        Get-ChildItem -LiteralPath (Join-Path $projectRoot "deploy\mvp\bin") `
            -Filter "*.sh" -File | ForEach-Object {
                & $bashPath -n $_.FullName
                if ($LASTEXITCODE -ne 0) {
                    throw "Shell syntax validation failed for $($_.Name)."
                }
            }
        & $bashPath -n (Join-Path $projectRoot "deploy\mvp\portal-entrypoint.sh")
        if ($LASTEXITCODE -ne 0) { throw "Portal entrypoint shell syntax validation failed." }
        Write-Host "[OK] Deployment shell syntax passed."
    } else {
        Write-Host "[SKIP] bash is unavailable; deployment shell syntax is unverified on this host."
    }

    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $projectRoot "scripts\Build-AndShip.ps1"),
        [ref]$null,
        [ref]$parseErrors
    )
    if ($parseErrors.Count -gt 0) {
        throw "Build-AndShip.ps1 has PowerShell parse errors."
    }

    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if ($null -eq $docker) {
        Write-Host "[SKIP] Docker is not installed; Compose runtime/config validation is unverified."
        exit 0
    }
    & docker compose version *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[SKIP] Docker Compose v2 is unavailable; Compose config validation is unverified."
        exit 0
    }

    $checkRoot = Join-Path $projectRoot "build\mvp-compose-check"
    $expectedRoot = [System.IO.Path]::GetFullPath(
        (Join-Path $projectRoot "build\mvp-compose-check")
    )
    $resolvedRoot = [System.IO.Path]::GetFullPath($checkRoot)
    if ($resolvedRoot -ne $expectedRoot) { throw "Unexpected Compose check directory." }
    if (Test-Path -LiteralPath $resolvedRoot) {
        Get-ChildItem -LiteralPath $resolvedRoot -Force -Recurse |
            Select-Object FullName, Length |
            Out-Null
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    }
    $secretDir = Join-Path $resolvedRoot "secrets"
    New-Item -ItemType Directory -Path $secretDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $secretDir "supabase_publishable_key") `
        -Value "sb_publishable_static_config_check" -Encoding ASCII

    $previousSecrets = $env:MVP_SECRETS_DIR
    $previousCaddy = $env:CADDY_IMAGE
    try {
        $env:MVP_SECRETS_DIR = $secretDir
        $env:CADDY_IMAGE = "caddy@sha256:$('0' * 64)"
        & docker compose --env-file $exampleEnv --file $composeFile config --quiet
        if ($LASTEXITCODE -ne 0) { throw "Docker Compose config validation failed." }
        Write-Host "[OK] Docker Compose accepted the production Portal/edge configuration."
    } finally {
        $env:MVP_SECRETS_DIR = $previousSecrets
        $env:CADDY_IMAGE = $previousCaddy
        if (Test-Path -LiteralPath $resolvedRoot) {
            Get-ChildItem -LiteralPath $resolvedRoot -Force -Recurse |
                Select-Object FullName, Length |
                Out-Null
            Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
        }
    }
} finally {
    Pop-Location
}
