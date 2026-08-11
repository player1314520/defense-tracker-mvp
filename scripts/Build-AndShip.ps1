<#
.SYNOPSIS
Builds, validates, smoke-tests and atomically promotes DefenseTracker.

.DESCRIPTION
The build runs only from .venv-build, writes only to build/release-staging,
recursively scans the staged artifact, validates PE headers, launches the EXE,
checks HTTP and the V9 window title, writes a SHA-256 manifest, migrates legacy
runtime data without overwrite, and only then replaces dist/DefenseTracker.
The optional MVP release mode additionally requires a clean Git worktree,
preinstalled SignTool and Inno Setup, SHA-256 Authenticode signatures and a
trusted RFC 3161 timestamp. It never installs tools or reads a PFX/password.
#>

#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateRange(1, 60)]
    [int]$MaxArtifactAgeMinutes = 5,

    [switch]$RequireSignedInstaller,

    [string]$SigningCertificateThumbprint = $env:DEFENSE_TRACKER_SIGNING_THUMBPRINT,

    [string]$TimestampUrl = $env:DEFENSE_TRACKER_TIMESTAMP_URL,

    [string]$PublisherName = $env:DEFENSE_TRACKER_PUBLISHER,

    [string]$SignToolPath = $env:DEFENSE_TRACKER_SIGNTOOL,

    [string]$InnoSetupCompiler = $env:DEFENSE_TRACKER_ISCC
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

function Get-BuilderSafetyFindings {
    param([Parameter(Mandatory = $true)][string]$Path)
    $source = [System.IO.File]::ReadAllText($Path)
    $findings = New-Object System.Collections.Generic.List[string]
    $patterns = @{
        "runtime-package-install" = '["'']pip["'']\s*,\s*["'']install["'']'
        "interactive-prompt" = '\binput\s*\('
        "sensitive-file-preservation" = '\bKEEP_(?:FILES|DIRS)\b'
    }
    foreach ($entry in $patterns.GetEnumerator()) {
        if ([regex]::IsMatch($source, $entry.Value, "IgnoreCase")) {
            $findings.Add($entry.Key)
        }
    }
    return @($findings)
}

function Get-ArtifactSafetyFindings {
    param([Parameter(Mandatory = $true)][string]$Root)
    $findings = New-Object System.Collections.Generic.List[string]
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd("\") + "\"
    $forbiddenNames = @(
        ".access_token",
        ".ai_config.json",
        ".feishu_config.json",
        ".supabase_config.json",
        ".supabase_v9_config.json",
        ".v9_local_master.key",
        ".search_config.json",
        ".email_config.json"
    )
    $forbiddenExtensions = @(
        ".key", ".pfx", ".p12", ".kdbx", ".sqlite", ".sqlite3", ".db"
    )
    $textExtensions = @(
        "", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
        ".conf", ".env", ".py", ".js", ".css", ".html", ".htm", ".md",
        ".xml", ".csv", ".log", ".ps1", ".bat", ".cmd", ".pem"
    )
    $assetLibraryName = ([string][char]0x7D20) + ([string][char]0x6750) + ([string][char]0x5E93)
    $secretRules = @(
        [regex]::new('-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        [regex]::new(
            '(?:sk-(?:proj-)?[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        ),
        [regex]::new(
            '(?:api[_-]?key|app[_-]?secret|access[_-]?token|refresh[_-]?token|password|private[_-]?key)' +
            '\s*[:=]\s*["''][^"'']{8,}["'']',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    )

    foreach ($file in Get-ChildItem -LiteralPath $Root -File -Recurse -Force) {
        $relativePath = $file.FullName.Substring($rootFull.Length)
        $parts = @($relativePath -split '[\\/]')
        $lowerName = $file.Name.ToLowerInvariant()
        $lowerExtension = $file.Extension.ToLowerInvariant()
        if (
            $forbiddenNames -contains $lowerName -or
            $lowerName -like ".env*" -or
            $forbiddenExtensions -contains $lowerExtension -or
            @($parts | Where-Object { $_ -eq $assetLibraryName }).Count -gt 0
        ) {
            $findings.Add("forbidden-artifact:$relativePath")
            continue
        }
        if ($textExtensions -notcontains $lowerExtension) {
            continue
        }

        $stream = $null
        try {
            $stream = [System.IO.File]::Open(
                $file.FullName,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite
            )
            $buffer = New-Object byte[] 65536
            $tail = ""
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $chunk = $tail + [System.Text.Encoding]::UTF8.GetString($buffer, 0, $read)
                if (@($secretRules | Where-Object { $_.IsMatch($chunk) }).Count -gt 0) {
                    $findings.Add("secret-content:$relativePath")
                    break
                }
                $tailLength = [Math]::Min(512, $chunk.Length)
                $tail = $chunk.Substring($chunk.Length - $tailLength)
            }
        } catch {
            $findings.Add("content-scan-error:$relativePath")
        } finally {
            if ($null -ne $stream) { $stream.Dispose() }
        }
    }
    return @($findings)
}

function Assert-WindowsPeFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        if ($stream.Length -lt 68) { throw "PE file is too short: $Path" }
        $dos = New-Object byte[] 64
        if ($stream.Read($dos, 0, 64) -ne 64) { throw "Cannot read DOS header: $Path" }
        if ($dos[0] -ne 0x4D -or $dos[1] -ne 0x5A) { throw "Missing MZ signature: $Path" }
        $peOffset = [System.BitConverter]::ToInt32($dos, 0x3C)
        if ($peOffset -lt 64 -or $peOffset -gt ($stream.Length - 4)) {
            throw "Invalid e_lfanew: $Path"
        }
        $null = $stream.Seek($peOffset, [System.IO.SeekOrigin]::Begin)
        $signature = New-Object byte[] 4
        if ($stream.Read($signature, 0, 4) -ne 4) { throw "Cannot read PE signature: $Path" }
        if (
            $signature[0] -ne 0x50 -or $signature[1] -ne 0x45 -or
            $signature[2] -ne 0x00 -or $signature[3] -ne 0x00
        ) { throw "Missing PE signature: $Path" }
    } finally {
        $stream.Dispose()
    }
}

function Get-SharedPythonFingerprint {
    if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
        throw "Python launcher 'py' was not found on PATH."
    }
    $freeze = (& py -3 -m pip freeze --disable-pip-version-check 2>$null | Out-String)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($freeze)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "")
    } finally {
        $sha.Dispose()
    }
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [System.IO.File]::OpenRead($Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace("-", "")
    } finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function Assert-CleanReleaseCommit {
    param([Parameter(Mandatory = $true)][string]$ProjectRoot)
    $status = (& git -C $ProjectRoot status --porcelain --untracked-files=all 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "Unable to inspect Git release state." }
    if (-not [string]::IsNullOrWhiteSpace($status)) {
        throw "Signed release requires a clean Git worktree, including no untracked files."
    }
    $commit = (& git -C $ProjectRoot rev-parse HEAD 2>$null | Out-String).Trim()
    if ($commit -notmatch '^[0-9a-f]{40}$') {
        throw "Signed release requires a full Git commit SHA."
    }
    return $commit
}

function Resolve-RequiredTool {
    param(
        [Parameter(Mandatory = $true)][string]$ExplicitPath,
        [Parameter(Mandatory = $true)][string]$CommandName,
        [Parameter(Mandatory = $true)][string]$Description
    )
    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        $resolved = [System.IO.Path]::GetFullPath($ExplicitPath)
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            throw "$Description was not found at the configured path."
        }
        return $resolved
    }
    $command = Get-Command $CommandName -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        throw "$Description is not preinstalled. The release gate never installs tools."
    }
    return $command.Source
}

function Assert-SigningCertificate {
    param([Parameter(Mandatory = $true)][string]$Thumbprint)
    $normalized = ($Thumbprint -replace '\s', '').ToUpperInvariant()
    if ($normalized -notmatch '^[0-9A-F]{40}$') {
        throw "A 40-character CurrentUser certificate thumbprint is required."
    }
    $certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$normalized" -ErrorAction SilentlyContinue
    if ($null -eq $certificate) { throw "Signing certificate was not found in CurrentUser\\My." }
    if (-not $certificate.HasPrivateKey) { throw "Signing certificate has no private key." }
    if ($certificate.NotBefore -gt (Get-Date) -or $certificate.NotAfter -le (Get-Date).AddDays(7)) {
        throw "Signing certificate is not currently valid for the release window."
    }
    return $normalized
}

function Invoke-SignAndVerify {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Tool,
        [Parameter(Mandatory = $true)][string]$Thumbprint,
        [Parameter(Mandatory = $true)][string]$Timestamp
    )
    & $Tool sign /sha1 $Thumbprint /fd SHA256 /tr $Timestamp /td SHA256 $Path
    if ($LASTEXITCODE -ne 0) { throw "SignTool failed to sign release artifact." }
    & $Tool verify /pa /all /q $Path
    if ($LASTEXITCODE -ne 0) { throw "SignTool verification failed for release artifact." }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Get-AuthenticodeSignature did not report a valid signature."
    }
    if ($null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint -ne $Thumbprint) {
        throw "Release artifact was signed by an unexpected certificate."
    }
    if ($null -eq $signature.TimeStamperCertificate) {
        throw "Release artifact has no trusted timestamp countersignature."
    }
}

function Reset-GeneratedDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][string]$InventoryPath
    )
    $resolved = [System.IO.Path]::GetFullPath($Path)
    $expected = [System.IO.Path]::GetFullPath($ExpectedPath)
    if ($resolved -ne $expected) { throw "Unexpected generated directory: $resolved" }
    if (Test-Path -LiteralPath $resolved -PathType Container) {
        Get-ChildItem -LiteralPath $resolved -Force -Recurse |
            Select-Object FullName, Length, LastWriteTimeUtc |
            ConvertTo-Json -Depth 3 |
            Set-Content -LiteralPath $InventoryPath -Encoding UTF8
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
    New-Item -ItemType Directory -Path $resolved -Force | Out-Null
}

function Invoke-DesktopSmokeTest {
    param(
        [Parameter(Mandatory = $true)][string]$ExePath,
        [Parameter(Mandatory = $true)][string]$RuntimeRoot
    )
    $previousHome = [Environment]::GetEnvironmentVariable("DEFENSE_TRACKER_HOME", "Process")
    [Environment]::SetEnvironmentVariable("DEFENSE_TRACKER_HOME", $RuntimeRoot, "Process")
    $process = $null
    try {
        $process = Start-Process -FilePath $ExePath -PassThru
        $deadline = [DateTime]::UtcNow.AddSeconds(50)
        $httpReady = $false
        $windowReady = $false
        while ([DateTime]::UtcNow -lt $deadline) {
            if ($process.HasExited) {
                throw "Desktop smoke process exited early with code $($process.ExitCode)."
            }
            $process.Refresh()
            if ($process.MainWindowTitle -like "*V9*Defense Command Hub*") {
                $windowReady = $true
            }
            foreach ($port in 5000..5019) {
                try {
                    $response = Invoke-WebRequest -UseBasicParsing -TimeoutSec 1 `
                        -Uri "http://127.0.0.1:$port/"
                    if (
                        $response.StatusCode -eq 200 -and
                        $response.Content -match "command-hub-v9"
                    ) {
                        $httpReady = $true
                        break
                    }
                } catch {}
            }
            if ($httpReady -and $windowReady) { return }
            Start-Sleep -Milliseconds 400
        }
        throw "Desktop smoke timeout (HTTP=$httpReady, V9 window=$windowReady)."
    } finally {
        if ($null -ne $process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force
            $process.WaitForExit(10000) | Out-Null
        }
        [Environment]::SetEnvironmentVariable(
            "DEFENSE_TRACKER_HOME",
            $previousHome,
            "Process"
        )
    }
}

function Invoke-LegacyMigration {
    param(
        [Parameter(Mandatory = $true)][string]$Python,
        [Parameter(Mandatory = $true)][string]$ProjectRoot,
        [Parameter(Mandatory = $true)][string]$LegacyRoot,
        [Parameter(Mandatory = $true)][string]$TargetRoot
    )
    if (-not (Test-Path -LiteralPath $LegacyRoot -PathType Container)) { return }
    $previousHome = [Environment]::GetEnvironmentVariable("DEFENSE_TRACKER_HOME", "Process")
    [Environment]::SetEnvironmentVariable("DEFENSE_TRACKER_HOME", $TargetRoot, "Process")
    try {
        $code = (
            "from pathlib import Path; import state; " +
            "print(state.migrate_legacy_runtime(Path(__import__('sys').argv[1]), state.RUNTIME_LAYOUT))"
        )
        Push-Location $ProjectRoot
        try {
            & $Python -c $code $LegacyRoot
            if ($LASTEXITCODE -ne 0) { throw "Legacy migration failed: $LegacyRoot" }
        } finally {
            Pop-Location
        }
    } finally {
        [Environment]::SetEnvironmentVariable(
            "DEFENSE_TRACKER_HOME",
            $previousHome,
            "Process"
        )
    }
}

function Write-ReleaseManifest {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Python,
        [Parameter(Mandatory = $true)][datetime]$StartedUtc,
        [Parameter(Mandatory = $true)][string]$ProjectRoot
    )
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd("\") + "\"
    $files = @(
        Get-ChildItem -LiteralPath $Root -File -Recurse -Force |
            Sort-Object FullName |
            ForEach-Object {
                [ordered]@{
                    path = $_.FullName.Substring($rootFull.Length).Replace("\", "/")
                    bytes = $_.Length
                    sha256 = Get-Sha256 -Path $_.FullName
                }
            }
    )
    $packages = @(& $Python -m pip freeze --disable-pip-version-check)
    $commit = (& git -C $ProjectRoot rev-parse HEAD 2>$null | Out-String).Trim()
    $manifest = [ordered]@{
        schema = 1
        product = "DefenseTracker"
        version = "V9"
        built_at = $StartedUtc.ToString("o")
        commit = $commit
        python = (& $Python --version 2>&1 | Out-String).Trim()
        packages = $packages
        files = $files
    }
    $manifestPath = Join-Path $Root "release-manifest.json"
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    return $manifestPath
}

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$builder = Join-Path $projectRoot "scripts\build_app.py"
$venvPython = Join-Path $projectRoot ".venv-build\Scripts\python.exe"
$stagingRoot = Join-Path $projectRoot "build\release-staging\DefenseTracker"
$stagedExe = Join-Path $stagingRoot "DefenseTracker.exe"
$smokeRuntime = Join-Path $projectRoot "build\smoke-runtime"
$distParent = Join-Path $projectRoot "dist"
$releaseRoot = Join-Path $distParent "DefenseTracker"
$rollbackRoot = Join-Path $distParent "DefenseTracker.previous"
$inventoryPath = Join-Path $projectRoot "build\untrusted-dist-inventory.json"
$installerStaging = Join-Path $projectRoot "build\installer-staging"
$installerDefinition = Join-Path $projectRoot "deploy\mvp\DefenseTracker.iss"
$installerInventory = Join-Path $projectRoot "build\stale-installer-inventory.json"
$installerReleaseRoot = ""
$releaseCommit = ""
$resolvedSignTool = ""
$resolvedInno = ""
$normalizedThumbprint = ""

if ($RequireSignedInstaller) {
    $releaseCommit = Assert-CleanReleaseCommit -ProjectRoot $projectRoot
    if ($TimestampUrl -notmatch '^https://[^\s]+$') {
        throw "Signed release requires an explicit HTTPS RFC 3161 timestamp URL."
    }
    if ([string]::IsNullOrWhiteSpace($PublisherName)) {
        throw "Signed release requires an explicit publisher name."
    }
    if (-not (Test-Path -LiteralPath $installerDefinition -PathType Leaf)) {
        throw "Inno Setup definition is missing: $installerDefinition"
    }
    $resolvedSignTool = Resolve-RequiredTool -ExplicitPath $SignToolPath `
        -CommandName "signtool.exe" -Description "Windows SDK SignTool"
    $resolvedInno = Resolve-RequiredTool -ExplicitPath $InnoSetupCompiler `
        -CommandName "ISCC.exe" -Description "Inno Setup compiler"
    $normalizedThumbprint = Assert-SigningCertificate -Thumbprint $SigningCertificateThumbprint
    $installerReleaseRoot = Join-Path $distParent ("installers\" + $releaseCommit)
    if (Test-Path -LiteralPath $installerReleaseRoot) {
        throw "Immutable installer release already exists: $installerReleaseRoot"
    }
    Reset-GeneratedDirectory -Path $installerStaging -ExpectedPath $installerStaging `
        -InventoryPath $installerInventory
}

if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
    throw "Missing isolated build environment. Run scripts\Prepare-BuildEnv.ps1 first."
}
$builderFindings = @(Get-BuilderSafetyFindings -Path $builder)
if ($builderFindings.Count -gt 0) {
    throw "Builder safety gate failed before Python started: $($builderFindings -join ', ')"
}

$sharedBefore = Get-SharedPythonFingerprint
$buildStartedUtc = [DateTime]::UtcNow
Write-Host "[BUILD] Isolated toolchain: $venvPython"
Push-Location $projectRoot
try {
    & $venvPython scripts/build_app.py
    if ($LASTEXITCODE -ne 0) { throw "Build failed with exit code $LASTEXITCODE." }
} finally {
    Pop-Location
}
$sharedAfter = Get-SharedPythonFingerprint
if ($sharedBefore -ne $sharedAfter) {
    throw "Shared py -3 environment changed during build."
}

if (-not (Test-Path -LiteralPath $stagedExe -PathType Leaf)) {
    throw "Staged executable was not created: $stagedExe"
}
$exe = Get-Item -LiteralPath $stagedExe
if ($exe.Length -le 0) { throw "Staged executable is empty." }
if ($exe.LastWriteTimeUtc -lt $buildStartedUtc.AddSeconds(-5)) {
    throw "Staged executable predates this build."
}
$ageMinutes = ([DateTime]::UtcNow - $exe.LastWriteTimeUtc).TotalMinutes
if ($ageMinutes -gt $MaxArtifactAgeMinutes) {
    throw "Staged executable is stale ($ageMinutes minutes)."
}
Assert-WindowsPeFile -Path $stagedExe

$artifactFindings = @(Get-ArtifactSafetyFindings -Root $stagingRoot)
if ($artifactFindings.Count -gt 0) {
    throw "Artifact safety scan failed:`n - $($artifactFindings -join "`n - ")"
}

if ($RequireSignedInstaller) {
    Write-Host "[SIGN] Signing staged EXE with SHA-256 and RFC 3161 timestamp."
    Invoke-SignAndVerify -Path $stagedExe -Tool $resolvedSignTool `
        -Thumbprint $normalizedThumbprint -Timestamp $TimestampUrl
}

Write-Host "[SMOKE] Launching staged EXE and verifying HTTP + V9 window title."
Invoke-DesktopSmokeTest -ExePath $stagedExe -RuntimeRoot $smokeRuntime

$manifestPath = Write-ReleaseManifest `
    -Root $stagingRoot `
    -Python $venvPython `
    -StartedUtc $buildStartedUtc `
    -ProjectRoot $projectRoot
$artifactFindings = @(Get-ArtifactSafetyFindings -Root $stagingRoot)
if ($artifactFindings.Count -gt 0) {
    throw "Post-manifest artifact scan failed:`n - $($artifactFindings -join "`n - ")"
}

$stagedInstaller = ""
if ($RequireSignedInstaller) {
    $shortCommit = $releaseCommit.Substring(0, 12)
    & $resolvedInno `
        "/DAppSource=$stagingRoot" `
        "/DOutputDir=$installerStaging" `
        "/DAppVersion=9.0.0" `
        "/DGitShort=$shortCommit" `
        "/DPublisherName=$PublisherName" `
        $installerDefinition
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed." }
    $stagedInstaller = Join-Path $installerStaging "DefenseTracker-Setup-$shortCommit.exe"
    if (-not (Test-Path -LiteralPath $stagedInstaller -PathType Leaf)) {
        throw "Signed installer candidate was not created."
    }
    Assert-WindowsPeFile -Path $stagedInstaller
    Invoke-SignAndVerify -Path $stagedInstaller -Tool $resolvedSignTool `
        -Thumbprint $normalizedThumbprint -Timestamp $TimestampUrl
}

$localAppData = [Environment]::GetFolderPath("LocalApplicationData")
if ([string]::IsNullOrWhiteSpace($localAppData)) {
    throw "Unable to resolve LocalApplicationData."
}
$runtimeTarget = Join-Path $localAppData "DefenseTracker"
Invoke-LegacyMigration -Python $venvPython -ProjectRoot $projectRoot `
    -LegacyRoot $projectRoot -TargetRoot $runtimeTarget
Invoke-LegacyMigration -Python $venvPython -ProjectRoot $projectRoot `
    -LegacyRoot $releaseRoot -TargetRoot $runtimeTarget

New-Item -ItemType Directory -Path $distParent -Force | Out-Null
if (Test-Path -LiteralPath $rollbackRoot) {
    $resolvedRollback = [System.IO.Path]::GetFullPath($rollbackRoot)
    $expectedRollback = [System.IO.Path]::GetFullPath(
        (Join-Path $distParent "DefenseTracker.previous")
    )
    if ($resolvedRollback -ne $expectedRollback) {
        throw "Unexpected rollback path: $resolvedRollback"
    }
    Get-ChildItem -LiteralPath $rollbackRoot -Force -Recurse |
        Select-Object FullName, Length |
        ConvertTo-Json -Depth 3 |
        Set-Content -LiteralPath (Join-Path $projectRoot "build\stale-rollback-inventory.json")
    Remove-Item -LiteralPath $rollbackRoot -Recurse -Force
}

if (Test-Path -LiteralPath $releaseRoot) {
    Get-ChildItem -LiteralPath $releaseRoot -Force -Recurse |
        Select-Object FullName, Length, LastWriteTimeUtc |
        ConvertTo-Json -Depth 3 |
        Set-Content -LiteralPath $inventoryPath -Encoding UTF8
    Move-Item -LiteralPath $releaseRoot -Destination $rollbackRoot
}

try {
    Move-Item -LiteralPath $stagingRoot -Destination $releaseRoot
} catch {
    if (
        -not (Test-Path -LiteralPath $releaseRoot) -and
        (Test-Path -LiteralPath $rollbackRoot)
    ) {
        Move-Item -LiteralPath $rollbackRoot -Destination $releaseRoot
    }
    throw
}

if (Test-Path -LiteralPath $smokeRuntime) {
    Get-ChildItem -LiteralPath $smokeRuntime -Force -Recurse |
        Select-Object FullName, Length |
        Set-Content -LiteralPath (Join-Path $projectRoot "build\smoke-runtime-inventory.txt")
    Remove-Item -LiteralPath $smokeRuntime -Recurse -Force
}

$releasedInstaller = $null
if ($RequireSignedInstaller) {
    New-Item -ItemType Directory -Path $installerReleaseRoot -Force | Out-Null
    $releasedInstallerPath = Join-Path $installerReleaseRoot ([System.IO.Path]::GetFileName($stagedInstaller))
    Move-Item -LiteralPath $stagedInstaller -Destination $releasedInstallerPath
    $releasedInstaller = Get-Item -LiteralPath $releasedInstallerPath
    Invoke-SignAndVerify -Path $releasedInstaller.FullName -Tool $resolvedSignTool `
        -Thumbprint $normalizedThumbprint -Timestamp $TimestampUrl
    $installerManifest = [ordered]@{
        schema = 1
        product = "DefenseTracker"
        commit = $releaseCommit
        file = $releasedInstaller.Name
        bytes = $releasedInstaller.Length
        sha256 = Get-Sha256 -Path $releasedInstaller.FullName
        authenticode = "Valid"
        timestamped = $true
    }
    $installerManifest | ConvertTo-Json -Depth 3 |
        Set-Content -LiteralPath (Join-Path $installerReleaseRoot "installer-manifest.json") -Encoding UTF8
}

$releasedExe = Get-Item -LiteralPath (Join-Path $releaseRoot "DefenseTracker.exe")
$releasedHash = Get-Sha256 -Path $releasedExe.FullName
Write-Host ""
Write-Host "[OK] DefenseTracker V9 release promoted."
Write-Host "     EXE: $($releasedExe.FullName)"
Write-Host "     Bytes: $($releasedExe.Length)"
Write-Host "     SHA-256: $releasedHash"
Write-Host "     Manifest: $(Join-Path $releaseRoot 'release-manifest.json')"
Write-Host "     Runtime: $runtimeTarget"
if ($null -ne $releasedInstaller) {
    Write-Host "     Signed installer: $($releasedInstaller.FullName)"
}
if (Test-Path -LiteralPath $rollbackRoot) {
    Write-Host "     Previous release retained: $rollbackRoot"
}
Write-Host "[DEPLOY] No remote deployment, publish, credential write, or dist copy occurred."
