<#
.SYNOPSIS
Builds and verifies one exact DefenseTracker release commit.

.DESCRIPTION
The release is materialized with git archive, built with a fresh one-use
hash-locked CPython 3.11 x64 environment, scanned, smoke-tested and promoted
locally. Stable assets are produced only after trusted Authenticode signing.
This script never creates a Git tag, GitHub Release or remote deployment.
#>

#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedReleaseSha,

    [ValidateRange(1, 60)]
    [int]$MaxArtifactAgeMinutes = 5,

    [switch]$RequireSignedInstaller,

    [switch]$CandidateOnly,

    [string]$SigningProvider = $env:DEFENSE_TRACKER_SIGNING_PROVIDER,
    [string]$TimestampUrl = $env:DEFENSE_TRACKER_TIMESTAMP_URL,
    [string]$PublisherName = $env:DEFENSE_TRACKER_PUBLISHER,
    [string]$SignToolPath = $env:DEFENSE_TRACKER_SIGNTOOL,
    [string]$InnoSetupCompiler = $env:DEFENSE_TRACKER_ISCC,
    [string]$SevenZipPath = $env:DEFENSE_TRACKER_7ZIP,
    [string]$DefenderPath = $env:DEFENSE_TRACKER_DEFENDER,
    [string]$AzureSigningDlib = $env:DEFENSE_TRACKER_AZURE_SIGNING_DLIB,
    [string]$AzureSigningMetadata = $env:DEFENSE_TRACKER_AZURE_SIGNING_METADATA,
    [string]$DigiCertKeyAlias = $env:DEFENSE_TRACKER_DIGICERT_KEY_ALIAS,
    [string]$DigiCertCertificateFile = $env:DEFENSE_TRACKER_DIGICERT_CERT_FILE,
    [string]$ExpectedSignToolSha256 = $env:DEFENSE_TRACKER_SIGNTOOL_SHA256,
    [string]$ExpectedInnoSha256 = $env:DEFENSE_TRACKER_ISCC_SHA256,
    [string]$ExpectedSevenZipSha256 = $env:DEFENSE_TRACKER_7ZIP_SHA256,
    [string]$ExpectedDefenderSha256 = $env:DEFENSE_TRACKER_DEFENDER_SHA256,
    [string]$ExpectedAzureDlibSha256 = $env:DEFENSE_TRACKER_AZURE_SIGNING_DLIB_SHA256,
    [string]$ExpectedAzureMetadataSha256 = $env:DEFENSE_TRACKER_AZURE_SIGNING_METADATA_SHA256,
    [string]$InnoLicenseTextPath = $env:DEFENSE_TRACKER_INNO_LICENSE_TEXT,
    [string]$ExpectedInnoLicenseTextSha256 = $env:DEFENSE_TRACKER_INNO_LICENSE_TEXT_SHA256,
    [string]$InnoCopyrightText = $env:DEFENSE_TRACKER_INNO_COPYRIGHT_TEXT,
    [string]$ComplianceEvidencePath = $env:DEFENSE_TRACKER_COMPLIANCE_EVIDENCE,
    [string]$ComplianceSignaturePath = $env:DEFENSE_TRACKER_COMPLIANCE_SIGNATURE,
    [string]$ExpectedComplianceEvidenceSha256 = $env:DEFENSE_TRACKER_COMPLIANCE_EVIDENCE_SHA256,
    [string]$PreparationRunId = $env:GITHUB_RUN_ID,
    [string]$PreparationRunAttempt = $env:GITHUB_RUN_ATTEMPT,
    [string]$PreparationArtifactName = $env:DEFENSE_TRACKER_PREPARATION_ARTIFACT_NAME,
    [string]$PreparationRepository = $env:GITHUB_REPOSITORY,
    [string]$PreparationWorkflowRef = $env:GITHUB_WORKFLOW_REF,

    [ValidatePattern('^[0-9a-f]{7,40}-[0-9]{8}$')]
    [string]$LegacyArchiveId = $env:DEFENSE_TRACKER_LEGACY_ARCHIVE_ID
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
if ($CandidateOnly -and -not $RequireSignedInstaller) {
    throw "CandidateOnly requires a signed installer candidate."
}
if ($RequireSignedInstaller -and -not $CandidateOnly) {
    throw "Single-stage signed release builds are disabled. Prepare an installer-review bundle, then run Finalize-SignedCandidate.ps1 in the independent installer-signing environment."
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Resolve-RequiredTool {
    param(
        [string]$ExplicitPath,
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

function Get-VerifiedToolEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$Description,
        [string]$VersionOverride
    )
    if ($ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "$Description requires an expected lowercase SHA-256 value."
    }
    $actualSha256 = Get-Sha256 $Path
    if ($actualSha256 -cne $ExpectedSha256) {
        throw "$Description SHA-256 differs from the trusted value."
    }
    $versionValue = $VersionOverride
    if ([string]::IsNullOrWhiteSpace($versionValue)) {
        $versionInfo = (Get-Item -LiteralPath $Path).VersionInfo
        $versionValue = [string]$versionInfo.FileVersion
        if ([string]::IsNullOrWhiteSpace($versionValue)) {
            $versionValue = [string]$versionInfo.ProductVersion
        }
    }
    if ([string]::IsNullOrWhiteSpace($versionValue)) {
        throw "$Description does not expose a version for release evidence."
    }
    return [ordered]@{
        version = $versionValue.Trim()
        sha256 = $actualSha256
        expected_sha256 = $ExpectedSha256
        hash_verified = $true
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
        ".access_token", ".ai_config.json", ".feishu_config.json",
        ".supabase_config.json", ".supabase_v9_config.json",
        ".v9_local_master.key", ".search_config.json", ".email_config.json"
    )
    $forbiddenExtensions = @(".key", ".pfx", ".p12", ".kdbx", ".sqlite", ".sqlite3", ".db")
    $textExtensions = @(
        "", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
        ".conf", ".env", ".py", ".js", ".css", ".html", ".htm", ".md",
        ".xml", ".csv", ".log", ".ps1", ".bat", ".cmd", ".pem"
    )
    $rasterExtensions = @(".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico")
    # python-docx 1.2.0 ships this fixed, non-user thumbnail. Every other
    # raster image is rejected, so an account screenshot or QR image cannot
    # enter a release merely by using an innocent filename.
    $allowedRasterHashes = @{
        "_internal\docx\templates\default-docx-template\docprops\thumbnail.jpeg" =
            "96367138dc44ce09bf2c8f0f8e49348a1478d2c5c0af69bbc2bbc38b63cdcead"
    }
    $forbiddenNamePattern = '(?i)(?:^|[-_.])(qr(?:code)?|wechat|account|screenshot)(?:[-_.]|$)|二维码|账号|账户截图'
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
    $binarySecretRules = @(
        [regex]::new('-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        [regex]::new(
            '(?:sk-(?:proj-)?[A-Za-z0-9_-]{24,}|ghp_[A-Za-z0-9]{32,}|AKIA[A-Z0-9]{16})',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    )

    foreach ($file in Get-ChildItem -LiteralPath $Root -File -Recurse -Force) {
        $relativePath = $file.FullName.Substring($rootFull.Length)
        $normalizedRelativePath = $relativePath.Replace("/", "\").ToLowerInvariant()
        $parts = @($relativePath -split '[\\/]')
        $lowerName = $file.Name.ToLowerInvariant()
        $lowerExtension = $file.Extension.ToLowerInvariant()
        if (
            $forbiddenNames -contains $lowerName -or
            $lowerName -like ".env*" -or
            $forbiddenExtensions -contains $lowerExtension -or
            $file.BaseName -match $forbiddenNamePattern -or
            @($parts | Where-Object { $_ -eq $assetLibraryName }).Count -gt 0
        ) {
            $findings.Add("forbidden-artifact:$relativePath")
            continue
        }
        if ($rasterExtensions -contains $lowerExtension) {
            $allowedHash = $allowedRasterHashes[$normalizedRelativePath]
            if ([string]::IsNullOrWhiteSpace($allowedHash) -or
                (Get-Sha256 $file.FullName) -cne $allowedHash) {
                $findings.Add("unapproved-raster-image:$relativePath")
            }
            continue
        }
        if ($lowerExtension -eq ".svg") {
            try {
                $svg = [System.IO.File]::ReadAllText($file.FullName)
                if ($svg -match '(?i)<image\b|data\s*:\s*image/') {
                    $findings.Add("embedded-image-svg:$relativePath")
                    continue
                }
            } catch {
                $findings.Add("content-scan-error:$relativePath")
                continue
            }
        }
        $stream = $null
        try {
            $stream = [System.IO.File]::Open(
                $file.FullName, [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite
            )
            $buffer = New-Object byte[] 65536
            $tail = ""
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $chunk = $tail + [System.Text.Encoding]::UTF8.GetString($buffer, 0, $read)
                $rules = if ($textExtensions -contains $lowerExtension) {
                    $secretRules
                } else {
                    $binarySecretRules
                }
                if (@($rules | Where-Object { $_.IsMatch($chunk) }).Count -gt 0) {
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
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$RequireX64
    )
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        if ($stream.Length -lt 70) { throw "PE file is too short: $Path" }
        $dos = New-Object byte[] 64
        if ($stream.Read($dos, 0, 64) -ne 64) { throw "Cannot read DOS header: $Path" }
        if ($dos[0] -ne 0x4D -or $dos[1] -ne 0x5A) { throw "Missing MZ signature: $Path" }
        $peOffset = [System.BitConverter]::ToInt32($dos, 0x3C)
        if ($peOffset -lt 64 -or $peOffset -gt ($stream.Length - 6)) {
            throw "Invalid e_lfanew: $Path"
        }
        $null = $stream.Seek($peOffset, [System.IO.SeekOrigin]::Begin)
        $header = New-Object byte[] 6
        if ($stream.Read($header, 0, 6) -ne 6) { throw "Cannot read PE header: $Path" }
        if (
            $header[0] -ne 0x50 -or $header[1] -ne 0x45 -or
            $header[2] -ne 0x00 -or $header[3] -ne 0x00
        ) { throw "Missing PE signature: $Path" }
        $machine = [System.BitConverter]::ToUInt16($header, 4)
        if ($RequireX64 -and $machine -ne 0x8664) {
            throw "PE is not AMD64 (machine=0x$($machine.ToString('X4'))): $Path"
        }
    } finally {
        $stream.Dispose()
    }
}

function Assert-VersionInfo {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Version,
        [Parameter(Mandatory = $true)][string]$Publisher
    )
    $info = (Get-Item -LiteralPath $Path).VersionInfo
    $expected = [ordered]@{
        FileVersion = $Version.windows_file_version
        ProductVersion = $Version.semantic_version
        ProductName = $Version.product_name
        CompanyName = $Publisher
        OriginalFilename = "$($Version.product_name).exe"
    }
    foreach ($entry in $expected.GetEnumerator()) {
        if ([string]$info.($entry.Key) -ne [string]$entry.Value) {
            throw "VersionInfo $($entry.Key) mismatch for $Path."
        }
    }
    if ([string]::IsNullOrWhiteSpace($info.LegalCopyright)) {
        throw "VersionInfo copyright is missing for $Path."
    }
}

function Invoke-Git {
    param(
        [Parameter(Mandatory = $true)][string]$ProjectRoot,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $output = (& git -C $ProjectRoot @Arguments 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "git $($Arguments -join ' ') failed: $output" }
    return $output
}

function Assert-CleanReleaseCommit {
    param(
        [Parameter(Mandatory = $true)][string]$ProjectRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedSha,
        [Parameter(Mandatory = $true)][string]$BaselineSha
    )
    $status = Invoke-Git $ProjectRoot @("status", "--porcelain", "--untracked-files=all")
    if (-not [string]::IsNullOrWhiteSpace($status)) {
        throw "Release requires a clean Git worktree, including no untracked files."
    }
    $head = Invoke-Git $ProjectRoot @("rev-parse", "HEAD")
    if ($head -ne $ExpectedSha) { throw "HEAD differs from ExpectedReleaseSha." }
    Invoke-Git $ProjectRoot @("fetch", "--no-tags", "origin", "main") | Out-Null
    $remoteMain = Invoke-Git $ProjectRoot @("rev-parse", "refs/remotes/origin/main")
    if ($remoteMain -ne $ExpectedSha) {
        throw "ExpectedReleaseSha must equal the freshly fetched origin/main."
    }
    & git -C $ProjectRoot merge-base --is-ancestor $BaselineSha $ExpectedSha
    if ($LASTEXITCODE -ne 0) { throw "Release baseline is not an ancestor of the release commit." }
    $modes = Invoke-Git $ProjectRoot @("ls-tree", "-r", $ExpectedSha)
    if ($modes -match '(?m)^(120000|160000) ') {
        throw "Release source contains a symlink or submodule, which git archive cannot safely reproduce."
    }
    return [ordered]@{
        commit = $head
        tree = Invoke-Git $ProjectRoot @("rev-parse", "$ExpectedSha`^{tree}")
        epoch = [int64](Invoke-Git $ProjectRoot @("show", "-s", "--format=%ct", $ExpectedSha))
        remote_main = $remoteMain
    }
}

function Assert-AndConsumeBuildEnvironment {
    param(
        [Parameter(Mandatory = $true)][string]$VenvRoot,
        [Parameter(Mandatory = $true)][string]$ProjectRoot,
        [switch]$RequireVerifiedPython
    )
    $markerPath = Join-Path $VenvRoot ".build-environment.json"
    $freezePath = Join-Path $VenvRoot ".installed-packages.txt"
    $pythonPath = Join-Path $VenvRoot "Scripts\python.exe"
    foreach ($required in @($markerPath, $freezePath, $pythonPath)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Fresh prepared build environment is incomplete: $required"
        }
    }
    $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
    if ($marker.schema -ne 1 -or $null -ne $marker.consumed_at_utc) {
        throw "Build environment is not fresh and unused. Run Prepare-BuildEnv.ps1 again."
    }
    $prepared = [DateTime]::Parse($marker.prepared_at_utc).ToUniversalTime()
    if (([DateTime]::UtcNow - $prepared).TotalHours -gt 2) {
        throw "Build environment is older than two hours; prepare a fresh environment."
    }
    if ($marker.build_lock_sha256 -ne (Get-Sha256 (Join-Path $ProjectRoot "requirements.build.lock")) -or
        $marker.bootstrap_lock_sha256 -ne (Get-Sha256 (Join-Path $ProjectRoot "requirements.bootstrap.lock")) -or
        $marker.installed_packages_sha256 -ne (Get-Sha256 $freezePath)) {
        throw "Build environment fingerprint differs from the committed hash locks."
    }
    if ($RequireVerifiedPython -and (
        $marker.python_hash_verified -ne $true -or
        [string]$marker.python_source_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$marker.python_expected_sha256 -cne [string]$marker.python_source_sha256
    )) {
        throw "Signed candidate requires a build Python verified against its expected SHA-256."
    }
    $actualFreeze = (& $pythonPath -m pip freeze --all --disable-pip-version-check | Out-String).Trim() + "`n"
    $actualBytes = [System.Text.Encoding]::UTF8.GetBytes($actualFreeze)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $actualFreezeHash = ([System.BitConverter]::ToString($sha.ComputeHash($actualBytes))).Replace("-", "").ToLowerInvariant()
    } finally { $sha.Dispose() }
    if ($actualFreezeHash -ne $marker.installed_packages_sha256) {
        throw "Installed package set changed after the build environment was prepared."
    }
    $marker.consumed_at_utc = [DateTime]::UtcNow.ToString("o")
    $marker | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $markerPath -Encoding UTF8
    return $pythonPath
}

function Assert-CertificateChain {
    param([Parameter(Mandatory = $true)]$Certificate)
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    try {
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(20)
        if (-not $chain.Build($Certificate)) {
            $statuses = @($chain.ChainStatus | ForEach-Object { $_.Status.ToString() }) -join ","
            throw "Certificate chain validation failed: $statuses"
        }
    } finally { $chain.Dispose() }
}

function Invoke-SignAndVerify {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Tool,
        [Parameter(Mandatory = $true)][string]$Provider,
        [Parameter(Mandatory = $true)][string]$Publisher,
        [Parameter(Mandatory = $true)][string]$Timestamp,
        [string]$AzureDlib,
        [string]$AzureMetadata,
        [string]$DigiCertAlias,
        [string]$DigiCertCertFile,
        [switch]$VerifyOnly
    )
    $arguments = @("sign", "/v", "/fd", "SHA256", "/tr", $Timestamp, "/td", "SHA256")
    if ($Provider -eq "AzureArtifactSigning") {
        $arguments += @("/dlib", $AzureDlib, "/dmdf", $AzureMetadata)
    } elseif ($Provider -eq "DigiCertKeyLocker") {
        $arguments += @(
            "/csp", "DigiCert Signing Manager KSP", "/kc", $DigiCertAlias,
            "/f", $DigiCertCertFile
        )
    } else {
        throw "Unsupported trusted signing provider."
    }
    if (-not $VerifyOnly) {
        & $Tool @arguments $Path
        if ($LASTEXITCODE -ne 0) { throw "SignTool failed to sign $Path." }
    }
    & $Tool verify /pa /all /v /tw $Path
    if ($LASTEXITCODE -ne 0) { throw "SignTool verification failed for $Path." }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Get-AuthenticodeSignature did not report a valid signature."
    }
    if ($null -eq $signature.SignerCertificate -or $null -eq $signature.TimeStamperCertificate) {
        throw "Signature lacks a signer or trusted RFC 3161 timestamp certificate."
    }
    $simpleName = $signature.SignerCertificate.GetNameInfo(
        [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
        $false
    )
    if ($simpleName -cne $Publisher) {
        throw "Signer Publisher '$simpleName' differs from DEFENSE_TRACKER_PUBLISHER."
    }
    $codeSigningEku = $false
    foreach ($extension in $signature.SignerCertificate.Extensions) {
        if ($extension -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            if (@($extension.EnhancedKeyUsages | Where-Object { $_.Value -eq "1.3.6.1.5.5.7.3.3" }).Count -gt 0) {
                $codeSigningEku = $true
            }
        }
    }
    if (-not $codeSigningEku) { throw "Signer certificate lacks the Code Signing EKU." }
    Assert-CertificateChain $signature.SignerCertificate
    Assert-CertificateChain $signature.TimeStamperCertificate
    return [ordered]@{
        provider = $Provider
        publisher = $Publisher
        signer_subject = $signature.SignerCertificate.Subject
        timestamp_url = $Timestamp
        timestamp_certificate_subject = $signature.TimeStamperCertificate.Subject
        verified_at_utc = [DateTime]::UtcNow.ToString("o")
    }
}

function Invoke-DesktopSmokeTest {
    param(
        [Parameter(Mandatory = $true)][string]$ExePath,
        [Parameter(Mandatory = $true)][string]$RuntimeRoot,
        [Parameter(Mandatory = $true)]$Version,
        [Parameter(Mandatory = $true)][string]$ExpectedCommit
    )
    $previousHome = [Environment]::GetEnvironmentVariable("DEFENSE_TRACKER_HOME", "Process")
    $previousEvidence = [Environment]::GetEnvironmentVariable("DEFENSE_TRACKER_SMOKE_EVIDENCE", "Process")
    $smokeEvidence = Join-Path $RuntimeRoot "desktop-smoke.json"
    [Environment]::SetEnvironmentVariable("DEFENSE_TRACKER_HOME", $RuntimeRoot, "Process")
    [Environment]::SetEnvironmentVariable("DEFENSE_TRACKER_SMOKE_EVIDENCE", $smokeEvidence, "Process")
    $process = $null
    try {
        $process = Start-Process -FilePath $ExePath -PassThru -WindowStyle Hidden
        $deadline = [DateTime]::UtcNow.AddSeconds(60)
        $workspaceReady = $false
        $windowReady = $false
        while ([DateTime]::UtcNow -lt $deadline) {
            if ($process.HasExited) { throw "Desktop smoke process exited early with code $($process.ExitCode)." }
            $process.Refresh()
            if ($process.MainWindowTitle -like "*V9*Defense Command Hub*") { $windowReady = $true }
            if (Test-Path -LiteralPath $smokeEvidence -PathType Leaf) {
                try {
                    $evidence = Get-Content -LiteralPath $smokeEvidence -Raw | ConvertFrom-Json
                    if ($evidence.schema -eq 1 -and
                        $evidence.http_status -eq 200 -and
                        $evidence.pathname -eq "/" -and
                        $evidence.workspace_ready -eq $true -and
                        $evidence.version -eq $Version.semantic_version -and
                        $evidence.display_version -eq $Version.display_version -and
                        $evidence.release_tag -eq $Version.release_tag -and
                        $evidence.build_commit -eq $ExpectedCommit) {
                        $workspaceReady = $true
                    }
                } catch {}
            }
            if ($workspaceReady -and $windowReady) { return }
            Start-Sleep -Milliseconds 400
        }
        throw "Desktop smoke timeout (authenticated workspace=$workspaceReady, V9 window=$windowReady)."
    } finally {
        if ($null -ne $process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force
            $process.WaitForExit(10000) | Out-Null
        }
        [Environment]::SetEnvironmentVariable("DEFENSE_TRACKER_HOME", $previousHome, "Process")
        [Environment]::SetEnvironmentVariable("DEFENSE_TRACKER_SMOKE_EVIDENCE", $previousEvidence, "Process")
    }
}

function Invoke-InstallerLifecycleSmokeTest {
    param(
        [Parameter(Mandatory = $true)][string]$InstallerPath,
        [Parameter(Mandatory = $true)][string]$InstallRoot,
        [Parameter(Mandatory = $true)][string]$RuntimeRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedExeSha256,
        [Parameter(Mandatory = $true)]$Version,
        [Parameter(Mandatory = $true)][string]$ExpectedCommit
    )
    $installLog = Join-Path $InstallRoot "install-smoke.log"
    $arguments = @(
        "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-",
        ('/DIR="' + $InstallRoot + '"'), ('/LOG="' + $installLog + '"')
    )
    $setup = Start-Process -FilePath $InstallerPath -ArgumentList $arguments `
        -PassThru -Wait -WindowStyle Hidden
    if ($setup.ExitCode -ne 0) { throw "Silent installer smoke failed with exit $($setup.ExitCode)." }
    $installedExe = Join-Path $InstallRoot "DefenseTracker.exe"
    if (-not (Test-Path -LiteralPath $installedExe -PathType Leaf) -or
        (Get-Sha256 $installedExe) -cne $ExpectedExeSha256) {
        throw "Silent installer did not install the exact signed application."
    }
    Invoke-DesktopSmokeTest $installedExe $RuntimeRoot $Version $ExpectedCommit

    $uninstaller = Join-Path $InstallRoot "unins000.exe"
    if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
        throw "Silent installer did not create an uninstaller."
    }
    $uninstall = Start-Process -FilePath $uninstaller `
        -ArgumentList @("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART") `
        -PassThru -Wait -WindowStyle Hidden
    if ($uninstall.ExitCode -ne 0) { throw "Silent uninstall smoke failed with exit $($uninstall.ExitCode)." }
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while ((Test-Path -LiteralPath $installedExe) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 250
    }
    if (Test-Path -LiteralPath $installedExe) {
        throw "Silent uninstall left the installed application executable behind."
    }
}

function Invoke-LegacyMigrationSmokeTest {
    param(
        [Parameter(Mandatory = $true)][string]$ApplicationRoot,
        [Parameter(Mandatory = $true)][string]$RuntimeRoot,
        [Parameter(Mandatory = $true)]$Version,
        [Parameter(Mandatory = $true)][string]$ExpectedCommit
    )
    $legacyToken = "legacy-synthetic-token-never-publish"
    $currentToken = "current-synthetic-token-never-overwrite"
    New-Item -ItemType Directory -Path (Join-Path $ApplicationRoot "data") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $RuntimeRoot "config") -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $ApplicationRoot ".access_token") `
        -Value $legacyToken -Encoding UTF8 -NoNewline
    Set-Content -LiteralPath (Join-Path $ApplicationRoot "data\migration-smoke.json") `
        -Value '{"synthetic":true}' -Encoding UTF8 -NoNewline
    Set-Content -LiteralPath (Join-Path $RuntimeRoot "config\.access_token") `
        -Value $currentToken -Encoding UTF8 -NoNewline

    Invoke-DesktopSmokeTest (Join-Path $ApplicationRoot "DefenseTracker.exe") `
        $RuntimeRoot $Version $ExpectedCommit
    $retained = Get-Content -LiteralPath (Join-Path $RuntimeRoot "config\.access_token") -Raw
    if ($retained -cne $currentToken) { throw "Legacy migration overwrote existing runtime configuration." }
    if (-not (Test-Path -LiteralPath (Join-Path $RuntimeRoot "data\migration-smoke.json") -PathType Leaf)) {
        throw "Legacy migration did not copy a missing synthetic data file."
    }
    $migrationManifest = Join-Path $RuntimeRoot "logs\legacy-migration.json"
    if (-not (Test-Path -LiteralPath $migrationManifest -PathType Leaf)) {
        throw "Legacy migration did not write its redacted evidence manifest."
    }
    $manifestText = Get-Content -LiteralPath $migrationManifest -Raw
    if ($manifestText.Contains($legacyToken) -or $manifestText.Contains($currentToken)) {
        throw "Legacy migration evidence exposed synthetic configuration values."
    }
}

function Invoke-DefenderScan {
    param(
        [Parameter(Mandatory = $true)][string]$Tool,
        [Parameter(Mandatory = $true)][string]$Path
    )
    & $Tool -DisableRemediation -Scan -ScanType 3 -File $Path
    if ($LASTEXITCODE -ne 0) { throw "Microsoft Defender scan failed for $Path (exit $LASTEXITCODE)." }
}

function Write-DevelopmentBuildManifest {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)]$Version,
        [Parameter(Mandatory = $true)]$GitFacts,
        [Parameter(Mandatory = $true)][string]$Publisher
    )
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd("\") + "\"
    $files = @(
        Get-ChildItem -LiteralPath $Root -File -Recurse -Force | Sort-Object FullName |
            ForEach-Object {
                [ordered]@{
                    path = $_.FullName.Substring($rootFull.Length).Replace("\", "/")
                    bytes = $_.Length
                    sha256 = Get-Sha256 $_.FullName
                }
            }
    )
    [ordered]@{
        schema = 2
        kind = "unsigned-development-build"
        product = $Version.product_name
        version = $Version
        release = [ordered]@{
            commit = $GitFacts.commit
            baseline_commit = $Version.release_baseline
            source_tree = $GitFacts.tree
        }
        signature = [ordered]@{ authenticode = "NotRequiredForDevelopment"; publisher = $Publisher }
        files = $files
    } | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath (Join-Path $Root "release-manifest.json") -Encoding UTF8
}

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$versionFile = Join-Path $projectRoot "version.json"
if (-not (Test-Path -LiteralPath $versionFile -PathType Leaf)) { throw "version.json is missing." }
$version = Get-Content -LiteralPath $versionFile -Raw | ConvertFrom-Json
if ($version.semantic_version -notmatch '^\d+\.\d+\.\d+$' -or
    $version.windows_file_version -notmatch '^\d+\.\d+\.\d+\.\d+$' -or
    $version.release_tag -ne "v$($version.semantic_version)") {
    throw "version.json is invalid."
}
if ([string]::IsNullOrWhiteSpace($PublisherName)) {
    throw "DEFENSE_TRACKER_PUBLISHER must be the verified legal Publisher; it is never inferred."
}

$gitFacts = Assert-CleanReleaseCommit $projectRoot $ExpectedReleaseSha $version.release_baseline
$venvRoot = Join-Path $projectRoot ".venv-build"
$venvPython = Assert-AndConsumeBuildEnvironment $venvRoot $projectRoot `
    -RequireVerifiedPython:$RequireSignedInstaller
$buildEnvironmentMarker = Get-Content -LiteralPath (Join-Path $venvRoot ".build-environment.json") `
    -Raw | ConvertFrom-Json
$buildRoot = Join-Path $projectRoot "build"
$sourceRoot = Join-Path $buildRoot "release-source"
$sourceArchive = Join-Path $buildRoot "release-source.zip"
$stagingRoot = Join-Path $buildRoot "release-staging\DefenseTracker"
$stagedExe = Join-Path $stagingRoot "DefenseTracker.exe"
$smokeRuntime = Join-Path $buildRoot "smoke-runtime"
$installerStaging = Join-Path $buildRoot "installer-staging"
$installerExtract = Join-Path $buildRoot "installer-extract"
$preparationStaging = Join-Path $buildRoot "candidate-preparation"
$portableExtract = Join-Path $buildRoot "portable-extract"
$portableSmokeRuntime = Join-Path $buildRoot "portable-smoke-runtime"
$installerSmokeRoot = Join-Path $buildRoot "installer-smoke-install"
$installerSmokeRuntime = Join-Path $buildRoot "installer-smoke-runtime"
$migrationSmokeApp = Join-Path $buildRoot "migration-smoke-app"
$migrationSmokeRuntime = Join-Path $buildRoot "migration-smoke-runtime"
$assetStaging = Join-Path $buildRoot "release-assets"
$evidenceRoot = Join-Path $buildRoot "release-evidence"
New-Item -ItemType Directory -Path $buildRoot,$evidenceRoot -Force | Out-Null
Reset-GeneratedDirectory $sourceRoot $sourceRoot (Join-Path $evidenceRoot "previous-release-source.json")
Reset-GeneratedDirectory $installerStaging $installerStaging (Join-Path $evidenceRoot "previous-installer-staging.json")
Reset-GeneratedDirectory $preparationStaging $preparationStaging (Join-Path $evidenceRoot "previous-candidate-preparation.json")
Reset-GeneratedDirectory $assetStaging $assetStaging (Join-Path $evidenceRoot "previous-release-assets.json")
Reset-GeneratedDirectory $smokeRuntime $smokeRuntime (Join-Path $evidenceRoot "previous-smoke-runtime.json")
Reset-GeneratedDirectory $portableSmokeRuntime $portableSmokeRuntime (Join-Path $evidenceRoot "previous-portable-smoke-runtime.json")
Reset-GeneratedDirectory $installerSmokeRoot $installerSmokeRoot (Join-Path $evidenceRoot "previous-installer-smoke-install.json")
Reset-GeneratedDirectory $installerSmokeRuntime $installerSmokeRuntime (Join-Path $evidenceRoot "previous-installer-smoke-runtime.json")
Reset-GeneratedDirectory $migrationSmokeApp $migrationSmokeApp (Join-Path $evidenceRoot "previous-migration-smoke-app.json")
Reset-GeneratedDirectory $migrationSmokeRuntime $migrationSmokeRuntime (Join-Path $evidenceRoot "previous-migration-smoke-runtime.json")
if (Test-Path -LiteralPath $sourceArchive) { Remove-Item -LiteralPath $sourceArchive -Force }

& git -C $projectRoot archive --format=zip --output=$sourceArchive $ExpectedReleaseSha
if ($LASTEXITCODE -ne 0) { throw "Unable to materialize the immutable release source." }
Expand-Archive -LiteralPath $sourceArchive -DestinationPath $sourceRoot -Force
$builder = Join-Path $sourceRoot "scripts\build_app.py"
$builderFindings = @(Get-BuilderSafetyFindings $builder)
if ($builderFindings.Count -gt 0) { throw "Builder safety gate failed: $($builderFindings -join ', ')" }

$environmentNames = @(
    "DEFENSE_TRACKER_BUILD_OUTPUT_ROOT", "DEFENSE_TRACKER_BUILD_TOOLCHAIN_ROOT",
    "DEFENSE_TRACKER_PUBLISHER", "DEFENSE_TRACKER_EXPECTED_RELEASE_SHA",
    "DEFENSE_TRACKER_SOURCE_TREE", "SOURCE_DATE_EPOCH"
)
$previousEnvironment = @{}
foreach ($name in $environmentNames) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}
$buildStartedUtc = [DateTime]::UtcNow
$buildFinishedUtc = $null
try {
    [Environment]::SetEnvironmentVariable("DEFENSE_TRACKER_BUILD_OUTPUT_ROOT", $buildRoot, "Process")
    [Environment]::SetEnvironmentVariable("DEFENSE_TRACKER_BUILD_TOOLCHAIN_ROOT", $venvRoot, "Process")
    [Environment]::SetEnvironmentVariable("DEFENSE_TRACKER_PUBLISHER", $PublisherName, "Process")
    [Environment]::SetEnvironmentVariable("DEFENSE_TRACKER_EXPECTED_RELEASE_SHA", $ExpectedReleaseSha, "Process")
    [Environment]::SetEnvironmentVariable("DEFENSE_TRACKER_SOURCE_TREE", $gitFacts.tree, "Process")
    [Environment]::SetEnvironmentVariable("SOURCE_DATE_EPOCH", [string]$gitFacts.epoch, "Process")
    Push-Location $sourceRoot
    try {
        & $venvPython scripts/build_app.py
        if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed with exit $LASTEXITCODE." }
        $buildFinishedUtc = [DateTime]::UtcNow
    } finally { Pop-Location }
} finally {
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], "Process")
    }
}

if (-not (Test-Path -LiteralPath $stagedExe -PathType Leaf)) { throw "Staged executable is missing." }
$exe = Get-Item -LiteralPath $stagedExe
if ($exe.Length -le 0 -or $exe.LastWriteTimeUtc -lt $buildStartedUtc.AddSeconds(-5)) {
    throw "Staged executable is empty or predates this build."
}
if (([DateTime]::UtcNow - $exe.LastWriteTimeUtc).TotalMinutes -gt $MaxArtifactAgeMinutes) {
    throw "Staged executable is older than the allowed build window."
}
Assert-WindowsPeFile $stagedExe -RequireX64
Assert-VersionInfo $stagedExe $version $PublisherName
$artifactFindings = @(Get-ArtifactSafetyFindings $stagingRoot)
if ($artifactFindings.Count -gt 0) { throw "Artifact safety scan failed:`n - $($artifactFindings -join "`n - ")" }
$packagesFile = Join-Path $venvRoot ".installed-packages.txt"
$runtimeLockHash = Get-Sha256 (Join-Path $projectRoot "requirements.runtime.lock")
$buildLockHash = Get-Sha256 (Join-Path $projectRoot "requirements.build.lock")
$componentInventoryPath = Join-Path $evidenceRoot "unsigned-component-inventory.json"
$reviewerRegistry = Join-Path $sourceRoot "release\compliance-reviewers.json"

$signatureEvidence = $null
$resolvedSignTool = ""
$resolvedInno = ""
$resolvedSevenZip = ""
$resolvedDefender = ""
$resolvedInnoLicenseText = ""
$resolvedComplianceEvidence = ""
$toolchainEvidence = $null
if ($RequireSignedInstaller) {
    if ([string]::IsNullOrWhiteSpace($ComplianceEvidencePath) -or
        [string]::IsNullOrWhiteSpace($ComplianceSignaturePath) -or
        $ExpectedComplianceEvidenceSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "Signed candidates require signed, hash-pinned compliance evidence from the protected environment."
    }
    $resolvedComplianceEvidence = [System.IO.Path]::GetFullPath($ComplianceEvidencePath)
    $resolvedComplianceSignature = [System.IO.Path]::GetFullPath($ComplianceSignaturePath)
    if (-not (Test-Path -LiteralPath $resolvedComplianceEvidence -PathType Leaf) -or
        -not (Test-Path -LiteralPath $resolvedComplianceSignature -PathType Leaf) -or
        (Get-Sha256 $resolvedComplianceEvidence) -cne $ExpectedComplianceEvidenceSha256) {
        throw "Compliance evidence/signature is missing or differs from the protected SHA-256."
    }
    & $venvPython (Join-Path $sourceRoot "scripts\generate_component_inventory.py") `
        $stagingRoot $componentInventoryPath
    if ($LASTEXITCODE -ne 0) { throw "Unsigned component inventory generation failed." }
    $complianceVerifiedAtUtc = [DateTime]::UtcNow.ToString("o")
    & $venvPython (Join-Path $sourceRoot "scripts\verify_compliance_evidence.py") `
        --evidence $resolvedComplianceEvidence `
        --evidence-signature $resolvedComplianceSignature `
        --reviewer-registry $reviewerRegistry `
        --component-inventory $componentInventoryPath `
        --application-root $stagingRoot `
        --expected-sha256 $ExpectedComplianceEvidenceSha256 `
        --commit $ExpectedReleaseSha `
        --source-tree $gitFacts.tree `
        --publisher $PublisherName `
        --packages-file $packagesFile `
        --third-party-notices (Join-Path $sourceRoot "THIRD_PARTY_NOTICES.md") `
        --runtime-lock-sha256 $runtimeLockHash `
        --build-lock-sha256 $buildLockHash `
        --verified-at-utc $complianceVerifiedAtUtc
    if ($LASTEXITCODE -ne 0) { throw "Pre-sign compliance evidence validation failed." }
    if ($SigningProvider -notin @("AzureArtifactSigning", "DigiCertKeyLocker")) {
        throw "Stable release requires AzureArtifactSigning or DigiCertKeyLocker."
    }
    if ($TimestampUrl -notmatch '^https?://[^\s]+$') {
        throw "Stable release requires an explicit HTTP(S) RFC 3161 timestamp URL."
    }
    $resolvedSignTool = Resolve-RequiredTool $SignToolPath "signtool.exe" "Windows SDK SignTool"
    $resolvedInno = Resolve-RequiredTool $InnoSetupCompiler "ISCC.exe" "Inno Setup compiler"
    $resolvedSevenZip = Resolve-RequiredTool $SevenZipPath "7z.exe" "7-Zip installer inspector"
    $resolvedInnoLicenseText = Resolve-RequiredTool $InnoLicenseTextPath `
        "Inno Setup License.txt" "Inno Setup license text"
    if ($ExpectedInnoLicenseTextSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        (Get-Sha256 $resolvedInnoLicenseText) -cne $ExpectedInnoLicenseTextSha256) {
        throw "Inno Setup license text requires the exact protected SHA-256."
    }
    if ([string]::IsNullOrWhiteSpace($InnoCopyrightText) -or
        $InnoCopyrightText.Length -gt 500 -or $InnoCopyrightText -match '[\r\n\x00-\x08\x0b\x0c\x0e-\x1f]') {
        throw "Inno Setup copyright text is missing or unsafe."
    }
    if (-not [string]::IsNullOrWhiteSpace($DefenderPath)) {
        $resolvedDefender = Resolve-RequiredTool $DefenderPath "MpCmdRun.exe" "Microsoft Defender scanner"
    } else {
        $resolvedDefender = Resolve-RequiredTool "" "MpCmdRun.exe" "Microsoft Defender scanner"
    }
    if ($SigningProvider -eq "AzureArtifactSigning") {
        $AzureSigningDlib = Resolve-RequiredTool $AzureSigningDlib "Azure.CodeSigning.Dlib.dll" "Azure Artifact Signing DLib"
        $AzureSigningMetadata = Resolve-RequiredTool $AzureSigningMetadata "artifact-signing-metadata.json" "Azure Artifact Signing metadata"
    } else {
        if ([string]::IsNullOrWhiteSpace($DigiCertKeyAlias)) { throw "DigiCert KeyLocker key alias is missing." }
        $DigiCertCertificateFile = Resolve-RequiredTool $DigiCertCertificateFile "signing-certificate.crt" "DigiCert public signing certificate"
    }
    $toolchainEvidence = [ordered]@{
        python = [ordered]@{
            version = [string]$buildEnvironmentMarker.python
            sha256 = [string]$buildEnvironmentMarker.python_source_sha256
            expected_sha256 = [string]$buildEnvironmentMarker.python_expected_sha256
            hash_verified = $buildEnvironmentMarker.python_hash_verified -eq $true
        }
        signtool = Get-VerifiedToolEvidence $resolvedSignTool $ExpectedSignToolSha256 "Windows SDK SignTool"
        iscc = Get-VerifiedToolEvidence $resolvedInno $ExpectedInnoSha256 "Inno Setup compiler"
        seven_zip = Get-VerifiedToolEvidence $resolvedSevenZip $ExpectedSevenZipSha256 "7-Zip"
        defender = Get-VerifiedToolEvidence $resolvedDefender $ExpectedDefenderSha256 "Microsoft Defender scanner"
    }
    if ($SigningProvider -eq "AzureArtifactSigning") {
        $toolchainEvidence["azure_dlib"] = Get-VerifiedToolEvidence `
            $AzureSigningDlib $ExpectedAzureDlibSha256 "Azure Artifact Signing DLib"
        $toolchainEvidence["azure_metadata"] = Get-VerifiedToolEvidence `
            $AzureSigningMetadata $ExpectedAzureMetadataSha256 `
            "Azure Artifact Signing metadata" "not-applicable:json-metadata"
    }
    $toolchainEvidencePath = Join-Path $evidenceRoot "toolchain-evidence.json"
    $toolchainEvidence | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $toolchainEvidencePath -Encoding UTF8
    $applicationUnsignedDigestPath = Join-Path $evidenceRoot "application-authenticode-unsigned.json"
    & $venvPython (Join-Path $sourceRoot "scripts\authenticode_digest.py") `
        --path $stagedExe --require-state unsigned --output $applicationUnsignedDigestPath
    if ($LASTEXITCODE -ne 0) { throw "Unsigned application Authenticode identity capture failed." }
    $applicationUnsignedDigest = Get-Content -LiteralPath $applicationUnsignedDigestPath -Raw |
        ConvertFrom-Json
    $signatureEvidence = Invoke-SignAndVerify $stagedExe $resolvedSignTool $SigningProvider `
        $PublisherName $TimestampUrl $AzureSigningDlib $AzureSigningMetadata `
        $DigiCertKeyAlias $DigiCertCertificateFile
    $applicationSignedDigestPath = Join-Path $evidenceRoot "application-authenticode-signed.json"
    & $venvPython (Join-Path $sourceRoot "scripts\authenticode_digest.py") `
        --path $stagedExe --require-state signed `
        --expected-unsigned-size ([string]$applicationUnsignedDigest.bytes) `
        --expected-normalized-sha256 ([string]$applicationUnsignedDigest.normalized_sha256) `
        --output $applicationSignedDigestPath
    if ($LASTEXITCODE -ne 0) {
        throw "Signed application changed outside the Authenticode-normalized fields."
    }
}

Write-Host "[SMOKE] Launching staged application."
Invoke-DesktopSmokeTest $stagedExe $smokeRuntime $version $ExpectedReleaseSha

if ($RequireSignedInstaller) {
    $installerDefinition = Join-Path $sourceRoot "deploy\mvp\DefenseTracker.iss"
    & $resolvedInno `
        "/DAppSource=$stagingRoot" `
        "/DOutputDir=$installerStaging" `
        "/DAppVersion=$($version.semantic_version)" `
        "/DDisplayVersion=$($version.display_version)" `
        "/DWindowsFileVersion=$($version.windows_file_version)" `
        "/DGitShort=$($ExpectedReleaseSha.Substring(0, 12))" `
        "/DPublisherName=$PublisherName" `
        $installerDefinition
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed." }
    $stagedInstaller = Join-Path $installerStaging (
        "DefenseTracker-Setup-v$($version.semantic_version)-windows-x64.exe"
    )
    if (-not (Test-Path -LiteralPath $stagedInstaller -PathType Leaf)) { throw "Installer candidate is missing." }
    # Inno's bootstrap can be architecture-neutral; the embedded application
    # is independently required to be AMD64 above.
    Assert-WindowsPeFile $stagedInstaller
    if ($CandidateOnly) {
        if ($PreparationRunId -cnotmatch '^[1-9][0-9]{0,19}$' -or
            $PreparationRunAttempt -cnotmatch '^[1-9][0-9]{0,9}$' -or
            $PreparationRepository -cnotmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or
            [string]::IsNullOrWhiteSpace($PreparationWorkflowRef)) {
            throw "Candidate preparation requires exact GitHub run, repository and workflow provenance."
        }
        $expectedPreparationArtifactName =
            "DefenseTracker-v$($version.semantic_version)-preparation-$ExpectedReleaseSha-$PreparationRunId-$PreparationRunAttempt"
        if ($PreparationArtifactName -cne $expectedPreparationArtifactName) {
            throw "Candidate preparation artifact name differs from the exact run/SHA binding."
        }

        $installerUnsignedDigestPath = Join-Path $evidenceRoot "installer-authenticode-unsigned.json"
        & $venvPython (Join-Path $sourceRoot "scripts\authenticode_digest.py") `
            --path $stagedInstaller --require-state unsigned --output $installerUnsignedDigestPath
        if ($LASTEXITCODE -ne 0) { throw "Unsigned installer identity capture failed." }

        Reset-GeneratedDirectory $installerExtract $installerExtract `
            (Join-Path $evidenceRoot "previous-installer-extract.json")
        & $resolvedSevenZip x -y "-o$installerExtract" $stagedInstaller
        if ($LASTEXITCODE -ne 0) { throw "Unable to fully extract the unsigned installer with 7-Zip." }
        $installerFindings = @(Get-ArtifactSafetyFindings $installerExtract)
        if ($installerFindings.Count -gt 0) {
            throw "Unsigned installer content scan failed:`n - $($installerFindings -join "`n - ")"
        }
        $installedExe = @(Get-ChildItem -LiteralPath $installerExtract -Recurse -File -Filter "DefenseTracker.exe")
        if ($installedExe.Count -ne 1 -or
            (Get-Sha256 $installedExe[0].FullName) -cne (Get-Sha256 $stagedExe)) {
            throw "Unsigned installer does not contain the exact reviewed signed application."
        }

        $signedComponentInventoryPath = Join-Path $evidenceRoot "signed-component-inventory.json"
        & $venvPython (Join-Path $sourceRoot "scripts\generate_component_inventory.py") `
            $stagingRoot $signedComponentInventoryPath
        if ($LASTEXITCODE -ne 0) { throw "Signed application inventory generation failed." }
        $installerReviewRequestPath = Join-Path $evidenceRoot "installer-review-request.json"
        & $venvPython (Join-Path $sourceRoot "scripts\generate_installer_review_request.py") `
            --unsigned-installer $stagedInstaller `
            --payload-root $installerExtract `
            --signed-application-inventory $signedComponentInventoryPath `
            --iss $installerDefinition `
            --iscc $resolvedInno `
            --iscc-version ([string]$toolchainEvidence.iscc.version) `
            --seven-zip $resolvedSevenZip `
            --seven-zip-version ([string]$toolchainEvidence.seven_zip.version) `
            --bootstrap-license-declared LicenseRef-Inno-Setup `
            --bootstrap-license-concluded LicenseRef-Inno-Setup `
            --bootstrap-copyright-text $InnoCopyrightText `
            --bootstrap-license-text $resolvedInnoLicenseText `
            --commit $ExpectedReleaseSha `
            --source-tree $gitFacts.tree `
            --version $version.semantic_version `
            --publisher $PublisherName `
            --output $installerReviewRequestPath
        if ($LASTEXITCODE -ne 0) { throw "Installer review request generation failed." }

        $applicationCompliance = Get-Content -LiteralPath $resolvedComplianceEvidence -Raw |
            ConvertFrom-Json
        $applicationReviewerKeyId = [string]$applicationCompliance.reviewer_key_id
        if ($applicationReviewerKeyId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$') {
            throw "Application compliance evidence has no trustworthy reviewer key ID."
        }

        $bundleApplication = Join-Path $preparationStaging "application"
        $bundleInstallerRoot = Join-Path $preparationStaging "installer"
        $bundleEvidence = Join-Path $preparationStaging "evidence"
        New-Item -ItemType Directory -Path $bundleApplication,$bundleInstallerRoot,$bundleEvidence -Force |
            Out-Null
        Get-ChildItem -LiteralPath $stagingRoot -Force | Copy-Item -Destination $bundleApplication -Recurse -Force
        $bundleInstaller = Join-Path $bundleInstallerRoot ([System.IO.Path]::GetFileName($stagedInstaller))
        Copy-Item -LiteralPath $stagedInstaller -Destination $bundleInstaller
        $evidenceCopies = [ordered]@{
            "application-authenticode-unsigned.json" = $applicationUnsignedDigestPath
            "application-authenticode-signed.json" = $applicationSignedDigestPath
            "installer-authenticode-unsigned.json" = $installerUnsignedDigestPath
            "unsigned-component-inventory.json" = $componentInventoryPath
            "signed-component-inventory.json" = $signedComponentInventoryPath
            "toolchain-evidence.json" = $toolchainEvidencePath
            "application-compliance-evidence.json" = $resolvedComplianceEvidence
            "application-compliance-signature.txt" = $resolvedComplianceSignature
            "installed-packages.txt" = $packagesFile
            "installer-review-request.json" = $installerReviewRequestPath
            "inno-license.txt" = $resolvedInnoLicenseText
        }
        foreach ($name in $evidenceCopies.Keys) {
            Copy-Item -LiteralPath $evidenceCopies[$name] -Destination (Join-Path $bundleEvidence $name)
        }

        $bundleFiles = @(
            Get-ChildItem -LiteralPath $preparationStaging -Recurse -Force -File |
                Sort-Object FullName |
                ForEach-Object {
                    if (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                        throw "Candidate preparation bundle contains a reparse point."
                    }
                    [ordered]@{
                        path = $_.FullName.Substring($preparationStaging.Length + 1).Replace('\', '/')
                        bytes = $_.Length
                        sha256 = Get-Sha256 $_.FullName
                    }
                }
        )
        $preparationCreatedUtc = [DateTime]::UtcNow.ToString("o")
        $preparationManifest = [ordered]@{
            schema = 1
            kind = "defense-tracker-installer-review-preparation"
            release = [ordered]@{
                commit = $ExpectedReleaseSha
                source_tree = $gitFacts.tree
                source_date_epoch = [int64]$gitFacts.epoch
                source_date_epoch_utc = [DateTimeOffset]::FromUnixTimeSeconds(
                    [int64]$gitFacts.epoch
                ).UtcDateTime.ToString("o")
                version = $version.semantic_version
                release_tag = $version.release_tag
                publisher = $PublisherName
            }
            provenance = [ordered]@{
                repository = $PreparationRepository
                workflow_ref = $PreparationWorkflowRef
                run_id = $PreparationRunId
                run_attempt = $PreparationRunAttempt
                artifact_name = $PreparationArtifactName
            }
            build = [ordered]@{
                started_at_utc = $buildStartedUtc.ToString("o")
                application_finished_at_utc = $buildFinishedUtc.ToString("o")
                prepared_at_utc = $preparationCreatedUtc
                runtime_lock_sha256 = $runtimeLockHash
                build_lock_sha256 = $buildLockHash
            }
            application = [ordered]@{
                root = "application"
                reviewer_key_id = $applicationReviewerKeyId
                unsigned_digest = "evidence/application-authenticode-unsigned.json"
                signed_digest = "evidence/application-authenticode-signed.json"
                unsigned_component_inventory = "evidence/unsigned-component-inventory.json"
                signed_component_inventory = "evidence/signed-component-inventory.json"
                compliance_evidence = "evidence/application-compliance-evidence.json"
                compliance_signature = "evidence/application-compliance-signature.txt"
            }
            installer = [ordered]@{
                path = "installer/$([System.IO.Path]::GetFileName($stagedInstaller))"
                unsigned_digest = "evidence/installer-authenticode-unsigned.json"
                review_request = "evidence/installer-review-request.json"
                bootstrap_license = "evidence/inno-license.txt"
                bootstrap_license_sha256 = $ExpectedInnoLicenseTextSha256
                bootstrap_copyright_text = $InnoCopyrightText
            }
            files = $bundleFiles
        }
        $preparationManifestPath = Join-Path $preparationStaging "preparation-manifest.json"
        $preparationManifest | ConvertTo-Json -Depth 10 |
            Set-Content -LiteralPath $preparationManifestPath -Encoding UTF8

        $postStatus = Invoke-Git $projectRoot @("status", "--porcelain", "--untracked-files=all")
        if (-not [string]::IsNullOrWhiteSpace($postStatus)) {
            throw "Tracked or untracked source changed during candidate preparation."
        }
        if ((Invoke-Git $projectRoot @("rev-parse", "HEAD")) -ne $ExpectedReleaseSha) {
            throw "HEAD changed during candidate preparation."
        }
        Invoke-Git $projectRoot @("fetch", "--no-tags", "origin", "main") | Out-Null
        if ((Invoke-Git $projectRoot @("rev-parse", "refs/remotes/origin/main")) -ne $ExpectedReleaseSha) {
            throw "origin/main changed during candidate preparation; restart from the reviewed commit."
        }

        $distRoot = Join-Path $projectRoot "dist"
        $preparationParent = Join-Path $distRoot ("candidate-preparations\" + $version.release_tag)
        $preparationCommitRoot = Join-Path $preparationParent $ExpectedReleaseSha
        $preparationRoot = Join-Path $preparationCommitRoot $PreparationRunId
        if (Test-Path -LiteralPath $preparationRoot) {
            throw "Immutable candidate preparation directory already exists: $preparationRoot"
        }
        New-Item -ItemType Directory -Path $preparationCommitRoot -Force | Out-Null
        Move-Item -LiteralPath $preparationStaging -Destination $preparationRoot
        Write-Host ""
        Write-Host "[REVIEW] Signed application and unsigned installer review bundle prepared."
        Write-Host "         Commit: $ExpectedReleaseSha"
        Write-Host "         Run: $PreparationRunId"
        Write-Host "         Bundle: $preparationRoot"
        Write-Host "         The installer is unsigned; no stable assets were generated."
        return
    }
    $installerSignature = Invoke-SignAndVerify $stagedInstaller $resolvedSignTool $SigningProvider `
        $PublisherName $TimestampUrl $AzureSigningDlib $AzureSigningMetadata `
        $DigiCertKeyAlias $DigiCertCertificateFile
    $buildFinishedUtc = [DateTime]::UtcNow
    Invoke-DefenderScan $resolvedDefender $stagingRoot
    Invoke-DefenderScan $resolvedDefender $stagedInstaller

    Reset-GeneratedDirectory $installerExtract $installerExtract (Join-Path $evidenceRoot "previous-installer-extract.json")
    & $resolvedSevenZip x -y "-o$installerExtract" $stagedInstaller
    if ($LASTEXITCODE -ne 0) { throw "Unable to inspect installer contents with 7-Zip." }
    $installerFindings = @(Get-ArtifactSafetyFindings $installerExtract)
    if ($installerFindings.Count -gt 0) { throw "Installer content scan failed:`n - $($installerFindings -join "`n - ")" }
    $installedExe = @(Get-ChildItem -LiteralPath $installerExtract -Recurse -File -Filter "DefenseTracker.exe")
    if ($installedExe.Count -ne 1 -or (Get-Sha256 $installedExe[0].FullName) -ne (Get-Sha256 $stagedExe)) {
        throw "Installer does not contain the exact signed staged executable."
    }
    Invoke-InstallerLifecycleSmokeTest $stagedInstaller $installerSmokeRoot `
        $installerSmokeRuntime (Get-Sha256 $stagedExe) $version $ExpectedReleaseSha
    $releaseInputsVerifiedUtc = [DateTime]::UtcNow

    $pythonVersion = (& $venvPython --version 2>&1 | Out-String).Trim()
    & $venvPython (Join-Path $sourceRoot "scripts\package_release_assets.py") `
        --application-root $stagingRoot `
        --installer $stagedInstaller `
        --output-dir $assetStaging `
        --third-party-notices (Join-Path $sourceRoot "THIRD_PARTY_NOTICES.md") `
        --packages-file $packagesFile `
        --commit $ExpectedReleaseSha `
        --source-tree $gitFacts.tree `
        --source-date-epoch $gitFacts.epoch `
        --build-started-utc $buildStartedUtc.ToString("o") `
        --build-finished-utc $buildFinishedUtc.ToString("o") `
        --verified-at-utc $releaseInputsVerifiedUtc.ToString("o") `
        --publisher $PublisherName `
        --signing-provider $SigningProvider `
        --signer-subject $installerSignature.signer_subject `
        --timestamp-url $TimestampUrl `
        --timestamp-subject $installerSignature.timestamp_certificate_subject `
        --python-version $pythonVersion `
        --runtime-lock-sha256 $runtimeLockHash `
        --build-lock-sha256 $buildLockHash `
        --toolchain-evidence $toolchainEvidencePath `
        --compliance-evidence $resolvedComplianceEvidence `
        --compliance-evidence-sha256 $ExpectedComplianceEvidenceSha256 `
        --compliance-signature $resolvedComplianceSignature `
        --compliance-reviewer-registry $reviewerRegistry `
        --component-inventory $componentInventoryPath
    if ($LASTEXITCODE -ne 0) { throw "Release asset packaging failed." }
    Reset-GeneratedDirectory $portableExtract $portableExtract (Join-Path $evidenceRoot "previous-portable-extract.json")
    $portableZip = Join-Path $assetStaging (
        "DefenseTracker-v$($version.semantic_version)-windows-x64-portable.zip"
    )
    Expand-Archive -LiteralPath $portableZip -DestinationPath $portableExtract -Force
    $portableFindings = @(Get-ArtifactSafetyFindings $portableExtract)
    if ($portableFindings.Count -gt 0) { throw "Portable ZIP content scan failed:`n - $($portableFindings -join "`n - ")" }
    $portableExe = Join-Path $portableExtract "DefenseTracker\DefenseTracker.exe"
    $null = Invoke-SignAndVerify $portableExe $resolvedSignTool $SigningProvider `
        $PublisherName $TimestampUrl $AzureSigningDlib $AzureSigningMetadata `
        $DigiCertKeyAlias $DigiCertCertificateFile -VerifyOnly
    Invoke-DefenderScan $resolvedDefender $portableExtract
    Invoke-DesktopSmokeTest $portableExe $portableSmokeRuntime $version $ExpectedReleaseSha
    Copy-Item -Path (Join-Path $portableExtract "DefenseTracker\*") `
        -Destination $migrationSmokeApp -Recurse -Force
    Invoke-LegacyMigrationSmokeTest $migrationSmokeApp $migrationSmokeRuntime `
        $version $ExpectedReleaseSha
    $assetFindings = @(Get-ArtifactSafetyFindings $assetStaging)
    if ($assetFindings.Count -gt 0) { throw "Final asset safety scan failed:`n - $($assetFindings -join "`n - ")" }
    $releaseVerificationCompletedUtc = [DateTime]::UtcNow.ToString("o")
    & $venvPython (Join-Path $sourceRoot "scripts\finalize_release_assets.py") `
        $assetStaging --expected-commit $ExpectedReleaseSha `
        --completed-at-utc $releaseVerificationCompletedUtc `
        --portable-exe-sha256 (Get-Sha256 $portableExe)
    if ($LASTEXITCODE -ne 0) { throw "Release verification evidence finalization failed." }
    & $venvPython (Join-Path $sourceRoot "scripts\verify_release_assets.py") `
        $assetStaging --expected-commit $ExpectedReleaseSha
    if ($LASTEXITCODE -ne 0) { throw "Release asset verification failed." }
} else {
    Write-DevelopmentBuildManifest $stagingRoot $version $gitFacts $PublisherName
}

$postStatus = Invoke-Git $projectRoot @("status", "--porcelain", "--untracked-files=all")
if (-not [string]::IsNullOrWhiteSpace($postStatus)) { throw "Tracked or untracked source changed during the build." }
if ((Invoke-Git $projectRoot @("rev-parse", "HEAD")) -ne $ExpectedReleaseSha) { throw "HEAD changed during the build." }
Invoke-Git $projectRoot @("fetch", "--no-tags", "origin", "main") | Out-Null
if ((Invoke-Git $projectRoot @("rev-parse", "refs/remotes/origin/main")) -ne $ExpectedReleaseSha) {
    throw "origin/main changed during the release build; restart from the newly reviewed commit."
}

$distRoot = Join-Path $projectRoot "dist"
$activeRoot = Join-Path $distRoot "DefenseTracker"
$archiveRoot = Join-Path $distRoot "archive"
$publishedAssetRoot = $null
if ($RequireSignedInstaller -and $CandidateOnly) {
    $candidateParent = Join-Path $distRoot ("candidates\" + $version.release_tag)
    $candidateRoot = Join-Path $candidateParent $ExpectedReleaseSha
    if (Test-Path -LiteralPath $candidateRoot) {
        throw "Immutable signed candidate directory already exists: $candidateRoot"
    }
    New-Item -ItemType Directory -Path $candidateParent -Force | Out-Null
    Move-Item -LiteralPath $assetStaging -Destination $candidateRoot
    & $venvPython (Join-Path $sourceRoot "scripts\verify_release_assets.py") `
        $candidateRoot --expected-commit $ExpectedReleaseSha
    if ($LASTEXITCODE -ne 0) { throw "Promoted candidate asset verification failed." }
    Write-Host ""
    Write-Host "[CANDIDATE] Signed private candidate retained without changing dist\DefenseTracker."
    Write-Host "            Commit: $ExpectedReleaseSha"
    Write-Host "            Assets: $candidateRoot"
    Write-Host "            Stable promotion remains blocked until strict compliance verification passes."
} elseif ($RequireSignedInstaller) {
    New-Item -ItemType Directory -Path $distRoot,$archiveRoot -Force | Out-Null
    $releaseParent = Join-Path $distRoot ("releases\" + $version.release_tag)
    $publishedAssetRoot = Join-Path $releaseParent $ExpectedReleaseSha
    if (Test-Path -LiteralPath $publishedAssetRoot) {
        throw "Immutable local release asset directory already exists: $publishedAssetRoot"
    }
    New-Item -ItemType Directory -Path $releaseParent -Force | Out-Null
    Move-Item -LiteralPath $assetStaging -Destination $publishedAssetRoot
    & $venvPython (Join-Path $sourceRoot "scripts\verify_release_assets.py") `
        $publishedAssetRoot --expected-commit $ExpectedReleaseSha
    if ($LASTEXITCODE -ne 0) { throw "Promoted release asset verification failed." }
    if (Test-Path -LiteralPath $activeRoot -PathType Container) {
        Get-ChildItem -LiteralPath $activeRoot -Force -Recurse |
            Select-Object FullName, Length, LastWriteTimeUtc |
            ConvertTo-Json -Depth 3 |
            Set-Content -LiteralPath (Join-Path $evidenceRoot "previous-active-release.json") -Encoding UTF8

        $oldCommit = ""
        $oldManifest = Join-Path $activeRoot "release-manifest.json"
        if (Test-Path -LiteralPath $oldManifest -PathType Leaf) {
            try {
                $oldData = Get-Content -LiteralPath $oldManifest -Raw | ConvertFrom-Json
                if ($oldData.release.commit -match '^[0-9a-f]{40}$') { $oldCommit = $oldData.release.commit.Substring(0, 12) }
                elseif ($oldData.commit -match '^[0-9a-f]{40}$') { $oldCommit = $oldData.commit.Substring(0, 12) }
            } catch {}
        }
        if ([string]::IsNullOrWhiteSpace($oldCommit) -and [string]::IsNullOrWhiteSpace($LegacyArchiveId)) {
            throw "The active legacy build has no trustworthy manifest. Supply an audited DEFENSE_TRACKER_LEGACY_ARCHIVE_ID such as 88d507f-20260725; the build will never guess it."
        }
        if (-not [string]::IsNullOrWhiteSpace($LegacyArchiveId) -and
            -not [string]::IsNullOrWhiteSpace($oldCommit) -and
            -not $LegacyArchiveId.StartsWith($oldCommit, [System.StringComparison]::Ordinal)) {
            throw "DEFENSE_TRACKER_LEGACY_ARCHIVE_ID does not match the active manifest commit."
        }
        $archiveId = if ([string]::IsNullOrWhiteSpace($LegacyArchiveId)) {
            $oldCommit + "-" + [DateTime]::UtcNow.ToString("yyyyMMdd")
        } else {
            $LegacyArchiveId
        }
        $archiveDestination = Join-Path $archiveRoot $archiveId
        if (Test-Path -LiteralPath $archiveDestination) {
            throw "Legacy archive destination already exists: $archiveDestination"
        }
        Move-Item -LiteralPath $activeRoot -Destination $archiveDestination
        try {
            Move-Item -LiteralPath $stagingRoot -Destination $activeRoot
        } catch {
            if (-not (Test-Path -LiteralPath $activeRoot) -and
                (Test-Path -LiteralPath $archiveDestination -PathType Container)) {
                Move-Item -LiteralPath $archiveDestination -Destination $activeRoot
            }
            throw
        }
    } else {
        Move-Item -LiteralPath $stagingRoot -Destination $activeRoot
    }
    $releasedExe = Get-Item -LiteralPath (Join-Path $activeRoot "DefenseTracker.exe")
    Write-Host ""
    Write-Host "[OK] Signed DefenseTracker $($version.display_version) local release promoted."
    Write-Host "     Commit: $ExpectedReleaseSha"
    Write-Host "     EXE: $($releasedExe.FullName)"
    Write-Host "     SHA-256: $(Get-Sha256 $releasedExe.FullName)"
    Write-Host "     Stable assets: $publishedAssetRoot"
} else {
    $candidateParent = Join-Path $distRoot ("candidates\" + $version.release_tag)
    $candidateRoot = Join-Path $candidateParent $ExpectedReleaseSha
    if (Test-Path -LiteralPath $candidateRoot) {
        throw "Unsigned candidate directory already exists: $candidateRoot"
    }
    New-Item -ItemType Directory -Path $candidateParent -Force | Out-Null
    Move-Item -LiteralPath $stagingRoot -Destination $candidateRoot
    $candidateExe = Get-Item -LiteralPath (Join-Path $candidateRoot "DefenseTracker.exe")
    Write-Host "[CANDIDATE] Unsigned build retained without changing dist\DefenseTracker."
    Write-Host "            EXE: $($candidateExe.FullName)"
    Write-Host "            SHA-256: $(Get-Sha256 $candidateExe.FullName)"
}
Write-Host "[PUBLISH] No Git tag, GitHub Release or remote deployment was created."
