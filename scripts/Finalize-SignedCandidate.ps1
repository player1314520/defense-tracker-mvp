<#
.SYNOPSIS
Finalizes one independently reviewed DefenseTracker installer candidate.

.DESCRIPTION
Consumes the exact attested stage-A preparation artifact, authenticates a
separate Ed25519 installer approval, proves the installer payload before and
after Authenticode signing, runs the release smoke/scanning gates, and emits
the fixed six-file private candidate. It never creates a tag, GitHub Release,
deployment, or active local installation.
#>

#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedReleaseSha,

    [Parameter(Mandatory = $true)]
    [string]$PreparationRoot,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[1-9][0-9]{0,19}$')]
    [string]$ExpectedPreparationRunId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[1-9][0-9]{0,9}$')]
    [string]$ExpectedPreparationRunAttempt,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedPreparationArtifactName,

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
    [string]$ExpectedDigiCertCertificateFileSha256 = $env:DEFENSE_TRACKER_DIGICERT_CERT_FILE_SHA256,
    [string]$ExpectedSignerSubjects = $env:DEFENSE_TRACKER_EXPECTED_SIGNER_SUBJECTS,
    [string]$ExpectedSignerSpkiSha256 = $env:DEFENSE_TRACKER_EXPECTED_SIGNER_SPKI_SHA256,
    [string]$ExpectedSignerIssuers = $env:DEFENSE_TRACKER_EXPECTED_SIGNER_ISSUERS,
    [string]$ExpectedSignerRootSha256 = $env:DEFENSE_TRACKER_EXPECTED_SIGNER_ROOT_SHA256,
    [string]$ExpectedSignToolSha256 = $env:DEFENSE_TRACKER_SIGNTOOL_SHA256,
    [string]$ExpectedInnoSha256 = $env:DEFENSE_TRACKER_ISCC_SHA256,
    [string]$ExpectedSevenZipSha256 = $env:DEFENSE_TRACKER_7ZIP_SHA256,
    [string]$ExpectedDefenderSha256 = $env:DEFENSE_TRACKER_DEFENDER_SHA256,
    [string]$ExpectedAzureDlibSha256 = $env:DEFENSE_TRACKER_AZURE_SIGNING_DLIB_SHA256,
    [string]$ExpectedAzureMetadataSha256 = $env:DEFENSE_TRACKER_AZURE_SIGNING_METADATA_SHA256,
    [string]$ExpectedInnoLicenseTextSha256 = $env:DEFENSE_TRACKER_INNO_LICENSE_TEXT_SHA256,
    [string]$InnoCopyrightText = $env:DEFENSE_TRACKER_INNO_COPYRIGHT_TEXT,
    [string]$ExpectedApplicationComplianceSha256 = $env:DEFENSE_TRACKER_COMPLIANCE_EVIDENCE_SHA256,
    [string]$InstallerReviewEvidencePath = $env:DEFENSE_TRACKER_INSTALLER_REVIEW_EVIDENCE,
    [string]$InstallerReviewSignaturePath = $env:DEFENSE_TRACKER_INSTALLER_REVIEW_SIGNATURE,
    [string]$ExpectedInstallerReviewEvidenceSha256 = $env:DEFENSE_TRACKER_INSTALLER_REVIEW_EVIDENCE_SHA256,
    [string]$ExpectedRepository = $env:GITHUB_REPOSITORY,
    [string]$ExpectedWorkflowRef = $env:GITHUB_WORKFLOW_REF
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
. (Join-Path $PSScriptRoot 'ReleaseCertificatePolicy.ps1')

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
        throw "$Description is not preinstalled. The finalizer never installs tools."
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
        throw "$Description requires a protected lowercase SHA-256."
    }
    $actual = Get-Sha256 $Path
    if ($actual -cne $ExpectedSha256) { throw "$Description SHA-256 differs from the trusted value." }
    $version = $VersionOverride
    if ([string]::IsNullOrWhiteSpace($version)) {
        $info = (Get-Item -LiteralPath $Path).VersionInfo
        $version = [string]$info.FileVersion
        if ([string]::IsNullOrWhiteSpace($version)) { $version = [string]$info.ProductVersion }
    }
    if ([string]::IsNullOrWhiteSpace($version)) { throw "$Description exposes no version." }
    return [ordered]@{
        version = $version.Trim()
        sha256 = $actual
        expected_sha256 = $ExpectedSha256
        hash_verified = $true
    }
}

function Reset-GeneratedDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    if (Test-Path -LiteralPath $full -PathType Container) {
        throw "Finalizer workspace already exists; use a fresh ephemeral runner: $full"
    }
    New-Item -ItemType Directory -Path $full -Force | Out-Null
}

function Resolve-BundlePath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Relative,
        [switch]$Directory
    )
    if ([string]::IsNullOrWhiteSpace($Relative) -or
        [System.IO.Path]::IsPathRooted($Relative) -or $Relative -match '(^|/|\\)\.\.($|/|\\)') {
        throw "Preparation manifest contains an unsafe relative path."
    }
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    $resolved = [System.IO.Path]::GetFullPath((Join-Path $Root $Relative))
    if (-not $resolved.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Preparation path escapes the attested artifact root."
    }
    $expectedType = if ($Directory) { 'Container' } else { 'Leaf' }
    if (-not (Test-Path -LiteralPath $resolved -PathType $expectedType)) {
        throw "Preparation artifact path is missing: $Relative"
    }
    $item = Get-Item -LiteralPath $resolved -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Preparation artifact path is a reparse point: $Relative"
    }
    return $resolved
}

function Assert-PreparationBundle {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$ExpectedSha,
        [Parameter(Mandatory = $true)][string]$ExpectedTree,
        [Parameter(Mandatory = $true)][string]$ExpectedRunId,
        [Parameter(Mandatory = $true)][string]$ExpectedRunAttempt,
        [Parameter(Mandatory = $true)][string]$ExpectedArtifact,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$WorkflowRef,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$Publisher
    )
    $rootFull = [System.IO.Path]::GetFullPath($Root)
    if (-not (Test-Path -LiteralPath $rootFull -PathType Container)) {
        throw "Preparation artifact root is missing."
    }
    if (@(Get-ChildItem -LiteralPath $rootFull -Recurse -Force |
        Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 }).Count -gt 0) {
        throw "Preparation artifact contains a reparse point."
    }
    $manifestPath = Resolve-BundlePath $rootFull "preparation-manifest.json"
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.schema -ne 1 -or
        $manifest.kind -cne "defense-tracker-installer-review-preparation" -or
        $manifest.release.commit -cne $ExpectedSha -or
        $manifest.release.source_tree -cne $ExpectedTree -or
        $manifest.release.version -cne $Version -or
        $manifest.release.release_tag -cne "v$Version" -or
        $manifest.release.publisher -cne $Publisher -or
        [string]$manifest.provenance.run_id -cne $ExpectedRunId -or
        [string]$manifest.provenance.run_attempt -cne $ExpectedRunAttempt -or
        $manifest.provenance.artifact_name -cne $ExpectedArtifact -or
        $manifest.provenance.repository -cne $Repository -or
        $manifest.provenance.workflow_ref -cne $WorkflowRef) {
        throw "Preparation manifest provenance differs from the exact run/SHA/source binding."
    }
    if ($null -eq $manifest.files -or @($manifest.files).Count -eq 0) {
        throw "Preparation manifest file inventory is empty."
    }
    $listed = @{}
    foreach ($entry in @($manifest.files)) {
        $relative = [string]$entry.path
        if ($listed.ContainsKey($relative) -or $relative -cnotmatch '^[^\\/:*?"<>|]+(?:/[^\\/:*?"<>|]+)*$' -or
            [string]$entry.sha256 -cnotmatch '^[0-9a-f]{64}$' -or [int64]$entry.bytes -lt 0) {
            throw "Preparation manifest file inventory is malformed."
        }
        $path = Resolve-BundlePath $rootFull $relative
        $item = Get-Item -LiteralPath $path
        if ($item.Length -ne [int64]$entry.bytes -or (Get-Sha256 $path) -cne [string]$entry.sha256) {
            throw "Preparation artifact file differs from its attested manifest: $relative"
        }
        $listed[$relative] = $true
    }
    $actual = @(
        Get-ChildItem -LiteralPath $rootFull -Recurse -Force -File |
            ForEach-Object { $_.FullName.Substring($rootFull.Length + 1).Replace('\', '/') } |
            Where-Object { $_ -cne 'preparation-manifest.json' }
    )
    if ($actual.Count -ne $listed.Count -or @($actual | Where-Object { -not $listed.ContainsKey($_) }).Count -gt 0) {
        throw "Preparation artifact contains an unreviewed or missing file."
    }
    return $manifest
}

function Invoke-Git {
    param([string]$Root,[string[]]$Arguments)
    $output = (& git -C $Root @Arguments 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "git $($Arguments -join ' ') failed: $output" }
    return $output
}

function Assert-AndConsumeBuildEnvironment {
    param([string]$VenvRoot,[string]$ProjectRoot)
    $markerPath = Join-Path $VenvRoot ".build-environment.json"
    $freezePath = Join-Path $VenvRoot ".installed-packages.txt"
    $pythonPath = Join-Path $VenvRoot "Scripts\python.exe"
    foreach ($path in @($markerPath,$freezePath,$pythonPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Fresh prepared finalizer environment is incomplete."
        }
    }
    $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
    if ($marker.schema -ne 1 -or $null -ne $marker.consumed_at_utc -or
        $marker.python_hash_verified -ne $true -or
        [string]$marker.python_source_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$marker.python_source_sha256 -cne [string]$marker.python_expected_sha256 -or
        $marker.build_lock_sha256 -cne (Get-Sha256 (Join-Path $ProjectRoot "requirements.build.lock")) -or
        $marker.bootstrap_lock_sha256 -cne (Get-Sha256 (Join-Path $ProjectRoot "requirements.bootstrap.lock")) -or
        $marker.installed_packages_sha256 -cne (Get-Sha256 $freezePath)) {
        throw "Finalizer Python environment is not fresh or hash-locked."
    }
    $prepared = [DateTime]::Parse($marker.prepared_at_utc).ToUniversalTime()
    if (([DateTime]::UtcNow - $prepared).TotalHours -gt 2) {
        throw "Finalizer Python environment is older than two hours."
    }
    $marker.consumed_at_utc = [DateTime]::UtcNow.ToString("o")
    $marker | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $markerPath -Encoding UTF8
    return [ordered]@{ python = $pythonPath; marker = $marker; packages = $freezePath }
}

function Invoke-SignAndVerify {
    param(
        [string]$Path,[string]$Tool,[string]$Provider,[string]$Publisher,[string]$Timestamp,
        [string]$AzureDlib,[string]$AzureMetadata,[string]$DigiCertAlias,[string]$DigiCertCertFile,
        [Parameter(Mandatory = $true)]$CertificatePolicy,
        [switch]$VerifyOnly
    )
    $arguments = @('sign','/v','/fd','SHA256','/tr',$Timestamp,'/td','SHA256')
    if ($Provider -eq 'AzureArtifactSigning') {
        $arguments += @('/dlib',$AzureDlib,'/dmdf',$AzureMetadata)
    } elseif ($Provider -eq 'DigiCertKeyLocker') {
        $arguments += @('/csp','DigiCert Signing Manager KSP','/kc',$DigiCertAlias,'/f',$DigiCertCertFile)
    } else { throw "Unsupported trusted signing provider." }
    if (-not $VerifyOnly) {
        & $Tool @arguments $Path
        if ($LASTEXITCODE -ne 0) { throw "SignTool failed to sign the reviewed candidate." }
    }
    & $Tool verify /pa /all /v /tw $Path
    if ($LASTEXITCODE -ne 0) { throw "SignTool verification failed for the candidate." }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or $null -eq $signature.TimeStamperCertificate) {
        throw "Authenticode or RFC 3161 timestamp validation failed."
    }
    $simpleName = $signature.SignerCertificate.GetNameInfo(
        [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false
    )
    if ($simpleName -cne $Publisher) { throw "Signer Publisher differs from the reviewed Publisher." }
    $identity = Assert-ReleaseSignerCertificatePolicy $signature.SignerCertificate $CertificatePolicy
    $null = Assert-TrustedCertificateChain $signature.TimeStamperCertificate
    return [ordered]@{
        provider = $Provider
        publisher = $Publisher
        signer_subject = $identity.normalized_subject
        signer_spki_sha256 = $identity.spki_sha256
        signer_issuer_subject = $identity.issuer_subject
        signer_root_sha256 = $identity.root_sha256
        timestamp_url = $Timestamp
        timestamp_certificate_subject = $signature.TimeStamperCertificate.Subject
        verified_at_utc = [DateTime]::UtcNow.ToString('o')
    }
}

function Get-ArtifactSafetyFindings {
    param([Parameter(Mandatory = $true)][string]$Root)
    $findings = New-Object System.Collections.Generic.List[string]
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    $forbiddenNames = @(
        '.access_token','.ai_config.json','.feishu_config.json','.supabase_config.json',
        '.supabase_v9_config.json','.v9_local_master.key','.search_config.json','.email_config.json'
    )
    $forbiddenExtensions = @('.key','.pfx','.p12','.kdbx','.sqlite','.sqlite3','.db')
    $textExtensions = @(
        '', '.txt', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg',
        '.conf', '.env', '.py', '.js', '.css', '.html', '.htm', '.md',
        '.xml', '.csv', '.log', '.ps1', '.bat', '.cmd', '.pem'
    )
    $rasterExtensions = @('.png','.jpg','.jpeg','.gif','.webp','.bmp','.ico')
    $allowedRasterHashes = @{
        '_internal\docx\templates\default-docx-template\docprops\thumbnail.jpeg' =
            '96367138dc44ce09bf2c8f0f8e49348a1478d2c5c0af69bbc2bbc38b63cdcead'
    }
    $forbiddenPattern = '(?i)(?:^|[-_.])(qr(?:code)?|wechat|account|screenshot)(?:[-_.]|$)|二维码|账号|账户截图'
    $textSecretRules = @(
        [regex]::new('-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        [regex]::new('(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])','IgnoreCase'),
        [regex]::new('(?<![A-Za-z0-9])ghp_[A-Za-z0-9]{20,}(?![A-Za-z0-9])','IgnoreCase'),
        [regex]::new('(?<![A-Za-z0-9])AKIA[A-Z0-9]{16}(?![A-Za-z0-9])','IgnoreCase'),
        [regex]::new('(?<![A-Za-z0-9])sb_secret_[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])','IgnoreCase')
    )
    $binarySecretRules = @(
        [regex]::new('-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        [regex]::new('(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])','IgnoreCase'),
        [regex]::new('(?<![A-Za-z0-9])ghp_[A-Za-z0-9]{32,}(?![A-Za-z0-9])','IgnoreCase'),
        [regex]::new('(?<![A-Za-z0-9])AKIA[A-Z0-9]{16}(?![A-Za-z0-9])','IgnoreCase'),
        [regex]::new('(?<![A-Za-z0-9])sb_secret_[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])','IgnoreCase')
    )
    foreach ($file in Get-ChildItem -LiteralPath $Root -File -Recurse -Force) {
        $relative = $file.FullName.Substring($rootFull.Length)
        $extension = $file.Extension.ToLowerInvariant()
        if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $forbiddenNames -contains $file.Name.ToLowerInvariant() -or
            $file.Name.ToLowerInvariant() -like '.env*' -or
            $forbiddenExtensions -contains $extension -or $file.BaseName -match $forbiddenPattern) {
            $findings.Add("forbidden-artifact:$relative")
            continue
        }
        if ($rasterExtensions -contains $extension) {
            $normalized = $relative.Replace('/','\').ToLowerInvariant()
            $allowed = $allowedRasterHashes[$normalized]
            if ([string]::IsNullOrWhiteSpace($allowed) -or (Get-Sha256 $file.FullName) -cne $allowed) {
                $findings.Add("unapproved-raster-image:$relative")
            }
            continue
        }
        $stream = $null
        try {
            $stream = [System.IO.File]::OpenRead($file.FullName)
            $buffer = New-Object byte[] 65536
            $tail = ''
            while (($read = $stream.Read($buffer,0,$buffer.Length)) -gt 0) {
                $chunk = $tail + [System.Text.Encoding]::UTF8.GetString($buffer,0,$read)
                $rules = if ($textExtensions -contains $extension) {
                    $textSecretRules
                } else {
                    $binarySecretRules
                }
                if (@($rules | Where-Object { $_.IsMatch($chunk) }).Count -gt 0) {
                    $findings.Add("secret-content:$relative")
                    break
                }
                $tailLength = [Math]::Min(512,$chunk.Length)
                $tail = $chunk.Substring($chunk.Length - $tailLength)
            }
        } catch { $findings.Add("content-scan-error:$relative") }
        finally { if ($null -ne $stream) { $stream.Dispose() } }
    }
    return @($findings)
}

function Invoke-DesktopSmokeTest {
    param([string]$ExePath,[string]$RuntimeRoot,$Version,[string]$ExpectedCommit)
    $previousHome = [Environment]::GetEnvironmentVariable('DEFENSE_TRACKER_HOME','Process')
    $previousEvidence = [Environment]::GetEnvironmentVariable('DEFENSE_TRACKER_SMOKE_EVIDENCE','Process')
    $smokeEvidence = Join-Path $RuntimeRoot 'desktop-smoke.json'
    New-Item -ItemType Directory -Path $RuntimeRoot -Force | Out-Null
    [Environment]::SetEnvironmentVariable('DEFENSE_TRACKER_HOME',$RuntimeRoot,'Process')
    [Environment]::SetEnvironmentVariable('DEFENSE_TRACKER_SMOKE_EVIDENCE',$smokeEvidence,'Process')
    $process = $null
    try {
        $process = Start-Process -FilePath $ExePath -PassThru -WindowStyle Hidden
        $deadline = [DateTime]::UtcNow.AddSeconds(60)
        $workspaceReady = $false
        $windowReady = $false
        while ([DateTime]::UtcNow -lt $deadline) {
            if ($process.HasExited) { throw "Desktop smoke process exited early." }
            $process.Refresh()
            if ($process.MainWindowTitle -like '*V9*Defense Command Hub*') { $windowReady = $true }
            if (Test-Path -LiteralPath $smokeEvidence -PathType Leaf) {
                try {
                    $evidence = Get-Content -LiteralPath $smokeEvidence -Raw | ConvertFrom-Json
                    if ($evidence.schema -eq 1 -and $evidence.http_status -eq 200 -and
                        $evidence.pathname -eq '/' -and $evidence.workspace_ready -eq $true -and
                        $evidence.version -eq $Version.semantic_version -and
                        $evidence.display_version -eq $Version.display_version -and
                        $evidence.release_tag -eq $Version.release_tag -and
                        $evidence.build_commit -eq $ExpectedCommit) { $workspaceReady = $true }
                } catch {}
            }
            if ($workspaceReady -and $windowReady) { return }
            Start-Sleep -Milliseconds 400
        }
        throw "Desktop smoke timeout."
    } finally {
        if ($null -ne $process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force
            $process.WaitForExit(10000) | Out-Null
        }
        [Environment]::SetEnvironmentVariable('DEFENSE_TRACKER_HOME',$previousHome,'Process')
        [Environment]::SetEnvironmentVariable('DEFENSE_TRACKER_SMOKE_EVIDENCE',$previousEvidence,'Process')
    }
}

function Invoke-InstallerLifecycleSmokeTest {
    param([string]$InstallerPath,[string]$InstallRoot,[string]$RuntimeRoot,[string]$ExpectedExeSha256,$Version,[string]$ExpectedCommit)
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
    $installLog = Join-Path $InstallRoot 'install-smoke.log'
    $arguments = @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-',('/DIR="' + $InstallRoot + '"'),('/LOG="' + $installLog + '"'))
    $setup = Start-Process -FilePath $InstallerPath -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
    if ($setup.ExitCode -ne 0) { throw "Silent installer smoke failed." }
    $installedExe = Join-Path $InstallRoot 'DefenseTracker.exe'
    if (-not (Test-Path -LiteralPath $installedExe -PathType Leaf) -or
        (Get-Sha256 $installedExe) -cne $ExpectedExeSha256) {
        throw "Silent installer did not install the exact signed application."
    }
    Invoke-DesktopSmokeTest $installedExe $RuntimeRoot $Version $ExpectedCommit
    $uninstaller = Join-Path $InstallRoot 'unins000.exe'
    if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) { throw "Installer created no uninstaller." }
    $uninstall = Start-Process -FilePath $uninstaller -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') -PassThru -Wait -WindowStyle Hidden
    if ($uninstall.ExitCode -ne 0) { throw "Silent uninstall failed." }
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while ((Test-Path -LiteralPath $installedExe) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 250
    }
    if (Test-Path -LiteralPath $installedExe) { throw "Silent uninstall left the application executable behind." }
}

function Invoke-LegacyMigrationSmokeTest {
    param([string]$ApplicationRoot,[string]$RuntimeRoot,$Version,[string]$ExpectedCommit)
    $legacyToken = 'legacy-synthetic-token-never-publish'
    $currentToken = 'current-synthetic-token-never-overwrite'
    New-Item -ItemType Directory -Path (Join-Path $ApplicationRoot 'data'),(Join-Path $RuntimeRoot 'config') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $ApplicationRoot '.access_token') -Value $legacyToken -Encoding UTF8 -NoNewline
    Set-Content -LiteralPath (Join-Path $ApplicationRoot 'data\migration-smoke.json') -Value '{"synthetic":true}' -Encoding UTF8 -NoNewline
    Set-Content -LiteralPath (Join-Path $RuntimeRoot 'config\.access_token') -Value $currentToken -Encoding UTF8 -NoNewline
    Invoke-DesktopSmokeTest (Join-Path $ApplicationRoot 'DefenseTracker.exe') $RuntimeRoot $Version $ExpectedCommit
    if ((Get-Content -LiteralPath (Join-Path $RuntimeRoot 'config\.access_token') -Raw) -cne $currentToken) {
        throw "Legacy migration overwrote existing runtime configuration."
    }
    if (-not (Test-Path -LiteralPath (Join-Path $RuntimeRoot 'data\migration-smoke.json') -PathType Leaf)) {
        throw "Legacy migration did not copy the synthetic data file."
    }
    $migrationManifest = Join-Path $RuntimeRoot 'logs\legacy-migration.json'
    if (-not (Test-Path -LiteralPath $migrationManifest -PathType Leaf)) { throw "Legacy migration wrote no evidence." }
    $text = Get-Content -LiteralPath $migrationManifest -Raw
    if ($text.Contains($legacyToken) -or $text.Contains($currentToken)) { throw "Migration evidence exposed configuration." }
}

function Invoke-DefenderScan {
    param([string]$Tool,[string]$Path)
    & $Tool -DisableRemediation -Scan -ScanType 3 -File $Path
    if ($LASTEXITCODE -ne 0) { throw "Microsoft Defender scan failed." }
}

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$version = Get-Content -LiteralPath (Join-Path $projectRoot 'version.json') -Raw | ConvertFrom-Json
if ($version.semantic_version -notmatch '^\d+\.\d+\.\d+$' -or
    $version.release_tag -cne "v$($version.semantic_version)" -or
    [string]::IsNullOrWhiteSpace($PublisherName)) {
    throw "Version or protected Publisher configuration is invalid."
}
if ($SigningProvider -notin @('AzureArtifactSigning','DigiCertKeyLocker') -or
    $TimestampUrl -notmatch '^https?://[^\s]+$') {
    throw "Finalization requires a trusted signing provider and explicit RFC 3161 URL."
}
$certificatePolicy = Get-ReleaseCertificatePolicy `
    -ExpectedSignerSubjects $ExpectedSignerSubjects `
    -ExpectedSignerSpkiSha256 $ExpectedSignerSpkiSha256 `
    -ExpectedSignerIssuers $ExpectedSignerIssuers `
    -ExpectedSignerRootSha256 $ExpectedSignerRootSha256
if ($ExpectedRepository -cnotmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or
    [string]::IsNullOrWhiteSpace($ExpectedWorkflowRef) -or
    $ExpectedPreparationArtifactName -cne
        "DefenseTracker-v$($version.semantic_version)-preparation-$ExpectedReleaseSha-$ExpectedPreparationRunId-$ExpectedPreparationRunAttempt") {
    throw "Expected preparation artifact provenance is invalid."
}
if ([string]$env:GITHUB_RUN_ID -cne $ExpectedPreparationRunId) {
    throw "Finalizer must run in the same exact workflow run as the preparation job."
}
if ([string]$env:GITHUB_RUN_ATTEMPT -cne $ExpectedPreparationRunAttempt) {
    throw "Finalizer must run in the same exact workflow attempt as the preparation job."
}

$status = Invoke-Git $projectRoot @('status','--porcelain','--untracked-files=all')
if (-not [string]::IsNullOrWhiteSpace($status)) { throw "Finalizer requires a clean Git worktree." }
if ((Invoke-Git $projectRoot @('rev-parse','HEAD')) -cne $ExpectedReleaseSha) {
    throw "Finalizer checkout differs from the expected release SHA."
}
Invoke-Git $projectRoot @('fetch','--no-tags','origin','main') | Out-Null
if ((Invoke-Git $projectRoot @('rev-parse','refs/remotes/origin/main')) -cne $ExpectedReleaseSha) {
    throw "Finalizer SHA is no longer the exact protected main commit."
}
$sourceTree = Invoke-Git $projectRoot @('rev-parse',"$ExpectedReleaseSha`^{tree}")
$sourceEpoch = [int64](Invoke-Git $projectRoot @('show','-s','--format=%ct',$ExpectedReleaseSha))

$preparationFull = [System.IO.Path]::GetFullPath($PreparationRoot)
$preparation = Assert-PreparationBundle $preparationFull $ExpectedReleaseSha $sourceTree `
    $ExpectedPreparationRunId $ExpectedPreparationRunAttempt $ExpectedPreparationArtifactName $ExpectedRepository `
    $ExpectedWorkflowRef $version.semantic_version $PublisherName
if ([int64]$preparation.release.source_date_epoch -ne $sourceEpoch) {
    throw "Preparation source epoch differs from the exact release commit."
}

$applicationRoot = Resolve-BundlePath $preparationFull ([string]$preparation.application.root) -Directory
$unsignedInstaller = Resolve-BundlePath $preparationFull ([string]$preparation.installer.path)
$applicationUnsignedDigest = Resolve-BundlePath $preparationFull ([string]$preparation.application.unsigned_digest)
$applicationSignedDigest = Resolve-BundlePath $preparationFull ([string]$preparation.application.signed_digest)
$unsignedComponentInventory = Resolve-BundlePath $preparationFull ([string]$preparation.application.unsigned_component_inventory)
$signedComponentInventory = Resolve-BundlePath $preparationFull ([string]$preparation.application.signed_component_inventory)
$applicationComplianceEvidence = Resolve-BundlePath $preparationFull ([string]$preparation.application.compliance_evidence)
$applicationComplianceSignature = Resolve-BundlePath $preparationFull ([string]$preparation.application.compliance_signature)
$bundlePackages = Resolve-BundlePath $preparationFull 'evidence/installed-packages.txt'
$innoLicenseText = Resolve-BundlePath $preparationFull ([string]$preparation.installer.bootstrap_license)

if ($ExpectedApplicationComplianceSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    (Get-Sha256 $applicationComplianceEvidence) -cne $ExpectedApplicationComplianceSha256) {
    throw "Application compliance approval differs from the protected SHA-256."
}
if ($ExpectedInnoLicenseTextSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    (Get-Sha256 $innoLicenseText) -cne $ExpectedInnoLicenseTextSha256 -or
    [string]$preparation.installer.bootstrap_license_sha256 -cne $ExpectedInnoLicenseTextSha256 -or
    [string]$preparation.installer.bootstrap_copyright_text -cne $InnoCopyrightText) {
    throw "Installer bootstrap license inputs differ from the protected review configuration."
}

$installerReviewEvidence = [System.IO.Path]::GetFullPath($InstallerReviewEvidencePath)
$installerReviewSignature = [System.IO.Path]::GetFullPath($InstallerReviewSignaturePath)
if ($ExpectedInstallerReviewEvidenceSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    -not (Test-Path -LiteralPath $installerReviewEvidence -PathType Leaf) -or
    -not (Test-Path -LiteralPath $installerReviewSignature -PathType Leaf) -or
    (Get-Sha256 $installerReviewEvidence) -cne $ExpectedInstallerReviewEvidenceSha256) {
    throw "Independent installer approval/signature is absent or not hash-pinned."
}

$applicationReviewerKeyId = [string]$preparation.application.reviewer_key_id
$applicationCompliance = Get-Content -LiteralPath $applicationComplianceEvidence -Raw | ConvertFrom-Json
if ($applicationReviewerKeyId -cne [string]$applicationCompliance.reviewer_key_id) {
    throw "Application reviewer identity differs from the prepared compliance approval."
}

$environment = Assert-AndConsumeBuildEnvironment (Join-Path $projectRoot '.venv-build') $projectRoot
$python = [string]$environment.python
if ((Get-Sha256 $bundlePackages) -cne (Get-Sha256 ([string]$environment.packages))) {
    throw "Finalizer installed package inventory differs from the reviewed stage-A inventory."
}

$signTool = Resolve-RequiredTool $SignToolPath 'signtool.exe' 'Windows SDK SignTool'
$iscc = Resolve-RequiredTool $InnoSetupCompiler 'ISCC.exe' 'Inno Setup compiler'
$sevenZip = Resolve-RequiredTool $SevenZipPath '7z.exe' '7-Zip installer inspector'
$defender = Resolve-RequiredTool $DefenderPath 'MpCmdRun.exe' 'Microsoft Defender scanner'
if ($SigningProvider -eq 'AzureArtifactSigning') {
    $AzureSigningDlib = Resolve-RequiredTool $AzureSigningDlib 'Azure.CodeSigning.Dlib.dll' 'Azure Artifact Signing DLib'
    $AzureSigningMetadata = Resolve-RequiredTool $AzureSigningMetadata 'artifact-signing-metadata.json' 'Azure signing metadata'
} else {
    if ([string]::IsNullOrWhiteSpace($DigiCertKeyAlias)) { throw "DigiCert KeyLocker alias is missing." }
    $DigiCertCertificateFile = Resolve-RequiredTool $DigiCertCertificateFile 'signing-certificate.crt' 'DigiCert certificate'
    $digicertCertificateIdentity = Assert-DigiCertCertificateFilePolicy `
        -Path $DigiCertCertificateFile `
        -ExpectedSha256 $ExpectedDigiCertCertificateFileSha256 `
        -Policy $certificatePolicy
}
$toolchain = [ordered]@{
    python = [ordered]@{
        version = [string]$environment.marker.python
        sha256 = [string]$environment.marker.python_source_sha256
        expected_sha256 = [string]$environment.marker.python_expected_sha256
        hash_verified = $environment.marker.python_hash_verified -eq $true
    }
    signtool = Get-VerifiedToolEvidence $signTool $ExpectedSignToolSha256 'Windows SDK SignTool'
    iscc = Get-VerifiedToolEvidence $iscc $ExpectedInnoSha256 'Inno Setup compiler'
    seven_zip = Get-VerifiedToolEvidence $sevenZip $ExpectedSevenZipSha256 '7-Zip'
    defender = Get-VerifiedToolEvidence $defender $ExpectedDefenderSha256 'Microsoft Defender scanner'
}
if ($SigningProvider -eq 'AzureArtifactSigning') {
    $toolchain['azure_dlib'] = Get-VerifiedToolEvidence $AzureSigningDlib $ExpectedAzureDlibSha256 'Azure signing DLib'
    $toolchain['azure_metadata'] = Get-VerifiedToolEvidence $AzureSigningMetadata $ExpectedAzureMetadataSha256 `
        'Azure signing metadata' 'not-applicable:json-metadata'
} else {
    $toolchain['digicert_certificate'] = [ordered]@{
        version = "X.509 $($digicertCertificateIdentity.normalized_subject)"
        sha256 = $ExpectedDigiCertCertificateFileSha256
        expected_sha256 = $ExpectedDigiCertCertificateFileSha256
        hash_verified = $true
    }
}

$workRoot = Join-Path $projectRoot 'build\candidate-finalization'
$preExtract = Join-Path $workRoot 'installer-pre-sign-extract'
$postExtract = Join-Path $workRoot 'installer-post-sign-extract'
$installerSmokeRoot = Join-Path $workRoot 'installer-smoke-install'
$installerSmokeRuntime = Join-Path $workRoot 'installer-smoke-runtime'
$portableExtract = Join-Path $workRoot 'portable-extract'
$portableSmokeRuntime = Join-Path $workRoot 'portable-smoke-runtime'
$migrationSmokeApp = Join-Path $workRoot 'migration-smoke-app'
$migrationSmokeRuntime = Join-Path $workRoot 'migration-smoke-runtime'
$assetStaging = Join-Path $workRoot 'release-assets'
$evidenceRoot = Join-Path $workRoot 'evidence'
Reset-GeneratedDirectory $workRoot
New-Item -ItemType Directory -Path $evidenceRoot -Force | Out-Null

$toolchainEvidencePath = Join-Path $evidenceRoot 'toolchain-evidence.json'
$toolchain | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $toolchainEvidencePath -Encoding UTF8
$applicationDigest = Get-Content -LiteralPath $applicationUnsignedDigest -Raw | ConvertFrom-Json
$applicationExe = Join-Path $applicationRoot 'DefenseTracker.exe'
& $python (Join-Path $projectRoot 'scripts\authenticode_digest.py') `
    --path $applicationExe --require-state signed `
    --expected-unsigned-size ([string]$applicationDigest.bytes) `
    --expected-normalized-sha256 ([string]$applicationDigest.normalized_sha256) `
    --output (Join-Path $evidenceRoot 'application-authenticode-reverified.json')
if ($LASTEXITCODE -ne 0) { throw "Prepared signed application fails normalized Authenticode verification." }
$applicationSignature = Invoke-SignAndVerify $applicationExe $signTool $SigningProvider $PublisherName $TimestampUrl `
    $AzureSigningDlib $AzureSigningMetadata $DigiCertKeyAlias $DigiCertCertificateFile `
    $certificatePolicy -VerifyOnly

$runtimeLockHash = Get-Sha256 (Join-Path $projectRoot 'requirements.runtime.lock')
$buildLockHash = Get-Sha256 (Join-Path $projectRoot 'requirements.build.lock')
$applicationComplianceRegistry = Join-Path $projectRoot 'release\compliance-reviewers.json'
$complianceVerifiedAtUtc = [DateTime]::UtcNow.ToString('o')
& $python (Join-Path $projectRoot 'scripts\verify_compliance_evidence.py') `
    --evidence $applicationComplianceEvidence `
    --evidence-signature $applicationComplianceSignature `
    --reviewer-registry $applicationComplianceRegistry `
    --component-inventory $unsignedComponentInventory `
    --application-root $applicationRoot `
    --expected-sha256 $ExpectedApplicationComplianceSha256 `
    --commit $ExpectedReleaseSha `
    --source-tree $sourceTree `
    --publisher $PublisherName `
    --packages-file $bundlePackages `
    --third-party-notices (Join-Path $projectRoot 'THIRD_PARTY_NOTICES.md') `
    --runtime-lock-sha256 $runtimeLockHash `
    --build-lock-sha256 $buildLockHash `
    --verified-at-utc $complianceVerifiedAtUtc
if ($LASTEXITCODE -ne 0) { throw "Prepared application compliance revalidation failed." }

$signedInstaller = Join-Path $workRoot ([System.IO.Path]::GetFileName($unsignedInstaller))
Copy-Item -LiteralPath $unsignedInstaller -Destination $signedInstaller
if ((Get-Sha256 $signedInstaller) -cne (Get-Sha256 $unsignedInstaller)) {
    throw "Installer working copy differs before signing."
}
Reset-GeneratedDirectory $preExtract
& $sevenZip x -y "-o$preExtract" $unsignedInstaller
if ($LASTEXITCODE -ne 0) { throw "Pre-sign full installer extraction failed." }
$preFindings = @(Get-ArtifactSafetyFindings $preExtract)
if ($preFindings.Count -gt 0) { throw "Pre-sign installer payload safety scan failed." }

$installerReviewerRegistry = Join-Path $projectRoot 'release\installer-reviewers.json'
$installerDefinition = Join-Path $projectRoot 'deploy\mvp\DefenseTracker.iss'
$reviewArguments = @(
    '--evidence',$installerReviewEvidence,
    '--signature',$installerReviewSignature,
    '--reviewer-registry',$installerReviewerRegistry,
    '--expected-evidence-sha256',$ExpectedInstallerReviewEvidenceSha256,
    '--application-reviewer-key-id',$applicationReviewerKeyId,
    '--unsigned-installer',$unsignedInstaller,
    '--signed-application-inventory',$signedComponentInventory,
    '--iss',$installerDefinition,
    '--iscc',$iscc,
    '--iscc-version',[string]$toolchain.iscc.version,
    '--seven-zip',$sevenZip,
    '--seven-zip-version',[string]$toolchain.seven_zip.version,
    '--bootstrap-license-declared','LicenseRef-Inno-Setup',
    '--bootstrap-license-concluded','LicenseRef-Inno-Setup',
    '--bootstrap-copyright-text',$InnoCopyrightText,
    '--bootstrap-license-text',$innoLicenseText,
    '--commit',$ExpectedReleaseSha,
    '--source-tree',$sourceTree,
    '--version',$version.semantic_version,
    '--publisher',$PublisherName
)
& $python (Join-Path $projectRoot 'scripts\installer_review.py') pre-sign @reviewArguments `
    --payload-root $preExtract --output (Join-Path $evidenceRoot 'installer-pre-sign-binding.json')
if ($LASTEXITCODE -ne 0) { throw "Independent installer review failed before signing." }
$installerApproval = Get-Content -LiteralPath $installerReviewEvidence -Raw | ConvertFrom-Json
$applicationRegistry = Get-Content -LiteralPath $applicationComplianceRegistry -Raw | ConvertFrom-Json
$installerRegistry = Get-Content -LiteralPath $installerReviewerRegistry -Raw | ConvertFrom-Json
$applicationKey = @($applicationRegistry.reviewers | Where-Object { $_.key_id -ceq $applicationReviewerKeyId })
$installerKey = @($installerRegistry.reviewers | Where-Object { $_.key_id -ceq [string]$installerApproval.reviewer_key_id })
if ($applicationKey.Count -ne 1 -or $installerKey.Count -ne 1 -or
    [string]$applicationKey[0].public_key_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
    [string]$installerKey[0].public_key_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
    [string]$applicationKey[0].public_key_sha256 -ceq [string]$installerKey[0].public_key_sha256) {
    throw "Application and installer reviews must use distinct registered Ed25519 keys."
}

$installerSignature = Invoke-SignAndVerify $signedInstaller $signTool $SigningProvider `
    $PublisherName $TimestampUrl $AzureSigningDlib $AzureSigningMetadata `
    $DigiCertKeyAlias $DigiCertCertificateFile $certificatePolicy
if ($installerSignature.signer_subject -cne $applicationSignature.signer_subject -or
    $installerSignature.signer_spki_sha256 -cne $applicationSignature.signer_spki_sha256 -or
    $installerSignature.signer_issuer_subject -cne $applicationSignature.signer_issuer_subject -or
    $installerSignature.signer_root_sha256 -cne $applicationSignature.signer_root_sha256) {
    throw 'Application and installer were not signed by the same pinned certificate identity.'
}
$unsignedInstallerDigest = Get-Content -LiteralPath (
    Resolve-BundlePath $preparationFull ([string]$preparation.installer.unsigned_digest)
) -Raw | ConvertFrom-Json
& $python (Join-Path $projectRoot 'scripts\authenticode_digest.py') `
    --path $signedInstaller --require-state signed `
    --expected-unsigned-size ([string]$unsignedInstallerDigest.bytes) `
    --expected-normalized-sha256 ([string]$unsignedInstallerDigest.normalized_sha256) `
    --output (Join-Path $evidenceRoot 'installer-authenticode-signed.json')
if ($LASTEXITCODE -ne 0) { throw "Signed installer changed outside Authenticode-normalized fields." }

Reset-GeneratedDirectory $postExtract
& $sevenZip x -y "-o$postExtract" $signedInstaller
if ($LASTEXITCODE -ne 0) { throw "Post-sign full installer extraction failed." }
$postFindings = @(Get-ArtifactSafetyFindings $postExtract)
if ($postFindings.Count -gt 0) { throw "Post-sign installer payload safety scan failed." }
& $python (Join-Path $projectRoot 'scripts\installer_review.py') post-sign @reviewArguments `
    --payload-root $postExtract --signed-installer $signedInstaller `
    --output (Join-Path $evidenceRoot 'installer-post-sign-binding.json')
if ($LASTEXITCODE -ne 0) { throw "Signed installer payload differs from the independent review." }

Invoke-DefenderScan $defender $applicationRoot
Invoke-DefenderScan $defender $signedInstaller
Invoke-DefenderScan $defender $postExtract
Invoke-InstallerLifecycleSmokeTest $signedInstaller $installerSmokeRoot $installerSmokeRuntime `
    (Get-Sha256 $applicationExe) $version $ExpectedReleaseSha

$releaseInputsVerifiedUtc = [DateTime]::UtcNow
$pythonVersion = (& $python --version 2>&1 | Out-String).Trim()
& $python (Join-Path $projectRoot 'scripts\package_release_assets.py') `
    --application-root $applicationRoot `
    --installer $signedInstaller `
    --output-dir $assetStaging `
    --third-party-notices (Join-Path $projectRoot 'THIRD_PARTY_NOTICES.md') `
    --packages-file $bundlePackages `
    --commit $ExpectedReleaseSha `
    --source-tree $sourceTree `
    --source-date-epoch $sourceEpoch `
    --build-started-utc ([string]$preparation.build.started_at_utc) `
    --build-finished-utc $releaseInputsVerifiedUtc.ToString('o') `
    --verified-at-utc $releaseInputsVerifiedUtc.ToString('o') `
    --publisher $PublisherName `
    --signing-provider $SigningProvider `
    --signer-subject $installerSignature.signer_subject `
    --timestamp-url $TimestampUrl `
    --timestamp-subject $installerSignature.timestamp_certificate_subject `
    --python-version $pythonVersion `
    --runtime-lock-sha256 $runtimeLockHash `
    --build-lock-sha256 $buildLockHash `
    --toolchain-evidence $toolchainEvidencePath `
    --compliance-evidence $applicationComplianceEvidence `
    --compliance-evidence-sha256 $ExpectedApplicationComplianceSha256 `
    --compliance-signature $applicationComplianceSignature `
    --compliance-reviewer-registry $applicationComplianceRegistry `
    --component-inventory $unsignedComponentInventory `
    --application-signer-subject $applicationSignature.signer_subject `
    --application-timestamp-subject $applicationSignature.timestamp_certificate_subject `
    --installer-review-evidence $installerReviewEvidence `
    --installer-review-signature $installerReviewSignature `
    --installer-reviewer-registry $installerReviewerRegistry `
    --installer-review-evidence-sha256 $ExpectedInstallerReviewEvidenceSha256 `
    --unsigned-installer $unsignedInstaller `
    --installer-payload-root $postExtract `
    --signed-application-inventory $signedComponentInventory `
    --iss $installerDefinition `
    --iscc $iscc `
    --iscc-version ([string]$toolchain.iscc.version) `
    --seven-zip $sevenZip `
    --seven-zip-version ([string]$toolchain.seven_zip.version) `
    --bootstrap-license-declared LicenseRef-Inno-Setup `
    --bootstrap-license-concluded LicenseRef-Inno-Setup `
    --bootstrap-copyright-text $InnoCopyrightText `
    --bootstrap-license-text $innoLicenseText
if ($LASTEXITCODE -ne 0) { throw "Release asset packaging failed." }

Reset-GeneratedDirectory $portableExtract
$portableZip = Join-Path $assetStaging "DefenseTracker-v$($version.semantic_version)-windows-x64-portable.zip"
Expand-Archive -LiteralPath $portableZip -DestinationPath $portableExtract -Force
$portableFindings = @(Get-ArtifactSafetyFindings $portableExtract)
if ($portableFindings.Count -gt 0) { throw "Portable ZIP content safety scan failed." }
$portableExe = Join-Path $portableExtract 'DefenseTracker\DefenseTracker.exe'
$null = Invoke-SignAndVerify $portableExe $signTool $SigningProvider $PublisherName $TimestampUrl `
    $AzureSigningDlib $AzureSigningMetadata $DigiCertKeyAlias $DigiCertCertificateFile `
    $certificatePolicy -VerifyOnly
& $python (Join-Path $projectRoot 'scripts\authenticode_digest.py') `
    --path $portableExe --require-state signed `
    --expected-unsigned-size ([string]$applicationDigest.bytes) `
    --expected-normalized-sha256 ([string]$applicationDigest.normalized_sha256)
if ($LASTEXITCODE -ne 0) { throw "Portable application normalized digest differs." }
Invoke-DefenderScan $defender $portableExtract
Invoke-DesktopSmokeTest $portableExe $portableSmokeRuntime $version $ExpectedReleaseSha
Reset-GeneratedDirectory $migrationSmokeApp
Reset-GeneratedDirectory $migrationSmokeRuntime
Get-ChildItem -LiteralPath (Join-Path $portableExtract 'DefenseTracker') -Force |
    Copy-Item -Destination $migrationSmokeApp -Recurse -Force
Invoke-LegacyMigrationSmokeTest $migrationSmokeApp $migrationSmokeRuntime $version $ExpectedReleaseSha

$assetFindings = @(Get-ArtifactSafetyFindings $assetStaging)
if ($assetFindings.Count -gt 0) { throw "Final candidate asset safety scan failed." }
$releaseCompletedUtc = [DateTime]::UtcNow.ToString('o')
& $python (Join-Path $projectRoot 'scripts\finalize_release_assets.py') `
    $assetStaging --expected-commit $ExpectedReleaseSha `
    --completed-at-utc $releaseCompletedUtc `
    --portable-exe-sha256 (Get-Sha256 $portableExe)
if ($LASTEXITCODE -ne 0) { throw "Candidate verification evidence finalization failed." }
& $python (Join-Path $projectRoot 'scripts\verify_release_assets.py') `
    $assetStaging --expected-commit $ExpectedReleaseSha `
    --reviewer-registry $applicationComplianceRegistry `
    --installer-reviewer-registry $installerReviewerRegistry
if ($LASTEXITCODE -ne 0) { throw "Strict six-asset candidate verification failed." }

$status = Invoke-Git $projectRoot @('status','--porcelain','--untracked-files=all')
if (-not [string]::IsNullOrWhiteSpace($status) -or
    (Invoke-Git $projectRoot @('rev-parse','HEAD')) -cne $ExpectedReleaseSha) {
    throw "Source changed during candidate finalization."
}
Invoke-Git $projectRoot @('fetch','--no-tags','origin','main') | Out-Null
if ((Invoke-Git $projectRoot @('rev-parse','refs/remotes/origin/main')) -cne $ExpectedReleaseSha) {
    throw "origin/main changed during finalization."
}

$candidateParent = Join-Path $projectRoot ("dist\candidates\" + $version.release_tag)
$candidateRoot = Join-Path $candidateParent $ExpectedReleaseSha
if (Test-Path -LiteralPath $candidateRoot) {
    throw "Immutable signed candidate already exists: $candidateRoot"
}
New-Item -ItemType Directory -Path $candidateParent -Force | Out-Null
Move-Item -LiteralPath $assetStaging -Destination $candidateRoot
& $python (Join-Path $projectRoot 'scripts\verify_release_assets.py') `
    $candidateRoot --expected-commit $ExpectedReleaseSha `
    --reviewer-registry $applicationComplianceRegistry `
    --installer-reviewer-registry $installerReviewerRegistry
if ($LASTEXITCODE -ne 0) { throw "Promoted private candidate verification failed." }

Write-Host ''
Write-Host '[CANDIDATE] Independently reviewed signed candidate is ready.'
Write-Host "            Commit: $ExpectedReleaseSha"
Write-Host "            Preparation run: $ExpectedPreparationRunId"
Write-Host "            Assets: $candidateRoot"
Write-Host '            No tag, public Release, deployment or active install was changed.'
