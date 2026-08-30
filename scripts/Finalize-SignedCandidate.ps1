<#
.SYNOPSIS
Credentiallessly verifies signed application and installer exchanges and emits
the fixed six-file DefenseTracker candidate.

.DESCRIPTION
Inputs are already-decrypted local directories. This script never signs,
decrypts, publishes, deploys, or promotes a local installation.
#>
#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedReleaseSha,
    [Parameter(Mandatory = $true)][string]$SignedApplicationBundleRoot,
    [Parameter(Mandatory = $true)][string]$ApplicationSigningReceipt,
    [Parameter(Mandatory = $true)][string]$SignedInstallerBundleRoot,
    [Parameter(Mandatory = $true)][string]$InstallerSigningReceipt,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ApplicationSigningRequestSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')]
    [string]$InstallerSigningRequestSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedApplicationSigningReceiptSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedInstallerSigningReceiptSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('^[1-9][0-9]{0,18}$')]
    [string]$ExpectedApplicationRunId,
    [Parameter(Mandatory = $true)][ValidatePattern('^[1-9][0-9]{0,9}$')]
    [string]$ExpectedApplicationRunAttempt,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [string]$PublisherPolicyPath = (Join-Path $PSScriptRoot '..\release\publisher-policy.json'),
    [string]$ExpectedPublisherPolicySha256 = $env:PUBLISHER_POLICY_SHA256,
    [string]$SignToolPath = $env:DEFENSE_TRACKER_SIGNTOOL,
    [string]$InnoSetupCompiler = $env:DEFENSE_TRACKER_ISCC,
    [string]$SevenZipPath = $env:DEFENSE_TRACKER_7ZIP,
    [string]$DefenderPath = $env:DEFENSE_TRACKER_DEFENDER,
    [string]$ExpectedSignToolSha256 = $env:DEFENSE_TRACKER_SIGNTOOL_SHA256,
    [string]$ExpectedInnoSha256 = $env:DEFENSE_TRACKER_ISCC_SHA256,
    [string]$ExpectedSevenZipSha256 = $env:DEFENSE_TRACKER_7ZIP_SHA256,
    [string]$ExpectedDefenderSha256 = $env:DEFENSE_TRACKER_DEFENDER_SHA256,
    [string]$Repository = $env:GITHUB_REPOSITORY,
    [string]$InstallerRunId = $env:GITHUB_RUN_ID,
    [string]$InstallerRunAttempt = $env:GITHUB_RUN_ATTEMPT,
    [string]$InstallerWorkflowRef = $env:GITHUB_WORKFLOW_REF
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
. (Join-Path $PSScriptRoot 'ReleaseCertificatePolicy.ps1')

function Get-Sha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Resolve-Tool([string]$Explicit,[string]$Command,[string]$Label) {
    if (-not [string]::IsNullOrWhiteSpace($Explicit)) {
        $full = [IO.Path]::GetFullPath($Explicit)
        if (Test-Path -LiteralPath $full -PathType Leaf) { return $full }
    }
    $found = Get-Command $Command -ErrorAction SilentlyContinue
    if ($null -eq $found) { throw "$Label is absent; finalization never installs tools." }
    return $found.Source
}

function Invoke-Git([string]$Root,[string[]]$Arguments) {
    $result = & git -C $Root @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "git $($Arguments -join ' ') failed: $result" }
    ($result | Out-String).Trim()
}

function Reset-GeneratedDirectory([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if (Test-Path -LiteralPath $full) {
        Get-ChildItem -LiteralPath $full -Force -Recurse |
            Select-Object FullName,Length,Attributes | Out-String | Write-Verbose
        Remove-Item -LiteralPath $full -Force -Recurse
    }
    New-Item -ItemType Directory -Path $full -Force | Out-Null
}

function Assert-RegularTree([string]$Root,[string]$Label) {
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { throw "$Label is absent." }
    foreach ($entry in Get-ChildItem -LiteralPath $Root -Force -Recurse) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label contains a reparse point."
        }
    }
}

function Get-TreeIdentity([string]$Root) {
    Assert-RegularTree $Root 'Release tree'
    $prefix = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    @(
        Get-ChildItem -LiteralPath $Root -File -Force -Recurse | Sort-Object FullName |
            ForEach-Object {
                [ordered]@{
                    path = $_.FullName.Substring($prefix.Length).Replace('\','/')
                    bytes = [int64]$_.Length
                    sha256 = Get-Sha256 $_.FullName
                }
            }
    ) | ConvertTo-Json -Compress
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
    # raster image is rejected, so account screenshots and QR images cannot
    # enter a release merely by using an innocent filename.
    $allowedRasterHashes = @{
        "_internal\docx\templates\default-docx-template\docprops\thumbnail.jpeg" =
            "96367138dc44ce09bf2c8f0f8e49348a1478d2c5c0af69bbc2bbc38b63cdcead"
    }
    $forbiddenNamePattern = '(?i)(?:^|[-_.])(qr(?:code)?|wechat|account|screenshot)(?:[-_.]|$)|二维码|账号|账户截图'
    $assetLibraryName = ([string][char]0x7D20) + ([string][char]0x6750) + ([string][char]0x5E93)
    $textSecretRules = @(
        [regex]::new('-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        [regex]::new(
            '(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        ),
        [regex]::new(
            '(?<![A-Za-z0-9])ghp_[A-Za-z0-9]{20,}(?![A-Za-z0-9])',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        ),
        [regex]::new(
            '(?<![A-Za-z0-9])AKIA[A-Z0-9]{16}(?![A-Za-z0-9])',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        ),
        [regex]::new(
            '(?<![A-Za-z0-9])sb_secret_[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])',
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
            '(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        ),
        [regex]::new(
            '(?<![A-Za-z0-9])ghp_[A-Za-z0-9]{32,}(?![A-Za-z0-9])',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        ),
        [regex]::new(
            '(?<![A-Za-z0-9])AKIA[A-Z0-9]{16}(?![A-Za-z0-9])',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        ),
        [regex]::new(
            '(?<![A-Za-z0-9])sb_secret_[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])',
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
                    $textSecretRules
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

function Assert-NoReleaseSafetyFinding([string]$Root) {
    Assert-RegularTree $Root 'Release material'
    $findings = @(Get-ArtifactSafetyFindings -Root $Root)
    if ($findings.Count -gt 0) {
        throw "Release material safety scan failed:`n - $($findings -join "`n - ")"
    }
}

function ConvertTo-ReleaseUtc {
    param([Parameter(Mandatory = $true)]$Value)
    if ($Value -is [DateTimeOffset]) {
        return $Value.UtcDateTime
    }
    if ($Value -is [DateTime]) {
        return $Value.ToUniversalTime()
    }
    $parsed = [DateTimeOffset]::Parse(
        [string]$Value,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind
    )
    return $parsed.UtcDateTime
}

function Assert-AndConsumeBuildEnvironment {
    param([string]$VenvRoot,[string]$ProjectRoot)
    $markerPath = Join-Path $VenvRoot '.build-environment.json'
    $freezePath = Join-Path $VenvRoot '.installed-packages.txt'
    $pythonPath = Join-Path $VenvRoot 'Scripts\python.exe'
    foreach ($path in @($markerPath,$freezePath,$pythonPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw 'Fresh prepared finalizer environment is incomplete.'
        }
    }
    $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
    if ($marker.schema -ne 1 -or $null -ne $marker.consumed_at_utc -or
        $marker.python_hash_verified -ne $true -or
        [string]$marker.python_source_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$marker.python_source_sha256 -cne [string]$marker.python_expected_sha256 -or
        $marker.build_lock_sha256 -cne (Get-Sha256 (Join-Path $ProjectRoot 'requirements.build.lock')) -or
        $marker.bootstrap_lock_sha256 -cne (Get-Sha256 (Join-Path $ProjectRoot 'requirements.bootstrap.lock')) -or
        $marker.installed_packages_sha256 -cne (Get-Sha256 $freezePath)) {
        throw 'Finalizer Python environment is not fresh or hash-locked.'
    }
    $prepared = ConvertTo-ReleaseUtc $marker.prepared_at_utc
    if (([DateTime]::UtcNow - $prepared).TotalHours -gt 2) {
        throw 'Finalizer Python environment is older than two hours.'
    }
    $actualFreeze = (& $pythonPath -m pip freeze --all --disable-pip-version-check | Out-String).Trim() + "`n"
    $actualBytes = [Text.Encoding]::UTF8.GetBytes($actualFreeze)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $actualFreezeHash = ([BitConverter]::ToString($sha.ComputeHash($actualBytes))).Replace('-','').ToLowerInvariant()
    } finally { $sha.Dispose() }
    if ($actualFreezeHash -cne [string]$marker.installed_packages_sha256) {
        throw 'Finalizer installed package set changed after preparation.'
    }
    $marker.consumed_at_utc = [DateTime]::UtcNow.ToString('o')
    $marker | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $markerPath -Encoding UTF8
    return [ordered]@{ python=$pythonPath; marker=$marker; packages=$freezePath }
}

function Get-ToolEvidence([string]$Path,[string]$Expected,[string]$Label,[string]$VersionOverride) {
    if ($Expected -cnotmatch '^[0-9a-f]{64}$' -or (Get-Sha256 $Path) -cne $Expected) {
        throw "$Label digest differs from its protected value."
    }
    $version = $VersionOverride
    if ([string]::IsNullOrWhiteSpace($version)) {
        $version = [string](Get-Item -LiteralPath $Path).VersionInfo.FileVersion
    }
    if ([string]::IsNullOrWhiteSpace($version)) { throw "$Label exposes no version." }
    [ordered]@{version=$version.Trim();sha256=$Expected;expected_sha256=$Expected;hash_verified=$true}
}

function Assert-ReceiptPolicy($Receipt,$Policy,[string]$PolicySha,[string]$Label) {
    $signature = $Receipt.signature
    $evidence = $signature.publisher_policy
    if ([string]$signature.provider -cne [string]$Policy.provider -or
        [string]$signature.publisher -cne [string]$Policy.publisher -or
        [string]$evidence.sha256 -cne $PolicySha -or
        [string]$evidence.sha256 -cne [string]$Policy.policy_sha256 -or
        [string]$evidence.leaf_spki_policy -cne [string]$Policy.leaf_spki_policy) {
        throw "$Label receipt differs from Publisher policy."
    }
    if ([string]$Policy.provider -ceq 'AzureArtifactSigning') {
        if ([string]$evidence.durable_identity_eku -cne [string]$Policy.azure.durable_identity_eku -or
            [string]$evidence.azure_endpoint -cne [string]$Policy.azure.endpoint -or
            [string]$evidence.azure_account_name -cne [string]$Policy.azure.account_name -or
            [string]$evidence.azure_certificate_profile_name -cne [string]$Policy.azure.certificate_profile_name -or
            [string]$evidence.azure_metadata_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $null -ne $evidence.digicert_sm_host -or $null -ne $evidence.digicert_key_alias) {
            throw "$Label Azure durable identity differs from policy."
        }
    } else {
        if ([string]$evidence.digicert_sm_host -cne [string]$Policy.digicert.sm_host -or
            [string]$evidence.digicert_key_alias -cne [string]$Policy.digicert.key_alias -or
            $null -ne $evidence.durable_identity_eku -or $null -ne $evidence.azure_endpoint -or
            $null -ne $evidence.azure_account_name -or $null -ne $evidence.azure_certificate_profile_name -or
            $null -ne $evidence.azure_metadata_sha256) {
            throw "$Label DigiCert durable identity differs from policy."
        }
    }
}

function Get-SignatureEvidence([string]$Path,[string]$SignTool,$Policy,$Receipt,[string]$Label) {
    & $SignTool verify /pa /all /v /tw $Path
    if ($LASTEXITCODE -ne 0) { throw "$Label SignTool /tw verification failed." }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or $null -eq $signature.TimeStamperCertificate) {
        throw "$Label Authenticode/timestamp verification failed."
    }
    $identity = Assert-ReleaseSignerCertificatePolicy $signature.SignerCertificate $Policy
    $null = Assert-TrustedCertificateChain $signature.TimeStamperCertificate
    if ([string]$identity.normalized_subject -cne [string]$Receipt.signature.signer_subject -or
        [string]$identity.spki_sha256 -cne [string]$Receipt.signature.signer_spki_sha256 -or
        [string]$identity.issuer_subject -cne [string]$Receipt.signature.signer_issuer_subject -or
        [string]$identity.root_sha256 -cne [string]$Receipt.signature.signer_root_sha256 -or
        [string]$signature.TimeStamperCertificate.Subject -cne
            [string]$Receipt.signature.timestamp_certificate_subject -or
        (Get-Sha256 $Path) -cne [string]$Receipt.signed_sha256 -or
        [int64](Get-Item -LiteralPath $Path).Length -ne [int64]$Receipt.signed_bytes) {
        throw "$Label signature differs from canonical receipt."
    }
    [ordered]@{
        signer_subject=[string]$identity.normalized_subject
        signer_spki_sha256=[string]$identity.spki_sha256
        signer_issuer_subject=[string]$identity.issuer_subject
        signer_root_sha256=[string]$identity.root_sha256
        publisher_policy=$Receipt.signature.publisher_policy
    }
}

function Get-SmokeTransportStatus {
    param([Parameter(Mandatory = $true)]$ErrorRecord)
    $responseValues = @(
        $ErrorRecord.Exception.PSObject.Properties |
            Where-Object { $_.Name -eq 'Response' } |
            ForEach-Object { $_.Value } |
            Where-Object { $null -ne $_ }
    )
    $statusValues = @(
        $responseValues |
            ForEach-Object {
                $_.PSObject.Properties |
                    Where-Object { $_.Name -eq 'StatusCode' } |
                    ForEach-Object { $_.Value } |
                    Where-Object { $null -ne $_ }
            }
    )
    if ($statusValues.Count -eq 1) {
        return 'http-' + [int]$statusValues[0]
    }
    return 'connection-error'
}

function Invoke-DesktopSmokeTest {
    param([string]$ExePath,[string]$RuntimeRoot,$Version,[string]$ExpectedCommit)
    $previousHome = [Environment]::GetEnvironmentVariable('DEFENSE_TRACKER_HOME','Process')
    $previousEvidence = [Environment]::GetEnvironmentVariable('DEFENSE_TRACKER_SMOKE_EVIDENCE','Process')
    $previousSmokeToken = [Environment]::GetEnvironmentVariable('DEFENSE_TRACKER_SMOKE_TOKEN','Process')
    $smokeEvidence = Join-Path $RuntimeRoot 'desktop-smoke.json'
    $tokenBytes = New-Object byte[] 32
    $tokenGenerator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $tokenGenerator.GetBytes($tokenBytes) } finally { $tokenGenerator.Dispose() }
    $smokeToken = -join ($tokenBytes | ForEach-Object { $_.ToString('x2') })
    $smokeEndpoint = '/_internal/v9/desktop-release-smoke'
    New-Item -ItemType Directory -Path $RuntimeRoot -Force | Out-Null
    if (Test-Path -LiteralPath $smokeEvidence) { throw 'Desktop smoke evidence path must be new.' }
    [Environment]::SetEnvironmentVariable('DEFENSE_TRACKER_HOME',$RuntimeRoot,'Process')
    [Environment]::SetEnvironmentVariable('DEFENSE_TRACKER_SMOKE_EVIDENCE','authenticated-loopback-v1','Process')
    [Environment]::SetEnvironmentVariable('DEFENSE_TRACKER_SMOKE_TOKEN',$smokeToken,'Process')
    $process = $null
    try {
        # SW_HIDE suppresses pywebview's authenticated shown-callback probe.
        $process = Start-Process -FilePath $ExePath -PassThru
        $deadline = [DateTime]::UtcNow.AddSeconds(60)
        $workspaceReady = $false
        $windowReady = $false
        $lastListenerCount = 0
        $ownedPort = 0
        $lastListenerQuery = 'not-run'
        $lastTransportStatus = 'not-requested'
        while ([DateTime]::UtcNow -lt $deadline) {
            if ($process.HasExited) { throw 'Desktop smoke process exited early.' }
            $process.Refresh()
            if ($process.MainWindowTitle -like '*V9*Defense Command Hub*') { $windowReady = $true }
            if (-not $workspaceReady) {
                try {
                    $ownedListeners = @(
                        Get-NetTCPConnection -State Listen -OwningProcess $process.Id -ErrorAction Stop |
                            Where-Object {
                                $_.LocalAddress -eq '127.0.0.1' -and
                                $_.LocalPort -in 49231..49235
                            }
                    )
                    $lastListenerQuery = 'ok'
                } catch {
                    $ownedListeners = @()
                    $lastListenerQuery = 'query-error'
                }
                $lastListenerCount = $ownedListeners.Count
                if ($ownedListeners.Count -gt 1) {
                    throw 'Desktop smoke process owns multiple registered loopback listeners.'
                }
                if ($ownedListeners.Count -eq 0) {
                    $lastTransportStatus = 'no-owned-listener'
                } else {
                    $ownedPort = [int]$ownedListeners[0].LocalPort
                    $response = $null
                    try {
                        $response = Invoke-RestMethod `
                            -Uri ("http://127.0.0.1:{0}{1}" -f $ownedPort, $smokeEndpoint) `
                            -Headers @{ 'X-Defense-Tracker-Smoke' = $smokeToken } `
                            -Method Get -TimeoutSec 1 -ErrorAction Stop
                        $lastTransportStatus = 'http-200'
                    } catch {
                        $lastTransportStatus = Get-SmokeTransportStatus -ErrorRecord $_
                    }
                    if ($null -ne $response) {
                        $evidence = $response.evidence
                        if ($response.process_id -eq $process.Id -and
                            $response.renderer -eq 'edgechromium' -and
                            $evidence.schema -eq 1 -and $evidence.http_status -eq 200 -and
                            $evidence.pathname -eq '/' -and $evidence.workspace_ready -eq $true -and
                            $evidence.version -eq $Version.semantic_version -and
                            $evidence.display_version -eq $Version.display_version -and
                            $evidence.release_tag -eq $Version.release_tag -and
                            $evidence.build_commit -eq $ExpectedCommit) {
                            $evidenceJson = $evidence | ConvertTo-Json -Compress
                            $evidenceBytes = [Text.UTF8Encoding]::new($false).GetBytes(
                                $evidenceJson + [Environment]::NewLine
                            )
                            $evidenceStream = [System.IO.FileStream]::new(
                                $smokeEvidence,
                                [System.IO.FileMode]::CreateNew,
                                [System.IO.FileAccess]::Write,
                                [System.IO.FileShare]::None
                            )
                            try {
                                $evidenceStream.Write($evidenceBytes,0,$evidenceBytes.Length)
                                $evidenceStream.Flush($true)
                            } finally { $evidenceStream.Dispose() }
                            $workspaceReady = $true
                        } else {
                            $lastTransportStatus = 'invalid-evidence'
                        }
                    }
                }
            }
            if ($workspaceReady -and $windowReady) { return }
            Start-Sleep -Milliseconds 400
        }
        throw (
            "Desktop smoke timeout (authenticated workspace=$workspaceReady, " +
            "V9 window=$windowReady, listener_count=$lastListenerCount, " +
            "owned_port=$ownedPort, listener_query=$lastListenerQuery, " +
            "transport=$lastTransportStatus)."
        )
    } finally {
        if ($null -ne $process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force
            $process.WaitForExit(10000) | Out-Null
        }
        [Environment]::SetEnvironmentVariable('DEFENSE_TRACKER_HOME',$previousHome,'Process')
        [Environment]::SetEnvironmentVariable('DEFENSE_TRACKER_SMOKE_EVIDENCE',$previousEvidence,'Process')
        [Environment]::SetEnvironmentVariable('DEFENSE_TRACKER_SMOKE_TOKEN',$previousSmokeToken,'Process')
    }
}

function Invoke-InstallerLifecycleSmokeTest {
    param([string]$InstallerPath,[string]$InstallRoot,[string]$RuntimeRoot,[string]$ExpectedExeSha256,$Version,[string]$ExpectedCommit)
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
    $installLog = Join-Path $InstallRoot 'install-smoke.log'
    $arguments = @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-',('/DIR="' + $InstallRoot + '"'),('/LOG="' + $installLog + '"'))
    $setup = Start-Process -FilePath $InstallerPath -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
    if ($setup.ExitCode -ne 0) { throw 'Silent installer smoke failed.' }
    $installedExe = Join-Path $InstallRoot 'DefenseTracker.exe'
    if (-not (Test-Path -LiteralPath $installedExe -PathType Leaf) -or
        (Get-Sha256 $installedExe) -cne $ExpectedExeSha256) {
        throw 'Silent installer did not install the exact signed application.'
    }
    Invoke-DesktopSmokeTest $installedExe $RuntimeRoot $Version $ExpectedCommit
    $uninstaller = Join-Path $InstallRoot 'unins000.exe'
    if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) { throw 'Installer created no uninstaller.' }
    $uninstall = Start-Process -FilePath $uninstaller -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') -PassThru -Wait -WindowStyle Hidden
    if ($uninstall.ExitCode -ne 0) { throw 'Silent uninstall failed.' }
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while ((Test-Path -LiteralPath $installedExe) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 250
    }
    if (Test-Path -LiteralPath $installedExe) {
        throw 'Silent uninstall left the installed application executable behind.'
    }
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
        throw 'Legacy migration overwrote existing runtime configuration.'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $RuntimeRoot 'data\migration-smoke.json') -PathType Leaf)) {
        throw 'Legacy migration did not copy the synthetic data file.'
    }
    $migrationManifest = Join-Path $RuntimeRoot 'logs\legacy-migration.json'
    if (-not (Test-Path -LiteralPath $migrationManifest -PathType Leaf)) { throw 'Legacy migration wrote no evidence.' }
    $text = Get-Content -LiteralPath $migrationManifest -Raw
    if ($text.Contains($legacyToken) -or $text.Contains($currentToken)) { throw 'Migration evidence exposed configuration.' }
}

function Invoke-DefenderScan {
    param([string]$Tool,[string]$Path)
    & $Tool -Scan -ScanType 3 -File $Path -DisableRemediation
    if ($LASTEXITCODE -ne 0) { throw 'Microsoft Defender scan failed.' }
}

foreach ($name in @(
    'AZURE_CLIENT_SECRET','DIGICERT_SM_API_KEY','SM_API_KEY','SM_CLIENT_CERT_PASSWORD',
    'DEFENSE_TRACKER_AZURE_SIGNING_DLIB','DEFENSE_TRACKER_AZURE_SIGNING_METADATA',
    'DEFENSE_TRACKER_DIGICERT_CERT_FILE'
)) {
    if (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
        throw "Credentialless finalization refuses signing identity material: $name"
    }
}

$project = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$applicationBundle = [IO.Path]::GetFullPath($SignedApplicationBundleRoot)
$installerBundle = [IO.Path]::GetFullPath($SignedInstallerBundleRoot)
$publicApplicationReceipt = [IO.Path]::GetFullPath($ApplicationSigningReceipt)
$publicInstallerReceipt = [IO.Path]::GetFullPath($InstallerSigningReceipt)
$output = [IO.Path]::GetFullPath($OutputRoot)
if ($output.StartsWith($project.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or
    (Test-Path -LiteralPath $output)) { throw 'Output must be a fresh directory outside the source worktree.' }
if ($ExpectedPublisherPolicySha256 -cnotmatch '^[0-9a-f]{64}$' -or
    $Repository -cnotmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or
    $InstallerRunId -cnotmatch '^[1-9][0-9]{0,18}$' -or
    $InstallerRunAttempt -cnotmatch '^[1-9][0-9]{0,9}$') { throw 'Dispatch identity is malformed.' }
$applicationWorkflow = "$Repository/.github/workflows/v9-application-signing.yml@refs/heads/main"
$installerWorkflow = "$Repository/.github/workflows/v9-signed-candidate.yml@refs/heads/main"
if ($InstallerWorkflowRef -cne $installerWorkflow) { throw 'Finalizer workflow is not protected main.' }

Assert-RegularTree $applicationBundle 'Application bundle'
Assert-RegularTree $installerBundle 'Installer bundle'
$status = Invoke-Git $project @('status','--porcelain','--untracked-files=all')
if (-not [string]::IsNullOrWhiteSpace($status) -or (Invoke-Git $project @('rev-parse','HEAD')) -cne $ExpectedReleaseSha) {
    throw 'Finalizer checkout is not the exact clean release commit.'
}
Invoke-Git $project @('fetch','--no-tags','origin','main') | Out-Null
if ((Invoke-Git $project @('rev-parse','refs/remotes/origin/main')) -cne $ExpectedReleaseSha) {
    throw 'Release is no longer exact protected main.'
}
$tree = Invoke-Git $project @('rev-parse',"$ExpectedReleaseSha`^{tree}")
$epoch = [int64](Invoke-Git $project @('show','-s','--format=%ct',$ExpectedReleaseSha))
$version = Get-Content -LiteralPath (Join-Path $project 'version.json') -Raw | ConvertFrom-Json

$appRequest = Join-Path $applicationBundle 'signing-request.json'
$appReceipt = Join-Path $applicationBundle 'signing-receipt.json'
$installerRequest = Join-Path $installerBundle 'signing-request.json'
$installerReceipt = Join-Path $installerBundle 'signing-receipt.json'
if ((Get-Sha256 $appRequest) -cne $ApplicationSigningRequestSha256 -or
    (Get-Sha256 $installerRequest) -cne $InstallerSigningRequestSha256 -or
    (Get-Sha256 $appReceipt) -cne $ExpectedApplicationSigningReceiptSha256 -or
    (Get-Sha256 $installerReceipt) -cne $ExpectedInstallerSigningReceiptSha256 -or
    -not [Linq.Enumerable]::SequenceEqual([byte[]][IO.File]::ReadAllBytes($appReceipt),[byte[]][IO.File]::ReadAllBytes($publicApplicationReceipt)) -or
    -not [Linq.Enumerable]::SequenceEqual([byte[]][IO.File]::ReadAllBytes($installerReceipt),[byte[]][IO.File]::ReadAllBytes($publicInstallerReceipt))) {
    throw 'Request/receipt bytes differ from dispatched identities.'
}

$environment = Assert-AndConsumeBuildEnvironment `
    -VenvRoot (Join-Path $project '.venv-build') -ProjectRoot $project
$python = [string]$environment.python
$evidence = Join-Path $output 'evidence'
$work = Join-Path $output 'work'
$assets = Join-Path $output 'release-assets'
New-Item -ItemType Directory -Path $evidence,$work,$assets -Force | Out-Null
$appPublisher = [string](Get-Content $appRequest -Raw | ConvertFrom-Json).release.publisher
$installerPublisher = [string](Get-Content $installerRequest -Raw | ConvertFrom-Json).release.publisher

$applicationReturn = Join-Path $evidence 'application-return.json'
$applicationPathRoot = Split-Path $applicationBundle -Parent
$boundedApplicationReturn = Join-Path $applicationPathRoot (
    'application-return-' + [guid]::NewGuid().ToString('N') + '.json'
)
try {
    Push-Location -LiteralPath $applicationPathRoot
    try {
        & $python (Join-Path $project 'scripts\signing_exchange.py') verify-return `
            --bundle-root ([IO.Path]::GetRelativePath($applicationPathRoot, $applicationBundle).Replace('\','/')) `
            --request ([IO.Path]::GetRelativePath($applicationPathRoot, $appRequest).Replace('\','/')) `
            --receipt ([IO.Path]::GetRelativePath($applicationPathRoot, $appReceipt).Replace('\','/')) `
            --expected-request-sha256 $ApplicationSigningRequestSha256 --expected-subject-kind application `
            --expected-release-commit $ExpectedReleaseSha --expected-publisher $appPublisher `
            --expected-repository $Repository --expected-workflow-ref $applicationWorkflow `
            --expected-run-id $ExpectedApplicationRunId --expected-run-attempt $ExpectedApplicationRunAttempt `
            --expected-job sign-application `
            --output ([IO.Path]::GetRelativePath($applicationPathRoot, $boundedApplicationReturn).Replace('\','/'))
        if ($LASTEXITCODE -ne 0) { throw 'Application exchange verification failed.' }
    } finally {
        Pop-Location
    }
    Copy-Item -LiteralPath $boundedApplicationReturn -Destination $applicationReturn -Force
} finally {
    Remove-Item -LiteralPath $boundedApplicationReturn -Force -ErrorAction SilentlyContinue
}

$installerReturn = Join-Path $evidence 'installer-return.json'
$installerPathRoot = Split-Path $installerBundle -Parent
$boundedInstallerReturn = Join-Path $installerPathRoot (
    'installer-return-' + [guid]::NewGuid().ToString('N') + '.json'
)
try {
    Push-Location -LiteralPath $installerPathRoot
    try {
        & $python (Join-Path $project 'scripts\signing_exchange.py') verify-return `
            --bundle-root ([IO.Path]::GetRelativePath($installerPathRoot, $installerBundle).Replace('\','/')) `
            --request ([IO.Path]::GetRelativePath($installerPathRoot, $installerRequest).Replace('\','/')) `
            --receipt ([IO.Path]::GetRelativePath($installerPathRoot, $installerReceipt).Replace('\','/')) `
            --expected-request-sha256 $InstallerSigningRequestSha256 --expected-subject-kind installer `
            --expected-release-commit $ExpectedReleaseSha --expected-publisher $installerPublisher `
            --expected-repository $Repository --expected-workflow-ref $installerWorkflow `
            --expected-run-id $InstallerRunId --expected-run-attempt $InstallerRunAttempt `
            --expected-job sign-installer `
            --output ([IO.Path]::GetRelativePath($installerPathRoot, $boundedInstallerReturn).Replace('\','/'))
        if ($LASTEXITCODE -ne 0) { throw 'Installer exchange verification failed.' }
    } finally {
        Pop-Location
    }
    Copy-Item -LiteralPath $boundedInstallerReturn -Destination $installerReturn -Force
} finally {
    Remove-Item -LiteralPath $boundedInstallerReturn -Force -ErrorAction SilentlyContinue
}

$appReceiptData = Get-Content -LiteralPath $appReceipt -Raw | ConvertFrom-Json
$installerReceiptData = Get-Content -LiteralPath $installerReceipt -Raw | ConvertFrom-Json
if ([string]$appReceiptData.signature.provider -cne [string]$installerReceiptData.signature.provider) {
    throw 'Signing providers differ.'
}
$policyPath = [IO.Path]::GetFullPath($PublisherPolicyPath)
if ((Get-Sha256 $policyPath) -cne $ExpectedPublisherPolicySha256) { throw 'Publisher policy digest changed.' }
$policy = Get-ReleasePublisherPolicy -Path $policyPath -SigningProvider ([string]$appReceiptData.signature.provider)
Assert-ReceiptPolicy $appReceiptData $policy $ExpectedPublisherPolicySha256 'Application'
Assert-ReceiptPolicy $installerReceiptData $policy $ExpectedPublisherPolicySha256 'Installer'

$signTool = Resolve-Tool $SignToolPath 'signtool.exe' 'SignTool'
$iscc = Resolve-Tool $InnoSetupCompiler 'ISCC.exe' 'Inno Setup'
$sevenZip = Resolve-Tool $SevenZipPath '7z.exe' '7-Zip'
$defender = Resolve-Tool $DefenderPath 'MpCmdRun.exe' 'Microsoft Defender'
$toolchain = [ordered]@{
    python=[ordered]@{version=[string]$environment.marker.python;sha256=[string]$environment.marker.python_source_sha256;expected_sha256=[string]$environment.marker.python_expected_sha256;hash_verified=$true}
    signtool=Get-ToolEvidence $signTool $ExpectedSignToolSha256 'SignTool' ''
    iscc=Get-ToolEvidence $iscc $ExpectedInnoSha256 'Inno Setup' ''
    seven_zip=Get-ToolEvidence $sevenZip $ExpectedSevenZipSha256 '7-Zip' ''
    defender=Get-ToolEvidence $defender $ExpectedDefenderSha256 'Defender' ''
}
$toolchainPath = Join-Path $evidence 'toolchain-evidence.json'
$toolchain | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $toolchainPath -Encoding UTF8

$applicationRoot = Join-Path $applicationBundle 'payload\DefenseTracker'
$applicationExe = Join-Path $applicationRoot 'DefenseTracker.exe'
$installerName = "DefenseTracker-Setup-v$($version.semantic_version)-windows-x64.exe"
$signedInstaller = Join-Path $installerBundle "payload\$installerName"
$appSignature = Get-SignatureEvidence $applicationExe $signTool $policy $appReceiptData 'Application'
$installerSignature = Get-SignatureEvidence $signedInstaller $signTool $policy $installerReceiptData 'Installer'
if ([string]$policy.provider -ceq 'DigiCertKeyLocker' -and (
    $appSignature.signer_subject -cne $installerSignature.signer_subject -or
    $appSignature.signer_spki_sha256 -cne $installerSignature.signer_spki_sha256 -or
    $appSignature.signer_issuer_subject -cne $installerSignature.signer_issuer_subject -or
    $appSignature.signer_root_sha256 -cne $installerSignature.signer_root_sha256)) {
    throw 'DigiCert certificates differ across stages.'
}
if ((Get-TreeIdentity $applicationBundle) -cne (Get-TreeIdentity (Join-Path $installerBundle 'application'))) {
    throw 'Nested application bundle differs from the signed application exchange.'
}
Assert-NoReleaseSafetyFinding $applicationRoot

$extract = Join-Path $work 'installer-extract'
Reset-GeneratedDirectory $extract
& $sevenZip x -y "-o$extract" $signedInstaller
if ($LASTEXITCODE -ne 0) { throw 'Installer extraction failed.' }
Assert-NoReleaseSafetyFinding $extract
$installed = @(Get-ChildItem -LiteralPath $extract -Filter DefenseTracker.exe -File -Recurse)
if ($installed.Count -ne 1 -or (Get-Sha256 $installed[0].FullName) -cne (Get-Sha256 $applicationExe)) {
    throw 'Installer payload does not contain the exact signed application.'
}
foreach ($scan in @($applicationRoot,$signedInstaller,$extract)) {
    Invoke-DefenderScan -Tool $defender -Path $scan
}
Invoke-DesktopSmokeTest $applicationExe (Join-Path $work 'application-smoke') $version $ExpectedReleaseSha
Invoke-InstallerLifecycleSmokeTest $signedInstaller (Join-Path $work 'install-smoke') `
    (Join-Path $work 'install-runtime') (Get-Sha256 $applicationExe) $version $ExpectedReleaseSha
$migrationApplication = Join-Path $work 'migration-application'
Copy-Item -LiteralPath $applicationRoot -Destination $migrationApplication -Recurse -Force
Invoke-LegacyMigrationSmokeTest $migrationApplication (Join-Path $work 'migration-runtime') `
    $version $ExpectedReleaseSha

$build = Get-Content -LiteralPath (Join-Path $applicationBundle 'evidence\build-provenance.json') -Raw | ConvertFrom-Json
$compliance = Join-Path $installerBundle 'evidence\compliance-evidence.json'
$componentInventory = Join-Path $applicationBundle 'evidence\unsigned-component-inventory.json'
$packages = Join-Path $applicationBundle 'evidence\installed-packages.txt'
$review = Join-Path $installerBundle 'evidence\installer-review-request.json'
$signedInventory = Join-Path $installerBundle 'evidence\signed-component-inventory.json'
$license = Join-Path $installerBundle 'evidence\inno-license.txt'
$iss = Join-Path $project 'deploy\mvp\DefenseTracker.iss'
$reviewData = Get-Content -LiteralPath $review -Raw | ConvertFrom-Json
$now = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$pythonVersion = (& $python --version 2>&1 | Out-String).Trim()
$packageInputRoot = Join-Path $work 'package-inputs'
Reset-GeneratedDirectory $packageInputRoot
$packageInputFiles = [ordered]@{
    'application-signing-request.json' = $appRequest
    'application-signing-receipt.json' = $appReceipt
    'installer-signing-request.json' = $installerRequest
    'installer-signing-receipt.json' = $installerReceipt
    'publisher-policy.json' = $policyPath
}
foreach ($entry in $packageInputFiles.GetEnumerator()) {
    Copy-Item -LiteralPath $entry.Value -Destination (Join-Path $packageInputRoot $entry.Key)
}
Push-Location -LiteralPath $packageInputRoot
try {
    & $python (Join-Path $project 'scripts\package_release_assets.py') `
        --application-root $applicationRoot --installer $signedInstaller --output-dir $assets `
        --third-party-notices (Join-Path $project 'THIRD_PARTY_NOTICES.md') --packages-file $packages `
        --commit $ExpectedReleaseSha --source-tree $tree --source-date-epoch $epoch `
        --build-started-utc ([string]$build.build_started_at_utc) --build-finished-utc $now --verified-at-utc $now `
        --publisher ([string]$policy.publisher) --signing-provider ([string]$policy.provider) `
        --python-version $pythonVersion --runtime-lock-sha256 (Get-Sha256 (Join-Path $project 'requirements.runtime.lock')) `
        --build-lock-sha256 (Get-Sha256 (Join-Path $project 'requirements.build.lock')) `
        --toolchain-evidence $toolchainPath --publisher-policy 'publisher-policy.json' `
        --application-signing-request 'application-signing-request.json' `
        --application-signing-receipt 'application-signing-receipt.json' `
        --installer-signing-request 'installer-signing-request.json' `
        --installer-signing-receipt 'installer-signing-receipt.json' `
        --compliance-evidence $compliance --compliance-evidence-sha256 (Get-Sha256 $compliance) `
        --component-inventory $componentInventory --installer-review-request $review `
        --installer-payload-root $extract --signed-application-inventory $signedInventory `
        --iss $iss --iscc $iscc --iscc-version ([string]$toolchain.iscc.version) `
        --seven-zip $sevenZip --seven-zip-version ([string]$toolchain.seven_zip.version) `
        --bootstrap-license-declared LicenseRef-Inno-Setup --bootstrap-license-concluded LicenseRef-Inno-Setup `
        --bootstrap-copyright-text ([string]$reviewData.bootstrap_license.copyright_text) --bootstrap-license-text $license
    if ($LASTEXITCODE -ne 0) { throw 'Release asset packaging failed.' }
} finally {
    Pop-Location
}

$portableRoot = Join-Path $work 'portable'
Reset-GeneratedDirectory $portableRoot
$portable = Join-Path $assets "DefenseTracker-v$($version.semantic_version)-windows-x64-portable.zip"
& $python (Join-Path $project 'scripts\verify_release_assets.py') $assets `
    --expected-commit $ExpectedReleaseSha --portable-inventory-only
if ($LASTEXITCODE -ne 0) { throw 'Portable ZIP inventory is unsafe or differs from its manifest.' }
Expand-Archive -LiteralPath $portable -DestinationPath $portableRoot -Force
Assert-NoReleaseSafetyFinding $portableRoot
$portableExe = Join-Path $portableRoot 'DefenseTracker\DefenseTracker.exe'
$null = Get-SignatureEvidence $portableExe $signTool $policy $appReceiptData 'Portable application'
Invoke-DesktopSmokeTest $portableExe (Join-Path $work 'portable-smoke') $version $ExpectedReleaseSha

Assert-NoReleaseSafetyFinding $assets
& $python (Join-Path $project 'scripts\finalize_release_assets.py') $assets `
    --expected-commit $ExpectedReleaseSha --completed-at-utc ([DateTime]::UtcNow.ToString('o')) `
    --portable-exe-sha256 (Get-Sha256 $portableExe)
if ($LASTEXITCODE -ne 0) { throw 'Release evidence finalization failed.' }
& $python (Join-Path $project 'scripts\verify_release_assets.py') $assets --expected-commit $ExpectedReleaseSha
if ($LASTEXITCODE -ne 0) { throw 'Strict six-asset verification failed.' }
if (-not [string]::IsNullOrWhiteSpace((Invoke-Git $project @('status','--porcelain','--untracked-files=all')))) {
    throw 'Source changed during finalization.'
}
Write-Host "release-assets=$assets"
Write-Host 'credentialless-finalization=PASS'
