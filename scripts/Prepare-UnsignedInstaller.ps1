<#
.SYNOPSIS
Verifies a signed application and builds the exact unsigned installer request.

.DESCRIPTION
This stage is credentialless. It consumes an already-decrypted signed
application bundle plus canonical public evidence, verifies the trusted
signature against the committed Publisher policy, builds but never signs the
installer, and emits a new plaintext local exchange bundle. Encryption and
transport are separate workflow responsibilities.
#>

#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedReleaseSha,

    [Parameter(Mandatory = $true)][string]$SignedApplicationBundleRoot,
    [Parameter(Mandatory = $true)][string]$ApplicationSigningReceipt,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ApplicationSigningRequestSha256,
    [string]$ExpectedApplicationSigningReceiptSha256 = $env:APPLICATION_RECEIPT_SHA256,

    [Parameter(Mandatory = $true)][string]$OutputRoot,

    [string]$ComplianceEvidence = $env:COMPLIANCE_EVIDENCE_PATH,
    [string]$ExpectedComplianceEvidenceSha256 = $env:COMPLIANCE_SHA256,
    [string]$PublisherPolicyPath = (Join-Path $PSScriptRoot '..\release\publisher-policy.json'),
    [string]$InnoSetupCompiler = $env:DEFENSE_TRACKER_ISCC,
    [string]$SevenZipPath = $env:DEFENSE_TRACKER_7ZIP,
    [string]$SignToolPath = $env:DEFENSE_TRACKER_SIGNTOOL,
    [string]$InnoLicenseTextPath = $env:DEFENSE_TRACKER_INNO_LICENSE_TEXT,
    [string]$Repository = $env:GITHUB_REPOSITORY,
    [string]$WorkflowRef = $env:GITHUB_WORKFLOW_REF,
    [string]$RunId = $env:GITHUB_RUN_ID,
    [string]$RunAttempt = $env:GITHUB_RUN_ATTEMPT
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
. (Join-Path $PSScriptRoot 'ReleaseCertificatePolicy.ps1')

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Resolve-File {
    param([string]$Path,[string]$Command,[string]$Description)
    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $full = [System.IO.Path]::GetFullPath($Path)
        if (Test-Path -LiteralPath $full -PathType Leaf) { return $full }
    }
    $resolved = Get-Command $Command -ErrorAction SilentlyContinue
    if ($null -eq $resolved) { throw "$Description is not available." }
    return $resolved.Source
}

function Assert-NoReleaseSafetyFinding {
    param([Parameter(Mandatory = $true)][string]$Root)
    $forbiddenNames = @(
        '.access_token','.ai_config.json','.feishu_config.json','.env',
        '.supabase_config.json','.supabase_v9_config.json','.v9_local_master.key'
    )
    $forbiddenExtensions = @('.key','.pfx','.p12','.kdbx','.sqlite','.sqlite3','.db')
    $sensitiveName = '(?i)(?:^|[-_.])(qr(?:code)?|wechat|account|screenshot)(?:[-_.]|$)|二维码|账号|账户截图'
    $secretPatterns = @(
        '-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
        '(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])',
        '(?<![A-Za-z0-9])ghp_[A-Za-z0-9]{32,}(?![A-Za-z0-9])',
        '(?<![A-Za-z0-9])AKIA[A-Z0-9]{16}(?![A-Za-z0-9])'
    )
    foreach ($item in Get-ChildItem -LiteralPath $Root -Force -Recurse) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Release material contains a reparse point.'
        }
        if ($item.PSIsContainer) { continue }
        if ($forbiddenNames -contains $item.Name.ToLowerInvariant() -or
            $forbiddenExtensions -contains $item.Extension.ToLowerInvariant() -or
            $item.BaseName -match $sensitiveName) {
            throw 'Release material contains a forbidden private or account artifact.'
        }
        if ($item.Length -le 8MB -and $item.Extension.ToLowerInvariant() -in @(
            '.txt','.json','.yaml','.yml','.toml','.ini','.cfg','.conf','.env',
            '.py','.js','.css','.html','.md','.xml','.csv','.log','.ps1','.bat','.cmd','.pem'
        )) {
            $text = [System.IO.File]::ReadAllText($item.FullName)
            foreach ($pattern in $secretPatterns) {
                if ($text -match $pattern) { throw 'Release material contains secret-like content.' }
            }
        }
    }
}

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$bundle = [System.IO.Path]::GetFullPath($SignedApplicationBundleRoot)
$publicReceipt = [System.IO.Path]::GetFullPath($ApplicationSigningReceipt)
$outputFull = [System.IO.Path]::GetFullPath($OutputRoot)
if ($outputFull.StartsWith($projectRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Installer exchange output must be outside the clean source worktree.'
}
if (Test-Path -LiteralPath $outputFull) { throw 'Installer output root already exists.' }
if (-not (Test-Path -LiteralPath $bundle -PathType Container) -or
    -not (Test-Path -LiteralPath $publicReceipt -PathType Leaf)) {
    throw 'Signed application bundle or public receipt is absent.'
}
if ($Repository -cnotmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or
    $RunId -cnotmatch '^[1-9][0-9]{0,19}$' -or $RunAttempt -cnotmatch '^[1-9][0-9]{0,9}$' -or
    [string]::IsNullOrWhiteSpace($WorkflowRef)) {
    throw 'Installer preparation GitHub provenance is malformed.'
}
$internalRequest = Join-Path $bundle 'signing-request.json'
$internalReceipt = Join-Path $bundle 'signing-receipt.json'
if (-not (Test-Path -LiteralPath $internalRequest -PathType Leaf) -or
    -not (Test-Path -LiteralPath $internalReceipt -PathType Leaf) -or
    (Get-Sha256 $internalRequest) -cne $ApplicationSigningRequestSha256 -or
    -not [System.Linq.Enumerable]::SequenceEqual(
        [byte[]][IO.File]::ReadAllBytes($internalReceipt),
        [byte[]][IO.File]::ReadAllBytes($publicReceipt)
    )) {
    throw 'Application request/receipt bytes differ from the dispatched artifacts.'
}
if ($ExpectedApplicationSigningReceiptSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    (Get-Sha256 $publicReceipt) -cne $ExpectedApplicationSigningReceiptSha256) {
    throw 'Application signing receipt differs from its dispatched SHA-256.'
}
$request = Get-Content -LiteralPath $internalRequest -Raw | ConvertFrom-Json
$receipt = Get-Content -LiteralPath $internalReceipt -Raw | ConvertFrom-Json
$publisher = [string]$request.release.publisher
$provider = [string]$receipt.signature.provider
$policyPath = [System.IO.Path]::GetFullPath($PublisherPolicyPath)
$policy = Get-ReleasePublisherPolicy -Path $policyPath -SigningProvider $provider
if ([string]$policy.publisher -cne $publisher -or
    [string]$receipt.signature.publisher_policy.sha256 -cne [string]$policy.policy_sha256) {
    throw 'Application receipt differs from the committed Publisher policy.'
}
$receiptPolicy = $receipt.signature.publisher_policy
if ([string]$provider -ceq 'AzureArtifactSigning') {
    if ([string]$receiptPolicy.leaf_spki_policy -cne 'record-only' -or
        [string]$receiptPolicy.durable_identity_eku -cne [string]$policy.azure.durable_identity_eku -or
        [string]$receiptPolicy.azure_endpoint -cne [string]$policy.azure.endpoint -or
        [string]$receiptPolicy.azure_account_name -cne [string]$policy.azure.account_name -or
        [string]$receiptPolicy.azure_certificate_profile_name -cne
            [string]$policy.azure.certificate_profile_name -or
        [string]$receiptPolicy.azure_metadata_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $null -ne $receiptPolicy.digicert_sm_host -or $null -ne $receiptPolicy.digicert_key_alias) {
        throw 'Application receipt Azure durable identity differs from committed policy.'
    }
} elseif ([string]$receiptPolicy.leaf_spki_policy -cne 'required-pin' -or
    [string]$receiptPolicy.digicert_sm_host -cne [string]$policy.digicert.sm_host -or
    [string]$receiptPolicy.digicert_key_alias -cne [string]$policy.digicert.key_alias -or
    $null -ne $receiptPolicy.durable_identity_eku -or $null -ne $receiptPolicy.azure_endpoint -or
    $null -ne $receiptPolicy.azure_account_name -or
    $null -ne $receiptPolicy.azure_certificate_profile_name -or
    $null -ne $receiptPolicy.azure_metadata_sha256) {
    throw 'Application receipt DigiCert durable identity differs from committed policy.'
}

$python = Join-Path $projectRoot '.venv-build\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw 'Prepared credentialless Python environment is absent.'
}
$applicationPathRoot = Split-Path $bundle -Parent
$applicationVerification = Join-Path $applicationPathRoot (
    'defensetracker-app-return-' + [guid]::NewGuid().ToString('N') + '.json'
)
try {
    $bundleRelative = [IO.Path]::GetRelativePath($applicationPathRoot, $bundle).Replace('\','/')
    $requestRelative = [IO.Path]::GetRelativePath($applicationPathRoot, $internalRequest).Replace('\','/')
    $receiptRelative = [IO.Path]::GetRelativePath($applicationPathRoot, $internalReceipt).Replace('\','/')
    $verificationRelative = [IO.Path]::GetRelativePath($applicationPathRoot, $applicationVerification).Replace('\','/')
    Push-Location -LiteralPath $applicationPathRoot
    try {
        & $python (Join-Path $projectRoot 'scripts\signing_exchange.py') verify-return `
            --bundle-root $bundleRelative --request $requestRelative --receipt $receiptRelative `
            --expected-request-sha256 $ApplicationSigningRequestSha256 `
            --expected-subject-kind application --expected-release-commit $ExpectedReleaseSha `
            --expected-publisher $publisher --expected-repository $Repository `
            --expected-workflow-ref $WorkflowRef --expected-run-id $RunId `
            --expected-run-attempt $RunAttempt --expected-job sign-application `
            --output $verificationRelative
        if ($LASTEXITCODE -ne 0) { throw 'Signed application exchange verification failed.' }
    } finally {
        Pop-Location
    }
} finally {
    if (Test-Path -LiteralPath $applicationVerification -PathType Leaf) {
        Remove-Item -LiteralPath $applicationVerification -Force
    }
}

$signTool = Resolve-File $SignToolPath 'signtool.exe' 'Windows SDK SignTool'
$iscc = Resolve-File $InnoSetupCompiler 'ISCC.exe' 'Inno Setup compiler'
$sevenZip = Resolve-File $SevenZipPath '7z.exe' '7-Zip'
$licenseText = Resolve-File $InnoLicenseTextPath 'license.txt' 'Inno Setup license text'
$applicationRoot = Join-Path $bundle 'payload\DefenseTracker'
$applicationExe = Join-Path $applicationRoot 'DefenseTracker.exe'
& $signTool verify /pa /all /v /tw $applicationExe
if ($LASTEXITCODE -ne 0) { throw 'Application Authenticode trust verification failed.' }
$signature = Get-AuthenticodeSignature -LiteralPath $applicationExe
if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
    $null -eq $signature.SignerCertificate -or $null -eq $signature.TimeStamperCertificate) {
    throw 'Application signature or trusted timestamp is invalid.'
}
$identity = Assert-ReleaseSignerCertificatePolicy $signature.SignerCertificate $policy
if ([string]$identity.normalized_subject -cne [string]$receipt.signature.signer_subject -or
    [string]$identity.spki_sha256 -cne [string]$receipt.signature.signer_spki_sha256 -or
    [string]$identity.issuer_subject -cne [string]$receipt.signature.signer_issuer_subject -or
    [string]$identity.root_sha256 -cne [string]$receipt.signature.signer_root_sha256 -or
    [string]$identity.leaf_spki_policy -cne [string]$receipt.signature.publisher_policy.leaf_spki_policy) {
    throw 'Observed application signer identity differs from the receipt.'
}

if ([string]::IsNullOrWhiteSpace($ComplianceEvidence) -or
    $ExpectedComplianceEvidenceSha256 -cnotmatch '^[0-9a-f]{64}$') {
    throw 'Installer preparation requires the exact reviewed compliance evidence.'
}
$complianceFull = [System.IO.Path]::GetFullPath($ComplianceEvidence)
if (-not (Test-Path -LiteralPath $complianceFull -PathType Leaf) -or
    (Get-Sha256 $complianceFull) -cne $ExpectedComplianceEvidenceSha256) {
    throw 'Reviewed compliance evidence is missing or has changed.'
}
$bundleEvidence = Join-Path $bundle 'evidence'
$componentInventory = Join-Path $bundleEvidence 'unsigned-component-inventory.json'
$packages = Join-Path $bundleEvidence 'installed-packages.txt'
$runtimeLock = Join-Path $bundleEvidence 'requirements.runtime.lock'
$buildLock = Join-Path $bundleEvidence 'requirements.build.lock'
$complianceVerification = Join-Path ([System.IO.Path]::GetTempPath()) (
    'defensetracker-compliance-' + [guid]::NewGuid().ToString('N') + '.json'
)
try {
    & $python (Join-Path $projectRoot 'scripts\verify_compliance_evidence.py') `
        --evidence $complianceFull --application-signing-request $internalRequest `
        --expected-application-signing-request-sha256 $ApplicationSigningRequestSha256 `
        --component-inventory $componentInventory --application-root $applicationRoot `
        --expected-sha256 $ExpectedComplianceEvidenceSha256 `
        --commit $ExpectedReleaseSha --source-tree ([string]$request.release.source_tree) `
        --publisher $publisher --packages-file $packages `
        --third-party-notices (Join-Path $projectRoot 'THIRD_PARTY_NOTICES.md') `
        --runtime-lock-sha256 (Get-Sha256 $runtimeLock) `
        --build-lock-sha256 (Get-Sha256 $buildLock) `
        --verified-at-utc ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')) `
        --github-repository ([string]$request.provenance.repository) `
        --github-workflow-ref ([string]$request.provenance.workflow_ref) `
        --github-run-id ([string]$request.provenance.run_id) `
        --github-run-attempt ([string]$request.provenance.run_attempt) `
        --output-receipt $complianceVerification
    if ($LASTEXITCODE -ne 0) { throw 'Compliance evidence revalidation failed.' }

    Assert-NoReleaseSafetyFinding $applicationRoot
    $installerWork = Join-Path $outputFull 'work'
    $installerOutput = Join-Path $installerWork 'installer'
    $extractRoot = Join-Path $installerWork 'extract'
    $exchangeRoot = Join-Path $outputFull 'installer-unsigned-bundle'
    $exchangePayload = Join-Path $exchangeRoot 'payload'
    $exchangeApplication = Join-Path $exchangeRoot 'application'
    $exchangeEvidence = Join-Path $exchangeRoot 'evidence'
    @(
        $installerOutput,$extractRoot,$exchangePayload,
        $exchangeApplication,$exchangeEvidence
    ) | ForEach-Object { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
    $installerDefinition = Join-Path $projectRoot 'deploy\mvp\DefenseTracker.iss'
    $version = Get-Content -LiteralPath (Join-Path $projectRoot 'version.json') -Raw | ConvertFrom-Json
    & $iscc "/DAppSource=$applicationRoot" "/DOutputDir=$installerOutput" `
        "/DAppVersion=$($version.semantic_version)" "/DDisplayVersion=$($version.display_version)" `
        "/DWindowsFileVersion=$($version.windows_file_version)" `
        "/DGitShort=$($ExpectedReleaseSha.Substring(0,12))" "/DPublisherName=$publisher" `
        $installerDefinition
    if ($LASTEXITCODE -ne 0) { throw 'Inno Setup compilation failed.' }
    $installerName = "DefenseTracker-Setup-v$($version.semantic_version)-windows-x64.exe"
    $unsignedInstaller = Join-Path $installerOutput $installerName
    if (-not (Test-Path -LiteralPath $unsignedInstaller -PathType Leaf) -or
        (Get-AuthenticodeSignature -LiteralPath $unsignedInstaller).Status -ne
            [Management.Automation.SignatureStatus]::NotSigned) {
        throw 'Unsigned installer output is absent or unexpectedly signed.'
    }
    & $sevenZip x -y "-o$extractRoot" $unsignedInstaller
    if ($LASTEXITCODE -ne 0) { throw 'Unsigned installer extraction failed.' }
    Assert-NoReleaseSafetyFinding $extractRoot
    $installedExe = @(Get-ChildItem -LiteralPath $extractRoot -Filter DefenseTracker.exe -File -Recurse)
    if ($installedExe.Count -ne 1 -or (Get-Sha256 $installedExe[0].FullName) -cne
        (Get-Sha256 $applicationExe)) {
        throw 'Unsigned installer does not contain the exact signed application.'
    }

    $signedInventory = Join-Path $exchangeEvidence 'signed-component-inventory.json'
    & $python (Join-Path $projectRoot 'scripts\generate_component_inventory.py') `
        $applicationRoot $signedInventory
    if ($LASTEXITCODE -ne 0) { throw 'Signed application inventory generation failed.' }
    $installerDigest = Join-Path $exchangeEvidence 'installer-authenticode-unsigned.json'
    & $python (Join-Path $projectRoot 'scripts\authenticode_digest.py') `
        --path $unsignedInstaller --require-state unsigned --output $installerDigest
    if ($LASTEXITCODE -ne 0) { throw 'Unsigned installer digest capture failed.' }
    $copyrightLine = @(
        Get-Content -LiteralPath $licenseText |
            Where-Object { $_ -match '(?i)copyright' -and -not [string]::IsNullOrWhiteSpace($_) }
    ) | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace([string]$copyrightLine) -or
        ([string]$copyrightLine).Length -gt 500) {
        throw 'Inno Setup copyright text cannot be derived from the pinned license.'
    }
    $reviewRequest = Join-Path $exchangeEvidence 'installer-review-request.json'
    $isccVersion = [string](Get-Item -LiteralPath $iscc).VersionInfo.FileVersion
    $sevenZipVersion = [string](Get-Item -LiteralPath $sevenZip).VersionInfo.FileVersion
    & $python (Join-Path $projectRoot 'scripts\generate_installer_review_request.py') `
        --unsigned-installer $unsignedInstaller --payload-root $extractRoot `
        --signed-application-inventory $signedInventory --iss $installerDefinition `
        --iscc $iscc --iscc-version $isccVersion --seven-zip $sevenZip `
        --seven-zip-version $sevenZipVersion `
        --bootstrap-license-declared LicenseRef-Inno-Setup `
        --bootstrap-license-concluded LicenseRef-Inno-Setup `
        --bootstrap-copyright-text ([string]$copyrightLine).Trim() `
        --bootstrap-license-text $licenseText --commit $ExpectedReleaseSha `
        --source-tree ([string]$request.release.source_tree) `
        --version $version.semantic_version --publisher $publisher --output $reviewRequest
    if ($LASTEXITCODE -ne 0) { throw 'Installer review request generation failed.' }

    Copy-Item -LiteralPath $unsignedInstaller -Destination (Join-Path $exchangePayload $installerName)
    Get-ChildItem -LiteralPath $bundle -Force |
        Copy-Item -Destination $exchangeApplication -Recurse -Force
    Copy-Item -LiteralPath $licenseText -Destination (Join-Path $exchangeEvidence 'inno-license.txt')
    Copy-Item -LiteralPath $complianceFull -Destination (Join-Path $exchangeEvidence 'compliance-evidence.json')
    Copy-Item -LiteralPath $complianceVerification -Destination (
        Join-Path $exchangeEvidence 'compliance-dispatch-verification.json'
    )
    $requestPath = Join-Path $exchangeRoot 'signing-request.json'
    $materialInputs = Join-Path $outputFull 'material-inputs'
    New-Item -ItemType Directory -Path $materialInputs -Force | Out-Null
    $materialCopies = [ordered]@{
        'iscc.exe' = $iscc
        'seven-zip.exe' = $sevenZip
        'inno-license.txt' = $licenseText
        'DefenseTracker.iss' = $installerDefinition
        'signed-application-inventory.json' = $signedInventory
        'application-signing-request.json' = $internalRequest
        'application-signing-receipt.json' = $internalReceipt
        'compliance-evidence.json' = $complianceFull
    }
    foreach ($name in $materialCopies.Keys) {
        $sourceMaterial = Get-Item -LiteralPath $materialCopies[$name] -Force
        if ($sourceMaterial.PSIsContainer -or
            ($sourceMaterial.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Installer signing material is not a regular non-reparse file: $name"
        }
        $stagedMaterial = Join-Path $materialInputs $name
        Copy-Item -LiteralPath $sourceMaterial.FullName -Destination $stagedMaterial
        $stagedItem = Get-Item -LiteralPath $stagedMaterial -Force
        if ($stagedItem.PSIsContainer -or
            ($stagedItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Staged installer signing material is not a regular file: $name"
        }
    }
    $exchangeRelative = [IO.Path]::GetRelativePath($outputFull, $exchangeRoot).Replace('\','/')
    $requestRelative = [IO.Path]::GetRelativePath($outputFull, $requestPath).Replace('\','/')
    $materialRelative = [IO.Path]::GetRelativePath($outputFull, $materialInputs).Replace('\','/')
    Push-Location -LiteralPath $outputFull
    try {
        & $python (Join-Path $projectRoot 'scripts\signing_exchange.py') create-request `
            --subject-kind installer --bundle-root $exchangeRelative `
            --target "payload/$installerName" --release-commit $ExpectedReleaseSha `
            --source-tree ([string]$request.release.source_tree) --version $version.semantic_version `
            --publisher $publisher --repository $Repository --workflow-ref $WorkflowRef `
            --run-id $RunId --run-attempt $RunAttempt --job prepare-unsigned-installer `
            --material "iscc=$materialRelative/iscc.exe" `
            --material "seven-zip=$materialRelative/seven-zip.exe" `
            --material "inno-license=$materialRelative/inno-license.txt" `
            --material "installer-definition=$materialRelative/DefenseTracker.iss" `
            --material "signed-application-inventory=$materialRelative/signed-application-inventory.json" `
            --material "application-signing-request=$materialRelative/application-signing-request.json" `
            --material "application-signing-receipt=$materialRelative/application-signing-receipt.json" `
            --material "compliance-evidence=$materialRelative/compliance-evidence.json" `
            --output $requestRelative
        if ($LASTEXITCODE -ne 0) { throw 'Installer signing request generation failed.' }
    } finally {
        Pop-Location
        Remove-Item -LiteralPath $materialInputs -Recurse -Force -ErrorAction SilentlyContinue
    }
    Copy-Item -LiteralPath $requestPath -Destination (Join-Path $outputFull 'installer-signing-request.json')
    Remove-Item -LiteralPath $installerWork -Recurse -Force
} finally {
    if (Test-Path -LiteralPath $complianceVerification -PathType Leaf) {
        Remove-Item -LiteralPath $complianceVerification -Force
    }
}

Write-Host "installer-bundle=$(Join-Path $outputFull 'installer-unsigned-bundle')"
Write-Host "installer-signing-request=$(Join-Path $outputFull 'installer-signing-request.json')"
