<#
.SYNOPSIS
Bootstraps the hash-locked Windows release tools on a GitHub-hosted runner.

.DESCRIPTION
Downloads only the two pinned NuGet packages required for Windows SDK signing,
discovers the preinstalled GitHub runner tools, and exports absolute paths plus
their observed SHA-256 digests through GITHUB_ENV. Signing credentials are not
accepted by this script and no metadata content is written to the log.
#>

#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('VerificationOnly', 'AzureArtifactSigning', 'DigiCertKeyLocker')]
    [string]$Mode = 'VerificationOnly',

    [string]$GitHubEnvironmentFile = $env:GITHUB_ENV,
    [string]$RunnerTemporaryDirectory = $env:RUNNER_TEMP
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$sdkPackageVersion = '10.0.26100.4188'
$sdkPackageSha256 = '180deb372659029864c10a0c04787833234d64aacd1d2c0661d2c00295d8e022'
$artifactSigningVersion = '1.0.128'
$artifactSigningSha256 = '74bd7d27e6ce1051409c38d9b46bc8df0400ecd643d51ffbf2ac00869061e40b'

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-PlainEnvironmentValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][string]$Value
    )
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Contains("`r") -or $Value.Contains("`n")) {
        throw "$Name is missing or contains a line break."
    }
}

function Export-GitHubEnvironmentValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value
    )
    if ($Name -cnotmatch '^[A-Z][A-Z0-9_]+$') {
        throw 'Refusing to export an invalid environment variable name.'
    }
    Assert-PlainEnvironmentValue -Name $Name -Value $Value
    [System.IO.File]::AppendAllText(
        $script:resolvedGitHubEnvironmentFile,
        "$Name=$Value`n",
        [System.Text.UTF8Encoding]::new($false)
    )
}

function Get-VerifiedNuGetPackage {
    param(
        [Parameter(Mandatory = $true)][string]$PackageId,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$DestinationRoot
    )
    $lowerId = $PackageId.ToLowerInvariant()
    $packagePath = Join-Path $DestinationRoot "$PackageId.$Version.nupkg"
    $packageUri = "https://api.nuget.org/v3-flatcontainer/$lowerId/$Version/$lowerId.$Version.nupkg"
    Invoke-WebRequest -Uri $packageUri -OutFile $packagePath -UseBasicParsing
    if ((Get-Sha256 -Path $packagePath) -cne $ExpectedSha256) {
        throw "Downloaded $PackageId package does not match the pinned SHA-256."
    }
    $expandedRoot = Join-Path $DestinationRoot "$PackageId.$Version"
    New-Item -ItemType Directory -Path $expandedRoot | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($packagePath, $expandedRoot)
    return $expandedRoot
}

function Resolve-SingleFile {
    param(
        [Parameter(Mandatory = $true)][string[]]$Candidates,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $matches = @(
        $Candidates |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object {
                if (Test-Path -LiteralPath $_ -PathType Leaf) {
                    [System.IO.Path]::GetFullPath($_)
                }
            } |
            Select-Object -Unique
    )
    if ($matches.Count -ne 1) {
        throw "$Description could not be resolved to exactly one file."
    }
    return $matches[0]
}

function Export-ToolIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$PathVariable,
        [Parameter(Mandatory = $true)][string]$HashVariable,
        [Parameter(Mandatory = $true)][string]$Path
    )
    Export-GitHubEnvironmentValue -Name $PathVariable -Value $Path
    Export-GitHubEnvironmentValue -Name $HashVariable -Value (Get-Sha256 -Path $Path)
}

if ($env:GITHUB_ACTIONS -cne 'true' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
    $env:RUNNER_OS -cne 'Windows') {
    throw 'Release tool bootstrap is restricted to an ephemeral GitHub-hosted Windows runner.'
}
Assert-PlainEnvironmentValue -Name 'GITHUB_ENV' -Value $GitHubEnvironmentFile
Assert-PlainEnvironmentValue -Name 'RUNNER_TEMP' -Value $RunnerTemporaryDirectory
$resolvedRunnerTemp = [System.IO.Path]::GetFullPath($RunnerTemporaryDirectory)
if (-not (Test-Path -LiteralPath $resolvedRunnerTemp -PathType Container)) {
    throw 'RUNNER_TEMP does not identify an existing directory.'
}
$script:resolvedGitHubEnvironmentFile = [System.IO.Path]::GetFullPath($GitHubEnvironmentFile)
$environmentParent = Split-Path -Parent $script:resolvedGitHubEnvironmentFile
if (-not (Test-Path -LiteralPath $environmentParent -PathType Container)) {
    throw 'The parent directory of GITHUB_ENV does not exist.'
}

$toolRoot = Join-Path $resolvedRunnerTemp 'defense-tracker-release-tools'
if (Test-Path -LiteralPath $toolRoot) {
    throw 'The one-use release tool directory already exists.'
}
New-Item -ItemType Directory -Path $toolRoot | Out-Null

$sdkRoot = Get-VerifiedNuGetPackage `
    -PackageId 'Microsoft.Windows.SDK.BuildTools' `
    -Version $sdkPackageVersion `
    -ExpectedSha256 $sdkPackageSha256 `
    -DestinationRoot $toolRoot
$signTool = Resolve-SingleFile `
    -Candidates @(Get-ChildItem -LiteralPath $sdkRoot -Filter 'signtool.exe' -File -Recurse |
        Where-Object { $_.FullName -match '[\\/]x64[\\/]signtool\.exe$' } |
        Select-Object -ExpandProperty FullName) `
    -Description 'x64 Windows SDK SignTool'

Assert-PlainEnvironmentValue -Name 'pythonLocation' -Value $env:pythonLocation
$python = Resolve-SingleFile `
    -Candidates @(Join-Path $env:pythonLocation 'python.exe') `
    -Description 'setup-python CPython'

$isccCommand = Get-Command ISCC.exe -ErrorAction SilentlyContinue
$isccCandidates = @(
    if ($null -ne $isccCommand) { $isccCommand.Source }
    (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe')
    (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe')
)
$iscc = Resolve-SingleFile -Candidates $isccCandidates -Description 'Inno Setup compiler'

$sevenZipCommand = Get-Command 7z.exe -ErrorAction SilentlyContinue
$sevenZipCandidates = @(
    if ($null -ne $sevenZipCommand) { $sevenZipCommand.Source }
    (Join-Path $env:ProgramFiles '7-Zip\7z.exe')
    (Join-Path ${env:ProgramFiles(x86)} '7-Zip\7z.exe')
)
$sevenZip = Resolve-SingleFile -Candidates $sevenZipCandidates -Description '7-Zip'

$defenderCandidates = @()
$defenderPlatformRoot = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform'
if (Test-Path -LiteralPath $defenderPlatformRoot -PathType Container) {
    $latestDefender = Get-ChildItem -LiteralPath $defenderPlatformRoot -Directory |
        Sort-Object Name -Descending |
        ForEach-Object { Join-Path $_.FullName 'MpCmdRun.exe' } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
    if ($null -ne $latestDefender) { $defenderCandidates += $latestDefender }
}
if ($defenderCandidates.Count -eq 0) {
    $defenderCandidates += (Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe')
}
$defender = Resolve-SingleFile -Candidates $defenderCandidates -Description 'Microsoft Defender command-line scanner'

Export-GitHubEnvironmentValue -Name 'DEFENSE_TRACKER_EPHEMERAL_RUNNER_MODE' -Value 'ephemeral'
Export-GitHubEnvironmentValue -Name 'DEFENSE_TRACKER_SIGNING_PROVIDER' -Value $Mode
Export-ToolIdentity -PathVariable 'DEFENSE_TRACKER_BUILD_PYTHON' `
    -HashVariable 'DEFENSE_TRACKER_BUILD_PYTHON_SHA256' -Path $python
Export-ToolIdentity -PathVariable 'DEFENSE_TRACKER_SIGNTOOL' `
    -HashVariable 'DEFENSE_TRACKER_SIGNTOOL_SHA256' -Path $signTool
Export-ToolIdentity -PathVariable 'DEFENSE_TRACKER_ISCC' `
    -HashVariable 'DEFENSE_TRACKER_ISCC_SHA256' -Path $iscc
Export-ToolIdentity -PathVariable 'DEFENSE_TRACKER_7ZIP' `
    -HashVariable 'DEFENSE_TRACKER_7ZIP_SHA256' -Path $sevenZip
Export-ToolIdentity -PathVariable 'DEFENSE_TRACKER_DEFENDER' `
    -HashVariable 'DEFENSE_TRACKER_DEFENDER_SHA256' -Path $defender

$innoLicense = Resolve-SingleFile `
    -Candidates @(
        (Join-Path (Split-Path -Parent $iscc) 'license.txt'),
        (Join-Path (Split-Path -Parent $iscc) 'LICENSE.TXT')
    ) `
    -Description 'Inno Setup license text'
Export-ToolIdentity -PathVariable 'DEFENSE_TRACKER_INNO_LICENSE_TEXT' `
    -HashVariable 'DEFENSE_TRACKER_INNO_LICENSE_TEXT_SHA256' -Path $innoLicense

if ($Mode -eq 'AzureArtifactSigning') {
    foreach ($requiredName in @(
        'DEFENSE_TRACKER_AZURE_SIGNING_ENDPOINT',
        'DEFENSE_TRACKER_AZURE_SIGNING_ACCOUNT_NAME',
        'DEFENSE_TRACKER_AZURE_SIGNING_CERTIFICATE_PROFILE_NAME',
        'GITHUB_REPOSITORY',
        'GITHUB_RUN_ID',
        'GITHUB_RUN_ATTEMPT',
        'GITHUB_SHA'
    )) {
        Assert-PlainEnvironmentValue -Name $requiredName -Value ([Environment]::GetEnvironmentVariable($requiredName))
    }
    $endpoint = [Uri]$env:DEFENSE_TRACKER_AZURE_SIGNING_ENDPOINT
    if (-not $endpoint.IsAbsoluteUri -or $endpoint.Scheme -cne 'https') {
        throw 'Azure Artifact Signing endpoint must be an absolute HTTPS URI.'
    }
    if ($env:GITHUB_REPOSITORY -cnotmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or
        $env:GITHUB_RUN_ID -cnotmatch '^[1-9][0-9]*$' -or
        $env:GITHUB_RUN_ATTEMPT -cnotmatch '^[1-9][0-9]*$' -or
        $env:GITHUB_SHA -cnotmatch '^[0-9a-f]{40}$') {
        throw 'GitHub run identity is malformed.'
    }
    $artifactRoot = Get-VerifiedNuGetPackage `
        -PackageId 'Microsoft.ArtifactSigning.Client' `
        -Version $artifactSigningVersion `
        -ExpectedSha256 $artifactSigningSha256 `
        -DestinationRoot $toolRoot
    $azureDlib = Resolve-SingleFile `
        -Candidates @(Join-Path $artifactRoot 'bin\x64\Azure.CodeSigning.Dlib.dll') `
        -Description 'Azure Artifact Signing x64 DLib'
    $metadataPath = Join-Path $toolRoot 'artifact-signing-metadata.json'
    $correlationId = if ([string]::IsNullOrWhiteSpace($env:DEFENSE_TRACKER_AZURE_SIGNING_CORRELATION_ID)) {
        "$env:GITHUB_REPOSITORY/$env:GITHUB_RUN_ID/$env:GITHUB_RUN_ATTEMPT/$env:GITHUB_SHA"
    } else {
        $env:DEFENSE_TRACKER_AZURE_SIGNING_CORRELATION_ID
    }
    Assert-PlainEnvironmentValue -Name 'DEFENSE_TRACKER_AZURE_SIGNING_CORRELATION_ID' -Value $correlationId
    $metadata = [ordered]@{
        Endpoint = $endpoint.AbsoluteUri
        CodeSigningAccountName = $env:DEFENSE_TRACKER_AZURE_SIGNING_ACCOUNT_NAME
        CertificateProfileName = $env:DEFENSE_TRACKER_AZURE_SIGNING_CERTIFICATE_PROFILE_NAME
        CorrelationId = $correlationId
    }
    [System.IO.File]::WriteAllText(
        $metadataPath,
        ($metadata | ConvertTo-Json -Compress),
        [System.Text.UTF8Encoding]::new($false)
    )
    Export-ToolIdentity -PathVariable 'DEFENSE_TRACKER_AZURE_SIGNING_DLIB' `
        -HashVariable 'DEFENSE_TRACKER_AZURE_SIGNING_DLIB_SHA256' -Path $azureDlib
    Export-ToolIdentity -PathVariable 'DEFENSE_TRACKER_AZURE_SIGNING_METADATA' `
        -HashVariable 'DEFENSE_TRACKER_AZURE_SIGNING_METADATA_SHA256' -Path $metadataPath
} elseif ($Mode -eq 'DigiCertKeyLocker') {
    # The pinned DigiCert action prepares KeyLocker authentication separately.
    # This bootstrap intentionally handles only the credentialless toolchain.
}

Write-Host '[OK] Hash-locked GitHub-hosted Windows release tools are ready.'
