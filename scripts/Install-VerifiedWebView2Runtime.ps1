param(
    [string]$LockFile = (Join-Path $PSScriptRoot '..\release\webview2-runtime-lock.json'),
    [string]$DownloadDirectory = (Join-Path $env:RUNNER_TEMP 'defensetracker-webview2')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-WebView2RuntimeVersion {
    $minimumRuntimeVersion = [System.Version]'86.0.622.0'
    $clientId = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    $keys = @(
        "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$clientId",
        "Registry::HKEY_CURRENT_USER\Software\Microsoft\EdgeUpdate\Clients\$clientId"
    )
    foreach ($key in $keys) {
        if (-not (Test-Path -LiteralPath $key)) { continue }
        $version = [string](Get-ItemPropertyValue -LiteralPath $key -Name 'pv' -ErrorAction SilentlyContinue)
        $parsedVersion = $null
        if ([System.Version]::TryParse($version, [ref]$parsedVersion) -and
            $parsedVersion -ge $minimumRuntimeVersion) {
            return $parsedVersion.ToString()
        }
    }
    return ''
}

$lockPath = [System.IO.Path]::GetFullPath($LockFile)
if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
    throw 'WebView2 runtime lock is missing.'
}
$lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
$expectedKeys = @(
    'architecture',
    'bytes',
    'distribution',
    'installer_file_version',
    'original_filename',
    'publisher_subject',
    'retrieved_utc',
    'schema',
    'sha256',
    'source_url'
)
$actualKeys = @($lock.PSObject.Properties.Name | Sort-Object)
if (($actualKeys -join "`n") -cne (($expectedKeys | Sort-Object) -join "`n")) {
    throw 'WebView2 runtime lock has an unexpected schema.'
}
if ($lock.schema -ne 1 -or $lock.distribution -cne 'evergreen-standalone' -or
    $lock.architecture -cne 'x64' -or [string]$lock.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
    [long]$lock.bytes -le 0) {
    throw 'WebView2 runtime lock identity is invalid.'
}
$source = [Uri]([string]$lock.source_url)
if ($source.Scheme -cne 'https' -or
    $source.Host -cne 'msedge.sf.dl.delivery.mp.microsoft.com' -or
    -not $source.AbsolutePath.EndsWith('/MicrosoftEdgeWebView2RuntimeInstallerX64.exe', [StringComparison]::Ordinal)) {
    throw 'WebView2 runtime source is not the pinned Microsoft HTTPS origin.'
}

$downloadRoot = [System.IO.Path]::GetFullPath($DownloadDirectory)
[System.IO.Directory]::CreateDirectory($downloadRoot) | Out-Null
$installer = Join-Path $downloadRoot 'MicrosoftEdgeWebView2RuntimeInstallerX64.exe'
if (-not (Test-Path -LiteralPath $installer -PathType Leaf) -or
    (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$lock.sha256) {
    Invoke-WebRequest -Uri $source.AbsoluteUri -OutFile $installer
}

$file = Get-Item -LiteralPath $installer
$sha256 = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
if ($file.Length -ne [long]$lock.bytes -or $sha256 -cne [string]$lock.sha256) {
    throw 'WebView2 runtime installer differs from the hash-pinned lock.'
}
$signature = Get-AuthenticodeSignature -LiteralPath $installer
if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
    [string]$signature.SignerCertificate.Subject -cne [string]$lock.publisher_subject) {
    throw 'WebView2 runtime installer publisher verification failed.'
}
$versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($installer)
if ($versionInfo.FileVersion -cne [string]$lock.installer_file_version -or
    $versionInfo.OriginalFilename -cne [string]$lock.original_filename) {
    throw 'WebView2 runtime installer VersionInfo differs from the lock.'
}

$runtimeVersion = Get-WebView2RuntimeVersion
$installAction = 'already-present'
if (-not $runtimeVersion) {
    $process = Start-Process -FilePath $installer -ArgumentList @('/silent', '/install') `
        -PassThru -Wait -WindowStyle Hidden
    if ($process.ExitCode -ne 0) {
        throw "WebView2 runtime installer failed with exit $($process.ExitCode)."
    }
    $runtimeVersion = Get-WebView2RuntimeVersion
    $installAction = 'installed'
}
if (-not $runtimeVersion) {
    throw 'WebView2 Runtime was not registered after verified installation.'
}

Write-Host (
    "WEBVIEW2_RUNTIME_VERIFIED architecture=x64 installer_sha256=$sha256 " +
    "runtime_version=$runtimeVersion publisher=Microsoft-Corporation action=$installAction"
)
