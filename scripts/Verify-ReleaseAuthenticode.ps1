#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$AssetRoot,
    [Parameter(Mandatory = $true)][string]$PublisherName,
    [Parameter(Mandatory = $true)][string]$SignToolPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$root = [System.IO.Path]::GetFullPath($AssetRoot)
$tool = [System.IO.Path]::GetFullPath($SignToolPath)
if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw "Asset root is missing." }
if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw "SignTool is missing." }
$manifest = Get-Content -LiteralPath (Join-Path $root "release-manifest.json") -Raw | ConvertFrom-Json
$version = $manifest.version.semantic_version
$installer = Join-Path $root "DefenseTracker-Setup-v$version-windows-x64.exe"
$portable = Join-Path $root "DefenseTracker-v$version-windows-x64-portable.zip"

function Assert-SignedFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    & $tool verify /pa /all /v /tw $Path
    if ($LASTEXITCODE -ne 0) { throw "SignTool rejected $Path." }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or
        $null -eq $signature.TimeStamperCertificate) {
        throw "Authenticode or timestamp validation failed for $Path."
    }
    $simpleName = $signature.SignerCertificate.GetNameInfo(
        [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
        $false
    )
    if ($simpleName -cne $PublisherName) { throw "Unexpected Authenticode Publisher." }
}

Assert-SignedFile $installer
$temporaryParent = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd("\") + "\"
$extractRoot = Join-Path $temporaryParent ("defensetracker-release-verify-" + [guid]::NewGuid().ToString("N"))
try {
    New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null
    Expand-Archive -LiteralPath $portable -DestinationPath $extractRoot
    Assert-SignedFile (Join-Path $extractRoot "DefenseTracker\DefenseTracker.exe")
} finally {
    if (Test-Path -LiteralPath $extractRoot -PathType Container) {
        $resolved = [System.IO.Path]::GetFullPath($extractRoot)
        if (-not $resolved.StartsWith($temporaryParent) -or
            [System.IO.Path]::GetFileName($resolved) -notmatch '^defensetracker-release-verify-[0-9a-f]{32}$') {
            throw "Refusing to remove unexpected verification directory."
        }
        Get-ChildItem -LiteralPath $resolved -Force -Recurse | Select-Object FullName,Length | Out-Null
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
Write-Host "release-authenticode: PASS"
