Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:RequestFileName = 'candidate-transport-request.json'
$script:ReceiptFileName = 'candidate-transport-receipt.json'
$script:RequestSchema = 'defense-tracker-candidate-transport-request-v1'
$script:ReceiptSchema = 'defense-tracker-candidate-transport-receipt-v1'
$script:ArtifactNamePattern = '^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$'
$script:Sha256Pattern = '^[0-9a-f]{64}$'
$script:ReleaseCommitPattern = '^[0-9a-f]{40}$'
$script:RepositoryPattern = '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'
$script:PositiveIntegerPattern = '^[1-9][0-9]*$'
$script:RecipientPattern = '^age1[0-9a-z]{58}$'
$script:IdentityPattern = '^AGE-SECRET-KEY-1[023456789ACDEFGHJKLMNPQRSTUVWXYZ]{58}$'

function Get-ReleaseArtifactSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [System.IO.File]::OpenRead($Path)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $algorithm.ComputeHash($stream)
        return (($digest | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $algorithm.Dispose()
        $stream.Dispose()
    }
}

function Assert-ReleaseArtifactPlainValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory = $true)][string]$Pattern
    )
    if ($Value.Contains("`r") -or $Value.Contains("`n") -or $Value -cnotmatch $Pattern) {
        throw "$Name is malformed."
    }
}

function Test-ReleaseArtifactFilesystemLink {
    param([Parameter(Mandatory = $true)]$Item)
    if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        return $true
    }
    $linkType = $Item.PSObject.Properties['LinkType']
    return $null -ne $linkType -and
        -not [string]::IsNullOrWhiteSpace([string]$linkType.Value)
}

function Assert-ReleaseArtifactNoReparsePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$AllowMissingLeaf
    )
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $cursor = $fullPath
    $isLeaf = $true
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (Test-ReleaseArtifactFilesystemLink $item) {
                throw 'Release artifact paths must not contain a reparse point.'
            }
        } elseif (-not ($AllowMissingLeaf -and $isLeaf)) {
            throw 'A required release artifact path does not exist.'
        }
        $parent = Split-Path -Parent $cursor
        if ($parent -ceq $cursor) { break }
        $cursor = $parent
        $isLeaf = $false
    }
    return $fullPath
}

function Read-ReleaseArtifactSingleLineKey {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Pattern
    )
    $fullPath = Assert-ReleaseArtifactNoReparsePath -Path $Path
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "$Name must identify a regular file."
    }
    $bytes = [System.IO.File]::ReadAllBytes($fullPath)
    if ($bytes.Length -eq 0 -or
        ($bytes.Length -ge 3 -and $bytes[0] -eq 0xef -and $bytes[1] -eq 0xbb -and $bytes[2] -eq 0xbf)) {
        throw "$Name must be non-empty UTF-8 without a BOM."
    }
    try {
        $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    } catch {
        throw "$Name is not valid UTF-8."
    }
    if ($text.EndsWith("`n")) {
        $value = $text.Substring(0, $text.Length - 1)
    } else {
        $value = $text
    }
    if ($value.Contains("`r") -or $value.Contains("`n") -or $value -cnotmatch $Pattern) {
        throw "$Name must contain exactly one supported key and no injected line."
    }
    return [pscustomobject]@{
        Path = $fullPath
        Sha256 = Get-ReleaseArtifactSha256 -Path $fullPath
    }
}

function Get-ReleaseArtifactSafeFiles {
    param([Parameter(Mandatory = $true)][string]$Root)
    $resolvedRoot = Assert-ReleaseArtifactNoReparsePath -Path $Root
    if (-not (Test-Path -LiteralPath $resolvedRoot -PathType Container)) {
        throw 'PlaintextRoot must identify a directory.'
    }
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($resolvedRoot)
    $files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force)) {
            if (Test-ReleaseArtifactFilesystemLink $item) {
                throw 'PlaintextRoot contains a forbidden reparse point.'
            }
            if ($item.PSIsContainer) {
                $pending.Push($item.FullName)
            } elseif ($item -is [System.IO.FileInfo]) {
                $files.Add($item)
            } else {
                throw 'PlaintextRoot contains an unsupported filesystem object.'
            }
        }
    }
    if ($files.Count -eq 0) {
        throw 'PlaintextRoot must contain at least one regular file.'
    }
    return @($files | Sort-Object FullName)
}

function New-ReleaseArtifactArchive {
    param(
        [Parameter(Mandatory = $true)][string]$PlaintextRoot,
        [Parameter(Mandatory = $true)][string]$ArchivePath
    )
    $root = [System.IO.Path]::GetFullPath($PlaintextRoot).TrimEnd([char[]]@('\', '/'))
    $files = Get-ReleaseArtifactSafeFiles -Root $root
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archiveStream = [System.IO.File]::Open(
        $ArchivePath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None
    )
    try {
        $archive = [System.IO.Compression.ZipArchive]::new(
            $archiveStream,
            [System.IO.Compression.ZipArchiveMode]::Create,
            $false
        )
        try {
            foreach ($file in $files) {
                $relative = $file.FullName.Substring($root.Length).TrimStart([char[]]@('\', '/')).Replace('\', '/')
                if ([string]::IsNullOrWhiteSpace($relative) -or
                    $relative.StartsWith('/') -or
                    $relative.Contains(':') -or
                    @($relative.Split('/') | Where-Object { $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' }).Count -ne 0) {
                    throw 'PlaintextRoot produced an unsafe archive entry name.'
                }
                $entry = $archive.CreateEntry(
                    "payload/$relative",
                    [System.IO.Compression.CompressionLevel]::Optimal
                )
                $entry.LastWriteTime = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
                $sourceStream = $file.OpenRead()
                $destinationStream = $entry.Open()
                try {
                    $sourceStream.CopyTo($destinationStream)
                } finally {
                    $destinationStream.Dispose()
                    $sourceStream.Dispose()
                }
            }
        } finally {
            $archive.Dispose()
        }
    } finally {
        $archiveStream.Dispose()
    }
}

function ConvertTo-ReleaseArtifactCanonicalJson {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Value)
    return ($Value | ConvertTo-Json -Compress -Depth 8)
}

function Write-ReleaseArtifactCanonicalJson {
    param(
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    [System.IO.File]::WriteAllText(
        $Path,
        (ConvertTo-ReleaseArtifactCanonicalJson -Value $Value),
        [System.Text.UTF8Encoding]::new($false)
    )
}

function Read-ReleaseArtifactJsonText {
    param([Parameter(Mandatory = $true)][string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xef -and $bytes[1] -eq 0xbb -and $bytes[2] -eq 0xbf) {
        throw 'Transport JSON must be UTF-8 without a BOM.'
    }
    try {
        return [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    } catch {
        throw 'Transport JSON is not valid UTF-8.'
    }
}

function Assert-ReleaseArtifactExactProperties {
    param(
        [Parameter(Mandatory = $true)][psobject]$Value,
        [Parameter(Mandatory = $true)][string[]]$Expected
    )
    $actual = @($Value.PSObject.Properties.Name)
    if ($actual.Count -ne $Expected.Count -or ($actual -join "`0") -cne ($Expected -join "`0")) {
        throw 'Transport JSON has missing, reordered, or extra properties.'
    }
}

function Get-ReleaseArtifactValidatedRequest {
    param([Parameter(Mandatory = $true)][string]$Path)
    $text = Read-ReleaseArtifactJsonText -Path $Path
    try { $value = $text | ConvertFrom-Json } catch { throw 'Transport request is not valid JSON.' }
    $properties = @(
        'artifact_name', 'recipient_file_sha256', 'release_commit', 'repository',
        'run_attempt', 'run_id', 'schema'
    )
    Assert-ReleaseArtifactExactProperties -Value $value -Expected $properties
    Assert-ReleaseArtifactPlainValue -Name 'artifact_name' -Value ([string]$value.artifact_name) -Pattern $script:ArtifactNamePattern
    if ([string]$value.artifact_name -match '(?i)\.age$') { throw 'artifact_name must not include the .age suffix.' }
    Assert-ReleaseArtifactPlainValue -Name 'recipient_file_sha256' -Value ([string]$value.recipient_file_sha256) -Pattern $script:Sha256Pattern
    Assert-ReleaseArtifactPlainValue -Name 'release_commit' -Value ([string]$value.release_commit) -Pattern $script:ReleaseCommitPattern
    Assert-ReleaseArtifactPlainValue -Name 'repository' -Value ([string]$value.repository) -Pattern $script:RepositoryPattern
    Assert-ReleaseArtifactPlainValue -Name 'run_attempt' -Value ([string]$value.run_attempt) -Pattern $script:PositiveIntegerPattern
    Assert-ReleaseArtifactPlainValue -Name 'run_id' -Value ([string]$value.run_id) -Pattern $script:PositiveIntegerPattern
    if ([string]$value.schema -cne $script:RequestSchema) { throw 'Transport request schema is unsupported.' }
    $canonical = [ordered]@{
        artifact_name = [string]$value.artifact_name
        recipient_file_sha256 = [string]$value.recipient_file_sha256
        release_commit = [string]$value.release_commit
        repository = [string]$value.repository
        run_attempt = [string]$value.run_attempt
        run_id = [string]$value.run_id
        schema = $script:RequestSchema
    }
    if ($text -cne (ConvertTo-ReleaseArtifactCanonicalJson -Value $canonical)) {
        throw 'Transport request is not canonical JSON.'
    }
    return $canonical
}

function Get-ReleaseArtifactValidatedReceipt {
    param([Parameter(Mandatory = $true)][string]$Path)
    $text = Read-ReleaseArtifactJsonText -Path $Path
    try { $value = $text | ConvertFrom-Json } catch { throw 'Transport receipt is not valid JSON.' }
    $properties = @(
        'ciphertext_file', 'ciphertext_sha256', 'ciphertext_size',
        'plaintext_archive_sha256', 'plaintext_archive_size', 'request_file',
        'request_sha256', 'schema'
    )
    Assert-ReleaseArtifactExactProperties -Value $value -Expected $properties
    Assert-ReleaseArtifactPlainValue -Name 'ciphertext_file' -Value ([string]$value.ciphertext_file) -Pattern '^.+\.age$'
    if ([System.IO.Path]::GetFileName([string]$value.ciphertext_file) -cne [string]$value.ciphertext_file) {
        throw 'ciphertext_file must be a base filename.'
    }
    foreach ($name in @('ciphertext_sha256', 'plaintext_archive_sha256', 'request_sha256')) {
        Assert-ReleaseArtifactPlainValue -Name $name -Value ([string]$value.$name) -Pattern $script:Sha256Pattern
    }
    foreach ($name in @('ciphertext_size', 'plaintext_archive_size')) {
        Assert-ReleaseArtifactPlainValue -Name $name -Value ([string]$value.$name) -Pattern $script:PositiveIntegerPattern
    }
    if ([string]$value.request_file -cne $script:RequestFileName) { throw 'Transport receipt request filename is invalid.' }
    if ([string]$value.schema -cne $script:ReceiptSchema) { throw 'Transport receipt schema is unsupported.' }
    $canonical = [ordered]@{
        ciphertext_file = [string]$value.ciphertext_file
        ciphertext_sha256 = [string]$value.ciphertext_sha256
        ciphertext_size = [string]$value.ciphertext_size
        plaintext_archive_sha256 = [string]$value.plaintext_archive_sha256
        plaintext_archive_size = [string]$value.plaintext_archive_size
        request_file = $script:RequestFileName
        request_sha256 = [string]$value.request_sha256
        schema = $script:ReceiptSchema
    }
    if ($text -cne (ConvertTo-ReleaseArtifactCanonicalJson -Value $canonical)) {
        throw 'Transport receipt is not canonical JSON.'
    }
    return $canonical
}

function Assert-ReleaseArtifactExecutable {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )
    Assert-ReleaseArtifactPlainValue -Name 'ExpectedAgeExecutableSha256' -Value $ExpectedSha256 -Pattern $script:Sha256Pattern
    $fullPath = Assert-ReleaseArtifactNoReparsePath -Path $Path
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf) -or
        (Get-ReleaseArtifactSha256 -Path $fullPath) -cne $ExpectedSha256) {
        throw 'age executable does not match its expected SHA-256.'
    }
    return $fullPath
}

function Assert-ReleaseArtifactEnvelopeLayout {
    param([Parameter(Mandatory = $true)][string]$EnvelopeDirectory)
    $root = Assert-ReleaseArtifactNoReparsePath -Path $EnvelopeDirectory
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw 'EnvelopeDirectory must identify a directory.'
    }
    $items = @(Get-ChildItem -LiteralPath $root -Force)
    foreach ($item in $items) {
        if ((Test-ReleaseArtifactFilesystemLink $item) -or $item.PSIsContainer) {
            throw 'Transport envelope contains a directory, reparse point, or unsupported object.'
        }
    }
    $ageFiles = @($items | Where-Object { $_.Name -cmatch '^.+\.age$' })
    if ($items.Count -ne 3 -or $ageFiles.Count -ne 1 -or
        @($items | Where-Object { $_.Name -ceq $script:RequestFileName }).Count -ne 1 -or
        @($items | Where-Object { $_.Name -ceq $script:ReceiptFileName }).Count -ne 1) {
        throw 'Transport envelope must contain exactly one .age file, one request, and one receipt.'
    }
    return [pscustomobject]@{
        Root = $root
        Ciphertext = $ageFiles[0].FullName
        Request = Join-Path $root $script:RequestFileName
        Receipt = Join-Path $root $script:ReceiptFileName
    }
}

function Expand-ReleaseArtifactArchiveSafely {
    param(
        [Parameter(Mandatory = $true)][string]$ArchivePath,
        [Parameter(Mandatory = $true)][string]$OutputDirectory
    )
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
    if (Test-Path -LiteralPath $outputRoot) { throw 'OutputDirectory must not already exist.' }
    [System.IO.Directory]::CreateDirectory($outputRoot) | Out-Null
    $outputPrefix = $outputRoot.TrimEnd([char[]]@('\', '/')) + [System.IO.Path]::DirectorySeparatorChar
    $comparison = if ($env:OS -ceq 'Windows_NT') {
        [System.StringComparison]::OrdinalIgnoreCase
    } else {
        [System.StringComparison]::Ordinal
    }
    $nameComparer = if ($env:OS -ceq 'Windows_NT') {
        [System.StringComparer]::OrdinalIgnoreCase
    } else {
        [System.StringComparer]::Ordinal
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new($nameComparer)
    $stream = [System.IO.File]::OpenRead($ArchivePath)
    try {
        $archive = [System.IO.Compression.ZipArchive]::new(
            $stream,
            [System.IO.Compression.ZipArchiveMode]::Read,
            $false
        )
        try {
            if ($archive.Entries.Count -eq 0) { throw 'Plaintext archive is empty.' }
            foreach ($entry in $archive.Entries) {
                $entryName = $entry.FullName
                $unixType = ($entry.ExternalAttributes -shr 16) -band 0xf000
                if ($entryName.Contains('\') -or
                    -not $entryName.StartsWith('payload/', [System.StringComparison]::Ordinal) -or
                    $entryName.EndsWith('/') -or
                    $entryName.Contains(':') -or
                    $unixType -eq 0xa000) {
                    throw 'Plaintext archive contains an unsafe entry.'
                }
                $relative = $entryName.Substring('payload/'.Length)
                if ([string]::IsNullOrWhiteSpace($relative) -or
                    @($relative.Split('/') | Where-Object { $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' }).Count -ne 0 -or
                    -not $seen.Add($relative)) {
                    throw 'Plaintext archive contains an invalid or duplicate entry.'
                }
                $destination = [System.IO.Path]::GetFullPath(
                    (Join-Path $outputRoot ($relative.Replace([char]'/', [System.IO.Path]::DirectorySeparatorChar)))
                )
                if (-not $destination.StartsWith($outputPrefix, $comparison)) {
                    throw 'Plaintext archive entry escapes OutputDirectory.'
                }
                $parent = Split-Path -Parent $destination
                [System.IO.Directory]::CreateDirectory($parent) | Out-Null
                $sourceStream = $entry.Open()
                $destinationStream = [System.IO.File]::Open(
                    $destination,
                    [System.IO.FileMode]::CreateNew,
                    [System.IO.FileAccess]::Write,
                    [System.IO.FileShare]::None
                )
                try {
                    $sourceStream.CopyTo($destinationStream)
                } finally {
                    $destinationStream.Dispose()
                    $sourceStream.Dispose()
                }
            }
        } finally {
            $archive.Dispose()
        }
    } catch {
        if (Test-Path -LiteralPath $outputRoot) { [System.IO.Directory]::Delete($outputRoot, $true) }
        throw
    } finally {
        $stream.Dispose()
    }
    Get-ReleaseArtifactSafeFiles -Root $outputRoot | Out-Null
}

function Protect-ReleaseArtifact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$AgeExecutable,
        [Parameter(Mandatory = $true)][string]$ExpectedAgeExecutableSha256,
        [Parameter(Mandatory = $true)][string]$PlaintextRoot,
        [Parameter(Mandatory = $true)][string]$RecipientFile,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][string]$ArtifactName,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$ReleaseCommit,
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][string]$RunAttempt,
        [string]$TemporaryDirectory = $(if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { [System.IO.Path]::GetTempPath() } else { $env:RUNNER_TEMP })
    )
    $age = Assert-ReleaseArtifactExecutable -Path $AgeExecutable -ExpectedSha256 $ExpectedAgeExecutableSha256
    $recipient = Read-ReleaseArtifactSingleLineKey -Path $RecipientFile -Name 'RecipientFile' -Pattern $script:RecipientPattern
    Assert-ReleaseArtifactPlainValue -Name 'ArtifactName' -Value $ArtifactName -Pattern $script:ArtifactNamePattern
    if ($ArtifactName -match '(?i)\.age$') { throw 'ArtifactName must not include the .age suffix.' }
    Assert-ReleaseArtifactPlainValue -Name 'Repository' -Value $Repository -Pattern $script:RepositoryPattern
    Assert-ReleaseArtifactPlainValue -Name 'ReleaseCommit' -Value $ReleaseCommit -Pattern $script:ReleaseCommitPattern
    Assert-ReleaseArtifactPlainValue -Name 'RunId' -Value $RunId -Pattern $script:PositiveIntegerPattern
    Assert-ReleaseArtifactPlainValue -Name 'RunAttempt' -Value $RunAttempt -Pattern $script:PositiveIntegerPattern
    $plaintext = Assert-ReleaseArtifactNoReparsePath -Path $PlaintextRoot
    if (-not (Test-Path -LiteralPath $plaintext -PathType Container)) { throw 'PlaintextRoot must identify a directory.' }
    $output = [System.IO.Path]::GetFullPath($OutputDirectory)
    Assert-ReleaseArtifactNoReparsePath -Path $output -AllowMissingLeaf | Out-Null
    $plainPrefix = $plaintext.TrimEnd([char[]]@('\', '/')) + [System.IO.Path]::DirectorySeparatorChar
    if ($output.StartsWith($plainPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or $output -ceq $plaintext) {
        throw 'OutputDirectory must be outside PlaintextRoot.'
    }
    if (Test-Path -LiteralPath $output) { throw 'OutputDirectory must not already exist.' }
    $tempParent = Assert-ReleaseArtifactNoReparsePath -Path $TemporaryDirectory
    if (-not (Test-Path -LiteralPath $tempParent -PathType Container)) { throw 'TemporaryDirectory must identify a directory.' }
    $tempRoot = Join-Path $tempParent ("defense-tracker-age-protect-" + [guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($tempRoot) | Out-Null
    [System.IO.Directory]::CreateDirectory($output) | Out-Null
    $archivePath = Join-Path $tempRoot 'candidate.zip'
    $ciphertextName = "$ArtifactName.age"
    $ciphertextPath = Join-Path $output $ciphertextName
    $requestPath = Join-Path $output $script:RequestFileName
    $receiptPath = Join-Path $output $script:ReceiptFileName
    $completed = $false
    try {
        New-ReleaseArtifactArchive -PlaintextRoot $plaintext -ArchivePath $archivePath
        $request = [ordered]@{
            artifact_name = $ArtifactName
            recipient_file_sha256 = $recipient.Sha256
            release_commit = $ReleaseCommit
            repository = $Repository
            run_attempt = $RunAttempt
            run_id = $RunId
            schema = $script:RequestSchema
        }
        Write-ReleaseArtifactCanonicalJson -Value $request -Path $requestPath
        $nativeOutput = & $age '--encrypt' '--recipients-file' $recipient.Path '--output' $ciphertextPath $archivePath 2>&1
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $ciphertextPath -PathType Leaf)) {
            throw 'age encryption failed.'
        }
        $ciphertextInfo = Get-Item -LiteralPath $ciphertextPath
        $archiveInfo = Get-Item -LiteralPath $archivePath
        if ($ciphertextInfo.Length -le 0 -or $archiveInfo.Length -le 0) { throw 'age produced an empty transport file.' }
        $receipt = [ordered]@{
            ciphertext_file = $ciphertextName
            ciphertext_sha256 = Get-ReleaseArtifactSha256 -Path $ciphertextPath
            ciphertext_size = $ciphertextInfo.Length.ToString([System.Globalization.CultureInfo]::InvariantCulture)
            plaintext_archive_sha256 = Get-ReleaseArtifactSha256 -Path $archivePath
            plaintext_archive_size = $archiveInfo.Length.ToString([System.Globalization.CultureInfo]::InvariantCulture)
            request_file = $script:RequestFileName
            request_sha256 = Get-ReleaseArtifactSha256 -Path $requestPath
            schema = $script:ReceiptSchema
        }
        Write-ReleaseArtifactCanonicalJson -Value $receipt -Path $receiptPath
        $layout = Assert-ReleaseArtifactEnvelopeLayout -EnvelopeDirectory $output
        Get-ReleaseArtifactValidatedRequest -Path $layout.Request | Out-Null
        Get-ReleaseArtifactValidatedReceipt -Path $layout.Receipt | Out-Null
        $completed = $true
    } finally {
        $nativeOutput = $null
        if (Test-Path -LiteralPath $tempRoot) { [System.IO.Directory]::Delete($tempRoot, $true) }
        if (-not $completed -and (Test-Path -LiteralPath $output)) { [System.IO.Directory]::Delete($output, $true) }
    }
}

function Unprotect-ReleaseArtifact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$AgeExecutable,
        [Parameter(Mandatory = $true)][string]$ExpectedAgeExecutableSha256,
        [Parameter(Mandatory = $true)][string]$EnvelopeDirectory,
        [Parameter(Mandatory = $true)][string]$IdentityFile,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [string]$ExpectedRepository = '',
        [string]$ExpectedReleaseCommit = '',
        [string]$ExpectedRunId = '',
        [string]$ExpectedRunAttempt = '',
        [switch]$RemoveIdentityFile,
        [string]$TemporaryDirectory = $(if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { [System.IO.Path]::GetTempPath() } else { $env:RUNNER_TEMP })
    )
    $identityPath = Assert-ReleaseArtifactNoReparsePath -Path $IdentityFile
    $removeIdentity = $RemoveIdentityFile.IsPresent
    try {
        $age = Assert-ReleaseArtifactExecutable -Path $AgeExecutable -ExpectedSha256 $ExpectedAgeExecutableSha256
        $identity = Read-ReleaseArtifactSingleLineKey -Path $identityPath -Name 'IdentityFile' -Pattern $script:IdentityPattern
        $layout = Assert-ReleaseArtifactEnvelopeLayout -EnvelopeDirectory $EnvelopeDirectory
        $request = Get-ReleaseArtifactValidatedRequest -Path $layout.Request
        $receipt = Get-ReleaseArtifactValidatedReceipt -Path $layout.Receipt
        if ($receipt.ciphertext_file -cne [System.IO.Path]::GetFileName($layout.Ciphertext) -or
            $receipt.ciphertext_file -cne "$($request.artifact_name).age") {
            throw 'Transport request, receipt, and ciphertext filename do not agree.'
        }
        if ((Get-ReleaseArtifactSha256 -Path $layout.Request) -cne $receipt.request_sha256) {
            throw 'Transport request SHA-256 mismatch.'
        }
        $ciphertextInfo = Get-Item -LiteralPath $layout.Ciphertext
        if ($ciphertextInfo.Length.ToString([System.Globalization.CultureInfo]::InvariantCulture) -cne $receipt.ciphertext_size -or
            (Get-ReleaseArtifactSha256 -Path $layout.Ciphertext) -cne $receipt.ciphertext_sha256) {
            throw 'Transport ciphertext hash or size mismatch.'
        }
        foreach ($expectation in @(
            @('ExpectedRepository', $ExpectedRepository, $request.repository, $script:RepositoryPattern),
            @('ExpectedReleaseCommit', $ExpectedReleaseCommit, $request.release_commit, $script:ReleaseCommitPattern),
            @('ExpectedRunId', $ExpectedRunId, $request.run_id, $script:PositiveIntegerPattern),
            @('ExpectedRunAttempt', $ExpectedRunAttempt, $request.run_attempt, $script:PositiveIntegerPattern)
        )) {
            if (-not [string]::IsNullOrWhiteSpace([string]$expectation[1])) {
                Assert-ReleaseArtifactPlainValue -Name ([string]$expectation[0]) -Value ([string]$expectation[1]) -Pattern ([string]$expectation[3])
                if ([string]$expectation[1] -cne [string]$expectation[2]) {
                    throw "$($expectation[0]) does not match the transport request."
                }
            }
        }
        $output = [System.IO.Path]::GetFullPath($OutputDirectory)
        Assert-ReleaseArtifactNoReparsePath -Path $output -AllowMissingLeaf | Out-Null
        if (Test-Path -LiteralPath $output) { throw 'OutputDirectory must not already exist.' }
        $tempParent = Assert-ReleaseArtifactNoReparsePath -Path $TemporaryDirectory
        if (-not (Test-Path -LiteralPath $tempParent -PathType Container)) { throw 'TemporaryDirectory must identify a directory.' }
        $tempRoot = Join-Path $tempParent ("defense-tracker-age-unprotect-" + [guid]::NewGuid().ToString('N'))
        [System.IO.Directory]::CreateDirectory($tempRoot) | Out-Null
        $archivePath = Join-Path $tempRoot 'candidate.zip'
        try {
            $nativeOutput = & $age '--decrypt' '--identity' $identity.Path '--output' $archivePath $layout.Ciphertext 2>&1
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
                throw 'age decryption failed.'
            }
            $archiveInfo = Get-Item -LiteralPath $archivePath
            if ($archiveInfo.Length.ToString([System.Globalization.CultureInfo]::InvariantCulture) -cne $receipt.plaintext_archive_size -or
                (Get-ReleaseArtifactSha256 -Path $archivePath) -cne $receipt.plaintext_archive_sha256) {
                throw 'Decrypted plaintext archive hash or size mismatch.'
            }
            Expand-ReleaseArtifactArchiveSafely -ArchivePath $archivePath -OutputDirectory $output
        } finally {
            $nativeOutput = $null
            if (Test-Path -LiteralPath $tempRoot) { [System.IO.Directory]::Delete($tempRoot, $true) }
        }
    } finally {
        if ($removeIdentity -and (Test-Path -LiteralPath $identityPath -PathType Leaf)) {
            [System.IO.File]::Delete($identityPath)
        }
    }
}

Export-ModuleMember -Function Protect-ReleaseArtifact, Unprotect-ReleaseArtifact
