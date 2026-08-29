#requires -Version 5.1

Set-StrictMode -Version Latest

function ConvertFrom-ReleaseCertificateAllowList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Name,
        [ValidateRange(1, 4)][int]$MaximumCount = 4
    )

    $candidate = $Value.Trim()
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        throw "$Name is missing."
    }
    if ($candidate.StartsWith('[')) {
        if (-not $candidate.EndsWith(']')) {
            throw "$Name must be one value or a JSON array."
        }
        try {
            $parsed = ConvertFrom-Json -InputObject $candidate -ErrorAction Stop
        } catch {
            throw "$Name is not valid JSON."
        }
        $values = @($parsed)
    } else {
        $values = @($candidate)
    }
    if ($values.Count -lt 1 -or $values.Count -gt $MaximumCount) {
        throw "$Name must contain between one and $MaximumCount entries."
    }

    $result = New-Object System.Collections.Generic.List[string]
    foreach ($entry in $values) {
        if ($entry -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$entry)) {
            throw "$Name contains an empty or non-string entry."
        }
        $normalized = ([string]$entry).Trim()
        if ($result.Contains($normalized)) {
            throw "$Name contains a duplicate entry."
        }
        $result.Add($normalized)
    }
    return $result.ToArray()
}

function ConvertTo-NormalizedX500Name {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$DistinguishedName)

    try {
        if ($DistinguishedName -is [System.Security.Cryptography.X509Certificates.X500DistinguishedName]) {
            $name = $DistinguishedName
        } elseif ($DistinguishedName -is [string]) {
            $name = New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName(
                ([string]$DistinguishedName).Trim()
            )
        } else {
            throw 'Unsupported distinguished-name value.'
        }
        $flags = [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseCommas
        $normalized = $name.Decode($flags).Trim()
    } catch {
        throw "Invalid X.500 distinguished name: $($_.Exception.Message)"
    }
    if ([string]::IsNullOrWhiteSpace($normalized) -or
        @($normalized -split ',').Count -lt 2) {
        throw 'A complete normalized certificate Subject/Issuer is required; a CN-only name is rejected.'
    }
    return $normalized
}

function ConvertTo-DerLength {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateRange(0, [int]::MaxValue)][int]$Length)

    if ($Length -lt 128) { return [byte[]]@([byte]$Length) }
    $bytes = New-Object System.Collections.Generic.List[byte]
    $remaining = [uint64]$Length
    while ($remaining -gt 0) {
        $bytes.Insert(0, [byte]($remaining -band 0xff))
        $remaining = $remaining -shr 8
    }
    $prefix = [byte](0x80 -bor $bytes.Count)
    return [byte[]](@($prefix) + @($bytes.ToArray()))
}

function ConvertTo-DerOidSubIdentifier {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][uint64]$Value)

    $bytes = New-Object System.Collections.Generic.List[byte]
    $bytes.Insert(0, [byte]($Value -band 0x7f))
    $remaining = $Value -shr 7
    while ($remaining -gt 0) {
        $bytes.Insert(0, [byte](0x80 -bor ($remaining -band 0x7f)))
        $remaining = $remaining -shr 7
    }
    return $bytes.ToArray()
}

function ConvertTo-DerObjectIdentifier {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Oid)

    if ($Oid -notmatch '^[0-2](?:\.[0-9]+)+$') { throw 'Certificate public-key OID is malformed.' }
    $parts = @($Oid.Split('.') | ForEach-Object { [uint64]::Parse($_) })
    if ($parts.Count -lt 2 -or ($parts[0] -lt 2 -and $parts[1] -gt 39)) {
        throw 'Certificate public-key OID has invalid leading arcs.'
    }
    if ($parts[1] -gt ([uint64]::MaxValue - (40 * $parts[0]))) {
        throw 'Certificate public-key OID is too large.'
    }
    $body = New-Object System.Collections.Generic.List[byte]
    $body.AddRange([byte[]](ConvertTo-DerOidSubIdentifier (40 * $parts[0] + $parts[1])))
    for ($index = 2; $index -lt $parts.Count; $index++) {
        $body.AddRange([byte[]](ConvertTo-DerOidSubIdentifier $parts[$index]))
    }
    return [byte[]](@(0x06) + @(ConvertTo-DerLength $body.Count) + @($body.ToArray()))
}

function New-DerSequence {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Body)
    return [byte[]](@(0x30) + @(ConvertTo-DerLength $Body.Length) + @($Body))
}

function Get-CertificateSpkiSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $exportMethod = $Certificate.PublicKey.GetType().GetMethod(
        'ExportSubjectPublicKeyInfo',
        [Type[]]@()
    )
    if ($null -ne $exportMethod) {
        $spki = [byte[]]$exportMethod.Invoke($Certificate.PublicKey, @())
    } else {
        $oid = ConvertTo-DerObjectIdentifier $Certificate.PublicKey.Oid.Value
        $parameters = [byte[]]$Certificate.PublicKey.EncodedParameters.RawData
        $algorithmIdentifier = New-DerSequence ([byte[]](@($oid) + @($parameters)))
        $keyValue = [byte[]]$Certificate.PublicKey.EncodedKeyValue.RawData
        $bitStringBody = [byte[]](@(0x00) + @($keyValue))
        $bitString = [byte[]](@(0x03) + @(ConvertTo-DerLength $bitStringBody.Length) + @($bitStringBody))
        $spki = New-DerSequence ([byte[]](@($algorithmIdentifier) + @($bitString)))
    }
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha256.ComputeHash($spki))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Get-CertificateSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha256.ComputeHash($Certificate.RawData))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Get-ReleaseCertificatePolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ExpectedSignerSubjects,
        [Parameter(Mandatory = $true)][string]$ExpectedSignerSpkiSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedSignerIssuers,
        [Parameter(Mandatory = $true)][string]$ExpectedSignerRootSha256
    )

    $subjects = @(
        ConvertFrom-ReleaseCertificateAllowList $ExpectedSignerSubjects 'Expected signer Subjects' |
            ForEach-Object {
                $value = ConvertTo-NormalizedX500Name $_
                if ($value -cnotmatch '(?:^|,\s*)CN=' -or $value -cnotmatch '(?:^|,\s*)O=') {
                    throw 'Expected signer Subject must include both CN and organization RDNs.'
                }
                $value
            }
    )
    $spkiHashes = @(
        ConvertFrom-ReleaseCertificateAllowList $ExpectedSignerSpkiSha256 'Expected signer SPKI SHA-256' |
            ForEach-Object {
                $value = $_.ToLowerInvariant()
                if ($value -notmatch '^[0-9a-f]{64}$') { throw 'Expected signer SPKI SHA-256 is malformed.' }
                $value
            }
    )
    $issuers = @(
        ConvertFrom-ReleaseCertificateAllowList $ExpectedSignerIssuers 'Expected signer Issuers' |
            ForEach-Object { ConvertTo-NormalizedX500Name $_ }
    )
    $rootHashes = @(
        ConvertFrom-ReleaseCertificateAllowList $ExpectedSignerRootSha256 'Expected signer root SHA-256' |
            ForEach-Object {
                $value = $_.ToLowerInvariant()
                if ($value -notmatch '^[0-9a-f]{64}$') { throw 'Expected signer root SHA-256 is malformed.' }
                $value
            }
    )
    if ($subjects.Count -ne $spkiHashes.Count) {
        throw 'Signer Subject and SPKI allowlists must have the same number of ordered entries.'
    }
    foreach ($count in @($issuers.Count, $rootHashes.Count)) {
        if ($count -ne 1 -and $count -ne $subjects.Count) {
            throw 'Issuer/root allowlists must contain one shared pin or one ordered pin per signer.'
        }
    }
    return [ordered]@{
        subjects = $subjects
        spki_sha256 = $spkiHashes
        issuers = $issuers
        root_sha256 = $rootHashes
    }
}

function Test-CodeSigningEku {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    foreach ($extension in $Certificate.Extensions) {
        if ($extension -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] -and
            @($extension.EnhancedKeyUsages | Where-Object { $_.Value -ceq '1.3.6.1.5.5.7.3.3' }).Count -gt 0) {
            return $true
        }
    }
    return $false
}

function Assert-TrustedCertificateChain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [switch]$RequireCodeSigningEku
    )

    if ($RequireCodeSigningEku -and -not (Test-CodeSigningEku $Certificate)) {
        throw 'Signer certificate lacks the Code Signing EKU.'
    }
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    try {
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(20)
        if (-not $chain.Build($Certificate)) {
            $statuses = @($chain.ChainStatus | ForEach-Object { $_.Status.ToString() }) -join ','
            throw "Certificate chain validation failed: $statuses"
        }
        if ($chain.ChainElements.Count -lt 2) {
            throw 'Signer certificate chain has no separately identified issuer/root.'
        }
        return [ordered]@{
            issuer_subject = ConvertTo-NormalizedX500Name $chain.ChainElements[1].Certificate.SubjectName
            root_sha256 = Get-CertificateSha256 $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
        }
    } finally {
        $chain.Dispose()
    }
}

function Assert-ReleaseSignerCertificatePolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)]$Policy
    )

    $subject = ConvertTo-NormalizedX500Name $Certificate.SubjectName
    $spkiSha256 = Get-CertificateSpkiSha256 $Certificate
    $matchingPolicy = @()
    for ($index = 0; $index -lt $Policy.subjects.Count; $index++) {
        if ($subject -ceq [string]$Policy.subjects[$index] -and
            $spkiSha256 -ceq [string]$Policy.spki_sha256[$index]) {
            $matchingPolicy += $index
        }
    }
    if ($matchingPolicy.Count -ne 1) {
        throw 'Signer certificate Subject/SPKI is outside the protected ordered allowlist.'
    }
    $policyIndex = [int]$matchingPolicy[0]
    $chainIdentity = Assert-TrustedCertificateChain $Certificate -RequireCodeSigningEku
    $issuerIndex = if ($Policy.issuers.Count -eq 1) { 0 } else { $policyIndex }
    $rootIndex = if ($Policy.root_sha256.Count -eq 1) { 0 } else { $policyIndex }
    if ($chainIdentity.issuer_subject -cne [string]$Policy.issuers[$issuerIndex]) {
        throw 'Signer issuer differs from the protected issuer pin.'
    }
    if ($chainIdentity.root_sha256 -cne [string]$Policy.root_sha256[$rootIndex]) {
        throw 'Signer root certificate differs from the protected root pin.'
    }
    return [ordered]@{
        policy_index = $policyIndex
        normalized_subject = $subject
        spki_sha256 = $spkiSha256
        issuer_subject = [string]$chainIdentity.issuer_subject
        root_sha256 = [string]$chainIdentity.root_sha256
    }
}

function Get-CertificateFromFile {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    try {
        return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$bytes)
    } catch {
        $text = [System.Text.Encoding]::ASCII.GetString($bytes)
        $match = [regex]::Match(
            $text,
            '-----BEGIN CERTIFICATE-----\s*(?<body>[A-Za-z0-9+/=\r\n]+)\s*-----END CERTIFICATE-----'
        )
        if (-not $match.Success) { throw 'DigiCert public certificate file is not DER or PEM X.509.' }
        try {
            $der = [Convert]::FromBase64String(($match.Groups['body'].Value -replace '\s', ''))
            return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$der)
        } catch {
            throw 'DigiCert public certificate file is not a valid X.509 certificate.'
        }
    }
}

function Assert-DigiCertCertificateFilePolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)]$Policy
    )

    if ($ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Protected DigiCert certificate-file SHA-256 is missing or malformed.'
    }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $ExpectedSha256) {
        throw 'DigiCert public certificate file differs from the protected SHA-256.'
    }
    $certificate = Get-CertificateFromFile $Path
    try {
        return Assert-ReleaseSignerCertificatePolicy $certificate $Policy
    } finally {
        $certificate.Dispose()
    }
}
