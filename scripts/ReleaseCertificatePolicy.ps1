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

function Assert-ExactJsonProperties {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Description
    )

    if ($null -eq $Value -or $Value -isnot [psobject]) {
        throw "$Description must be a JSON object."
    }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    if (($actual -join "`n") -cne ($wanted -join "`n")) {
        throw "$Description has missing or unexpected fields."
    }
}

function ConvertTo-ReleasePolicyText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Description,
        [ValidateRange(1, 512)][int]$MaximumLength = 200
    )

    if ($Value -isnot [string]) { throw "$Description must be a string." }
    $text = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($text) -or $text.Length -gt $MaximumLength -or
        $text.Contains("`r") -or $text.Contains("`n") -or $text.Contains([char]0)) {
        throw "$Description is missing or malformed."
    }
    return $text
}

function ConvertTo-ReleasePolicyList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Description,
        [ValidateRange(1, 4)][int]$MaximumCount = 4
    )

    if ($null -eq $Value -or $Value -is [string]) {
        throw "$Description must be a JSON array."
    }
    $entries = @($Value)
    if ($entries.Count -lt 1 -or $entries.Count -gt $MaximumCount) {
        throw "$Description must contain between one and $MaximumCount entries."
    }
    $result = New-Object System.Collections.Generic.List[string]
    foreach ($entry in $entries) {
        $normalized = ConvertTo-ReleasePolicyText $entry $Description
        if ($result.Contains($normalized)) { throw "$Description contains a duplicate entry." }
        $result.Add($normalized)
    }
    return $result.ToArray()
}

function ConvertTo-ReleasePolicyNames {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Description,
        [switch]$RequirePublisherRdns
    )

    $result = @(
        ConvertTo-ReleasePolicyList $Value $Description |
            ForEach-Object {
                $name = ConvertTo-NormalizedX500Name $_
                if ($RequirePublisherRdns -and
                    ($name -cnotmatch '(?:^|,\s*)CN=' -or $name -cnotmatch '(?:^|,\s*)O=')) {
                    throw "$Description must include both CN and organization RDNs."
                }
                $name
            }
    )
    if (@($result | Sort-Object -Unique).Count -ne $result.Count) {
        throw "$Description contains a duplicate normalized X.500 name."
    }
    return $result
}

function ConvertTo-ReleasePolicyHashes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Description
    )

    return @(
        ConvertTo-ReleasePolicyList $Value $Description |
            ForEach-Object {
                $hash = $_.ToLowerInvariant()
                if ($hash -cnotmatch '^[0-9a-f]{64}$') { throw "$Description contains a malformed SHA-256." }
                $hash
            }
    )
}

function Assert-ReleasePolicyPinCardinality {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][int]$SubjectCount,
        [Parameter(Mandatory = $true)][int]$IssuerCount,
        [Parameter(Mandatory = $true)][int]$RootCount
    )

    foreach ($count in @($IssuerCount, $RootCount)) {
        if ($count -ne 1 -and $count -ne $SubjectCount) {
            throw 'Issuer/root allowlists must contain one shared pin or one ordered pin per signer.'
        }
    }
}

function ConvertFrom-ReleasePolicyUtf8Json {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Description
    )

    try {
        $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
        $text = $utf8.GetString([byte[]]$Bytes)
        if ($text.Length -gt 0 -and $text[0] -eq [char]0xfeff) {
            throw 'UTF-8 BOM is not allowed.'
        }
        return (ConvertFrom-Json -InputObject $text -ErrorAction Stop)
    } catch {
        throw "$Description is not valid UTF-8 JSON."
    }
}

function Get-ReleasePublisherPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]
        [ValidateSet('AzureArtifactSigning', 'DigiCertKeyLocker')]
        [string]$SigningProvider,
        [string]$AzureMetadataPath,
        [string]$DigiCertSmHost,
        [string]$DigiCertKeyAlias
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw 'Committed Publisher policy is missing.'
    }
    $file = Get-Item -LiteralPath $fullPath
    if ($file.Length -lt 2 -or $file.Length -gt 1048576) {
        throw 'Committed Publisher policy size is invalid.'
    }
    $policyBytes = [System.IO.File]::ReadAllBytes($fullPath)
    $document = ConvertFrom-ReleasePolicyUtf8Json $policyBytes 'Committed Publisher policy'
    Assert-ExactJsonProperties $document @(
        '$schema','schema_version','status','publisher','active_provider','providers'
    ) 'Publisher policy'
    if ([string]$document.'$schema' -cne './publisher-policy.schema.json' -or
        [int]$document.schema_version -ne 1) {
        throw 'Publisher policy schema identity is unsupported.'
    }
    Assert-ExactJsonProperties $document.providers @(
        'AzureArtifactSigning','DigiCertKeyLocker'
    ) 'Publisher provider collection'
    $azureDocument = $document.providers.AzureArtifactSigning
    $digicertDocument = $document.providers.DigiCertKeyLocker
    Assert-ExactJsonProperties $azureDocument @(
        'status','endpoint','account_name','certificate_profile_name',
        'expected_subjects','expected_issuers','expected_root_sha256',
        'durable_identity_eku','public_trust_eku','code_signing_eku',
        'forbidden_test_eku','leaf_spki_policy'
    ) 'Azure Artifact Signing policy'
    Assert-ExactJsonProperties $digicertDocument @(
        'status','sm_host','key_alias','certificate_file_sha256',
        'expected_subjects','expected_spki_sha256',
        'expected_issuers','expected_root_sha256','code_signing_eku','leaf_spki_policy'
    ) 'DigiCert KeyLocker policy'
    if ([string]$azureDocument.public_trust_eku -cne '1.3.6.1.4.1.311.97.1.0' -or
        [string]$azureDocument.code_signing_eku -cne '1.3.6.1.5.5.7.3.3' -or
        [string]$azureDocument.forbidden_test_eku -cne '1.3.6.1.4.1.311.10.3.13' -or
        [string]$azureDocument.leaf_spki_policy -cne 'record-only' -or
        [string]$digicertDocument.code_signing_eku -cne '1.3.6.1.5.5.7.3.3' -or
        [string]$digicertDocument.leaf_spki_policy -cne 'required-pin') {
        throw 'Publisher policy changes a fixed provider trust rule.'
    }

    if ([string]$document.status -ceq 'pending') {
        if ($null -ne $document.publisher -or $null -ne $document.active_provider -or
            [string]$azureDocument.status -cne 'pending' -or
            [string]$digicertDocument.status -cne 'pending' -or
            $null -ne $azureDocument.endpoint -or $null -ne $azureDocument.account_name -or
            $null -ne $azureDocument.certificate_profile_name -or
            @($azureDocument.expected_subjects).Count -ne 0 -or
            @($azureDocument.expected_issuers).Count -ne 0 -or
            @($azureDocument.expected_root_sha256).Count -ne 0 -or
            $null -ne $azureDocument.durable_identity_eku -or
            $null -ne $digicertDocument.sm_host -or
            $null -ne $digicertDocument.key_alias -or
            $null -ne $digicertDocument.certificate_file_sha256 -or
            @($digicertDocument.expected_subjects).Count -ne 0 -or
            @($digicertDocument.expected_spki_sha256).Count -ne 0 -or
            @($digicertDocument.expected_issuers).Count -ne 0 -or
            @($digicertDocument.expected_root_sha256).Count -ne 0) {
            throw 'Pending Publisher policy contains unapproved identity values.'
        }
        throw 'Publisher policy is pending verified legal and signing-provider identity.'
    }
    if ([string]$document.status -cne 'approved') {
        throw 'Publisher policy status is unsupported.'
    }
    $publisher = ConvertTo-ReleasePolicyText $document.publisher 'Publisher legal name'
    if ([string]$document.active_provider -cne $SigningProvider) {
        throw 'Requested signing provider differs from the committed active provider.'
    }
    $providerDocument = $document.providers.$SigningProvider
    if ([string]$providerDocument.status -cne 'approved') {
        throw 'The committed active provider is not approved.'
    }
    $subjects = @(ConvertTo-ReleasePolicyNames $providerDocument.expected_subjects `
        'Expected signer Subjects' -RequirePublisherRdns)
    $issuers = @(ConvertTo-ReleasePolicyNames $providerDocument.expected_issuers `
        'Expected signer Issuers')
    $rootHashes = @(ConvertTo-ReleasePolicyHashes $providerDocument.expected_root_sha256 `
        'Expected signer root SHA-256')
    Assert-ReleasePolicyPinCardinality $subjects.Count $issuers.Count $rootHashes.Count

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $policySha256 = ([System.BitConverter]::ToString($sha256.ComputeHash($policyBytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
    $result = [ordered]@{
        schema_version = 1
        policy_path = $fullPath
        policy_sha256 = $policySha256
        provider = $SigningProvider
        publisher = $publisher
        subjects = $subjects
        issuers = $issuers
        root_sha256 = $rootHashes
        required_eku_oids = @([string]$providerDocument.code_signing_eku)
        forbidden_eku_oids = @()
        leaf_spki_policy = [string]$providerDocument.leaf_spki_policy
        spki_sha256 = @()
    }

    if ($SigningProvider -eq 'AzureArtifactSigning') {
        $endpointText = ConvertTo-ReleasePolicyText $azureDocument.endpoint `
            'Azure Artifact Signing endpoint' 512
        try { $endpoint = [Uri]$endpointText } catch { throw 'Azure Artifact Signing endpoint is malformed.' }
        if (-not $endpoint.IsAbsoluteUri -or $endpoint.Scheme -cne 'https' -or
            -not [string]::IsNullOrEmpty($endpoint.UserInfo) -or
            -not [string]::IsNullOrEmpty($endpoint.Query) -or
            -not [string]::IsNullOrEmpty($endpoint.Fragment) -or
            $endpoint.AbsoluteUri -cne $endpointText) {
            throw 'Azure Artifact Signing endpoint must be a canonical credential-free HTTPS URI.'
        }
        $account = ConvertTo-ReleasePolicyText $azureDocument.account_name `
            'Azure Artifact Signing account name'
        $profile = ConvertTo-ReleasePolicyText $azureDocument.certificate_profile_name `
            'Azure Artifact Signing certificate profile name'
        foreach ($pair in @(@($account, 'account'), @($profile, 'certificate profile'))) {
            if ([string]$pair[0] -cnotmatch '^[A-Za-z][A-Za-z0-9-]{2,99}$' -or
                [string]$pair[0] -match '--' -or [string]$pair[0] -match '-$') {
                throw "Azure Artifact Signing $($pair[1]) name is malformed."
            }
        }
        $durableEku = ConvertTo-ReleasePolicyText $azureDocument.durable_identity_eku `
            'Azure Artifact Signing durable identity EKU'
        if ($durableEku -cnotmatch '^1\.3\.6\.1\.4\.1\.311\.97\.(?:[0-9]+\.)+[0-9]+$' -or
            $durableEku -ceq '1.3.6.1.4.1.311.97.1.0' -or
            $durableEku -match '^1\.3\.6\.1\.4\.1\.311\.97\.1\.(?:3|4)\.1(?:\.|$)') {
            throw 'Azure Artifact Signing durable identity EKU is not a Public Trust subscriber identity.'
        }
        $result.required_eku_oids = @(
            [string]$azureDocument.code_signing_eku,
            [string]$azureDocument.public_trust_eku,
            $durableEku
        )
        $result.forbidden_eku_oids = @([string]$azureDocument.forbidden_test_eku)
        $result.azure = [ordered]@{
            endpoint = $endpointText
            account_name = $account
            certificate_profile_name = $profile
            durable_identity_eku = $durableEku
            public_trust_eku = [string]$azureDocument.public_trust_eku
            metadata_sha256 = $null
        }
        if (-not [string]::IsNullOrWhiteSpace($AzureMetadataPath)) {
            $metadataFull = [System.IO.Path]::GetFullPath($AzureMetadataPath)
            if (-not (Test-Path -LiteralPath $metadataFull -PathType Leaf) -or
                (Get-Item -LiteralPath $metadataFull).Length -gt 65536) {
                throw 'Azure Artifact Signing metadata file is missing or oversized.'
            }
            $metadataBytes = [System.IO.File]::ReadAllBytes($metadataFull)
            $metadata = ConvertFrom-ReleasePolicyUtf8Json $metadataBytes `
                'Azure Artifact Signing metadata'
            Assert-ExactJsonProperties $metadata @(
                'Endpoint','CodeSigningAccountName','CertificateProfileName','CorrelationId'
            ) 'Azure Artifact Signing metadata'
            $correlation = ConvertTo-ReleasePolicyText $metadata.CorrelationId `
                'Azure Artifact Signing CorrelationId' 512
            if ([string]$metadata.Endpoint -cne $endpointText -or
                [string]$metadata.CodeSigningAccountName -cne $account -or
                [string]$metadata.CertificateProfileName -cne $profile) {
                throw 'Azure Artifact Signing metadata differs from the committed account/profile/endpoint policy.'
            }
            $metadataHasher = [System.Security.Cryptography.SHA256]::Create()
            try {
                $metadataSha256 = ([System.BitConverter]::ToString(
                    $metadataHasher.ComputeHash($metadataBytes)
                )).Replace('-', '').ToLowerInvariant()
            } finally {
                $metadataHasher.Dispose()
            }
            $result.azure.metadata_sha256 = $metadataSha256
            $result.azure.correlation_id = $correlation
        }
    } else {
        $smHostText = ConvertTo-ReleasePolicyText $digicertDocument.sm_host `
            'DigiCert Software Trust Manager host' 512
        try { $smHost = [Uri]$smHostText } catch { throw 'DigiCert Software Trust Manager host is malformed.' }
        if (-not $smHost.IsAbsoluteUri -or $smHost.Scheme -cne 'https' -or
            -not [string]::IsNullOrEmpty($smHost.UserInfo) -or
            -not [string]::IsNullOrEmpty($smHost.Query) -or
            -not [string]::IsNullOrEmpty($smHost.Fragment) -or
            $smHost.AbsoluteUri -cne $smHostText) {
            throw 'DigiCert Software Trust Manager host must be a canonical credential-free HTTPS URI.'
        }
        $keyAlias = ConvertTo-ReleasePolicyText $digicertDocument.key_alias `
            'DigiCert KeyLocker key alias'
        if (-not [string]::IsNullOrWhiteSpace($DigiCertSmHost) -and
            $DigiCertSmHost -cne $smHostText) {
            throw 'DigiCert runtime SM host differs from the committed Publisher policy.'
        }
        if (-not [string]::IsNullOrWhiteSpace($DigiCertKeyAlias) -and
            $DigiCertKeyAlias -cne $keyAlias) {
            throw 'DigiCert runtime key alias differs from the committed Publisher policy.'
        }
        $spkiHashes = @(ConvertTo-ReleasePolicyHashes $digicertDocument.expected_spki_sha256 `
            'Expected signer SPKI SHA-256')
        if ($subjects.Count -ne $spkiHashes.Count) {
            throw 'DigiCert signer Subject and SPKI allowlists must have the same ordered count.'
        }
        $certificateFileSha256 = ConvertTo-ReleasePolicyText `
            $digicertDocument.certificate_file_sha256 'DigiCert certificate-file SHA-256'
        if ($certificateFileSha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'DigiCert certificate-file SHA-256 is malformed.'
        }
        $result.spki_sha256 = $spkiHashes
        $result.digicert = [ordered]@{
            sm_host = $smHostText
            key_alias = $keyAlias
            certificate_file_sha256 = $certificateFileSha256
        }
    }
    return $result
}

function Get-ReleasePublisherPolicyEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Policy)

    if ([string]$Policy.policy_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Policy.leaf_spki_policy -notin @('record-only','required-pin')) {
        throw 'Loaded Publisher policy evidence is incomplete.'
    }
    if ([string]$Policy.provider -eq 'AzureArtifactSigning') {
        if ([string]$Policy.azure.metadata_sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'Azure Publisher-policy evidence requires exact metadata provenance.'
        }
        return [ordered]@{
            sha256 = [string]$Policy.policy_sha256
            leaf_spki_policy = 'record-only'
            durable_identity_eku = [string]$Policy.azure.durable_identity_eku
            azure_endpoint = [string]$Policy.azure.endpoint
            azure_account_name = [string]$Policy.azure.account_name
            azure_certificate_profile_name = [string]$Policy.azure.certificate_profile_name
            azure_metadata_sha256 = [string]$Policy.azure.metadata_sha256
            digicert_sm_host = $null
            digicert_key_alias = $null
        }
    }
    if ([string]$Policy.provider -ne 'DigiCertKeyLocker') {
        throw 'Loaded Publisher policy provider is unsupported.'
    }
    return [ordered]@{
        sha256 = [string]$Policy.policy_sha256
        leaf_spki_policy = 'required-pin'
        durable_identity_eku = $null
        azure_endpoint = $null
        azure_account_name = $null
        azure_certificate_profile_name = $null
        azure_metadata_sha256 = $null
        digicert_sm_host = [string]$Policy.digicert.sm_host
        digicert_key_alias = [string]$Policy.digicert.key_alias
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
        provider = 'DigiCertKeyLocker'
        publisher = $null
        leaf_spki_policy = 'required-pin'
        required_eku_oids = @('1.3.6.1.5.5.7.3.3')
        forbidden_eku_oids = @()
        digicert = $null
        subjects = $subjects
        spki_sha256 = $spkiHashes
        issuers = $issuers
        root_sha256 = $rootHashes
    }
}

function Get-CertificateEnhancedKeyUsageOids {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $result = New-Object System.Collections.Generic.List[string]
    foreach ($extension in $Certificate.Extensions) {
        if ($extension -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            foreach ($oid in $extension.EnhancedKeyUsages) {
                if (-not $result.Contains([string]$oid.Value)) { $result.Add([string]$oid.Value) }
            }
        }
    }
    return $result.ToArray()
}

function Test-CodeSigningEku {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    return @(
        Get-CertificateEnhancedKeyUsageOids $Certificate |
            Where-Object { $_ -ceq '1.3.6.1.5.5.7.3.3' }
    ).Count -gt 0
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

    if ([string]$Policy.provider -notin @('AzureArtifactSigning','DigiCertKeyLocker')) {
        throw 'Signer certificate policy provider is unsupported.'
    }
    $subject = ConvertTo-NormalizedX500Name $Certificate.SubjectName
    if (-not [string]::IsNullOrWhiteSpace([string]$Policy.publisher)) {
        $simpleName = $Certificate.GetNameInfo(
            [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
            $false
        )
        if ($simpleName -cne [string]$Policy.publisher) {
            throw 'Signer certificate simple Publisher differs from the committed legal Publisher.'
        }
    }
    $spkiSha256 = Get-CertificateSpkiSha256 $Certificate
    $matchingPolicy = @()
    for ($index = 0; $index -lt $Policy.subjects.Count; $index++) {
        $subjectMatches = $subject -ceq [string]$Policy.subjects[$index]
        if ($Policy.provider -eq 'AzureArtifactSigning') {
            # Artifact Signing rotates short-lived leaf certificates daily. The leaf SPKI is evidence only,
            # never a durable Azure allow decision; the subscriber EKU and service provenance are pinned.
            if ($subjectMatches) { $matchingPolicy += $index }
        } elseif ($subjectMatches -and
            $spkiSha256 -ceq [string]$Policy.spki_sha256[$index]) {
            $matchingPolicy += $index
        }
    }
    if ($matchingPolicy.Count -ne 1) {
        if ($Policy.provider -eq 'AzureArtifactSigning') {
            throw 'Azure signer certificate Subject is outside the protected ordered allowlist.'
        }
        throw 'DigiCert signer certificate Subject/SPKI is outside the protected ordered allowlist.'
    }
    $policyIndex = [int]$matchingPolicy[0]
    $ekuOids = @(Get-CertificateEnhancedKeyUsageOids $Certificate)
    foreach ($requiredOid in @($Policy.required_eku_oids)) {
        if (@($ekuOids | Where-Object { $_ -ceq [string]$requiredOid }).Count -ne 1) {
            if ($Policy.provider -eq 'AzureArtifactSigning' -and
                [string]$requiredOid -ceq [string]$Policy.azure.durable_identity_eku) {
                throw 'Azure Artifact Signing durable identity EKU is missing.'
            }
            throw "Signer certificate lacks required EKU $requiredOid."
        }
    }
    foreach ($forbiddenOid in @($Policy.forbidden_eku_oids)) {
        if (@($ekuOids | Where-Object { $_ -ceq [string]$forbiddenOid }).Count -gt 0) {
            throw "Signer certificate contains forbidden test EKU $forbiddenOid."
        }
    }
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
        provider = [string]$Policy.provider
        policy_index = $policyIndex
        normalized_subject = $subject
        spki_sha256 = $spkiSha256
        leaf_spki_policy = [string]$Policy.leaf_spki_policy
        issuer_subject = [string]$chainIdentity.issuer_subject
        root_sha256 = [string]$chainIdentity.root_sha256
        durable_identity_eku = if ($Policy.provider -eq 'AzureArtifactSigning') {
            [string]$Policy.azure.durable_identity_eku
        } else { $null }
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

    if ([string]$Policy.provider -cne 'DigiCertKeyLocker') {
        throw 'DigiCert certificate file cannot be checked against a non-DigiCert policy.'
    }
    if ($ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Protected DigiCert certificate-file SHA-256 is missing or malformed.'
    }
    if ($null -ne $Policy.digicert -and
        [string]$Policy.digicert.certificate_file_sha256 -cne $ExpectedSha256) {
        throw 'DigiCert certificate-file SHA-256 differs from the committed Publisher policy.'
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
