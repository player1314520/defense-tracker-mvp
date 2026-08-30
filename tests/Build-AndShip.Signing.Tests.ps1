$repoRoot = Split-Path -Parent $PSScriptRoot
$buildScriptPath = Join-Path $repoRoot 'scripts\Build-AndShip.ps1'
. (Join-Path $repoRoot 'scripts\ReleaseCertificatePolicy.ps1')

function New-InMemoryCodeSigningCertificate {
    param([Parameter(Mandatory = $true)][string]$Subject)

    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $Subject,
        $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $oids = New-Object System.Security.Cryptography.OidCollection
    $null = $oids.Add((New-Object System.Security.Cryptography.Oid('1.3.6.1.5.5.7.3.3')))
    $request.CertificateExtensions.Add(
        (New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension(
            $oids,
            $true
        ))
    )
    return [ordered]@{
        certificate = $request.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddMinutes(-1),
            [DateTimeOffset]::UtcNow.AddHours(1)
        )
        key = $rsa
    }
}

function Invoke-SimulatedDigiCertSignAfterFileGate {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)]$Policy
    )
    $null = Assert-DigiCertCertificateFilePolicy `
        -Path $Path -ExpectedSha256 $ExpectedSha256 -Policy $Policy
    $script:signCommandCount++
}

function Assert-ThrowsBeforeSignCommand {
    param([Parameter(Mandatory = $true)][scriptblock]$Operation)

    $threw = $false
    try {
        & $Operation
    } catch {
        $threw = $true
    }
    if (-not $threw) { throw 'Expected the certificate gate to fail closed.' }
    if ($script:signCommandCount -ne 0) {
        throw 'A simulated sign command ran after a certificate-gate failure.'
    }
}

Describe 'Build-And-Ship Stage A signing identity gate' {
    BeforeAll {
        $script:subject = 'CN=DefenseTracker Publisher, O=DefenseTracker Community'
        $script:issuer = 'CN=Trusted Issuer, O=Trusted CA'
        $script:rootHash = ('a' * 64)
        $script:primary = New-InMemoryCodeSigningCertificate $script:subject
        $script:replacement = New-InMemoryCodeSigningCertificate $script:subject
        $script:primaryPath = Join-Path $TestDrive 'primary-signing-certificate.cer'
        $script:replacementPath = Join-Path $TestDrive 'replacement-signing-certificate.cer'
        [System.IO.File]::WriteAllBytes(
            $script:primaryPath,
            $script:primary.certificate.RawData
        )
        [System.IO.File]::WriteAllBytes(
            $script:replacementPath,
            $script:replacement.certificate.RawData
        )
        $script:primaryHash = (Get-FileHash -LiteralPath $script:primaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $script:replacementHash = (Get-FileHash -LiteralPath $script:replacementPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $script:normalizedSubject = ConvertTo-NormalizedX500Name `
            $script:primary.certificate.SubjectName
        $script:policy = Get-ReleaseCertificatePolicy `
            -ExpectedSignerSubjects $script:normalizedSubject `
            -ExpectedSignerSpkiSha256 (
                Get-CertificateSpkiSha256 $script:primary.certificate
            ) `
            -ExpectedSignerIssuers $script:issuer `
            -ExpectedSignerRootSha256 $script:rootHash
    }

    AfterAll {
        $script:primary.certificate.Dispose()
        $script:primary.key.Dispose()
        $script:replacement.certificate.Dispose()
        $script:replacement.key.Dispose()
    }

    BeforeEach {
        $script:signCommandCount = 0
        $script:chainIdentity = [ordered]@{
            issuer_subject = ConvertTo-NormalizedX500Name $script:issuer
            root_sha256 = $script:rootHash
        }
        Mock Assert-TrustedCertificateChain { return $script:chainIdentity }
    }

    It 'places full policy and DigiCert file validation before the first sign command' {
        $source = [System.IO.File]::ReadAllText($buildScriptPath)
        $policy = $source.IndexOf('$certificatePolicy = Get-ReleaseCertificatePolicy')
        $certificateFile = $source.IndexOf(
            '$digicertCertificateIdentity = Assert-DigiCertCertificateFilePolicy'
        )
        $sign = $source.IndexOf('$signatureEvidence = Invoke-SignAndVerify $stagedExe')
        if ($policy -lt 0 -or $certificateFile -lt 0 -or $sign -lt 0 -or
            -not ($policy -lt $certificateFile -and $certificateFile -lt $sign)) {
            throw 'Stage A certificate policy/file gates do not precede the first sign command.'
        }
    }

    It 'rejects the same Subject with a different SPKI before a sign command' {
        Assert-ThrowsBeforeSignCommand {
            Invoke-SimulatedDigiCertSignAfterFileGate `
                $script:replacementPath $script:replacementHash $script:policy
        }
    }

    It 'rejects a different issuer before a sign command' {
        $script:chainIdentity.issuer_subject = ConvertTo-NormalizedX500Name `
            'CN=Unexpected Issuer, O=Unexpected CA'
        Assert-ThrowsBeforeSignCommand {
            Invoke-SimulatedDigiCertSignAfterFileGate `
                $script:primaryPath $script:primaryHash $script:policy
        }
    }

    It 'rejects a different root before a sign command' {
        $script:chainIdentity.root_sha256 = ('b' * 64)
        Assert-ThrowsBeforeSignCommand {
            Invoke-SimulatedDigiCertSignAfterFileGate `
                $script:primaryPath $script:primaryHash $script:policy
        }
    }

    It 'rejects a wrong DigiCert certificate-file hash before a sign command' {
        $path = Join-Path $TestDrive 'signing-certificate.crt'
        [System.IO.File]::WriteAllBytes($path, [byte[]](1, 2, 3, 4))
        Assert-ThrowsBeforeSignCommand {
            Invoke-SimulatedDigiCertSignAfterFileGate `
                $path ('0' * 64) $script:policy
        }
    }
}
