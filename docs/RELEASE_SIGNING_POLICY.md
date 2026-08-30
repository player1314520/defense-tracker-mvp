# Windows Release Signing and Immutability Policy

## Scope

This policy applies to official stable DefenseTracker Windows releases. It
does not authorize signing, deployment, tagging, or publishing. Those actions
require the exact protected-branch source, trusted signing credentials, and
the release environment's approval gates.

The stable `v9.0.0` assets are:

- `DefenseTracker-Setup-v9.0.0-windows-x64.exe`;
- `DefenseTracker-v9.0.0-windows-x64-portable.zip`;
- `SHA256SUMS.txt`;
- `release-manifest.json`;
- `DefenseTracker-v9.0.0.spdx.json`; and
- `THIRD_PARTY_NOTICES.md`.

The inner PyInstaller executable is not uploaded as a standalone Release
asset; it is signed inside the complete portable package.

## Accepted trust providers

Exactly one of these trusted paths may sign a stable release:

1. **Microsoft Artifact Signing (Public Trust)** through GitHub Actions OIDC,
   SignTool integration, and provider metadata. The committed policy binds the
   endpoint, account, profile, Publisher, Subject, issuer, root, code-signing
   EKU, Public Trust EKU, and durable identity EKU. Short-lived leaf SPKI is
   recorded as evidence only; it is not an allow decision.
2. **DigiCert KeyLocker** as the documented fallback, using its protected
   remote-key workflow. The committed policy additionally pins the canonical
   SM host, key alias, public certificate-file SHA-256, Subject, leaf SPKI,
   issuer, and root.

Every executable signature must include a verifiable RFC 3161 trusted
timestamp. Self-signed, test, locally generated, expired, untrusted-chain, or
unexpected-Publisher certificates are prohibited for stable assets.

The only authoritative trust source is `release/publisher-policy.json` from the
exact protected-main commit plus its SHA-256. Environment variables select a
provisioned runtime provider but cannot define or expand trust. The expected
Publisher must be the separately verified organization legal name. The current
committed policy is deliberately `pending`, with a null Publisher and active
provider, so every stable signing path fails closed instead of inventing one.

## Source and build binding

Before signing:

- the requested release SHA must equal the fetched protected `origin/main`
  SHA and the checkout must be clean;
- all required CI checks and public-tree/history scans must pass for that exact
  SHA;
- an exact SHA-256-pinned public compliance-evidence document must come from a
  separate evidence commit, so it cannot create a self-referential source-tree
  hash;
- the unsigned bytes and canonical signing request must already exist in a
  prior credentialless job/run. Request SHA, encrypted-artifact digest, run
  ID/attempt, source tree, Publisher-policy SHA, dependency locks, installed
  package inventory, third-party notices, and every component's path, size,
  SHA-256, SPDX license, and copyright are checked before the first signature;
- the build uses a fresh isolated, fixed Windows toolchain with hash-locked
  dependencies and no secrets or user material in its inputs;
- the source tree is rechecked after build to detect mutation or time-of-check
  to time-of-use drift; and
- plaintext candidate artifacts remain confidential. Public Actions retention
  contains only `age` ciphertext and sanitized requests/receipts.

The chain uses separate credentialless and signer-only jobs on fresh
GitHub-hosted `windows-2022` VMs. `v9-release-preparation.yml` creates the
unsigned application request and encrypted bundle. `v9-application-signing.yml`
verifies that prior request; `v9-trusted-signing` signs one application PE, then
a credentialless job builds the unsigned installer and emits its request.
`v9-signed-candidate.yml` verifies that second request;
`v9-installer-signing-review` signs one installer PE, then a credentialless
finalizer revalidates both request/receipt pairs, full payloads, smoke, malware,
portable, SBOM, and six-asset gates. No signer job builds, executes, scans, or
packages the candidate.

Environment approval allows a job to start; it cannot prove that the approver
inspected bytes created after approval. Requests therefore predate signer jobs,
and the Environment URL points to their exact prior run. Signing receipts prove
post-signing bytes and provenance, not who clicked Approve. The approvals may
currently be performed by the one maintainer. This is an explicitly disclosed
`single-maintainer-audited` model, not independent human review. A second
maintainer should be added later and `prevent self-review` enabled without
changing the binary evidence contract.

Every signing and stable-publication job uses a new GitHub-hosted VM. Signer-only
jobs do not checkout, setup Python, run repository code, compile installers,
execute candidates, or run Defender. They download only fixed-hash `age`,
SignTool, and the required Azure client. Azure uses GitHub OIDC; DigiCert checks
the committed SM host, key alias, certificate hash, and identity pins before
credential use, then removes temporary files unconditionally. Python, Inno
Setup, 7-Zip, Defender, and their evidence belong only to credentialless jobs.
The final Release job receives no signing identity, although it has the
protected candidate-decryption identity needed to republish previously approved
bytes.

## Required verification evidence

The schema-2 release manifest records:

- semantic and Windows file versions, release tag, final release commit, and
  original baseline commit;
- every asset's name, size, and SHA-256;
- signature provider, expected Publisher, certificate chain result, timestamp
  service URL, timestamper certificate Subject, trusted-timestamp verification
  result, and `timestamp_verified_at_utc` observation time;
- separate application and installer signing-request/receipt hashes, their
  cross-run workflow provenance, Publisher-policy SHA, Authenticode-neutral
  digests, and complete payload bindings;
- PE architecture and VersionInfo verification;
- privacy/secret, QR/account-material, malware, archive, and SBOM results; and
- verifiable GitHub build and SBOM attestation references.

Verification is repeated after downloading the public assets from GitHub.

## Immutable stable releases

All gates must pass before creating the stable tag or Release. The tag points
to the exact accepted commit. After publication:

- the tag must not move or be deleted;
- assets must not be replaced, renamed, or deleted;
- the Release remains stable and immutable; and
- any defect is corrected in a new patch version, such as `v9.0.1`.

If trusted signing, staging, production, checksum, signature, SBOM, build/SBOM
attestation, immutable-release enforcement, or post-download verification is
unavailable or fails, the stable Windows release is blocked and the workflow
stops before a public stable tag/Release is created.

## Current blocking state

The committed Publisher policy is `pending`; no repository document proves that
Microsoft Artifact Signing Public Trust is approved, that DigiCert KeyLocker is
provisioned, or that the final legal Publisher is verified. The full
component-license evidence also has not yet been approved for one exact release
build. Those are real external/legal inputs. Until a real provider, approved
policy, matching identity pins, and complete public compliance evidence exist,
the first signer job, signed candidate, and stable Release fail closed. A
self-signed substitute is not allowed.

## Honest boundaries

- Authenticode proves the publisher identity asserted by a trusted certificate
  and the integrity of signed bytes; it does not prove software safety.
- SignTool verifies the RFC 3161 timestamp and timestamper certificate. The
  manifest records verification time, not the token's actual issuance instant;
  either form of evidence cannot make a compromised build trustworthy.
- GitHub attestations describe build provenance; they do not replace source
  review, malware scanning, deployment acceptance, or key protection.
- Environment approval proves only that a protected job was allowed to start;
  offline request/receipt files cannot prove who clicked Approve or what the
  reviewer inspected. The GitHub audit trail remains necessary.
- Repository readers can download retained Actions artifacts. `age` protects
  candidate plaintext, while names, requests, receipts, hashes, and run metadata
  remain visible. Confidentiality depends on protecting and rotating
  `RELEASE_ARTIFACT_AGE_IDENTITY`.
- One maintainer performing both approvals is auditable but is not separation of
  duties. Repository rules should move to two-person review when another trusted
  maintainer exists.
- A new publisher can still trigger Microsoft SmartScreen warnings until
  reputation develops.
