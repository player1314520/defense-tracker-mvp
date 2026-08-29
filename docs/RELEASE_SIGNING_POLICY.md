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
   SignTool integration, and provider metadata. Verification binds the
   signature to the expected Publisher and trusted chain; it must not pin a
   rotating leaf-certificate thumbprint.
2. **DigiCert KeyLocker** as the documented fallback, using its protected
   remote-key workflow and the same expected-Publisher and trust-chain checks.

Every executable signature must include a verifiable RFC 3161 trusted
timestamp. Self-signed, test, locally generated, expired, untrusted-chain, or
unexpected-Publisher certificates are prohibited for stable assets.

The expected Publisher must be the separately verified organization legal
name. The repository currently contains no authoritative Publisher value and
must not invent one.

## Source and build binding

Before signing:

- the requested release SHA must equal the fetched protected `origin/main`
  SHA and the checkout must be clean;
- all required CI checks and public-tree/history scans must pass for that exact
  SHA;
- the protected application-signing environment must supply SHA-256-pinned
  compliance evidence and a valid Ed25519 signature from a reviewer whose
  public key and allowed Publisher are registered in the reviewed source tree;
- that signed decision must bind the exact commit, source tree, Publisher,
  dependency locks, installed package inventory, third-party notices, and the
  path, size, SHA-256, SPDX license, and copyright statement of every unsigned
  onedir component; absence or mismatch stops before the first signature;
- the build uses a fresh isolated, fixed Windows toolchain with hash-locked
  dependencies and no secrets or user material in its inputs;
- the source tree is rechecked after build to detect mutation or time-of-check
  to time-of-use drift; and
- candidate artifacts remain private until all staging and production gates
  succeed.

The Windows candidate is deliberately split across two protected ephemeral
environments. Stage A signs the reviewed onedir executable, builds but does not
sign the installer, extracts its complete payload, and retains an attested
review bundle. A second reviewer must approve that exact request with a
different Ed25519 key. Stage B downloads only that exact run-bound bundle,
revalidates every file and the independent approval, signs a copy of the
installer, and proves that only Authenticode checksum/security-directory/
certificate-table bytes changed. It then re-extracts and compares the complete
payload before smoke, malware, portable, SBOM, and final six-asset checks. No
single-stage path may produce a signed installer or stable assets.

That two-stage design is not currently sufficient to authorize credential use.
The candidate workflow therefore starts with a tokenless GitHub-hosted gate
that emits a machine-readable `SIGNING_ISOLATION_NOT_PROVISIONED` blocker and
exits non-zero. Every source-verification or signing job depends on that failed
gate, so neither a signing environment, OIDC login, secret, nor self-hosted
runner can be reached by a manual dispatch. The blocker may be replaced only by
a separately reviewed change after all of these roles exist:

1. a credentialless builder/scanner and approval controller that emits the
   approved artifact hashes;
2. a minimal signing runner that accepts only those approved bytes, verifies
   their hashes, signs them, and never executes a candidate; and
3. a credentialless or least-privileged, restricted-egress, single-use VM that
   performs post-signature smoke tests, followed by controller-signed runner
   deregistration and VM-destruction receipts.

Those roles must not share a runner image, long-lived workspace, credential, or
controller identity. Missing teardown receipts fail the candidate run closed.

## Required verification evidence

The schema-2 release manifest records:

- semantic and Windows file versions, release tag, final release commit, and
  original baseline commit;
- every asset's name, size, and SHA-256;
- signature provider, expected Publisher, certificate chain result, RFC 3161
  timestamp, and verification time;
- separate application and installer review identities, signed evidence,
  reviewer-registry hashes, Authenticode-neutral digests, and pre/post installer
  payload bindings;
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
unavailable or fails, the workflow stops before a public stable tag/Release is
created.

## Current blocking state

No repository document proves that Microsoft Artifact Signing Public Trust is
approved, that DigiCert KeyLocker is provisioned, or that the final legal
Publisher is verified. The tracked `release/compliance-reviewers.json` and
`release/installer-reviewers.json` registries are also deliberately `inactive`
and contain no reviewer key. Activating either requires a dedicated
governance/legal-review change that records the verified reviewer organization,
Ed25519 public-key fingerprint, and allowed Publisher. The two active reviews
must use distinct public keys; an environment-variable edit cannot activate a
reviewer or bypass that separation. Until those conditions are satisfied, the
stable Windows release is blocked, and signed candidates are also blocked. A
self-signed substitute is not allowed. The explicit isolation blocker described
above is also active; a failed candidate run produces no releasable artifact,
and the stable workflow accepts only a successful run of this exact candidate
workflow before attempting its exact artifact download.

## Honest boundaries

- Authenticode proves the publisher identity asserted by a trusted certificate
  and the integrity of signed bytes; it does not prove software safety.
- RFC 3161 timestamps preserve signature timing evidence but do not make a
  compromised build trustworthy.
- GitHub attestations describe build provenance; they do not replace source
  review, malware scanning, deployment acceptance, or key protection.
- A new publisher can still trigger Microsoft SmartScreen warnings until
  reputation develops.
