# Public Release Scope

## Community source

DefenseTracker V9 Community Edition is published under GNU AGPL v3 only
(`AGPL-3.0-only`). The public repository contains reviewable first-party
source, tests, the Portal, Supabase migrations and Edge Functions, and the
isolated `deploy/mvp` deployment surface. Separate third-party materials keep
their upstream licenses.

The presence of source does not mean a stable Windows package or live Portal
has passed the release gates. Only an immutable GitHub Release created from
the exact protected default-branch commit may represent a stable version.

## Included public material

- source required to run the local community edition and V9 Portal;
- automated Python, JavaScript, and Supabase contract tests;
- Supabase migrations and MVP Edge Functions;
- `deploy/mvp` configuration, release, rollback, backup, and restore tooling;
- inert configuration examples and public operational documentation;
- community governance, contribution, security, data, and signing policies;
  and
- required third-party bundles, license texts, notices, and release SBOM.

## Deliberately excluded material

- credentials, `.env` files, tokens, private keys, signing configuration,
  backup identities, real email addresses, databases, and user exports;
- private planning, task, handoff, staging, review, and release evidence;
- screenshots, QR codes, account details, personal paths, raw logs, local tool
  state, or other personally identifiable information;
- private source material, copied articles, paywalled text, internal documents,
  generated reports, and historical selection records; and
- caches, unsigned installers, mutable build environments, and other
  machine-local artifacts.

## Pre-publication gates

### Explicit unsigned desktop MVP preview

The separately authorized `v9.0.0-mvp.1` channel may publish a portable Windows
x64 ZIP as a GitHub **Pre-release**, with `make_latest=false` and an explicit
**unsigned MVP preview** label. Use `Build-AndShip.ps1 -UnsignedMvpPreview` from
the exact protected `origin/main` commit. This preserves the clean-source,
hash-locked dependency, PE, privacy, and desktop smoke gates. Only its explicit
`unsigned-mvp-preview` manifest is accepted by `package_mvp_preview.py`, which
checks every payload byte and emits the ZIP, `SHA256SUMS`, and
`preview-release.json`. Existing development candidates cannot be repackaged
as previews through this entrypoint. The preview retains the unsigned
development CompanyName resource and asserts no legal publisher identity.

This narrow channel does not require an Authenticode provider or Portal
deployment evidence. It does not publish an installer, use the stable `v9.0.0`
tag, or satisfy any signed stable-release requirement below. A preview does
not establish SmartScreen reputation, clean-machine compatibility, or cloud
and multi-user production readiness. Preserve each published preview's bytes;
subsequent fixes require a new explicitly reviewed preview tag.

### Signed stable release

Run these gates against the exact commit and tracked tree to be published:

1. `python scripts/verify_public_tree.py` passes.
2. Python, JavaScript, Edge Function, and deployment contract tests pass from
   clean locked dependency installations.
3. Checked-in browser bundles reproduce without a diff.
4. The entire tracked history and release tree pass secret, personal-data,
   account-material, QR-code, local-path, and executable allowlist scans.
5. License compatibility, governance documents, third-party notices, and the
   generated SPDX SBOM match the exact release inputs.
6. The Windows onedir and installer pass malware, archive, PE, VersionInfo,
   Authenticode-chain, publisher, timestamp, and SHA-256 verification.
7. Independent staging passes multi-user, multi-device, quota, revocation,
   backup, restore, rollback, and observation gates.
8. Production deploys the same accepted image digest and passes desktop and
   mobile browser smoke tests before the stable release is created.

Passing CI alone authorizes neither remote deployment nor a live-readiness
claim.

The Windows chain is split across four manually dispatched workflows and fresh
GitHub-hosted `windows-2022` machines:

1. `v9-release-preparation.yml` has no signing or decryption identity. It builds
   and scans the unsigned application, then emits a canonical public signing
   request plus an `age`-encrypted application bundle.
2. `v9-application-signing.yml` verifies the exact prior run, artifact digest,
   request SHA, compliance evidence, and committed Publisher-policy SHA.
   `v9-trusted-signing` admits a signer-only job that signs only the reviewed
   application PE. A later credentialless job builds the unsigned installer and
   emits its request and encrypted bundle.
3. `v9-signed-candidate.yml` repeats the exact-byte checks.
   `v9-installer-signing-review` admits a signer-only job that signs only the
   reviewed installer PE. A credentialless finalizer then verifies both signing
   receipts, payloads, smoke tests, malware checks, SBOM, and the fixed six
   assets before encrypting the final candidate.
4. `v9-stable-release.yml` performs read-only production verification and emits
   a public promotion request. The separate `v9-production-release` job is the
   only job with `contents:write`; it has no signing identity, re-decrypts the
   exact candidate, matches every byte to the promotion request, then publishes.

Environment approval allows a job to start; it does not prove that the reviewer
inspected bytes created after approval. Each signing request therefore exists in
a prior credentialless job/run and is bound by request SHA, artifact digest, run
ID/attempt, exact protected-main commit, and an Environment URL visible before
approval. A signing receipt binds the post-signature bytes and signer-policy
evidence; it does not invent an approver identity. GitHub's Environment audit
trail remains the online record. The current arrangement is honestly
`single-maintainer-audited`, not independent two-person review.

Signer-only jobs do not checkout source, install Python dependencies, run
repository scripts, build installers, execute candidate programs, or run
Defender. They download only hash-pinned `age`, SignTool, and the provider client
needed for one signature. Python, Inno Setup, 7-Zip, Defender, and application
tests remain in credentialless jobs. Azure uses GitHub OIDC; temporary DigiCert
material is validated against the committed policy and removed unconditionally.

Public Actions artifacts contain ciphertext and sanitized requests/receipts,
not plaintext candidate binaries. The source-ZIP CLI likewise accepts no output
path: it writes only
`build/release-evidence/source-zips/DefenseTracker-source-<expected-sha>.zip`.
Existing targets, links, reparse points, and non-directory parents fail closed.

## Stable `v9.x` rule

The stable tag must point to the exact accepted release commit. The Release is
created only after every required asset and evidence check has passed. Once
published as immutable, its tag and assets are never moved, deleted, or
replaced. A defect is fixed in a new patch release such as `v9.0.1`.

See [the release signing policy](RELEASE_SIGNING_POLICY.md).

## Honest boundaries

- Local and CI checks do not exercise real DNS, TLS, SMTP, WAF, Supabase,
  backup storage, monitoring, or disaster-recovery infrastructure.
- Synthetic tests do not establish isolation, revocation, quotas, or encrypted
  sync under real multi-user concurrency.
- A valid signature authenticates a publisher and signed bytes; it does not
  guarantee the absence of vulnerabilities or immediate SmartScreen
  reputation.
- A dependency inventory is not a complete legal-compliance opinion.
- Repository readers can download retained Actions artifacts. `age` protects
  candidate plaintext, but artifact names, requests, receipts, hashes, and run
  metadata remain visible.
- Candidate confidentiality depends on the secrecy, rotation, and Environment
  access controls of `RELEASE_ARTIFACT_AGE_IDENTITY`; compromise exposes retained
  candidate ciphertext.
- Environment approval proves that a job was allowed to start, not that the
  approver inspected each byte. Offline requests and receipts do not identify
  who clicked Approve.
- Public-source metadata and summaries may still be wrong, incomplete, biased,
  or unsuitable for redistribution or operational use.
