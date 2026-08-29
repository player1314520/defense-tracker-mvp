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

A signed candidate requires two source-registered Ed25519 decisions. The first
reviews the hash-pinned application components before the first release
signature; the second, using a distinct public key, reviews the exact unsigned
installer, its full extracted payload, build recipe, tools, and bootstrap
license. Stage A may sign the application and retain the attested unsigned
installer review bundle, but cannot sign the installer or create final assets.
Stage B must consume that exact run-bound bundle, authenticate the independent
approval, and prove the signed installer has the same Authenticode-neutral bytes
and complete payload before packaging. The evidence binds the exact commit,
source tree, Publisher, dependency locks, installed package inventory,
third-party notices, and final shipped bytes. If any evidence, reviewer,
component, payload entry, signature, or binding is absent or mismatched,
candidate creation stops. The stable verifier independently requires the two
reviews, a final-shipped-bytes SBOM without `NOASSERTION`, and complete deployment
evidence; no manifest flag may be changed after packaging.

Signed-candidate dispatch is presently fail-closed before credentials. A
tokenless GitHub-hosted job emits a structured isolation blocker and exits
non-zero before any protected signing environment, OIDC login, secret, or
self-hosted runner is eligible to start. Enabling the path requires three
separate roles: credentialless build/scan approval, hash-verifying signing that
never executes the candidate, and post-signature smoke testing in a
credentialless or least-privileged restricted-egress single-use VM. The
controller must record runner deregistration and VM destruction; absence of
either receipt remains a release blocker.

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
- Public-source metadata and summaries may still be wrong, incomplete, biased,
  or unsuitable for redistribution or operational use.
