# Contributing to DefenseTracker

Thank you for helping improve DefenseTracker V9 Community Edition. The project
welcomes reproducible bug reports, design discussion, documentation feedback,
and carefully sourced public-data suggestions.

## Read this first

1. Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
2. Read the [governance](GOVERNANCE.md), [security](SECURITY.md), and
   [data contribution](docs/DATA_CONTRIBUTION_POLICY.md) policies.
3. Do not include credentials, personal data, screenshots of accounts, QR
   codes, private logs, local paths, real configuration, copied articles, or
   suspected internal/sensitive material.
4. Report vulnerabilities privately. Never put exploit details in a public
   issue, discussion, or pull request.

## Current external-contribution gate

The contributor-license-agreement process is **inactive and not legally
approved**. Until the legal steward and exact Individual/Corporate CLA texts
are published after legal review, maintainers must not merge or cherry-pick an
external code, documentation, design, or test contribution.

External pull requests may be discussed and reviewed, but they will remain
blocked or be closed without merge. Filing an issue, discussing an approach, or
submitting a pull request does not assign copyright, grant a commercial
license, or create an accepted CLA. See [CLA_POLICY.md](CLA_POLICY.md).

This temporary gate does not prevent:

- filing a minimal, reproducible bug report using synthetic data;
- proposing a feature or architecture in GitHub Discussions;
- suggesting a lawful public URL with factual metadata and an original short
  summary under the data policy; or
- privately reporting a vulnerability.

## Before opening a pull request

Open or link an issue for non-trivial work. Keep changes focused, preserve the
project's privacy and authentication controls, and avoid unrelated cleanup.
Never weaken a test or bypass a release/security gate to make a change pass.

Use a GitHub-provided `users.noreply.github.com` commit email so a public pull
request does not expose a personal address. The release-history gate accepts
community noreply authors and GitHub's merge service, while the maintainer's own
commits must use the repository's prescribed numeric noreply identity. Commit
messages are scanned for secrets and local paths regardless of author.

Run the relevant checks:

```sh
python -m compileall -q .
python -m pytest -q
python scripts/verify_public_tree.py
npm ci --prefix web/v9-auth
npm run build --prefix web/v9-auth
node --test tests/js/*.test.mjs tests/js/*.test.cjs
```

Describe the user-visible change, security/privacy impact, tests actually run,
and any unverified boundary. Do not claim production readiness from local or CI
results.

## Source and data contributions

Only submit:

- a direct lawful public-source URL;
- factual metadata such as title, publisher, publication date, and language;
- a short summary written by the contributor; and
- provenance and license/redistribution information when known.

Do not paste or upload third-party full text, paywalled content, account
screenshots, QR codes, personal information, real credentials/configuration,
private datasets, user exports, or suspected internal or classified material.
Use the dedicated data-source issue form.

## Review and release expectations

All changes use pull requests and required CI checks. The current single
maintainer records release decisions and exact-source evidence. After a second
qualified maintainer is appointed, an author must not approve their own change
and at least one independent maintainer approval becomes mandatory.

Official Windows assets additionally require the trusted-signing and immutable
release gates in [docs/RELEASE_SIGNING_POLICY.md](docs/RELEASE_SIGNING_POLICY.md).

## Honest boundaries

- Review does not guarantee that a contribution will be accepted or merged.
- Automated tests and secret scans cannot prove that code is vulnerability-free
  or that submitted material is lawful to redistribute.
- Maintainers cannot provide legal advice or validate a contributor's ownership
  of every submitted idea or source.
- The project currently has no confidential conduct-reporting channel,
  guaranteed response SLA, or contributor compensation program.
