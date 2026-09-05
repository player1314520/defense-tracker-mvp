# DefenseTracker V9 Community Edition

DefenseTracker is a local-first system for collecting lawfully available
public-source defense reporting, organizing evidence, drafting analytical
products, and collaborating through an encrypted, role-aware workspace.
The public project is licensed under **GNU AGPL v3 only
(`AGPL-3.0-only`)**.

> **Release status:** this source tree is being prepared for the `v9.0.0`
> community release. A green CI run is not evidence that a signed Windows
> package or a production Portal exists. Use only assets that appear in an
> official GitHub Release and pass the published signature and checksum
> checks.

An explicitly labeled **unsigned MVP preview** may be downloaded from a GitHub
Pre-release tagged `v9.0.0-mvp.1`. It is a portable Windows x64 ZIP: extract the
whole archive, keep `_internal` beside `DefenseTracker.exe`, and read
`START-HERE.txt`. Verify `SHA256SUMS` first. This preview has no trusted
publisher signature or SmartScreen reputation and makes no Portal production
or multi-user readiness claim. The signed stable release gates remain unchanged.
Maintainers build this separate channel with
`scripts/Build-AndShip.ps1 -ExpectedReleaseSha <exact-main-sha> -UnsignedMvpPreview`;
it emits a dedicated preview manifest and ZIP, never a stable installer.

## Product boundary

| Surface | Purpose | Public boundary |
|---|---|---|
| GitHub Pages | Public introduction, version notes, briefs, download verification, and links | Static public content only |
| GitHub repository | AGPL source, issues, pull requests, discussions, and private security reports | No credentials, private source material, user exports, or operational data |
| V9 Portal | Application review, invitation-only login, alerts, tasks, approvals, and device administration | Public signup stays disabled; access requires human approval and an invitation |
| Signed Windows desktop | Full local collection, analysis, AI-assisted drafting, local data, and encrypted synchronization | Official packages must be signed and timestamped under the release policy |

The legacy Flask workspace is a desktop/local surface. It is not the public
Portal and must not be exposed directly to the Internet. Real AI keys, Feishu
configuration, account material, QR codes, private datasets, and internal
documents are never part of the public deployment contract.

## Current evidence boundary

| Area | What the repository can demonstrate | What still requires live evidence |
|---|---|---|
| Source | Reviewable code, automated tests, privacy gates, and deployment contracts | Independent security assessment |
| Windows | Credentialless preparation/finalization, isolated signer-only jobs, encrypted candidate transport, and exact request/receipt verification | Approved committed Publisher policy, provisioned trusted signing provider, configured Environment review, valid Authenticode signatures, and clean-machine installation and migration tests |
| Portal | Local browser and API contract tests | Separate staging/production infrastructure, real SMTP, WAF, backup/restore, and multi-user acceptance |
| Operations | Documented health, rollback, and recovery gates | Measured availability, latency, recovery point, and recovery time |

## Local Portal smoke test

Requirements:

- Python 3.11 or newer;
- Node.js 20 or newer for JavaScript tests and browser bundles;
- Windows for the desktop wrapper and DPAPI-specific tests; and
- Docker Compose v2 and Caddy only for an authorized deployment evaluation.

Start the unconfigured Portal locally:

```sh
python -m venv .venv
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
# POSIX shell: source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r deploy/requirements.cloud.txt
python v9_cloud.py
```

Open <http://127.0.0.1:8080/portal/>. Without operator-supplied Supabase
configuration, only the unconfigured/anonymous surface is expected to work.
This is a smoke test, not a production deployment.

For the desktop wrapper, use an isolated environment and run
`python launcher.py`. Local startup may create ignored runtime state; never
copy that state into a public checkout or release package.

## Tests and public-tree gate

```sh
python -m pip install -r requirements-dev.txt "PyYAML==6.0.2"
python -m compileall -q .
python -m pytest -q
python scripts/verify_public_tree.py
```

Run the JavaScript tests and reproduce the checked-in browser bundles:

```sh
npm ci --prefix web/v9-auth
npm audit --prefix web/v9-auth --audit-level=high
npm run build --prefix web/v9-auth
node --test tests/js/*.test.mjs tests/js/*.test.cjs
git diff --exit-code -- static/js/vendor/v9-supabase-auth.mjs web/v9-portal/supabase-client.mjs
```

The globbed `node --test` command assumes a POSIX-compatible shell. GitHub
Actions is the canonical cross-platform command record.

## Deployment

Only [`deploy/mvp`](deploy/mvp) is the supported public deployment path.
[Deployment guidance](docs/MVP_DEPLOY.md) requires an exact reviewed commit,
images pinned by digest, a pinned self-hosted Supabase checkout, externally
stored secrets, separate staging and production resources, live TLS/SMTP/WAF
checks, backup and isolated restore exercises, and an operator-managed rollback
decision.

CI performs no deployment and receives no production secrets. Do not treat a
successful image build or local health response as production acceptance.

## Join the community

- Read [CONTRIBUTING.md](CONTRIBUTING.md) before filing an issue or pull
  request.
- Use [GitHub Discussions](https://github.com/player1314520/defense-tracker-mvp/discussions)
  for design proposals and community questions.
- Submit source suggestions only under the
  [data contribution policy](docs/DATA_CONTRIBUTION_POLICY.md).
- Report vulnerabilities privately under [SECURITY.md](SECURITY.md).
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md) and
  [governance rules](GOVERNANCE.md).

The contributor-license-agreement process is not active yet. Until the legal
steward, exact CLA text, and signing authority have completed legal review,
external pull requests may be discussed and reviewed but **must not be
merged**. Issues, reproducible bug reports, and compliant public-source links
remain welcome. See [CLA_POLICY.md](CLA_POLICY.md).

## Privacy and source handling

- Never commit `.env` files, tokens, private keys, credentials, personal
  contact lists, account screenshots, QR codes, databases, user exports,
  local paths, or raw logs.
- A data suggestion may contain a lawful public URL, factual metadata, and the
  contributor's own short summary. It must not contain copied articles,
  paywalled text, personal data, real configuration, or suspected internal or
  sensitive material.
- The Portal deployment context is built from a narrow committed-file
  allowlist. Local state, tests, uncommitted files, and private materials are
  not Portal image inputs.
- The desktop application can contact configured feeds, AI providers, and a
  configured Supabase service. Operators must review those endpoints and what
  data is transmitted; local-first does not mean offline.
- Generated analysis may be incomplete or wrong. It is not classified,
  operational, or decision-authoritative intelligence.

## License

Unless a file or directory states otherwise, first-party material in this
repository is licensed under [GNU AGPL v3 only](LICENSE), SPDX identifier
`AGPL-3.0-only`. Network operators of modified versions must follow the
Corresponding Source obligations in section 13.

Third-party components remain under their own licenses; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). A commercial license, if
offered, requires a separate signed agreement with the verified rights holder;
this repository does not grant one. See
[COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md).

## Honest boundaries

This repository cannot establish that:

1. a public `v9.0.0` installer exists, has a valid trusted timestamp, or has
   acquired Microsoft SmartScreen reputation;
2. the Portal works on real staging and production domains with real SMTP,
   WAF, monitoring, backup, restore, and rollback;
3. role isolation, revocation, quotas, and encrypted sync remain correct under
   real multi-user and multi-device concurrency;
4. the cryptographic design or release pipeline has passed an independent
   security or legal audit;
5. a single-server deployment is highly available or resistant to denial of
   service; or
6. public-source inputs and generated outputs are accurate, complete, lawful
   to redistribute, or suitable for operational decisions.
