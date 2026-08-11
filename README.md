# DefenseTracker V9 MVP

DefenseTracker is a local-first prototype for collecting public-source defense
reporting, organizing evidence, drafting analytical products, and evaluating a
role-aware encrypted synchronization workflow. This repository is a
history-free, source-visible MVP snapshot intended for technical review and
authorized evaluation.

> **Status:** the source and release tooling have local automated-test and
> static-validation coverage. No public production deployment, signed Windows
> installer, live multi-user acceptance test, or independent security audit is
> represented by this snapshot.

## MVP surfaces

| Surface | Purpose | Current evidence boundary |
|---|---|---|
| Windows desktop/local workspace | Local research, evidence, drafting, and device-held key workflows | Source and automated tests; no signed public installer |
| V9 Portal | Application/login entry point and role-aware team workflow | Local browser and contract-test scope; requires an operator-supplied Supabase environment for live use |
| Self-hosted cloud services | Supabase Auth, Postgres, Storage, Realtime, and Edge Functions | Deployment assets and static checks only in this snapshot |
| MVP deployment | Caddy plus the isolated Portal and self-hosted Supabase | **Only [`deploy/mvp`](deploy/mvp) is supported**; all other deployment paths are outside the public MVP contract |

The encryption and access-control code is part of the MVP implementation, but
it has not been independently audited. Treat it as reviewable engineering, not
as a certification or a claim that a live environment is secure.

## Requirements

- Python 3.11 or newer
- Node.js 20 or newer for JavaScript tests and the Supabase client bundle
- Windows for the desktop wrapper and DPAPI-specific tests
- Docker Compose v2, Caddy, and a pinned self-hosted Supabase checkout only for
  an authorized deployment evaluation

## Local Portal smoke test

The unconfigured Portal can be started locally without production credentials:

```sh
python -m venv .venv
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
# POSIX shell: source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r deploy/requirements.cloud.txt
python v9_cloud.py
```

Open <http://127.0.0.1:8080/portal/>. Without Supabase configuration, only the
unconfigured/anonymous surface is expected to be usable. This is a smoke test,
not a production deployment.

For the Windows desktop wrapper, install `requirements.txt` in an isolated
environment and run `python launcher.py`. Local startup may create ignored
runtime state; do not copy that state into a public checkout.

## Tests and quality gates

Install the Python test dependencies, including the direct YAML dependency used
by the deployment-contract tests:

```sh
python -m pip install -r requirements-dev.txt "PyYAML==6.0.2"
python -m compileall -q .
python -m pytest -q
```

Run the JavaScript tests and reproduce the checked-in browser bundles:

```sh
npm ci --prefix web/v9-auth
npm audit --prefix web/v9-auth --audit-level=high
npm run build --prefix web/v9-auth
node --test tests/js/*.test.mjs tests/js/*.test.cjs
git diff --exit-code -- static/js/vendor/v9-supabase-auth.mjs web/v9-portal/supabase-client.mjs
```

The globbed `node --test` command above assumes a POSIX-compatible shell. The
GitHub Actions workflow is the canonical cross-platform command record. Before
publishing, also run the public-tree gate:

```sh
python scripts/verify_public_tree.py
```

## Supported deployment path

Production-like evaluation is documented in
[`docs/MVP_DEPLOY.md`](docs/MVP_DEPLOY.md) and implemented only under
[`deploy/mvp`](deploy/mvp). It requires a clean, reviewed commit; images pinned
by digest; an exact self-hosted Supabase upstream commit; externally stored
configuration and secrets; live domain, TLS, SMTP, backup, restore, and
multi-user verification; and an operator-managed rollback decision.

CI performs no deployment and receives no production secrets. Do not treat a
green workflow, a successful image build, or a healthy local container as live
production acceptance.

## Privacy and public-snapshot posture

- No operational secrets are required for local tests or CI. Checked-in example
  values are inert placeholders; never commit `.env` files, tokens, private
  keys, credentials, email lists, databases, or user exports.
- The public snapshot intentionally excludes private commit history, internal
  planning and evidence logs, screenshots, local paths and state, private source
  material, generated reports, and build artifacts.
- The Portal deployment context is created from a narrow committed-file
  allowlist. Local configuration, tests, private materials, and uncommitted
  files are not Portal image inputs.
- The desktop application can contact configured feeds, AI providers, and a
  configured Supabase service. Operators must review those endpoints and the
  data sent to them; “local-first” does not mean “no network access.”
- Use only lawfully obtained public-source material. Generated analysis may be
  incomplete or wrong and must not be treated as classified, operational, or
  decision-authoritative intelligence.

See [`SECURITY.md`](SECURITY.md) for private vulnerability reporting and
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for third-party components.

## Honest boundaries

This snapshot cannot establish that:

1. the MVP works on a real VPS, domain, SMTP provider, or production Supabase
   stack;
2. role isolation, device revocation, encrypted sync, backup/restore, and
   concurrency behave correctly across real users and machines;
3. the cryptographic design or deployment configuration has passed an
   independent security audit;
4. a Windows installer is signed, timestamped, reproducible, or safe to
   distribute;
5. a single-VPS deployment is highly available or protected from DDoS; or
6. public-source inputs and generated output are accurate, complete, or cleared
   for redistribution.

## License

The first-party source is **source-visible and all rights reserved**. This is
not an open-source license, and no permission to use, copy, modify, deploy, or
redistribute the first-party material is granted by publication. See
[`LICENSE`](LICENSE). Third-party components remain under their own licenses.
