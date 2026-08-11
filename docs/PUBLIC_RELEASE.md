# Public Release Scope

## What this snapshot is

This repository is intended to be published as a history-free, source-visible
snapshot of the DefenseTracker V9 MVP. It provides reviewable first-party
source, tests, the Portal, Supabase migrations and Edge Functions, and the
isolated `deploy/mvp` release surface.

The snapshot is not an open-source release. No first-party license is granted;
third-party components retain their own licenses.

## Included public material

- source required to run the local MVP and V9 Portal;
- automated Python and JavaScript tests;
- Supabase migrations and the MVP Edge Functions;
- `deploy/mvp` configuration, release, rollback, backup, and restore tooling;
- inert configuration examples and public operational documentation; and
- required third-party bundles and notices.

## Deliberately excluded material

- private Git history and internal planning, task, handoff, staging, and review
  evidence;
- screenshots, personal paths, raw logs, local tool state, and account details;
- credentials, `.env` files, tokens, keys, email lists, databases, and user
  exports;
- private source material, generated reports, historical selection records,
  and date-specific operator scripts; and
- build directories, unsigned installers, caches, and other reproducible or
  machine-local artifacts.

## Pre-publication gates

Run these gates against the exact tree that will become the public repository:

1. `python scripts/verify_public_tree.py` passes.
2. Python and JavaScript tests pass from clean dependency installations.
3. Checked-in browser bundles reproduce without a diff.
4. Deployment shell, Python, YAML, and Compose assets pass static validation.
5. The tracked-file and commit-metadata privacy scan reports no operational
   secrets, personal contact details, private local paths, or private assets.
6. `README.md`, `LICENSE`, `SECURITY.md`, and `THIRD_PARTY_NOTICES.md` match the
   final tree.
7. A fresh repository is created without importing private commit history.

Passing these gates authorizes neither a remote deployment nor a claim of live
production readiness.

## Honest boundaries

- Static and local checks do not exercise a real VPS, DNS, TLS, SMTP, Supabase
  deployment, backup target, or disaster-recovery host.
- Synthetic tests do not establish cross-user isolation or revocation under
  real multi-device concurrency.
- The snapshot includes no signed or reproducible Windows installer.
- Dependency notices are not a complete SBOM or legal compliance opinion.
- Removing private history does not prove that every public-source input is
  accurate, complete, or redistributable.
