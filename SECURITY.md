# Security Policy

## Supported code

Security fixes are considered on a best-effort basis for the latest commit on
the default branch. Older snapshots, local modifications, unsigned binaries,
and deployments not following `deploy/mvp` are not supported security targets.
There is currently no vulnerability-reward program or guaranteed response SLA.

## Report a vulnerability privately

Use GitHub's private vulnerability reporting flow for this repository:

1. Open the repository's **Security** tab.
2. Select **Advisories** and then **Report a vulnerability**.
3. Submit a private draft Security Advisory with the affected commit, impact,
   minimal reproduction steps, and a proposed mitigation if known.

Do not include credentials, personal data, private datasets, classified
material, or unrelated system logs. Redact tokens and use synthetic test data.
Do not open a public issue or pull request containing vulnerability details.

If private vulnerability reporting is unavailable, open a public issue that
contains no security details and asks the maintainers to enable a private
Security Advisory. No personal email address is used for security reports.

## Safe research expectations

- Test only local instances and accounts, data, and infrastructure you own or
  are explicitly authorized to assess.
- Do not access other users' data, disrupt service, send unsolicited email,
  perform denial-of-service testing, or attempt persistence.
- Stop when a vulnerability is demonstrated. Preserve only the minimum
  sanitized evidence needed to reproduce it.
- Allow maintainers a reasonable opportunity to investigate before public
  disclosure. Any disclosure timeline must be agreed in the private advisory.

Third-party vulnerabilities should normally be reported to the upstream
project. If the issue is specific to this repository's integration, report it
here privately as well.

## Security boundaries

A private report does not imply authorization to test a live deployment, access
third-party services, or handle real user data. A CI pass does not prove a live
deployment secure. This policy also does not promise that every report will be
accepted, fixed, or eligible for public credit.
