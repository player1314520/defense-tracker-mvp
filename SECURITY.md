# Security Policy

## Supported code and releases

Security fixes are considered on a best-effort basis for the latest commit on
the default branch and, after a stable release exists, the latest immutable
`v9.x` release. Older snapshots, local modifications, unsigned binaries,
repacked archives, and deployments outside `deploy/mvp` are not supported
security targets.

An official Windows package must be downloaded from this repository's GitHub
Releases page and must pass both the Authenticode and SHA-256 verification
steps described by the release. A tag, filename, or green CI badge alone is not
proof that a binary is official.

There is no vulnerability-reward program and no guaranteed response or repair
SLA.

## Report a vulnerability privately

Use GitHub private vulnerability reporting:

1. Open the repository's **Security** tab.
2. Select **Advisories**, then **Report a vulnerability**.
3. Submit a private draft advisory with the affected commit or version, impact,
   minimal reproduction steps, and a proposed mitigation if known.

Do not include credentials, personal data, private datasets, classified or
suspected internal material, account screenshots, QR codes, or unrelated
system logs. Redact tokens and use synthetic test data. Do not open a public
issue or pull request containing vulnerability details.

If private reporting is unavailable, open a public issue containing no
vulnerability details and ask the maintainers to restore the private advisory
channel. No personal email address is designated for security reports.

## Safe research expectations

- Test only local instances and accounts, data, and infrastructure you own or
  are explicitly authorized to assess.
- Do not access another person's data, disrupt service, send unsolicited mail,
  perform denial-of-service testing, evade quotas, or attempt persistence.
- Stop when the issue is demonstrated. Retain only the minimum sanitized
  evidence needed to reproduce it.
- Do not upload secrets or live user data to third-party scanners or public
  paste services.
- Allow maintainers a reasonable opportunity to investigate. Any coordinated
  disclosure date must be agreed in the private advisory.

Report an upstream dependency vulnerability to its upstream project unless the
problem is specific to this integration; integration-specific impact may also
be reported here.

## Release and deployment security

- Stable Windows releases require a trusted publisher certificate, RFC 3161
  timestamp, exact-source provenance, privacy/secret scans, malware scanning,
  an SBOM, and published checksums. Self-signed certificates are prohibited.
- Public signup remains disabled. A live Portal must use human-reviewed
  applications and invitations, separate staging and production resources,
  WAF controls, monitoring, encrypted backups, and a tested restore path.
- Credentials, signing configuration, deployment environment files, backup
  identities, and personal contact data must stay outside the repository and
  outside public issues and discussions.

See [the release signing policy](docs/RELEASE_SIGNING_POLICY.md) for the
Windows trust and immutable-release gates.

## Security boundaries

This policy:

1. does not authorize testing of a live deployment or any third-party service;
2. does not prove that a CI-passing build, signed binary, or configured Portal
   is free of vulnerabilities;
3. does not promise that every report will be accepted, fixed, disclosed, or
   credited; and
4. cannot provide confidential conduct reporting, legal advice, service
   availability, or recovery guarantees.
