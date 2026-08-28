# DefenseTracker Governance

## Project status

DefenseTracker V9 Community Edition is an AGPL-licensed public project with one
current repository maintainer, `@player1314520`. This username identifies the
repository maintainer; it does not establish the legal organization,
commercial-licensing counterparty, or code-signing Publisher. Those identities
remain pending formal verification and publication.

## Roles

### Community participants

Anyone following the community policies may file issues, join discussions, or
suggest lawful public sources. Until the CLA gate is activated, external pull
requests cannot be merged.

### Contributors

A contributor is a person or organization whose change has passed the active
contribution agreement, review, testing, licensing, privacy, and provenance
gates and has been merged. Opening a pull request alone does not confer this
role.

### Maintainers

Maintainers triage issues, review changes, enforce community and security
policies, manage repository settings, and make release decisions. Maintainers
must protect credentials and private reports, record material release evidence,
and disclose when a decision is not independently reviewed.

## Decision process

- Routine decisions are documented in an issue or pull request with scope,
  alternatives when material, tests, and remaining risk.
- Security-sensitive details stay in a private advisory.
- Changes to licensing, contributor agreements, data policy, authentication,
  cryptography, release signing, or production architecture require explicit
  review and cannot be inferred from a routine patch.
- A stable release requires every gate in the release-signing policy; a failed
  gate blocks the release rather than becoming a waived warning.

The maintainer may close proposals that exceed the product boundary, create
unacceptable legal/privacy risk, lack evidence, or cannot be supported.

## Single-maintainer controls

While there is one maintainer:

- changes still use pull requests and required automated checks;
- the exact protected-default-branch commit is recorded for releases;
- stable assets are signed, timestamped, hashed, attested, and immutable;
- exceptions and unverified boundaries are written into the release record;
  and
- the maintainer must not claim independent human approval.

After a second qualified maintainer is appointed, branch protection must
require at least one approval from a maintainer other than the author, and
self-approval is prohibited. High-risk releases should use two-person review
and recovery access.

## Becoming a maintainer

Candidates should demonstrate sustained, policy-compliant work; sound security
and privacy judgment; respectful review; and the ability to operate release
and recovery gates. Appointment is recorded publicly by an existing maintainer
after access scope and conflicts are reviewed. Repository access is least
privilege and revoked when no longer needed.

## Licensing and legal stewardship

First-party covered material is available under `AGPL-3.0-only`. A commercial
license exists only if a verified rights holder signs a separate agreement.
The project must not publish an organization legal name, CLA, or signing
Publisher until that exact identity and authority are verified.

## Honest boundaries

- One maintainer is a governance and availability single point of failure.
- Automated checks and immutable releases reduce risk but do not replace
  independent review or legal authority.
- Public discussion cannot safely resolve confidential security, conduct, or
  commercial matters without dedicated private channels.
- Governance documents cannot compel third-party hosting platforms, package
  consumers, or downstream operators to follow operational recommendations.
