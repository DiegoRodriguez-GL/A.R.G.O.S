# Security Policy

ARGOS is a security tool. A vulnerability in ARGOS can blind an auditor, so we
treat disclosure with the seriousness it deserves.

## Supported Versions

During the pre-alpha phase, only the current `main` branch receives security
fixes. The table below will grow as minor versions ship.

| Version       | Supported       |
| ------------- | --------------- |
| `main`        | Yes             |
| `< 0.1.0`     | No (pre-alpha)  |

## Reporting a Vulnerability

Please use GitHub's **private vulnerability reporting** for this repository:

- <https://github.com/argos-ai-audit/argos/security/advisories/new>

If that channel is not available, send an encrypted email to the maintainers
(see the public PGP key pinned to the repository README once an official
maintainer team is established).

Do **not**:

- Open a public issue, PR, or Discussion thread.
- Share proof-of-concept material in a public location before a fix ships.
- Test against infrastructure or services that are not yours.

## What to Include

A good report usually contains:

1. A clear description of the vulnerability and its impact.
2. A minimal reproducer -- ideally a failing test case against `main`.
3. The commit hash you tested against.
4. Your suggested severity (CVSS v3.1 vector if you can).

## Response Targets

| Phase                        | Target                           |
| ---------------------------- | -------------------------------- |
| Acknowledgement              | within 3 business days           |
| Triage and severity decision | within 7 business days           |
| Fix available                | within 30 days for High/Critical |
| Public advisory              | coordinated with the reporter    |

We will credit reporters in the advisory unless they prefer to remain
anonymous.

## Safe-Harbour

We consider good-faith security research to be authorised under the
[disclose.io](https://disclose.io/) baseline, provided the research:

- Stays on your own infrastructure,
- Does not degrade service for others,
- Does not access, modify, or destroy data you do not own,
- Does not attempt social-engineering attacks against maintainers or users.

## Out of Scope

- Findings limited to third-party dependencies should be reported upstream
  first. We will track the impact through our dependency-review process
  (Dependabot + CI).
- Denial-of-service issues that require privileged network position.
- Self-XSS or configuration issues requiring the victim to copy arbitrary
  code into their shell.
