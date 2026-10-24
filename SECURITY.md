# Security Policy

## Reporting a vulnerability

Please do not report security vulnerabilities in public issues or pull requests.

Report them privately through GitHub: open this repository's **Security** tab and choose **Report a vulnerability**. GitHub keeps the report private between you and the maintainers.

Include:
- the version or commit you tested (for example `0.2.0`),
- the record, trust file, or command that shows the problem, with any real secrets removed,
- what you expected and what happened.

## Scope

In scope: the verifier's checks in `src/` (hash, legacy and hybrid signatures, the trust rules, and the command-line tool).

Out of scope: how a public key is distributed to you. The verifier only proves that a record matches a key you pinned. It cannot prove who owns that key.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.3.x   | Yes       |
| 0.2.x   | Yes       |
| < 0.2   | No        |
