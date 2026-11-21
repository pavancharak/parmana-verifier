# Parmana Verifier

[![CI](https://github.com/pavancharak/parmana-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/pavancharak/parmana-verifier/actions/workflows/ci.yml) [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE) [![Node](https://img.shields.io/badge/node-%3E%3D24-brightgreen)](package.json)

**Parmana makes sure AI agents take only the actions your business has approved, and keeps signed proof of what they did.** This verifier checks that proof using only a record file and the keys you trust. It needs no network access, no account and no dependencies.

Parmana signs an **Execution Trust Record** for every action an agent takes through it. The record says what was authorized, what ran, and what the outcome was. This verifier checks that a record has not been changed and that it was signed by keys you chose to trust. It does not contact Parmana's servers, so you do not have to trust them to check a record.

The records come from [Parmana](https://github.com/pavancharak/parmana-core), which signs them. The verifier works without the rest of Parmana: it needs only a record and a trust file.

Test results, the security review scope and the changelog are indexed under [Reports and evidence](#reports-and-evidence).

## Who it is for

- **Auditors and reviewers** who need to confirm a record without relying on the system that produced it.
- **Operators** who want to check records in their own environment, with keys they pinned themselves.
- **Developers** who want a small, dependency-free reference implementation of the record checks.

## Quick start

Requires Node.js 24 or later. Ed25519 works on any Node 24 build; post-quantum ML-DSA-65 signatures need OpenSSL 3.5 or later. From a clone of this repository:

```sh
node bin/parmana-verify.mjs test/vectors/parmana-core-generated/v3-hybrid-record.json test/vectors/parmana-core-generated/trust-v3-hybrid.json
```

```json
{"valid":true,"errors":[],"checks":{"trustRecordHash":true,"signatures":true},"correspondence":{"status":"not_checked","executions":[]}}
```

The record is schema version 3, with two signatures (Ed25519 and ML-DSA-65). The verifier checks only schema version 3 (decision D24).

The exit code is `0`. The `correspondence` field is a separate report, described in [Execution correspondence](#execution-correspondence). It does not change `valid` or the exit code. This sample record is a trimmed test vector that does not embed its authorization, so there is nothing to compare and its correspondence is reported as `not_checked`, not as a mismatch. A complete record from Parmana embeds the authorization and is checked. A record that has been changed is rejected:

```sh
node bin/parmana-verify.mjs test/vectors/parmana-core-generated/v3-hybrid-record-tampered.json test/vectors/parmana-core-generated/trust-v3-hybrid.json
```

The exit code is `1`, and the output lists the failed checks. The test vectors are labelled test material; see [test/vectors/README.md](test/vectors/README.md). For real records, pin the keys you trust (see [Pinning a key](#pinning-a-key)).

On Windows PowerShell, run the same two commands with Windows paths. Use Node 24 or later:

```powershell
node bin\parmana-verify.mjs test\vectors\parmana-core-generated\v3-hybrid-record.json test\vectors\parmana-core-generated\trust-v3-hybrid.json
node bin\parmana-verify.mjs test\vectors\parmana-core-generated\v3-hybrid-record-tampered.json test\vectors\parmana-core-generated\trust-v3-hybrid.json
```

The first prints the valid result above and exits with `0`. The second prints `"valid":false` and exits with `1`.

## Installation and usage

The package is published on npm as [`@parmana/verifier`](https://www.npmjs.com/package/@parmana/verifier). Install it, or run it without installing:

```sh
npm install -g @parmana/verifier
parmana-verify <proof.json> <trust.json>
parmana-verify key-fingerprint <public-key.pem>
```

```sh
npx @parmana/verifier <proof.json> <trust.json>
```

From a clone of this repository, run the same commands with `node bin/parmana-verify.mjs` in place of `parmana-verify`.

There is also a Python version in [`python/`](python/README.md). It checks the same records and gives the same results, including ML-DSA-65 (hybrid) signatures when `cryptography` 48.0.0 or later is installed.

```sh
pip install parmana-verifier
parmana-verify <proof.json> <trust.json>
```

- `proof.json` is the Execution Trust Record.
- `trust.json` is the trust set. It lists each key you accept:

  ```json
  {
    "keys": [
      {
        "keyId": "default",
        "algorithm": "ed25519",
        "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
        "fingerprint": "sha256:<64 hex digits>",
        "validFrom": "2026-01-01T00:00:00.000Z",
        "validUntil": null,
        "compromised": false
      }
    ]
  }
  ```

- `key-fingerprint` prints the `sha256:` value to pin for a PEM key. To pin a key safely, follow the steps in [Pinning a key](#pinning-a-key).

The verify command prints one line of JSON and exits with `0` (valid), `1` (invalid, with reasons), or `2` (usage, missing file, or invalid JSON). The full input and output rules are in [docs/FORMAT.md](docs/FORMAT.md).

On Windows PowerShell, use the same commands with Windows paths, for example `node bin\parmana-verify.mjs proof.json trust.json`.

## Execution correspondence

The output also carries a `correspondence` report: whether what was dispatched is what was authorized. It is checked from the record alone, the same way as the signatures, and it uses the same rules as Parmana's own offline check.

For each execution, the record's authorization (its nonce, business transaction hash, policy content hash and authority grant) is compared with the execution's `evidence.correspondence`. Every field must be present and must match, and the dispatched content hash must equal the authorized one. The statuses are:

- `passed`: every field is present and matches the authorization.
- `failed`: a field is missing or different. This is a mismatch that was observed.
- `not_checked`: the execution has no correspondence fields, no evidence, or the record embeds no authorization to compare with. Nothing was compared, so this is not a mismatch. It is never reported as passed.

The report is `passed` only when every execution is checked and corresponds. The verifier reports it and does not decide what it means for your system: a `failed` or `not_checked` report is for you to act on. It is meaningful only for a record whose signatures also verify, so read it together with `valid`.

## Pinning a key

A signature proves only that a key made it. Before you trust a record, decide which keys you trust, and check that each key is the one its owner published.

1. Get the operator's public key PEM and the `sha256:` fingerprint they published. Get the fingerprint from a source other than the one that gave you the key, such as a signed message or a call to a known number.
2. Run `node bin/parmana-verify.mjs key-fingerprint public-key.pem` on the PEM you received.
3. Compare the two fingerprints character by character. If they differ, do not use the key.
4. Only then add the key to your trust file with that fingerprint.

## Trust rules

A key is used only if all of these hold:

- its PEM hashes to the pinned fingerprint (SHA-256 of the SPKI DER encoding);
- the algorithm named by the signature entry matches the algorithm in the trust file;
- it is not marked `compromised`;
- the record's `createdAt` is at or after `validFrom` and before `validUntil` (if set).

A compromised key is rejected whatever the timestamp, so signatures it made stay void.

### Signatures and the cutover

The verifier accepts only schema version 3 (decision D24). Any other `schemaVersion`, or none, is refused before any signature is read. Schema version 2 and the legacy top-level `signature` are no longer accepted.

A schema version 3 record has a `signatures` array of one or two entries, each for a different algorithm:

- **Single mode**: one entry, Ed25519 or ML-DSA-65, the configured algorithm. One valid entry is accepted.
- **Hybrid**: two entries, Ed25519 and ML-DSA-65. Both must verify, so one valid part is never enough.

`hybridRequiredFrom` (ADR-0016) is the cutover in the trust file. A record created at or after it must carry both entries. A record created before it is accepted with one valid entry. The cutover is inclusive.

A trust file that still sets `allowLegacyOnly` or `allowLegacyV2` is refused with exit `2`. Remove those fields. Which trust policy to use for each state of a deployment, and how to move from single mode to hybrid, is in [docs/OPERATING-MODES.md](docs/OPERATING-MODES.md). See [docs/FORMAT.md](docs/FORMAT.md#trust-set-trustjson) for the trust-set format.

## Examples

Run every example with:

```sh
npm run examples
```

The examples are in `examples/`, and each one prints what it checks:

- `01-verify-a-proof.mjs`: verify a record and explain each check.
- `02-tamper-detection.mjs`: change a signed field, then show that recomputing the hash does not help an attacker.
- `03-pinned-keys-and-windows.mjs`: how pinned fingerprints, validity windows and compromised keys decide what is accepted.
- `04-hybrid-envelope.mjs`: the Ed25519 and ML-DSA-65 entries of a hybrid record (needs Node 24).
- `05-build-and-verify-a-record.mjs`: build, hash, sign, pin and verify a record from scratch, with a runtime test key.
- `06-command-line.mjs`: the command-line exit codes, and fingerprinting a key for pinning.
- `07-whole-record-coverage.mjs`: what a schema version 3 signature protects, including a changed `updatedAt` that the hash does not catch.
- `08-hybrid-cutover.mjs`: a single-entry record before and after the `hybridRequiredFrom` cutover.
- `09-unsupported-schema-version.mjs`: a schema version other than 3 is refused, not guessed at.

Each example exits `0` when it behaves as described, so the set runs in CI.

## Testing

```sh
npm test
```

Run the tests on Node 24. On Node 22 or any runtime without ML-DSA-65, the hybrid tests are skipped. Test keys are generated at run time, labelled "TEST KEY - NOT FOR PRODUCTION", and never written to disk.

The suite covers the whole-record hash and signatures, single mode and hybrid signatures, the cutover, the trust rules, the removed legacy flags, the execution correspondence report, the quick start, the test vectors, and the command-line exit codes. Each area has its own file under `test/`.

Records from parmana-core are tested in `test/parmana-core-records.test.mjs` and `python/tests/test_parmana_core_records.py`. They use `test/vectors/parmana-core-generated/cases.json`: 16 cases over two records generated with parmana-core's signing code (hybrid and single mode, decision D24), with tampered copies and trust-file edits. Both verifiers must agree on every case. The quick-start record in `python/README.md` is tested in `test/quickstart.test.mjs` and `python/tests/test_quickstart.py`.

## Limitations

- The verifier can only check that a record was signed by the key you pinned. It cannot prove that the key belongs to Parmana. That depends on how you obtained and compared the fingerprint.
- Every top-level field except `signatures`, `schemaVersion`, `verifications` and `receipts` is protected by the signatures. `verifications` and `receipts` are attached after signing and are not covered.
- `trustRecordHash` covers the six canonical fields. The signatures cover the whole record, so a change to a field outside the hash, such as `updatedAt`, is caught by the signatures alone.
- In single mode, a record has one signature. The verifier cannot tell that a second one was expected. Set `hybridRequiredFrom` in the trust file to require both from a given instant. Records created before that instant stay accepted with one valid signature.
- The validity window is checked against the record's `createdAt`, not against the signing time. A record that carries a false `createdAt` is checked against the window for that false time.
- Keys and fingerprints must be kept current. The verifier does not know about rotations or revocations that you have not written into the trust file.
- It does not verify the policy the record cites, the authorization decision logic, or the state of any connector or external system.
- It checks Policy version 2 evidence only as a chain and an outcome hash, with `parmana-verify policy-v2`. It does not evaluate the decisions in it.
- It does not confirm that the action described by the record was executed.
- The records in `test/vectors/` were produced by the Parmana signing code and are test material only. They show that the checks agree with that code; they are not an independent specification.

## Reports and evidence

Every report is listed once, here. Start with the question you have.

**Test results**

- **Live CI runs:** the [CI workflow](https://github.com/pavancharak/parmana-verifier/actions/workflows/ci.yml) runs the tests and examples on every push. The [Python workflow](https://github.com/pavancharak/parmana-verifier/actions/workflows/python.yml) runs the Python package tests.
- **Test suite:** what it covers, and how to run it on Node 24, is under [Testing](#testing).
- **Test vectors:** labelled test records and keys, in [test/vectors/](test/vectors/README.md). They are for tests only, not for production use.
- **Examples:** nine runnable examples that check their own behaviour, run by `npm run examples` ([Examples](#examples)).

**Security**

- **Security review scope:** [docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md) is written for an external reviewer. It covers what the verifier claims, what to examine, and its known limits.
- **Security policy:** [SECURITY.md](SECURITY.md) explains how to report a vulnerability privately.

**Releases**

- **Published versions:** `@parmana/verifier` 2.0.3 on npm and `parmana-verifier` 2.0.3 on PyPI, published 2026-11-15 from commit `4068278`.
- **Changelog:** [CHANGELOG.md](CHANGELOG.md) lists each change to the record formats and the command-line interface.
- **Release process:** [RELEASING.md](RELEASING.md) describes how a release is built, checked and published.

---

## Read the Parmana blog

The [Parmana blog](https://blog.parmanasystems.com) explains how the verifier fits into the wider product, in plain terms. Read the post for your role:

- **Auditors and risk teams:** [Check a record offline, without trusting us](https://blog.parmanasystems.com/2026/10/25/check-a-record-offline/). How to verify a signed record with only a file and a trust file, and what the check does not cover.
- **Engineers:** [Run the checks in an afternoon](https://blog.parmanasystems.com/2026/10/25/run-the-checks-in-an-afternoon/). Build, test and verify a record from source.
- **Anyone who wants the honest picture:** [Lessons from the limits we still have](https://blog.parmanasystems.com/2026/10/25/lessons-from-the-limits-we-still-have/). What we got wrong, and what remains open.

New posts are published regularly, so check the blog for updates.

## Status

This is version 2.0.3, published 2026-11-15 on npm and PyPI, released with the 2.0.3 SDK packages. Each change to the record formats or the command-line interface is listed in [CHANGELOG.md](CHANGELOG.md).

On 2026-10-29, on Node 24.22.1 and Windows PowerShell, the two quick-start commands above returned the output shown, with exit codes `0` and `1`. The release process builds the packages, records their hashes, and attaches build provenance. See [RELEASING.md](RELEASING.md) for the steps.

What this version does not do is listed under [Limitations](#limitations).

## Repository layout

| Path        | Contents                                                               |
| ----------- | ---------------------------------------------------------------------- |
| `bin/`      | The `parmana-verify` command-line entry point                          |
| `src/`      | The checks: canonical JSON, hashing, signatures, trust rules           |
| `test/`     | The test suite, and `test/vectors/`, the labelled test records         |
| `examples/` | Nine runnable examples, run by `npm run examples`                      |
| `docs/`     | `FORMAT.md` (the input and output rules) and `SECURITY-REVIEW.md`      |
| `reports/`  | Pointer to the reports index in this README (see Reports and evidence) |

## Security

Do not open a public issue for a security problem. Report it through GitHub's private vulnerability reporting: open the **Security** tab and choose **Report a vulnerability**. See [SECURITY.md](SECURITY.md). The scope for an external review is in [docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md).

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before you open a pull request. Run `npm test` on Node 24 first. Every commit must carry a `Signed-off-by` line (`git commit -s`), certifying the [Developer Certificate of Origin](https://developercertificate.org). Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
