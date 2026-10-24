# Parmana Verifier

[![CI](https://github.com/pavancharak/parmana-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/pavancharak/parmana-verifier/actions/workflows/ci.yml) [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE) [![Node](https://img.shields.io/badge/node-%3E%3D24-brightgreen)](package.json)

Check whether an AI agent's action was approved and recorded as signed, using only a file and the keys you trust. No network access, no account, no dependencies.

Parmana signs an **Execution Trust Record** for every action an agent takes through it. The record says what was authorized, what ran, and what the outcome was, and it is signed with keys. This verifier checks that a record has not been changed and that it was signed by keys you chose to trust. It does not ask Parmana's servers anything, so you do not have to trust them to check a record.

The records come from [Parmana](https://github.com/pavancharak/parmana-core), which signs them. The verifier works without the rest of Parmana: it needs only a record and a trust file.

## Who it is for

- **Auditors and reviewers** who need to confirm a record without relying on the system that produced it.
- **Operators** who want to check records in their own environment, with keys they pinned themselves.
- **Developers** who want a small, dependency-free reference implementation of the record checks.

## Quick start

Requires Node.js 24 or later. Ed25519 works on any Node 24 build; post-quantum ML-DSA-65 signatures need OpenSSL 3.5 or later. From a clone of this repository:

```sh
node bin/parmana-verify.mjs test/vectors/record-whole-record-v3.json test/vectors/trust-whole-record.json
```

```json
{"valid":true,"coverage":"full","errors":[],"checks":{"trustRecordHash":true,"signature":true,"hybridSignatures":true}}
```

The exit code is `0`. A record that has been changed is rejected:

```sh
node bin/parmana-verify.mjs test/vectors/record-tampered-amount.json test/vectors/trust.json
```

The exit code is `1`, and the output lists the failed checks. The test vectors are labelled test material; see [test/vectors/README.md](test/vectors/README.md). For real records, pin the keys you trust (see [Pinning a key](#pinning-a-key)).

## Installation and usage

The package is not published to npm. Run it from a clone of this repository.

```sh
node bin/parmana-verify.mjs <proof.json> <trust.json>
node bin/parmana-verify.mjs key-fingerprint <public-key.pem>
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

## Pinning a key

A signature proves only that a key made it. Before you trust a record, decide which keys you trust, and check that each key is the one its owner published.

1. Get the operator's public key PEM and the `sha256:` fingerprint they published. Get the fingerprint from a source other than the one that gave you the key, such as a signed message or a call to a known number.
2. Run `node bin/parmana-verify.mjs key-fingerprint public-key.pem` on the PEM you received.
3. Compare the two fingerprints character by character. If they differ, do not use the key.
4. Only then add the key to your trust file with that fingerprint.

## Trust rules

A key is used only if all of these hold:

- its PEM hashes to the pinned fingerprint (SHA-256 of the SPKI DER encoding);
- the algorithm named by the signature matches the algorithm in the trust file;
- it is not marked `compromised`;
- the record's `createdAt` is at or after `validFrom` and before `validUntil` (if set).

A compromised key is rejected whatever the timestamp, so signatures it made stay void.

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
- `07-whole-record-coverage.mjs`: what coverage `full` and `legacy` mean, and that a changed covered field is refused.
- `08-hybrid-cutover.mjs`: the `hybridRequiredFrom` cutover, and what it adds to a record created after it.
- `09-unsupported-schema-version.mjs`: a schema version other than 2 or 3 is refused, not guessed at.

Each example exits `0` when it behaves as described, so the set runs in CI.

## Testing

```sh
npm test
```

Run the tests on Node 24. On Node 22 or any runtime without ML-DSA-65, the hybrid tests are skipped. Test keys are generated at run time, labelled "TEST KEY - NOT FOR PRODUCTION", and never written to disk.

The suite covers the legacy signature and hash, hybrid signatures, schema version 3 coverage, the trust rules, the test vectors, and the command-line exit codes. Each area has its own file under `test/`.

## Limitations

- The verifier can only check that a record was signed by the key you pinned. It cannot prove that the key belongs to Parmana. That depends on how you obtained and compared the fingerprint.
- For records with `schemaVersion` 2, or with no `schemaVersion`, only the fields listed in [docs/FORMAT.md](docs/FORMAT.md) are protected. Any other field can be changed without the verifier noticing. Read decisions only from covered fields. See "Fields not covered by any signature" in that document.
- For records with `schemaVersion` 3, every field except the signature envelope, `verifications` and `receipts` is protected. Check that `coverage` is `full` when that matters.
- A record with `schemaVersion` 2 can be downgraded by someone who can write to storage, since `schemaVersion` is unsigned. Set `hybridRequiredFrom` in the trust file to reject downgraded records created after a cutover. Records before the cutover stay open to this.
- The validity window is checked against the record's `createdAt`, not against the signing time. A record that carries a false `createdAt` is checked against the window for that false time.
- Keys and fingerprints must be kept current. The verifier does not know about rotations or revocations that you have not written into the trust file.
- It does not verify the policy the record cites, the authorization decision logic, or the state of any connector or external system.
- It does not confirm that the action described by the record was executed.
- The records in `test/vectors/` were produced by the Parmana signing code and are test material only. They show that the checks agree with that code; they are not an independent specification.

## Status

This is version 0.3.0. The record formats and the command-line interface may still change before 1.0; each change is listed in [CHANGELOG.md](CHANGELOG.md).

## Repository layout

| Path         | Contents                                                                 |
| ------------ | ------------------------------------------------------------------------ |
| `bin/`       | The `parmana-verify` command-line entry point                            |
| `src/`       | The checks: canonical JSON, hashing, signatures, trust rules             |
| `test/`      | The test suite, and `test/vectors/`, the labelled test records           |
| `examples/`  | Nine runnable examples, run by `npm run examples`                        |
| `docs/`      | `FORMAT.md` (the input and output rules) and `SECURITY-REVIEW.md`        |

## Security

Do not open a public issue for a security problem. Report it through GitHub's private vulnerability reporting: open the **Security** tab and choose **Report a vulnerability**. See [SECURITY.md](SECURITY.md). The scope for an external review is in [docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md).

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before you open a pull request. Run `npm test` on Node 24 first. Every commit must carry a `Signed-off-by` line (`git commit -s`), certifying the [Developer Certificate of Origin](https://developercertificate.org). Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
