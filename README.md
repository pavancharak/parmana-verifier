# Parmana Verifier

The Parmana verifier checks an Execution Trust Record offline. It recomputes the record's hash and checks its Ed25519 signature against a public key you supply, without contacting Parmana's services.

## Installation and usage

Requires Node.js 24 or later (ML-DSA-65 support for hybrid records) with OpenSSL 3.5 or later. It has no dependencies.

```sh
node bin/parmana-verify.mjs <proof.json> <public-keys.json>
```

- `proof.json` is the Execution Trust Record.
- `public-keys.json` maps each `keyId` to an Ed25519 public key in SPKI PEM form.

The command prints a JSON result and exits with:

- `0`: the record is valid.
- `1`: the record is invalid. The result lists the failed checks.
- `2`: usage or read error.

## What is tested

Run the tests with:

```sh
node --test test/verify.test.mjs test/hybrid.test.mjs
```

The hybrid tests are skipped on runtimes without ML-DSA-65 support. Node 24.22 runs all 25 tests with none skipped.

`test/verify.test.mjs` checks that:

- a correctly hashed and signed record verifies;
- changing a signed field breaks both the hash and the signature;
- a signature made by a different key is rejected;
- an unknown `keyId` is reported as an error;
- an algorithm other than `ed25519` is rejected;
- a public key that is not Ed25519 is rejected;
- a record over 4096 bytes verifies when signed as a large-message commitment, and when signed raw;
- a commitment signature over a small record is rejected;
- a `__proto__` key is kept in the canonical bytes, and injecting one into a signed record breaks verification;
- a hybrid record verifies when every entry is valid, and fails when any entry is wrong, a second entry is missing, an algorithm repeats or is unknown, a key has the wrong type, the signed fields change, or the schemaVersion differs;
- a record with a `signatures` field must also pass its hybrid entries, so the legacy signature alone is not enough;
- the command-line exit codes are 0, 1 and 2 as described above.

`test/helpers.mjs` generates test keys at runtime. They are labelled "TEST KEY - NOT FOR PRODUCTION" and are never written to disk.

## Limitations

- Hybrid verification follows the rules in this repository's `OfflineVerifier.ts`. It has not yet been checked against a record produced by the repository's own signing code.
- It checks that the record is internally consistent and signed by the key you supply. It does not check that the key belongs to Parmana, or that the key was valid at the time of signing. You must obtain and trust the public keys yourself.
- It does not verify the policy the record cites, the authorization decision logic, or the state of any connector or external system.
- It does not check Parmana's services, the record's history, or whether an action was executed.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE` and `NOTICE`.
