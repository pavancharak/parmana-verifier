# Parmana Verifier

The Parmana verifier checks an Execution Trust Record offline. It recomputes the record's hash, and checks its Ed25519 and, where present, ML-DSA-65 signatures against keys you pin in a trust file. It makes no network calls.

## Installation and usage

Requires Node.js 24 or later with OpenSSL 3.5 or later (for ML-DSA-65). It has no dependencies.

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

- `key-fingerprint` prints the `sha256:` value to pin for a PEM key. Publish that value through a channel you trust, then compare it before you write a trust file.

`verify` prints a JSON result and exits with `0` (valid), `1` (invalid, with reasons), or `2` (usage or read error).

## Trust rules

A key is used only if all of these hold:

- its PEM hashes to the pinned fingerprint (SHA-256 of the SPKI DER encoding);
- the algorithm named by the signature matches the algorithm in the trust file;
- it is not marked `compromised`;
- the record's `createdAt` is at or after `validFrom` and before `validUntil` (if set).

A compromised key is rejected whatever the timestamp, so signatures it made stay void.

## What is tested

Run the tests on Node 24:

```sh
node --test test/verify.test.mjs test/hybrid.test.mjs test/trust.test.mjs test/vectors.test.mjs
```

On Node 22 or any runtime without ML-DSA-65, the hybrid tests are skipped. `test/helpers.mjs` generates test keys at runtime, labelled "TEST KEY - NOT FOR PRODUCTION", and never writes them to disk. The suite on Node 24.22 runs 44 tests with none skipped.

- `test/verify.test.mjs` covers the legacy signature and hash: a valid record verifies; changing a signed field fails; a signature from another key fails; an unknown `keyId` fails; an unsupported algorithm fails; a non-Ed25519 key fails; records over 4096 bytes verify when signed as a commitment or raw; a commitment over a small record is rejected; `__proto__` keys are covered by the hash; and the CLI exit codes.
- `test/hybrid.test.mjs` covers hybrid `signatures`: both entries must verify over the canonical fields plus `schemaVersion`; a single entry, a repeated algorithm, an unknown algorithm, a wrong key type, a wrong `schemaVersion`, changed fields, and malformed entries all fail.
- `test/vectors.test.mjs` checks the records in `test/vectors/`, which were signed by this repository's own signing code. They are labelled TEST KEY - NOT FOR PRODUCTION, and their results match the repository's offline verifier.
- `test/trust.test.mjs` covers the trust rules: a PEM that doesn't match its pinned fingerprint fails; `validFrom` is inclusive and `validUntil` exclusive; a compromised key fails inside its window; an algorithm mismatch fails; an unparseable `createdAt` fails; malformed or duplicate trust entries are rejected; and the `key-fingerprint` command.

## Limitations

- The verifier can only check that a record was signed by the key you pinned. It cannot prove that the key belongs to Parmana. That depends on how you obtained and compared the fingerprint.
- The validity window is checked against the record's `createdAt`, not against the signing time. A record that carries a false `createdAt` is checked against the window for that false time.
- Keys and fingerprints must be kept current. The verifier does not know about rotations or revocations that you have not written into the trust file.
- It does not verify the policy the record cites, the authorization decision logic, or the state of any connector or external system.
- It does not confirm that the action described by the record was executed.
- Hybrid verification follows the rules in this repository's `OfflineVerifier.ts`. It has not yet been checked against a record produced by the repository's own signing code.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE` and `NOTICE`.
