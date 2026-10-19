# Changelog

## [0.3.0] - 2026-10-19

- Verifies schema version 3 records: a hybrid envelope over every field except the signature envelope, `verifications` and `receipts`. A change to a field such as `updatedAt` now fails verification.
- Adds `coverage` to the result: `full` for a verified version 3 envelope, `legacy` otherwise.
- Adds an optional `hybridRequiredFrom` cutover to the trust file. Records created at or after it must carry a valid hybrid envelope.
- Rejects records with an unsupported `schemaVersion` (anything other than 2 or 3).
- Adds `test/vectors/record-whole-record-v3.json` and `record-whole-record-v3-updated-at.json`, signed by Parmana's signing code.
- Schema version 2 behavior is unchanged.

## [0.2.0] - 2026-10-18

- Verifies hybrid `signatures` (ML-DSA-65 with Ed25519). Requires Node 24 with OpenSSL 3.5.
- Replaces the public-key map with a trust file. Each key is pinned by SHA-256 fingerprint, with a validity window and a compromised flag.
- Adds `key-fingerprint` to print the pinned value for a PEM key.

## [0.1.0] - 2026-10-18

Initial public release of the proof verifier, separated from the core repository.
