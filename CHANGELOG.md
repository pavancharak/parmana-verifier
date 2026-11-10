# Changelog

## [2.0.1] - 2026-11-10

- Version aligned with the Parmana SDK packages, all at 2.0.1 (`@parmana/sdk`, `parmana`, `@parmana/connector-sdk`, `parmana-connector-sdk`, `@parmana/cli`, `@parmana/shared`, `@parmana/crypto`). Both verifier packages carry 2.0.1: `@parmana/verifier` on npm and `parmana-verifier` on PyPI.
- No verification behavior changed in this release. The 2.0.0 breaking changes below still apply.

## [2.0.0] - 2026-11-07

- **Breaking:** a record with no `schemaVersion`, or with `schemaVersion` 2, is refused by default in both the Node and Python verifiers. Schema version 2 signs only seven top-level fields, so a record outside those fields could be altered without detection. Migration: re-issue the record as schemaVersion 3, or set `"allowLegacyV2": true` in the trust file (Node: `allowLegacyV2` option; Python: `allow_legacy_v2`). The CLI reads the same trust-file field.
- Adds the optional `allowLegacyV2` trust-file field (a boolean, `false` when omitted), validated in both parsers.
- Test vectors and examples that use schema version 2 now opt in explicitly. The AgenTrust cross-check vector opts in in its test, since its trust file is external to this repository.
- Version number: not changed here. The release version is a decision for the owner, because the package versions are aligned with the Parmana SDK packages.

## [1.6.3] - 2026-11-01

- **Breaking:** a record with no hybrid envelope is refused by default. Before, it passed whenever its hash and legacy signature verified, even with no `hybridRequiredFrom` set, so a stripped envelope was accepted. Now it is accepted only if it predates a `hybridRequiredFrom` cutover, or the trust file sets `"allowLegacyOnly": true` and no cutover is set. Migration: if you verify legacy-only records and have no cutover, add `"allowLegacyOnly": true` to your trust file.
- Adds the optional `allowLegacyOnly` trust-file field (a boolean, `false` when omitted), and the matching `allowLegacyOnly` option on `verifyExecutionTrustRecord`.
- The Python package (`python/`) has the same change: the same default refusal, the same `allowLegacyOnly` trust-file field, and the same rules for a record created before or after `hybridRequiredFrom`.
- The sample legacy-only vector `test/vectors/trust-python-ed25519.json` now sets `"allowLegacyOnly": true`, so the README example still verifies.

## [1.6.2] - 2026-10-28

- Version aligned with the Parmana SDK packages (`@parmana/sdk`, `parmana`, `@parmana/connector-sdk`, `parmana-connector-sdk`), all at 1.6.2. The `@parmana/verifier` npm package goes from 0.3.0 to 1.6.2, and the `parmana-verifier` PyPI package from 0.1.0 to 1.6.2.
- No verification code changed. The Node CLI is unchanged since 0.3.0. The Python package has only documentation changes since 0.1.0.

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
