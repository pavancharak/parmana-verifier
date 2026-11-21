# Changelog

## [Unreleased]

- **Breaking (decision D24): schema version 3 only.** Both verifiers accept only `schemaVersion` 3. Records with `schemaVersion` 2, or with none, are refused before any signature is read. The legacy top-level `signature` field is no longer read, and the `value` name of a signature entry is no longer accepted. No customer or vendor received an earlier record, so there is no migration path.
- **Breaking: the `signatures` array is the whole-record signature.** It has one or two entries. Single mode uses one entry; hybrid uses two (Ed25519 and ML-DSA-65). A two-entry record is never accepted on one valid entry. `hybridRequiredFrom` (ADR-0016) requires both entries at or after the cutover, and one valid entry before it.
- **Breaking: removed trust-file flags.** `allowLegacyOnly` and `allowLegacyV2` are refused with exit `2`. Remove them from trust files.
- **Breaking: result fields.** `coverage` is removed. `checks.signature` and `checks.hybridSignatures` are replaced by `checks.signatures`. The Node and Python results have the same shape.
- The schema version 3 message covers every top-level field except `signatures`, `schemaVersion`, `verifications` and `receipts`, and includes `updatedAt`.
- Replaces the vectors in `test/vectors/parmana-core-generated` with two records signed by parmana-core's own signing code (hybrid and single mode). `cases.json` now has 16 cases, read by both suites. The Node suite's `test/vectors.test.mjs` is removed; its cases are in `test/whole-record.test.mjs` and `test/parmana-core-records.test.mjs`.
- Replaces the quick-start record with the single-mode v3 record. Examples 01 to 09 are rewritten for schema version 3 and run in `npm run examples`.
- Documents: `docs/FORMAT.md` and `docs/OPERATING-MODES.md` describe single mode and the cutover only. `test/vectors/README.md` lists the current vectors.
- `docs/agentrust-fixture-crosscheck.md` and `docs/SECURITY-REVIEW.md` are dated records of earlier checks. Notes at the top say which parts no longer apply.

- Added: `parmana-verify policy-v2` checks a Policy version 2 evidence chain and a review outcome that refers to a decision in it. The checks are the same hashes parmana-core writes; the vectors in `test/vectors/policy-v2` were produced by parmana-core. The Python package does not have this command yet.

## [2.0.3] - 2026-11-15

- Changes the correspondence result for a record that embeds no authorization from `failed` to `not_checked`, in both verifiers. Nothing was compared, so it is not a mismatch. `valid`, the exit code and every other check are unchanged. A record with no authorization is never reported as `passed`. parmana-core's offline check (`ExecutionCorrespondenceOffline`) makes the same change.
- Fixes the Python quick start. `test/vectors/trust-python-ed25519.json` now sets `allowLegacyV2`, because its record is schema version 2 and the verifier refuses that by default. Without it, the command in `python/README.md` exited 1 with `valid: false`. Adds quick-start tests in both suites (`test/quickstart.test.mjs`, `python/tests/test_quickstart.py`).
- Adds `test/vectors/parmana-core-generated`: 22 cases over records exported from parmana-core at `7e9a54fb`, covering schema version 3 (valid), schema version 2 and single-algorithm (refused by default, accepted with the allowances), tampered copies, and trust-file edits. The Node and Python suites read the same cases and must agree.
- Documents what `coverage` means (full only when the hybrid signatures verify) and what `checks.signature` covers (the legacy fields only). No verification behaviour changed.
- Adds an execution correspondence report to the output of both verifiers (Node `src/correspondence.mjs`, Python `parmana_verifier/correspondence.py`). For each execution it checks that the dispatched content hash equals the authorized one, and that the nonce, the business transaction hash, the policy content hash and the authority grant match the record's authorization. Statuses: `passed`, `failed`, and `not_checked`, which is never reported as passed. It mirrors parmana-core's offline check (`ExecutionCorrespondenceOffline`, on its status-events branch, not yet merged).
- The report does not change `valid`, the exit code, or any existing check. The command-line output gains a `correspondence` field.
- Version number: not changed here. The release version is a decision for the owner.

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
