# Remaining work

Status as of 2026-11-07.

## Done

- **Strict timestamps (VF-001).** The Node verifier parses timestamps strictly, as the Python verifier does. A timestamp must carry `Z` or a `±hh:mm` offset, and impossible dates are rejected. Merged in PR #32. Source: `src/timestamp.mjs`, tests in `test/timestamp.test.mjs`.
- **ML-DSA-65 checks.** Both verifiers check `dilithium3` (ML-DSA-65) entries. Merged in PR #31 (Python) and earlier in the Node verifier. Issue #28 is closed.
- **Schema version 3 (whole-record) records.** Both verifiers read v3 records and check the whole-record message: every top-level field except `signature`, `signatures`, `schemaVersion`, `verifications` and `receipts`, plus the schema version. Merged in PR #34 (a field added after signing is rejected) and PR #35 (a record signed by the server's own signing code, `test/vectors/record-server-v3.json`, verifies with full coverage in both verifiers).
- **Fixtures from the server.** The v3 vector is written by parmana-core's `scripts/generate-whole-record-v3-fixture.ts` (parmana-core PR #490), not by hand.

## Open

- **Schema v3 on the server (issue #27 and parmana-core #291).** The verifier can read v3. The server still issues v2. Issue #27 stays open until the server issues v3, which is a separate decision and runs Preview first (parmana-core `docs/internal/runbooks/SCHEMA-V3-ROLLOUT.md`).
- **Node version.** ML-DSA-65 needs Node 24 or later with OpenSSL 3.5 or later. On an earlier Node, a record signed with `dilithium3` is refused with an error that says so, not accepted.
- **Python ML-DSA-65 needs `cryptography` 47 or later** for the hybrid check. The verifier's Python package declares this where it depends on `cryptography`.

## Notes for the next change

- A change to the timestamp rules affects every record check. Run the full test suite, and compare the Node and Python verifiers on the same records.
- Any change to the whole-record message must be made in both verifiers, and the server-signed vector must still verify in both.
