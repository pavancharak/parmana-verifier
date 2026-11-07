# Remaining work

Status as of 2026-11-07.

## Done

- **Strict timestamps (VF-001).** The Node verifier now parses timestamps strictly, as the Python verifier does. A timestamp must carry `Z` or a `±hh:mm` offset, and impossible dates are rejected. Merged in PR #32 (`80498b9`). Source: `src/timestamp.mjs`, with tests in `test/timestamp.test.mjs`.
- **ML-DSA-65 checks.** Merged in PR #31. Issue #28 is done.

## Open

- **Schema v3 records (issue #27).** Still open. It stays open until parmana-core provides server-built fixtures (parmana-core issue #291), so the verifier can be tested against records the server actually produced.
- **Node version.** ML-DSA-65 (`dilithium3`) checks need Node 24 or later with OpenSSL 3.5 or later. On an earlier Node, a record signed with `dilithium3` is refused with an error that says so, not accepted.

## Notes for the next change

- A change to the timestamp rules affects every record check. Run the full test suite, and compare the Node and Python verifiers on the same records.
