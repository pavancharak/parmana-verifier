# Remaining work

Status as of 2026-11-15.

## Done

- **Strict timestamps (VF-001).** The Node verifier now parses timestamps strictly, as the Python verifier does. A timestamp must carry `Z` or a `±hh:mm` offset, and impossible dates are rejected. Merged in PR #32 (`80498b9`). Source: `src/timestamp.mjs`, with tests in `test/timestamp.test.mjs`.
- **ML-DSA-65 checks.** Merged in PR #31. Issue #28 is done.
- **Execution correspondence report (PR #39, merged).** Both verifiers report `correspondence`. A record with no embedded authorization is `not_checked`, not `failed`.
- **Python quick start (merged).** The sample trust file sets `allowLegacyV2`, so the documented command verifies. Both suites test it.
- **Records from parmana-core (merged).** `test/vectors/parmana-core-generated` holds 22 cases over records exported from parmana-core `7e9a54fb`, run by both suites, which must agree.
- **Published verifiers read schema version 3 (2026-11-15).** Checked by running the published 2.0.1 CLIs, and by reading the source of the 0.3.0 npm and 0.1.0 and 1.6.3 PyPI releases.

## Open

- **Schema v3 records (issue #27).** Closed on 2026-11-15. Both verifiers read and verify schema version 3, and the fixtures are in `test/vectors/parmana-core-generated`. The fixtures were exported by parmana-core's test harness, not by the deployed server.
- **Node version.** ML-DSA-65 (`dilithium3`) checks need Node 24 or later with OpenSSL 3.5 or later. On an earlier Node, a record signed with `dilithium3` is refused with an error that says so, not accepted.

## Notes for the next change

- A change to the timestamp rules affects every record check. Run the full test suite, and compare the Node and Python verifiers on the same records.
