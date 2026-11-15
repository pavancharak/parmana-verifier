# Test vectors

**TEST KEY - NOT FOR PRODUCTION.** These keys were generated for these tests only. Do not use them to verify real records.

- `trust.json`: trust set with an Ed25519 key (`ed-key`) and an ML-DSA-65 key (`ml-key`), pinned by fingerprint.
- `record-implicit-v2.json`: hybrid record, no `schemaVersion` field. Valid.
- `record-explicit-v2.json`: hybrid record with `schemaVersion: 2`. Valid.
- `record-tampered-amount.json`: `transaction.amount` changed after signing. Invalid.
- `record-schema-v3.json`: `schemaVersion` changed to 3 after signing. Invalid.
- `record-single-entry.json`: only one entry in `signatures`. Invalid.
- `trust-whole-record.json`: trust set for the two schema version 3 vectors below, with `hybridRequiredFrom` set.
- `record-whole-record-v3.json`: schema version 3 hybrid record, signed over the whole record (`updatedAt` included). Valid, `coverage` `full`.
- `record-whole-record-v3-updated-at.json`: the same record with `updatedAt` changed after signing. Invalid, although the hash still matches.

- `record-python-ed25519.json` and `trust-python-ed25519.json`: an Ed25519-only record and trust set, used by the Python quick start. Valid. The Python verifier checks it; the hybrid records above need the Node verifier.
- `record-python-ed25519-tampered.json`: the same record with `transaction.amount` changed after signing. Invalid.

These two were signed with a fixed test key (bytes `0x00` to `0x1f`), generated with the Python verifier's canonicalization.

The records were signed with Parmana's own signing code, so they cross-check this verifier against that code. The signing code's offline verifier gives the same results for each record.

- `agentrust-refund-approved.json` and `agentrust-trust.json`: the approved refund record (fixture 01) from the AgenTrust `parmana-server` integration, copied unedited, with its trust set. The key is a test key generated for that integration's run and is not chained to any trusted issuer. The record has no hybrid envelope, so the trust set sets `allowLegacyOnly`; `coverage` is `legacy`. Valid. Checked by `test/agentrust-fixture.test.mjs`.

## `parmana-core-generated/`: records from parmana-core

**TEST KEY - NOT FOR PRODUCTION.** The records and their trust files were exported from the `parmana-core` working tree at commit `7e9a54fb` by an HTTP declare-then-execute run, once per configuration: hybrid schema v3, hybrid schema v2, and single-algorithm. The keys are generated per run by the test harness. The export harness is not committed in `parmana-core`, so these files are a snapshot, not a regenerating script.

- `v3-record-1..3.json` with `trust-v3.json`: hybrid, schema version 3. Valid, `coverage` `full`.
- `v2-record-1.json` with `trust-v2.json`: hybrid, schema version 2. Refused by default; accepted with `trust-v2-allow-legacy-v2.json` (`allowLegacyV2`).
- `single-record-1.json` with `trust-single.json`: single-algorithm, no envelope. Refused by default; accepted with `trust-single-allow-legacy.json` (`allowLegacyV2` and `allowLegacyOnly`).
- `cases.json`: 22 cases over these records, with tampered copies and trust edits. Both `test/parmana-core-records.test.mjs` (Node) and `python/tests/test_parmana_core_records.py` (Python) read it. The Python suite also runs the Node CLI on every case and requires the two verdicts, checks, coverage and correspondence to agree.

Two details the cases pin down. `coverage` is `full` only when the hybrid signatures verify, so a failed record reports `legacy` even when its schema is version 3. The top-level `signature` covers the seven legacy fields and not `updatedAt`, so an `updatedAt` change is caught by the hybrid signatures alone (`checks.signature` stays `true`).
