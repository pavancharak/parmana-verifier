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
