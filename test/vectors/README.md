# Test vectors

**TEST KEY - NOT FOR PRODUCTION.** These keys were generated for these tests only. Do not use them to verify real records.

- `trust.json`: trust set with an Ed25519 key (`ed-key`) and an ML-DSA-65 key (`ml-key`), pinned by fingerprint.
- `record-implicit-v2.json`: hybrid record, no `schemaVersion` field. Valid.
- `record-explicit-v2.json`: hybrid record with `schemaVersion: 2`. Valid.
- `record-tampered-amount.json`: `transaction.amount` changed after signing. Invalid.
- `record-schema-v3.json`: `schemaVersion` changed to 3 after signing. Invalid.
- `record-single-entry.json`: only one entry in `signatures`. Invalid.

The records were signed with Parmana's own signing code, so they cross-check this verifier against that code. The signing code's offline verifier gives the same results for each record.
