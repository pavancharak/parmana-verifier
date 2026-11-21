# Test vectors

**TEST KEY - NOT FOR PRODUCTION.** These keys were generated for these tests only. Do not use them to verify real records.

All vectors are schema version 3 (decision D24). Schema version 2 records and the legacy top-level `signature` field are no longer accepted, so the earlier vectors were removed.

## `parmana-core-generated/`: records signed by parmana-core's signing code

These files are produced by `scripts/generate-verifier-vectors.ts` in parmana-core, which calls the server's own signing code (`VerificationCrypto`). The canonical bytes therefore come from parmana-core, not from this repository. The script writes the private keys into the directory you give it, and refuses any directory inside the parmana-core checkout. Only the public records and trust files are kept here.

To regenerate (run from a parmana-core checkout, with the output outside it):

```sh
npx tsx scripts/generate-verifier-vectors.ts hybrid /path/outside/repo/hybrid
npx tsx scripts/generate-verifier-vectors.ts single /path/outside/repo/single
```

Copy `record.json` and `trust.json` from each output directory to `v3-hybrid-record.json` and `trust-v3-hybrid.json` (hybrid), or to `v3-single-record.json` and `trust-v3-single.json` (single). Then regenerate `v3-hybrid-record-tampered.json` by changing `transaction.signals.amount` to 999, and run `npm test` and `python -m pytest`. Key ids are fixed by the script (`whole-record-ed`, `whole-record-ml`, `single-record-ed`), so `cases.json` does not change.

- `v3-hybrid-record.json` with `trust-v3-hybrid.json`: two signature entries (Ed25519 `whole-record-ed` and ML-DSA-65 `whole-record-ml`). The trust file sets `hybridRequiredFrom` to `2026-01-01T00:00:00.000Z`, and the record was created `2026-03-01T00:00:00.000Z`, so both entries are required. Valid.
- `v3-single-record.json` with `trust-v3-single.json`: one Ed25519 entry (`single-record-ed`), single mode, created `2026-11-21T00:00:00.000Z`. No cutover. Valid. The same record is refused when a cutover earlier than its creation is set, which the cases and tests check.
- `v3-hybrid-record-tampered.json`: the hybrid record with `transaction.signals.amount` changed to 999 after signing, for the README's tamper example. Refused.
- `cases.json`: 16 cases over these records. Each case names a record, a trust file, optional `tamper` operations (a path and a new value), optional `trustEdits` (remove a key, or set fields on one), optional `trustFields` (top-level fields such as `hybridRequiredFrom`), and the expected verdict. `test/parmana-core-records.test.mjs` (Node) and `python/tests/test_parmana_core_records.py` (Python) both read it, and both must agree on every case.

## Other vectors

- `agentrust-refund-approved.json` and `agentrust-trust.json`: the approved refund record (fixture 01) from the AgenTrust `parmana-server` integration, copied unedited, with its trust set. It is a schema version 2 record, and its trust file sets the removed flags `allowLegacyOnly` and `allowLegacyV2`. Both are refused under decision D24. `test/agentrust-fixture.test.mjs` pins the refusal. The key is a test key generated for that integration's run and is not chained to any trusted issuer.
- `policy-v2/`: Policy version 2 evidence chain and review outcome, for `parmana-verify policy-v2`. These are a separate format and are unchanged.
