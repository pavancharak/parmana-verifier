# Cross-check of AgenTrust Parmana fixtures with parmana-verifier

Date: 2026-11-04

## Question

Does a second, independent verifier (`parmana-verifier`, Node, no dependencies) agree with the custom checker used by the AgenTrust `parmana-server` integration (`parmana_evidence.py`)?

## Method

1. Extracted Parmana's public signing key from `fixtures/parmana-signing-key.json` (keyId `default`, Ed25519).
2. Computed its fingerprint with `node bin/parmana-verify.mjs key-fingerprint`:
   `sha256:f22816ae6e17b1d0cedb5e0d5532bd1d4a80946a8cf2fbbf95a84705c7c17d26`
3. Built a trust file pinning that key, valid from 2026-01-01, with `allowLegacyOnly: true`. The record has no hybrid envelope, so the verifier refuses it unless this is set.
4. Ran each fixture record through `parmana-verify`.
5. Tampered a copy of the approved record (amount 500 changed to 5000) and re-ran it.

## Results

| Fixture | Verifier result | Exit | Notes |
|---|---|---|---|
| `01-valid-approval.execution-trust-record.json` | valid, `coverage: legacy`, trustRecordHash and signature true | 0 | Agrees with the integration's expectation that this record is approved and signed. |
| Tampered copy of 01 (amount 500 to 5000) | invalid, hash and signature both fail | 1 | Confirms the verifier detects a change to a covered field. |
| `02-refusal.refusal-record.json` | invalid, hash and signature both fail | 1 | Format mismatch, not a finding about the record. See below. |
| `03-replay.refusal-record.json` | invalid, hash and signature both fail | 1 | Same as 02. |

## Interpretation

- **Agreement on the approved record.** The second verifier accepts the approved Execution Trust Record and its signature with the key Parmana published. The integration's `parmana_evidence.py` also accepts it, per its own test suite (18 passing).
- **Refusal records are not in this verifier's scope.** They have a different structure (`refusalRecordId`, `refusalRecordHash`, no trust-record fields). The verifier only handles Execution Trust Records, so it rejects them. This is a scope gap, not evidence that the records are invalid.
- **Coverage is `legacy`.** The record has no `schemaVersion`, so only fields listed in the verifier's `docs/FORMAT.md` are protected. Other fields could change without the verifier noticing.
- **Legacy-only acceptance is a choice.** The record has no hybrid signature envelope. The verifier accepts it only because the trust file sets `allowLegacyOnly: true`. A production trust file should decide this deliberately.
- **Key ownership is not proven.** The verifier confirms only that this key signed the record. It cannot show the key belongs to Parmana.

## What was added to the repo

- PR #29 in `pavancharak/parmana-verifier` (merged): adds the approved record and its trust set as test vectors, plus `test/agentrust-fixture.test.mjs`. Both tests pass, and the full suite passes (63 of 63 at the time).

## Not covered

- Refusal records (02, 03) were not verified. The verifier would need support for that format, or a separate check.
- The key was not checked against any independent source of Parmana's public key.
- No connector or external system was involved, so this says nothing about whether the refund happened.
