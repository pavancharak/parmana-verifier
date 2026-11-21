# Operating modes: which trust policy to use

The verifier reads its policy from the trust file, never from environment variables. A policy is fixed and reviewable, and a change to it shows up in review. This page says which policy to use for each state of a parmana-core deployment, and how to move between them.

Every record is schema version 3 (decision D24). The only policy choices are whether one signature is enough, and from when two are required. The tests for both are in `test/operating-modes.test.mjs` and `test/whole-record.test.mjs`.

## The two policies

**1. Single mode.** For a deployment that runs `CRYPTO_MODE=single`. Its records carry one signature, for the configured algorithm (Ed25519 or ML-DSA-65). The trust file lists that key and no cutover:

```json
{
  "keys": [ ... ]
}
```

A record is valid when its hash matches and its one signature verifies over the whole record. Nothing in the record says that a second signature was expected, so this policy gives the assurance of one signature. Say so to anyone who relies on the result.

**2. Hybrid with a cutover.** For a deployment that runs `CRYPTO_MODE=hybrid`. Set the cutover to the moment hybrid signing started:

```json
{
  "keys": [ ... ],
  "hybridRequiredFrom": "2026-11-21T00:00:00Z"
}
```

A record created at or after the cutover must carry both signatures (Ed25519 and ML-DSA-65). A record created before it is accepted with one valid signature, so single-mode records from before the switch keep verifying.

## Removed flags

Earlier verifier versions had `allowLegacyOnly` and `allowLegacyV2` in the trust file. Decision D24 removed them: schema version 2 records and records with no hybrid envelope are no longer accepted by any setting. A trust file that still sets either flag is refused with exit code `2`, and the error names the flag. Remove the flag from the file.

## Moving from single mode to hybrid

1. **Deploy the trust file first.** Set `hybridRequiredFrom` to the moment hybrid signing starts in the core, not earlier. A cutover earlier than that would refuse single-mode records created in between, which are valid.
2. **Turn on hybrid in the core** (`CRYPTO_MODE=hybrid` and its key settings), at or after the cutover instant.
3. **Check the new records.** A record created after the cutover should show `valid: true` with `checks.signatures: true`, and it has two entries in `signatures`. If it is refused with "must carry both hybrid signatures", the core is still signing one entry: stop and check the core's configuration.

## Checking what a deployment runs

The core logs its effective settings once at startup, in the line `effective_crypto_config`. That line shows whether the deployment runs single or hybrid, so you can choose the policy to match. The core's `docs/developer-portal/security/key-management.md` explains where to find it.
