# Operating modes: which trust policy to use

The verifier reads its policy from the trust file, never from environment variables. A policy is fixed and reviewable, and a change to it shows up in review. This page says which policy to use for each state of a parmana-core deployment, and how to move between them.

The tests for every mode are in `test/operating-modes.test.mjs`.

## The three policies

**1. Default (no flags).** Refuses any record with no hybrid envelope, and any record with `schemaVersion` 2 or no `schemaVersion`. Use it when every record you verify should be hybrid.

**2. Single mode.** For a deployment that runs `CRYPTO_MODE=single`. Its records have no hybrid envelope, and no `schemaVersion` (or version 2). Set:

```json
{
  "keys": [ ... ],
  "allowLegacyOnly": true,
  "allowLegacyV2": true
}
```

The result is `valid: true` with `coverage: "legacy"`. A record in this state is checked for its seven signed fields and its single signature. It is not checked against a hybrid envelope, so this policy gives less assurance than a hybrid one. Say so to anyone who relies on the result.

**3. Hybrid with a cutover.** For a deployment that runs `CRYPTO_MODE=hybrid`. Set:

```json
{
  "keys": [ ... ],
  "hybridRequiredFrom": "2026-11-21T00:00:00Z"
}
```

A record created at or after the cutover must carry a valid hybrid envelope, whatever its `schemaVersion`. Records created before the cutover are still judged by the rules in policy 2, so they keep working, as long as the flags for them are set.

## The downgrade trade-off

`schemaVersion` is not signed. Someone who can write to storage can change a version-3 record to version 2, and a version-2 record is checked only for its seven fields. That is why `allowLegacyV2` is a choice: while it is set, a version-2 record is accepted without a hybrid check.

The cutover closes this for new records. After `hybridRequiredFrom`, a record with no valid hybrid envelope is refused, whatever its version. So the period in which version-2 records are accepted is the period before the cutover, and nothing else.

## Moving from single mode to hybrid

1. **Deploy the trust file first.** Policy 3 must be in place before hybrid is turned on, so nothing is judged by the wrong rules.
2. **Set `hybridRequiredFrom` to the moment hybrid signing starts** in the core, not earlier. A cutover earlier than that would refuse single-mode records created in between, which are valid.
3. **Turn on hybrid in the core** (`CRYPTO_MODE=hybrid` and its key settings), at or after the cutover instant.
4. **Check the new records.** A new record created after the cutover should show `coverage: "full"`. If it shows `"legacy"` or is refused, stop and check the core's configuration.
5. **Keep the `allowLegacyV2` and `allowLegacyOnly` flags** until every record you need to verify predates the cutover. After that, you can remove them.

## Checking what a deployment runs

The core logs its effective settings once at startup, in the line `effective_crypto_config`. That line shows whether the deployment runs single or hybrid, so you can choose the policy to match. The core's `docs/developer-portal/security/key-management.md` explains where to find it.
