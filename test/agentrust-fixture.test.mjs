// The AgenTrust parmana-server integration's approved refund record (fixture 01), copied unedited.
// It is a schema version 2 record, and its trust file sets the legacy flags. Both are refused under
// decision D24. The fixture is kept as evidence of that refusal; it is not edited here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { verifyExecutionTrustRecord } from "../src/verify.mjs";
import { parseTrustPolicy, parseTrustSet } from "../src/trust.mjs";

const dir = fileURLToPath(new URL("./vectors/", import.meta.url));
const load = (name) => JSON.parse(readFileSync(dir + name, "utf8"));

test("agentrust fixture: its trust file sets removed legacy flags, so it is refused as a whole", () => {
  assert.throws(() => parseTrustPolicy(load("agentrust-trust.json")), /no longer supported/);
});

test("agentrust fixture: the schema version 2 record is refused, with the same keys", () => {
  // Keys only: strip the removed flags, as a verifier on schema version 3 would have to.
  const { keys } = load("agentrust-trust.json");
  const result = verifyExecutionTrustRecord(load("agentrust-refund-approved.json"), parseTrustSet({ keys }));

  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /only schemaVersion 3/);
});
