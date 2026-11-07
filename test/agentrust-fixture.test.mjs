// The AgenTrust parmana-server integration's approved refund record (fixture 01),
// copied unedited. Its key is a test key generated for that integration's run.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { verifyExecutionTrustRecord } from "../src/verify.mjs";
import { parseTrustPolicy } from "../src/trust.mjs";

const dir = fileURLToPath(new URL("./vectors/", import.meta.url));
const load = (name) => JSON.parse(readFileSync(dir + name, "utf8"));
const trust = parseTrustPolicy(load("agentrust-trust.json"));
// This external vector is a schema version 2 record. Opt in explicitly: the
// trust file belongs to AgenTrust and is not edited here.
const options = { hybridRequiredFrom: trust.hybridRequiredFrom, allowLegacyOnly: trust.allowLegacyOnly, allowLegacyV2: true };

test("agentrust fixture: approved refund record verifies with its pinned key", () => {
  const result = verifyExecutionTrustRecord(load("agentrust-refund-approved.json"), trust.keys, options);
  assert.equal(result.valid, true, result.errors.join("; "));
  assert.equal(result.checks.trustRecordHash, true);
  assert.equal(result.checks.signature, true);
  assert.equal(result.coverage, "legacy");
});

test("agentrust fixture: a changed amount is refused", () => {
  const record = load("agentrust-refund-approved.json");
  const text = JSON.stringify(record).replace(/"500"/, '"5000"').replace(/:500([,}])/, ":5000$1");
  assert.notEqual(text, JSON.stringify(record));
  const result = verifyExecutionTrustRecord(JSON.parse(text), trust.keys, options);
  assert.equal(result.valid, false);
});
