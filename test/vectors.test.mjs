// Test vectors signed by the repository's own signing code (see test/vectors/README.md).
// Hybrid vectors need Node 24+ with OpenSSL 3.5+ (ML-DSA-65).
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { verifyExecutionTrustRecord } from "../src/verify.mjs";
import { parseTrustSet } from "../src/trust.mjs";

const dir = fileURLToPath(new URL("./vectors/", import.meta.url));
const trustKeys = parseTrustSet(JSON.parse(readFileSync(dir + "trust.json", "utf8")));
const load = (name) => JSON.parse(readFileSync(dir + name, "utf8"));

const mlDsaSupported = (() => {
  try {
    generateKeyPairSync("ml-dsa-65");
    return true;
  } catch {
    return false;
  }
})();
const HYBRID = mlDsaSupported ? {} : { skip: "needs Node 24+ with OpenSSL 3.5+ (ML-DSA-65)" };

test("vector: hybrid record without schemaVersion verifies", HYBRID, () => {
  const result = verifyExecutionTrustRecord(load("record-implicit-v2.json"), trustKeys);
  assert.equal(result.valid, true, result.errors.join("; "));
  assert.equal(result.checks.hybridSignatures, true);
});

test("vector: hybrid record with schemaVersion 2 verifies", HYBRID, () => {
  const result = verifyExecutionTrustRecord(load("record-explicit-v2.json"), trustKeys);
  assert.equal(result.valid, true, result.errors.join("; "));
});

test("vector: changed amount is rejected by the hash", HYBRID, () => {
  const result = verifyExecutionTrustRecord(load("record-tampered-amount.json"), trustKeys);
  assert.equal(result.valid, false);
  assert.equal(result.checks.trustRecordHash, false);
});

test("vector: changed schemaVersion is rejected by the hybrid check", HYBRID, () => {
  const result = verifyExecutionTrustRecord(load("record-schema-v3.json"), trustKeys);
  assert.equal(result.valid, false);
  assert.equal(result.checks.trustRecordHash, true);
  assert.equal(result.checks.hybridSignatures, false);
});

test("vector: a single-entry hybrid envelope is rejected", HYBRID, () => {
  const result = verifyExecutionTrustRecord(load("record-single-entry.json"), trustKeys);
  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /need at least 2/);
});
