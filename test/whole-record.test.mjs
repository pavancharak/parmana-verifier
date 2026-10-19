// Schema version 3 (whole-record signature) and the hybridRequiredFrom cutover.
// Hybrid cases run only on Node 24+ with OpenSSL 3.5+ (ML-DSA-65).
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as signRaw } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { canonicalBytes } from "../src/canonical.mjs";
import { hybridMessage, verifyExecutionTrustRecord } from "../src/verify.mjs";
import { parseTrustPolicy } from "../src/trust.mjs";
import { makeHybridRecord, makeKeyPair, makeMlDsaKeyPair, makeRecord, trustEntry, trustSet } from "./helpers.mjs";

const mlDsaSupported = (() => {
  try {
    generateKeyPairSync("ml-dsa-65");
    return true;
  } catch {
    return false;
  }
})();

const SKIP = mlDsaSupported ? false : "needs Node 24+ with OpenSSL 3.5+ (ML-DSA-65)";

const vectors = fileURLToPath(new URL("./vectors/", import.meta.url));
const load = (name) => JSON.parse(readFileSync(`${vectors}${name}`, "utf8"));

// Builds a schema version 3 record: the hybrid entries sign the whole record,
// as Parmana's signing code does.
function makeWholeRecord(overrides, { ed, ml }) {
  const record = makeRecord({ schemaVersion: 3, updatedAt: "2026-01-01T00:00:00.000Z", ...overrides }, ed, "ed-key");
  const message = hybridMessage(record, 3);

  record.signatures = [
    { algorithm: "ed25519", keyId: "ed-key", signature: signRaw(null, message, ed.privateKey).toString("base64") },
    { algorithm: "dilithium3", keyId: "ml-key", signature: signRaw(null, message, ml.privateKey).toString("base64") },
  ];

  return record;
}

function keysFor(ed, ml) {
  return trustSet(trustEntry("ed-key", "ed25519", ed), trustEntry("ml-key", "dilithium3", ml));
}

test("a schema version 3 vector verifies with full coverage", { skip: SKIP }, () => {
  const trust = parseTrustPolicy(load("trust-whole-record.json")).keys;
  const result = verifyExecutionTrustRecord(load("record-whole-record-v3.json"), trust);

  assert.equal(result.valid, true, result.errors.join("; "));
  assert.equal(result.coverage, "full");
});

test("a schema version 3 record with a changed updatedAt is rejected, though the hash still matches", { skip: SKIP }, () => {
  const trust = parseTrustPolicy(load("trust-whole-record.json")).keys;
  const result = verifyExecutionTrustRecord(load("record-whole-record-v3-updated-at.json"), trust);

  assert.equal(result.valid, false);
  assert.equal(result.checks.trustRecordHash, true);
  assert.equal(result.checks.hybridSignatures, false);
  assert.equal(result.coverage, "legacy");
});

test("the same updatedAt change on a schema version 2 record is accepted: version 2 does not cover it", { skip: SKIP }, () => {
  const ed = makeKeyPair();
  const ml = makeMlDsaKeyPair();
  const record = makeHybridRecord({ updatedAt: "2026-01-01T00:00:00.000Z" }, { ed, ml }, { schemaVersion: 2 });
  record.updatedAt = "2026-02-01T00:00:00.000Z";

  const result = verifyExecutionTrustRecord(record, keysFor(ed, ml));

  assert.equal(result.valid, true, result.errors.join("; "));
  assert.equal(result.coverage, "legacy");
});

test("a schema version 3 record does not cover verifications or receipts", { skip: SKIP }, () => {
  const ed = makeKeyPair();
  const ml = makeMlDsaKeyPair();
  const record = makeWholeRecord({}, { ed, ml });
  record.verifications = [{ verificationId: "v_1", status: "VERIFIED" }];
  record.receipts = [{ receiptId: "r_1", signature: "not checked here" }];

  const result = verifyExecutionTrustRecord(record, keysFor(ed, ml));

  assert.equal(result.valid, true, result.errors.join("; "));
  assert.equal(result.coverage, "full");
});

test("a schema version 3 record relabelled as version 2 is rejected", { skip: SKIP }, () => {
  const ed = makeKeyPair();
  const ml = makeMlDsaKeyPair();
  const record = makeWholeRecord({}, { ed, ml });
  record.schemaVersion = 2;

  const result = verifyExecutionTrustRecord(record, keysFor(ed, ml));

  assert.equal(result.valid, false);
  assert.equal(result.checks.hybridSignatures, false);
});

test("a schema version 3 record with its signatures removed is rejected", () => {
  const ed = makeKeyPair();
  const record = makeRecord({ schemaVersion: 3 }, ed, "ed-key");

  const result = verifyExecutionTrustRecord(record, trustSet(trustEntry("ed-key", "ed25519", ed)));

  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /no signatures array/);
});

test("an unsupported schema version is rejected", () => {
  const ed = makeKeyPair();
  const record = makeRecord({ schemaVersion: 4 }, ed, "ed-key");

  const result = verifyExecutionTrustRecord(record, trustSet(trustEntry("ed-key", "ed25519", ed)));

  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /unsupported schemaVersion 4/);
});

test("a record created at or after hybridRequiredFrom without a hybrid envelope is rejected", () => {
  const ed = makeKeyPair();
  const record = makeRecord({ createdAt: "2026-06-01T00:00:00.000Z" }, ed, "ed-key");
  const trust = trustSet(trustEntry("ed-key", "ed25519", ed));

  const result = verifyExecutionTrustRecord(record, trust, { hybridRequiredFrom: "2026-01-01T00:00:00.000Z" });

  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /hybridRequiredFrom/);
});

test("a record created before hybridRequiredFrom keeps the legacy rules", () => {
  const ed = makeKeyPair();
  const record = makeRecord({ createdAt: "2025-06-01T00:00:00.000Z" }, ed, "ed-key");
  const trust = trustSet(trustEntry("ed-key", "ed25519", ed));

  const result = verifyExecutionTrustRecord(record, trust, { hybridRequiredFrom: "2026-01-01T00:00:00.000Z" });

  assert.equal(result.valid, true, result.errors.join("; "));
  assert.equal(result.coverage, "legacy");
});

test("the cutover is inclusive: a record created exactly at hybridRequiredFrom needs a hybrid envelope", () => {
  const ed = makeKeyPair();
  const record = makeRecord({ createdAt: "2026-01-01T00:00:00.000Z" }, ed, "ed-key");

  const result = verifyExecutionTrustRecord(record, trustSet(trustEntry("ed-key", "ed25519", ed)), {
    hybridRequiredFrom: "2026-01-01T00:00:00.000Z",
  });

  assert.equal(result.valid, false);
});

test("a record after the cutover with a valid hybrid envelope is accepted", { skip: SKIP }, () => {
  const ed = makeKeyPair();
  const ml = makeMlDsaKeyPair();
  const record = makeWholeRecord({ createdAt: "2026-06-01T00:00:00.000Z" }, { ed, ml });

  const result = verifyExecutionTrustRecord(record, keysFor(ed, ml), { hybridRequiredFrom: "2026-01-01T00:00:00.000Z" });

  assert.equal(result.valid, true, result.errors.join("; "));
  assert.equal(result.coverage, "full");
});

test("parseTrustPolicy reads hybridRequiredFrom and defaults it to null", () => {
  const ed = makeKeyPair();
  const keys = [trustEntry("ed-key", "ed25519", ed)];

  assert.equal(parseTrustPolicy({ keys }).hybridRequiredFrom, null);
  assert.equal(parseTrustPolicy({ keys, hybridRequiredFrom: "2026-01-01T00:00:00.000Z" }).hybridRequiredFrom, "2026-01-01T00:00:00.000Z");
});

test("parseTrustPolicy rejects a cutover without a UTC designator", () => {
  const ed = makeKeyPair();

  assert.throws(
    () => parseTrustPolicy({ keys: [trustEntry("ed-key", "ed25519", ed)], hybridRequiredFrom: "2026-01-01T00:00:00.000" }),
    /ending in "Z"/,
  );
});

test("the schema version 3 message is every covered field plus schemaVersion", () => {
  const record = makeRecord({ updatedAt: "2026-01-01T00:00:00.000Z" }, makeKeyPair(), "ed-key");
  const expected = canonicalBytes({
    trustRecordId: record.trustRecordId,
    businessTransactionId: record.businessTransactionId,
    transaction: record.transaction,
    authorization: record.authorization,
    overrides: record.overrides,
    executions: record.executions,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    trustRecordHash: record.trustRecordHash,
    schemaVersion: 3,
  });

  assert.deepEqual(hybridMessage(record, 3), expected);
});
