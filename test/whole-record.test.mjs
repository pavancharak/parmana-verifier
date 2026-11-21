// Schema version 3 (whole-record signature), single mode and hybrid, and the hybridRequiredFrom cutover (ADR-0016).
// Hybrid cases run only on Node 24+ with OpenSSL 3.5+ (ML-DSA-65).
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { verifyExecutionTrustRecord } from "../src/verify.mjs";
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

const fixtures = fileURLToPath(new URL("./vectors/parmana-core-generated/", import.meta.url));
const load = (name) => JSON.parse(readFileSync(`${fixtures}${name}`, "utf8"));

// The cutover in the hybrid fixture's trust file is 2026-01-01; its record was created 2026-03-01.
const CUTOVER_BEFORE_RECORD = "2026-01-01T00:00:00.000Z";
const CUTOVER_AFTER_RECORD = "2999-01-01T00:00:00.000Z";

function keysFor(ed, ml) {
  return trustSet(trustEntry("ed-key", "ed25519", ed), trustEntry("ml-key", "dilithium3", ml));
}

test("a server-signed version 3 hybrid record verifies", { skip: SKIP }, () => {
  const trust = parseTrustPolicy(load("trust-v3-hybrid.json")).keys;
  const result = verifyExecutionTrustRecord(load("v3-hybrid-record.json"), trust);

  assert.equal(result.valid, true, result.errors.join("; "));
  assert.deepEqual(result.checks, { trustRecordHash: true, signatures: true });
});

test("a server-signed version 3 single-mode record verifies, with one entry", () => {
  const trust = parseTrustPolicy(load("trust-v3-single.json")).keys;
  const record = load("v3-single-record.json");
  const result = verifyExecutionTrustRecord(record, trust);

  assert.equal(record.signatures.length, 1);
  assert.equal(result.valid, true, result.errors.join("; "));
});

test("a version 3 record with a field added after signing is rejected", { skip: SKIP }, () => {
  const trust = parseTrustPolicy(load("trust-v3-hybrid.json")).keys;
  const record = load("v3-hybrid-record.json");
  // A field the signer never saw. Version 3 covers every top-level field, so the addition fails the signatures.
  const result = verifyExecutionTrustRecord({ ...record, addedAfterSigning: "x" }, trust);

  assert.equal(result.valid, false);
  assert.equal(result.checks.signatures, false);
});

test("a version 3 record with a changed updatedAt is rejected, though the hash still matches", { skip: SKIP }, () => {
  const trust = parseTrustPolicy(load("trust-v3-hybrid.json")).keys;
  const record = { ...load("v3-hybrid-record.json"), updatedAt: "2026-02-01T00:00:00.000Z" };
  const result = verifyExecutionTrustRecord(record, trust);

  assert.equal(result.valid, false);
  assert.equal(result.checks.trustRecordHash, true);
  assert.equal(result.checks.signatures, false);
});

test("a version 3 record does not cover verifications or receipts", { skip: SKIP }, () => {
  const ed = makeKeyPair();
  const ml = makeMlDsaKeyPair();
  const record = makeHybridRecord({}, { ed, ml });
  record.verifications = [{ verificationId: "v_1", status: "VERIFIED" }];
  record.receipts = [{ receiptId: "r_1", signature: "not checked here" }];

  const result = verifyExecutionTrustRecord(record, keysFor(ed, ml));

  assert.equal(result.valid, true, result.errors.join("; "));
});

test("a version 3 record with its signatures removed is rejected", () => {
  const ed = makeKeyPair();
  const record = makeRecord({}, ed, "ed-key");
  delete record.signatures;

  const result = verifyExecutionTrustRecord(record, trustSet(trustEntry("ed-key", "ed25519", ed)));

  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /no signatures array/);
});

test("a single-entry record is accepted without a cutover (single mode)", () => {
  const ed = makeKeyPair();
  const record = makeRecord({ createdAt: "2026-06-01T00:00:00.000Z" }, ed, "ed-key");

  const result = verifyExecutionTrustRecord(record, trustSet(trustEntry("ed-key", "ed25519", ed)));

  assert.equal(result.valid, true, result.errors.join("; "));
});

test("a single-entry record created at or after hybridRequiredFrom is refused: both entries are required", () => {
  const ed = makeKeyPair();
  const record = makeRecord({ createdAt: "2026-06-01T00:00:00.000Z" }, ed, "ed-key");

  const result = verifyExecutionTrustRecord(record, trustSet(trustEntry("ed-key", "ed25519", ed)), {
    hybridRequiredFrom: "2026-01-01T00:00:00.000Z",
  });

  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /must carry both hybrid signatures/);
});

test("a single-entry record created before hybridRequiredFrom is accepted", () => {
  const ed = makeKeyPair();
  const record = makeRecord({ createdAt: "2025-06-01T00:00:00.000Z" }, ed, "ed-key");

  const result = verifyExecutionTrustRecord(record, trustSet(trustEntry("ed-key", "ed25519", ed)), {
    hybridRequiredFrom: "2026-01-01T00:00:00.000Z",
  });

  assert.equal(result.valid, true, result.errors.join("; "));
});

test("the cutover is inclusive: a single-entry record created exactly at hybridRequiredFrom is refused", () => {
  const ed = makeKeyPair();
  const record = makeRecord({ createdAt: "2026-01-01T00:00:00.000Z" }, ed, "ed-key");

  const result = verifyExecutionTrustRecord(record, trustSet(trustEntry("ed-key", "ed25519", ed)), {
    hybridRequiredFrom: "2026-01-01T00:00:00.000Z",
  });

  assert.equal(result.valid, false);
});

test("a hybrid record after the cutover with both entries is accepted", { skip: SKIP }, () => {
  const ed = makeKeyPair();
  const ml = makeMlDsaKeyPair();
  const record = makeHybridRecord({ createdAt: "2026-06-01T00:00:00.000Z" }, { ed, ml });

  const result = verifyExecutionTrustRecord(record, keysFor(ed, ml), { hybridRequiredFrom: "2026-01-01T00:00:00.000Z" });

  assert.equal(result.valid, true, result.errors.join("; "));
});

test("a server-signed single-entry record is refused by a cutover earlier than it, and accepted by a later one", () => {
  const trust = parseTrustPolicy(load("trust-v3-single.json")).keys;
  const record = load("v3-single-record.json");

  const before = verifyExecutionTrustRecord(record, trust, { hybridRequiredFrom: CUTOVER_BEFORE_RECORD });
  const after = verifyExecutionTrustRecord(record, trust, { hybridRequiredFrom: CUTOVER_AFTER_RECORD });

  assert.equal(before.valid, false);
  assert.match(before.errors.join(" "), /must carry both hybrid signatures/);
  assert.equal(after.valid, true, after.errors.join("; "));
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
