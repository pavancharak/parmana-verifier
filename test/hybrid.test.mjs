// Hybrid verification (two signatures, Ed25519 and ML-DSA-65). Runs only on Node 24+ with OpenSSL 3.5+.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync, verify as cryptoVerify } from "node:crypto";
import { canonicalBytes } from "../src/canonical.mjs";
import { hybridMessage, verifyExecutionTrustRecord } from "../src/verify.mjs";
import { makeHybridRecord, makeKeyPair, makeMlDsaKeyPair, trustEntry, trustSet } from "./helpers.mjs";

const mlDsaSupported = (() => {
  try {
    generateKeyPairSync("ml-dsa-65");
    return true;
  } catch {
    return false;
  }
})();

const SKIP = mlDsaSupported ? false : "needs Node 24+ with OpenSSL 3.5+ (ML-DSA-65)";

function keysFor(ed, ml) {
  return trustSet(trustEntry("ed-key", "ed25519", ed), trustEntry("ml-key", "dilithium3", ml));
}

test("a hybrid record with both valid signatures verifies", { skip: SKIP }, () => {
  const ed = makeKeyPair();
  const ml = makeMlDsaKeyPair();
  const record = makeHybridRecord({}, { ed, ml });
  const result = verifyExecutionTrustRecord(record, keysFor(ed, ml));
  assert.equal(result.valid, true, result.errors.join("; "));
  assert.equal(result.checks.signatures, true);
});

test("a hybrid record is invalid when its ML-DSA signature is wrong", { skip: SKIP }, () => {
  const ed = makeKeyPair();
  const ml = makeMlDsaKeyPair();
  const other = makeMlDsaKeyPair();
  const record = makeHybridRecord({}, { ed, ml });
  const result = verifyExecutionTrustRecord(record, trustSet(trustEntry("ed-key", "ed25519", ed), trustEntry("ml-key", "dilithium3", other)));
  assert.equal(result.valid, false);
  assert.equal(result.checks.signatures, false);
  assert.match(result.errors.join(" "), /signature verification failed for keyId "ml-key"/);
});

test("a signature made over the version 3 message, relabelled as version 2, is rejected", { skip: SKIP }, () => {
  const ed = makeKeyPair();
  const ml = makeMlDsaKeyPair();
  const record = makeHybridRecord({}, { ed, ml });
  record.schemaVersion = 2;
  const result = verifyExecutionTrustRecord(record, keysFor(ed, ml));
  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /only schemaVersion 3/);
});

test("more than two entries in signatures is rejected", { skip: SKIP }, () => {
  const ed = makeKeyPair();
  const ml = makeMlDsaKeyPair();
  const full = makeHybridRecord({}, { ed, ml });
  const record = makeHybridRecord({}, { ed, ml }, { entries: [...full.signatures, full.signatures[0]] });
  const result = verifyExecutionTrustRecord(record, keysFor(ed, ml));
  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /need one or two/);
});

test("a repeated algorithm in signatures is rejected", { skip: SKIP }, () => {
  const ed = makeKeyPair();
  const ml = makeMlDsaKeyPair();
  const full = makeHybridRecord({}, { ed, ml });
  const record = makeHybridRecord({}, { ed, ml }, { entries: [full.signatures[0], full.signatures[0]] });
  const result = verifyExecutionTrustRecord(record, keysFor(ed, ml));
  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /duplicate algorithm/);
});

test("an unknown algorithm in signatures is rejected", { skip: SKIP }, () => {
  const ed = makeKeyPair();
  const ml = makeMlDsaKeyPair();
  const full = makeHybridRecord({}, { ed, ml });
  const bogus = { algorithm: "rsa", keyId: "ml-key", signature: full.signatures[1].signature };
  const record = makeHybridRecord({}, { ed, ml }, { entries: [full.signatures[0], bogus] });
  const result = verifyExecutionTrustRecord(record, keysFor(ed, ml));
  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /unsupported algorithm: rsa/);
});

test("a dilithium3 entry naming an Ed25519 key is rejected", { skip: SKIP }, () => {
  const ed = makeKeyPair();
  const ml = makeMlDsaKeyPair();
  const full = makeHybridRecord({}, { ed, ml });
  const record = makeHybridRecord({}, { ed, ml }, {
    entries: [full.signatures[0], { ...full.signatures[1], keyId: "ed-key" }],
  });
  const result = verifyExecutionTrustRecord(record, keysFor(ed, ml));
  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /is trusted for ed25519, not dilithium3/);
});

test("a hybrid record whose signed fields were altered is invalid", { skip: SKIP }, () => {
  const ed = makeKeyPair();
  const ml = makeMlDsaKeyPair();
  const record = makeHybridRecord({}, { ed, ml });
  record.transaction.amount = 1;
  const result = verifyExecutionTrustRecord(record, keysFor(ed, ml));
  assert.equal(result.valid, false);
  assert.equal(result.checks.signatures, false);
});

test("malformed signatures are rejected, not treated as absent", { skip: SKIP }, () => {
  const ed = makeKeyPair();
  const ml = makeMlDsaKeyPair();
  const record = makeHybridRecord({}, { ed, ml }, { entries: "not-an-array" });
  const result = verifyExecutionTrustRecord(record, keysFor(ed, ml));
  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /malformed signatures/);
});

test("the Ed25519 entry signs the version 3 message: every covered field plus schemaVersion 3", { skip: SKIP }, () => {
  const ed = makeKeyPair();
  const ml = makeMlDsaKeyPair();
  const record = makeHybridRecord({}, { ed, ml });
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
  const edSig = Buffer.from(record.signatures[0].signature, "base64");

  assert.deepEqual(hybridMessage(record, 3), expected);
  assert.equal(cryptoVerify(null, Buffer.from(expected), createPublicKey(ed.publicPem), edSig), true);
});
