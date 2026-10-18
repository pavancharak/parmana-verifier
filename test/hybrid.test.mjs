// Hybrid verification. Runs only on Node 24+ with OpenSSL 3.5+ (ML-DSA-65).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync, verify as crypto_verify } from "node:crypto";
import { canonicalBytes } from "../src/canonical.mjs";
import { canonicalTrustRecord, verifyExecutionTrustRecord } from "../src/verify.mjs";
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
  assert.equal(result.checks.hybridSignatures, true);
});

test("a hybrid record is invalid when its ML-DSA signature is wrong", { skip: SKIP }, () => {
  const ed = makeKeyPair();
  const ml = makeMlDsaKeyPair();
  const other = makeMlDsaKeyPair();
  const record = makeHybridRecord({}, { ed, ml });
  const result = verifyExecutionTrustRecord(record, trustSet(trustEntry("ed-key", "ed25519", ed), trustEntry("ml-key", "dilithium3", other)));
  assert.equal(result.valid, false);
  assert.equal(result.checks.hybridSignatures, false);
  assert.equal(result.checks.signature, true);
});

test("a hybrid signature made over a different schemaVersion is rejected", { skip: SKIP }, () => {
  const ed = makeKeyPair();
  const ml = makeMlDsaKeyPair();
  const record = makeHybridRecord({}, { ed, ml }, { schemaVersion: 2 });
  record.schemaVersion = 3;
  const result = verifyExecutionTrustRecord(record, keysFor(ed, ml));
  assert.equal(result.valid, false);
  assert.equal(result.checks.hybridSignatures, false);
});

test("a single-entry signatures array is rejected", { skip: SKIP }, () => {
  const ed = makeKeyPair();
  const ml = makeMlDsaKeyPair();
  const full = makeHybridRecord({}, { ed, ml });
  const record = makeHybridRecord({}, { ed, ml }, { entries: [full.signatures[0]] });
  const result = verifyExecutionTrustRecord(record, keysFor(ed, ml));
  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /need at least 2/);
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

test("a dilithium3 entry with an Ed25519 key is rejected", { skip: SKIP }, () => {
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
  assert.equal(result.checks.hybridSignatures, false);
});

test("malformed signatures are rejected, not treated as absent", { skip: SKIP }, () => {
  const ed = makeKeyPair();
  const ml = makeMlDsaKeyPair();
  const record = makeHybridRecord({}, { ed, ml }, { entries: "not-an-array" });
  const result = verifyExecutionTrustRecord(record, keysFor(ed, ml));
  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /malformed signatures/);
});

test("the hybrid message is the canonical fields plus schemaVersion", { skip: SKIP }, () => {
  const ed = makeKeyPair();
  const ml = makeMlDsaKeyPair();
  const record = makeHybridRecord({}, { ed, ml });
  const expected = canonicalBytes({ ...canonicalTrustRecord(record), schemaVersion: 2 });
  const edSig = Buffer.from(record.signatures[0].signature, "base64");
  const verify = (alg, data, pem, sig) => crypto_verify(alg, data, createPublicKey(pem), sig);
  assert.equal(verify(null, Buffer.from(expected), ed.publicPem, edSig), true);
});

