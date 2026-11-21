// TEST KEY - NOT FOR PRODUCTION.
// Keys are generated at runtime and never written to disk or to the repository.
//
// Builds schema version 3 records (decision D24): the signatures array signs the
// whole record, as parmana-core's signing code does.

import { createHash, generateKeyPairSync, sign as signRaw } from "node:crypto";
import { canonicalBytes } from "../src/canonical.mjs";
import { canonicalTrustRecord, hybridMessage } from "../src/verify.mjs";
import { keyFingerprint, parseTrustSet } from "../src/trust.mjs";

const COMMITMENT_PREFIX = Buffer.from("PARMANA-ED25519-LARGE-MESSAGE-V1\0", "utf8");
export const SCHEMA_VERSION = 3;

export function makeKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKey,
    publicPem: publicKey.export({ type: "spki", format: "pem" }),
  };
}

// TEST KEY - NOT FOR PRODUCTION. ML-DSA-65 key for hybrid tests.
export function makeMlDsaKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ml-dsa-65");
  return {
    privateKey,
    publicPem: publicKey.export({ type: "spki", format: "pem" }),
  };
}

// The record fields, with schemaVersion 3 and an updatedAt that a whole-record signature covers.
function baseFields(overrides) {
  return {
    trustRecordId: "tr_test_1",
    businessTransactionId: "bt_test_1",
    transaction: { amount: 100, currency: "INR", payee: "vendor-a" },
    authorization: { decision: "allow", policyVersion: "v1" },
    overrides: [],
    executions: [{ executionId: "ex_1", status: "succeeded" }],
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
    schemaVersion: SCHEMA_VERSION,
    ...overrides,
  };
}

// Sets trustRecordHash over the seven canonical fields, as parmana-core does.
function hashed(overrides) {
  const record = baseFields(overrides);
  record.trustRecordHash = createHash("sha256").update(canonicalBytes(canonicalTrustRecord(record))).digest("hex");
  return record;
}

// The bytes a signature covers. mode "commitment" signs the large-message commitment instead of the message.
function signedBytes(message, mode) {
  return mode === "commitment"
    ? Buffer.concat([COMMITMENT_PREFIX, createHash("sha512").update(message).digest()])
    : message;
}

// Builds a single-entry record (single mode): one Ed25519 signature over the whole record.
// `mode` controls how the signature is made: "raw" signs the message, "commitment" signs the
// large-message commitment.
export function makeRecord(overrides, keyPair, keyId = "test-key", mode = "raw") {
  const record = hashed(overrides);
  const message = hybridMessage(record, SCHEMA_VERSION);

  record.signatures = [
    {
      algorithm: "ed25519",
      keyId,
      signature: signRaw(null, signedBytes(message, mode), keyPair.privateKey).toString("base64"),
    },
  ];

  return record;
}

// Builds a two-entry record (hybrid): an Ed25519 and an ML-DSA-65 signature over the whole record.
// `entries` replaces the signatures array, so a test can send a malformed or repeated one.
export function makeHybridRecord(overrides, { ed, ml }, { entries } = {}) {
  const record = hashed(overrides);
  const message = hybridMessage(record, SCHEMA_VERSION);

  record.signatures = entries ?? [
    {
      algorithm: "ed25519",
      keyId: "ed-key",
      signature: signRaw(null, message, ed.privateKey).toString("base64"),
    },
    {
      algorithm: "dilithium3",
      keyId: "ml-key",
      signature: signRaw(null, message, ml.privateKey).toString("base64"),
    },
  ];

  return record;
}

// Builds a trust entry for a key pair, pinned to its real fingerprint.
export function trustEntry(keyId, algorithm, keyPair, overrides = {}) {
  return {
    keyId,
    algorithm,
    publicKeyPem: keyPair.publicPem,
    fingerprint: keyFingerprint(keyPair.publicPem),
    validFrom: "2025-01-01T00:00:00.000Z",
    validUntil: null,
    compromised: false,
    ...overrides,
  };
}

// Parses trust entries into the Map the verifier takes.
export function trustSet(...entries) {
  return parseTrustSet({ keys: entries });
}
