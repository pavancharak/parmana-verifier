// TEST KEY - NOT FOR PRODUCTION.
// Keys are generated at runtime and never written to disk or to the repository.

import { createHash, generateKeyPairSync, sign as signRaw } from "node:crypto";
import { canonicalBytes } from "../src/canonical.mjs";
import { canonicalTrustRecord } from "../src/verify.mjs";

const COMMITMENT_PREFIX = Buffer.from("PARMANA-ED25519-LARGE-MESSAGE-V1\0", "utf8");

export function makeKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKey,
    publicPem: publicKey.export({ type: "spki", format: "pem" }),
  };
}

// Builds a record whose hash and signature are valid for its fields.
// `mode` controls how the signature is made: "raw" signs the canonical bytes,
// "commitment" signs the large-message commitment.
export function makeRecord(overrides, keyPair, keyId = "test-key", mode = "raw") {
  const record = {
    trustRecordId: "tr_test_1",
    businessTransactionId: "bt_test_1",
    transaction: { amount: 100, currency: "INR", payee: "vendor-a" },
    authorization: { decision: "allow", policyVersion: "v1" },
    overrides: [],
    executions: [{ executionId: "ex_1", status: "succeeded" }],
    createdAt: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };

  const canonical = canonicalBytes(canonicalTrustRecord(record));
  record.trustRecordHash = createHash("sha256").update(canonical).digest("hex");

  const message =
    mode === "commitment"
      ? Buffer.concat([COMMITMENT_PREFIX, createHash("sha512").update(canonical).digest()])
      : canonical;

  record.signature = {
    algorithm: "ed25519",
    keyId,
    value: signRaw(null, message, keyPair.privateKey).toString("base64"),
  };

  return record;
}
