// Build an Execution Trust Record step by step, sign it with a test key, and
// verify it. Shows the canonical form that every hash and signature covers.
//
// Keys are generated at runtime. TEST KEY - NOT FOR PRODUCTION.
// Run: node examples/05-build-and-verify-a-record.mjs
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { canonicalBytes } from "../src/canonical.mjs";
import { keyFingerprint, parseTrustSet } from "../src/trust.mjs";
import { canonicalTrustRecord, verifyExecutionTrustRecord } from "../src/verify.mjs";
import { heading } from "./shared.mjs";

heading("1. The fields that are signed");
const record = {
  trustRecordId: "tr_build_1",
  businessTransactionId: "bt_build_1",
  transaction: { amount: 2500, currency: "INR", payee: "vendor-7" },
  authorization: { decision: "allow", policyVersion: "v3" },
  overrides: [],
  executions: [{ executionId: "ex_1", status: "succeeded" }],
  createdAt: "2026-03-01T09:30:00.000Z",
};
console.log("Only these seven fields are covered by the hash and the signature:");
console.log(Object.keys(canonicalTrustRecord(record)).join(", "));

heading("2. Canonical bytes");
// Keys are sorted, arrays keep their order, output is UTF-8 JSON.
const bytes = canonicalBytes(canonicalTrustRecord(record));
console.log(new TextDecoder().decode(bytes).slice(0, 160) + " ...");
console.log(`${bytes.length} bytes`);

heading("3. Hash and sign");
record.trustRecordHash = createHash("sha256").update(bytes).digest("hex");
const key = generateKeyPairSync("ed25519");
record.signature = {
  algorithm: "ed25519",
  keyId: "build-key",
  value: sign(null, bytes, key.privateKey).toString("base64"),
};
console.log(`trustRecordHash ${record.trustRecordHash}`);
console.log(`signature       ${record.signature.value.slice(0, 32)}...`);

heading("4. Pin the key and verify");
const publicPem = key.publicKey.export({ type: "spki", format: "pem" });
const trust = parseTrustSet({
  keys: [
    {
      keyId: "build-key",
      algorithm: "ed25519",
      publicKeyPem: publicPem,
      fingerprint: keyFingerprint(publicPem),
      validFrom: "2026-01-01T00:00:00.000Z",
      validUntil: null,
      compromised: false,
    },
  ],
});
const result = verifyExecutionTrustRecord(record, trust);
console.log(result.valid ? "VALID" : `INVALID: ${result.errors.join(" ")}`);

heading("5. Change one field");
record.transaction.amount = 99999;
const after = verifyExecutionTrustRecord(record, trust);
console.log(after.valid ? "VALID (unexpected)" : "INVALID, as expected: the hash no longer matches.");

process.exitCode = result.valid && !after.valid ? 0 : 1;
