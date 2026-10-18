// Show what changes when a signed record is altered, and why re-hashing the
// altered record does not help an attacker.
//
// Run: node examples/02-tamper-detection.mjs
import { createHash } from "node:crypto";
import { canonicalBytes } from "../src/canonical.mjs";
import { parseTrustSet } from "../src/trust.mjs";
import { canonicalTrustRecord, verifyExecutionTrustRecord } from "../src/verify.mjs";
import { caught, heading, loadVector } from "./shared.mjs";

const trust = parseTrustSet(loadVector("trust.json"));
const original = loadVector("record-implicit-v2.json");

heading("1. The original record");
const before = verifyExecutionTrustRecord(original, trust);
console.log(`${before.valid ? "VALID" : "INVALID"}  transaction.amount = ${original.transaction.amount}`);

heading("2. Change the amount, keep the stored hash and signature");
const edited = structuredClone(original);
edited.transaction.amount = 999999;
const afterEdit = verifyExecutionTrustRecord(edited, trust);
console.log(`${caught(afterEdit.checks.trustRecordHash)}  trustRecordHash`);
console.log(`${caught(afterEdit.checks.signature)}  signature`);
console.log(`${caught(afterEdit.checks.hybridSignatures)}  hybrid signatures`);
console.log(`Result: ${afterEdit.valid ? "VALID" : "INVALID"}`);
for (const error of afterEdit.errors) console.log(`  - ${error}`);

heading("3. Change the amount and recompute the hash");
// An attacker can recompute the hash. The signature still fails, because the
// attacker does not hold the signing key.
const rehashed = structuredClone(edited);
rehashed.trustRecordHash = createHash("sha256")
  .update(canonicalBytes(canonicalTrustRecord(rehashed)))
  .digest("hex");
const afterRehash = verifyExecutionTrustRecord(rehashed, trust);
console.log(`${caught(afterRehash.checks.trustRecordHash)}  trustRecordHash (recomputed by the attacker)`);
console.log(`${caught(afterRehash.checks.signature)}  signature (the attacker cannot produce this)`);
console.log(`Result: ${afterRehash.valid ? "VALID" : "INVALID"}`);

heading("4. Why this matters");
console.log("A valid hash alone proves nothing. The signature binds the content to a key you trust.");

// Exit 0 only when every tampered variant is rejected, which is the expected outcome.
process.exitCode = !afterEdit.valid && !afterRehash.valid && before.valid ? 0 : 1;
