// Inspect a hybrid signatures array: two entries (Ed25519 and ML-DSA-65), each verified over the whole record.
// Run: node examples/04-hybrid-envelope.mjs
import { parseTrustPolicy } from "../src/trust.mjs";
import { verifyExecutionTrustRecord } from "../src/verify.mjs";
import { caught, decision, heading, loadVector } from "./shared.mjs";

const hybrid = loadVector("parmana-core-generated/v3-hybrid-record.json");
const hybridPolicy = parseTrustPolicy(loadVector("parmana-core-generated/trust-v3-hybrid.json"));
const single = loadVector("parmana-core-generated/v3-single-record.json");
const singlePolicy = parseTrustPolicy(loadVector("parmana-core-generated/trust-v3-single.json"));

heading("1. The hybrid envelope");
console.log("The record carries one signatures array, one entry per algorithm. Each entry signs the same message:");
console.log("every top-level field except signatures, schemaVersion, verifications and receipts, plus schemaVersion.");
for (const entry of hybrid.signatures) {
  console.log(`  ${entry.algorithm.padEnd(10)} keyId=${entry.keyId}`);
}
const hybridResult = verifyExecutionTrustRecord(hybrid, hybridPolicy.keys, { hybridRequiredFrom: hybridPolicy.hybridRequiredFrom });
console.log(`${decision(hybridResult.valid)}  hybrid record`);

heading("2. A single-entry record, before and after a cutover");
const before = verifyExecutionTrustRecord(single, singlePolicy.keys, {});
const after = verifyExecutionTrustRecord(single, singlePolicy.keys, { hybridRequiredFrom: "2026-01-01T00:00:00.000Z" });
console.log(`${decision(before.valid)}  single entry, no cutover (single mode)`);
console.log(`${decision(after.valid)}  single entry, cutover ${"2026-01-01T00:00:00.000Z"} (both entries required)`);
if (!after.valid) console.log(`      reason: ${after.errors[0]}`);

heading("3. Relabelling the schema version");
const relabelled = verifyExecutionTrustRecord({ ...hybrid, schemaVersion: 2 }, hybridPolicy.keys);
console.log(`${caught(relabelled.valid)}  schemaVersion 2 is refused, whatever the signatures`);
console.log(`      reason: ${relabelled.errors[0]}`);

process.exitCode = hybridResult.valid && before.valid && !after.valid && !relabelled.valid ? 0 : 1;
