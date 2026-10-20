// What the record's coverage level means, and what a schema version 3 record
// protects. A version 3 envelope covers every field except the signature
// envelope, verifications and receipts. A changed covered field is refused.
// Run: node examples/07-whole-record-coverage.mjs
import { parseTrustPolicy } from "../src/trust.mjs";
import { verifyExecutionTrustRecord } from "../src/verify.mjs";
import { caught, decision, heading, loadVector } from "./shared.mjs";

const policy = parseTrustPolicy(loadVector("trust-whole-record.json"));
const options = { hybridRequiredFrom: policy.hybridRequiredFrom ?? undefined };

heading("1. A version 3 record: coverage is full");
const v3 = verifyExecutionTrustRecord(loadVector("record-whole-record-v3.json"), policy.keys, options);
console.log(`${decision(v3.valid)}  coverage=${v3.coverage}`);

heading("2. A version 2 record: coverage is legacy");
const v2 = verifyExecutionTrustRecord(loadVector("record-explicit-v2.json"), parseTrustPolicy(loadVector("trust.json")).keys);
console.log(`${decision(v2.valid)}  coverage=${v2.coverage}`);
console.log("Read decisions from version 2 records only through the fields the format document lists.");

heading("3. A covered field changed (updatedAt)");
const changed = verifyExecutionTrustRecord(loadVector("record-whole-record-v3-updated-at.json"), policy.keys, options);
console.log(`${decision(changed.valid)}  ${caught(changed.valid)}`);
console.log(`reason: ${changed.errors[0] ?? "none"}`);

const ok = v3.valid && v3.coverage === "full" && v2.valid && v2.coverage === "legacy" && !changed.valid;
if (!ok) {
  throw new Error("coverage example did not behave as described");
}
console.log("\nAll checks in this example behaved as described.");
