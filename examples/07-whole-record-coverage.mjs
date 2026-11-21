// What a schema version 3 record protects. Its signatures cover every top-level field except
// signatures, schemaVersion, verifications and receipts, so a change to any covered field is caught,
// even when the stored hash still matches.
// Run: node examples/07-whole-record-coverage.mjs
import { parseTrustPolicy } from "../src/trust.mjs";
import { verifyExecutionTrustRecord } from "../src/verify.mjs";
import { decision, heading, loadVector } from "./shared.mjs";

const policy = parseTrustPolicy(loadVector("parmana-core-generated/trust-v3-hybrid.json"));
const record = loadVector("parmana-core-generated/v3-hybrid-record.json");

heading("1. The record as signed");
const signed = verifyExecutionTrustRecord(record, policy.keys, { hybridRequiredFrom: policy.hybridRequiredFrom });
console.log(`${decision(signed.valid)}  checks: ${JSON.stringify(signed.checks)}`);

heading("2. updatedAt changed after signing");
const changed = verifyExecutionTrustRecord({ ...record, updatedAt: "2026-02-01T00:00:00.000Z" }, policy.keys);
console.log(`${decision(changed.valid)}  checks: ${JSON.stringify(changed.checks)}`);
console.log("      The hash still matches, because updatedAt is not in the seven hashed fields. The signatures catch it.");

heading("3. verifications and receipts added after signing");
const attached = verifyExecutionTrustRecord(
  { ...record, verifications: [{ verificationId: "v_1" }], receipts: [{ receiptId: "r_1" }] },
  policy.keys,
);
console.log(`${decision(attached.valid)}  checks: ${JSON.stringify(attached.checks)}`);
console.log("      These are attached after signing, so they are not covered and do not break the signatures.");

const ok = signed.valid && !changed.valid && attached.valid;
process.exitCode = ok ? 0 : 1;
