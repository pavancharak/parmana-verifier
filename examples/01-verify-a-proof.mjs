// Verify a schema version 3 hybrid record against its trust file. Both signatures must verify.
// Run: node examples/01-verify-a-proof.mjs
import { parseTrustPolicy } from "../src/trust.mjs";
import { verifyExecutionTrustRecord } from "../src/verify.mjs";
import { heading, loadVector, mark } from "./shared.mjs";

heading("1. Load the record and the trust file");
const record = loadVector("parmana-core-generated/v3-hybrid-record.json");
const policy = parseTrustPolicy(loadVector("parmana-core-generated/trust-v3-hybrid.json"));
console.log(`schemaVersion ${record.schemaVersion}, ${record.signatures.length} signature entries: ${record.signatures.map((s) => s.algorithm).join(", ")}`);

heading("2. Verify");
const result = verifyExecutionTrustRecord(record, policy.keys, { hybridRequiredFrom: policy.hybridRequiredFrom ?? undefined });
console.log(`${mark(result.checks.trustRecordHash)}  trustRecordHash (the seven canonical fields)`);
console.log(`${mark(result.checks.signatures)}  signatures (Ed25519 + ML-DSA-65, over the whole record)`);
console.log(result.valid ? "VALID" : `INVALID: ${result.errors.join(" ")}`);

process.exitCode = result.valid ? 0 : 1;
