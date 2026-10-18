// Verify an Execution Trust Record and explain what each check means.
//
// Run: node examples/01-verify-a-proof.mjs
import { parseTrustSet } from "../src/trust.mjs";
import { verifyExecutionTrustRecord } from "../src/verify.mjs";
import { heading, loadVector, mark } from "./shared.mjs";

// The trust set says which keys are accepted, and pins each one by fingerprint.
const trust = parseTrustSet(loadVector("trust.json"));

// A hybrid record, signed by the repository's own signing code. The trust file
// and the record are both test data (see test/vectors/README.md).
const record = loadVector("record-explicit-v2.json");

heading("1. The record");
console.log(`trustRecordId         ${record.trustRecordId}`);
console.log(`businessTransactionId ${record.businessTransactionId}`);
console.log(`createdAt             ${record.createdAt}`);
console.log(`signatures            ${record.signatures.map((s) => s.algorithm).join(", ")}`);

const result = verifyExecutionTrustRecord(record, trust);

heading("2. The checks");
console.log(`${mark(result.checks.trustRecordHash)}  trustRecordHash`);
console.log("      The stored hash equals the SHA-256 of the canonical record fields.");
console.log(`${mark(result.checks.signature)}  signature (Ed25519, legacy field)`);
console.log("      The Ed25519 key named by signature.keyId signed the same canonical bytes.");
console.log(`${mark(result.checks.hybridSignatures)}  hybrid signatures (Ed25519 + ML-DSA-65)`);
console.log("      Both entries verify over the canonical fields plus schemaVersion.");

heading("3. Result");
console.log(result.valid ? "VALID: every check passed." : `INVALID: ${result.errors.join(" ")}`);

// Exit 0 for a valid record, so this example can run in a script or in CI.
process.exitCode = result.valid ? 0 : 1;
