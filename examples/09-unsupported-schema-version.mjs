// Only schema version 3 is accepted (decision D24). Any other version, including the discarded version 2,
// is refused before any signature is read.
// Run: node examples/09-unsupported-schema-version.mjs
import { parseTrustPolicy } from "../src/trust.mjs";
import { verifyExecutionTrustRecord } from "../src/verify.mjs";
import { decision, heading, loadVector } from "./shared.mjs";

const { keys } = parseTrustPolicy(loadVector("parmana-core-generated/trust-v3-hybrid.json"));
const original = loadVector("parmana-core-generated/v3-hybrid-record.json");

heading("Schema version 3 is accepted");
const known = verifyExecutionTrustRecord(original, keys);
console.log(`${decision(known.valid)}  schemaVersion=3`);

for (const version of [2, 4]) {
  heading(`Schema version ${version} is refused`);
  const result = verifyExecutionTrustRecord({ ...original, schemaVersion: version }, keys);
  console.log(`${decision(result.valid)}  schemaVersion=${version}`);
  console.log(`reason: ${result.errors.find((e) => e.includes("unsupported schemaVersion")) ?? "none"}`);
  if (result.valid) process.exitCode = 1;
}

process.exitCode = process.exitCode ?? (known.valid ? 0 : 1);
