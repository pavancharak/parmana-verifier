// The cutover (hybridRequiredFrom, ADR-0016): a single-entry record is accepted before the cutover and refused at
// or after it, where both hybrid signatures are required.
// Run: node examples/08-hybrid-cutover.mjs
import { parseTrustPolicy } from "../src/trust.mjs";
import { verifyExecutionTrustRecord } from "../src/verify.mjs";
import { decision, heading, loadVector } from "./shared.mjs";

const record = loadVector("parmana-core-generated/v3-single-record.json");
const { keys } = parseTrustPolicy(loadVector("parmana-core-generated/trust-v3-single.json"));
const createdAt = record.createdAt;

function check(label, hybridRequiredFrom) {
  const result = verifyExecutionTrustRecord(record, keys, hybridRequiredFrom ? { hybridRequiredFrom } : {});
  console.log(`${decision(result.valid).padEnd(9)} ${label}`);
  if (!result.valid) console.log(`      reason: ${result.errors[0]}`);
  return result.valid;
}

heading(`Single-entry record created ${createdAt}`);
const none = check("no cutover: single mode accepts one entry", undefined);
const earlier = check("cutover 2026-01-01T00:00:00Z (before the record): both entries required", "2026-01-01T00:00:00Z");
const later = check("cutover 2999-01-01T00:00:00Z (after the record): not yet required", "2999-01-01T00:00:00Z");

const ok = none && !earlier && later;
process.exitCode = ok ? 0 : 1;
