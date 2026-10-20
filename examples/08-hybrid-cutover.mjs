// The hybrid cutover. The trust file can say that records created at or after a
// time must carry a valid hybrid envelope. The cutover adds its own refusal to a
// record created after it. It never makes an invalid record valid, and it does
// not touch a record created before it.
// Run: node examples/08-hybrid-cutover.mjs
import { parseTrustPolicy } from "../src/trust.mjs";
import { verifyExecutionTrustRecord } from "../src/verify.mjs";
import { decision, heading, loadVector } from "./shared.mjs";

const CUTOVER_REASON = "hybridRequiredFrom";
const record = loadVector("record-single-entry.json");
const { keys } = parseTrustPolicy(loadVector("trust-whole-record.json"));

function check(cutover) {
  const policy = parseTrustPolicy({ keys: [...keys.values()], hybridRequiredFrom: cutover });
  return verifyExecutionTrustRecord(record, policy.keys, { hybridRequiredFrom: policy.hybridRequiredFrom ?? undefined });
}

heading("1. Cutover before the record was created");
const past = check("2026-01-01T00:00:00.000Z");
console.log(`${decision(past.valid)}  record created ${record.createdAt}, cutover 2026-01-01`);
console.log(`cutover reason given: ${past.errors.some((e) => e.includes(CUTOVER_REASON))}`);

heading("2. Cutover after the record was created");
const future = check("2027-01-01T00:00:00.000Z");
console.log(`${decision(future.valid)}  record created ${record.createdAt}, cutover 2027-01-01`);
console.log(`cutover reason given: ${future.errors.some((e) => e.includes(CUTOVER_REASON))}`);
console.log(`other reasons: ${future.errors.filter((e) => !e.includes(CUTOVER_REASON)).length}`);

heading("3. No cutover set");
const none = verifyExecutionTrustRecord(record, keys);
console.log(`${decision(none.valid)}  no cutover in the trust file`);
console.log(`errors identical to case 2: ${JSON.stringify(none.errors) === JSON.stringify(future.errors.filter((e) => !e.includes(CUTOVER_REASON)))}`);

const ok =
  !past.valid &&
  past.errors.some((e) => e.includes(CUTOVER_REASON)) &&
  !future.valid &&
  !future.errors.some((e) => e.includes(CUTOVER_REASON)) &&
  JSON.stringify(none.errors) === JSON.stringify(future.errors);
if (!ok) {
  throw new Error("cutover example did not behave as described");
}
console.log("\nAll checks in this example behaved as described.");
