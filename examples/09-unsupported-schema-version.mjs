// The verifier knows schema versions 2 and 3 only. Any other value is refused,
// never guessed at, so a record with an unknown version cannot pass as a known one.
// Run: node examples/09-unsupported-schema-version.mjs
import { parseTrustPolicy } from "../src/trust.mjs";
import { verifyExecutionTrustRecord } from "../src/verify.mjs";
import { decision, heading, loadVector } from "./shared.mjs";

const { keys } = parseTrustPolicy(loadVector("trust-whole-record.json"));
const original = loadVector("record-whole-record-v3.json");

heading("1. A known version (3)");
const known = verifyExecutionTrustRecord(original, keys, {});
console.log(`${decision(known.valid)}  schemaVersion=3`);

heading("2. An unknown version (4)");
const unknown = verifyExecutionTrustRecord({ ...original, schemaVersion: 4 }, keys, {});
console.log(`${decision(unknown.valid)}  schemaVersion=4`);
console.log(`reason: ${unknown.errors.find((e) => e.includes("unsupported schemaVersion")) ?? "none"}`);

const ok = known.valid && !unknown.valid && unknown.errors.some((e) => e.includes("unsupported schemaVersion"));
if (!ok) {
  throw new Error("schema version example did not behave as described");
}
console.log("\nAll checks in this example behaved as described.");
