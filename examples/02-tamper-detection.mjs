// Change a field after signing, then show what catches it. A valid hash alone proves nothing.
// Run: node examples/02-tamper-detection.mjs
import { parseTrustPolicy } from "../src/trust.mjs";
import { verifyExecutionTrustRecord } from "../src/verify.mjs";
import { caught, heading, loadVector } from "./shared.mjs";
import { createHash } from "node:crypto";
import { canonicalBytes } from "../src/canonical.mjs";
import { canonicalTrustRecord } from "../src/verify.mjs";

const original = loadVector("parmana-core-generated/v3-hybrid-record.json");
const { keys } = parseTrustPolicy(loadVector("parmana-core-generated/trust-v3-hybrid.json"));

heading("1. The record as signed");
const before = verifyExecutionTrustRecord(original, keys);
console.log(before.valid ? "VALID" : `INVALID: ${before.errors.join(" ")}`);

heading("2. Change the amount, keep the stored hash and signatures");
const edited = structuredClone(original);
edited.transaction.signals.amount = 999;
const afterEdit = verifyExecutionTrustRecord(edited, keys);
console.log(`${caught(afterEdit.checks.trustRecordHash)}  trustRecordHash`);
console.log(`${caught(afterEdit.checks.signatures)}  signatures`);

heading("3. Change the amount and recompute the hash");
const rehashed = structuredClone(edited);
rehashed.trustRecordHash = createHash("sha256").update(canonicalBytes(canonicalTrustRecord(rehashed))).digest("hex");
const afterRehash = verifyExecutionTrustRecord(rehashed, keys);
console.log(`${caught(afterRehash.checks.trustRecordHash)}  trustRecordHash (the attacker can make this match)`);
console.log(`${caught(afterRehash.checks.signatures)}  signatures (the attacker cannot produce these)`);

heading("4. Add a field the signer never saw");
const extended = { ...original, addedAfterSigning: "x" };
console.log(`${caught(verifyExecutionTrustRecord(extended, keys).checks.signatures)}  signatures`);

const ok = before.valid && !afterEdit.valid && !afterRehash.valid;
process.exitCode = ok ? 0 : 1;
