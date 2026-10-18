// Inspect a hybrid signature envelope: two entries (Ed25519 and ML-DSA-65),
// both verified over the same canonical bytes plus schemaVersion.
//
// Needs Node 24 with OpenSSL 3.5 (ML-DSA-65). On other runtimes this example
// explains what it would check and exits 0.
// Run: node examples/04-hybrid-envelope.mjs
import { generateKeyPairSync } from "node:crypto";
import { parseTrustSet } from "../src/trust.mjs";
import { verifyExecutionTrustRecord } from "../src/verify.mjs";
import { caught, heading, loadVector } from "./shared.mjs";

const mlDsaSupported = (() => {
  try {
    generateKeyPairSync("ml-dsa-65");
    return true;
  } catch {
    return false;
  }
})();

heading("What a hybrid envelope is");
console.log("A record carries the legacy signature plus a signatures array, one entry per algorithm.");
console.log("Each entry is verified over the canonical fields plus schemaVersion (default 2).");
console.log("A record is valid only if every entry verifies, at least two entries are present,");
console.log("and no algorithm repeats.");

if (!mlDsaSupported) {
  heading("Skipped");
  console.log("This runtime has no ML-DSA-65 support. Re-run with Node 24 and OpenSSL 3.5 or later.");
  process.exitCode = 0;
} else {
  const trust = parseTrustSet(loadVector("trust.json"));

  heading("1. A valid hybrid record");
  const valid = verifyExecutionTrustRecord(loadVector("record-explicit-v2.json"), trust);
  for (const entry of loadVector("record-explicit-v2.json").signatures) {
    console.log(`  ${entry.algorithm.padEnd(10)} keyId=${entry.keyId}`);
  }
  console.log(`${valid.checks.hybridSignatures ? "ACCEPTED" : "REFUSED "}  both entries verify`);

  heading("2. The same envelope with one entry removed");
  const single = verifyExecutionTrustRecord(loadVector("record-single-entry.json"), trust);
  console.log(`${caught(single.valid)}  a single-entry envelope is refused`);
  console.log(`      reason: ${single.errors.join(" ")}`);

  heading("3. Changing schemaVersion after signing");
  const v3 = verifyExecutionTrustRecord(loadVector("record-schema-v3.json"), trust);
  console.log(`${caught(v3.checks.hybridSignatures)}  changed schemaVersion is refused by the hybrid entries`);

  // Exit 0 when the valid record passes and the two tampered records are refused.
  process.exitCode = valid.valid && !single.valid && !v3.valid ? 0 : 1;
}
