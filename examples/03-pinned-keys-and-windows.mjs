// Show how a trust set decides which signatures are accepted: pinned fingerprints, validity windows, and compromised keys.
//
// Keys are generated at runtime. TEST KEY - NOT FOR PRODUCTION.
// Run: node examples/03-pinned-keys-and-windows.mjs
import { generateKeyPairSync } from "node:crypto";
import { keyFingerprint, parseTrustSet } from "../src/trust.mjs";
import { verifyExecutionTrustRecord } from "../src/verify.mjs";
import { decision, heading, signRecordV3 } from "./shared.mjs";

const key = generateKeyPairSync("ed25519");
const publicPem = key.publicKey.export({ type: "spki", format: "pem" });
const otherPem = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" });

function signedRecord(createdAt) {
  return signRecordV3(
    {
      trustRecordId: "tr_example_03",
      businessTransactionId: "bt_example_03",
      transaction: { amount: 100, currency: "INR" },
      authorization: { decision: "allow" },
      overrides: [],
      executions: [],
      createdAt,
      updatedAt: createdAt,
    },
    key.privateKey,
    "example-key",
  );
}

function entry(overrides = {}) {
  return {
    keyId: "example-key",
    algorithm: "ed25519",
    publicKeyPem: publicPem,
    fingerprint: keyFingerprint(publicPem),
    validFrom: "2026-01-01T00:00:00.000Z",
    validUntil: "2027-01-01T00:00:00.000Z",
    compromised: false,
    ...overrides,
  };
}

const record = signedRecord("2026-06-01T00:00:00.000Z");
const cases = [
  ["Pinned fingerprint matches, inside the window", entry()],
  ["Fingerprint pinned from a different key", entry({ fingerprint: keyFingerprint(otherPem) })],
  ["Record created before validFrom", entry({ validFrom: "2026-07-01T00:00:00.000Z" })],
  ["Record created at or after validUntil", entry({ validUntil: "2026-06-01T00:00:00.000Z" })],
  ["Key marked compromised, inside the window", entry({ compromised: true })],
];

heading("Trust decisions for one signed record");
for (const [label, trusted] of cases) {
  const result = verifyExecutionTrustRecord(record, parseTrustSet({ keys: [trusted] }));
  console.log(`${decision(result.valid).padEnd(9)} ${label}`);
  if (!result.valid) console.log(`      reason: ${result.errors[0]}`);
}

heading("Why each rule exists");
console.log("- The fingerprint proves the PEM is the key you pinned, not whatever a server returned.");
console.log("- The window limits which records a key may sign (validUntil is exclusive).");
console.log("- A compromised key is refused whatever the timestamp, so its signatures stay void.");

// Exit 0 when the first case passes and each other case is refused.
const outcomes = cases.map(([, trusted]) => verifyExecutionTrustRecord(record, parseTrustSet({ keys: [trusted] })).valid);
process.exitCode = outcomes[0] === true && outcomes.slice(1).every((v) => v === false) ? 0 : 1;
