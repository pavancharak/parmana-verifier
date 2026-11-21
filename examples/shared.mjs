// Helpers shared by the examples. Nothing here is part of the verifier itself.
import { createHash, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { canonicalBytes } from "../src/canonical.mjs";
import { canonicalTrustRecord, hybridMessage } from "../src/verify.mjs";

export const VECTORS = new URL("../test/vectors/", import.meta.url);

export function loadVector(name) {
  return JSON.parse(readFileSync(new URL(name, VECTORS), "utf8"));
}

export function heading(title) {
  console.log();
  console.log(title);
  console.log("-".repeat(title.length));
}

export function mark(passed) {
  return passed ? "PASS" : "FAIL";
}

// For cases that are meant to be refused: a failed check means the problem was caught.
export function caught(passed) {
  return passed ? "not triggered" : "CAUGHT";
}

// For cases that must be accepted, or refused, by a trust decision.
export function decision(accepted) {
  return accepted ? "ACCEPTED" : "REFUSED";
}

// Signs a schema version 3 record with one Ed25519 key (single mode), as parmana-core does: the
// hash covers the seven canonical fields, and the signature covers the whole record. TEST KEY.
export function signRecordV3(record, privateKey, keyId) {
  record.schemaVersion = 3;
  record.trustRecordHash = createHash("sha256").update(canonicalBytes(canonicalTrustRecord(record))).digest("hex");
  record.signatures = [
    { algorithm: "ed25519", keyId, signature: sign(null, hybridMessage(record, 3), privateKey).toString("base64") },
  ];
  return record;
}
