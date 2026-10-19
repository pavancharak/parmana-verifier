#!/usr/bin/env node
// Usage:
//   parmana-verify <proof.json> <trust.json>
//   parmana-verify key-fingerprint <public-key.pem>
//
// verify exits 0 = valid, 1 = invalid, 2 = usage or read error.
// key-fingerprint prints the "sha256:..." value to pin in a trust file.

import { readFileSync } from "node:fs";
import { verifyExecutionTrustRecord } from "../src/verify.mjs";
import { keyFingerprint, parseTrustPolicy } from "../src/trust.mjs";

const args = process.argv.slice(2);
const USAGE = "usage: parmana-verify <proof.json> <trust.json>\n       parmana-verify key-fingerprint <public-key.pem>";

if (args[0] === "key-fingerprint") {
  if (args.length !== 2) {
    console.error(USAGE);
    process.exit(2);
  }

  try {
    console.log(keyFingerprint(readFileSync(args[1], "utf8")));
    process.exit(0);
  } catch (error) {
    console.error(`key error: ${error.message}`);
    process.exit(2);
  }
}

const [proofPath, trustPath] = args;

if (!proofPath || !trustPath || args.length !== 2) {
  console.error(USAGE);
  process.exit(2);
}

let proof;
let policy;

try {
  proof = JSON.parse(readFileSync(proofPath, "utf8"));
  policy = parseTrustPolicy(JSON.parse(readFileSync(trustPath, "utf8")));
} catch (error) {
  console.error(`read error: ${error.message}`);
  process.exit(2);
}

const result = verifyExecutionTrustRecord(proof, policy.keys, { hybridRequiredFrom: policy.hybridRequiredFrom ?? undefined });

console.log(JSON.stringify(result));

process.exit(result.valid ? 0 : 1);
