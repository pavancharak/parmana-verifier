#!/usr/bin/env node
// Usage: parmana-verify <proof.json> <public-keys.json>
//
// Exit codes: 0 = valid, 1 = invalid, 2 = usage or read error.

import { readFileSync } from "node:fs";
import { verifyExecutionTrustRecord } from "../src/verify.mjs";

const [proofPath, keysPath] = process.argv.slice(2);

if (!proofPath || !keysPath) {
  console.error("usage: parmana-verify <proof.json> <public-keys.json>");
  process.exit(2);
}

let proof;
let publicKeys;

try {
  proof = JSON.parse(readFileSync(proofPath, "utf8"));
  publicKeys = JSON.parse(readFileSync(keysPath, "utf8"));
} catch (error) {
  console.error(`read error: ${error.message}`);
  process.exit(2);
}

const result = verifyExecutionTrustRecord(proof, publicKeys);

console.log(JSON.stringify(result));

process.exit(result.valid ? 0 : 1);
