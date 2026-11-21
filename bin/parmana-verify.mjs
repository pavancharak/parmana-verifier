#!/usr/bin/env node
// Usage:
//   parmana-verify <proof.json> <trust.json>
//   parmana-verify key-fingerprint <public-key.pem>
//   parmana-verify policy-v2 <evidence.json>   (the evidence chain, and any review outcome in it)
//
// verify exits 0 = valid, 1 = invalid, 2 = usage or read error.
// key-fingerprint prints the "sha256:..." value to pin in a trust file.

import { readFileSync } from "node:fs";
import { verifyExecutionTrustRecord } from "../src/verify.mjs";
import { keyFingerprint, parseTrustPolicy } from "../src/trust.mjs";
import { checkTrustRecordCorrespondence } from "../src/correspondence.mjs";
import { verifyEvidenceChain, verifyReviewOutcome } from "../src/policy-v2.mjs";

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

if (args[0] === "policy-v2") {
  // evidence.json: { "records": [...], "outcome": { ... } (optional) }
  if (args.length !== 2) {
    console.error(USAGE);
    process.exit(2);
  }

  let file;

  try {
    file = JSON.parse(readFileSync(args[1], "utf8"));
  } catch (error) {
    console.error(`read error: ${error.message}`);
    process.exit(2);
  }

  if (!Array.isArray(file?.records)) {
    console.error('read error: the file must hold a "records" list.');
    process.exit(2);
  }

  const chain = verifyEvidenceChain(file.records);
  const outcome = file.outcome === undefined ? undefined : verifyReviewOutcome(file.outcome, file.records);
  const valid = chain.valid && (outcome === undefined || outcome.valid);
  console.log(JSON.stringify({ valid, chain, ...(outcome === undefined ? {} : { outcome }) }));
  process.exit(valid ? 0 : 1);
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

// The correspondence report does not change `valid` or the exit code (see src/correspondence.mjs).
console.log(JSON.stringify({ ...result, correspondence: checkTrustRecordCorrespondence(proof) }));

process.exit(result.valid ? 0 : 1);
