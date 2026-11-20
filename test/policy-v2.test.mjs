import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  evidenceRecordHash,
  reviewOutcomeHash,
  verifyEvidenceChain,
  verifyReviewOutcome,
} from "../src/policy-v2.mjs";

// Produced by parmana-core's own EvidenceLog and ReviewQueue, not by this verifier.
const vectors = JSON.parse(
  readFileSync(new URL("./vectors/policy-v2/core-vectors.json", import.meta.url), "utf8"),
);
const clone = (value) => JSON.parse(JSON.stringify(value));

test("core's evidence chain verifies", () => {
  const result = verifyEvidenceChain(vectors.records);
  assert.equal(result.valid, true, JSON.stringify(result.errors));
  assert.equal(result.records, 2);
});

test("a changed evidence record breaks its hash", () => {
  const records = clone(vectors.records);
  records[0].decision.outcome = "APPROVE";
  const result = verifyEvidenceChain(records);
  assert.equal(result.valid, false);
  assert.match(result.errors.join("\n"), /ev-1: hash does not match/);
});

test("a broken link between records is found", () => {
  const records = clone(vectors.records);
  records[1].prevHash = "0".repeat(64);
  records[1].hash = evidenceRecordHash(records[1]);
  const result = verifyEvidenceChain(records);
  assert.equal(result.valid, false);
  assert.match(result.errors.join("\n"), /ev-2: prevHash does not link/);
});

test("a dropped record is found, because the next record no longer links", () => {
  const result = verifyEvidenceChain([vectors.records[1]]);
  assert.equal(result.valid, false);
});

test("core's review outcome verifies against its chain", () => {
  const result = verifyReviewOutcome(vectors.outcome, vectors.records);
  assert.equal(result.valid, true, JSON.stringify(result.errors));
  assert.equal(reviewOutcomeHash(vectors.outcome), vectors.outcome.outcomeHash);
});

test("an outcome that names a different decision hash fails", () => {
  const outcome = clone(vectors.outcome);
  outcome.decisionRecord.hash = "f".repeat(64);
  const result = verifyReviewOutcome(outcome, vectors.records);
  assert.equal(result.valid, false);
});

test("an outcome that names a decision not in the chain fails", () => {
  const outcome = clone(vectors.outcome);
  outcome.decisionRecord.recordId = "ev-99";
  const result = verifyReviewOutcome(outcome, vectors.records);
  assert.equal(result.valid, false);
  assert.match(result.errors.join("\n"), /ev-99 is not in the evidence chain/);
});

test("a changed outcome field breaks the outcome hash", () => {
  const outcome = clone(vectors.outcome);
  outcome.outcome = "REFUSED";
  assert.equal(verifyReviewOutcome(outcome).valid, false);
});
