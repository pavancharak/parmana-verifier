// Offline checks for Policy version 2 evidence, produced by parmana-core.
//
// Two artifacts:
//   1. The evidence chain: decision records, each hashed over its contents and
//      linked to the record before it. The first record links to "genesis".
//   2. A review outcome: the final result of a review. It names the decision it
//      finished (its evidence recordId and hash) and carries its own hash over
//      that reference, so changing either one breaks the outcome's hash.
//
// The hashes are SHA-256 over the canonical bytes (see canonical.mjs), with the
// hash field set to "" for an evidence record and outcomeHash excluded for an
// outcome. These are the same bytes parmana-core writes; the vectors in
// test/vectors/policy-v2 were produced by parmana-core.
//
// These checks do not evaluate a policy, do not confirm a source's answer, and
// do not confirm that anything was released.

import { createHash } from "node:crypto";
import { canonicalBytes } from "./canonical.mjs";

const sha256Hex = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** The hash of an evidence record: SHA-256 over the record with hash set to "". */
export function evidenceRecordHash(record) {
  return sha256Hex(canonicalBytes({ ...record, hash: "" }));
}

/** Checks each record's hash and its link to the record before it. */
export function verifyEvidenceChain(records) {
  const errors = [];
  let previous = "genesis";
  records.forEach((record, index) => {
    const name = record.recordId ?? `record ${index + 1}`;
    if (record.prevHash !== previous) {
      errors.push(`${name}: prevHash does not link to the record before it.`);
    }
    if (evidenceRecordHash(record) !== record.hash) {
      errors.push(`${name}: hash does not match its contents.`);
    }
    previous = record.hash;
  });
  return { valid: errors.length === 0, records: records.length, errors };
}

/** The hash of a review outcome: SHA-256 over every field except outcomeHash. */
export function reviewOutcomeHash(outcome) {
  const { outcomeHash: _omitted, ...rest } = outcome;
  return sha256Hex(
    canonicalBytes({
      reviewId: rest.reviewId,
      outcome: rest.outcome,
      decidedBy: rest.decidedBy,
      digest: rest.digest,
      at: rest.at,
      decisionRecord: rest.decisionRecord,
    }),
  );
}

/**
 * Checks a review outcome. Its hash must match. If the evidence chain is given,
 * the decision it names must be in the chain, with the same hash.
 */
export function verifyReviewOutcome(outcome, records) {
  const errors = [];
  if (reviewOutcomeHash(outcome) !== outcome.outcomeHash) {
    errors.push("outcomeHash does not match the outcome's contents.");
  }
  if (records !== undefined) {
    const decision = records.find(
      (record) => record.recordId === outcome.decisionRecord?.recordId,
    );
    if (decision === undefined) {
      errors.push(
        `the decision ${outcome.decisionRecord?.recordId} is not in the evidence chain.`,
      );
    } else if (decision.hash !== outcome.decisionRecord.hash) {
      errors.push(
        `the outcome refers to decision ${decision.recordId} with a hash that is not that record's.`,
      );
    }
  }
  return { valid: errors.length === 0, errors };
}
