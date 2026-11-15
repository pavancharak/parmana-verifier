import { test } from "node:test";
import assert from "node:assert/strict";

import { checkExecutionCorrespondence, checkTrustRecordCorrespondence } from "../src/correspondence.mjs";

const AUTH = {
  nonce: "n-1",
  businessTransactionHash: "h-authorized",
  policyContentHash: "p-1",
  authorityGrantId: "g-1",
};

function correspondence(overrides = {}) {
  return {
    schemaVersion: 1,
    authorizationNonce: "n-1",
    authorizedContentHash: "h-authorized",
    dispatchedContentHash: "h-authorized",
    policyContentHash: "p-1",
    authorityGrantId: "g-1",
    ...overrides,
  };
}

function record(executions, authorization = { payload: { nonce: "n-1", businessTransactionHash: "h-authorized", policyContentHash: "p-1", authorityGrant: { grantId: "g-1" } } }) {
  return { authorization, executions };
}

test("a matching correspondence passes", () => {
  assert.deepEqual(checkExecutionCorrespondence(correspondence(), AUTH), { status: "passed" });
});

test("a missing correspondence is not checked, never passed", () => {
  assert.equal(checkExecutionCorrespondence(undefined, AUTH).status, "not_checked");
  assert.equal(checkExecutionCorrespondence(null, AUTH).status, "not_checked");
});

test("dispatched content that differs from the authorized content fails", () => {
  const result = checkExecutionCorrespondence(correspondence({ dispatchedContentHash: "h-other" }), AUTH);
  assert.equal(result.status, "failed");
  assert.deepEqual(result.failures, ["dispatched content differs from the authorized content"]);
});

test("each missing or different field is named, and nothing is skipped", () => {
  const result = checkExecutionCorrespondence(
    correspondence({ authorizationNonce: "other", authorizedContentHash: undefined, schemaVersion: 2, policyContentHash: "p-2", authorityGrantId: "g-2" }),
    AUTH,
  );
  assert.equal(result.status, "failed");
  assert.ok(result.failures.includes("unsupported correspondence schemaVersion 2"));
  assert.ok(result.failures.includes("authorizationNonce differs from the authorization"));
  assert.ok(result.failures.includes("authorizedContentHash is missing"));
  assert.ok(result.failures.includes("policyContentHash differs from the authorization"));
  assert.ok(result.failures.includes("authorityGrantId differs from the authorization"));
});

test("a record with no authorization is not checked, never failed", () => {
  const report = checkTrustRecordCorrespondence(record([{ executionId: "e-1", evidence: { correspondence: correspondence() } }], null));
  assert.equal(report.status, "not_checked");
  assert.equal(report.executions[0].result.status, "not_checked");
  assert.match(report.executions[0].result.reason, /no authorization/);
});

test("an execution without evidence is not checked, so the report is not passed", () => {
  const report = checkTrustRecordCorrespondence(record([{ executionId: "e-1" }]));
  assert.equal(report.status, "not_checked");
});

test("a record with no executions is not checked", () => {
  assert.equal(checkTrustRecordCorrespondence(record([])).status, "not_checked");
});

test("one failed execution makes the report failed, even beside a passed one", () => {
  const report = checkTrustRecordCorrespondence(
    record([
      { executionId: "e-1", evidence: { correspondence: correspondence() } },
      { executionId: "e-2", evidence: { correspondence: correspondence({ dispatchedContentHash: "h-x" }) } },
    ]),
  );
  assert.equal(report.status, "failed");
});

test("passed only when every execution is checked and corresponds", () => {
  const report = checkTrustRecordCorrespondence(
    record([
      { executionId: "e-1", evidence: { correspondence: correspondence() } },
      { executionId: "e-2", evidence: { correspondence: correspondence() } },
    ]),
  );
  assert.equal(report.status, "passed");
  assert.equal(report.executions.length, 2);
});

test("an unchecked execution beside a passed one prevents passed", () => {
  const report = checkTrustRecordCorrespondence(
    record([{ executionId: "e-1", evidence: { correspondence: correspondence() } }, { executionId: "e-2" }]),
  );
  assert.equal(report.status, "not_checked");
});

test("an unknown dispatched hash source fails, and the two known sources pass", () => {
  assert.equal(checkExecutionCorrespondence(correspondence({ dispatchedHashSource: "gateway" }), AUTH).status, "passed");
  assert.equal(checkExecutionCorrespondence(correspondence({ dispatchedHashSource: "connector-wire" }), AUTH).status, "passed");
  assert.deepEqual(checkExecutionCorrespondence(correspondence({ dispatchedHashSource: "other" }), AUTH), {
    status: "failed",
    failures: ["dispatchedHashSource other is not a known source"],
  });
});

test("the record is not modified", () => {
  const input = record([{ executionId: "e-1", evidence: { correspondence: correspondence() } }]);
  const before = JSON.stringify(input);
  checkTrustRecordCorrespondence(input);
  assert.equal(JSON.stringify(input), before);
});
