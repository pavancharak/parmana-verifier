// Execution correspondence: an offline check that what was dispatched is what
// was authorized. It is a separate report from verifyExecutionTrustRecord: it
// does not change `valid`, and it means something only for a record whose
// signatures also verify. Run both.
//
// Mirrors parmana-core's checkExecutionCorrespondence and
// checkTrustRecordCorrespondenceOffline (packages/shared and packages/crypto).
// Pure string comparison; the caller's record is not modified.
//
// Statuses:
//   "passed"      every required field is present and matches the authorization.
//   "failed"      a field is missing, malformed or different, or the record
//                 embeds no authorization.
//   "not_checked" the record carries no correspondence fields, or an execution
//                 has no evidence. Never reported as passed.
//
// The report's status: "failed" if any execution failed; "not_checked" if no
// execution was checked or any could not be checked; "passed" only when every
// execution was checked and corresponds.

const SUPPORTED_SCHEMA_VERSION = 1;

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

export function checkExecutionCorrespondence(correspondence, authorization) {
  if (correspondence === undefined || correspondence === null) {
    return { status: "not_checked", reason: "record predates the correspondence fields" };
  }

  const failures = [];

  if (correspondence.schemaVersion !== SUPPORTED_SCHEMA_VERSION) {
    failures.push(`unsupported correspondence schemaVersion ${String(correspondence.schemaVersion)}`);
  }

  if (!isNonEmptyString(correspondence.authorizationNonce)) {
    failures.push("authorizationNonce is missing");
  } else if (correspondence.authorizationNonce !== authorization.nonce) {
    failures.push("authorizationNonce differs from the authorization");
  }

  if (!isNonEmptyString(correspondence.authorizedContentHash)) {
    failures.push("authorizedContentHash is missing");
  } else if (correspondence.authorizedContentHash !== authorization.businessTransactionHash) {
    failures.push("authorizedContentHash differs from the authorization");
  }

  if (!isNonEmptyString(correspondence.dispatchedContentHash)) {
    failures.push("dispatchedContentHash is missing");
  } else if (correspondence.dispatchedContentHash !== correspondence.authorizedContentHash) {
    failures.push("dispatched content differs from the authorized content");
  }

  if (authorization.policyContentHash !== undefined && correspondence.policyContentHash !== authorization.policyContentHash) {
    failures.push("policyContentHash differs from the authorization");
  }

  if (authorization.authorityGrantId !== undefined && correspondence.authorityGrantId !== authorization.authorityGrantId) {
    failures.push("authorityGrantId differs from the authorization");
  }

  return failures.length === 0 ? { status: "passed" } : { status: "failed", failures };
}

// The authorization fields correspondence is checked against, from the record.
function authorizationOf(record) {
  const payload = record?.authorization?.payload;

  if (payload === undefined || payload === null) {
    return undefined;
  }

  const authorization = {
    nonce: payload.nonce,
    businessTransactionHash: payload.businessTransactionHash,
  };

  if (payload.policyContentHash !== undefined) {
    authorization.policyContentHash = payload.policyContentHash;
  }

  if (payload.authorityGrant !== undefined && payload.authorityGrant !== null) {
    authorization.authorityGrantId = payload.authorityGrant.grantId;
  }

  return authorization;
}

export function checkTrustRecordCorrespondence(record) {
  const authorization = authorizationOf(record);
  const executions = (Array.isArray(record?.executions) ? record.executions : []).map((execution) => {
    if (authorization === undefined) {
      return {
        executionId: execution.executionId,
        result: { status: "failed", failures: ["no authorization is embedded in the trust record"] },
      };
    }

    if (execution.evidence === undefined || execution.evidence === null) {
      return {
        executionId: execution.executionId,
        result: { status: "not_checked", reason: "execution has no evidence recorded" },
      };
    }

    return {
      executionId: execution.executionId,
      result: checkExecutionCorrespondence(execution.evidence.correspondence, authorization),
    };
  });

  if (executions.length === 0) {
    return { status: "not_checked", executions };
  }

  if (executions.some((entry) => entry.result.status === "failed")) {
    return { status: "failed", executions };
  }

  if (executions.some((entry) => entry.result.status === "not_checked")) {
    return { status: "not_checked", executions };
  }

  return { status: "passed", executions };
}
