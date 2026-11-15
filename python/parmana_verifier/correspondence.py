"""Execution correspondence: an offline check that what was dispatched is what was authorized.

A separate report from verify_execution_trust_record: it does not change `valid`, and it means
something only for a record whose signatures also verify. Mirrors the Node module
(src/correspondence.mjs) and parmana-core's checkExecutionCorrespondence. Pure string comparison;
the record is not modified.

Statuses per execution: "passed", "failed" (a field is missing, malformed or different, or the record
embeds no authorization) and "not_checked" (no correspondence fields, or no evidence). The report is
"passed" only when every execution was checked and corresponds.
"""

from __future__ import annotations

SUPPORTED_SCHEMA_VERSION = 1


def _non_empty_string(value):
    return isinstance(value, str) and len(value) > 0


def check_execution_correspondence(correspondence, authorization):
    if correspondence is None:
        return {"status": "not_checked", "reason": "record predates the correspondence fields"}

    failures = []

    if correspondence.get("schemaVersion") != SUPPORTED_SCHEMA_VERSION:
        failures.append(f"unsupported correspondence schemaVersion {correspondence.get('schemaVersion')}")

    if not _non_empty_string(correspondence.get("authorizationNonce")):
        failures.append("authorizationNonce is missing")
    elif correspondence["authorizationNonce"] != authorization["nonce"]:
        failures.append("authorizationNonce differs from the authorization")

    if not _non_empty_string(correspondence.get("authorizedContentHash")):
        failures.append("authorizedContentHash is missing")
    elif correspondence["authorizedContentHash"] != authorization["businessTransactionHash"]:
        failures.append("authorizedContentHash differs from the authorization")

    if not _non_empty_string(correspondence.get("dispatchedContentHash")):
        failures.append("dispatchedContentHash is missing")
    elif correspondence["dispatchedContentHash"] != correspondence["authorizedContentHash"]:
        failures.append("dispatched content differs from the authorized content")

    # The source of the dispatched hash is recorded for review. Only the two known values are accepted when the field
    # is present. Whether the two sources must agree is an owner decision; this check does not compare them.
    source = correspondence.get("dispatchedHashSource")
    if source is not None and source not in ("gateway", "connector-wire"):
        failures.append(f"dispatchedHashSource {source} is not a known source")

    if "policyContentHash" in authorization and correspondence.get("policyContentHash") != authorization["policyContentHash"]:
        failures.append("policyContentHash differs from the authorization")

    if "authorityGrantId" in authorization and correspondence.get("authorityGrantId") != authorization["authorityGrantId"]:
        failures.append("authorityGrantId differs from the authorization")

    return {"status": "passed"} if not failures else {"status": "failed", "failures": failures}


def _authorization_of(record):
    authorization = record.get("authorization") if isinstance(record, dict) else None
    payload = authorization.get("payload") if isinstance(authorization, dict) else None

    if not isinstance(payload, dict):
        return None

    result = {"nonce": payload.get("nonce"), "businessTransactionHash": payload.get("businessTransactionHash")}

    if payload.get("policyContentHash") is not None:
        result["policyContentHash"] = payload["policyContentHash"]

    grant = payload.get("authorityGrant")
    if isinstance(grant, dict):
        result["authorityGrantId"] = grant.get("grantId")

    return result


def check_trust_record_correspondence(record):
    authorization = _authorization_of(record)
    raw_executions = record.get("executions") if isinstance(record, dict) else None
    executions = []

    for execution in raw_executions if isinstance(raw_executions, list) else []:
        execution_id = execution.get("executionId")

        if authorization is None:
            result = {"status": "failed", "failures": ["no authorization is embedded in the trust record"]}
        elif execution.get("evidence") is None:
            result = {"status": "not_checked", "reason": "execution has no evidence recorded"}
        else:
            result = check_execution_correspondence(execution["evidence"].get("correspondence"), authorization)

        executions.append({"executionId": execution_id, "result": result})

    if not executions:
        return {"status": "not_checked", "executions": executions}

    statuses = [entry["result"]["status"] for entry in executions]

    if "failed" in statuses:
        status = "failed"
    elif "not_checked" in statuses:
        status = "not_checked"
    else:
        status = "passed"

    return {"status": status, "executions": executions}
