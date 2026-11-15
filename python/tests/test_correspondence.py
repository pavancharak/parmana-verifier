import copy

from parmana_verifier.correspondence import (
    check_execution_correspondence,
    check_trust_record_correspondence,
)

AUTH = {
    "nonce": "n-1",
    "businessTransactionHash": "h-authorized",
    "policyContentHash": "p-1",
    "authorityGrantId": "g-1",
}


def correspondence(**overrides):
    value = {
        "schemaVersion": 1,
        "authorizationNonce": "n-1",
        "authorizedContentHash": "h-authorized",
        "dispatchedContentHash": "h-authorized",
        "policyContentHash": "p-1",
        "authorityGrantId": "g-1",
    }
    value.update(overrides)
    return value


def record(executions, authorization=None):
    if authorization is None:
        authorization = {
            "payload": {
                "nonce": "n-1",
                "businessTransactionHash": "h-authorized",
                "policyContentHash": "p-1",
                "authorityGrant": {"grantId": "g-1"},
            }
        }
    return {"authorization": authorization, "executions": executions}


def test_a_matching_correspondence_passes():
    assert check_execution_correspondence(correspondence(), AUTH) == {"status": "passed"}


def test_a_missing_correspondence_is_not_checked_never_passed():
    assert check_execution_correspondence(None, AUTH)["status"] == "not_checked"


def test_dispatched_content_that_differs_fails():
    result = check_execution_correspondence(correspondence(dispatchedContentHash="h-other"), AUTH)
    assert result == {
        "status": "failed",
        "failures": ["dispatched content differs from the authorized content"],
    }


def test_each_missing_or_different_field_is_named():
    result = check_execution_correspondence(
        correspondence(
            authorizationNonce="other",
            authorizedContentHash=None,
            schemaVersion=2,
            policyContentHash="p-2",
            authorityGrantId="g-2",
        ),
        AUTH,
    )
    assert result["status"] == "failed"
    failures = result["failures"]
    assert "unsupported correspondence schemaVersion 2" in failures
    assert "authorizationNonce differs from the authorization" in failures
    assert "authorizedContentHash is missing" in failures
    assert "policyContentHash differs from the authorization" in failures
    assert "authorityGrantId differs from the authorization" in failures


def test_a_record_with_no_authorization_fails_each_execution():
    report = check_trust_record_correspondence(
        record([{"executionId": "e-1", "evidence": {"correspondence": correspondence()}}], authorization={})
    )
    assert report["status"] == "failed"
    assert report["executions"][0]["result"]["status"] == "failed"


def test_an_execution_without_evidence_is_not_checked():
    assert check_trust_record_correspondence(record([{"executionId": "e-1"}]))["status"] == "not_checked"


def test_a_record_with_no_executions_is_not_checked():
    assert check_trust_record_correspondence(record([]))["status"] == "not_checked"


def test_one_failed_execution_makes_the_report_failed():
    report = check_trust_record_correspondence(
        record(
            [
                {"executionId": "e-1", "evidence": {"correspondence": correspondence()}},
                {"executionId": "e-2", "evidence": {"correspondence": correspondence(dispatchedContentHash="h-x")}},
            ]
        )
    )
    assert report["status"] == "failed"


def test_passed_only_when_every_execution_is_checked_and_corresponds():
    report = check_trust_record_correspondence(
        record(
            [
                {"executionId": "e-1", "evidence": {"correspondence": correspondence()}},
                {"executionId": "e-2", "evidence": {"correspondence": correspondence()}},
            ]
        )
    )
    assert report["status"] == "passed"
    assert len(report["executions"]) == 2


def test_an_unchecked_execution_beside_a_passed_one_prevents_passed():
    report = check_trust_record_correspondence(
        record([{"executionId": "e-1", "evidence": {"correspondence": correspondence()}}, {"executionId": "e-2"}])
    )
    assert report["status"] == "not_checked"


def test_an_unknown_dispatched_hash_source_fails_and_the_known_sources_pass():
    assert check_execution_correspondence(correspondence(dispatchedHashSource="gateway"), AUTH) == {"status": "passed"}
    assert check_execution_correspondence(correspondence(dispatchedHashSource="connector-wire"), AUTH) == {"status": "passed"}
    assert check_execution_correspondence(correspondence(dispatchedHashSource="other"), AUTH) == {
        "status": "failed",
        "failures": ["dispatchedHashSource other is not a known source"],
    }


def test_the_record_is_not_modified():
    value = record([{"executionId": "e-1", "evidence": {"correspondence": correspondence()}}])
    before = copy.deepcopy(value)
    check_trust_record_correspondence(value)
    assert value == before
