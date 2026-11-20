"""Policy version 2 evidence checks. The vectors were produced by parmana-core."""

import copy
import json
from pathlib import Path

from parmana_verifier.policy_v2 import (
    evidence_record_hash,
    review_outcome_hash,
    verify_evidence_chain,
    verify_review_outcome,
)

VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "test" / "vectors" / "policy-v2" / "core-vectors.json").read_text()
)


def test_core_evidence_chain_verifies():
    result = verify_evidence_chain(VECTORS["records"])
    assert result["valid"], result["errors"]
    assert result["records"] == 2


def test_changed_record_breaks_its_hash():
    records = copy.deepcopy(VECTORS["records"])
    records[0]["decision"]["outcome"] = "APPROVE"
    result = verify_evidence_chain(records)
    assert not result["valid"]
    assert "ev-1: hash does not match" in " ".join(result["errors"])


def test_broken_link_is_found():
    records = copy.deepcopy(VECTORS["records"])
    records[1]["prevHash"] = "0" * 64
    records[1]["hash"] = evidence_record_hash(records[1])
    result = verify_evidence_chain(records)
    assert not result["valid"]
    assert "ev-2: prevHash does not link" in " ".join(result["errors"])


def test_core_review_outcome_verifies_against_its_chain():
    result = verify_review_outcome(VECTORS["outcome"], VECTORS["records"])
    assert result["valid"], result["errors"]
    assert review_outcome_hash(VECTORS["outcome"]) == VECTORS["outcome"]["outcomeHash"]


def test_outcome_naming_a_different_hash_fails():
    outcome = copy.deepcopy(VECTORS["outcome"])
    outcome["decisionRecord"]["hash"] = "f" * 64
    assert not verify_review_outcome(outcome, VECTORS["records"])["valid"]


def test_outcome_naming_a_decision_not_in_the_chain_fails():
    outcome = copy.deepcopy(VECTORS["outcome"])
    outcome["decisionRecord"]["recordId"] = "ev-99"
    result = verify_review_outcome(outcome, VECTORS["records"])
    assert not result["valid"]
    assert "ev-99 is not in the evidence chain" in " ".join(result["errors"])


def test_changed_outcome_field_breaks_its_hash():
    outcome = copy.deepcopy(VECTORS["outcome"])
    outcome["outcome"] = "REFUSED"
    assert not verify_review_outcome(outcome)["valid"]
