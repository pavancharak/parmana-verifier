"""Offline checks for Policy version 2 evidence produced by parmana-core.

Two artifacts, as in src/policy-v2.mjs (the npm implementation):

1. The evidence chain: each decision record is hashed over its contents and
   linked to the record before it. The first links to "genesis".
2. A review outcome: names the decision it finished (recordId and hash), and
   carries its own hash over that reference.

The hashes are SHA-256 over the canonical bytes (see canonical.py). The test
vectors in test/vectors/policy-v2 were produced by parmana-core.

These checks do not evaluate a policy, confirm a source's answer, or confirm
that anything was released.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .canonical import canonical_bytes


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def evidence_record_hash(record: dict[str, Any]) -> str:
    """SHA-256 over the record with its hash set to the empty string."""
    return _sha256_hex(canonical_bytes({**record, "hash": ""}))


def verify_evidence_chain(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Checks each record's hash and its link to the record before it."""
    errors: list[str] = []
    previous = "genesis"
    for index, record in enumerate(records):
        name = record.get("recordId", f"record {index + 1}")
        if record.get("prevHash") != previous:
            errors.append(f"{name}: prevHash does not link to the record before it.")
        if evidence_record_hash(record) != record.get("hash"):
            errors.append(f"{name}: hash does not match its contents.")
        previous = record.get("hash")
    return {"valid": not errors, "records": len(records), "errors": errors}


def review_outcome_hash(outcome: dict[str, Any]) -> str:
    """SHA-256 over every field of the outcome except outcomeHash."""
    return _sha256_hex(
        canonical_bytes(
            {
                "reviewId": outcome.get("reviewId"),
                "outcome": outcome.get("outcome"),
                "decidedBy": outcome.get("decidedBy"),
                "digest": outcome.get("digest"),
                "at": outcome.get("at"),
                "decisionRecord": outcome.get("decisionRecord"),
            }
        )
    )


def verify_review_outcome(
    outcome: dict[str, Any], records: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """The outcome's hash must match. If the chain is given, the decision it names must be in it, with the same hash."""
    errors: list[str] = []
    if review_outcome_hash(outcome) != outcome.get("outcomeHash"):
        errors.append("outcomeHash does not match the outcome's contents.")
    if records is not None:
        reference = outcome.get("decisionRecord") or {}
        decision = next(
            (record for record in records if record.get("recordId") == reference.get("recordId")),
            None,
        )
        if decision is None:
            errors.append(
                f"the decision {reference.get('recordId')} is not in the evidence chain."
            )
        elif decision.get("hash") != reference.get("hash"):
            errors.append(
                f"the outcome refers to decision {decision.get('recordId')} with a hash that is not that record's."
            )
    return {"valid": not errors, "errors": errors}
