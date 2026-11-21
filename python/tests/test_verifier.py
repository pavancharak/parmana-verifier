import base64
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from parmana_verifier.canonical import canonical_bytes, js_number
from parmana_verifier.timestamps import parse_timestamp
from parmana_verifier.trust import parse_trust_policy, key_fingerprint
from parmana_verifier.verify import canonical_trust_record, verify_execution_trust_record, hybrid_message

# Schema version 3 only (decision D24). The vectors are signed by parmana-core's signing code; see test/vectors/README.md.
VECTORS = Path(__file__).resolve().parents[2] / "test" / "vectors" / "parmana-core-generated"
PREFIX = b"PARMANA-ED25519-LARGE-MESSAGE-V1\x00"


def load(name):
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def trust_entry(key_id, private_key, **overrides):
    public = private_key.public_key()
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    entry = {
        "keyId": key_id,
        "algorithm": "ed25519",
        "publicKeyPem": pem,
        "fingerprint": "sha256:" + hashlib.sha256(der).hexdigest(),
        "validFrom": "2026-01-01T00:00:00.000Z",
        "validUntil": None,
        "compromised": False,
    }
    entry.update(overrides)
    return entry


def signed_record(private_key, key_id, body, created="2026-06-01T12:00:00.000Z", mode="raw"):
    """A schema version 3 record with one Ed25519 entry, signed over the whole-record message."""
    record = {
        "trustRecordId": "tr-1",
        "businessTransactionId": "btx-1",
        "transaction": body,
        "authorization": {"approvedBy": "ana"},
        "overrides": None,
        "executions": [{"n": 1}],
        "createdAt": created,
        "updatedAt": created,
        "schemaVersion": 3,
    }
    record["trustRecordHash"] = hashlib.sha256(canonical_bytes(canonical_trust_record(record))).hexdigest()
    message = hybrid_message(record)
    signed = message if mode == "raw" else PREFIX + hashlib.sha512(message).digest()
    record["signatures"] = [
        {
            "algorithm": "ed25519",
            "keyId": key_id,
            "signature": base64.b64encode(private_key.sign(signed)).decode(),
        }
    ]
    return record


def trust_map(*entries):
    return parse_trust_policy({"keys": list(entries)}).keys


# Vectors: the same records the Node verifier tests against (parmana-core-generated/).

def test_server_signed_v3_hybrid_record_verifies():
    record = load("v3-hybrid-record.json")
    trust = parse_trust_policy(load("trust-v3-hybrid.json"))
    result = verify_execution_trust_record(record, trust.keys, trust.hybrid_required_from)
    assert result["valid"] is True, result["errors"]
    assert result["checks"] == {"trustRecordHash": True, "signatures": True}


def test_server_signed_v3_single_record_verifies_with_one_entry():
    record = load("v3-single-record.json")
    trust = parse_trust_policy(load("trust-v3-single.json"))
    assert len(record["signatures"]) == 1
    assert verify_execution_trust_record(record, trust.keys, trust.hybrid_required_from)["valid"] is True


def test_tampered_amount_fails_hash_and_signatures():
    record = load("v3-hybrid-record.json")
    record["transaction"]["signals"]["amount"] = 999
    trust = parse_trust_policy(load("trust-v3-hybrid.json"))
    result = verify_execution_trust_record(record, trust.keys, trust.hybrid_required_from)
    assert result["valid"] is False
    assert result["checks"]["trustRecordHash"] is False
    assert result["checks"]["signatures"] is False


def test_changed_updated_at_is_caught_by_the_signatures_alone():
    record = load("v3-hybrid-record.json")
    record["updatedAt"] = "2026-02-01T00:00:00.000Z"
    trust = parse_trust_policy(load("trust-v3-hybrid.json"))
    result = verify_execution_trust_record(record, trust.keys, trust.hybrid_required_from)
    assert result["checks"] == {"trustRecordHash": True, "signatures": False}


def test_server_signed_record_with_a_field_added_after_signing_is_rejected():
    record = {**load("v3-hybrid-record.json"), "addedAfterSigning": "x"}
    trust = parse_trust_policy(load("trust-v3-hybrid.json"))
    result = verify_execution_trust_record(record, trust.keys, trust.hybrid_required_from)
    assert result["valid"] is False
    assert result["checks"]["signatures"] is False


def test_tampered_ml_dsa_signature_fails_the_check():
    record = load("v3-hybrid-record.json")
    entry = next(item for item in record["signatures"] if item["algorithm"] == "dilithium3")
    value = entry["signature"]
    entry["signature"] = ("A" if value[0] != "A" else "B") + value[1:]
    trust = parse_trust_policy(load("trust-v3-hybrid.json"))
    result = verify_execution_trust_record(record, trust.keys, trust.hybrid_required_from)
    assert result["checks"]["signatures"] is False
    assert result["valid"] is False
    assert any("signature verification failed" in error and "dilithium3" in error for error in result["errors"])


def test_schema_version_2_is_refused():
    record = {**load("v3-single-record.json"), "schemaVersion": 2}
    trust = parse_trust_policy(load("trust-v3-single.json"))
    result = verify_execution_trust_record(record, trust.keys)
    assert result["valid"] is False
    assert "only schemaVersion 3" in result["errors"][0]


def test_single_entry_at_or_after_cutover_is_refused():
    record = load("v3-single-record.json")
    trust = parse_trust_policy(load("trust-v3-single.json"))
    result = verify_execution_trust_record(record, trust.keys, "2026-01-01T00:00:00Z")
    assert result["valid"] is False
    assert "must carry both hybrid signatures" in result["errors"][0]


def test_trust_file_with_a_removed_legacy_flag_is_refused():
    with pytest.raises(ValueError, match="allowLegacyV2 is no longer supported"):
        parse_trust_policy({"keys": [], "allowLegacyV2": True})
    with pytest.raises(ValueError, match="allowLegacyOnly is no longer supported"):
        parse_trust_policy({"keys": [], "allowLegacyOnly": True})


# Canonical serialization, matching ECMAScript Number and JSON.stringify.

@pytest.mark.parametrize(
    "number, expected",
    [
        (1.0, "1"),
        (-0.0, "0"),
        (100.0, "100"),
        (1e20, "100000000000000000000"),
        (1e21, "1e+21"),
        (1e-7, "1e-7"),
        (0.00001, "0.00001"),
        (0.1 + 0.2, "0.30000000000000004"),
        (123.456, "123.456"),
        (5e-324, "5e-324"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
    ],
)
def test_js_number_format(number, expected):
    assert js_number(number) == expected


def test_keys_sort_in_utf16_code_unit_order():
    # U+1F600 is a surrogate pair in UTF-16, so it sorts before U+FFFD.
    value = {"￿": 1, "\U0001F600": 2, "a": 3, "B": 4}
    assert canonical_bytes(value).decode("utf-8") == '{"B":4,"a":3,"\U0001F600":2,"￿":1}'


def test_strings_escape_like_json_stringify():
    value = {"s": "tab\tquote\"ctrl\u0001"}
    assert canonical_bytes(value).decode("utf-8") == '{"s":"tab\\tquote\\"ctrl\\u0001"}'


def test_lone_surrogate_is_escaped_not_emitted_raw():
    value = json.loads('{"s": "\\ud800"}')
    assert canonical_bytes(value) == b'{"s":"\\ud800"}'


def test_integer_beyond_safe_range_is_rounded_as_javascript_does():
    value = json.loads("123456789012345678901234")
    assert canonical_bytes(value) == b"1.2345678901234569e+23"


# Records generated at test time, signed with Ed25519 keys made here.

@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


def test_raw_signature_verifies(key):
    trust = trust_map(trust_entry("main", key))
    record = signed_record(key, "main", {"a": 1})
    result = verify_execution_trust_record(record, trust)
    assert result == {"valid": True, "errors": [], "checks": {"trustRecordHash": True, "signatures": True}}


def test_single_entry_is_accepted_without_a_cutover(key):
    trust = trust_map(trust_entry("main", key))
    assert verify_execution_trust_record(signed_record(key, "main", {"a": 1}), trust)["valid"] is True


def test_large_message_accepts_commitment_signature(key):
    trust = trust_map(trust_entry("main", key))
    body = {"items": ["x" * 200] * 40}
    record = signed_record(key, "main", body, mode="commitment")
    assert verify_execution_trust_record(record, trust)["valid"] is True


def test_small_message_rejects_commitment_signature(key):
    trust = trust_map(trust_entry("main", key))
    record = signed_record(key, "main", {"a": 1}, mode="commitment")
    result = verify_execution_trust_record(record, trust)
    assert result["valid"] is False
    assert result["checks"]["signatures"] is False


def test_tampered_signature_is_rejected(key):
    trust = trust_map(trust_entry("main", key))
    record = signed_record(key, "main", {"a": 1})
    raw = bytearray(base64.b64decode(record["signatures"][0]["signature"]))
    raw[0] ^= 1
    record["signatures"][0]["signature"] = base64.b64encode(bytes(raw)).decode()
    assert verify_execution_trust_record(record, trust)["valid"] is False


def test_unknown_keyid_is_rejected(key):
    trust = trust_map(trust_entry("main", key))
    record = signed_record(key, "nobody", {"a": 1})
    assert "no trusted key" in verify_execution_trust_record(record, trust)["errors"][0]


def test_compromised_key_is_rejected(key):
    trust = trust_map(trust_entry("main", key, compromised=True))
    record = signed_record(key, "main", {"a": 1})
    assert verify_execution_trust_record(record, trust)["valid"] is False
