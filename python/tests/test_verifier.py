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

VECTORS = Path(__file__).resolve().parents[2] / "test" / "vectors"
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
    record = {
        "trustRecordId": "tr-1",
        "businessTransactionId": "btx-1",
        "transaction": body,
        "authorization": {"approvedBy": "ana"},
        "overrides": None,
        "executions": [{"n": 1}],
        "createdAt": created,
    }
    message = canonical_bytes(canonical_trust_record(record))
    record["trustRecordHash"] = hashlib.sha256(message).hexdigest()
    signed = message if mode == "raw" else PREFIX + hashlib.sha512(message).digest()
    record["signature"] = {
        "algorithm": "ed25519",
        "keyId": key_id,
        "signature": base64.b64encode(private_key.sign(signed)).decode(),
    }
    return record


def trust_map(*entries):
    return parse_trust_policy({"keys": list(entries)}).keys


# Vectors: the same records the Node verifier tests against.

def test_tampered_record_fails_hash_and_signature():
    trust = parse_trust_policy(load("trust.json"))
    result = verify_execution_trust_record(load("record-tampered-amount.json"), trust.keys)
    assert result["valid"] is False
    assert result["checks"]["trustRecordHash"] is False
    assert result["checks"]["signature"] is False


def test_v2_record_ed25519_part_verifies_and_hybrid_is_reported_unsupported():
    trust = parse_trust_policy(load("trust.json"))
    result = verify_execution_trust_record(load("record-explicit-v2.json"), trust.keys)
    assert result["checks"] == {"trustRecordHash": True, "signature": True, "hybridSignatures": False}
    assert result["valid"] is False
    assert any("dilithium3" in error for error in result["errors"])


def test_whole_record_v3_ed25519_entry_verifies_over_the_v3_message():
    # The ed25519 entry of the v3 vector must verify over the whole-record
    # message. A failure here would mean hybrid_message() builds different bytes.
    record = load("record-whole-record-v3.json")
    trust = parse_trust_policy(load("trust-whole-record.json"))
    result = verify_execution_trust_record(record, trust.keys, trust.hybrid_required_from)
    assert not any("signature verification failed" in error for error in result["errors"])
    ed_entry = next(entry for entry in record["signatures"] if entry["algorithm"] == "ed25519")
    assert ed_entry["keyId"] in trust.keys
    assert hybrid_message(record, 3)


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
    assert result == {"valid": True, "coverage": "legacy", "errors": [], "checks": {"trustRecordHash": True, "signature": True}}


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
    assert result["checks"]["signature"] is False


def test_tampered_signature_is_rejected(key):
    trust = trust_map(trust_entry("main", key))
    record = signed_record(key, "main", {"a": 1})
    raw = bytearray(base64.b64decode(record["signature"]["signature"]))
    raw[0] ^= 1
    record["signature"]["signature"] = base64.b64encode(bytes(raw)).decode()
    assert verify_execution_trust_record(record, trust)["valid"] is False


def test_unknown_keyid_is_rejected(key):
    trust = trust_map(trust_entry("main", key))
    record = signed_record(key, "nobody", {"a": 1})
    assert "no trusted key" in verify_execution_trust_record(record, trust)["errors"][0]


def test_compromised_key_is_rejected(key):
    trust = trust_map(trust_entry("main", key, compromised=True))
    record = signed_record(key, "main", {"a": 1})
    assert verify_execution_trust_record(record, trust)["valid"] is False


def test_record_before_validity_window_is_rejected(key):
    trust = trust_map(trust_entry("main", key, validFrom="2026-07-01T00:00:00.000Z"))
    record = signed_record(key, "main", {"a": 1}, created="2026-06-01T00:00:00Z")
    result = verify_execution_trust_record(record, trust)
    assert result["valid"] is False
    assert "outside the validity window" in result["errors"][0]


def test_record_after_validity_end_is_rejected(key):
    trust = trust_map(trust_entry("main", key, validUntil="2026-05-01T00:00:00.000Z"))
    record = signed_record(key, "main", {"a": 1}, created="2026-06-01T00:00:00Z")
    assert verify_execution_trust_record(record, trust)["valid"] is False


def test_cutover_requires_hybrid_envelope_for_later_records(key):
    trust = trust_map(trust_entry("main", key))
    record = signed_record(key, "main", {"a": 1}, created="2026-06-01T12:00:00Z")
    result = verify_execution_trust_record(record, trust, "2026-01-01T00:00:00.000Z")
    assert result["valid"] is False
    assert "hybridRequiredFrom" in result["errors"][-1]


def test_cutover_does_not_apply_to_earlier_records(key):
    trust = trust_map(trust_entry("main", key, validFrom="2024-01-01T00:00:00.000Z"))
    record = signed_record(key, "main", {"a": 1}, created="2025-06-01T12:00:00Z")
    assert verify_execution_trust_record(record, trust, "2026-01-01T00:00:00.000Z")["valid"] is True


def test_fingerprint_mismatch_is_rejected(key):
    entry = trust_entry("main", key)
    entry["fingerprint"] = "sha256:" + "0" * 64
    result = verify_execution_trust_record(signed_record(key, "main", {"a": 1}), trust_map(entry))
    assert result["valid"] is False
    assert "pinned fingerprint" in result["errors"][0]


def test_non_object_record_is_rejected():
    result = verify_execution_trust_record(["not", "an", "object"], {})
    assert result == {"valid": False, "coverage": "legacy", "errors": ["record must be a JSON object"], "checks": {}}


def test_key_fingerprint_matches_trust_entry(key):
    entry = trust_entry("main", key)
    assert key_fingerprint(entry["publicKeyPem"]) == entry["fingerprint"]


# Trust set and timestamps.

@pytest.mark.parametrize(
    "document, message",
    [
        ({}, 'trust set must be an object with a "keys" array'),
        ({"keys": [{"keyId": ""}]}, "keys[0].keyId must be a non-empty string"),
        ({"keys": [{"keyId": "a", "algorithm": "rsa"}]}, "keys[0].algorithm must be one of ed25519, dilithium3"),
        ({"keys": [], "hybridRequiredFrom": "2026-01-01T00:00:00"}, 'hybridRequiredFrom must be an ISO-8601 UTC timestamp ending in "Z"'),
    ],
)
def test_malformed_trust_set_is_rejected(document, message):
    with pytest.raises(ValueError, match=re.escape(message)):
        parse_trust_policy(document)


def test_timestamp_forms():
    assert parse_timestamp("2026-01-01T00:00:00.000Z").isoformat() == "2026-01-01T00:00:00+00:00"
    assert parse_timestamp("2026-01-01T02:00:00+02:00").isoformat() == "2026-01-01T00:00:00+00:00"
    assert parse_timestamp("2026-01-01").isoformat() == "2026-01-01T00:00:00+00:00"
    # Fractions beyond microseconds are truncated, as V8's Date.parse accepts them.
    assert parse_timestamp("2026-01-01T00:00:00.1234567Z").microsecond == 123456
    assert parse_timestamp("2026-01-01T00:00:00") is None
    assert parse_timestamp("2026-13-01T00:00:00Z") is None


# Command line.

def run_cli(*args):
    return subprocess.run([sys.executable, "-m", "parmana_verifier", *args], capture_output=True, text=True,
                          cwd=Path(__file__).resolve().parents[1])


def test_cli_exit_codes(tmp_path, key):
    trust_path = tmp_path / "trust.json"
    trust_path.write_text(json.dumps({"keys": [trust_entry("main", key)]}))
    good = tmp_path / "good.json"
    good.write_text(json.dumps(signed_record(key, "main", {"a": 1})))
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(load("record-tampered-amount.json")))

    assert run_cli(str(good), str(trust_path)).returncode == 0
    assert run_cli(str(bad), str(trust_path)).returncode == 1
    assert run_cli(str(good)).returncode == 2
    assert run_cli(str(tmp_path / "missing.json"), str(trust_path)).returncode == 2


def test_cli_prints_one_json_line(tmp_path, key):
    trust_path = tmp_path / "trust.json"
    trust_path.write_text(json.dumps({"keys": [trust_entry("main", key)]}))
    good = tmp_path / "good.json"
    good.write_text(json.dumps(signed_record(key, "main", {"a": 1})))
    output = run_cli(str(good), str(trust_path)).stdout
    assert json.loads(output) == {"valid": True, "coverage": "legacy", "errors": [], "checks": {"trustRecordHash": True, "signature": True}}
    assert output.count("\n") == 1
