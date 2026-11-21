"""Offline verification of an Execution Trust Record (schema version 3 only, decision D24).

Mirrors src/verify.mjs. Checks run on the record alone:
  1. trustRecordHash equals the SHA-256 (hex) of the canonical record fields.
  2. signatures is a list of one or two entries, each for a different algorithm.
     Every entry is a valid signature over the whole record, made by a trusted
     key named by its keyId (see trust.py for the trust rules). A single valid
     entry is accepted.
  3. If a cutover is given (hybrid_required_from, from the trust file), a record
     created at or after it must carry both entries (ADR-0016).

Schema version 3 signs every top-level field except signatures, schemaVersion,
verifications and receipts, plus the schema version itself. There is no legacy
signature, and schema versions 2 and unversioned records are refused.

Supported algorithms:
  ed25519     Ed25519 keys. Messages over 4096 bytes may be signed as a
              commitment: the prefix below followed by the SHA-512 digest of
              the message. A raw signature is also accepted. A commitment over
              a small message is rejected.
  dilithium3  ML-DSA-65 keys, verified over the same message as the ed25519
              entry. There is no commitment form. Needs cryptography 48.0.0 or
              later.

The verifier reads no environment variables and private keys, and makes no
network calls.
"""

import base64
import binascii
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey

from .canonical import canonical_bytes
from .timestamps import parse_timestamp
from .trust import fingerprint_of_key

RAW_MESSAGE_LIMIT_BYTES = 4096
COMMITMENT_PREFIX = b"PARMANA-ED25519-LARGE-MESSAGE-V1\x00"
WHOLE_RECORD_SCHEMA_VERSION = 3

# The fields covered by trustRecordHash.
HASH_FIELDS = ("trustRecordId", "businessTransactionId", "transaction", "authorization", "overrides", "executions", "createdAt")
# Top-level fields that a version 3 message does not cover. "signature" is listed so the exclusion
# matches parmana-core, which once carried that field.
WHOLE_RECORD_EXCLUDED_FIELDS = ("signature", "signatures", "schemaVersion", "verifications", "receipts")

ALGORITHMS = {
    "ed25519": {"commitment": True},
    "dilithium3": {"commitment": False},
}


class _Context:
    def __init__(self, trust_keys, created_at):
        self.trust_keys = trust_keys
        self.created_at = created_at


def canonical_trust_record(record):
    """The fields covered by trustRecordHash."""
    # A field the record does not have is left out, as JSON.stringify leaves out undefined values in the JavaScript verifier.
    return {key: record[key] for key in HASH_FIELDS if key in record}


def hybrid_message(record):
    """The message the signatures array covers: every top-level field except the excluded ones, plus schemaVersion 3."""
    covered = {key: value for key, value in record.items() if key not in WHOLE_RECORD_EXCLUDED_FIELDS}
    covered["schemaVersion"] = WHOLE_RECORD_SCHEMA_VERSION
    return canonical_bytes(covered)


def verify_execution_trust_record(record, trust_keys, hybrid_required_from=None):
    """Verify a record against a trust set (a dict keyId -> TrustEntry).

    hybrid_required_from is the optional cutover from the trust file. Returns a dict with valid, errors and
    checks, the same shape as the Node verifier's result.
    """
    errors = []

    if not isinstance(record, dict):
        return {"valid": False, "errors": ["record must be a JSON object"], "checks": {}}

    # Schema version 3 only (decision D24). Any other version, or none, is refused before any signature is read.
    if record.get("schemaVersion") != WHOLE_RECORD_SCHEMA_VERSION:
        return {
            "valid": False,
            "errors": [
                f"unsupported schemaVersion {record.get('schemaVersion')!r}: only schemaVersion 3 is accepted (decision D24)."
            ],
            "checks": {},
        }

    expected_hash = hashlib.sha256(canonical_bytes(canonical_trust_record(record))).hexdigest()
    hash_valid = expected_hash == record.get("trustRecordHash")

    if not hash_valid:
        errors.append(f"trustRecordHash mismatch: expected {expected_hash}.")

    context = _Context(trust_keys, record.get("createdAt"))
    signatures_valid = False

    if record.get("signatures") is None:
        errors.append("schemaVersion 3 record has no signatures array: a whole-record signature is required.")
    else:
        signatures_valid = _verify_envelope(record["signatures"], hybrid_message(record), context, errors)

    # From the cutover on, both entries are required (ADR-0016).
    if (
        hybrid_required_from is not None
        and _is_at_or_after_cutover(record.get("createdAt"), hybrid_required_from)
        and signatures_valid
        and len(record["signatures"]) != 2
    ):
        errors.append(
            f"record created at or after hybridRequiredFrom ({hybrid_required_from}) must carry both hybrid signatures."
        )
        signatures_valid = False

    return {
        "valid": bool(hash_valid and signatures_valid),
        "errors": errors,
        "checks": {"trustRecordHash": hash_valid, "signatures": signatures_valid},
    }


def _is_at_or_after_cutover(created_at, hybrid_required_from):
    if hybrid_required_from is None:
        return False

    created = parse_timestamp(created_at)
    cutover = parse_timestamp(hybrid_required_from)

    return created is not None and cutover is not None and created >= cutover


def _verify_envelope(entries, message, context, errors):
    if not isinstance(entries, list) or not all(_is_signature_entry(entry) for entry in entries):
        errors.append("malformed signatures: expected an array of entries with string algorithm, keyId and signature.")
        return False

    if len(entries) < 1 or len(entries) > 2:
        errors.append(f"signatures array has {len(entries)} entries, need one or two.")
        return False

    seen = set()
    all_valid = True

    for entry in entries:
        if entry["algorithm"] in seen:
            errors.append(f"duplicate algorithm in signatures array: {entry['algorithm']}.")
            all_valid = False
            continue

        seen.add(entry["algorithm"])
        all_valid = _verify_entry(entry, message, context, errors) and all_valid

    return all_valid


def _verify_entry(entry, message, context, errors):
    signature_text = entry["signature"]
    algorithm_name = entry["algorithm"]
    key_id = entry["keyId"]

    if algorithm_name not in ALGORITHMS:
        errors.append(f"unsupported algorithm: {algorithm_name}.")
        return False

    trusted = context.trust_keys.get(key_id)

    if trusted is None:
        errors.append(f'no trusted key for keyId "{key_id}".')
        return False

    if trusted.algorithm != algorithm_name:
        errors.append(f'keyId "{key_id}" is trusted for {trusted.algorithm}, not {algorithm_name}.')
        return False

    if trusted.compromised:
        errors.append(f'keyId "{key_id}" is marked compromised; its signatures are not accepted.')
        return False

    if not _within_validity_window(trusted, context.created_at):
        errors.append(f'createdAt {context.created_at} is outside the validity window of keyId "{key_id}".')
        return False

    try:
        public_key = serialization.load_pem_public_key(trusted.public_key_pem.encode("utf-8"))
    except (ValueError, TypeError):
        errors.append(f'public key for keyId "{key_id}" is not a valid PEM key.')
        return False

    if fingerprint_of_key(public_key) != trusted.fingerprint:
        errors.append(f'public key for keyId "{key_id}" does not match its pinned fingerprint.')
        return False

    expected_key_type = MLDSA65PublicKey if algorithm_name == "dilithium3" else Ed25519PublicKey
    if not isinstance(public_key, expected_key_type):
        errors.append(f'public key for keyId "{key_id}" has type {type(public_key).__name__}, expected {algorithm_name}.')
        return False

    try:
        signature = base64.b64decode(signature_text, validate=False)
    except (binascii.Error, ValueError):
        signature = b""

    raw_valid = _safe_verify(message, signature, public_key)
    commitment_valid = (
        not raw_valid
        and ALGORITHMS[algorithm_name]["commitment"]
        and len(message) > RAW_MESSAGE_LIMIT_BYTES
        and _safe_verify(_commitment(message), signature, public_key)
    )

    if not raw_valid and not commitment_valid:
        errors.append(f'signature verification failed for keyId "{key_id}" ({algorithm_name}).')
        return False

    return True


def _within_validity_window(trusted, created_at):
    at = parse_timestamp(created_at)

    if at is None:
        return False

    if at < parse_timestamp(trusted.valid_from):
        return False

    return trusted.valid_until is None or at < parse_timestamp(trusted.valid_until)


def _commitment(message):
    return COMMITMENT_PREFIX + hashlib.sha512(message).digest()


def _safe_verify(message, signature, public_key):
    try:
        public_key.verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _is_signature_entry(value):
    return (
        isinstance(value, dict)
        and isinstance(value.get("algorithm"), str)
        and isinstance(value.get("keyId"), str)
        and isinstance(value.get("signature"), str)
    )


def result_to_json(result):
    """Serialize a result the way the Node CLI prints it (no spaces, UTF-8)."""
    return json.dumps(result, separators=(",", ":"), ensure_ascii=False)
