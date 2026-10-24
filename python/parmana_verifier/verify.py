"""Offline verification of an Execution Trust Record.

Mirrors src/verify.mjs. Checks run on the record alone:
  1. trustRecordHash equals the SHA-256 (hex) of the canonical record fields.
  2. signature is a valid signature over those canonical bytes, made by a
     trusted key named by signature.keyId (see trust.py for the trust rules).
  3. If signatures is present, it is a hybrid envelope: at least two entries,
     no repeated algorithm, and every entry verifies over the message for its
     schemaVersion (default 2). A record with schemaVersion 3 must carry one.
  4. If a cutover is given (hybrid_required_from, from the trust file), a record
     created at or after it must pass check 3.

Schema versions:
  2  the message is the canonical fields plus schemaVersion.
  3  the message is every top-level field except signature, signatures,
     schemaVersion, verifications and receipts, plus schemaVersion.

Supported algorithms:
  ed25519     Ed25519 keys. Messages over 4096 bytes may be signed as a
              commitment: the prefix below followed by the SHA-512 digest of
              the canonical bytes. A raw signature is also accepted. A
              commitment over a small message is rejected.
  dilithium3  ML-DSA-65 keys. This verifier does not check them, because the
              cryptography package does not provide ML-DSA. Such an entry is
              reported as a failed check, so a hybrid record is never accepted
              on its Ed25519 part alone.

The verifier reads no environment variables and private keys, and makes no
network calls.
"""

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from .canonical import canonical_bytes
from .timestamps import parse_timestamp
from .trust import fingerprint_of_key

RAW_MESSAGE_LIMIT_BYTES = 4096
COMMITMENT_PREFIX = b"PARMANA-ED25519-LARGE-MESSAGE-V1\x00"
DEFAULT_SCHEMA_VERSION = 2
WHOLE_RECORD_SCHEMA_VERSION = 3
SUPPORTED_SCHEMA_VERSIONS = (2, 3)

LEGACY_FIELDS = ("trustRecordId", "businessTransactionId", "transaction", "authorization", "overrides", "executions", "createdAt")
WHOLE_RECORD_EXCLUDED_FIELDS = ("signature", "signatures", "schemaVersion", "verifications", "receipts")

ALGORITHMS = {
    "ed25519": {"commitment": True},
    "dilithium3": {"commitment": False},
}


@dataclass
class _Context:
    trust_keys: dict
    created_at: object


def canonical_trust_record(record):
    """The fields covered by trustRecordHash and the legacy signature."""
    # A field the record does not have is left out, as JSON.stringify leaves out
    # undefined values in the JavaScript verifier.
    return {key: record[key] for key in LEGACY_FIELDS if key in record}


def hybrid_message(record, schema_version):
    """The message a hybrid envelope of the given schema version signs."""
    if schema_version == WHOLE_RECORD_SCHEMA_VERSION:
        covered = {key: value for key, value in record.items() if key not in WHOLE_RECORD_EXCLUDED_FIELDS}
        covered["schemaVersion"] = schema_version
        return canonical_bytes(covered)

    return canonical_bytes({**canonical_trust_record(record), "schemaVersion": schema_version})


def verify_execution_trust_record(record, trust_keys, hybrid_required_from=None):
    """Verify a record against a trust set (a dict keyId -> TrustEntry).

    Returns a dict with valid, coverage ("full" or "legacy"), errors and checks,
    the same shape as the Node verifier's result.
    """
    errors = []

    if not isinstance(record, dict):
        return {"valid": False, "coverage": "legacy", "errors": ["record must be a JSON object"], "checks": {}}

    legacy_message = canonical_bytes(canonical_trust_record(record))
    expected_hash = hashlib.sha256(legacy_message).hexdigest()
    hash_valid = expected_hash == record.get("trustRecordHash")

    if not hash_valid:
        errors.append(f"trustRecordHash mismatch: expected {expected_hash}.")

    context = _Context(trust_keys=trust_keys, created_at=record.get("createdAt"))

    signature_valid = _verify_legacy_signature(record.get("signature"), legacy_message, context, errors)

    checks = {"trustRecordHash": hash_valid, "signature": signature_valid}

    schema_version = record.get("schemaVersion")
    if schema_version is None:
        schema_version = DEFAULT_SCHEMA_VERSION
    has_envelope = record.get("signatures") is not None

    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        errors.append(f"unsupported schemaVersion {schema_version}: expected 2 or 3.")
        checks["hybridSignatures"] = False
    elif has_envelope:
        checks["hybridSignatures"] = _verify_hybrid_signatures(
            record["signatures"], hybrid_message(record, schema_version), context, errors
        )
    elif schema_version == WHOLE_RECORD_SCHEMA_VERSION:
        errors.append("schemaVersion 3 record has no signatures array: a whole-record signature is required.")
        checks["hybridSignatures"] = False

    cutover_ok = not _is_at_or_after_cutover(record.get("createdAt"), hybrid_required_from) or checks.get("hybridSignatures") is True

    if not cutover_ok:
        errors.append(f"record created at or after hybridRequiredFrom ({hybrid_required_from}) has no valid hybrid envelope.")

    coverage = "full" if schema_version == WHOLE_RECORD_SCHEMA_VERSION and checks.get("hybridSignatures") is True else "legacy"

    valid = hash_valid and signature_valid and checks.get("hybridSignatures", True) and cutover_ok

    return {"valid": bool(valid), "coverage": coverage, "errors": errors, "checks": checks}


def _is_at_or_after_cutover(created_at, hybrid_required_from):
    if hybrid_required_from is None:
        return False

    created = parse_timestamp(created_at)
    cutover = parse_timestamp(hybrid_required_from)

    return created is not None and cutover is not None and created >= cutover


def _verify_legacy_signature(signature, message, context, errors):
    if not _is_signature_entry(signature):
        errors.append("signature is missing or malformed.")
        return False

    return _verify_entry(signature, message, context, errors)


def _verify_hybrid_signatures(entries, message, context, errors):
    if not isinstance(entries, list) or not all(_is_signature_entry(entry) for entry in entries):
        errors.append("malformed signatures: expected an array of entries with string algorithm, keyId and signature.")
        return False

    if len(entries) < 2:
        noun = "entry" if len(entries) == 1 else "entries"
        errors.append(f"signatures array has {len(entries)} {noun}, need at least 2 for a hybrid record.")
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
    # The legacy signature field uses "value" for the same three parts.
    signature_text = entry.get("signature") if isinstance(entry.get("signature"), str) else entry.get("value")
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

    if algorithm_name == "dilithium3":
        errors.append(
            "algorithm dilithium3 (ML-DSA-65) is not supported by the Python verifier; "
            "use the Node verifier (@parmana/verifier) on Node 24+ with OpenSSL 3.5+."
        )
        return False

    try:
        public_key = serialization.load_pem_public_key(trusted.public_key_pem.encode("utf-8"))
    except (ValueError, TypeError):
        errors.append(f'public key for keyId "{key_id}" is not a valid PEM key.')
        return False

    if fingerprint_of_key(public_key) != trusted.fingerprint:
        errors.append(f'public key for keyId "{key_id}" does not match its pinned fingerprint.')
        return False

    if not isinstance(public_key, Ed25519PublicKey):
        errors.append(f'public key for keyId "{key_id}" has type {type(public_key).__name__}, expected ed25519.')
        return False

    try:
        signature = base64.b64decode(signature_text or "", validate=False)
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
        and (isinstance(value.get("signature"), str) or isinstance(value.get("value"), str))
    )


def result_to_json(result):
    """Serialize a result the way the Node CLI prints it (no spaces, UTF-8)."""
    return json.dumps(result, separators=(",", ":"), ensure_ascii=False)
