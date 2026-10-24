"""Trust set: the keys a verifier accepts, each pinned by fingerprint.

Mirrors src/trust.mjs. A key is used only when all of these hold:
  - its PEM hashes to the pinned fingerprint (SHA-256 of the SPKI DER);
  - its algorithm matches the algorithm the signature names;
  - it is not marked compromised;
  - the record's createdAt falls within [validFrom, validUntil).

The trust set is supplied by the caller. The verifier never fetches keys.
"""

import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives import serialization

from .timestamps import parse_timestamp

ALGORITHM_NAMES = ["ed25519", "dilithium3"]
_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass
class TrustEntry:
    key_id: str
    algorithm: str
    public_key_pem: str
    fingerprint: str
    valid_from: str
    valid_until: Optional[str]
    compromised: bool


@dataclass
class TrustPolicy:
    keys: dict = field(default_factory=dict)
    hybrid_required_from: Optional[str] = None


def key_fingerprint(public_key_pem):
    """Return the "sha256:..." value to pin for a PEM public key."""
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    return fingerprint_of_key(public_key)


def fingerprint_of_key(public_key):
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(der).hexdigest()


def parse_trust_policy(document):
    """Parse a trust-set document into a TrustPolicy. Raises ValueError when malformed."""
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise ValueError('trust set must be an object with a "keys" array')

    hybrid_required_from = None
    cutover = document.get("hybridRequiredFrom")
    if cutover is not None:
        if not isinstance(cutover, str) or not cutover.endswith("Z") or parse_timestamp(cutover) is None:
            raise ValueError('hybridRequiredFrom must be an ISO-8601 UTC timestamp ending in "Z"')
        hybrid_required_from = cutover

    keys = {}

    for index, entry in enumerate(document["keys"]):
        at = f"keys[{index}]"

        if not isinstance(entry, dict):
            raise ValueError(f"{at} must be an object")

        key_id = entry.get("keyId")
        if not isinstance(key_id, str) or key_id == "":
            raise ValueError(f"{at}.keyId must be a non-empty string")

        if key_id in keys:
            raise ValueError(f'duplicate keyId "{key_id}"')

        if entry.get("algorithm") not in ALGORITHM_NAMES:
            raise ValueError(f"{at}.algorithm must be one of {', '.join(ALGORITHM_NAMES)}")

        if not isinstance(entry.get("publicKeyPem"), str):
            raise ValueError(f"{at}.publicKeyPem must be a PEM string")

        fingerprint = entry.get("fingerprint")
        if not isinstance(fingerprint, str) or not _FINGERPRINT.match(fingerprint):
            raise ValueError(f'{at}.fingerprint must be "sha256:" followed by 64 lowercase hex digits')

        if parse_timestamp(entry.get("validFrom")) is None:
            raise ValueError(f"{at}.validFrom must be an ISO timestamp")

        valid_until = entry.get("validUntil")
        if valid_until is not None and parse_timestamp(valid_until) is None:
            raise ValueError(f"{at}.validUntil must be an ISO timestamp or null")

        compromised = entry.get("compromised", False)
        if compromised is None:
            compromised = False
        if not isinstance(compromised, bool):
            raise ValueError(f"{at}.compromised must be true or false")

        keys[key_id] = TrustEntry(
            key_id=key_id,
            algorithm=entry["algorithm"],
            public_key_pem=entry["publicKeyPem"],
            fingerprint=fingerprint,
            valid_from=entry["validFrom"],
            valid_until=valid_until,
            compromised=compromised,
        )

    return TrustPolicy(keys=keys, hybrid_required_from=hybrid_required_from)
