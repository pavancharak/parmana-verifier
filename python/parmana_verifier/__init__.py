"""Offline verifier for Parmana Execution Trust Records (Python).

Python counterpart to the Node verifier in the repository root. It checks the
record hash and Ed25519 signatures against the keys you pin in a trust file,
and makes no network calls. It checks ML-DSA-65 (dilithium3) signatures too,
with cryptography 48.0.0 or later; see README.md.
"""

from .canonical import canonical_bytes
from .trust import TrustEntry, TrustPolicy, key_fingerprint, parse_trust_policy
from .verify import verify_execution_trust_record

__all__ = [
    "TrustEntry",
    "TrustPolicy",
    "canonical_bytes",
    "key_fingerprint",
    "parse_trust_policy",
    "verify_execution_trust_record",
]

__version__ = "1.6.3"
