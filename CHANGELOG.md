# Changelog

## [0.2.0] - 2026-10-18

- Verifies hybrid `signatures` (ML-DSA-65 with Ed25519). Requires Node 24 with OpenSSL 3.5.
- Replaces the public-key map with a trust file. Each key is pinned by SHA-256 fingerprint, with a validity window and a compromised flag.
- Adds `key-fingerprint` to print the pinned value for a PEM key.

## [0.1.0] - 2026-10-18

Initial public release of the proof verifier, separated from the core repository.
