# Input and output format

This document specifies what the verifier reads and writes. Anything it doesn't describe here is not checked.

## Terms

- **Execution Trust Record:** the JSON record produced by Parmana for one executed or refused action. The verifier reads the file named `proof.json` in the examples.
- **Trust set:** the JSON file listing the public keys you accept, each pinned by fingerprint.
- **Canonical bytes:** the bytes that a hash or signature is computed over. They're produced from JSON by sorting object keys by code unit, keeping array order, and encoding the result as UTF-8 with no extra whitespace. Two JSON files that differ only in whitespace or key order produce the same canonical bytes.
- **SPKI DER:** the standard binary encoding of a public key (SubjectPublicKeyInfo). A PEM public key is this encoding in base64 between `BEGIN PUBLIC KEY` lines.
- **Fingerprint:** `sha256:` followed by the SHA-256 of a key's SPKI DER, as 64 lowercase hex digits.
- **Commitment:** a signature over a short fixed-size digest of a large message, used only for Ed25519 (see Algorithms).

## Execution Trust Record (`proof.json`)

The verifier uses these fields:

| Field | Required | Meaning |
|---|---|---|
| `trustRecordId`, `businessTransactionId`, `transaction`, `authorization`, `overrides`, `executions`, `createdAt` | Yes (the hash covers them) | The signed content. A field that is absent is left out of the canonical bytes. |
| `trustRecordHash` | Yes | Lowercase hex SHA-256 of the canonical bytes of the signed content above. |
| `signature` | Yes | One signature entry, described below. |
| `signatures` | No | Hybrid envelope: an array of signature entries. If present, it must pass the hybrid rules. |
| `schemaVersion` | No | Used only in the hybrid message. If absent, it is treated as `2`. |
| `createdAt` | Yes | An ISO 8601 timestamp. It must parse, and it decides which trust-set validity window applies. |

Every other field in the record is ignored. It is not covered by `trustRecordHash` or any signature, so the verifier cannot detect a change to it.

A signature entry is an object with:

- `algorithm`: `ed25519` or `dilithium3`.
- `keyId`: the trust-set key to use.
- `signature`: base64 text of the signature. The field `value` is also accepted with the same meaning.

## Trust set (`trust.json`)

The file is an object with a `keys` array. Each entry has:

| Field | Required | Rule |
|---|---|---|
| `keyId` | Yes | Non-empty, unique within the file. |
| `algorithm` | Yes | `ed25519` or `dilithium3`. |
| `publicKeyPem` | Yes | A PEM public key. |
| `fingerprint` | Yes | `sha256:` plus 64 lowercase hex digits, equal to the key's fingerprint. |
| `validFrom` | Yes | An ISO 8601 timestamp. The window includes this instant. |
| `validUntil` | No | An ISO 8601 timestamp, or `null`. If omitted or `null`, the window has no end. The window excludes this instant. |
| `compromised` | No | `true` or `false`. If omitted, it is `false`. |

A file that breaks any of these rules is rejected as a read error (exit code 2).

## Result (standard output)

The command prints one line of JSON:

```json
{"valid":true,"errors":[],"checks":{"trustRecordHash":true,"signature":true,"hybridSignatures":true}}
```

- `valid`: `true` only if every check that ran passed.
- `errors`: a list of plain-text reasons, empty when valid.
- `checks.trustRecordHash`: whether the hash matched.
- `checks.signature`: whether the legacy `signature` verified.
- `checks.hybridSignatures`: present only when `signatures` is present.

If the record is not a JSON object, the result is `{"valid":false,"errors":["record must be a JSON object"],"checks":{}}`.

Exit codes: `0` valid, `1` invalid, `2` usage error, missing file, or invalid JSON or trust set.

## Fields not covered by any signature

This is a known limitation of the current format (schema version 2 and the legacy `signature`). Read this section before you rely on a record.

**What is protected.** Only the fields listed in the table above are covered by `trustRecordHash`, by the legacy `signature`, and by the hybrid signatures. The hybrid message also covers `schemaVersion`.

**What is not protected.** Every other top-level field of the record, and any field nested inside an uncovered field, is outside the hash and every signature. The signature fields themselves (`signature`, `signatures`) are not covered either. The verifier reads none of these uncovered fields when it decides validity.

**Consequence.** If a record carries a field outside the covered set, such as a decision, status, or amount field, a party who can edit the file can change that field and the verifier still reports `"valid": true`. The verifier can only detect a change to the covered fields.

**What to do until this is closed.**
- Do not rely on any uncovered field for a decision. Read decisions only from covered fields.
- Treat a record as authentic only for the covered fields. Use the verifier's result to say that those fields were signed by a trusted key, not that the whole file is unchanged.
- Parmana should write decision-relevant data only into the covered fields.

**The planned fix.** Verify the whole record, excluding only the signature fields, under a new schema version. That needs a matching change in Parmana's signing code, and records signed under schema version 2 would still be verified under the current rules. Until that change ships and is documented here, this limitation stands.

## Hybrid signatures

When `signatures` is present, the verifier requires all of these:

- At least two entries.
- No algorithm appears twice.
- Every entry verifies over the canonical fields listed above, plus `schemaVersion` (default `2`).

Any failure makes the record invalid. The hybrid check and the legacy check are independent, so both must pass for a valid result.

## Algorithms

- **`ed25519`:** Ed25519 keys. The signed message is the canonical bytes. For messages longer than 4,096 bytes, the verifier also accepts a commitment: the signed message is the prefix `PARMANA-ED25519-LARGE-MESSAGE-V1` followed by a zero byte, then the SHA-512 digest of the canonical bytes. A commitment over a message of 4,096 bytes or less is rejected.
- **`dilithium3`:** ML-DSA-65 keys. Raw signatures only, with no commitment. It needs Node.js 24 or newer with OpenSSL 3.5 or newer. On an older runtime, a record with a `dilithium3` entry is reported as invalid with the reason "needs Node 24 or later", and the command exits with `1`. It does not crash.

## Trust rules

For a signature to be accepted, all of these must hold:

- The `keyId` exists in the trust set.
- The entry's `algorithm` matches the trust entry's `algorithm`.
- The trust entry is not `compromised`.
- The record's `createdAt` is at or after `validFrom` and before `validUntil`, when set.
- The PEM key's fingerprint equals the pinned `fingerprint`.
- The PEM key's type matches the algorithm.
