# Input and output format

This document specifies what the verifier reads and writes. Anything it doesn't describe here is not checked.

The verifier accepts Execution Trust Records of schema version 3 only (decision D24). Schema version 2 and unversioned records are refused, and the legacy top-level `signature` field is no longer read. There is no migration path for records of an earlier version: no customers or vendors received them.

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
| `trustRecordId`, `businessTransactionId`, `transaction`, `authorization`, `overrides`, `executions`, `createdAt` | Yes (the hash covers them) | The seven canonical fields. A field that is absent is left out of the canonical bytes. |
| `trustRecordHash` | Yes | Lowercase hex SHA-256 of the canonical bytes of the seven fields above. |
| `schemaVersion` | Yes | Must be `3`. Any other value, or no value, makes the record invalid before any signature is read. |
| `signatures` | Yes | An array of one or two signature entries, described below. The signatures cover the whole record. |
| `updatedAt` | No | Covered by the signatures, not by `trustRecordHash`. |
| `createdAt` | Yes | An ISO 8601 timestamp. It must parse, and it decides which trust-set validity window applies. |

A signature entry is an object with:

- `algorithm`: `ed25519` or `dilithium3`.
- `keyId`: the trust-set key to use.
- `signature`: base64 text of the signature. The older field name `value` is not read.

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

The file may also set one optional top-level field:

| Field | Required | Rule |
|---|---|---|
| `hybridRequiredFrom` | No | An ISO 8601 UTC timestamp ending in `Z` (the cutover, ADR-0016). A record whose `createdAt` is at or after this instant must carry two signature entries. If omitted or `null`, no cutover applies, and one valid entry is enough. |

The fields `allowLegacyOnly` and `allowLegacyV2` were removed under decision D24. A trust file that still sets either one is rejected as a read error (exit code 2), so an old file cannot silently change what is accepted. Remove them.

A file that breaks any of these rules is rejected as a read error (exit code 2).

## Result (standard output)

The command prints one line of JSON:

```json
{"valid":true,"errors":[],"checks":{"trustRecordHash":true,"signatures":true},"correspondence":{"status":"not_checked","executions":[]}}
```

- `valid`: `true` only if every check that ran passed.
- `errors`: a list of plain-text reasons, empty when valid.
- `checks.trustRecordHash`: whether the hash matched the seven canonical fields.
- `checks.signatures`: whether the `signatures` array passed the rules in [Hybrid signatures](#hybrid-signatures), including the cutover.
- `correspondence`: a separate report on whether what was dispatched is what was authorized. It does not change `valid` or the exit code. See the README.

If the record is not a JSON object, the result is `{"valid":false,"errors":["record must be a JSON object"],"checks":{}}`.

Exit codes: `0` valid, `1` invalid, `2` usage error, missing file, invalid JSON or trust set, or a trust file that sets a removed legacy flag.

## What a signature covers

Every top-level field is covered by the signatures except `signatures`, `schemaVersion`, `verifications` and `receipts`. `verifications` and `receipts` are attached after signing, and each receipt carries its own signature, which this verifier does not check. The schema version is covered as well.

So a change to any covered field, including `updatedAt`, makes the signatures fail, even when `trustRecordHash` still matches. A field added after signing (not `verifications` or `receipts`) fails the signatures too.

`trustRecordHash` covers only the seven canonical fields. The signatures are the check that covers the rest of the record.

## Hybrid signatures

The `signatures` array must satisfy these rules:

- It has one or two entries. Single mode uses one entry; hybrid uses two.
- No algorithm appears twice.
- Each entry is verified over the same message: every top-level field except `signatures`, `schemaVersion`, `verifications` and `receipts`, plus `schemaVersion` (as `3`).
- An entry whose `keyId` names a key of a different algorithm is refused.
- Both entries must verify when there are two. One valid entry is never enough for a two-entry record.

With a cutover (`hybridRequiredFrom`), a record created at or after the instant must have two entries. The cutover instant is inclusive. A record created before it may have one valid entry.

Any failure makes the record invalid.

## Algorithms

- **`ed25519`:** Ed25519 keys. The signed message is the canonical message. For messages longer than 4,096 bytes, the verifier also accepts a commitment: the signed message is the prefix `PARMANA-ED25519-LARGE-MESSAGE-V1` followed by a zero byte, then the SHA-512 digest of the message. A raw signature over a large message is also accepted. A commitment over a small message is refused.
- **`dilithium3`:** ML-DSA-65 keys. Raw signatures only, with no commitment. It needs Node.js 24 or newer with OpenSSL 3.5 or newer. On an older runtime, a record with a `dilithium3` entry is reported as invalid with the reason "needs Node 24 or later".

## Trust rules

For a signature to be accepted, all of these must hold:

- The `keyId` exists in the trust set.
- The entry's `algorithm` matches the trust entry's `algorithm`.
- The trust entry is not `compromised`.
- The record's `createdAt` is at or after `validFrom` and before `validUntil`, when set.
- The PEM key's fingerprint equals the pinned `fingerprint`.
- The PEM key's type matches the algorithm.

A record whose `createdAt` is at or after the trust file's `hybridRequiredFrom` is also invalid unless it has two valid entries. The instant itself is included in the requirement.

## Policy version 2 evidence (`parmana-verify policy-v2 <evidence.json>`)

The input is an object with a `records` list, the decision records in order, and optionally an `outcome`, a finished review.

- **Evidence record:** `hash` is the lowercase hex SHA-256 of the canonical bytes of the record with `hash` set to `""`. `prevHash` is the `hash` of the record before it, or `"genesis"` for the first.
- **Review outcome:** `outcomeHash` is the lowercase hex SHA-256 of the canonical bytes of `reviewId`, `outcome`, `decidedBy`, `digest`, `at` and `decisionRecord`. `decisionRecord` names the decision it finished, by `recordId` and `hash`. If the chain is given, that record must be in it, with the same hash.

The output is one line of JSON. `valid` is true only if the chain and the outcome, when present, are valid. Exit codes are as for `verify`.

These checks do not evaluate a policy, do not confirm a source's answer, and do not confirm that anything was released.
