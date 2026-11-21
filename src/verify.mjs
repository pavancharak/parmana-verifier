// Offline verification of an Execution Trust Record (schema version 3 only, decision D24).
//
// Checks run on the record alone:
//   1. trustRecordHash equals the SHA-256 (hex) of the canonical record fields.
//   2. signatures is an array of one or two entries, each for a different algorithm. Every entry is
//      a valid signature over the whole record, made by a trusted key named by its keyId (see
//      trust.mjs for the trust rules). A single valid entry is accepted.
//   3. If a cutover is given (options.hybridRequiredFrom, from the trust file), a record created at or
//      after it must carry both entries (ADR-0016).
//
// Schema version 3 signs every top-level field except signatures, schemaVersion, verifications and
// receipts, plus the schema version itself. There is no legacy signature, and schema versions 2 and
// unversioned records are refused.
//
// Each record's `valid` is true only when the hash and every check above pass.
//
// Supported algorithms:
//   ed25519     Ed25519 keys. Messages over 4096 bytes may be signed as a
//               commitment: the prefix below followed by the SHA-512 digest of
//               the canonical bytes. A raw signature over a large message is
//               also accepted. A commitment over a small message is rejected.
//   dilithium3  ML-DSA-65 keys (Node 24+ with OpenSSL 3.5+). Raw signatures
//               only.
//
// The verifier reads no environment variables, no private keys, and makes no
// network calls.

import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  verify as verifySignature,
} from "node:crypto";
import { canonicalBytes } from "./canonical.mjs";
import { fingerprintOfKey } from "./trust.mjs";
import { parseTimestamp } from "./timestamp.mjs";

const ALGORITHMS = {
  ed25519: { keyType: "ed25519", commitment: true },
  dilithium3: { keyType: "ml-dsa-65", commitment: false },
};

const RAW_MESSAGE_LIMIT_BYTES = 4096;
const COMMITMENT_PREFIX = Buffer.from("PARMANA-ED25519-LARGE-MESSAGE-V1\0", "utf8");
const WHOLE_RECORD_SCHEMA_VERSION = 3;

// Top-level fields that a version 3 message does not cover. verifications and
// receipts are attached after signing; receipts carry their own signature. "signature"
// is listed so the exclusion matches parmana-core, which once carried that field.
const WHOLE_RECORD_EXCLUDED_FIELDS = ["signature", "signatures", "schemaVersion", "verifications", "receipts"];

// The fields covered by trustRecordHash.
export function canonicalTrustRecord(record) {
  return {
    trustRecordId: record.trustRecordId,
    businessTransactionId: record.businessTransactionId,
    transaction: record.transaction,
    authorization: record.authorization,
    overrides: record.overrides,
    executions: record.executions,
    createdAt: record.createdAt,
  };
}

// The message the signatures array covers: every top-level field except the excluded ones, plus the schema version.
export function hybridMessage(record, schemaVersion) {
  const covered = Object.entries(record).filter(([key]) => !WHOLE_RECORD_EXCLUDED_FIELDS.includes(key));

  return canonicalBytes({ ...Object.fromEntries(covered), schemaVersion });
}

// trustKeys is a Map from keyId to a trust entry, as returned by parseTrustSet.
// options.hybridRequiredFrom is an ISO-8601 UTC timestamp from the trust file
// (see parseTrustPolicy); records created at or after it need a hybrid envelope.
export function verifyExecutionTrustRecord(record, trustKeys, options = {}) {
  const errors = [];

  if (!isObject(record)) {
    return { valid: false, errors: ["record must be a JSON object"], checks: {} };
  }

  // Schema version 3 only (decision D24). Any other version, or none, is refused before any signature is read.
  if (record.schemaVersion !== WHOLE_RECORD_SCHEMA_VERSION) {
    return {
      valid: false,
      errors: [
        `unsupported schemaVersion ${String(record.schemaVersion)}: only schemaVersion 3 is accepted (decision D24).`,
      ],
      checks: {},
    };
  }

  const canonical = canonicalBytes(canonicalTrustRecord(record));
  const expectedHash = createHash("sha256").update(canonical).digest("hex");
  const hashValid = expectedHash === record.trustRecordHash;

  if (!hashValid) {
    errors.push(`trustRecordHash mismatch: expected ${expectedHash}.`);
  }

  const context = { trustKeys, createdAt: record.createdAt };
  let signaturesValid = false;

  if (record.signatures === undefined || record.signatures === null) {
    errors.push("schemaVersion 3 record has no signatures array: a whole-record signature is required.");
  } else {
    signaturesValid = verifyEnvelope(
      record.signatures,
      hybridMessage(record, WHOLE_RECORD_SCHEMA_VERSION),
      context,
      errors,
    );
  }

  // From the cutover on, both entries are required (ADR-0016).
  const cutoverGiven = options.hybridRequiredFrom !== undefined && options.hybridRequiredFrom !== null;

  if (
    cutoverGiven &&
    isAtOrAfterCutover(record.createdAt, options.hybridRequiredFrom) &&
    signaturesValid &&
    record.signatures.length !== 2
  ) {
    errors.push(
      `record created at or after hybridRequiredFrom (${options.hybridRequiredFrom}) must carry both hybrid signatures.`,
    );
    signaturesValid = false;
  }

  return {
    valid: hashValid && signaturesValid,
    errors,
    checks: { trustRecordHash: hashValid, signatures: signaturesValid },
  };
}

function isAtOrAfterCutover(createdAt, hybridRequiredFrom) {
  if (hybridRequiredFrom === undefined) {
    return false;
  }

  const created = parseTimestamp(createdAt);

  return !Number.isNaN(created) && created >= parseTimestamp(hybridRequiredFrom);
}

function verifyEnvelope(entries, message, context, errors) {
  if (!Array.isArray(entries) || !entries.every(isSignatureEntry)) {
    errors.push("malformed signatures: expected an array of entries with string algorithm, keyId and signature.");
    return false;
  }

  if (entries.length < 1 || entries.length > 2) {
    errors.push(`signatures array has ${entries.length} entries, need one or two.`);
    return false;
  }

  const seen = new Set();
  let allValid = true;

  for (const entry of entries) {
    if (seen.has(entry.algorithm)) {
      errors.push(`duplicate algorithm in signatures array: ${entry.algorithm}.`);
      allValid = false;
      continue;
    }

    seen.add(entry.algorithm);
    allValid = verifyEntry(entry, message, context, errors) && allValid;
  }

  return allValid;
}

// Accepts { algorithm, keyId, signature } entries.
function verifyEntry(entry, message, context, errors) {
  const algorithm = ALGORITHMS[entry.algorithm];

  if (!algorithm) {
    errors.push(`unsupported algorithm: ${entry.algorithm}.`);
    return false;
  }

  const trusted = context.trustKeys.get(entry.keyId);

  if (!trusted) {
    errors.push(`no trusted key for keyId "${entry.keyId}".`);
    return false;
  }

  if (trusted.algorithm !== entry.algorithm) {
    errors.push(`keyId "${entry.keyId}" is trusted for ${trusted.algorithm}, not ${entry.algorithm}.`);
    return false;
  }

  if (trusted.compromised) {
    errors.push(`keyId "${entry.keyId}" is marked compromised; its signatures are not accepted.`);
    return false;
  }

  if (!withinValidityWindow(trusted, context.createdAt)) {
    errors.push(`createdAt ${context.createdAt} is outside the validity window of keyId "${entry.keyId}".`);
    return false;
  }

  if (entry.algorithm === "dilithium3" && !mlDsaSupported()) {
    errors.push("algorithm dilithium3 needs Node 24 or later with OpenSSL 3.5 or later.");
    return false;
  }

  let publicKey;

  try {
    publicKey = createPublicKey(trusted.publicKeyPem);
  } catch {
    errors.push(`public key for keyId "${entry.keyId}" is not a valid PEM key.`);
    return false;
  }

  if (fingerprintOfKey(publicKey) !== trusted.fingerprint) {
    errors.push(`public key for keyId "${entry.keyId}" does not match its pinned fingerprint.`);
    return false;
  }

  if (publicKey.asymmetricKeyType !== algorithm.keyType) {
    errors.push(`public key for keyId "${entry.keyId}" has type ${publicKey.asymmetricKeyType}, expected ${algorithm.keyType}.`);
    return false;
  }

  const sigBytes = Buffer.from(entry.signature, "base64");

  const rawValid = safeVerify(message, sigBytes, publicKey);

  const commitmentValid =
    !rawValid &&
    algorithm.commitment &&
    message.length > RAW_MESSAGE_LIMIT_BYTES &&
    safeVerify(commitment(message), sigBytes, publicKey);

  if (!rawValid && !commitmentValid) {
    errors.push(`signature verification failed for keyId "${entry.keyId}" (${entry.algorithm}).`);
    return false;
  }

  return true;
}

function withinValidityWindow(trusted, createdAt) {
  const at = parseTimestamp(createdAt);

  if (Number.isNaN(at)) {
    return false;
  }

  if (at < parseTimestamp(trusted.validFrom)) {
    return false;
  }

  return trusted.validUntil === null || at < parseTimestamp(trusted.validUntil);
}

function commitment(message) {
  return Buffer.concat([
    COMMITMENT_PREFIX,
    createHash("sha512").update(message).digest(),
  ]);
}

function safeVerify(message, sigBytes, publicKey) {
  try {
    return verifySignature(null, Buffer.from(message), publicKey, sigBytes);
  } catch {
    return false;
  }
}

let mlDsa;

function mlDsaSupported() {
  if (mlDsa === undefined) {
    try {
      generateKeyPairSync("ml-dsa-65");
      mlDsa = true;
    } catch {
      mlDsa = false;
    }
  }

  return mlDsa;
}

function isSignatureEntry(value) {
  return (
    isObject(value) &&
    typeof value.algorithm === "string" &&
    typeof value.keyId === "string" &&
    typeof value.signature === "string"
  );
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
