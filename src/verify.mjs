// Offline verification of an Execution Trust Record.
//
// Checks run on the record alone:
//   1. trustRecordHash equals the SHA-256 (hex) of the canonical record fields.
//   2. signature is a valid signature over those canonical bytes, made by the
//      key named by signature.keyId in publicKeys.
//   3. If signatures is present, it is a hybrid envelope: at least two entries,
//      no repeated algorithm, and every entry verifies over the canonical
//      fields plus schemaVersion (default 2). Any failure makes the record
//      invalid.
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

const ALGORITHMS = {
  ed25519: { keyType: "ed25519", commitment: true },
  dilithium3: { keyType: "ml-dsa-65", commitment: false },
};

const RAW_MESSAGE_LIMIT_BYTES = 4096;
const COMMITMENT_PREFIX = Buffer.from("PARMANA-ED25519-LARGE-MESSAGE-V1\0", "utf8");
const DEFAULT_SCHEMA_VERSION = 2;

// The fields covered by trustRecordHash and the legacy signature.
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

export function verifyExecutionTrustRecord(record, publicKeys) {
  const errors = [];

  if (!isObject(record)) {
    return { valid: false, errors: ["record must be a JSON object"], checks: {} };
  }

  const legacyMessage = canonicalBytes(canonicalTrustRecord(record));
  const expectedHash = createHash("sha256").update(legacyMessage).digest("hex");
  const hashValid = expectedHash === record.trustRecordHash;

  if (!hashValid) {
    errors.push(`trustRecordHash mismatch: expected ${expectedHash}.`);
  }

  const signatureValid = verifyLegacySignature(record.signature, legacyMessage, publicKeys, errors);

  const checks = { trustRecordHash: hashValid, signature: signatureValid };

  if (record.signatures !== undefined && record.signatures !== null) {
    const hybridMessage = canonicalBytes({
      ...canonicalTrustRecord(record),
      schemaVersion: record.schemaVersion ?? DEFAULT_SCHEMA_VERSION,
    });
    checks.hybridSignatures = verifyHybridSignatures(record.signatures, hybridMessage, publicKeys, errors);
  }

  return {
    valid: hashValid && signatureValid && (checks.hybridSignatures ?? true),
    errors,
    checks,
  };
}

function verifyLegacySignature(signature, message, publicKeys, errors) {
  if (!isSignatureEntry(signature)) {
    errors.push("signature is missing or malformed.");
    return false;
  }

  return verifyEntry(signature, message, publicKeys, errors);
}

function verifyHybridSignatures(entries, message, publicKeys, errors) {
  if (!Array.isArray(entries) || !entries.every(isSignatureEntry)) {
    errors.push("malformed signatures: expected an array of entries with string algorithm, keyId and signature.");
    return false;
  }

  if (entries.length < 2) {
    errors.push(`signatures array has ${entries.length} entr${entries.length === 1 ? "y" : "ies"}, need at least 2 for a hybrid record.`);
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
    allValid = verifyEntry(entry, message, publicKeys, errors) && allValid;
  }

  return allValid;
}

// Accepts { algorithm, keyId, signature } entries. The legacy `signature` field
// uses `value` for the same three parts, so that is accepted too.
function verifyEntry(entry, message, publicKeys, errors) {
  const signatureText = entry.signature ?? entry.value;
  const algorithm = ALGORITHMS[entry.algorithm];

  if (!algorithm) {
    errors.push(`unsupported algorithm: ${entry.algorithm}.`);
    return false;
  }

  if (!Object.prototype.hasOwnProperty.call(publicKeys, entry.keyId)) {
    errors.push(`no public key supplied for keyId "${entry.keyId}".`);
    return false;
  }

  if (entry.algorithm === "dilithium3" && !mlDsaSupported()) {
    errors.push("algorithm dilithium3 needs Node 24 or later with OpenSSL 3.5 or later.");
    return false;
  }

  let publicKey;

  try {
    publicKey = createPublicKey(publicKeys[entry.keyId]);
  } catch {
    errors.push(`public key for keyId "${entry.keyId}" is not a valid PEM key.`);
    return false;
  }

  if (publicKey.asymmetricKeyType !== algorithm.keyType) {
    errors.push(`public key for keyId "${entry.keyId}" has type ${publicKey.asymmetricKeyType}, expected ${algorithm.keyType}.`);
    return false;
  }

  const sigBytes = Buffer.from(signatureText, "base64");

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
    (typeof value.signature === "string" || typeof value.value === "string")
  );
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
