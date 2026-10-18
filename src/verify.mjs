// Offline verification of an Execution Trust Record.
//
// Two checks run on the record alone:
//   1. trustRecordHash equals the SHA-256 (hex) of the canonical record fields.
//   2. signature.value is a valid Ed25519 signature over the same canonical
//      bytes, made by the key named by signature.keyId in publicKeys.
//
// Records larger than 4096 bytes may have been signed as a commitment: the
// prefix below followed by the SHA-512 digest of the canonical bytes. A raw
// signature over a large message is also accepted. A commitment signature over
// a small message is rejected, so a small message cannot be downgraded.
//
// The verifier reads no environment variables, no private keys, and makes no
// network calls.

import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { canonicalBytes } from "./canonical.mjs";

const ALGORITHM = "ed25519";
const RAW_MESSAGE_LIMIT_BYTES = 4096;
const COMMITMENT_PREFIX = Buffer.from("PARMANA-ED25519-LARGE-MESSAGE-V1\0", "utf8");

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

  const canonical = canonicalBytes(canonicalTrustRecord(record));
  const expectedHash = createHash("sha256").update(canonical).digest("hex");
  const hashValid = expectedHash === record.trustRecordHash;

  if (!hashValid) {
    errors.push(`trustRecordHash mismatch: expected ${expectedHash}.`);
  }

  let signatureValid = false;
  const signature = record.signature;

  if (
    !isObject(signature) ||
    typeof signature.algorithm !== "string" ||
    typeof signature.keyId !== "string" ||
    typeof signature.value !== "string"
  ) {
    errors.push("signature is missing or malformed.");
  } else {
    signatureValid = verifyEntry(signature, canonical, publicKeys, errors);
  }

  return {
    valid: hashValid && signatureValid,
    errors,
    checks: { trustRecordHash: hashValid, signature: signatureValid },
    // Hybrid signatures are not checked by this verifier. Their presence is
    // reported so the output never implies that they were verified.
    hybridSignaturesPresent: record.signatures !== undefined && record.signatures !== null,
  };
}

function verifyEntry(signature, canonical, publicKeys, errors) {
  if (signature.algorithm !== ALGORITHM) {
    errors.push(`unsupported algorithm: ${signature.algorithm}.`);
    return false;
  }

  if (!Object.prototype.hasOwnProperty.call(publicKeys, signature.keyId)) {
    errors.push(`no public key supplied for keyId "${signature.keyId}".`);
    return false;
  }

  let publicKey;

  try {
    publicKey = createPublicKey(publicKeys[signature.keyId]);
  } catch {
    errors.push(`public key for keyId "${signature.keyId}" is not a valid PEM key.`);
    return false;
  }

  if (publicKey.asymmetricKeyType !== ALGORITHM) {
    errors.push(`public key for keyId "${signature.keyId}" is not an Ed25519 key.`);
    return false;
  }

  const sigBytes = Buffer.from(signature.value, "base64");

  const rawValid = safeVerify(canonical, sigBytes, publicKey);

  const commitmentValid =
    !rawValid &&
    canonical.length > RAW_MESSAGE_LIMIT_BYTES &&
    safeVerify(commitment(canonical), sigBytes, publicKey);

  if (!rawValid && !commitmentValid) {
    errors.push(`signature verification failed for keyId "${signature.keyId}".`);
    return false;
  }

  return true;
}

function commitment(canonical) {
  return Buffer.concat([
    COMMITMENT_PREFIX,
    createHash("sha512").update(canonical).digest(),
  ]);
}

function safeVerify(message, sigBytes, publicKey) {
  try {
    return verifySignature(null, Buffer.from(message), publicKey, sigBytes);
  } catch {
    return false;
  }
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
