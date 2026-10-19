// Trust set: the keys a verifier accepts, each pinned by fingerprint.
//
// A key is used only when all of these hold:
//   - its PEM hashes to the pinned fingerprint (SHA-256 of the SPKI DER);
//   - its algorithm matches the algorithm the signature names;
//   - it is not marked compromised;
//   - the record's createdAt falls within [validFrom, validUntil).
//
// The trust set is supplied by the caller. The verifier never fetches keys.

import { createHash, createPublicKey } from "node:crypto";

export const ALGORITHM_NAMES = ["ed25519", "dilithium3"];

export function keyFingerprint(publicKeyPem) {
  return fingerprintOfKey(createPublicKey(publicKeyPem));
}

export function fingerprintOfKey(publicKey) {
  const der = publicKey.export({ type: "spki", format: "der" });
  return `sha256:${createHash("sha256").update(der).digest("hex")}`;
}

// Parses a trust-set document into a Map keyId -> entry. Throws an Error with
// a readable message when the document is malformed.
export function parseTrustSet(document) {
  return parseTrustPolicy(document).keys;
}

// Parses a trust-set document into { keys, hybridRequiredFrom }. keys is the
// Map that parseTrustSet returns. hybridRequiredFrom is the optional cutover:
// a record created at or after it must carry a valid hybrid envelope. It is
// null when the document does not set one. It must be an ISO-8601 UTC
// timestamp ending in "Z", so that it means the same time everywhere.
export function parseTrustPolicy(document) {
  if (document === null || typeof document !== "object" || !Array.isArray(document.keys)) {
    throw new Error('trust set must be an object with a "keys" array');
  }

  let hybridRequiredFrom = null;

  if (document.hybridRequiredFrom !== undefined && document.hybridRequiredFrom !== null) {
    if (typeof document.hybridRequiredFrom !== "string" || !/Z$/.test(document.hybridRequiredFrom) || Number.isNaN(Date.parse(document.hybridRequiredFrom))) {
      throw new Error('hybridRequiredFrom must be an ISO-8601 UTC timestamp ending in "Z"');
    }

    hybridRequiredFrom = document.hybridRequiredFrom;
  }

  const trustKeys = new Map();

  for (const [index, entry] of document.keys.entries()) {
    const at = `keys[${index}]`;

    if (entry === null || typeof entry !== "object") {
      throw new Error(`${at} must be an object`);
    }

    if (typeof entry.keyId !== "string" || entry.keyId === "") {
      throw new Error(`${at}.keyId must be a non-empty string`);
    }

    if (trustKeys.has(entry.keyId)) {
      throw new Error(`duplicate keyId "${entry.keyId}"`);
    }

    if (!ALGORITHM_NAMES.includes(entry.algorithm)) {
      throw new Error(`${at}.algorithm must be one of ${ALGORITHM_NAMES.join(", ")}`);
    }

    if (typeof entry.publicKeyPem !== "string") {
      throw new Error(`${at}.publicKeyPem must be a PEM string`);
    }

    if (typeof entry.fingerprint !== "string" || !/^sha256:[0-9a-f]{64}$/.test(entry.fingerprint)) {
      throw new Error(`${at}.fingerprint must be "sha256:" followed by 64 lowercase hex digits`);
    }

    if (typeof entry.validFrom !== "string" || Number.isNaN(Date.parse(entry.validFrom))) {
      throw new Error(`${at}.validFrom must be an ISO timestamp`);
    }

    if (entry.validUntil !== undefined && entry.validUntil !== null &&
        (typeof entry.validUntil !== "string" || Number.isNaN(Date.parse(entry.validUntil)))) {
      throw new Error(`${at}.validUntil must be an ISO timestamp or null`);
    }

    if (entry.compromised !== undefined && typeof entry.compromised !== "boolean") {
      throw new Error(`${at}.compromised must be true or false`);
    }

    trustKeys.set(entry.keyId, {
      keyId: entry.keyId,
      algorithm: entry.algorithm,
      publicKeyPem: entry.publicKeyPem,
      fingerprint: entry.fingerprint,
      validFrom: entry.validFrom,
      validUntil: entry.validUntil ?? null,
      compromised: entry.compromised ?? false,
    });
  }

  return { keys: trustKeys, hybridRequiredFrom };
}
