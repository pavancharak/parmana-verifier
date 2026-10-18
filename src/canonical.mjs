// Canonical serialization for Parmana artifacts.
//
// Object keys are sorted in code-unit order, arrays keep their order, and the
// result is UTF-8 encoded JSON. Every hash and signature is computed over
// these bytes, so the verifier must produce exactly the same bytes as the
// signer.

export function canonicalBytes(value) {
  return new TextEncoder().encode(JSON.stringify(normalize(value)));
}

function normalize(value) {
  if (value === null || typeof value !== "object") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map(normalize);
  }

  const normalized = {};

  for (const key of Object.keys(value).sort()) {
    // defineProperty, not assignment: a key named "__proto__" must stay an
    // own property so its content is covered by the hash and signature.
    Object.defineProperty(normalized, key, {
      value: normalize(value[key]),
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }

  return normalized;
}
