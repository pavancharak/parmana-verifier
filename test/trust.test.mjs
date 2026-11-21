import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyExecutionTrustRecord } from "../src/verify.mjs";
import { keyFingerprint, parseTrustSet } from "../src/trust.mjs";
import { makeKeyPair, makeRecord, trustEntry, trustSet } from "./helpers.mjs";

const BIN = fileURLToPath(new URL("../bin/parmana-verify.mjs", import.meta.url));
const CREATED = "2026-01-01T00:00:00.000Z";

test("keyFingerprint is stable per key and differs between keys", () => {
  const a = makeKeyPair();
  const b = makeKeyPair();
  assert.match(keyFingerprint(a.publicPem), /^sha256:[0-9a-f]{64}$/);
  assert.equal(keyFingerprint(a.publicPem), keyFingerprint(a.publicPem));
  assert.notEqual(keyFingerprint(a.publicPem), keyFingerprint(b.publicPem));
});

test("a PEM that does not match the pinned fingerprint is rejected", () => {
  const key = makeKeyPair();
  const other = makeKeyPair();
  const record = makeRecord({}, key);
  const entry = trustEntry("test-key", "ed25519", other, { fingerprint: keyFingerprint(key.publicPem) });
  const result = verifyExecutionTrustRecord(record, trustSet(entry));
  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /does not match its pinned fingerprint/);
});

test("a record created before validFrom is rejected", () => {
  const key = makeKeyPair();
  const record = makeRecord({ createdAt: CREATED }, key);
  const trust = trustSet(trustEntry("test-key", "ed25519", key, { validFrom: "2026-06-01T00:00:00.000Z" }));
  const result = verifyExecutionTrustRecord(record, trust);
  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /outside the validity window/);
});

test("validUntil is exclusive: a record created at validUntil is rejected", () => {
  const key = makeKeyPair();
  const record = makeRecord({ createdAt: CREATED }, key);
  const trust = trustSet(trustEntry("test-key", "ed25519", key, { validUntil: CREATED }));
  assert.equal(verifyExecutionTrustRecord(record, trust).valid, false);
});

test("a record inside the window is accepted, including validFrom itself", () => {
  const key = makeKeyPair();
  const record = makeRecord({ createdAt: CREATED }, key);
  const trust = trustSet(trustEntry("test-key", "ed25519", key, {
    validFrom: CREATED,
    validUntil: "2027-01-01T00:00:00.000Z",
  }));
  assert.equal(verifyExecutionTrustRecord(record, trust).valid, true);
});

test("a compromised key is rejected even inside its window", () => {
  const key = makeKeyPair();
  const record = makeRecord({ createdAt: CREATED }, key);
  const trust = trustSet(trustEntry("test-key", "ed25519", key, { compromised: true }));
  const result = verifyExecutionTrustRecord(record, trust);
  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /marked compromised/);
});

test("a signature whose algorithm differs from the trusted key's is rejected", () => {
  const key = makeKeyPair();
  const record = makeRecord({}, key);
  const trust = trustSet(trustEntry("test-key", "dilithium3", key));
  const result = verifyExecutionTrustRecord(record, trust);
  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /is trusted for dilithium3, not ed25519/);
});

test("an unparseable createdAt is rejected", () => {
  const key = makeKeyPair();
  const record = makeRecord({ createdAt: "not-a-date" }, key);
  const result = verifyExecutionTrustRecord(record, trustSet(trustEntry("test-key", "ed25519", key)));
  assert.equal(result.valid, false);
});

test("a trust set entry without a fingerprint is rejected", () => {
  const key = makeKeyPair();
  const entry = trustEntry("test-key", "ed25519", key);
  delete entry.fingerprint;
  assert.throws(() => parseTrustSet({ keys: [entry] }), /fingerprint must be/);
});

test("a trust set with a duplicate keyId is rejected", () => {
  const key = makeKeyPair();
  const entry = trustEntry("test-key", "ed25519", key);
  assert.throws(() => parseTrustSet({ keys: [entry, entry] }), /duplicate keyId/);
});

test("a trust set without a keys array is rejected", () => {
  assert.throws(() => parseTrustSet({}), /"keys" array/);
});

function runCli(args) {
  return spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8" });
}

test("key-fingerprint prints the pinned value for a PEM file", () => {
  const dir = mkdtempSync(join(tmpdir(), "parmana-fp-"));
  const key = makeKeyPair();
  const pemPath = join(dir, "key.pem");
  writeFileSync(pemPath, key.publicPem);
  const run = runCli(["key-fingerprint", pemPath]);
  assert.equal(run.status, 0, run.stderr);
  assert.equal(run.stdout.trim(), keyFingerprint(key.publicPem));
});

test("key-fingerprint with a missing argument exits 2", () => {
  assert.equal(runCli(["key-fingerprint"]).status, 2);
});

test("CLI exits 2 for a malformed trust file", () => {
  const dir = mkdtempSync(join(tmpdir(), "parmana-bad-"));
  const key = makeKeyPair();
  const proof = join(dir, "proof.json");
  const trust = join(dir, "trust.json");
  writeFileSync(proof, JSON.stringify(makeRecord({}, key)));
  writeFileSync(trust, JSON.stringify({ keys: [{ keyId: "test-key", algorithm: "ed25519" }] }));
  assert.equal(runCli([proof, trust]).status, 2);
});
