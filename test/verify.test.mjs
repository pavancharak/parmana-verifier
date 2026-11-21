import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalBytes } from "../src/canonical.mjs";
import { verifyExecutionTrustRecord } from "../src/verify.mjs";
import { parseTrustPolicy } from "../src/trust.mjs";
import { makeKeyPair, makeRecord, trustEntry, trustSet } from "./helpers.mjs";

const BIN = fileURLToPath(new URL("../bin/parmana-verify.mjs", import.meta.url));

test("a correctly hashed and signed record verifies", () => {
  const key = makeKeyPair();
  const record = makeRecord({}, key);
  const result = verifyExecutionTrustRecord(record, trustSet(trustEntry("test-key", "ed25519", key)));
  assert.equal(result.valid, true);
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.checks, { trustRecordHash: true, signatures: true });
});

test("changing a signed field breaks the hash and the signature", () => {
  const key = makeKeyPair();
  const record = makeRecord({}, key);
  record.transaction.amount = 1000000;
  const result = verifyExecutionTrustRecord(record, trustSet(trustEntry("test-key", "ed25519", key)));
  assert.equal(result.valid, false);
  assert.equal(result.checks.trustRecordHash, false);
  assert.equal(result.checks.signatures, false);
});

test("a signature from a different key is rejected", () => {
  const signer = makeKeyPair();
  const other = makeKeyPair();
  const record = makeRecord({}, signer);
  const result = verifyExecutionTrustRecord(record, trustSet(trustEntry("test-key", "ed25519", other)));
  assert.equal(result.valid, false);
  assert.equal(result.checks.signatures, false);
});

test("an unknown keyId is reported, not treated as valid", () => {
  const key = makeKeyPair();
  const record = makeRecord({}, key, "missing-key");
  const result = verifyExecutionTrustRecord(record, trustSet(trustEntry("test-key", "ed25519", key)));
  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /no trusted key for keyId "missing-key"/);
});

test("an algorithm other than the supported ones is rejected", () => {
  const key = makeKeyPair();
  const record = makeRecord({}, key);
  record.signatures[0].algorithm = "rsa";
  const result = verifyExecutionTrustRecord(record, trustSet(trustEntry("test-key", "ed25519", key)));
  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /unsupported algorithm: rsa/);
});

test("a non-Ed25519 public key is rejected", () => {
  const key = makeKeyPair();
  const record = makeRecord({}, key);
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = rsa.publicKey.export({ type: "spki", format: "pem" });
  const trust = trustSet(trustEntry("test-key", "ed25519", { publicPem: pem }));
  const result = verifyExecutionTrustRecord(record, trust);
  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /expected ed25519/);
});

test("a record over 4096 bytes signed as a commitment verifies", () => {
  const key = makeKeyPair();
  const big = "x".repeat(5000);
  const record = makeRecord({ transaction: { note: big } }, key, "test-key", "commitment");
  assert.ok(canonicalBytes(record).length > 4096);
  const result = verifyExecutionTrustRecord(record, trustSet(trustEntry("test-key", "ed25519", key)));
  assert.equal(result.valid, true, result.errors.join("; "));
});

test("a record over 4096 bytes signed raw verifies", () => {
  const key = makeKeyPair();
  const big = "x".repeat(5000);
  const record = makeRecord({ transaction: { note: big } }, key, "test-key", "raw");
  const result = verifyExecutionTrustRecord(record, trustSet(trustEntry("test-key", "ed25519", key)));
  assert.equal(result.valid, true, result.errors.join("; "));
});

test("a commitment signature over a small record is rejected (no downgrade)", () => {
  const key = makeKeyPair();
  const record = makeRecord({}, key, "test-key", "commitment");
  const result = verifyExecutionTrustRecord(record, trustSet(trustEntry("test-key", "ed25519", key)));
  assert.equal(result.valid, false);
});

test("a key named __proto__ is kept in the canonical bytes", () => {
  const parsed = JSON.parse('{"__proto__": {"a": 1}, "b": 2}');
  const text = new TextDecoder().decode(canonicalBytes(parsed));
  assert.equal(text, '{"__proto__":{"a":1},"b":2}');
});

test("injecting a __proto__ key into a signed record breaks verification", () => {
  const key = makeKeyPair();
  const record = makeRecord({}, key);
  const tampered = JSON.parse(JSON.stringify(record));
  // Prepend the injected key to the serialized object, dropping its opening brace.
  tampered.transaction = JSON.parse(
    '{"__proto__":{"injected":true},' + JSON.stringify(tampered.transaction).slice(1),
  );
  const result = verifyExecutionTrustRecord(tampered, trustSet(trustEntry("test-key", "ed25519", key)));
  assert.equal(result.valid, false);
});

test("a record with no schemaVersion is refused, before any signature is read", () => {
  const key = makeKeyPair();
  const record = makeRecord({}, key);
  delete record.schemaVersion;
  const result = verifyExecutionTrustRecord(record, trustSet(trustEntry("test-key", "ed25519", key)));

  assert.equal(result.valid, false);
  assert.match(result.errors[0], /only schemaVersion 3/);
});

test("an explicit schemaVersion 2 record is refused (D24)", () => {
  const key = makeKeyPair();
  const record = makeRecord({ schemaVersion: 2 }, key);
  const result = verifyExecutionTrustRecord(record, trustSet(trustEntry("test-key", "ed25519", key)));

  assert.equal(result.valid, false);
  assert.match(result.errors[0], /only schemaVersion 3/);
});

test("a trust file that sets a removed legacy flag is refused, not silently honoured", () => {
  assert.throws(() => parseTrustPolicy({ keys: [], allowLegacyV2: true }), /allowLegacyV2 is no longer supported/);
  assert.throws(() => parseTrustPolicy({ keys: [], allowLegacyOnly: true }), /allowLegacyOnly is no longer supported/);
});

function runCli(args) {
  return spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8" });
}

test("CLI exits 0 for a valid record", () => {
  const dir = mkdtempSync(join(tmpdir(), "parmana-verify-"));
  const key = makeKeyPair();
  const proof = join(dir, "proof.json");
  const keys = join(dir, "keys.json");
  writeFileSync(proof, JSON.stringify(makeRecord({}, key)));
  writeFileSync(keys, JSON.stringify({ keys: [trustEntry("test-key", "ed25519", key)] }));
  const run = runCli([proof, keys]);
  assert.equal(run.status, 0, run.stderr);
  assert.equal(JSON.parse(run.stdout).valid, true);
});

test("CLI exits 1 for a tampered record", () => {
  const dir = mkdtempSync(join(tmpdir(), "parmana-verify-"));
  const key = makeKeyPair();
  const record = makeRecord({}, key);
  record.transaction.amount = 999;
  const proof = join(dir, "proof.json");
  const keys = join(dir, "keys.json");
  writeFileSync(proof, JSON.stringify(record));
  writeFileSync(keys, JSON.stringify({ keys: [trustEntry("test-key", "ed25519", key)] }));
  assert.equal(runCli([proof, keys]).status, 1);
});

test("CLI exits 2 on usage and read errors, and on a trust file with a removed flag", () => {
  assert.equal(runCli([]).status, 2);
  assert.equal(runCli(["/nonexistent/proof.json", "/nonexistent/keys.json"]).status, 2);

  const dir = mkdtempSync(join(tmpdir(), "parmana-verify-"));
  const key = makeKeyPair();
  const proof = join(dir, "proof.json");
  const keys = join(dir, "keys.json");
  writeFileSync(proof, JSON.stringify(makeRecord({}, key)));
  writeFileSync(keys, JSON.stringify({ keys: [trustEntry("test-key", "ed25519", key)], allowLegacyV2: true }));
  assert.equal(runCli([proof, keys]).status, 2);
});
