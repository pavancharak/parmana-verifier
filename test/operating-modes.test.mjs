// The trust policies a deployment can run, each checked against the vectors parmana-core produced
// (schema version 3 only, decision D24). The policy is set in the trust file, never in environment variables.
// Test key material only.
//
//   1. Single mode: one signature (Ed25519) over the whole record. No cutover in the trust file.
//   2. Hybrid with a cutover: records created at or after hybridRequiredFrom must carry both signatures.
//   3. Removed flags: a trust file that still sets allowLegacyV2 or allowLegacyOnly is refused.
//
// See docs/OPERATING-MODES.md for when to use each, and how to move from single mode to hybrid.
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "vectors", "parmana-core-generated");
const cli = join(here, "..", "bin", "parmana-verify.mjs");
const scratch = mkdtempSync(join(tmpdir(), "parmana-operating-modes-"));

after(() => rmSync(scratch, { recursive: true, force: true }));

const load = (name) => JSON.parse(readFileSync(join(fixtures, name), "utf8"));
let counter = 0;

// Runs the CLI on one record with one trust file (written from an object), and returns the parsed result and exit code.
function verify(record, trust) {
  const recordPath = join(scratch, `record-${counter}.json`);
  const trustPath = join(scratch, `trust-${counter}.json`);
  counter += 1;
  writeFileSync(recordPath, JSON.stringify(record));
  writeFileSync(trustPath, JSON.stringify(trust));
  const run = spawnSync(process.execPath, [cli, recordPath, trustPath], { encoding: "utf8" });
  // A usage or read error (exit 2) prints nothing on stdout; its reason is on stderr.
  return { result: run.stdout ? JSON.parse(run.stdout) : null, exitCode: run.status, stderr: run.stderr };
}

const singleTrust = load("trust-v3-single.json");
const hybridTrust = load("trust-v3-hybrid.json");

test("single mode accepts the single-signature record with no cutover", () => {
  const { result, exitCode } = verify(load("v3-single-record.json"), singleTrust);
  assert.equal(result.valid, true, result.errors.join(" "));
  assert.equal(exitCode, 0);
});

test("a cutover earlier than the single-signature record refuses it: both entries are required", () => {
  const { result, exitCode } = verify(load("v3-single-record.json"), { ...singleTrust, hybridRequiredFrom: "2026-01-01T00:00:00Z" });
  assert.equal(result.valid, false);
  assert.equal(exitCode, 1);
  assert.match(result.errors.join(" "), /must carry both hybrid signatures/);
});

test("hybrid with a cutover accepts the two-signature record created after it", () => {
  const { result, exitCode } = verify(load("v3-hybrid-record.json"), hybridTrust);
  assert.equal(result.valid, true, result.errors.join(" "));
  assert.equal(exitCode, 0);
});

test("a trust file that sets allowLegacyV2 is refused, with exit 2", () => {
  const { exitCode, stderr } = verify(load("v3-single-record.json"), { ...singleTrust, allowLegacyV2: true });
  assert.equal(exitCode, 2);
  assert.match(stderr, /allowLegacyV2 is no longer supported/);
});

test("a trust file that sets allowLegacyOnly is refused, with exit 2", () => {
  const { exitCode, stderr } = verify(load("v3-single-record.json"), { ...singleTrust, allowLegacyOnly: true });
  assert.equal(exitCode, 2);
  assert.match(stderr, /allowLegacyOnly is no longer supported/);
});
