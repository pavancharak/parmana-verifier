// The three trust policies a deployment can run, each checked against the vectors parmana-core produced.
// The policy is set in the trust file, never in environment variables. Test key material only.
//
//   1. Default: a record with no hybrid envelope, or schemaVersion 2, is refused.
//   2. Single mode (what parmana-core runs while CRYPTO_MODE=single): accept legacy-only records.
//   3. Hybrid with a cutover: records created at or after hybridRequiredFrom must carry a hybrid envelope.
//
// See docs/OPERATING-MODES.md for when to use each, and how to move from 2 to 3 safely.
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

// Runs the CLI on one record with one trust file, and returns the parsed result and exit code.
function verify(recordName, trust) {
  const trustPath = join(
    scratch,
    `trust-${Math.random().toString(36).slice(2)}.json`,
  );
  writeFileSync(trustPath, JSON.stringify(trust));
  const run = spawnSync(
    process.execPath,
    [cli, join(fixtures, recordName), trustPath],
    {
      encoding: "utf8",
    },
  );
  return { result: JSON.parse(run.stdout), exitCode: run.status };
}

const singleKeys = load("trust-single.json").keys;
const hybridKeys = load("trust-v3.json").keys;

test("default policy refuses a single-mode record, and says which flag would accept it", () => {
  const { result, exitCode } = verify("single-record-1.json", {
    keys: singleKeys,
  });
  assert.equal(result.valid, false);
  assert.equal(exitCode, 1);
  assert.match(result.errors.join(" "), /allowLegacyV2/);
});

test("single-mode policy accepts the single-mode record, with coverage reported as legacy", () => {
  const { result, exitCode } = verify("single-record-1.json", {
    keys: singleKeys,
    allowLegacyOnly: true,
    allowLegacyV2: true,
  });
  assert.equal(result.valid, true);
  assert.equal(result.coverage, "legacy");
  assert.equal(exitCode, 0);
});

test("single-mode policy with a cutover after the record refuses the record created after the cutover", () => {
  // The record was created 2026-11-15T10:54:37Z. A cutover earlier than that means hybrid is required.
  const { result, exitCode } = verify("single-record-1.json", {
    keys: singleKeys,
    allowLegacyOnly: true,
    allowLegacyV2: true,
    hybridRequiredFrom: "2026-11-15T00:00:00Z",
  });
  assert.equal(result.valid, false);
  assert.equal(exitCode, 1);
  assert.match(result.errors.join(" "), /at or after hybridRequiredFrom/);
});

test("hybrid policy with a cutover accepts a hybrid record that is after the cutover", () => {
  // The record was created 2026-11-15T10:54:30Z. The cutover is earlier, so hybrid is required, and the record has it.
  const { result, exitCode } = verify("v3-record-1.json", {
    keys: hybridKeys,
    hybridRequiredFrom: "2026-11-15T00:00:00Z",
  });
  assert.equal(result.valid, true);
  assert.equal(result.coverage, "full");
  assert.equal(exitCode, 0);
});
