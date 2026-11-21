// The quick start in the README runs a schema version 3 single-mode record through the Node CLI. Test key material only.
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
const scratch = mkdtempSync(join(tmpdir(), "parmana-quickstart-"));

after(() => rmSync(scratch, { recursive: true, force: true }));

function run(recordPath) {
  const proc = spawnSync(process.execPath, [cli, recordPath, join(fixtures, "trust-v3-single.json")], { encoding: "utf8" });
  return { exitCode: proc.status, result: JSON.parse(proc.stdout) };
}

test("the quick-start record verifies, exit 0", () => {
  const { exitCode, result } = run(join(fixtures, "v3-single-record.json"));
  assert.equal(exitCode, 0);
  assert.equal(result.valid, true);
  assert.deepEqual(result.errors, []);
});

test("the tampered quick-start record is refused, exit 1", () => {
  const record = JSON.parse(readFileSync(join(fixtures, "v3-single-record.json"), "utf8"));
  record.transaction.signals.amount = 999;
  const path = join(scratch, "tampered.json");
  writeFileSync(path, JSON.stringify(record));
  const { exitCode, result } = run(path);
  assert.equal(exitCode, 1);
  assert.equal(result.valid, false);
});
