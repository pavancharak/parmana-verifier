// The Python quick start in python/README.md runs this record through the Node CLI too. Test key material only.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = join(here, "vectors");
const cli = join(here, "..", "bin", "parmana-verify.mjs");

function run(record) {
  const proc = spawnSync(process.execPath, [cli, join(vectors, record), join(vectors, "trust-python-ed25519.json")], { encoding: "utf8" });
  return { exitCode: proc.status, result: JSON.parse(proc.stdout) };
}

test("the quick-start record verifies, exit 0", () => {
  const { exitCode, result } = run("record-python-ed25519.json");
  assert.equal(exitCode, 0);
  assert.equal(result.valid, true);
  assert.equal(result.coverage, "legacy");
  assert.deepEqual(result.errors, []);
});

test("the tampered quick-start record is refused, exit 1", () => {
  const { exitCode, result } = run("record-python-ed25519-tampered.json");
  assert.equal(exitCode, 1);
  assert.equal(result.valid, false);
});
