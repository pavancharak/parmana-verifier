// Verifies records produced by parmana-core, through the Node CLI. The expectations are in
// test/vectors/parmana-core-generated/cases.json, which the Python suite reads too. Test key material only.
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
const { cases } = JSON.parse(readFileSync(join(fixtures, "cases.json"), "utf8"));
const scratch = mkdtempSync(join(tmpdir(), "parmana-core-records-"));

after(() => rmSync(scratch, { recursive: true, force: true }));

function setPath(object, path, value) {
  const keys = path.split(".");
  let node = object;
  for (const key of keys.slice(0, -1)) {
    node = Array.isArray(node) ? node[Number(key)] : node[key];
  }
  const last = keys.at(-1);
  if (Array.isArray(node)) node[Number(last)] = value;
  else node[last] = value;
}

function applyTrustEdits(trust, edits = []) {
  let keys = trust.keys;
  for (const edit of edits) {
    if (edit.remove !== undefined) {
      keys = keys.filter((key) => key.keyId !== edit.remove);
    } else {
      for (const key of keys) {
        if (key.keyId === edit.keyId) Object.assign(key, edit.set);
      }
    }
  }
  return { ...trust, keys };
}

function materialize(spec) {
  const record = JSON.parse(readFileSync(join(fixtures, spec.record), "utf8"));
  for (const op of spec.tamper ?? []) setPath(record, op.path, op.value);
  const trust = applyTrustEdits(JSON.parse(readFileSync(join(fixtures, spec.trust), "utf8")), spec.trustEdits);
  return { record, trust };
}

function runNodeCli(spec, index) {
  const { record, trust } = materialize(spec);
  const recordPath = join(scratch, `case-${index}-record.json`);
  const trustPath = join(scratch, `case-${index}-trust.json`);
  writeFileSync(recordPath, JSON.stringify(record));
  writeFileSync(trustPath, JSON.stringify(trust));
  const proc = spawnSync(process.execPath, [cli, recordPath, trustPath], { encoding: "utf8" });
  return { exitCode: proc.status, result: JSON.parse(proc.stdout) };
}

cases.forEach((spec, index) => {
  test(`parmana-core record: ${spec.name}`, () => {
    const { exitCode, result } = runNodeCli(spec, index);
    const expect = spec.expect;

    assert.equal(result.valid, expect.valid, JSON.stringify(result.errors));
    assert.equal(exitCode, expect.valid ? 0 : 1);
    assert.equal(result.coverage, expect.coverage);

    for (const [check, value] of Object.entries(expect.checks ?? {})) {
      assert.equal(result.checks[check], value, `check ${check}`);
    }
    if (expect.correspondence !== undefined) {
      assert.equal(result.correspondence.status, expect.correspondence);
    }
    if (expect.errorIncludes !== undefined) {
      assert.ok(
        result.errors.some((error) => error.includes(expect.errorIncludes)),
        `expected an error containing "${expect.errorIncludes}", got ${JSON.stringify(result.errors)}`,
      );
    }
    if (expect.valid) {
      assert.deepEqual(result.errors, []);
    }
  });
});
