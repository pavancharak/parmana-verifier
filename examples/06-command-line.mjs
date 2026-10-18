// Use the command-line tool the way an auditor would: verify a proof file,
// and check the exit codes that scripts can rely on.
//
// Run: node examples/06-command-line.mjs
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { heading, loadVector } from "./shared.mjs";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BIN = fileURLToPath(new URL("../bin/parmana-verify.mjs", import.meta.url));
const dir = mkdtempSync(join(tmpdir(), "parmana-cli-example-"));
const trustPath = new URL("../test/vectors/trust.json", import.meta.url);

function run(args) {
  return spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8" });
}

const proofFile = join(dir, "proof.json");
const tamperedFile = join(dir, "tampered.json");
writeFileSync(proofFile, JSON.stringify(loadVector("record-implicit-v2.json")));
writeFileSync(tamperedFile, JSON.stringify(loadVector("record-tampered-amount.json")));

heading("1. Verify a valid record");
const valid = run([proofFile, fileURLToPath(trustPath)]);
console.log(`exit ${valid.status}`);
console.log(valid.stdout.trim());

heading("2. Verify a tampered record");
const tampered = run([tamperedFile, fileURLToPath(trustPath)]);
console.log(`exit ${tampered.status}`);
console.log(tampered.stdout.trim());

heading("3. Usage error");
const usage = run([]);
console.log(`exit ${usage.status}`);
console.log(usage.stderr.trim());

heading("4. Fingerprint a public key, for pinning");
const keyPem = loadVector("trust.json").keys[0].publicKeyPem;
const keyFile = join(dir, "key.pem");
writeFileSync(keyFile, keyPem);
const fingerprint = run(["key-fingerprint", keyFile]);
console.log(`exit ${fingerprint.status}`);
console.log(fingerprint.stdout.trim());

// The three exit codes a script can rely on: 0 valid, 1 invalid, 2 usage error.
process.exitCode = valid.status === 0 && tampered.status === 1 && usage.status === 2 && fingerprint.status === 0 ? 0 : 1;
