// Runs every example in order and stops at the first failure.
// Run: npm run examples
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { readdirSync } from "node:fs";

const here = fileURLToPath(new URL(".", import.meta.url));
const examples = readdirSync(here).filter((name) => /^\d{2}-.*\.mjs$/.test(name)).sort();

for (const name of examples) {
  console.log(`\n### ${name}`);
  const run = spawnSync(process.execPath, [`${here}${name}`], { stdio: "inherit" });
  if (run.status !== 0) {
    console.error(`\nExample ${name} exited with ${run.status}.`);
    process.exit(1);
  }
}

console.log(`\nAll ${examples.length} examples passed.`);
