// Helpers shared by the examples. Nothing here is part of the verifier itself.
import { readFileSync } from "node:fs";

export const VECTORS = new URL("../test/vectors/", import.meta.url);

export function loadVector(name) {
  return JSON.parse(readFileSync(new URL(name, VECTORS), "utf8"));
}

export function heading(title) {
  console.log();
  console.log(title);
  console.log("-".repeat(title.length));
}

export function mark(passed) {
  return passed ? "PASS" : "FAIL";
}

// For cases that are meant to be refused: a failed check means the problem was caught.
export function caught(passed) {
  return passed ? "not triggered" : "CAUGHT";
}

// For cases that must be accepted, or refused, by a trust decision.
export function decision(accepted) {
  return accepted ? "ACCEPTED" : "REFUSED";
}
