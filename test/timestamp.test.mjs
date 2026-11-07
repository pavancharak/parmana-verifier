import { test } from "node:test";
import assert from "node:assert/strict";
import { parseTimestamp } from "../src/timestamp.mjs";

test("accepts UTC and explicit offsets, and reads them as the same instant", () => {
  assert.equal(parseTimestamp("2026-01-01T00:00:00Z"), Date.UTC(2026, 0, 1));
  assert.equal(parseTimestamp("2026-01-01T02:00:00+02:00"), Date.UTC(2026, 0, 1));
  assert.equal(parseTimestamp("2026-01-01T00:00:00.123Z"), Date.UTC(2026, 0, 1) + 123);
  assert.equal(parseTimestamp("2026-01-01"), Date.UTC(2026, 0, 1));
});

test("refuses a timestamp with no offset, so the result does not depend on the local time zone", () => {
  assert.ok(Number.isNaN(parseTimestamp("2026-01-01T00:00:00")));
  assert.ok(Number.isNaN(parseTimestamp("2026-06-01T10:00:00")));
});

test("refuses impossible dates, out-of-range offsets, and non-strings", () => {
  assert.ok(Number.isNaN(parseTimestamp("2026-13-01T00:00:00Z")));
  assert.ok(Number.isNaN(parseTimestamp("2026-02-31T00:00:00Z")));
  assert.ok(Number.isNaN(parseTimestamp("2026-01-01T00:00:00+25:00")));
  assert.ok(Number.isNaN(parseTimestamp(undefined)));
  assert.ok(Number.isNaN(parseTimestamp(12345)));
});
