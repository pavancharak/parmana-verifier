// Strict ISO-8601 timestamp parsing, matching python/parmana_verifier/timestamps.py.
//
// Accepts a date, or a date and time with an explicit offset ("Z" or "+hh:mm").
// A timestamp without an offset is rejected rather than read in the local time
// zone, so a result never depends on the machine's clock setting. Returns NaN
// for anything else, so callers can keep their existing Number.isNaN checks.

const DATE_TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?(Z|[+-]\d{2}:\d{2})$/;
const DATE_ONLY = /^(\d{4})-(\d{2})-(\d{2})$/;

export function parseTimestamp(value) {
  if (typeof value !== "string") return NaN;

  const dateOnly = DATE_ONLY.exec(value);
  if (dateOnly) {
    return utcOrNaN(Number(dateOnly[1]), Number(dateOnly[2]), Number(dateOnly[3]), 0, 0, 0, 0);
  }

  const match = DATE_TIME.exec(value);
  if (!match) return NaN;

  const [, year, month, day, hour, minute, second, fraction, offset] = match;
  const millis = Number(((fraction ?? "") + "000").slice(0, 3));
  const utc = utcOrNaN(
    Number(year),
    Number(month),
    Number(day),
    Number(hour),
    Number(minute),
    Number(second ?? 0),
    millis,
  );
  if (Number.isNaN(utc)) return NaN;

  const offsetMs = offset === "Z" ? 0 : offsetToMillis(offset);
  if (offsetMs === undefined) return NaN;

  return utc - offsetMs;
}

function utcOrNaN(year, month, day, hour, minute, second, millis) {
  if (month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59) return NaN;

  const date = new Date(Date.UTC(year, month - 1, day, hour, minute, second, millis));

  // Date.UTC rolls an impossible day (for example 31 February) into the next
  // month. Reject it by checking the fields round-trip unchanged.
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    return NaN;
  }

  return date.getTime();
}

function offsetToMillis(text) {
  const sign = text[0] === "+" ? 1 : -1;
  const hours = Number(text.slice(1, 3));
  const minutes = Number(text.slice(4, 6));
  if (hours > 23 || minutes > 59) return undefined;
  return sign * (hours * 60 + minutes) * 60_000;
}
