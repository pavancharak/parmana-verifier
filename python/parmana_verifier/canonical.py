"""Canonical serialization for Parmana artifacts.

Mirrors src/canonical.mjs. Object keys are sorted in UTF-16 code-unit order,
arrays keep their order, and numbers and strings are written the way
JavaScript's JSON.stringify writes them. Every hash and signature is computed
over these bytes, so the verifier must produce exactly the same bytes as the
signer.
"""

import json
import re
from decimal import Decimal

_LONE_SURROGATE = re.compile("[\ud800-\udfff]")
_MAX_SAFE_INTEGER = 2**53 - 1


def canonical_bytes(value):
    return _dump(value).encode("utf-8")


def _dump(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, int):
        # JSON.parse rounds integers beyond 2**53 to the nearest double, so the
        # signer's bytes contain that rounded value, not the exact integer.
        if abs(value) > _MAX_SAFE_INTEGER:
            return js_number(float(value))
        return str(value)
    if isinstance(value, float):
        return js_number(value)
    if isinstance(value, list):
        return "[" + ",".join(_dump(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=_utf16_sort_key)
        return "{" + ",".join(_string(key) + ":" + _dump(value[key]) for key in keys) + "}"
    raise TypeError(f"cannot canonicalize value of type {type(value).__name__}")


def _utf16_sort_key(key):
    return key.encode("utf-16-be", "surrogatepass")


def _string(value):
    text = json.dumps(value, ensure_ascii=False)
    # JSON.stringify escapes an unpaired surrogate as \uXXXX (lowercase). Python
    # keeps it as a bare code point, which cannot be encoded as UTF-8.
    return _LONE_SURROGATE.sub(lambda match: "\\u%04x" % ord(match.group(0)), text)


def js_number(number):
    """Format a finite double the way ECMAScript Number.prototype.toString does."""
    if number != number or number in (float("inf"), float("-inf")):
        return "null"
    if number == 0:
        return "0"
    if number < 0:
        return "-" + js_number(-number)

    # repr gives the shortest digits that round-trip, the same digits as JavaScript.
    sign, digits, exponent = Decimal(repr(number)).as_tuple()
    text = "".join(str(d) for d in digits).rstrip("0") or "0"
    # Position of the decimal point relative to the start of the digit string.
    point = len(digits) + exponent
    k = len(text)
    n = point

    if k <= n <= 21:
        return text + "0" * (n - k)
    if 0 < n <= 21:
        return text[:n] + "." + text[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + text

    e = n - 1
    exponent_text = ("+" if e >= 0 else "-") + str(abs(e))
    if k == 1:
        return text + "e" + exponent_text
    return text[0] + "." + text[1:] + "e" + exponent_text
