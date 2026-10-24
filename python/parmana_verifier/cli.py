"""Command-line interface, matching bin/parmana-verify.mjs.

  parmana-verify <proof.json> <trust.json>
  parmana-verify key-fingerprint <public-key.pem>

verify exits 0 when the record is valid, 1 when it is invalid, and 2 for a
usage or read error. key-fingerprint prints the "sha256:..." value to pin in a
trust file.
"""

import json
import sys

from .trust import key_fingerprint, parse_trust_policy
from .verify import result_to_json, verify_execution_trust_record

USAGE = (
    "usage: parmana-verify <proof.json> <trust.json>\n"
    "       parmana-verify key-fingerprint <public-key.pem>"
)


def _reject_non_standard_constant(value):
    # JSON.parse rejects NaN and Infinity, so the Python reader does too.
    raise ValueError(f"invalid JSON constant {value}")


def _read_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.loads(handle.read(), parse_constant=_reject_non_standard_constant)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv

    if args and args[0] == "key-fingerprint":
        if len(args) != 2:
            print(USAGE, file=sys.stderr)
            return 2
        try:
            with open(args[1], "r", encoding="utf-8") as handle:
                print(key_fingerprint(handle.read()))
            return 0
        except (OSError, ValueError, TypeError) as error:
            print(f"key error: {error}", file=sys.stderr)
            return 2

    if len(args) != 2 or not args[0] or not args[1]:
        print(USAGE, file=sys.stderr)
        return 2

    proof_path, trust_path = args

    try:
        proof = _read_json(proof_path)
        policy = parse_trust_policy(_read_json(trust_path))
    except (OSError, ValueError) as error:
        print(f"read error: {error}", file=sys.stderr)
        return 2

    result = verify_execution_trust_record(proof, policy.keys, policy.hybrid_required_from)
    print(result_to_json(result))

    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
