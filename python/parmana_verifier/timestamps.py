"""ISO-8601 timestamp parsing for the verifier.

Accepts the forms the Parmana records and trust files use: a date, or a date
and time with an explicit offset ("Z" or "+hh:mm"). A timestamp without an
offset is rejected, rather than read in the local time zone as JavaScript's
Date.parse would, so that a result never depends on the machine's clock setting.
Returns None when the value is not such a timestamp.
"""

import re
from datetime import datetime, timedelta, timezone

_DATE_TIME = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?(Z|[+-]\d{2}:\d{2})$"
)
_DATE_ONLY = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")


def parse_timestamp(value):
    if not isinstance(value, str):
        return None

    date_only = _DATE_ONLY.match(value)
    if date_only:
        year, month, day = (int(part) for part in date_only.groups())
        try:
            return datetime(year, month, day, tzinfo=timezone.utc)
        except ValueError:
            return None

    match = _DATE_TIME.match(value)
    if not match:
        return None

    year, month, day, hour, minute = (int(part) for part in match.groups()[:5])
    second = int(match.group(6) or 0)
    # Keep microsecond precision: pad or truncate the fraction to six digits.
    microsecond = int(((match.group(7) or "") + "000000")[:6])

    try:
        moment = datetime(year, month, day, hour, minute, second, microsecond, tzinfo=timezone.utc)
        return moment - _offset(match.group(8))
    except (ValueError, OverflowError):
        return None


def _offset(text):
    if text == "Z":
        return timedelta(0)
    sign = 1 if text[0] == "+" else -1
    hours, minutes = int(text[1:3]), int(text[4:6])
    if hours > 23 or minutes > 59:
        raise ValueError("offset out of range")
    return sign * timedelta(hours=hours, minutes=minutes)
