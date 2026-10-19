import re

from jwt_toolkit.core.encoding import JsonObject
from jwt_toolkit.core.errors import ClaimConflictError, InvalidDurationError

_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86_400, "w": 604_800}
_DURATION = re.compile(r"([0-9]+)([smhdw]?)")
# A century is far beyond any sensible token lifetime and keeps exp within datetime range.
MAX_LIFETIME_SECONDS = 100 * 365 * 86_400


def parse_duration(text: str) -> int:
    match = _DURATION.fullmatch(text.strip())
    if match is None:
        raise InvalidDurationError(
            f"Invalid duration: {text!r}",
            ("Use a whole number with an optional unit: s, m, h, d, or w (e.g. 15m, 1h)",),
        )
    seconds = int(match.group(1)) * _UNIT_SECONDS[match.group(2) or "s"]
    if seconds <= 0:
        raise InvalidDurationError("Duration must be greater than zero")
    if seconds > MAX_LIFETIME_SECONDS:
        raise InvalidDurationError("Duration must be 100 years or less")
    return seconds


def with_lifetime(payload: JsonObject, *, lifetime_seconds: int, now: int) -> JsonObject:
    # iat and exp come from one clock reading so the lifetime is exact.
    conflicts = [claim for claim in ("iat", "exp") if claim in payload]
    if conflicts:
        raise ClaimConflictError(
            f"The payload already sets {' and '.join(conflicts)}",
            ("Remove it from the payload, or drop the lifetime option",),
        )
    return {**payload, "iat": now, "exp": now + lifetime_seconds}
