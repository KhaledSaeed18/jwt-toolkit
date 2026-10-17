import math
from dataclasses import dataclass
from datetime import UTC, datetime

# RFC 7519 section 4.1: exp, nbf, and iat are NumericDate values (seconds since the epoch).
TIME_CLAIMS = ("iat", "nbf", "exp")

_UNITS = (("d", 86_400), ("h", 3_600), ("m", 60), ("s", 1))


@dataclass(frozen=True)
class TimeClaim:
    # Exactly one of `utc` or `problem` is set. Nothing here says the token is valid.
    name: str
    value: object
    utc: str | None = None
    relative: str | None = None
    problem: str | None = None


def describe_time_claims(payload: dict, *, now: float) -> tuple[TimeClaim, ...]:
    return tuple(_describe(name, payload[name], now=now) for name in TIME_CLAIMS if name in payload)


def _describe(name: str, value: object, *, now: float) -> TimeClaim:
    # bool is an int subclass, but true is not a NumericDate.
    if isinstance(value, bool) or not isinstance(value, int | float):
        return TimeClaim(name, value, problem="not a NumericDate (expected a number of seconds)")
    if not math.isfinite(value):
        return TimeClaim(name, value, problem="not a finite number")
    try:
        moment = datetime.fromtimestamp(value, UTC)
    except (OverflowError, OSError, ValueError):
        return TimeClaim(name, value, problem="outside the range of representable dates")
    return TimeClaim(
        name,
        value,
        utc=moment.strftime("%Y-%m-%d %H:%M:%S UTC"),
        relative=format_relative(value - now),
    )


def format_relative(delta_seconds: float) -> str:
    seconds = round(abs(delta_seconds))
    if seconds == 0:
        return "now"
    parts = []
    for unit, size in _UNITS:
        count, seconds = divmod(seconds, size)
        if count:
            parts.append(f"{count}{unit}")
        if len(parts) == 2:
            break
    text = " ".join(parts)
    return f"in {text}" if delta_seconds > 0 else f"{text} ago"
