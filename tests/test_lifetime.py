import pytest

from jwt_toolkit.core.errors import ClaimConflictError, InvalidDurationError
from jwt_toolkit.core.lifetime import MAX_LIFETIME_SECONDS, parse_duration, with_lifetime


@pytest.mark.parametrize(
    ("text", "seconds"),
    [
        ("30", 30),
        ("30s", 30),
        ("15m", 900),
        ("1h", 3600),
        ("2d", 172_800),
        ("1w", 604_800),
        (" 5m ", 300),
    ],
)
def test_parse_duration(text, seconds):
    assert parse_duration(text) == seconds


@pytest.mark.parametrize(
    "text", ["", "m", "1.5h", "-5m", "5 m", "5M", "5y", "1h30m", "\N{ARABIC-INDIC DIGIT FIVE}m"]
)
def test_parse_duration_rejects_bad_formats(text):
    with pytest.raises(InvalidDurationError) as excinfo:
        parse_duration(text)
    assert excinfo.value.code == "invalid_duration"


def test_parse_duration_rejects_zero():
    with pytest.raises(InvalidDurationError, match="greater than zero"):
        parse_duration("0h")


def test_parse_duration_upper_bound():
    assert parse_duration(f"{MAX_LIFETIME_SECONDS}") == MAX_LIFETIME_SECONDS
    with pytest.raises(InvalidDurationError, match="100 years"):
        parse_duration(f"{MAX_LIFETIME_SECONDS + 1}")
    with pytest.raises(InvalidDurationError, match="100 years"):
        parse_duration("9" * 400 + "w")


def test_with_lifetime_sets_iat_and_exp_from_one_clock():
    payload = {"sub": "1"}
    result = with_lifetime(payload, lifetime_seconds=900, now=1_000)
    assert result == {"sub": "1", "iat": 1_000, "exp": 1_900}
    assert payload == {"sub": "1"}


@pytest.mark.parametrize("claim", ["iat", "exp"])
def test_with_lifetime_rejects_explicit_time_claims(claim):
    with pytest.raises(ClaimConflictError, match=claim) as excinfo:
        with_lifetime({claim: 1}, lifetime_seconds=60, now=0)
    assert excinfo.value.code == "claim_conflict"
