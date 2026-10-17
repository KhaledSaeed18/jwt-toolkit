import pytest

from jwt_toolkit.core.timestamps import describe_time_claims, format_relative

NOW = 1_700_000_000


def test_only_present_time_claims_are_described_in_fixed_order():
    claims = describe_time_claims({"exp": NOW, "sub": "1", "iat": NOW}, now=NOW)
    assert [c.name for c in claims] == ["iat", "exp"]


def test_utc_rendering_and_relative_time():
    (claim,) = describe_time_claims({"exp": NOW + 900}, now=NOW)
    assert claim.utc == "2023-11-14 22:28:20 UTC"
    assert claim.relative == "in 15m"
    assert claim.problem is None
    assert claim.value == NOW + 900


def test_fractional_values_are_accepted():
    (claim,) = describe_time_claims({"iat": NOW - 0.4}, now=NOW)
    assert claim.utc == "2023-11-14 22:13:19 UTC"
    assert claim.relative == "now"


@pytest.mark.parametrize(
    ("delta", "expected"),
    [
        (0, "now"),
        (0.4, "now"),
        (1, "in 1s"),
        (-1, "1s ago"),
        (59, "in 59s"),
        (61, "in 1m 1s"),
        (3_600, "in 1h"),
        (3_661, "in 1h 1m"),
        (-90_061, "1d 1h ago"),
        (86_400 * 400, "in 400d"),
    ],
)
def test_format_relative(delta, expected):
    assert format_relative(delta) == expected


@pytest.mark.parametrize("value", ["1700000000", True, None, [NOW], {"t": NOW}])
def test_non_numeric_values_are_reported_not_rendered(value):
    (claim,) = describe_time_claims({"exp": value}, now=NOW)
    assert claim.utc is None
    assert claim.relative is None
    assert claim.problem is not None
    assert "NumericDate" in claim.problem


@pytest.mark.parametrize("value", [10**20, -(10**20), 1e300])
def test_out_of_range_values_do_not_crash(value):
    (claim,) = describe_time_claims({"nbf": value}, now=NOW)
    assert claim.utc is None
    assert claim.problem == "outside the range of representable dates"


def test_non_finite_values_are_reported():
    (claim,) = describe_time_claims({"exp": float("nan")}, now=NOW)
    assert claim.problem == "not a finite number"
