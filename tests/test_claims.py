import pytest

from jwt_toolkit.core.claims import (
    Check,
    check_audience,
    check_critical_headers,
    check_issuer,
    check_time_claims,
    is_numeric_date,
)

NOW = 1_700_000_000.0


def _by_name(checks: list[Check]) -> dict[str, Check]:
    return {c.check: c for c in checks}


@pytest.mark.parametrize(
    ("value", "expected"), [(1, True), (1.5, True), (True, False), ("1", False)]
)
def test_is_numeric_date(value, expected):
    assert is_numeric_date(value) is expected


def test_missing_exp_is_a_warning():
    assert _by_name(check_time_claims({}, now=NOW))["exp"].result == "WARN"


def test_token_is_expired_at_exactly_exp():
    assert _by_name(check_time_claims({"exp": NOW}, now=NOW))["exp"].result == "FAIL"


def test_leeway_extends_exp():
    assert _by_name(check_time_claims({"exp": NOW}, now=NOW, leeway=1))["exp"].result == "PASS"


def test_future_nbf_fails_unless_within_leeway():
    assert (
        _by_name(check_time_claims({"exp": NOW + 99, "nbf": NOW + 5}, now=NOW))["nbf"].result
        == "FAIL"
    )
    within = check_time_claims({"exp": NOW + 99, "nbf": NOW + 5}, now=NOW, leeway=5)
    assert "nbf" not in _by_name(within)


def test_future_iat_beyond_skew_is_a_warning():
    checks = _by_name(check_time_claims({"exp": NOW + 999, "iat": NOW + 61}, now=NOW))
    assert checks["iat"].result == "WARN"


@pytest.mark.parametrize("claim", ["exp", "nbf"])
def test_non_numeric_time_claims_fail(claim):
    checks = _by_name(check_time_claims({"exp": NOW + 1, claim: "soon"}, now=NOW))
    assert checks[claim].result == "FAIL"


def test_crit_always_fails_because_no_extension_is_supported():
    assert check_critical_headers({"crit": ["exp"]})[0].result == "FAIL"
    assert "malformed" in check_critical_headers({"crit": []})[0].detail


def test_unencoded_payload_fails():
    assert check_critical_headers({"b64": False})[0].check == "b64"
    assert check_critical_headers({"b64": True}) == []


def test_issuer_missing_is_named_as_missing():
    check = check_issuer({}, "auth")
    assert check.result == "FAIL"
    assert "No iss claim" in check.detail


def test_issuer_match_and_mismatch():
    assert check_issuer({"iss": "auth"}, "auth").result == "PASS"
    assert check_issuer({"iss": "other"}, "auth").detail == (
        "Issuer mismatch: expected 'auth', got 'other'"
    )


@pytest.mark.parametrize(
    ("aud", "result"), [("api", "PASS"), (["web", "api"], "PASS"), (["web"], "FAIL"), (5, "FAIL")]
)
def test_audience_string_or_list(aud, result):
    assert check_audience({"aud": aud}, "api").result == result


def test_audience_missing_is_named_as_missing():
    assert "No aud claim" in check_audience({}, "api").detail
