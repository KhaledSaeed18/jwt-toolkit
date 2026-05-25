import time

import pytest

from jwt_toolkit.core.auditor import (
    Grade,
    Severity,
    _audit_b64,
    _audit_crit,
    _audit_kid_injection,
    _audit_sensitive_values,
    _audit_typ,
    run_audit,
)

# helpers


def _severities(findings):
    return {f.severity for f in findings}


def _find(findings, field):
    return next((f for f in findings if f.field == field), None)


def _has(findings, severity, field=None):
    return any(f.severity is severity and (field is None or f.field == field) for f in findings)


# Algorithm checks


def test_alg_none_is_critical():
    report = run_audit({"alg": "none", "typ": "JWT"}, {})
    assert report.grade is Grade.F
    f = _find(report.findings, "alg")
    assert f.severity is Severity.CRITICAL


def test_hs256_is_warn():
    report = run_audit(
        {"alg": "HS256", "typ": "JWT"}, {"exp": int(time.time()) + 3600, "iat": int(time.time())}
    )
    assert _has(report.findings, Severity.WARN, "alg")


@pytest.mark.parametrize("alg", ["RS256", "ES256", "PS256"])
def test_asymmetric_alg_is_pass(alg):
    report = run_audit(
        {"alg": alg, "typ": "JWT"}, {"exp": int(time.time()) + 3600, "iat": int(time.time())}
    )
    f = _find(report.findings, "alg")
    assert f.severity is Severity.PASS


def test_unknown_alg_is_warn():
    report = run_audit({"alg": "XYZ999", "typ": "JWT"}, {})
    assert _has(report.findings, Severity.WARN, "alg")


# typ checks


def test_typ_jwt_is_pass():
    findings = _audit_typ({"alg": "HS256", "typ": "JWT"})
    assert findings[0].severity is Severity.PASS


def test_typ_lowercase_jwt_is_pass():
    findings = _audit_typ({"alg": "HS256", "typ": "jwt"})
    assert findings[0].severity is Severity.PASS


def test_typ_unexpected_uses_normalized_case_in_message():
    """A4: WARN message echoes the normalized (uppercased) typ, not the raw stored value."""
    findings = _audit_typ({"alg": "HS256", "typ": "bearer"})
    assert findings[0].severity is Severity.WARN
    assert "'BEARER'" in findings[0].message


# kid injection checks


def test_kid_path_traversal_is_critical():
    findings = _audit_kid_injection({"alg": "HS256", "kid": "../../etc/passwd"})
    assert findings[0].severity is Severity.CRITICAL
    assert ".." in findings[0].message


def test_kid_null_byte_is_critical():
    findings = _audit_kid_injection({"alg": "HS256", "kid": "key\x00injected"})
    assert findings[0].severity is Severity.CRITICAL


def test_kid_slash_separator_is_pass():
    """A3: a bare '/' is legitimate (e.g. prod-key/v1) and must NOT be flagged."""
    findings = _audit_kid_injection({"alg": "HS256", "kid": "prod-key/v1"})
    assert findings[0].severity is Severity.PASS


def test_kid_sql_injection_chars_are_critical():
    for char in ("'", '"', ";", "`", "$("):
        findings = _audit_kid_injection({"alg": "HS256", "kid": f"key{char}bad"})
        assert findings[0].severity is Severity.CRITICAL, f"Expected CRITICAL for kid with {char!r}"


# Key smuggling checks


def test_jwk_smuggling_is_critical():
    report = run_audit({"alg": "HS256", "typ": "JWT", "jwk": {"kty": "oct"}}, {})
    assert _has(report.findings, Severity.CRITICAL, "jwk")


def test_jku_http_is_critical():
    report = run_audit({"alg": "RS256", "typ": "JWT", "jku": "http://evil.com/keys"}, {})
    assert _has(report.findings, Severity.CRITICAL, "jku")


def test_jku_https_is_warn():
    report = run_audit({"alg": "RS256", "typ": "JWT", "jku": "https://trusted.com/keys"}, {})
    assert _has(report.findings, Severity.WARN, "jku")


# Expiry checks


def test_expired_token_is_critical():
    report = run_audit({"alg": "RS256", "typ": "JWT"}, {"exp": int(time.time()) - 3600})
    assert _has(report.findings, Severity.CRITICAL, "exp")


def test_long_lived_token_over_30_days_is_critical():
    exp = int(time.time()) + 60 * 60 * 24 * 31
    iat = int(time.time())
    report = run_audit({"alg": "RS256", "typ": "JWT"}, {"exp": exp, "iat": iat})
    f = _find(report.findings, "exp")
    assert f.severity is Severity.CRITICAL


def test_long_lived_token_over_24h_is_warn():
    exp = int(time.time()) + 60 * 60 * 25
    iat = int(time.time())
    report = run_audit({"alg": "RS256", "typ": "JWT"}, {"exp": exp, "iat": iat})
    f = _find(report.findings, "exp")
    assert f.severity is Severity.WARN


# nbf, iat checks


def test_nbf_in_future_is_critical():
    report = run_audit(
        {"alg": "RS256", "typ": "JWT"},
        {"exp": int(time.time()) + 3600, "nbf": int(time.time()) + 9999},
    )
    assert _has(report.findings, Severity.CRITICAL, "nbf")


def test_iat_in_future_is_warn():
    now = int(time.time())
    # iat is in the future but still before exp, so iat-after-exp check doesn't fire
    report = run_audit(
        {"alg": "RS256", "typ": "JWT"},
        {"exp": now + 99999, "iat": now + 9999},
    )
    assert _has(report.findings, Severity.WARN, "iat")


def test_iat_after_exp_is_critical():
    now = int(time.time())
    report = run_audit(
        {"alg": "RS256", "typ": "JWT"},
        {"exp": now + 100, "iat": now + 200},
    )
    assert _has(report.findings, Severity.CRITICAL, "iat")


# Sensitive fields and values


def test_sensitive_field_names_are_warned():
    for field in ("password", "secret", "api_key", "ssn"):
        report = run_audit(
            {"alg": "RS256", "typ": "JWT"},
            {field: "somevalue", "exp": int(time.time()) + 60, "iat": int(time.time())},
        )
        assert _has(report.findings, Severity.WARN, field), f"Expected WARN for field {field!r}"


def test_credit_card_value_is_critical():
    # 4111111111111111 is a standard test Visa number that passes Luhn
    report = run_audit(
        {"alg": "RS256", "typ": "JWT"},
        {"data": "4111111111111111", "exp": int(time.time()) + 60, "iat": int(time.time())},
    )
    assert _has(report.findings, Severity.CRITICAL)
    assert any("Luhn" in f.message or "credit" in f.message.lower() for f in report.findings)


def test_multiple_pii_emails_grouped_into_one_finding():
    """A2: five email-like values → exactly one WARN finding, not five."""
    payload = {
        "c1": "a@example.com",
        "c2": "b@example.com",
        "c3": "c@example.com",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
    }
    findings = _audit_sensitive_values(payload)
    email_findings = [
        f for f in findings if f.severity is Severity.WARN and "email" in f.message.lower()
    ]
    assert len(email_findings) == 1
    assert "c1" in email_findings[0].message
    assert "c2" in email_findings[0].message
    assert "c3" in email_findings[0].message


# A1: required_claims upgrades INFO → WARN


def test_missing_claims_are_info_by_default():
    report = run_audit(
        {"alg": "RS256", "typ": "JWT"}, {"exp": int(time.time()) + 60, "iat": int(time.time())}
    )
    iss_finding = _find(report.findings, "iss")
    aud_finding = _find(report.findings, "aud")
    assert iss_finding is not None and iss_finding.severity is Severity.INFO
    assert aud_finding is not None and aud_finding.severity is Severity.INFO


def test_required_claims_upgrades_missing_to_warn():
    report = run_audit(
        {"alg": "RS256", "typ": "JWT"},
        {"exp": int(time.time()) + 60, "iat": int(time.time())},
        required_claims=frozenset({"iss", "aud"}),
    )
    iss_finding = _find(report.findings, "iss")
    aud_finding = _find(report.findings, "aud")
    assert iss_finding is not None and iss_finding.severity is Severity.WARN
    assert aud_finding is not None and aud_finding.severity is Severity.WARN


def test_present_required_claim_is_not_flagged():
    report = run_audit(
        {"alg": "RS256", "typ": "JWT"},
        {"exp": int(time.time()) + 60, "iat": int(time.time()), "iss": "auth.example.com"},
        required_claims=frozenset({"iss"}),
    )
    assert _find(report.findings, "iss") is None


# Grading


def test_grade_a_when_no_warnings():
    report = run_audit(
        {"alg": "RS256", "typ": "JWT"},
        {
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "iss": "x",
            "aud": "y",
            "jti": "z",
        },
    )
    assert report.grade is Grade.A


def test_grade_b_with_one_warn():
    # HS256 produces 1 WARN (alg); a short exp avoids exp WARN
    report = run_audit(
        {"alg": "HS256", "typ": "JWT"},
        {
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "iss": "x",
            "aud": "y",
            "jti": "z",
        },
    )
    assert report.grade is Grade.B


def test_grade_f_with_critical():
    report = run_audit({"alg": "none", "typ": "JWT"}, {})
    assert report.grade is Grade.F


# CVE annotations on existing findings


def test_alg_none_message_references_cve():
    report = run_audit({"alg": "none", "typ": "JWT"}, {})
    f = _find(report.findings, "alg")
    assert "CVE-2015-2951" in f.message


def test_jwk_smuggling_message_references_cve():
    report = run_audit({"alg": "RS256", "typ": "JWT", "jwk": {"kty": "RSA"}}, {})
    f = _find(report.findings, "jwk")
    assert "CVE-2018-0114" in f.message


# HS + key-smuggling key-confusion (CVE-2016-10555)


@pytest.mark.parametrize("header_name", ["jwk", "jku", "x5u", "x5c"])
def test_hs_alg_with_key_smuggling_header_is_critical(header_name):
    value = {"kty": "RSA"} if header_name == "jwk" else "https://example.com/keys"
    report = run_audit({"alg": "HS256", "typ": "JWT", header_name: value}, {})
    confusion = next(
        (f for f in report.findings if f.field == "alg" and f.severity is Severity.CRITICAL),
        None,
    )
    assert confusion is not None
    assert "CVE-2016-10555" in confusion.message
    assert header_name in confusion.message
    assert report.grade is Grade.F


def test_asymmetric_alg_with_smuggling_does_not_trigger_confusion():
    # RS256 + jku is already flagged by _audit_header_key_smuggling; the
    # key-confusion cross-check must not double-fire for asymmetric algorithms.
    report = run_audit({"alg": "RS256", "typ": "JWT", "jku": "https://trusted.com/keys"}, {})
    alg_criticals = [
        f for f in report.findings if f.field == "alg" and f.severity is Severity.CRITICAL
    ]
    assert alg_criticals == []


def test_hs_alg_without_smuggling_does_not_trigger_confusion():
    report = run_audit({"alg": "HS256", "typ": "JWT"}, {})
    alg_criticals = [
        f for f in report.findings if f.field == "alg" and f.severity is Severity.CRITICAL
    ]
    assert alg_criticals == []


# crit header (RFC 7515)


def test_crit_absent_emits_nothing():
    assert _audit_crit({"alg": "RS256"}) == []


def test_crit_well_formed_with_present_params_is_warn():
    findings = _audit_crit({"alg": "RS256", "crit": ["exp"], "exp": 0})
    assert findings[0].severity is Severity.WARN
    assert "crit" in findings[0].message


def test_crit_listing_missing_param_is_critical():
    findings = _audit_crit({"alg": "RS256", "crit": ["b64"]})
    assert findings[0].severity is Severity.CRITICAL
    assert "b64" in findings[0].message


def test_crit_empty_list_is_warn():
    findings = _audit_crit({"alg": "RS256", "crit": []})
    assert findings[0].severity is Severity.WARN


def test_crit_non_list_is_critical():
    findings = _audit_crit({"alg": "RS256", "crit": "exp"})
    assert findings[0].severity is Severity.CRITICAL


def test_crit_list_with_non_string_entries_is_critical():
    findings = _audit_crit({"alg": "RS256", "crit": ["exp", 42]})
    assert findings[0].severity is Severity.CRITICAL


# b64 header (RFC 7797)


def test_b64_absent_emits_nothing():
    assert _audit_b64({"alg": "RS256"}) == []


def test_b64_false_is_warn():
    findings = _audit_b64({"alg": "RS256", "b64": False})
    assert findings[0].severity is Severity.WARN
    assert "RFC 7797" in findings[0].message


def test_b64_true_is_info():
    findings = _audit_b64({"alg": "RS256", "b64": True})
    assert findings[0].severity is Severity.INFO


def test_b64_non_boolean_is_warn():
    findings = _audit_b64({"alg": "RS256", "b64": "false"})
    assert findings[0].severity is Severity.WARN
    assert "str" in findings[0].message
