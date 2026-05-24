from dataclasses import dataclass
from enum import Enum
import time

LONG_TTL_THRESHOLD = 60 * 60 * 24 * 30

SYMMETRIC_ALGORITHMS = {"HS256", "HS384", "HS512"}
ASYMMETRIC_ALGORITHMS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}
SENSITIVE_FIELDS = {"password", "secret", "token", "ssn", "credit_card", "email"}


class Severity(Enum):
    CRITICAL = "CRITICAL"
    WARN = "WARN"
    INFO = "INFO"
    PASS = "PASS"


@dataclass
class Finding:
    severity: Severity
    field: str
    message: str


def audit(header: dict, payload: dict) -> list[Finding]:
    findings = []
    findings.extend(_audit_algorithm(header))
    findings.extend(_audit_expiry(payload))
    findings.extend(_audit_nbf(payload))
    findings.extend(_audit_claims(payload))
    findings.extend(_audit_sensitive_fields(payload))
    return findings


def _audit_algorithm(header: dict) -> list[Finding]:
    alg = header.get("alg", "").upper()
    if alg == "NONE":
        return [Finding(Severity.CRITICAL, "alg", "none algorithm means no signature, token is completely unsigned")]
    if alg in SYMMETRIC_ALGORITHMS:
        return [Finding(Severity.WARN, "alg", f"{alg} is symmetric, secret must be strong or it can be brute-forced")]
    if alg in ASYMMETRIC_ALGORITHMS:
        return [Finding(Severity.PASS, "alg", f"{alg} uses asymmetric keys, good choice")]
    return [Finding(Severity.WARN, "alg", f"Unknown algorithm: {alg}")]


def _audit_expiry(payload: dict) -> list[Finding]:
    exp = payload.get("exp")
    if exp is None:
        return [Finding(Severity.WARN, "exp", "No expiry claim, token never expires")]
    now = time.time()
    if exp < now:
        return [Finding(Severity.CRITICAL, "exp", "Token is expired")]
    if exp - now > LONG_TTL_THRESHOLD:
        return [Finding(Severity.WARN, "exp", "Token expiry is more than 30 days, consider a shorter TTL")]
    return [Finding(Severity.PASS, "exp", "Token expiry looks reasonable")]


def _audit_nbf(payload: dict) -> list[Finding]:
    nbf = payload.get("nbf")
    if nbf is None:
        return []
    if time.time() < nbf:
        return [Finding(Severity.CRITICAL, "nbf", "Token is not yet valid (nbf is in the future)")]
    return [Finding(Severity.PASS, "nbf", "Token is past its not-before time")]


def _audit_claims(payload: dict) -> list[Finding]:
    return [
        Finding(Severity.INFO, claim, f"Missing {claim} claim")
        for claim in ("iss", "aud", "iat")
        if claim not in payload
    ]


def _audit_sensitive_fields(payload: dict) -> list[Finding]:
    return [
        Finding(Severity.WARN, key, f"Payload contains sensitive field {key!r}, JWTs are encoded not encrypted")
        for key in payload
        if key.lower() in SENSITIVE_FIELDS
    ]
