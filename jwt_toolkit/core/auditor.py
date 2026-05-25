import re
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from enum import Enum

# Auditor module — static security analysis of a decoded JWT header and payload.

# Symmetric algorithms — vulnerable to offline brute-force if the secret is weak.
SYMMETRIC_ALGORITHMS = {"HS256", "HS384", "HS512"}

# Asymmetric algorithms — public/private key pairs, no shared secret to crack.
ASYMMETRIC_ALGORITHMS = {
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
}

# Lifetime tiers, evaluated longest-first so the most severe match wins.
# Severity is derived in _audit_expiry to keep the table flat and editable.
_LIFETIME_TIERS: tuple[tuple[int, str], ...] = (
    (60 * 60 * 24 * 30, "more than 30 days"),
    (60 * 60 * 24, "more than 24 hours"),
    (60 * 60, "more than 1 hour"),
)

# Small clock-skew leeway when judging "iat in the future" — most systems drift a bit.
_IAT_FUTURE_LEEWAY_SECONDS = 60

# Header parameters that smuggle a key into the token itself.
# An attacker who controls these can sometimes coerce the verifier into trusting their key.
_KEY_SMUGGLING_HEADERS = ("jwk", "jku", "x5u", "x5c")

# CVE references attached to findings whose shape matches a known disclosed vulnerability.
# Keep the catalogue narrow — only well-known CVEs that map cleanly to a single header pattern.
_CVE_ALG_NONE = "CVE-2015-2951"
_CVE_HS_RS_CONFUSION = "CVE-2016-10555"
_CVE_JWK_INJECTION = "CVE-2018-0114"

# Characters that have caused real-world `kid` injection bugs
# (path traversal, SQLi, command injection, null-byte truncation).
# "/" is intentionally excluded — it is a legitimate path separator in
# key IDs like "prod-key/v1"; ".." already catches actual path traversal.
_KID_DANGEROUS_CHARS = ("..", "\\", "\x00", "'", '"', ";", "`", "$(")

# Acceptable `typ` values per RFC 7519 / RFC 9068 (access tokens).
_VALID_TYP_VALUES = {"JWT", "AT+JWT"}

# Heuristics for sensitive-value scanning. Conservative on purpose — we'd rather
# miss a borderline case than spam the report with false positives.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DIGITS_ONLY_RE = re.compile(r"^\d{13,19}$")

# Field names that should never appear in a JWT payload (encoded, not encrypted).
SENSITIVE_FIELDS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "refresh_token",
    "ssn",
    "credit_card",
    "card_number",
    "cvv",
    "email",  # email is borderline but common enough to flag
}


# Severity levels — ordered so higher-severity findings sort first.
class Severity(Enum):
    CRITICAL = "CRITICAL"
    WARN = "WARN"
    INFO = "INFO"
    PASS = "PASS"


# Letter grade derived from the set of findings.
class Grade(Enum):
    A = "A"
    B = "B"
    C = "C"
    F = "F"


# Stable sort order for findings — CRITICAL first, PASS last.
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.WARN: 1,
    Severity.INFO: 2,
    Severity.PASS: 3,
}


@dataclass(frozen=True)
class Finding:
    severity: Severity
    field: str
    message: str
    # Short, actionable next step. Optional so legacy callers stay valid.
    recommendation: str | None = None


@dataclass(frozen=True)
class Report:
    findings: tuple[Finding, ...]
    grade: Grade
    counts: dict[Severity, int] = field(default_factory=dict)


# Public entry point. The command layer should only ever call this — never the
# individual `_audit_*` helpers or `audit()` directly — so grading and sorting
# stay in lockstep with the findings.
def run_audit(
    header: dict,
    payload: dict,
    *,
    required_claims: frozenset[str] = frozenset(),
) -> Report:
    findings = tuple(
        sorted(
            audit(header, payload, required_claims=required_claims),
            key=_finding_sort_key,
        )
    )
    return Report(
        findings=findings,
        grade=_grade(findings),
        counts=_count_by_severity(findings),
    )


# Legacy in-module entry point. Kept because `run_audit` composes it.
def audit(
    header: dict,
    payload: dict,
    *,
    required_claims: frozenset[str] = frozenset(),
) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_audit_algorithm(header))
    findings.extend(_audit_typ(header))
    findings.extend(_audit_kid_injection(header))
    findings.extend(_audit_header_key_smuggling(header))
    findings.extend(_audit_alg_key_confusion(header))
    findings.extend(_audit_crit(header))
    findings.extend(_audit_b64(header))
    findings.extend(_audit_expiry(payload))
    findings.extend(_audit_nbf(payload))
    findings.extend(_audit_iat(payload))
    findings.extend(_audit_jti(payload))
    findings.extend(_audit_claims(payload, required_claims=required_claims))
    findings.extend(_audit_sensitive_fields(payload))
    findings.extend(_audit_sensitive_values(payload))
    return findings


# Grading


# Single source of truth for grade boundaries. `--strict` lives at the command
# layer; this function never sees it.
def _grade(findings: Iterable[Finding]) -> Grade:
    findings = tuple(findings)
    if any(f.severity is Severity.CRITICAL for f in findings):
        return Grade.F
    warns = sum(1 for f in findings if f.severity is Severity.WARN)
    if warns >= 3:
        return Grade.C
    if warns >= 1:
        return Grade.B
    return Grade.A


def _count_by_severity(findings: Iterable[Finding]) -> dict[Severity, int]:
    counts = dict.fromkeys(Severity, 0)
    for f in findings:
        counts[f.severity] += 1
    return counts


def _finding_sort_key(f: Finding) -> tuple[int, str]:
    # Group by severity, then alphabetise by field for deterministic output.
    return (_SEVERITY_ORDER[f.severity], f.field)


# Header checks
def _audit_algorithm(header: dict) -> list[Finding]:
    alg = str(header.get("alg", "")).upper()
    if alg == "NONE":
        return [
            Finding(
                Severity.CRITICAL,
                "alg",
                f"alg:none means the token carries no signature ({_CVE_ALG_NONE})",
                "Reject tokens whose header advertises alg:none at the verifier.",
            )
        ]
    if alg in SYMMETRIC_ALGORITHMS:
        return [
            Finding(
                Severity.WARN,
                "alg",
                f"{alg} is symmetric — the shared secret must be strong or it can be brute-forced",
                "Use a cryptographically strong secret (jwt-toolkit generate-secret) "
                "or migrate to an asymmetric algorithm.",
            )
        ]
    if alg in ASYMMETRIC_ALGORITHMS:
        return [Finding(Severity.PASS, "alg", f"{alg} uses asymmetric keys")]
    return [
        Finding(
            Severity.WARN,
            "alg",
            f"Unknown algorithm: {alg or '(missing)'}",
            "Pin the verifier to an explicit allow-list of algorithms.",
        )
    ]


def _audit_typ(header: dict) -> list[Finding]:
    if "typ" not in header:
        return [
            Finding(
                Severity.INFO,
                "typ",
                "No typ header — consumers cannot distinguish JWTs from other JOSE objects",
            )
        ]
    typ = str(header["typ"]).upper()
    if typ in _VALID_TYP_VALUES:
        return [Finding(Severity.PASS, "typ", f"typ={header['typ']}")]
    return [
        Finding(
            Severity.WARN,
            "typ",
            f"Unexpected typ value: {typ!r}",
            "Set typ to 'JWT' or 'at+jwt' so verifiers can reject unrelated tokens.",
        )
    ]


def _audit_kid_injection(header: dict) -> list[Finding]:
    kid = header.get("kid")
    if kid is None:
        return []
    if not isinstance(kid, str):
        return [
            Finding(
                Severity.WARN,
                "kid",
                f"kid is not a string ({type(kid).__name__}) — verifiers may mishandle it",
            )
        ]
    hit = next((c for c in _KID_DANGEROUS_CHARS if c in kid), None)
    if hit is not None:
        return [
            Finding(
                Severity.CRITICAL,
                "kid",
                f"kid contains dangerous sequence {hit!r} — possible injection attempt",
                "Look up keys by exact match against an allow-list; never concatenate kid "
                "into a path, SQL query, or shell command.",
            )
        ]
    return [Finding(Severity.PASS, "kid", "kid looks well-formed")]


def _audit_header_key_smuggling(header: dict) -> list[Finding]:
    findings: list[Finding] = []
    for name in _KEY_SMUGGLING_HEADERS:
        if name not in header:
            continue
        value = header[name]
        if name == "jwk":
            findings.append(
                Finding(
                    Severity.CRITICAL,
                    "jwk",
                    f"Header embeds a JWK — an attacker can ship their own key with the token ({_CVE_JWK_INJECTION})",
                    "Ignore the embedded jwk header; resolve keys from a server-side trust store.",
                )
            )
            continue
        # jku, x5u, x5c — URLs to remote key material.
        url = str(value) if not isinstance(value, list) else (value[0] if value else "")
        if isinstance(url, str) and url.lower().startswith("http://"):
            findings.append(
                Finding(
                    Severity.CRITICAL,
                    name,
                    f"{name} uses plain HTTP — key material can be MITM'd",
                    f"Require HTTPS for {name}, and pin to an allow-list of hosts.",
                )
            )
        else:
            findings.append(
                Finding(
                    Severity.WARN,
                    name,
                    f"{name} header references external key material",
                    f"Pin {name} to an allow-list of trusted hosts; never blindly fetch.",
                )
            )
    return findings


# Cross-check: HS* algorithm combined with header-supplied key material is the
# classic key-confusion shape — the verifier may resolve the "public key" from
# the header and then use it as an HMAC secret.
def _audit_alg_key_confusion(header: dict) -> list[Finding]:
    alg = str(header.get("alg", "")).upper()
    if alg not in SYMMETRIC_ALGORITHMS:
        return []
    smuggled = [name for name in _KEY_SMUGGLING_HEADERS if name in header]
    if not smuggled:
        return []
    return [
        Finding(
            Severity.CRITICAL,
            "alg",
            f"alg={alg} combined with {', '.join(smuggled)} header(s) — "
            f"classic key-confusion shape ({_CVE_HS_RS_CONFUSION})",
            "Pin the verifier to one algorithm family per key; never resolve HMAC "
            "secrets from header-supplied key material.",
        )
    ]


def _audit_crit(header: dict) -> list[Finding]:
    if "crit" not in header:
        return []
    crit = header["crit"]
    if not isinstance(crit, list) or not all(isinstance(x, str) for x in crit):
        return [
            Finding(
                Severity.CRITICAL,
                "crit",
                "crit header is malformed — RFC 7515 requires a non-empty list of strings",
                "Reject the token; a malformed crit is unparseable and unsafe to ignore.",
            )
        ]
    if not crit:
        return [
            Finding(
                Severity.WARN,
                "crit",
                "crit header is an empty list — RFC 7515 requires at least one entry",
                "Reject tokens with an empty crit list.",
            )
        ]
    dangling = [name for name in crit if name not in header]
    if dangling:
        return [
            Finding(
                Severity.CRITICAL,
                "crit",
                f"crit lists parameter(s) not present in the header: {dangling}",
                "Reject the token — every name in crit must be a recognised, present header parameter.",
            )
        ]
    return [
        Finding(
            Severity.WARN,
            "crit",
            f"crit header is present ({crit}) — many verifiers silently ignore it",
            "Confirm the verifier rejects tokens whose crit extensions it does not implement.",
        )
    ]


def _audit_b64(header: dict) -> list[Finding]:
    if "b64" not in header:
        return []
    b64 = header["b64"]
    if b64 is False:
        return [
            Finding(
                Severity.WARN,
                "b64",
                "b64:false (RFC 7797) — payload is not base64url-encoded; "
                "many verifiers mishandle this form",
                "Reject tokens with b64:false unless the verifier explicitly implements RFC 7797.",
            )
        ]
    if b64 is True:
        return [
            Finding(
                Severity.INFO,
                "b64",
                "b64:true is the default — the header is redundant but harmless",
            )
        ]
    return [
        Finding(
            Severity.WARN,
            "b64",
            f"b64 header has non-boolean value ({type(b64).__name__}) — RFC 7797 requires a boolean",
        )
    ]


# Payload checks
def _audit_expiry(payload: dict) -> list[Finding]:
    exp = payload.get("exp")
    iat = payload.get("iat")
    if exp is None:
        return [
            Finding(
                Severity.WARN,
                "exp",
                "No exp claim — token never expires",
                "Always set exp; short-lived tokens limit blast radius if leaked.",
            )
        ]
    if not isinstance(exp, (int, float)):
        return [Finding(Severity.WARN, "exp", f"exp is not numeric ({type(exp).__name__})")]

    now = time.time()
    if exp < now:
        return [Finding(Severity.CRITICAL, "exp", "Token is expired")]

    # Lifetime measured from iat when available, otherwise from now.
    lifetime = exp - (iat if isinstance(iat, (int, float)) else now)
    for threshold, suffix in _LIFETIME_TIERS:
        if lifetime > threshold:
            severity = (
                Severity.CRITICAL
                if threshold >= 60 * 60 * 24 * 30
                else Severity.WARN
                if threshold >= 60 * 60 * 24
                else Severity.INFO
            )
            return [
                Finding(
                    severity,
                    "exp",
                    f"Token lifetime is {suffix}",
                    "Shorten the TTL; pair access tokens with a refresh-token rotation flow.",
                )
            ]
    return [Finding(Severity.PASS, "exp", "Token expiry looks reasonable")]


def _audit_nbf(payload: dict) -> list[Finding]:
    nbf = payload.get("nbf")
    if nbf is None:
        return []
    if not isinstance(nbf, (int, float)):
        return [Finding(Severity.WARN, "nbf", f"nbf is not numeric ({type(nbf).__name__})")]
    if time.time() < nbf:
        return [Finding(Severity.CRITICAL, "nbf", "Token is not yet valid (nbf is in the future)")]
    return [Finding(Severity.PASS, "nbf", "Token is past its not-before time")]


def _audit_iat(payload: dict) -> list[Finding]:
    iat = payload.get("iat")
    if iat is None:
        return []
    if not isinstance(iat, (int, float)):
        return [Finding(Severity.WARN, "iat", f"iat is not numeric ({type(iat).__name__})")]
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and exp < iat:
        return [
            Finding(
                Severity.CRITICAL,
                "iat",
                "exp is earlier than iat — token is malformed and may be rejected unpredictably",
            )
        ]
    if iat > time.time() + _IAT_FUTURE_LEEWAY_SECONDS:
        return [
            Finding(
                Severity.WARN,
                "iat",
                "iat is in the future — clock skew or a forged token",
            )
        ]
    return [Finding(Severity.PASS, "iat", "iat looks sane")]


def _audit_jti(payload: dict) -> list[Finding]:
    if "jti" not in payload:
        return [
            Finding(
                Severity.INFO,
                "jti",
                "No jti claim — replay-defense via a token blocklist is harder",
                "Issue a unique jti per token so revocation and replay-detection are possible.",
            )
        ]
    return []


def _audit_claims(
    payload: dict,
    *,
    required_claims: frozenset[str] = frozenset(),
) -> list[Finding]:
    findings = []
    for claim in ("iss", "aud", "iat"):
        if claim not in payload:
            severity = Severity.WARN if claim in required_claims else Severity.INFO
            findings.append(Finding(severity, claim, f"Missing {claim} claim"))
    return findings


def _audit_sensitive_fields(payload: dict) -> list[Finding]:
    return [
        Finding(
            Severity.WARN,
            key,
            f"Payload contains sensitive field {key!r} — JWTs are encoded, not encrypted",
            "Move secrets out of the payload; pass them via a confidential side-channel.",
        )
        for key in payload
        if key.lower() in SENSITIVE_FIELDS
    ]


def _audit_sensitive_values(payload: dict) -> list[Finding]:
    # Walks nested dicts/lists looking for values that *look* like PII even when
    # the surrounding field name doesn't tip us off. Top-level keys already
    # caught by _audit_sensitive_fields are skipped to avoid duplicate findings.
    # Multiple hits of the same type are grouped into one finding to keep the
    # report readable when a payload has many PII fields.
    email_paths: list[str] = []
    card_paths: list[str] = []
    seen_paths: set[str] = set()
    skip_roots = {key for key in payload if key.lower() in SENSITIVE_FIELDS}

    for path, value in _walk(payload):
        root = path.split(".", 1)[0].split("[", 1)[0]
        if root in skip_roots or path in seen_paths or not isinstance(value, str):
            continue
        if _EMAIL_RE.match(value):
            email_paths.append(path)
            seen_paths.add(path)
        elif _DIGITS_ONLY_RE.match(value) and _looks_like_card(value):
            card_paths.append(path)
            seen_paths.add(path)

    findings: list[Finding] = []
    if email_paths:
        label = "paths" if len(email_paths) > 1 else "path"
        findings.append(
            Finding(
                Severity.WARN,
                "payload",
                f"Email-like value{'' if len(email_paths) == 1 else 's'} at {label}: "
                + ", ".join(email_paths),
                "Avoid embedding PII in JWT payloads; use an opaque subject identifier.",
            )
        )
    if card_paths:
        label = "paths" if len(card_paths) > 1 else "path"
        findings.append(
            Finding(
                Severity.CRITICAL,
                "payload",
                f"Credit-card-like value{'' if len(card_paths) == 1 else 's'} "
                f"(Luhn-valid) at {label}: " + ", ".join(card_paths),
                "Never place card data in a JWT — it is base64, not encryption.",
            )
        )
    return findings


def _walk(node, prefix: str = "") -> Iterator[tuple[str, object]]:
    # Yields (dotted_path, value) for every leaf and container in a JSON-like tree.
    if isinstance(node, dict):
        for key, value in node.items():
            child_path = f"{prefix}.{key}" if prefix else str(key)
            yield child_path, value
            yield from _walk(value, child_path)
    elif isinstance(node, list):
        for idx, value in enumerate(node):
            child_path = f"{prefix}[{idx}]"
            yield child_path, value
            yield from _walk(value, child_path)


def _looks_like_card(digits: str) -> bool:
    # Luhn checksum — keeps false positives down on long numeric IDs.
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = ord(ch) - 48
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0
