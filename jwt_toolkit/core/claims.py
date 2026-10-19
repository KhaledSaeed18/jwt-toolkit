from dataclasses import dataclass
from typing import Literal

from jwt_toolkit.core.encoding import JsonObject

# Clock-skew allowance before an iat in the future is reported.
IAT_FUTURE_LEEWAY_SECONDS = 60

type CheckResult = Literal["PASS", "FAIL", "WARN"]


@dataclass(frozen=True)
class Check:
    result: CheckResult
    check: str
    detail: str


def is_numeric_date(value: object) -> bool:
    # bool subclasses int in Python, but true/false is not a NumericDate.
    return isinstance(value, int | float) and not isinstance(value, bool)


def check_critical_headers(header: JsonObject) -> list[Check]:
    checks: list[Check] = []
    # RFC 7515 4.1.11: a recipient that does not implement every extension
    # listed in crit MUST reject the token. This verifier implements none.
    if "crit" in header:
        crit = header["crit"]
        if (
            not isinstance(crit, list)
            or not crit
            or not all(isinstance(name, str) for name in crit)
            or len(set(crit)) != len(crit)
        ):
            checks.append(
                Check("FAIL", "crit", "crit header is malformed, token cannot be trusted")
            )
        else:
            checks.append(
                Check(
                    "FAIL", "crit", f"Token requires unsupported header extensions: {sorted(crit)}"
                )
            )
    # RFC 7797 unencoded payloads change the signing input; they are not supported.
    if "b64" in header and header["b64"] is not True:
        checks.append(
            Check("FAIL", "b64", "Unencoded payload (b64) is not supported, token rejected")
        )
    return checks


def check_time_claims(payload: JsonObject, *, now: float, leeway: int = 0) -> list[Check]:
    checks: list[Check] = []

    exp = payload.get("exp")
    if exp is None:
        checks.append(Check("WARN", "exp", "No expiry claim"))
    elif not is_numeric_date(exp):
        checks.append(Check("FAIL", "exp", f"exp is not a number: {exp!r}"))
    elif now >= exp + leeway:
        # RFC 7519 4.1.4: the current time MUST be before exp.
        checks.append(Check("FAIL", "exp", "Token is expired"))
    else:
        checks.append(Check("PASS", "exp", "Token is not expired"))

    nbf = payload.get("nbf")
    if nbf is not None:
        if not is_numeric_date(nbf):
            checks.append(Check("FAIL", "nbf", f"nbf is not a number: {nbf!r}"))
        elif nbf > now + leeway:
            checks.append(Check("FAIL", "nbf", "Token is not yet valid (nbf is in the future)"))

    iat = payload.get("iat")
    if iat is not None:
        if not is_numeric_date(iat):
            checks.append(Check("WARN", "iat", f"iat is not a number: {iat!r}"))
        elif iat > now + IAT_FUTURE_LEEWAY_SECONDS + leeway:
            checks.append(
                Check("WARN", "iat", "iat is in the future: clock skew or a forged token")
            )

    return checks


def check_issuer(payload: JsonObject, issuer: str) -> Check:
    if "iss" not in payload:
        return Check("FAIL", "iss", f"No iss claim, expected {issuer!r}")
    if payload["iss"] == issuer:
        return Check("PASS", "iss", f"Issuer matches {issuer!r}")
    return Check("FAIL", "iss", f"Issuer mismatch: expected {issuer!r}, got {payload['iss']!r}")


def check_audience(payload: JsonObject, audience: str) -> Check:
    # RFC 7519 4.1.3: aud is a single string or a list of strings.
    if "aud" not in payload:
        return Check("FAIL", "aud", f"No aud claim, expected {audience!r}")
    aud = payload["aud"]
    accepted = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []
    if audience in accepted:
        return Check("PASS", "aud", f"Audience matches {audience!r}")
    return Check("FAIL", "aud", f"Audience mismatch: expected {audience!r}, got {aud!r}")
