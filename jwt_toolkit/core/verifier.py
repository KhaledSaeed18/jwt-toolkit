"""One verification pipeline shared by `verify` and `audit`.

The supplied key decides the algorithm family. A token that names another
family, no algorithm, or alg: none fails the signature check as a verdict on the
token; it is never trusted and never an error. A key that cannot be used at all
(unreadable, wrong curve, JWKS without a matching key) raises a typed error.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from jwt_toolkit.core.algorithms import AlgorithmSpec, require_algorithm
from jwt_toolkit.core.claims import (
    Check,
    check_audience,
    check_critical_headers,
    check_issuer,
    check_time_claims,
)
from jwt_toolkit.core.crypto import verify_with_key
from jwt_toolkit.core.decoder import DecodedToken
from jwt_toolkit.core.errors import UnsupportedAlgorithmError
from jwt_toolkit.core.keys import HmacKey, PublicKey, VerificationKey

# Picks the public key for a token once its algorithm is known, for example from
# a JWKS by `kid`. Raises a typed error when no usable key exists.
type KeyResolver = Callable[[DecodedToken, AlgorithmSpec], PublicKey]

SIGNATURE_VALID = "Signature is valid"
SIGNATURE_INVALID = "Signature is invalid, wrong key or tampered token"


@dataclass(frozen=True)
class Expectations:
    issuer: str | None = None
    audience: str | None = None
    # Clock-skew tolerance in seconds for exp and nbf.
    leeway: int = 0


_NO_EXPECTATIONS = Expectations()


@dataclass(frozen=True)
class VerificationResult:
    checks: tuple[Check, ...]

    @property
    def valid(self) -> bool:
        return not any(check.result == "FAIL" for check in self.checks)


def check_signature(decoded: DecodedToken, key: VerificationKey | KeyResolver) -> Check:
    uses_secret = isinstance(key, HmacKey)
    try:
        spec = require_algorithm(decoded.header)
    except UnsupportedAlgorithmError as exc:
        return Check("FAIL", "signature", " ".join((exc.headline, *exc.details[1:])))
    if uses_secret and not spec.is_hmac:
        return Check(
            "FAIL",
            "signature",
            f"Token claims {spec.name}, but an HMAC secret was supplied; the key decides the "
            "algorithm, so the token is rejected",
        )
    if not uses_secret and spec.is_hmac:
        return Check(
            "FAIL",
            "signature",
            f"Token claims {spec.name}, but a public key was supplied; accepting it would be "
            "algorithm confusion (CVE-2016-10555)",
        )
    verification_key = key if isinstance(key, HmacKey | PublicKey) else key(decoded, spec)
    message = f"{decoded.header_b64}.{decoded.payload_b64}".encode()
    if verify_with_key(message, decoded.signature, verification_key, spec):
        return Check("PASS", "signature", SIGNATURE_VALID)
    return Check("FAIL", "signature", SIGNATURE_INVALID)


def verify_token(
    decoded: DecodedToken,
    *,
    key: VerificationKey | KeyResolver,
    now: float,
    expected: Expectations = _NO_EXPECTATIONS,
    key_checks: Sequence[Check] = (),
) -> VerificationResult:
    # `now` is injected once, so every time-based check sees the same instant.
    # `key_checks` are reported right after the signature, for facts about where
    # the key came from (for example a JWKS fetched over plain HTTP).
    checks = [
        check_signature(decoded, key),
        *key_checks,
        *check_critical_headers(decoded.header),
        *check_time_claims(decoded.payload, now=now, leeway=expected.leeway),
    ]
    if expected.issuer is not None:
        checks.append(check_issuer(decoded.payload, expected.issuer))
    if expected.audience is not None:
        checks.append(check_audience(decoded.payload, expected.audience))
    return VerificationResult(tuple(checks))
