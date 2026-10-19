from jwt_toolkit.core.crypto import (
    ALL_SIGNING_ALGORITHMS,
    ASYMMETRIC_ALGORITHMS,
    SUPPORTED_ALGORITHMS,
    canonical_algorithm,
)
from jwt_toolkit.core.encoding import JsonObject
from jwt_toolkit.core.errors import UnsupportedAlgorithmError


def ensure_hmac_algorithm(header: JsonObject, *, action: str) -> str:
    # Validates that the token's alg is one we can sign/verify with HMAC.
    # `action` is the verb used in error copy — "verify"/"crack"/etc.
    alg = str(header.get("alg", "")).upper()
    if alg == "NONE":
        raise UnsupportedAlgorithmError(
            title="Verification Error" if action == "verify" else "Cannot Crack",
            headline=(
                "Token uses alg: none, it has no signature to verify"
                if action == "verify"
                else "Token uses alg: none, there is no signature to crack"
            ),
            details=(
                (
                    "This token is completely unsigned and trivially forgeable"
                    if action == "verify"
                    else "An unsigned token can be forged without any secret"
                ),
            ),
        )
    if alg not in SUPPORTED_ALGORITHMS:
        raise UnsupportedAlgorithmError(
            title="Verification Error" if action == "verify" else "Cannot Crack",
            headline=f"Unsupported algorithm: {alg}",
            details=(
                f"Supported : {', '.join(SUPPORTED_ALGORITHMS)}"
                if action == "verify"
                else f"crack only works on HMAC tokens: {', '.join(SUPPORTED_ALGORITHMS)}",
            ),
        )
    return alg


def ensure_signing_algorithm(header: JsonObject) -> str:
    # Validates that the token's alg is any signing algorithm we can verify
    # (HMAC or asymmetric). alg is case-sensitive (RFC 7515 4.1.1), so only
    # the exact registered spelling is accepted.
    alg = header.get("alg")
    if isinstance(alg, str) and alg.upper() == "NONE":
        raise UnsupportedAlgorithmError(
            title="Verification Error",
            headline="Token uses alg: none, it has no signature to verify",
            details=("This token is completely unsigned and trivially forgeable",),
        )
    if not isinstance(alg, str) or alg not in ALL_SIGNING_ALGORITHMS:
        details = [f"Supported: {', '.join(sorted(ALL_SIGNING_ALGORITHMS))}"]
        canonical = canonical_algorithm(alg) if isinstance(alg, str) else None
        if canonical is not None:
            details.append(f"alg is case-sensitive; {alg!r} is not {canonical!r}")
        shown = alg if isinstance(alg, str) else repr(alg)
        raise UnsupportedAlgorithmError(
            title="Verification Error",
            headline=f"Unsupported algorithm: {shown}",
            details=tuple(details),
        )
    return alg


def is_asymmetric(alg: str) -> bool:
    return canonical_algorithm(alg) in ASYMMETRIC_ALGORITHMS


def is_hmac(alg: str) -> bool:
    return canonical_algorithm(alg) in SUPPORTED_ALGORITHMS
