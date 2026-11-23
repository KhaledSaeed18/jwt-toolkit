import dataclasses

from jwt_toolkit.core.algorithms import (
    ASYMMETRIC_ALGORITHMS,
    SUPPORTED_ALGORITHMS,
    canonical_algorithm,
    require_algorithm,
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
    # Any signing algorithm we can verify (HMAC or asymmetric), validated in core
    # as an exact-case wire value; this layer only adds the panel title.
    try:
        return require_algorithm(header).name
    except UnsupportedAlgorithmError as exc:
        raise dataclasses.replace(exc, title="Verification Error") from exc


def is_asymmetric(alg: str) -> bool:
    return canonical_algorithm(alg) in ASYMMETRIC_ALGORITHMS


def is_hmac(alg: str) -> bool:
    return canonical_algorithm(alg) in SUPPORTED_ALGORITHMS
