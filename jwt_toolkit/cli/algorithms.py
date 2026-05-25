from jwt_toolkit.core.crypto import SUPPORTED_ALGORITHMS
from jwt_toolkit.core.errors import UnsupportedAlgorithmError


def ensure_hmac_algorithm(header: dict, *, action: str) -> str:
    # Validates that the token's alg is one we can sign/verify with HMAC.
    # `action` is the verb used in error copy — "verify"/"crack"/etc.
    alg = str(header.get("alg", "")).upper()
    if alg == "NONE":
        raise UnsupportedAlgorithmError(
            title="Verification Error" if action == "verify" else "Cannot Crack",
            headline=(
                "Token uses alg: none, it has no signature to verify"
                if action == "verify"
                else "Token uses alg: none — there is no signature to crack"
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
