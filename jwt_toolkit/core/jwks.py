import json
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from jwt_toolkit.core.encoding import base64url_decode

# JWKS module — resolve a verification key from a JSON Web Key Set (RFC 7517).
#
# The fetch helper is intentionally thin: stdlib urllib only, with a fixed
# timeout. Callers (and the audit module) are responsible for trust decisions
# such as host allow-listing — this module just retrieves and parses.

JWKS_FETCH_TIMEOUT_SECONDS = 10

# JWS algorithm → expected JWK key-type. Used to reject mismatches at selection
# time rather than producing a confusing crypto error later.
_KTY_BY_ALG = {
    "RS256": "RSA",
    "RS384": "RSA",
    "RS512": "RSA",
    "PS256": "RSA",
    "PS384": "RSA",
    "PS512": "RSA",
    "ES256": "EC",
    "ES384": "EC",
    "ES512": "EC",
}

# JWS ES* alg → expected JWK `crv` parameter per RFC 7518 §6.2.1.1.
_CRV_BY_ALG = {
    "ES256": "P-256",
    "ES384": "P-384",
    "ES512": "P-521",
}

# JWK `crv` → cryptography curve class.
_CURVE_BY_CRV: dict[str, type[ec.EllipticCurve]] = {
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
}


_PERMITTED_JWKS_SCHEMES = frozenset({"https", "http", "file"})


def fetch_jwks(url: str, *, timeout: int = JWKS_FETCH_TIMEOUT_SECONDS) -> dict:
    # Retrieves and parses a JWKS document. Supports https://, http://, and
    # file:// via urllib so tests can use local files without a live server.
    # Network and JSON failures are normalised to ValueError so the CLI layer
    # has a single exception class to render.
    scheme = urlparse(url).scheme
    if scheme not in _PERMITTED_JWKS_SCHEMES:
        raise ValueError(f"JWKS URL scheme {scheme!r} is not permitted — use https or http")
    try:
        with urlopen(url, timeout=timeout) as response:  # nosec B310 — scheme validated above
            body = response.read()
    except (URLError, ValueError, OSError) as exc:
        raise ValueError(f"Could not fetch JWKS from {url!r}: {exc}") from exc
    try:
        document = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ValueError(f"JWKS at {url!r} is not valid JSON: {exc.msg}") from exc
    if not isinstance(document, dict) or "keys" not in document:
        raise ValueError(f"JWKS at {url!r} has no 'keys' array")
    return document


def select_jwk(jwks: dict, *, kid: str | None, alg: str) -> dict:
    # Picks the single JWK that should verify a token with the given alg/kid.
    # Returns the JWK dict so the caller can decide how to materialise the key.
    keys = jwks.get("keys") or []
    if not isinstance(keys, list) or not keys:
        raise ValueError("JWKS has no keys")

    candidates = _filter_by_kid(keys, kid)
    if not candidates:
        raise ValueError(f"No JWKS key matches kid={kid!r}")
    if len(candidates) > 1:
        # Ambiguity is a configuration bug — refusing it is safer than guessing.
        raise ValueError(f"Multiple JWKS keys match kid={kid!r} — JWKS is ambiguous")

    chosen = candidates[0]
    _ensure_jwk_matches_alg(chosen, alg)
    return chosen


def jwk_to_public_pem(jwk: dict, alg: str) -> bytes:
    # Materialises a JWK into PEM bytes that `verify_asymmetric` can consume.
    # Mismatches between the JWK shape and the requested alg surface as
    # ValueError before any crypto operation runs.
    _ensure_jwk_matches_alg(jwk, alg)
    kty = jwk.get("kty")
    public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey
    if kty == "RSA":
        public_key = _rsa_public_key_from_jwk(jwk)
    elif kty == "EC":
        public_key = _ec_public_key_from_jwk(jwk, alg)
    else:
        # Defensive — _ensure_jwk_matches_alg already rejects unsupported algs,
        # but we may be called directly via a kty that has no JWS counterpart.
        raise ValueError(f"Unsupported JWK kty: {kty!r}")
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def resolve_jwks_key(
    url: str, *, kid: str | None, alg: str, timeout: int = JWKS_FETCH_TIMEOUT_SECONDS
) -> bytes:
    # End-to-end convenience: fetch → select → materialise. The CLI layer
    # should call this so the three steps share one error surface.
    jwks = fetch_jwks(url, timeout=timeout)
    jwk = select_jwk(jwks, kid=kid, alg=alg)
    return jwk_to_public_pem(jwk, alg)


# Internal helpers


def _filter_by_kid(keys: list, kid: str | None) -> list:
    # If the token names a kid, require an exact match. If it does not, only
    # an unambiguous single-key JWKS is acceptable — falling back to "guess
    # the first key" is how kid-confusion bugs happen in real verifiers.
    if kid is not None:
        return [k for k in keys if isinstance(k, dict) and k.get("kid") == kid]
    if len(keys) != 1:
        raise ValueError(
            "Token header has no kid and JWKS contains multiple keys — refusing to guess"
        )
    return list(keys)


def _ensure_jwk_matches_alg(jwk: dict, alg: str) -> None:
    alg = alg.upper()
    expected_kty = _KTY_BY_ALG.get(alg)
    if expected_kty is None:
        raise ValueError(f"Cannot resolve JWK for unsupported alg: {alg}")
    actual_kty = jwk.get("kty")
    if actual_kty != expected_kty:
        raise ValueError(
            f"JWK kty={actual_kty!r} does not match alg={alg} (expected {expected_kty})"
        )

    # A JWK may carry its own `alg` field — if present it must agree with the
    # token's alg, otherwise the keyset is configured for a different purpose.
    jwk_alg = jwk.get("alg")
    if jwk_alg is not None and str(jwk_alg).upper() != alg:
        raise ValueError(f"JWK alg={jwk_alg!r} does not match token alg={alg}")

    # For EC keys, the curve in the JWK must match the curve required by the alg.
    if expected_kty == "EC":
        expected_crv = _CRV_BY_ALG[alg]
        actual_crv = jwk.get("crv")
        if actual_crv != expected_crv:
            raise ValueError(
                f"JWK crv={actual_crv!r} does not match alg={alg} (expected {expected_crv})"
            )


def _rsa_public_key_from_jwk(jwk: dict) -> rsa.RSAPublicKey:
    try:
        n = _b64url_to_int(jwk["n"])
        e = _b64url_to_int(jwk["e"])
    except KeyError as exc:
        raise ValueError(f"RSA JWK is missing required field: {exc.args[0]!r}") from exc
    except ValueError as exc:
        raise ValueError(f"RSA JWK has malformed numeric field: {exc}") from exc
    return rsa.RSAPublicNumbers(e=e, n=n).public_key()


def _ec_public_key_from_jwk(jwk: dict, alg: str) -> ec.EllipticCurvePublicKey:
    crv = jwk.get("crv")
    curve_cls = _CURVE_BY_CRV.get(str(crv))
    if curve_cls is None:
        raise ValueError(f"Unsupported EC curve in JWK: {crv!r}")
    try:
        x = _b64url_to_int(jwk["x"])
        y = _b64url_to_int(jwk["y"])
    except KeyError as exc:
        raise ValueError(f"EC JWK is missing required field: {exc.args[0]!r}") from exc
    except ValueError as exc:
        raise ValueError(f"EC JWK has malformed numeric field: {exc}") from exc
    # Curve already validated against alg by _ensure_jwk_matches_alg.
    del alg
    return ec.EllipticCurvePublicNumbers(x=x, y=y, curve=curve_cls()).public_key()


def _b64url_to_int(value: str) -> int:
    if not isinstance(value, str):
        raise ValueError(f"expected base64url string, got {type(value).__name__}")
    return int.from_bytes(base64url_decode(value), "big")
