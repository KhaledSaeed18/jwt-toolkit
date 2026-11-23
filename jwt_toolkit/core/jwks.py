import json
from http.client import HTTPMessage
from typing import IO, override
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

from jwt_toolkit.core.algorithms import algorithm_spec, canonical_algorithm
from jwt_toolkit.core.encoding import JsonObject, base64url_decode
from jwt_toolkit.core.errors import (
    JwksAmbiguousError,
    JwksFetchError,
    JwksInvalidError,
    JwksNoMatchingKeyError,
    KeyAlgorithmMismatchError,
    UnsupportedAlgorithmError,
    redact_url,
)
from jwt_toolkit.core.keys import PublicKey

# RFC 7517 key sets. The fetch helper is intentionally thin: stdlib urllib only, with a fixed
# timeout. Callers (and the audit module) are responsible for trust decisions
# such as host allow-listing; this module just retrieves and parses.

JWKS_FETCH_TIMEOUT_SECONDS = 10

# Real key sets are a few kilobytes; the cap stops a hostile endpoint from
# streaming an unbounded body into memory.
MAX_JWKS_BYTES = 1_048_576

# JWK `crv` → cryptography curve class.
_CURVE_BY_CRV: dict[str, type[ec.EllipticCurve]] = {
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
}


_PERMITTED_JWKS_SCHEMES = frozenset({"https", "http", "file"})


class _NoDowngradeRedirectHandler(HTTPRedirectHandler):
    # A JWKS fetched over https must not be silently re-fetched over plain http.
    @override
    def redirect_request(
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> Request | None:
        if urlparse(req.full_url).scheme == "https" and urlparse(newurl).scheme != "https":
            raise URLError("refusing a redirect from https to a non-https URL")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_jwks(url: str, *, timeout: int = JWKS_FETCH_TIMEOUT_SECONDS) -> JsonObject:
    # Retrieves and parses a JWKS document. Supports https://, http://, and
    # file:// via urllib so tests can use local files without a live server.
    # Network and JSON failures become typed JWKS errors. URLs in messages are
    # redacted, since userinfo or a query string may carry credentials.
    scheme = urlparse(url).scheme
    if scheme not in _PERMITTED_JWKS_SCHEMES:
        raise JwksFetchError(
            f"JWKS URL scheme {scheme!r} is not permitted, use https, http, or file"
        )
    opener = build_opener(_NoDowngradeRedirectHandler)
    try:
        with opener.open(url, timeout=timeout) as response:  # nosec B310 - scheme validated above
            body = response.read(MAX_JWKS_BYTES + 1)
    except HTTPError as exc:
        raise JwksFetchError(
            f"Could not fetch JWKS from {redact_url(url)!r}: HTTP {exc.code} {exc.reason}"
        ) from exc
    except URLError as exc:
        reason = getattr(exc.reason, "strerror", None) or str(exc.reason)
        raise JwksFetchError(
            f"Could not fetch JWKS from {redact_url(url)!r}: {_scrub(reason, url)}"
        ) from exc
    except (ValueError, OSError) as exc:
        raise JwksFetchError(
            f"Could not fetch JWKS from {redact_url(url)!r}: {_scrub(str(exc), url)}"
        ) from exc
    if len(body) > MAX_JWKS_BYTES:
        raise JwksInvalidError(
            f"JWKS at {redact_url(url)!r} is larger than {MAX_JWKS_BYTES // 1024} KiB, refusing it"
        )
    try:
        document = json.loads(body)
    except json.JSONDecodeError as exc:
        raise JwksInvalidError(f"JWKS at {redact_url(url)!r} is not valid JSON: {exc.msg}") from exc
    if not isinstance(document, dict) or "keys" not in document:
        raise JwksInvalidError(f"JWKS at {redact_url(url)!r} has no 'keys' array")
    return document


def _scrub(text: str, url: str) -> str:
    # urllib messages can repeat the URL, or its userinfo, verbatim.
    netloc = urlparse(url).netloc
    text = text.replace(url, redact_url(url))
    if "@" in netloc:
        text = text.replace(netloc, netloc.rsplit("@", 1)[1])
    return text


def select_jwk(jwks: JsonObject, *, kid: str | None, alg: str) -> JsonObject:
    # Picks the single JWK that should verify a token with the given alg/kid.
    # Returns the JWK dict so the caller can decide how to materialise the key.
    keys = jwks.get("keys") or []
    if not isinstance(keys, list) or not keys:
        raise JwksInvalidError("JWKS has no keys")

    candidates = _filter_by_kid(keys, kid)
    if not candidates:
        raise JwksNoMatchingKeyError(f"No JWKS key matches kid={kid!r}")
    if len(candidates) > 1:
        # Ambiguity is a configuration bug — refusing it is safer than guessing.
        raise JwksAmbiguousError(f"Multiple JWKS keys match kid={kid!r}: JWKS is ambiguous")

    chosen = candidates[0]
    _ensure_jwk_is_for_signatures(chosen)
    _ensure_jwk_matches_alg(chosen, alg)
    return chosen


def jwk_to_public_key(jwk: JsonObject, alg: str) -> PublicKey:
    # Materialises a JWK into a verification key. Mismatches between the JWK
    # shape and the requested alg raise before any crypto operation runs.
    _ensure_jwk_matches_alg(jwk, alg)
    kty = jwk.get("kty")
    if kty == "RSA":
        return PublicKey(_rsa_public_key_from_jwk(jwk))
    if kty == "EC":
        return PublicKey(_ec_public_key_from_jwk(jwk, alg))
    if kty == "OKP":
        return PublicKey(_okp_public_key_from_jwk(jwk))
    # Defensive: _ensure_jwk_matches_alg already rejects unsupported algs, but we
    # may be called directly with a kty that has no JWS counterpart.
    raise JwksInvalidError(f"Unsupported JWK kty: {kty!r}")


def jwk_to_public_pem(jwk: JsonObject, alg: str) -> bytes:
    # PEM bytes that `verify_asymmetric` can consume.
    return jwk_to_public_key(jwk, alg).key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def resolve_jwks_public_key(
    url: str, *, kid: str | None, alg: str, timeout: int = JWKS_FETCH_TIMEOUT_SECONDS
) -> PublicKey:
    # Fetch, select and materialise in one call, so the three steps share one
    # error surface.
    jwks = fetch_jwks(url, timeout=timeout)
    return jwk_to_public_key(select_jwk(jwks, kid=kid, alg=alg), alg)


def resolve_jwks_key(
    url: str, *, kid: str | None, alg: str, timeout: int = JWKS_FETCH_TIMEOUT_SECONDS
) -> bytes:
    # The PEM form of resolve_jwks_public_key, kept for existing callers.
    return resolve_jwks_public_key(url, kid=kid, alg=alg, timeout=timeout).key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _filter_by_kid(keys: list[object], kid: str | None) -> list[JsonObject]:
    # If the token names a kid, require an exact match. If it does not, only
    # an unambiguous single-key JWKS is acceptable — falling back to "guess
    # the first key" is how kid-confusion bugs happen in real verifiers.
    if kid is not None:
        return [k for k in keys if isinstance(k, dict) and k.get("kid") == kid]
    if len(keys) != 1:
        raise JwksAmbiguousError(
            "Token header has no kid and JWKS contains multiple keys: refusing to guess"
        )
    if not isinstance(keys[0], dict):
        raise JwksInvalidError("JWKS key is not a JSON object")
    return [keys[0]]


def _ensure_jwk_is_for_signatures(jwk: JsonObject) -> None:
    # RFC 7517 4.2/4.3: a key published for encryption must not verify signatures.
    use = jwk.get("use")
    if use is not None and use != "sig":
        raise JwksInvalidError(f"JWK use={use!r} is not 'sig', so it cannot verify signatures")
    key_ops = jwk.get("key_ops")
    if key_ops is not None and (not isinstance(key_ops, list) or "verify" not in key_ops):
        raise JwksInvalidError(f"JWK key_ops={key_ops!r} does not allow 'verify'")


def _ensure_jwk_matches_alg(jwk: JsonObject, alg: str) -> None:
    alg = canonical_algorithm(alg) or alg
    spec = algorithm_spec(alg)
    expected_kty = spec.jwk_kty if spec is not None else None
    if spec is None or expected_kty is None:
        raise UnsupportedAlgorithmError(f"Cannot resolve JWK for unsupported alg: {alg}")
    actual_kty = jwk.get("kty")
    if actual_kty != expected_kty:
        raise KeyAlgorithmMismatchError(
            f"JWK kty={actual_kty!r} does not match alg={alg} (expected {expected_kty})"
        )

    # A JWK may carry its own `alg` field — if present it must agree with the
    # token's alg, otherwise the keyset is configured for a different purpose.
    jwk_alg = jwk.get("alg")
    if jwk_alg is not None and jwk_alg != alg:
        raise KeyAlgorithmMismatchError(f"JWK alg={jwk_alg!r} does not match token alg={alg}")

    # For EC keys, the curve in the JWK must match the curve required by the alg.
    if expected_kty == "OKP":
        allowed = spec.jwk_crvs
        actual_crv = jwk.get("crv")
        if actual_crv not in allowed:
            raise KeyAlgorithmMismatchError(
                f"JWK crv={actual_crv!r} does not match alg={alg} (expected {' or '.join(sorted(allowed))})"
            )

    if expected_kty == "EC":
        (expected_crv,) = spec.jwk_crvs
        actual_crv = jwk.get("crv")
        if actual_crv != expected_crv:
            raise KeyAlgorithmMismatchError(
                f"JWK crv={actual_crv!r} does not match alg={alg} (expected {expected_crv})"
            )


def _rsa_public_key_from_jwk(jwk: JsonObject) -> rsa.RSAPublicKey:
    try:
        n = _b64url_to_int(jwk["n"])
        e = _b64url_to_int(jwk["e"])
    except KeyError as exc:
        raise JwksInvalidError(f"RSA JWK is missing required field: {exc.args[0]!r}") from exc
    except ValueError as exc:
        raise JwksInvalidError(f"RSA JWK has malformed numeric field: {exc}") from exc
    return rsa.RSAPublicNumbers(e=e, n=n).public_key()


def _ec_public_key_from_jwk(jwk: JsonObject, alg: str) -> ec.EllipticCurvePublicKey:
    crv = jwk.get("crv")
    curve_cls = _CURVE_BY_CRV.get(str(crv))
    if curve_cls is None:
        raise JwksInvalidError(f"Unsupported EC curve in JWK: {crv!r}")
    try:
        x = _b64url_to_int(jwk["x"])
        y = _b64url_to_int(jwk["y"])
    except KeyError as exc:
        raise JwksInvalidError(f"EC JWK is missing required field: {exc.args[0]!r}") from exc
    except ValueError as exc:
        raise JwksInvalidError(f"EC JWK has malformed numeric field: {exc}") from exc
    # Curve already validated against alg by _ensure_jwk_matches_alg.
    del alg
    return ec.EllipticCurvePublicNumbers(x=x, y=y, curve=curve_cls()).public_key()


def _okp_public_key_from_jwk(jwk: JsonObject) -> ed25519.Ed25519PublicKey | ed448.Ed448PublicKey:
    x = jwk.get("x")
    if not isinstance(x, str):
        raise JwksInvalidError("OKP JWK is missing required field: 'x'")
    key_cls = ed25519.Ed25519PublicKey if jwk.get("crv") == "Ed25519" else ed448.Ed448PublicKey
    try:
        return key_cls.from_public_bytes(base64url_decode(x))
    except ValueError as exc:
        raise JwksInvalidError(f"OKP JWK has a malformed 'x' value: {exc}") from exc


def _b64url_to_int(value: str) -> int:
    if not isinstance(value, str):
        raise JwksInvalidError(f"expected base64url string, got {type(value).__name__}")
    return int.from_bytes(base64url_decode(value), "big")
