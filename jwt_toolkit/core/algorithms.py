import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519

from jwt_toolkit.core.encoding import JsonObject
from jwt_toolkit.core.errors import UnsupportedAlgorithmError


class Family(StrEnum):
    HMAC = "HMAC"
    RSA = "RSA"
    PSS = "PSS"
    EC = "EC"
    OKP = "OKP"


@dataclass(frozen=True)
class AlgorithmSpec:
    # Everything the toolkit needs to know about one JWS algorithm (RFC 7518, RFC 8037).
    name: str
    family: Family
    # HMAC: the hashlib constructor `crack` and `sign` use.
    hmac_digest: Callable[..., Any] | None = None
    # RSA, PSS and EC: the hash for the signature scheme.
    hash: Callable[[], hashes.HashAlgorithm] | None = None
    # JWK `kty` the verifying key must have; None for HMAC, which JWKS never serves here.
    jwk_kty: str | None = None
    # Accepted JWK `crv` values (EC and OKP).
    jwk_crvs: frozenset[str] = frozenset()
    # EC: the one curve RFC 7518 3.4 allows; other curves must be rejected.
    curve: type[ec.EllipticCurve] | None = None
    # EC: size of r and of s in the raw r || s signature.
    ec_component_bytes: int | None = None
    # OKP: the key classes that may sign and verify; plain "EdDSA" takes its curve from the key.
    okp_private_types: tuple[type, ...] = ()
    okp_public_types: tuple[type, ...] = ()

    @property
    def is_hmac(self) -> bool:
        return self.family is Family.HMAC


def _hmac(name: str, digest: Callable[..., Any]) -> AlgorithmSpec:
    return AlgorithmSpec(name, Family.HMAC, hmac_digest=digest)


def _rsa(name: str, family: Family, hash_: Callable[[], hashes.HashAlgorithm]) -> AlgorithmSpec:
    return AlgorithmSpec(name, family, hash=hash_, jwk_kty="RSA")


def _ec(
    name: str,
    hash_: Callable[[], hashes.HashAlgorithm],
    crv: str,
    curve: type[ec.EllipticCurve],
    component_bytes: int,
) -> AlgorithmSpec:
    return AlgorithmSpec(
        name,
        Family.EC,
        hash=hash_,
        jwk_kty="EC",
        jwk_crvs=frozenset({crv}),
        curve=curve,
        ec_component_bytes=component_bytes,
    )


# RFC 8037 2: OKP signing curves. X25519/X448 are key-agreement curves and must
# never verify a signature.
_ED25519_PRIVATE: tuple[type, ...] = (ed25519.Ed25519PrivateKey,)
_ED25519_PUBLIC: tuple[type, ...] = (ed25519.Ed25519PublicKey,)
_ED448_PRIVATE: tuple[type, ...] = (ed448.Ed448PrivateKey,)
_ED448_PUBLIC: tuple[type, ...] = (ed448.Ed448PublicKey,)


def _okp(
    name: str, crvs: frozenset[str], private: tuple[type, ...], public: tuple[type, ...]
) -> AlgorithmSpec:
    return AlgorithmSpec(
        name,
        Family.OKP,
        jwk_kty="OKP",
        jwk_crvs=crvs,
        okp_private_types=private,
        okp_public_types=public,
    )


# Order matters: the public dicts and sets below are derived from it, and
# SUPPORTED_ALGORITHMS keeps its HS256, HS384, HS512 order.
ALGORITHMS: dict[str, AlgorithmSpec] = {
    spec.name: spec
    for spec in (
        _hmac("HS256", hashlib.sha256),
        _hmac("HS384", hashlib.sha384),
        _hmac("HS512", hashlib.sha512),
        _rsa("RS256", Family.RSA, hashes.SHA256),
        _rsa("RS384", Family.RSA, hashes.SHA384),
        _rsa("RS512", Family.RSA, hashes.SHA512),
        _rsa("PS256", Family.PSS, hashes.SHA256),
        _rsa("PS384", Family.PSS, hashes.SHA384),
        _rsa("PS512", Family.PSS, hashes.SHA512),
        _ec("ES256", hashes.SHA256, "P-256", ec.SECP256R1, 32),
        _ec("ES384", hashes.SHA384, "P-384", ec.SECP384R1, 48),
        _ec("ES512", hashes.SHA512, "P-521", ec.SECP521R1, 66),
        # RFC 9864 deprecates the polymorphic "EdDSA" in favour of the fully
        # specified Ed25519/Ed448, but existing deployments still emit it.
        _okp(
            "EdDSA",
            frozenset({"Ed25519", "Ed448"}),
            _ED25519_PRIVATE + _ED448_PRIVATE,
            _ED25519_PUBLIC + _ED448_PUBLIC,
        ),
        _okp("Ed25519", frozenset({"Ed25519"}), _ED25519_PRIVATE, _ED25519_PUBLIC),
        _okp("Ed448", frozenset({"Ed448"}), _ED448_PRIVATE, _ED448_PUBLIC),
    )
}


def _names(family: Family) -> frozenset[str]:
    return frozenset(name for name, spec in ALGORITHMS.items() if spec.family is family)


# Public API (core/CLAUDE.md): names, order and value types never change.
SUPPORTED_ALGORITHMS = {
    name: spec.hmac_digest
    for name, spec in ALGORITHMS.items()
    if spec.family is Family.HMAC and spec.hmac_digest is not None
}
RSA_ALGORITHMS = _names(Family.RSA)
EC_ALGORITHMS = _names(Family.EC)
PSS_ALGORITHMS = _names(Family.PSS)
OKP_ALGORITHMS = _names(Family.OKP)
ASYMMETRIC_ALGORITHMS = RSA_ALGORITHMS | EC_ALGORITHMS | PSS_ALGORITHMS | OKP_ALGORITHMS
ALL_SIGNING_ALGORITHMS = frozenset(ALGORITHMS)

_CANONICAL_BY_UPPER = {name.upper(): name for name in ALGORITHMS}


def canonical_algorithm(name: str) -> str | None:
    # Case-insensitive lookup for callers passing a user-typed name. Token
    # headers must still match the registered spelling exactly (RFC 7515 4.1.1).
    return _CANONICAL_BY_UPPER.get(name.upper())


def algorithm_spec(name: str) -> AlgorithmSpec | None:
    # Exact-case lookup of a registered name.
    return ALGORITHMS.get(name)


def require_algorithm(header: JsonObject) -> AlgorithmSpec:
    # The token's `alg`, validated as a wire value: exact registered spelling only
    # (RFC 7515 4.1.1), and never "none".
    alg = header.get("alg")
    if isinstance(alg, str) and alg.upper() == "NONE":
        raise UnsupportedAlgorithmError(
            headline="Token uses alg: none, it has no signature to verify",
            details=("This token is completely unsigned and trivially forgeable",),
        )
    spec = algorithm_spec(alg) if isinstance(alg, str) else None
    if spec is None:
        details = [f"Supported: {', '.join(sorted(ALGORITHMS))}"]
        canonical = canonical_algorithm(alg) if isinstance(alg, str) else None
        if canonical is not None:
            details.append(f"alg is case-sensitive; {alg!r} is not {canonical!r}")
        shown = alg if isinstance(alg, str) else repr(alg)
        raise UnsupportedAlgorithmError(
            headline=f"Unsupported algorithm: {shown}",
            details=tuple(details),
        )
    return spec
