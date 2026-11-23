import hashlib

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from jwt_toolkit.core import algorithms, auditor, crypto
from jwt_toolkit.core.algorithms import (
    ALGORITHMS,
    Family,
    algorithm_spec,
    canonical_algorithm,
    require_algorithm,
)
from jwt_toolkit.core.errors import UnsupportedAlgorithmError

# The literals these public tables had before the registry existed (core/CLAUDE.md:
# names, order and value types are public API).
OLD_SUPPORTED = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
OLD_RSA = frozenset({"RS256", "RS384", "RS512"})
OLD_EC = frozenset({"ES256", "ES384", "ES512"})
OLD_PSS = frozenset({"PS256", "PS384", "PS512"})
OLD_OKP = frozenset({"EdDSA", "Ed25519", "Ed448"})


def test_supported_algorithms_keeps_names_order_and_values():
    assert crypto.SUPPORTED_ALGORITHMS == OLD_SUPPORTED
    assert list(crypto.SUPPORTED_ALGORITHMS) == ["HS256", "HS384", "HS512"]
    assert type(crypto.SUPPORTED_ALGORITHMS) is dict


def test_asymmetric_sets_keep_their_members_and_types():
    assert crypto.RSA_ALGORITHMS == OLD_RSA
    assert crypto.EC_ALGORITHMS == OLD_EC
    assert crypto.PSS_ALGORITHMS == OLD_PSS
    assert crypto.OKP_ALGORITHMS == OLD_OKP
    assert crypto.ASYMMETRIC_ALGORITHMS == OLD_RSA | OLD_EC | OLD_PSS | OLD_OKP
    assert frozenset(OLD_SUPPORTED) | crypto.ASYMMETRIC_ALGORITHMS == crypto.ALL_SIGNING_ALGORITHMS
    for table in (
        crypto.RSA_ALGORITHMS,
        crypto.EC_ALGORITHMS,
        crypto.PSS_ALGORITHMS,
        crypto.OKP_ALGORITHMS,
        crypto.ASYMMETRIC_ALGORITHMS,
        crypto.ALL_SIGNING_ALGORITHMS,
    ):
        assert type(table) is frozenset


def test_auditor_sets_are_unchanged():
    assert set(OLD_SUPPORTED) == auditor.SYMMETRIC_ALGORITHMS
    assert set(OLD_RSA | OLD_EC | OLD_PSS | OLD_OKP) == auditor.ASYMMETRIC_ALGORITHMS
    assert type(auditor.SYMMETRIC_ALGORITHMS) is set


def test_crypto_reexports_the_registry_objects():
    assert crypto.SUPPORTED_ALGORITHMS is algorithms.SUPPORTED_ALGORITHMS
    assert crypto.canonical_algorithm is algorithms.canonical_algorithm


@pytest.mark.parametrize(
    ("name", "hash_", "crv", "curve", "size"),
    [
        ("ES256", hashes.SHA256, "P-256", ec.SECP256R1, 32),
        ("ES384", hashes.SHA384, "P-384", ec.SECP384R1, 48),
        ("ES512", hashes.SHA512, "P-521", ec.SECP521R1, 66),
    ],
)
def test_ec_specs_follow_rfc_7518(name, hash_, crv, curve, size):
    spec = ALGORITHMS[name]
    assert spec.family is Family.EC
    assert spec.hash is hash_
    assert spec.jwk_kty == "EC"
    assert spec.jwk_crvs == {crv}
    assert spec.curve is curve
    assert spec.ec_component_bytes == size


def test_family_facts():
    assert all(ALGORITHMS[n].jwk_kty == "RSA" for n in OLD_RSA | OLD_PSS)
    assert all(ALGORITHMS[n].is_hmac and ALGORITHMS[n].jwk_kty is None for n in OLD_SUPPORTED)
    assert ALGORITHMS["EdDSA"].jwk_crvs == {"Ed25519", "Ed448"}
    assert ALGORITHMS["Ed25519"].jwk_crvs == {"Ed25519"}
    assert len(ALGORITHMS["EdDSA"].okp_public_types) == 2
    assert ALGORITHMS["PS256"].family is Family.PSS


def test_canonical_and_exact_lookup():
    assert canonical_algorithm("hs256") == "HS256"
    assert canonical_algorithm("eddsa") == "EdDSA"
    assert canonical_algorithm("none") is None
    assert algorithm_spec("hs256") is None
    assert algorithm_spec("HS256") is ALGORITHMS["HS256"]


def test_require_algorithm_accepts_exact_names_only():
    assert require_algorithm({"alg": "RS256"}).name == "RS256"
    with pytest.raises(UnsupportedAlgorithmError) as excinfo:
        require_algorithm({"alg": "rs256"})
    assert "case-sensitive" in " ".join(excinfo.value.details)


@pytest.mark.parametrize(
    "header", [{"alg": "none"}, {"alg": "NONE"}, {}, {"alg": 5}, {"alg": "XS1"}]
)
def test_require_algorithm_rejects(header):
    with pytest.raises(UnsupportedAlgorithmError):
        require_algorithm(header)
