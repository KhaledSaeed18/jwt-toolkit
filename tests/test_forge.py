import hashlib
import hmac
import json

import pytest

from jwt_toolkit.core.decoder import decode_token
from jwt_toolkit.core.encoding import base64url_decode, base64url_encode
from jwt_toolkit.core.forge import (
    ALL_VARIANT_NAMES,
    KEY_BASED_VARIANT_NAMES,
    STATIC_VARIANT_NAMES,
    forge_one,
    generate_variants,
)
from tests.helpers import make_token


def _decoded(payload: dict | None = None):
    return decode_token(make_token(payload or {"sub": "alice", "exp": 9999999999}))


# Registry shape


def test_static_and_key_based_lists_are_disjoint():
    assert set(STATIC_VARIANT_NAMES).isdisjoint(KEY_BASED_VARIANT_NAMES)


def test_all_variant_names_is_union():
    assert set(ALL_VARIANT_NAMES) == set(STATIC_VARIANT_NAMES) | set(KEY_BASED_VARIANT_NAMES)


def test_unknown_variant_raises():
    decoded = _decoded()
    with pytest.raises(ValueError, match="Unknown forge variant"):
        forge_one("does_not_exist", decoded)


def test_key_based_variant_without_pem_raises():
    decoded = _decoded()
    with pytest.raises(ValueError, match="requires --public-key"):
        forge_one("hs_rs_confusion", decoded)


# Every variant produces a well-formed three-part token


@pytest.mark.parametrize("name", STATIC_VARIANT_NAMES)
def test_static_variant_token_has_three_parts(name):
    decoded = _decoded()
    v = forge_one(name, decoded)
    assert v.token.count(".") == 2
    assert v.name == name


def test_hs_rs_confusion_token_has_three_parts(rsa_keypair):
    decoded = _decoded()
    v = forge_one("hs_rs_confusion", decoded, public_key_pem=rsa_keypair.public_pem)
    assert v.token.count(".") == 2


# alg:none variants — signature stripped, alg set to a `none` casing


@pytest.mark.parametrize(
    ("name", "expected_alg"),
    [
        ("alg_none_lower", "none"),
        ("alg_none_upper", "NONE"),
        ("alg_none_mixed", "nOnE"),
    ],
)
def test_alg_none_variants(name, expected_alg):
    decoded = _decoded()
    v = forge_one(name, decoded)
    h, _p, sig = v.token.split(".")
    header = json.loads(base64url_decode(h))
    assert header["alg"] == expected_alg
    assert sig == ""
    assert v.cve == "CVE-2015-2951"


def test_empty_signature_keeps_original_alg():
    decoded = _decoded()
    v = forge_one("empty_signature", decoded)
    h, _p, sig = v.token.split(".")
    header = json.loads(base64url_decode(h))
    assert header["alg"] == "HS256"
    assert sig == ""
    assert v.cve is None


# Header-injection variants — original signature preserved, header mutated


@pytest.mark.parametrize(
    ("name", "field", "needle"),
    [
        ("kid_path_traversal", "kid", "../"),
        ("kid_sql_injection", "kid", "OR"),
        ("jku_attacker", "jku", "attacker.example"),
    ],
)
def test_header_injection_variants(name, field, needle):
    decoded = _decoded()
    v = forge_one(name, decoded)
    h, _p, sig = v.token.split(".")
    header = json.loads(base64url_decode(h))
    assert needle in header[field]
    assert sig == decoded.signature


def test_jwk_embedded_variant_has_cve():
    decoded = _decoded()
    v = forge_one("jwk_embedded", decoded)
    h, _p, _sig = v.token.split(".")
    header = json.loads(base64url_decode(h))
    assert "jwk" in header
    assert v.cve == "CVE-2018-0114"


def test_tampered_payload_preserves_signature():
    decoded = _decoded()
    v = forge_one("tampered_payload", decoded)
    _h, p, sig = v.token.split(".")
    payload = json.loads(base64url_decode(p))
    assert payload.get("admin") is True
    assert payload.get("role") == "admin"
    # Original sub claim must still be present — we add, not replace.
    assert payload["sub"] == "alice"
    # Signature is the original one — the whole point is to test the verifier.
    assert sig == decoded.signature


# HS/RS confusion — signature is HS256(pem-bytes) over header.payload


def test_hs_rs_confusion_signature_is_hmac_of_pem(rsa_keypair):
    decoded = _decoded()
    v = forge_one("hs_rs_confusion", decoded, public_key_pem=rsa_keypair.public_pem)
    h, p, sig = v.token.split(".")
    header = json.loads(base64url_decode(h))
    assert header["alg"] == "HS256"
    expected = hmac.new(rsa_keypair.public_pem, f"{h}.{p}".encode(), hashlib.sha256).digest()
    assert sig == base64url_encode(expected)
    assert v.cve == "CVE-2016-10555"


# generate_variants


def test_generate_variants_default_without_pem_is_static_only():
    decoded = _decoded()
    variants = generate_variants(decoded)
    assert [v.name for v in variants] == list(STATIC_VARIANT_NAMES)


def test_generate_variants_default_with_pem_includes_key_based(rsa_keypair):
    decoded = _decoded()
    variants = generate_variants(decoded, public_key_pem=rsa_keypair.public_pem)
    assert [v.name for v in variants] == list(ALL_VARIANT_NAMES)


def test_generate_variants_explicit_key_based_without_pem_raises():
    decoded = _decoded()
    with pytest.raises(ValueError, match="requires --public-key"):
        generate_variants(decoded, names=["hs_rs_confusion"])


def test_generate_variants_without_pem_can_filter_to_static_only():
    decoded = _decoded()
    variants = generate_variants(decoded, names=STATIC_VARIANT_NAMES)
    assert [v.name for v in variants] == list(STATIC_VARIANT_NAMES)


def test_generate_variants_with_pem_emits_confusion(rsa_keypair):
    decoded = _decoded()
    variants = generate_variants(decoded, public_key_pem=rsa_keypair.public_pem)
    names = [v.name for v in variants]
    assert "hs_rs_confusion" in names


# Every emitted variant is decodable as a JWT


@pytest.mark.parametrize("name", STATIC_VARIANT_NAMES)
def test_every_static_variant_is_decodable(name):
    decoded = _decoded()
    v = forge_one(name, decoded)
    re_decoded = decode_token(v.token)
    assert "alg" in re_decoded.header


def test_hs_rs_confusion_variant_is_decodable(rsa_keypair):
    decoded = _decoded()
    v = forge_one("hs_rs_confusion", decoded, public_key_pem=rsa_keypair.public_pem)
    re_decoded = decode_token(v.token)
    assert re_decoded.header["alg"] == "HS256"
