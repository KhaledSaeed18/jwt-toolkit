"""Independent checks of the JWS implementation.

Signing and verifying with the same code can share a mistake, so this module checks
the toolkit against two outside references, offline:

- the JWS examples published in RFC 7515 Appendix A, RFC 8037 Appendix A.4 and
  RFC 7520 Section 4 (tests/vectors/jws_rfc_examples.json, with each source);
- PyJWT, a dev-only dependency (see uv.lock for the version), in both directions:
  PyJWT signs and the toolkit verifies, and the reverse.

Where the two disagree, the RFCs decide; the reasons are next to each negative test.
"""

import json
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from jwt.algorithms import OKPAlgorithm

from jwt_toolkit.cli import cli
from jwt_toolkit.core.algorithms import ALGORITHMS
from jwt_toolkit.core.crypto import sign_with_key, verify_with_key
from jwt_toolkit.core.decoder import decode_token
from jwt_toolkit.core.encoding import base64url_decode, base64url_encode
from jwt_toolkit.core.errors import KeyAlgorithmMismatchError, TokenDecodeError
from jwt_toolkit.core.jwks import jwk_to_public_key
from jwt_toolkit.core.keys import HmacKey, PrivateKey, PublicKey, as_private_key, as_public_key
from jwt_toolkit.core.verifier import check_signature

_VECTORS: dict[str, dict[str, Any]] = json.loads(
    (Path(__file__).parent / "vectors" / "jws_rfc_examples.json").read_text(encoding="utf-8")
)["vectors"]
_SIGNED = {name: v for name, v in _VECTORS.items() if v["alg"] != "none"}
_PRIVATE_MEMBERS = {"d", "p", "q", "dp", "dq", "qi"}
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_HMAC_SECRET = b"interop-secret-that-is-32-bytes!" * 2
_PAYLOAD = {"sub": "interop", "iat": 1_700_000_000}


def _hash(alg: str) -> hashes.HashAlgorithm:
    hash_class = ALGORITHMS[alg].hash
    assert hash_class is not None
    return hash_class()


def _int(value: str) -> int:
    return int.from_bytes(base64url_decode(value), "big")


def _private_key_from_jwk(jwk: dict[str, str]) -> Any:
    # Built with cryptography directly, so these tests do not depend on core/jwks.py.
    if jwk["kty"] == "RSA":
        public = rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"]))
        return rsa.RSAPrivateNumbers(
            p=_int(jwk["p"]),
            q=_int(jwk["q"]),
            d=_int(jwk["d"]),
            dmp1=_int(jwk["dp"]),
            dmq1=_int(jwk["dq"]),
            iqmp=_int(jwk["qi"]),
            public_numbers=public,
        ).private_key()
    if jwk["kty"] == "EC":
        curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}
        return ec.derive_private_key(_int(jwk["d"]), curve[jwk["crv"]])
    assert jwk == jwk | {"kty": "OKP", "crv": "Ed25519"}
    return ed25519.Ed25519PrivateKey.from_private_bytes(base64url_decode(jwk["d"]))


def _verification_key(vector: dict[str, Any]) -> HmacKey | PublicKey:
    jwk = vector["jwk"]
    if jwk["kty"] == "oct":
        return HmacKey(base64url_decode(jwk["k"]))
    return as_public_key(_private_key_from_jwk(jwk).public_key())


def _signing_input(token: str) -> tuple[bytes, str]:
    header, payload, signature = token.split(".")
    return f"{header}.{payload}".encode(), signature


def _flip_pad_bits(segment: str) -> str | None:
    # The last character of an unpadded base64url string carries unused low bits
    # unless the length is a multiple of 4. Changing them keeps the decoded bytes.
    unused = (6 * len(segment)) % 8
    if unused == 0:
        return None
    last = _ALPHABET.index(segment[-1])
    return segment[:-1] + _ALPHABET[last ^ 1]


# RFC examples


@pytest.mark.parametrize("name", sorted(_SIGNED))
def test_rfc_example_verifies(name):
    vector = _SIGNED[name]
    message, signature = _signing_input(vector["token"])
    spec = ALGORITHMS[vector["alg"]]
    assert verify_with_key(message, signature, _verification_key(vector), spec)


@pytest.mark.parametrize("name", sorted(n for n, v in _SIGNED.items() if v["jwk"]["kty"] != "oct"))
def test_rfc_example_verifies_with_the_jwk_loader(name):
    vector = _SIGNED[name]
    public_jwk = {k: v for k, v in vector["jwk"].items() if k not in _PRIVATE_MEMBERS}
    key = jwk_to_public_key(public_jwk, vector["alg"])
    message, signature = _signing_input(vector["token"])
    assert verify_with_key(message, signature, key, ALGORITHMS[vector["alg"]])


# HMAC, RSASSA-PKCS1-v1_5 and Ed25519 are deterministic: the toolkit must produce the
# published signature byte for byte. ECDSA and PSS are randomized, so only verified.
@pytest.mark.parametrize(
    "name", sorted(n for n, v in _SIGNED.items() if v["alg"] in {"HS256", "RS256", "EdDSA"})
)
def test_rfc_example_signature_is_reproduced(name):
    vector = _SIGNED[name]
    message, signature = _signing_input(vector["token"])
    jwk = vector["jwk"]
    key: HmacKey | PrivateKey = (
        HmacKey(base64url_decode(jwk["k"]))
        if jwk["kty"] == "oct"
        else as_private_key(_private_key_from_jwk(jwk))
    )
    assert base64url_encode(sign_with_key(message, key, ALGORITHMS[vector["alg"]])) == signature


@pytest.mark.parametrize("name", sorted(_SIGNED))
def test_rfc_example_with_a_changed_payload_fails(name):
    vector = _SIGNED[name]
    header, payload, signature = vector["token"].split(".")
    changed = payload[:-2] + ("A" if payload[-2] != "A" else "B") + payload[-1]
    message = f"{header}.{changed}".encode()
    assert not verify_with_key(
        message, signature, _verification_key(vector), ALGORITHMS[vector["alg"]]
    )


# RFC 7515 A.1 to A.3 carry a JSON claims set, so they also run through the full
# token path. The others sign plain text: valid JWS, but not JWTs.
@pytest.mark.parametrize("name", ["rfc7515-a1-hs256", "rfc7515-a2-rs256", "rfc7515-a3-es256"])
def test_rfc_jwt_examples_pass_the_signature_check(name):
    vector = _VECTORS[name]
    decoded = decode_token(vector["token"])
    assert decoded.payload["iss"] == "joe"
    assert check_signature(decoded, _verification_key(vector)).result == "PASS"


@pytest.mark.parametrize("name", ["rfc7515-a2-rs256", "rfc7515-a3-es256"])
def test_cli_verifies_rfc_examples_end_to_end(runner, tmp_path, name):
    vector = _VECTORS[name]
    pem = tmp_path / "key.pem"
    pem.write_bytes(
        _private_key_from_jwk(vector["jwk"])
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    result = runner.invoke(cli, ["verify", vector["token"], "--public-key", str(pem), "--json"])
    checks = {c["check"]: c["result"] for c in json.loads(result.output)["checks"]}
    assert checks["signature"] == "PASS"
    # The examples expired in 2011, so the token as a whole is still rejected.
    assert result.exit_code == 1


def test_rfc_unsecured_example_is_never_accepted():
    decoded = decode_token(_VECTORS["rfc7515-a5-none"]["token"])
    assert decoded.header == {"alg": "none"}
    check = check_signature(decoded, HmacKey(b"anything"))
    assert check.result == "FAIL"


# PyJWT in both directions, for every supported algorithm.


def _pem_keys(alg: str, keypair_for: Any) -> tuple[Any, Any]:
    pair = keypair_for(alg)
    private = serialization.load_pem_private_key(pair.private_pem, password=None)
    return private, private.public_key()


# PyJWT names EdDSA only; RFC 9864's Ed25519 and Ed448 are signed with its OKP
# primitive over the same signing input.
_PYJWT_ALG = {"Ed25519": "EdDSA", "Ed448": "EdDSA"}
_ASYMMETRIC = [alg for alg in ALGORITHMS if not ALGORITHMS[alg].is_hmac]


def _toolkit_token(alg: str, key: HmacKey | PrivateKey) -> str:
    header = base64url_encode(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    payload = base64url_encode(json.dumps(_PAYLOAD).encode())
    signature = sign_with_key(f"{header}.{payload}".encode(), key, ALGORITHMS[alg])
    return f"{header}.{payload}.{base64url_encode(signature)}"


def _pyjwt_token(alg: str, key: Any) -> str:
    if alg not in _PYJWT_ALG:
        return jwt.encode(_PAYLOAD, key, algorithm=alg)
    header = base64url_encode(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    payload = base64url_encode(json.dumps(_PAYLOAD).encode())
    signature = OKPAlgorithm().sign(f"{header}.{payload}".encode(), key)
    return f"{header}.{payload}.{base64url_encode(signature)}"


def _pyjwt_accepts(token: str, alg: str, key: Any) -> bool:
    try:
        if alg in _PYJWT_ALG:
            message, signature = _signing_input(token)
            return OKPAlgorithm().verify(message, key, base64url_decode(signature))
        return jwt.decode(token, key, algorithms=[alg]) == _PAYLOAD
    except jwt.InvalidTokenError:
        return False


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_hmac_toolkit_to_pyjwt(alg):
    assert _pyjwt_accepts(_toolkit_token(alg, HmacKey(_HMAC_SECRET)), alg, _HMAC_SECRET)


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_hmac_pyjwt_to_toolkit(alg):
    decoded = decode_token(jwt.encode(_PAYLOAD, _HMAC_SECRET, algorithm=alg))
    assert check_signature(decoded, HmacKey(_HMAC_SECRET)).result == "PASS"


@pytest.mark.parametrize("alg", _ASYMMETRIC)
def test_asymmetric_toolkit_to_pyjwt(alg, keypair_for):
    private, public = _pem_keys(alg, keypair_for)
    assert _pyjwt_accepts(_toolkit_token(alg, as_private_key(private)), alg, public)


@pytest.mark.parametrize("alg", _ASYMMETRIC)
def test_asymmetric_pyjwt_to_toolkit(alg, keypair_for):
    private, public = _pem_keys(alg, keypair_for)
    decoded = decode_token(_pyjwt_token(alg, private))
    assert check_signature(decoded, as_public_key(public)).result == "PASS"


def test_eddsa_with_an_ed448_key_both_ways(ed448_keypair):
    private = serialization.load_pem_private_key(ed448_keypair.private_pem, password=None)
    assert isinstance(private, ed448.Ed448PrivateKey)
    assert _pyjwt_accepts(
        _toolkit_token("EdDSA", as_private_key(private)), "EdDSA", private.public_key()
    )
    decoded = decode_token(jwt.encode(_PAYLOAD, private, algorithm="EdDSA"))
    assert check_signature(decoded, as_public_key(private.public_key())).result == "PASS"


# ECDSA: RFC 7518 3.4 requires the fixed-width r || s form, not DER.


@pytest.mark.parametrize(("alg", "width"), [("ES256", 64), ("ES384", 96), ("ES512", 132)])
def test_ecdsa_signatures_are_raw_r_and_s(alg, width, keypair_for):
    private, _ = _pem_keys(alg, keypair_for)
    signature = _toolkit_token(alg, as_private_key(private)).rsplit(".", 1)[1]
    assert len(base64url_decode(signature)) == width


@pytest.mark.parametrize("alg", ["ES256", "ES384", "ES512"])
def test_der_encoded_ecdsa_signature_is_rejected_by_both(alg, keypair_for):
    private, public = _pem_keys(alg, keypair_for)
    header, payload, _ = _toolkit_token(alg, as_private_key(private)).split(".")
    der = private.sign(f"{header}.{payload}".encode(), ec.ECDSA(_hash(alg)))
    token = f"{header}.{payload}.{base64url_encode(der)}"
    assert check_signature(decode_token(token), as_public_key(public)).result == "FAIL"
    assert not _pyjwt_accepts(token, alg, public)


def test_ecdsa_key_on_another_curve_is_refused(keypair_for):
    _, p256_public = _pem_keys("ES256", keypair_for)
    with pytest.raises(KeyAlgorithmMismatchError):
        verify_with_key(b"a.b", "c", as_public_key(p256_public), ALGORITHMS["ES384"])


# RSASSA-PSS: RFC 7518 3.5 fixes the salt length to the hash output size.


@pytest.mark.parametrize("alg", ["PS256", "PS384", "PS512"])
def test_pss_signature_uses_a_hash_length_salt(alg, keypair_for):
    private, public = _pem_keys(alg, keypair_for)
    message, signature = _signing_input(_toolkit_token(alg, as_private_key(private)))
    hash_alg = _hash(alg)
    public.verify(
        base64url_decode(signature),
        message,
        padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=hash_alg.digest_size),
        hash_alg,
    )


@pytest.mark.parametrize("alg", ["PS256", "PS384", "PS512"])
def test_pss_signature_with_another_salt_length_is_rejected(alg, keypair_for):
    private, public = _pem_keys(alg, keypair_for)
    header, payload, _ = _toolkit_token(alg, as_private_key(private)).split(".")
    hash_alg = _hash(alg)
    signature = private.sign(
        f"{header}.{payload}".encode(),
        padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.MAX_LENGTH),
        hash_alg,
    )
    token = f"{header}.{payload}.{base64url_encode(signature)}"
    assert check_signature(decode_token(token), as_public_key(public)).result == "FAIL"


# Non-canonical base64url. RFC 4648 3.5 lets a decoder reject non-zero pad bits, and
# PyJWT does. The toolkit now does too for every algorithm, so a token has exactly
# one valid spelling and a deny-list keyed on the token string cannot be bypassed.


@pytest.mark.parametrize("alg", list(ALGORITHMS))
def test_signature_with_altered_pad_bits_is_rejected(alg, keypair_for):
    if ALGORITHMS[alg].is_hmac:
        key: Any = _HMAC_SECRET
        verify_key: HmacKey | PublicKey = HmacKey(_HMAC_SECRET)
    else:
        key, public = _pem_keys(alg, keypair_for)
        verify_key = as_public_key(public)
    token = _pyjwt_token(alg, key)
    header, payload, signature = token.split(".")
    altered = _flip_pad_bits(signature)
    if altered is None:
        pytest.skip(f"{alg} signatures have no unused bits")
    assert base64url_decode(altered) == base64url_decode(signature)
    altered_token = f"{header}.{payload}.{altered}"
    assert check_signature(decode_token(altered_token), verify_key).result == "FAIL"
    if ALGORITHMS[alg].is_hmac or alg not in _PYJWT_ALG:
        assert not _pyjwt_accepts(altered_token, alg, key if ALGORITHMS[alg].is_hmac else public)


def test_header_with_altered_pad_bits_is_rejected():
    token = jwt.encode(_PAYLOAD, _HMAC_SECRET, algorithm="HS256", headers={"kid": "k"})
    header, payload, signature = token.split(".")
    altered = _flip_pad_bits(header)
    assert altered is not None
    with pytest.raises(TokenDecodeError) as exc:
        decode_token(f"{altered}.{payload}.{signature}")
    assert (exc.value.code, exc.value.cause) == ("invalid_base64url", "base64url_noncanonical")


def test_toolkit_hash_table_matches_the_pss_hashes():
    # Guards the salt tests above: they read the hash from the toolkit's own registry.
    assert ALGORITHMS["PS256"].hash is hashes.SHA256
    assert ALGORITHMS["PS512"].hash is hashes.SHA512
