import json

import pytest
from cryptography.hazmat.primitives import serialization

from jwt_toolkit.cli import cli
from jwt_toolkit.core.crypto import verify_asymmetric, verify_signature
from jwt_toolkit.core.decoder import decode_token
from jwt_toolkit.core.encoding import base64url_encode


def invoke(runner, *args):
    return runner.invoke(cli, ["sign", *args])


# Happy path


def test_sign_produces_three_part_token(runner):
    result = invoke(runner, "--payload", '{"sub":"1"}', "--secret", "mysecret")
    assert result.exit_code == 0
    parts = result.output.strip().split(".")
    assert len(parts) == 3


def test_sign_token_is_verifiable(runner):
    result = invoke(runner, "--payload", '{"sub":"1","exp":9999999999}', "--secret", "mysecret")
    token = result.output.strip()
    decoded = decode_token(token)
    assert verify_signature(
        decoded.header_b64, decoded.payload_b64, decoded.signature, "mysecret", "HS256"
    )


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_sign_all_alg_variants(runner, alg):
    result = invoke(runner, "--payload", '{"sub":"1"}', "--secret", "s", "--alg", alg)
    assert result.exit_code == 0
    decoded = decode_token(result.output.strip())
    assert decoded.header["alg"] == alg


# --header override
def test_sign_custom_header_overrides_alg(runner):
    custom_header = json.dumps({"alg": "HS512", "typ": "JWT", "kid": "my-key"})
    result = invoke(runner, "--payload", '{"sub":"1"}', "--secret", "s", "--header", custom_header)
    assert result.exit_code == 0
    decoded = decode_token(result.output.strip())
    assert decoded.header["alg"] == "HS512"
    assert decoded.header["kid"] == "my-key"


def test_sign_custom_header_without_alg_declares_signing_alg(runner):
    result = invoke(
        runner,
        "--payload",
        '{"sub":"1"}',
        "--secret",
        "s",
        "--alg",
        "HS384",
        "--header",
        '{"typ":"JWT","kid":"k1"}',
    )
    assert result.exit_code == 0
    decoded = decode_token(result.output.strip())
    assert decoded.header == {"alg": "HS384", "typ": "JWT", "kid": "k1"}
    assert verify_signature(
        decoded.header_b64, decoded.payload_b64, decoded.signature, "s", "HS384"
    )


def test_sign_custom_header_with_non_canonical_alg_exits_2(runner):
    result = invoke(
        runner, "--payload", '{"sub":"1"}', "--secret", "s", "--header", '{"alg":"hs256"}'
    )
    assert result.exit_code == 2
    assert "case-sensitive" in result.output


# Input validation


def test_sign_invalid_payload_json_exits_2(runner):
    result = invoke(runner, "--payload", "{not-json}", "--secret", "s")
    assert result.exit_code == 2


def test_sign_invalid_header_json_exits_2(runner):
    result = invoke(runner, "--payload", '{"sub":"1"}', "--secret", "s", "--header", "{not-json}")
    assert result.exit_code == 2


@pytest.mark.parametrize("value", ["[]", "null", '"text"', "true", "42"])
@pytest.mark.parametrize("flag", ["--payload", "--header"])
def test_sign_non_object_json_exits_2(runner, flag, value):
    args = {"--payload": '{"sub":"1"}', "--header": '{"alg":"HS256"}', flag: value}
    result = invoke(runner, *[x for kv in args.items() for x in kv], "--secret", "s")
    assert result.exit_code == 2
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "must be a JSON object" in result.output


@pytest.mark.parametrize("number", ["NaN", "Infinity", "1e400"])
def test_sign_non_finite_number_exits_2(runner, number):
    result = invoke(runner, "--payload", '{"exp":' + number + "}", "--secret", "s")
    assert result.exit_code == 2
    assert "not valid JSON" in result.output


def test_sign_empty_secret_exits_2(runner):
    result = invoke(runner, "--payload", '{"sub":"1"}', "--secret", "")
    assert result.exit_code == 2


def test_sign_unsupported_alg_in_header_exits_2(runner):
    # RS256 is now supported but requires --private-key, not --secret.
    custom_header = json.dumps({"alg": "RS256", "typ": "JWT"})
    result = invoke(runner, "--payload", '{"sub":"1"}', "--secret", "s", "--header", custom_header)
    assert result.exit_code == 2


# Asymmetric signing


@pytest.mark.parametrize(
    "alg",
    ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"],
)
def test_sign_asymmetric_produces_verifiable_token(runner, tmp_path, keypair_for, alg):
    kp = keypair_for(alg)
    priv = tmp_path / "key.pem"
    priv.write_bytes(kp.private_pem)
    result = invoke(
        runner,
        "--payload",
        '{"sub":"1"}',
        "--private-key",
        str(priv),
        "--alg",
        alg,
    )
    assert result.exit_code == 0, result.output
    token = result.output.strip()
    decoded = decode_token(token)
    assert decoded.header["alg"] == alg
    assert verify_asymmetric(
        decoded.header_b64, decoded.payload_b64, decoded.signature, kp.public_pem, alg
    )


def test_sign_asymmetric_alg_with_secret_exits_2(runner, tmp_path, keypair_for):
    kp = keypair_for("RS256")
    priv = tmp_path / "key.pem"
    priv.write_bytes(kp.private_pem)
    result = invoke(
        runner,
        "--payload",
        '{"sub":"1"}',
        "--secret",
        "s",
        "--alg",
        "RS256",
    )
    assert result.exit_code == 2


def test_sign_hmac_alg_with_private_key_exits_2(runner, tmp_path, keypair_for):
    kp = keypair_for("RS256")
    priv = tmp_path / "key.pem"
    priv.write_bytes(kp.private_pem)
    result = invoke(
        runner,
        "--payload",
        '{"sub":"1"}',
        "--private-key",
        str(priv),
        "--alg",
        "HS256",
    )
    assert result.exit_code == 2


def test_sign_both_secret_and_private_key_exits_2(runner, tmp_path, keypair_for):
    kp = keypair_for("RS256")
    priv = tmp_path / "key.pem"
    priv.write_bytes(kp.private_pem)
    result = invoke(
        runner,
        "--payload",
        '{"sub":"1"}',
        "--secret",
        "s",
        "--private-key",
        str(priv),
        "--alg",
        "RS256",
    )
    assert result.exit_code == 2


def test_sign_asymmetric_without_key_exits_2(runner):
    result = invoke(runner, "--payload", '{"sub":"1"}', "--alg", "RS256")
    assert result.exit_code == 2


def test_sign_hmac_without_secret_exits_2(runner):
    # Previously --secret was required by Click; now it is conditional.
    result = invoke(runner, "--payload", '{"sub":"1"}', "--alg", "HS256")
    assert result.exit_code == 2


def test_sign_asymmetric_wrong_key_type_for_alg_exits_2(runner, tmp_path, keypair_for):
    # EC key for an RSA algorithm — the core layer rejects this.
    ec_key = keypair_for("ES256")
    priv = tmp_path / "key.pem"
    priv.write_bytes(ec_key.private_pem)
    result = invoke(
        runner,
        "--payload",
        '{"sub":"1"}',
        "--private-key",
        str(priv),
        "--alg",
        "RS256",
    )
    assert result.exit_code == 2


@pytest.mark.parametrize("alg", ["EdDSA", "Ed25519", "Ed448"])
def test_sign_and_verify_eddsa_end_to_end(runner, tmp_path, keypair_for, alg):
    kp = keypair_for(alg)
    priv, pub = tmp_path / "priv.pem", tmp_path / "pub.pem"
    priv.write_bytes(kp.private_pem)
    pub.write_bytes(kp.public_pem)
    signed = invoke(
        runner,
        "--payload",
        '{"sub":"1","exp":9999999999}',
        "--alg",
        alg.lower(),
        "--private-key",
        str(priv),
    )
    assert signed.exit_code == 0
    token = signed.output.strip()
    assert decode_token(token).header["alg"] == alg
    verified = runner.invoke(cli, ["verify", token, "--public-key", str(pub), "--json"])
    assert verified.exit_code == 0
    assert json.loads(verified.output)["valid"] is True


def test_verify_ed448_token_via_jwks_file(runner, tmp_path, ed448_keypair):
    priv = tmp_path / "priv.pem"
    priv.write_bytes(ed448_keypair.private_pem)
    raw = serialization.load_pem_public_key(ed448_keypair.public_pem).public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    jwks = tmp_path / "jwks.json"
    jwks.write_text(
        json.dumps(
            {"keys": [{"kty": "OKP", "crv": "Ed448", "kid": "k1", "x": base64url_encode(raw)}]}
        )
    )
    header = json.dumps({"alg": "Ed448", "typ": "JWT", "kid": "k1"})
    token = invoke(
        runner, "--payload", '{"sub":"1"}', "--header", header, "--private-key", str(priv)
    ).output.strip()
    result = runner.invoke(cli, ["verify", token, "--jwks-url", jwks.as_uri()])
    assert result.exit_code == 0


def test_audit_verifies_eddsa_signature(runner, tmp_path, ed25519_keypair):
    priv, pub = tmp_path / "priv.pem", tmp_path / "pub.pem"
    priv.write_bytes(ed25519_keypair.private_pem)
    pub.write_bytes(ed25519_keypair.public_pem)
    token = invoke(
        runner, "--payload", '{"sub":"1"}', "--alg", "Ed25519", "--private-key", str(priv)
    ).output.strip()
    result = runner.invoke(cli, ["audit", token, "--public-key", str(pub), "--json"])
    assert json.loads(result.output)["signature_valid"] is True


def _write_encrypted_key(tmp_path, private_pem: bytes, passphrase: bytes):
    key = serialization.load_pem_private_key(private_pem, password=None)
    path = tmp_path / "enc.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase),
        )
    )
    return path


def test_sign_with_passphrase_file(runner, tmp_path, keypair_for):
    kp = keypair_for("ES256")
    key = _write_encrypted_key(tmp_path, kp.private_pem, b"  spaced pass  ")
    pw = tmp_path / "pw.txt"
    pw.write_bytes(b"  spaced pass  \n")
    result = invoke(
        runner,
        "--payload",
        '{"sub":"1"}',
        "--alg",
        "ES256",
        "--private-key",
        str(key),
        "--passphrase-file",
        str(pw),
    )
    assert result.exit_code == 0
    d = decode_token(result.output.strip())
    assert verify_asymmetric(d.header_b64, d.payload_b64, d.signature, kp.public_pem, "ES256")


def test_sign_encrypted_key_without_passphrase_fails_when_not_interactive(
    runner, tmp_path, keypair_for
):
    key = _write_encrypted_key(tmp_path, keypair_for("ES256").private_pem, b"pw")
    result = invoke(runner, "--payload", '{"sub":"1"}', "--alg", "ES256", "--private-key", str(key))
    assert result.exit_code == 2
    assert "--passphrase-file" in result.output


def test_sign_encrypted_key_prompts_on_a_terminal(runner, tmp_path, keypair_for, monkeypatch):
    key = _write_encrypted_key(tmp_path, keypair_for("ES256").private_pem, b"pw")
    monkeypatch.setattr("jwt_toolkit.commands.sign._is_interactive", lambda: True)
    args = ["sign", "--payload", '{"sub":"1"}', "--alg", "ES256", "--private-key", str(key)]
    result = runner.invoke(cli, args, input="pw\n")
    assert result.exit_code == 0
    assert "Private key passphrase" in result.stderr
    decode_token(result.stdout.strip())


def test_sign_wrong_passphrase_exits_2_without_echo(runner, tmp_path, keypair_for):
    key = _write_encrypted_key(tmp_path, keypair_for("ES256").private_pem, b"pw")
    pw = tmp_path / "pw.txt"
    pw.write_text("guess-9876\n")
    result = invoke(
        runner,
        "--payload",
        '{"sub":"1"}',
        "--alg",
        "ES256",
        "--private-key",
        str(key),
        "--passphrase-file",
        str(pw),
    )
    assert result.exit_code == 2
    assert "wrong passphrase" in result.output
    assert "guess-9876" not in result.output


def test_sign_passphrase_file_without_private_key_exits_2(runner, tmp_path):
    pw = tmp_path / "pw.txt"
    pw.write_text("x\n")
    result = invoke(
        runner, "--payload", '{"sub":"1"}', "--secret", "s", "--passphrase-file", str(pw)
    )
    assert result.exit_code == 2
