"""The single CLI error boundary: JSON error documents, exit codes, and no leaks."""

import dataclasses
import json
from contextlib import contextmanager

import click
import pytest
from click.testing import CliRunner

from jwt_toolkit.cli import cli
from jwt_toolkit.cli.errors import ToolkitCommand, error_document
from jwt_toolkit.core.crypto import sign_asymmetric
from jwt_toolkit.core.encoding import base64url_encode
from jwt_toolkit.core.errors import JwtToolkitError, KeyParseError
from tests.helpers import make_token

# Distinctive values that must never be echoed back anywhere.
LEAK_SECRET = "Zq7-LEAK-CANARY-SECRET-9f3b2c"
LEAK_PASSWORD = "hunter2-LEAK-CANARY"
LEAK_QUERY = "LEAKQUERYCANARY"


def _rs256_token(rsa_keypair):
    header = base64url_encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    payload = base64url_encode(json.dumps({"sub": "1"}).encode())
    return (
        f"{header}.{payload}.{sign_asymmetric(header, payload, rsa_keypair.private_pem, 'RS256')}"
    )


def _error_json(result) -> dict:
    assert result.exit_code == 2, (result.output, result.stderr)
    document = json.loads(result.stdout)
    assert document["schema_version"] == "0.1"
    assert isinstance(document["error"], str)
    assert isinstance(document["message"], str)
    assert isinstance(document["detail"], list)
    return document


def test_decode_json_errors(runner, tmp_path):
    assert _error_json(runner.invoke(cli, ["decode", "a.b", "--json"]))["error"] == (
        "invalid_structure"
    )
    missing = tmp_path / "missing.jwt"
    document = _error_json(runner.invoke(cli, ["decode", f"@{missing}", "--json"]))
    assert document["error"] == "token_unreadable"


def test_audit_json_errors(runner, valid_token, rsa_keypair, tmp_path):
    pub = tmp_path / "pub.pem"
    pub.write_bytes(rsa_keypair.public_pem)
    args = ["audit", valid_token, "--json", "--secret", "x", "--public-key", str(pub)]
    assert _error_json(runner.invoke(cli, args))["error"] == "invalid_key_options"
    assert _error_json(runner.invoke(cli, ["audit", "nope", "--json"]))["error"] == (
        "invalid_structure"
    )


def test_verify_json_errors_keep_the_broad_code_and_add_the_cause(runner, rsa_keypair, tmp_path):
    token = _rs256_token(rsa_keypair)
    assert _error_json(runner.invoke(cli, ["verify", token, "--json"]))["error"] == (
        "invalid_key_options"
    )
    bad_key = tmp_path / "bad.pem"
    bad_key.write_text("-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----\n")
    document = _error_json(
        runner.invoke(cli, ["verify", token, "--json", "--public-key", str(bad_key)])
    )
    assert document["error"] == "key_error"
    assert document["cause"] == "key_parse_failed"
    assert document["message"] == "Could not verify signature with the provided key"


def test_verify_jwks_errors_carry_the_jwks_cause(runner, rsa_keypair, tmp_path):
    jwks = tmp_path / "jwks.json"
    jwks.write_text(json.dumps({"keys": []}))
    token = _rs256_token(rsa_keypair)
    document = _error_json(
        runner.invoke(cli, ["verify", token, "--json", "--jwks-url", jwks.as_uri()])
    )
    assert document["error"] == "key_error"
    assert document["cause"] == "jwks_invalid"


def test_forge_json_errors(runner, valid_token, rsa_keypair, tmp_path):
    document = _error_json(
        runner.invoke(cli, ["forge", valid_token, "--json", "--mode", "hs_rs_confusion"])
    )
    assert document["error"] == "invalid_key_options"
    assert document["cause"] == "forge_variant_needs_key"
    private = tmp_path / "private.pem"
    private.write_bytes(rsa_keypair.private_pem)
    document = _error_json(
        runner.invoke(
            cli,
            [
                "forge",
                valid_token,
                "--json",
                "--mode",
                "hs_rs_confusion",
                "--public-key",
                str(private),
            ],
        )
    )
    assert document["cause"] == "key_not_public"


def test_diff_json_errors_name_the_input(runner, valid_token):
    document = _error_json(runner.invoke(cli, ["diff", "-", "-", "--json"]))
    assert document["error"] == "stdin_conflict"
    document = _error_json(runner.invoke(cli, ["diff", valid_token, "a.b", "--json"]))
    assert document["error"] == "invalid_structure"
    assert document["input"] == "after"


def test_crack_json_errors(runner, tmp_path):
    empty = tmp_path / "empty.txt"
    empty.write_text("")
    token = make_token({"sub": "1"})
    h, p, _ = token.split(".")
    assert _error_json(runner.invoke(cli, ["crack", f"{h}.{p}.", "--json"]))["error"] == (
        "signature_missing"
    )
    assert _error_json(runner.invoke(cli, ["crack", token, str(empty), "--json"]))["error"] == (
        "wordlist_empty"
    )
    rs = make_token({"sub": "1"}, header_override={"alg": "RS256", "typ": "JWT"})
    assert _error_json(runner.invoke(cli, ["crack", rs, str(empty), "--json"]))["error"] == (
        "unsupported_algorithm"
    )


def test_errors_without_json_render_a_panel_on_stderr(runner):
    result = runner.invoke(cli, ["decode", "a.b"])
    assert result.exit_code == 2
    assert result.stdout == ""
    assert "Invalid JWT structure" in result.stderr


def test_download_failures_keep_exit_code_1(runner, tmp_path):
    source = (tmp_path / "missing.txt").as_uri()
    result = runner.invoke(
        cli, ["download-wordlists", "--output-dir", str(tmp_path), "--source", source]
    )
    assert result.exit_code == 1
    assert "Download Failed" in result.stderr


def test_boundary_renders_any_toolkit_error():
    @click.command(cls=ToolkitCommand)
    @click.option("--json", "as_json", is_flag=True)
    def boom(as_json: bool) -> None:
        raise KeyParseError("Could not parse the key", ("detail",))

    result = CliRunner().invoke(boom, ["--json"])
    assert result.exit_code == 2
    assert json.loads(result.stdout)["error"] == "key_parse_failed"


def test_error_document_adds_cause_and_extra_only_when_set():
    plain = error_document(JwtToolkitError("Headline"))
    assert set(plain) == {"schema_version", "error", "message", "detail"}
    full = error_document(
        JwtToolkitError("Headline", cause="key_parse_failed", extra=(("input", "after"),))
    )
    assert full["cause"] == "key_parse_failed"
    assert full["input"] == "after"


def test_errors_stay_frozen_but_carry_tracebacks():
    @contextmanager
    def passthrough():
        yield

    with pytest.raises(KeyParseError) as excinfo, passthrough():
        try:
            raise OSError("disk")
        except OSError as exc:
            raise KeyParseError("Could not read the key") from exc
    error = excinfo.value
    assert error.__traceback__ is not None
    assert isinstance(error.__cause__, OSError)
    with pytest.raises(dataclasses.FrozenInstanceError):
        error.headline = "changed"


# Leak test: secrets and credential-bearing URLs must never reach any output.
@pytest.mark.parametrize(
    "args",
    [
        ["sign", "--payload", "{bad", "--secret", LEAK_SECRET],
        ["sign", "--payload", "{}", "--secret", LEAK_SECRET, "--alg", "RS256"],
        ["verify", "a.b", "--secret", LEAK_SECRET, "--json"],
        ["verify", "{rs}", "--secret", LEAK_SECRET, "--json"],
        ["audit", "{rs}", "--secret", LEAK_SECRET, "--json"],
        ["audit", "{rs}", "--secret", LEAK_SECRET],
        [
            "verify",
            "{rs}",
            "--json",
            "--jwks-url",
            f"ftp://admin:{LEAK_PASSWORD}@idp.example/jwks?api_key={LEAK_QUERY}",
        ],
        [
            "verify",
            "{rs}",
            "--jwks-url",
            f"file://admin:{LEAK_PASSWORD}@localhost/no-such-jwks.json?k={LEAK_QUERY}",
        ],
    ],
)
def test_no_secret_or_url_credential_reaches_any_output(runner, rsa_keypair, args):
    token = _rs256_token(rsa_keypair)
    result = runner.invoke(cli, [token if a == "{rs}" else a for a in args])
    output = result.stdout + result.stderr
    for canary in (LEAK_SECRET, LEAK_PASSWORD, LEAK_QUERY):
        assert canary not in output, (args, output)


def test_download_source_credentials_are_not_echoed(runner, tmp_path):
    source = f"file://admin:{LEAK_PASSWORD}@localhost/no-such-list.txt?token={LEAK_QUERY}"
    result = runner.invoke(
        cli, ["download-wordlists", "--output-dir", str(tmp_path), "--source", source]
    )
    output = result.stdout + result.stderr
    assert LEAK_PASSWORD not in output
    assert LEAK_QUERY not in output
