import pytest

from jwt_toolkit.cli import cli
from tests.helpers import TEST_SECRET, make_token

# Token contents and wordlist lines are untrusted. Rich markup inside them must be shown
# literally: an unbalanced tag used to crash with a traceback, and a balanced one could
# restyle or hide parts of a security report.
_HOSTILE = "[/x][red]PASS[/red]"


@pytest.fixture
def hostile_token() -> str:
    return make_token({"sub": _HOSTILE, "iss": _HOSTILE, "kid": _HOSTILE})


def test_audit_shows_markup_literally(runner, hostile_token):
    result = runner.invoke(cli, ["audit", hostile_token, "--secret", TEST_SECRET])
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert _HOSTILE in result.output


def test_verify_shows_markup_literally(runner, hostile_token):
    result = runner.invoke(
        cli, ["verify", hostile_token, "--secret", TEST_SECRET, "--issuer", "expected"]
    )
    assert result.exit_code == 1
    assert _HOSTILE in result.output


def test_decode_signature_shows_markup_literally(runner):
    header, payload, _ = make_token({"sub": "1"}).split(".")
    result = runner.invoke(cli, ["decode", f"{header}.{payload}.{_HOSTILE}"])
    assert result.exit_code == 0
    assert _HOSTILE in result.output


def test_forge_shows_markup_literally(runner):
    header, payload, _ = make_token({"sub": "1"}).split(".")
    result = runner.invoke(cli, ["forge", f"{header}.{payload}.{_HOSTILE}"])
    assert result.exit_code == 0
    assert _HOSTILE in result.output


def test_crack_shows_found_secret_literally(runner, tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text(f"nope\n{_HOSTILE}\n")
    token = make_token({"sub": "1"}, secret=_HOSTILE)
    result = runner.invoke(cli, ["crack", token, str(wordlist)])
    assert result.exit_code == 1
    assert _HOSTILE in result.output


def test_sign_error_shows_markup_literally(runner):
    result = runner.invoke(
        cli, ["sign", "--payload", "{}", "--secret", "s", "--header", '{"alg":"[/x]"}']
    )
    assert result.exit_code == 2
    assert "[/x]" in result.output.lower()
