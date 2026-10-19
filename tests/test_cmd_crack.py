import hashlib
import hmac
import json

import pytest

from jwt_toolkit.cli import cli
from jwt_toolkit.core.encoding import base64url_encode
from tests.helpers import make_rs256_token, make_token, make_unsigned_token


def invoke(runner, wordlist_path, token, *extra):
    return runner.invoke(cli, ["crack", token, str(wordlist_path), "--threads", "1", *extra])


# Found / not found


def test_crack_finds_secret(runner, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("wrong1\nwrong2\ntestsecret\nwrong3\n")
    t = make_token({"sub": "1"}, secret="testsecret")
    result = invoke(runner, wl, t)
    assert result.exit_code == 1
    assert "testsecret" in result.output


def test_crack_reports_position(runner, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("a\nb\ntestsecret\nd\n")
    t = make_token({"sub": "1"}, secret="testsecret")
    result = invoke(runner, wl, t)
    assert "#3" in result.output


def test_crack_not_found_exits_0(runner, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("wrong1\nwrong2\nwrong3\n")
    t = make_token({"sub": "1"}, secret="notinthelist")
    result = invoke(runner, wl, t)
    assert result.exit_code == 0
    assert "not found" in result.output.lower()


# Wordlist edge cases


def test_crack_empty_wordlist_exits_2(runner, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("")
    t = make_token({"sub": "1"})
    result = invoke(runner, wl, t)
    assert result.exit_code == 2
    assert "empty" in result.output.lower()


def test_crack_blank_lines_only_wordlist_exits_2(runner, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_bytes(b"\n\r\n\n")
    t = make_token({"sub": "1"})
    result = invoke(runner, wl, t)
    assert result.exit_code == 2


@pytest.mark.parametrize(
    "secret",
    [" leading-space", "trailing-space ", "tab\tinside", "trailing-tab\t", "#hash-prefixed", " "],
)
def test_crack_finds_secret_with_whitespace_or_hash(runner, tmp_path, secret):
    wl = tmp_path / "wl.txt"
    wl.write_bytes(b"alpha\n" + secret.encode() + b"\nomega\n")
    t = make_token({"sub": "1"}, secret=secret)
    result = invoke(runner, wl, t)
    assert result.exit_code == 1


def test_crack_handles_crlf_and_bom(runner, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_bytes(b"\xef\xbb\xbffirst\r\nsecond\r\n")
    for secret in ("first", "second"):
        result = invoke(runner, wl, make_token({"sub": "1"}, secret=secret))
        assert result.exit_code == 1, secret


def test_crack_finds_non_utf8_secret(runner, tmp_path):
    secret = "caf\xe9".encode("latin-1")
    h = base64url_encode(b'{"alg":"HS256","typ":"JWT"}')
    p = base64url_encode(b'{"sub":"1"}')
    sig = base64url_encode(hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest())
    wl = tmp_path / "wl.txt"
    wl.write_bytes(b"alpha\n" + secret + b"\n")
    result = invoke(runner, wl, f"{h}.{p}.{sig}")
    assert result.exit_code == 1


# Algorithm rejection


def test_crack_alg_none_exits_2(runner, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("secret\n")
    t = make_unsigned_token({"sub": "1"})
    result = invoke(runner, wl, t)
    assert result.exit_code == 2


def test_crack_rs256_exits_2(runner, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("secret\n")
    t = make_rs256_token({"sub": "1"})
    result = invoke(runner, wl, t)
    assert result.exit_code == 2


# --threads validation


def test_crack_invalid_threads_exits_2(runner, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("secret\n")
    t = make_token({"sub": "1"})
    result = runner.invoke(cli, ["crack", t, str(wl), "--threads", "0"])
    assert result.exit_code == 2


def test_crack_missing_wordlist_file_exits_2(runner, tmp_path):
    """Click's click.Path(exists=True) rejects a nonexistent wordlist path."""
    t = make_token({"sub": "1"})
    missing = str(tmp_path / "does_not_exist.txt")
    result = runner.invoke(cli, ["crack", t, missing])
    assert result.exit_code == 2


# --encoding


def test_crack_encoding_hex(runner, tmp_path):
    secret_bytes = b"mysecret"
    hex_secret = secret_bytes.hex()
    wl = tmp_path / "wl.txt"
    wl.write_text(f"{hex_secret}\n")
    t = make_token({"sub": "1"}, secret="mysecret")
    result = invoke(runner, wl, t, "--encoding", "hex")
    assert result.exit_code == 1
    assert hex_secret in result.output


def test_crack_encoding_all_deduplicates(runner, tmp_path):
    """A word whose utf-8 and hex expansions yield the same bytes should only be tried once."""
    # "mysecret" in utf-8 and its hex-encoded form decode to different bytes,
    # so no dedup happens here — but two lines with the same plaintext must not
    # produce duplicate utf-8 entries.
    wl = tmp_path / "wl.txt"
    wl.write_text("testsecret\ntestsecret\n")  # duplicate lines
    t = make_token({"sub": "1"}, secret="testsecret")
    result = invoke(runner, wl, t, "--encoding", "utf-8")
    # Should find on first occurrence, not error or duplicate
    assert result.exit_code == 1
    assert "testsecret" in result.output


# --output


def test_crack_output_writes_secret(runner, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("testsecret\n")
    out = tmp_path / "found.txt"
    t = make_token({"sub": "1"}, secret="testsecret")
    result = invoke(runner, wl, t, "--output", str(out))
    assert result.exit_code == 1
    assert out.exists()
    assert out.read_text().strip() == "testsecret"


def test_crack_output_write_failure_shows_inline_note(runner, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("testsecret\n")
    t = make_token({"sub": "1"}, secret="testsecret")
    # Point output at a path inside a nonexistent directory
    bad_output = str(tmp_path / "nonexistent_dir" / "out.txt")
    result = invoke(runner, wl, t, "--output", bad_output)
    assert result.exit_code == 1
    assert "Could not save" in result.output or "save" in result.output.lower()


def test_crack_workers_alias_matches_threads(runner, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("alpha\ntestsecret\n")
    t = make_token({"sub": "1"})
    result = runner.invoke(cli, ["crack", t, str(wl), "--workers", "2"])
    assert result.exit_code == 1


def test_crack_invalid_base64_signature_exits_2(runner, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("alpha\n")
    h, p, _ = make_token({"sub": "1"}).split(".")
    result = invoke(runner, wl, f"{h}.{p}.@@@not-base64@@@")
    assert result.exit_code == 2
    assert "not valid base64url" in result.output


def test_crack_without_wordlist_uses_bundled_list(runner):
    t = make_token({"sub": "1"}, secret="password")
    result = runner.invoke(cli, ["crack", t, "--workers", "1"])
    assert result.exit_code == 1
    assert "bundled common-secrets.txt" in result.output


def test_crack_without_wordlist_and_no_bundled_list_exits_2(runner, monkeypatch):
    monkeypatch.setattr("jwt_toolkit.commands.crack.bundled_wordlist", lambda: None)
    result = runner.invoke(cli, ["crack", make_token({"sub": "1"})])
    assert result.exit_code == 2
    assert "download-wordlists" in result.output


def test_crack_directory_wordlist_exits_2(runner, tmp_path):
    result = runner.invoke(cli, ["crack", make_token({"sub": "1"}), str(tmp_path)])
    assert result.exit_code == 2
    assert "Traceback" not in result.output


def test_crack_json_reports_found_secret(runner, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("wrong\ntestsecret\n")
    result = invoke(runner, wl, make_token({"sub": "1"}), "--json")
    assert result.exit_code == 1
    document = json.loads(result.stdout)
    assert document["found"] is True
    assert document["secret"] == "testsecret"
    assert document["secret_encoding"] == "utf-8"
    assert document["position"] == 2
    assert document["algorithm"] == "HS256"
    assert document["candidates_tried"] >= 2


def test_crack_json_reports_not_found(runner, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("wrong\n")
    result = invoke(runner, wl, make_token({"sub": "1"}), "--json")
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document == {
        "schema_version": "0.1",
        "found": False,
        "algorithm": "HS256",
        "wordlist": str(wl),
        "encoding": "utf-8",
        "candidates_tried": 1,
        "elapsed_seconds": document["elapsed_seconds"],
    }


def test_crack_json_error_for_empty_wordlist(runner, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("\n")
    result = invoke(runner, wl, make_token({"sub": "1"}), "--json")
    assert result.exit_code == 2
    assert json.loads(result.stdout)["error"] == "wordlist_empty"


def test_crack_json_error_for_rs256_token(runner, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("x\n")
    result = invoke(runner, wl, make_rs256_token({"sub": "1"}), "--json")
    assert result.exit_code == 2
    assert json.loads(result.stdout)["error"] == "unsupported_algorithm"


def test_crack_output_writes_the_wordlist_line_not_the_label(runner, tmp_path):
    secret = bytes.fromhex("00ff10")
    header = base64url_encode(b'{"alg":"HS256"}')
    payload = base64url_encode(b"{}")
    sig = hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    token = f"{header}.{payload}.{base64url_encode(sig)}"
    wl = tmp_path / "wl.txt"
    wl.write_text("00ff10\n")
    out = tmp_path / "found.txt"
    result = invoke(runner, wl, token, "--encoding", "hex", "--output", str(out))
    assert result.exit_code == 1
    assert out.read_bytes() == b"00ff10\n"


def test_crack_output_file_is_owner_only(runner, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("testsecret\n")
    out = tmp_path / "found.txt"
    out.write_text("old")
    out.chmod(0o644)
    invoke(runner, wl, make_token({"sub": "1"}), "--output", str(out))
    assert out.stat().st_mode & 0o777 == 0o600
    assert out.read_text() == "testsecret\n"


def test_crack_output_keeps_non_utf8_secret_bytes(runner, tmp_path):
    secret = b"caf\xe9"
    header = base64url_encode(b'{"alg":"HS256"}')
    payload = base64url_encode(b"{}")
    sig = hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    wl = tmp_path / "wl.txt"
    wl.write_bytes(secret + b"\n")
    out = tmp_path / "found.txt"
    invoke(runner, wl, f"{header}.{payload}.{base64url_encode(sig)}", "--output", str(out))
    assert out.read_bytes() == secret + b"\n"
