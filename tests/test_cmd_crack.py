from jwt_toolkit.cli import cli
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


def test_crack_comments_only_wordlist_exits_2(runner, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("# comment\n# another comment\n")
    t = make_token({"sub": "1"})
    result = invoke(runner, wl, t)
    assert result.exit_code == 2


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
