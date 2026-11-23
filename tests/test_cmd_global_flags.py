import os
import subprocess
import sys

import pytest

from jwt_toolkit.cli import cli
from tests.helpers import make_token


def test_quiet_keeps_the_generated_secret(runner):
    result = runner.invoke(cli, ["--quiet", "generate-secret"])
    assert result.exit_code == 0
    assert "Generated Secret" in result.stdout


def test_quiet_keeps_decode_output(runner, valid_token):
    result = runner.invoke(cli, ["--quiet", "decode", valid_token])
    assert result.exit_code == 0
    assert "Payload" in result.stdout


def test_quiet_keeps_verify_verdict(runner, valid_token):
    result = runner.invoke(cli, ["--quiet", "verify", valid_token, "--secret", "wrong"])
    assert result.exit_code == 1
    assert "INVALID" in result.stdout


def test_quiet_still_reports_errors(runner):
    result = runner.invoke(cli, ["--quiet", "decode", "not-a-token"])
    assert result.exit_code == 2
    assert "Invalid JWT structure" in result.stderr


def test_quiet_drops_crack_status_lines(runner, tmp_path):
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("nope\n")
    token = make_token({"sub": "1"})
    result = runner.invoke(cli, ["--quiet", "crack", token, str(wordlist), "--workers", "1"])
    assert result.exit_code == 0
    assert "Algorithm :" not in result.output
    assert "Secret not found" in result.stdout


def test_crack_status_lines_shown_without_quiet(runner, tmp_path):
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("nope\n")
    result = runner.invoke(cli, ["crack", make_token({"sub": "1"}), str(wordlist)])
    assert "Algorithm :" in result.stderr
    assert "Algorithm :" not in result.stdout


def test_error_panels_go_to_stderr(runner):
    result = runner.invoke(cli, ["sign", "--payload", "not json", "--secret", "x"])
    assert result.exit_code == 2
    assert result.stdout == ""
    assert "Invalid payload JSON" in result.stderr


def test_json_errors_stay_on_stdout(runner):
    result = runner.invoke(cli, ["decode", "not-a-token", "--json"])
    assert result.exit_code == 2
    assert '"error": "invalid_structure"' in result.stdout


def test_global_flags_do_not_leak_into_the_environment(runner, valid_token, monkeypatch):
    monkeypatch.delenv("JWT_TOOLKIT_QUIET", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    runner.invoke(cli, ["--quiet", "--no-color", "decode", valid_token])
    assert "JWT_TOOLKIT_QUIET" not in os.environ
    assert "NO_COLOR" not in os.environ


# FORCE_COLOR makes Rich treat the output as a terminal, where styles would be
# emitted; NO_COLOR and --no-color must still keep every escape code out.
_TERMINAL = {"FORCE_COLOR": "1", "COLUMNS": "100"}


def _assert_plain(text: str) -> None:
    assert "\x1b[" not in text, repr(text[:200])


def test_terminal_output_is_styled_without_no_color(runner, valid_token):
    result = runner.invoke(cli, ["--no-banner", "audit", valid_token], env=_TERMINAL)
    assert "\x1b[" in result.stdout


@pytest.mark.parametrize("command", [["decode"], ["audit"], ["verify", "--secret", "wrong"]])
def test_no_color_env_drops_all_styles_in_a_terminal(runner, valid_token, command):
    env = {**_TERMINAL, "NO_COLOR": "1"}
    result = runner.invoke(cli, ["--no-banner", command[0], valid_token, *command[1:]], env=env)
    _assert_plain(result.stdout)
    _assert_plain(result.stderr)


@pytest.mark.parametrize("command", [["decode"], ["audit"]])
def test_no_color_flag_drops_all_styles_in_a_terminal(runner, valid_token, command):
    result = runner.invoke(cli, ["--no-banner", "--no-color", *command, valid_token], env=_TERMINAL)
    _assert_plain(result.stdout)


def test_no_color_errors_have_no_styles(runner):
    env = {**_TERMINAL, "NO_COLOR": "1"}
    result = runner.invoke(cli, ["--no-banner", "decode", "not-a-token"], env=env)
    assert result.exit_code == 2
    _assert_plain(result.stderr)


def test_no_color_in_a_real_pseudo_terminal(valid_token):
    pty = pytest.importorskip("pty", reason="needs a POSIX pseudo-terminal")
    main, secondary = pty.openpty()
    env = {k: v for k, v in os.environ.items() if k not in ("FORCE_COLOR", "TERM")}
    env |= {"NO_COLOR": "1", "TERM": "xterm-256color", "COLUMNS": "100"}
    code = "from jwt_toolkit.cli import cli; cli()"
    proc = subprocess.Popen(
        [sys.executable, "-c", code, "--no-banner", "audit", valid_token],
        stdin=secondary,
        stdout=secondary,
        stderr=secondary,
        env=env,
    )
    # Read while the child runs: a pty buffer nobody drains would block it.
    os.close(secondary)
    chunks = []
    while True:
        try:
            data = os.read(main, 65536)
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
    os.close(main)
    proc.wait(timeout=60)
    output = b"".join(chunks).decode("utf-8", "replace")
    assert proc.returncode in (0, 1)
    assert "Token Audit" in output or "Grade" in output, output[:300]
    _assert_plain(output)
