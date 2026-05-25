import re

from jwt_toolkit.cli import cli


def invoke(runner, *args):
    return runner.invoke(cli, ["generate-secret", *args])


# Boundary / validation checks


def test_bits_zero_exits_2(runner):
    result = invoke(runner, "--bits", "0")
    assert result.exit_code == 2


def test_bits_negative_exits_2(runner):
    result = invoke(runner, "--bits", "-1")
    assert result.exit_code == 2


def test_bits_below_minimum_exits_2(runner):
    result = invoke(runner, "--bits", "7")
    assert result.exit_code == 2


def test_bits_not_multiple_of_8_exits_2(runner):
    result = invoke(runner, "--bits", "100")
    assert result.exit_code == 2


def test_bits_above_maximum_exits_2(runner):
    result = invoke(runner, "--bits", "5000")
    assert result.exit_code == 2


def test_bits_64_lower_bound_succeeds(runner):
    result = invoke(runner, "--bits", "64")
    assert result.exit_code == 0


def test_bits_4096_upper_bound_succeeds(runner):
    result = invoke(runner, "--bits", "4096")
    assert result.exit_code == 0


def test_bad_encoding_exits_2(runner):
    """Click's click.Choice rejects any value outside ['hex', 'base64']."""
    result = invoke(runner, "--encoding", "foobar")
    assert result.exit_code == 2


# Output format


def test_default_output_is_hex(runner):
    result = invoke(runner)
    assert result.exit_code == 0
    # hex output: 64 chars for 256-bit secret
    hex_match = re.search(r"\b[0-9a-f]{64}\b", result.output)
    assert hex_match is not None


def test_base64_encoding_produces_base64url_output(runner):
    result = invoke(runner, "--bits", "128", "--encoding", "base64")
    assert result.exit_code == 0
    assert "+" not in result.output
    assert "/" not in result.output
    assert "Encoding : base64" in result.output


def test_output_reports_correct_bit_length(runner):
    result = invoke(runner, "--bits", "512")
    assert result.exit_code == 0
    assert "512 bits" in result.output


def test_output_reports_strength_label(runner):
    result = invoke(runner, "--bits", "256")
    assert "strong" in result.output.lower()

    result = invoke(runner, "--bits", "128")
    assert "moderate" in result.output.lower()
