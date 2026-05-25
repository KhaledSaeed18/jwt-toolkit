from unittest.mock import MagicMock, patch

from jwt_toolkit.cli import cli


def _mock_response(content: bytes) -> MagicMock:
    """Simulate a urllib response that streams `content` in one read then EOF."""
    resp = MagicMock()
    resp.headers.get.return_value = str(len(content))
    resp.read.side_effect = [content, b""]
    return resp


def invoke(runner, *args):
    return runner.invoke(cli, ["download-wordlists", *args])


# File already exists


def test_existing_file_without_force_skips_download(runner, tmp_path):
    dest = tmp_path / "common-secrets.txt"
    dest.write_text("existing\n")
    result = invoke(runner, "--output-dir", str(tmp_path))
    assert result.exit_code == 0
    assert "Already exists" in result.output
    assert dest.read_text() == "existing\n"  # unchanged


def test_existing_file_with_force_overwrites(runner, tmp_path):
    dest = tmp_path / "common-secrets.txt"
    dest.write_text("old content\n")
    new_content = b"new_secret\n"

    with patch(
        "jwt_toolkit.commands.download_wordlists._open_url",
        return_value=_mock_response(new_content),
    ):
        # Force + custom source skips integrity check
        result = invoke(
            runner,
            "--output-dir",
            str(tmp_path),
            "--force",
            "--source",
            "https://example.com/wl.txt",
        )
    assert result.exit_code == 0
    assert dest.read_text() == "new_secret\n"


# Unwritable directory


def test_unwritable_parent_exits_2(runner, tmp_path):
    # Create a file where the directory should be to force mkdir to fail
    blocker = tmp_path / "blocked"
    blocker.write_text("i am a file, not a dir")
    nested = blocker / "wordlists"  # can't mkdir inside a file
    result = invoke(runner, "--output-dir", str(nested))
    assert result.exit_code == 2


# Happy path with --source (skips integrity check)


def test_happy_path_with_custom_source(runner, tmp_path):
    content = b"secret1\nsecret2\nsecret3\n"
    with patch(
        "jwt_toolkit.commands.download_wordlists._open_url", return_value=_mock_response(content)
    ):
        result = invoke(
            runner, "--output-dir", str(tmp_path), "--source", "https://example.com/wl.txt"
        )
    assert result.exit_code == 0
    dest = tmp_path / "common-secrets.txt"
    assert dest.exists()
    assert dest.read_bytes() == content


def test_happy_path_reports_entry_count(runner, tmp_path):
    content = b"secret1\nsecret2\nsecret3\n"
    with patch(
        "jwt_toolkit.commands.download_wordlists._open_url", return_value=_mock_response(content)
    ):
        result = invoke(
            runner, "--output-dir", str(tmp_path), "--source", "https://example.com/wl.txt"
        )
    assert "3" in result.output  # 3 lines reported
