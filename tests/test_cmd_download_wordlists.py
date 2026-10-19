import http.client
import ssl
import urllib.error
from importlib.metadata import version
from pathlib import Path
from unittest.mock import MagicMock, patch

from jwt_toolkit.cli import cli
from jwt_toolkit.commands.download_wordlists import _WORDLIST_URL


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


def test_tls_verification_failure_is_fatal_and_leaves_no_file(runner, tmp_path):
    cert_error = urllib.error.URLError(ssl.SSLCertVerificationError("self-signed certificate"))
    with patch(
        "jwt_toolkit.commands.download_wordlists.urllib.request.urlopen",
        side_effect=cert_error,
    ) as urlopen:
        result = invoke(runner, "--output-dir", str(tmp_path), "--source", "https://example.com/wl")
    assert result.exit_code == 1
    assert "certificate verification failed" in result.output
    assert urlopen.call_count == 1
    assert "context" not in urlopen.call_args.kwargs
    assert not (tmp_path / "common-secrets.txt").exists()


def test_default_url_is_pinned_to_installed_release_tag():
    assert f"/jwt-toolkit/v{version('jwt-toolkit')}/wordlists/" in _WORDLIST_URL
    assert "/main/" not in _WORDLIST_URL


def test_markup_in_source_and_path_is_shown_literally(runner, tmp_path):
    out_dir = tmp_path / "[red]"
    with patch(
        "jwt_toolkit.commands.download_wordlists._open_url", return_value=_mock_response(b"a\n")
    ):
        result = invoke(runner, "--output-dir", str(out_dir), "--source", "https://e.x/[/x]")
    assert result.exit_code == 0
    assert "https://e.x/[/x]" in result.output
    assert "[red]" in result.output


def test_failed_checksum_with_force_keeps_the_existing_copy(runner, tmp_path):
    dest = tmp_path / "common-secrets.txt"
    dest.write_text("good copy\n")
    with patch(
        "jwt_toolkit.commands.download_wordlists._open_url",
        return_value=_mock_response(b"tampered\n"),
    ):
        result = invoke(runner, "--output-dir", str(tmp_path), "--force")
    assert result.exit_code == 2
    assert "Integrity check failed" in result.stderr
    assert dest.read_text() == "good copy\n"
    assert list(tmp_path.iterdir()) == [dest]


def test_matching_checksum_from_default_url_is_saved(runner, tmp_path):
    content = (Path(__file__).parents[1] / "wordlists" / "common-secrets.txt").read_bytes()
    with patch(
        "jwt_toolkit.commands.download_wordlists._open_url", return_value=_mock_response(content)
    ):
        result = invoke(runner, "--output-dir", str(tmp_path))
    assert result.exit_code == 0
    assert (tmp_path / "common-secrets.txt").read_bytes() == content
    assert "Checksum" in result.stdout


def test_interrupted_download_leaves_no_partial_file(runner, tmp_path):
    response = _mock_response(b"")
    response.read.side_effect = [b"partial", http.client.IncompleteRead(b"")]
    with patch("jwt_toolkit.commands.download_wordlists._open_url", return_value=response):
        result = invoke(runner, "--output-dir", str(tmp_path), "--source", "https://e.x/wl")
    assert result.exit_code == 1
    assert "interrupted" in result.stderr
    assert list(tmp_path.iterdir()) == []
    response.close.assert_called_once()


def test_unsupported_source_scheme_exits_2(runner, tmp_path):
    result = invoke(runner, "--output-dir", str(tmp_path), "--source", "ftp://e.x/wl")
    assert result.exit_code == 2
    assert "not supported" in result.stderr


def test_single_entry_is_reported_in_the_singular(runner, tmp_path):
    with patch(
        "jwt_toolkit.commands.download_wordlists._open_url", return_value=_mock_response(b"a\n")
    ):
        result = invoke(runner, "--output-dir", str(tmp_path), "--source", "https://e.x/wl")
    assert "1 line\n" in result.stdout or "1 line " in result.stdout


def test_network_error_names_the_reason_without_errno(runner, tmp_path):
    error = urllib.error.URLError(OSError(8, "nodename nor servname provided"))
    with patch("jwt_toolkit.commands.download_wordlists._open_url", side_effect=error):
        result = invoke(runner, "--output-dir", str(tmp_path), "--source", "https://e.x/wl")
    assert result.exit_code == 1
    assert "nodename nor servname provided" in result.stderr
    assert "Errno" not in result.stderr
