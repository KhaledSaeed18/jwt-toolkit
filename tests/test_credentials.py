import pytest

from jwt_toolkit.cli.credentials import SecretInputError, resolve_secret


def _write(tmp_path, data: bytes):
    path = tmp_path / "secret"
    path.write_bytes(data)
    return path


def test_without_file_returns_inline_secret():
    assert resolve_secret("inline", None) == "inline"
    assert resolve_secret(None, None) is None


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"secret", "secret"),
        (b"secret\n", "secret"),
        (b"secret\r\n", "secret"),
        (b"\xef\xbb\xbfsecret\n", "secret"),
        (b"  spaced secret \n", "  spaced secret "),
        (b"secret\n\n", "secret\n"),
        ("päss".encode(), "päss"),
    ],
)
def test_reads_file_removing_only_one_line_ending(tmp_path, data, expected):
    assert resolve_secret(None, _write(tmp_path, data)) == expected


def test_both_sources_are_rejected(tmp_path):
    with pytest.raises(SecretInputError, match="not both"):
        resolve_secret("inline", _write(tmp_path, b"file"))


@pytest.mark.parametrize("data", [b"", b"\n", b"\xef\xbb\xbf"])
def test_empty_file_is_rejected(tmp_path, data):
    with pytest.raises(SecretInputError, match="empty"):
        resolve_secret(None, _write(tmp_path, data))


def test_non_utf8_file_is_rejected_without_echoing_contents(tmp_path):
    with pytest.raises(SecretInputError) as excinfo:
        resolve_secret(None, _write(tmp_path, b"\xff\xfesecret"))
    assert "UTF-8" in excinfo.value.headline
    assert "secret" not in " ".join((excinfo.value.headline, *excinfo.value.details)).replace(
        "--secret", ""
    )


def test_unreadable_file_is_reported(tmp_path):
    with pytest.raises(SecretInputError, match="Cannot read"):
        resolve_secret(None, tmp_path)
