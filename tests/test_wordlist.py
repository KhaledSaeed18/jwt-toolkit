import pytest

from jwt_toolkit.core.wordlist import (
    Candidate,
    contains_secret,
    count_lines,
    iter_candidates,
    iter_lines,
)


def test_iter_lines_strips_only_line_endings_and_leading_bom(tmp_path):
    path = tmp_path / "wl.txt"
    path.write_bytes(b"\xef\xbb\xbffirst\r\n  spaced  \n\n#hash\nlast")
    assert list(iter_lines(path)) == [b"first", b"  spaced  ", b"#hash", b"last"]


def test_count_lines_skips_blank_lines(tmp_path):
    path = tmp_path / "wl.txt"
    path.write_bytes(b"a\n\nb\n")
    assert count_lines(path) == 2


def test_all_encoding_yields_each_distinct_interpretation(tmp_path):
    path = tmp_path / "wl.txt"
    path.write_text("6869\n")
    candidates = list(iter_candidates(path, "all"))
    assert [(c.encoding, c.key) for c in candidates] == [
        ("utf-8", b"6869"),
        ("hex", b"hi"),
        ("base64", b"\xeb\xce\xbd"),
    ]
    assert {c.source for c in candidates} == {b"6869"}


def test_invalid_hex_and_base64_lines_are_skipped(tmp_path):
    path = tmp_path / "wl.txt"
    path.write_text("not hex!\n")
    assert list(iter_candidates(path, "hex")) == []
    assert list(iter_candidates(path, "base64")) == []


@pytest.mark.parametrize(
    ("encoding", "label"),
    [("utf-8", "abcd"), ("hex", "abcd [hex]"), ("base64", "abcd [b64]")],
)
def test_candidate_label_marks_the_encoding(encoding, label):
    assert Candidate(source=b"abcd", key=b"", encoding=encoding).label == label


def test_contains_secret_matches_whole_lines_only(tmp_path):
    path = tmp_path / "wl.txt"
    path.write_text("secret\nsupersecret\n")
    assert contains_secret(path, b"secret")
    assert not contains_secret(path, b"super")
