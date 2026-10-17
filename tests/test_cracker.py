import hashlib
import hmac

import pytest

from jwt_toolkit.core.cracker import find_secret

SIGNING_INPUT = b"header.payload"


def _signature(secret: bytes) -> bytes:
    return hmac.new(secret, SIGNING_INPUT, hashlib.sha256).digest()


def _candidates(words: list[str]) -> list[tuple[str, bytes]]:
    return [(w, w.encode()) for w in words]


def _run(words, secret, **kwargs):
    return find_secret(
        _candidates(words),
        signing_input=SIGNING_INPUT,
        signature=_signature(secret),
        digest="sha256",
        **kwargs,
    )


MODES = [
    pytest.param({"workers": 1}, id="serial"),
    pytest.param({"workers": 2, "batch_size": 3, "parallel": True}, id="processes"),
]


@pytest.mark.parametrize("mode", MODES)
def test_finds_secret_with_position(mode):
    words = [f"w{i}" for i in range(20)]
    result = _run(words, b"w13", **mode)
    assert result.label == "w13"
    assert result.position == 13


@pytest.mark.parametrize("mode", MODES)
def test_not_found_tests_every_candidate(mode):
    words = [f"w{i}" for i in range(20)]
    result = _run(words, b"absent", **mode)
    assert result.label is None
    assert result.position is None
    assert result.attempts == 20


def test_parallel_reports_first_match_in_candidate_order():
    words = [f"w{i}" for i in range(40)]
    words[5] = words[30] = "dup"
    result = _run(words, b"dup", workers=4, batch_size=1, parallel=True)
    assert result.position == 5


def test_parallel_flag_false_stays_in_process():
    result = _run(["a", "b"], b"b", workers=8, parallel=False)
    assert result.position == 1


def test_progress_is_monotonic_and_ends_at_attempts():
    seen: list[int] = []
    result = _run([f"w{i}" for i in range(10)], b"absent", batch_size=4, on_progress=seen.append)
    assert seen == sorted(seen)
    assert seen[-1] == result.attempts == 10


def test_empty_candidates():
    result = _run([], b"x")
    assert result.attempts == 0
    assert result.label is None
