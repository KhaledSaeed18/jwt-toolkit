"""Project-wide pytest fixtures.

Anything defined here is auto-injected into any test in `tests/` that
declares a matching argument — no imports required.
"""

import time
from collections.abc import Callable

import pytest
from click.testing import CliRunner

from tests.helpers import TEST_SECRET, make_token, make_unsigned_token

# Far-future expiry used by valid_token. A literal constant keeps tests
# readable without sprinkling magic numbers around.
_FAR_FUTURE = 9_999_999_999


@pytest.fixture
def runner() -> CliRunner:
    """Click test runner — one per test, isolated stdout/stderr."""
    return CliRunner()


@pytest.fixture
def test_secret() -> str:
    """The shared HS256 secret used by token factories."""
    return TEST_SECRET


@pytest.fixture
def now() -> int:
    """Frozen `int(time.time())` snapshot for the duration of the test.

    Captured once so multiple `now + delta` calls in the same test stay
    consistent — repeated inline `int(time.time())` does not guarantee that.
    """
    return int(time.time())


@pytest.fixture
def token_factory() -> Callable[..., str]:
    """Factory fixture returning `make_token` — preferred entry point for tests.

    Usage:
        def test_x(token_factory):
            t = token_factory({"sub": "1"}, alg="HS384")
    """
    return make_token


@pytest.fixture
def unsigned_token_factory() -> Callable[..., str]:
    """Factory for alg:none tokens."""
    return make_unsigned_token


@pytest.fixture
def valid_token() -> str:
    """HS256 JWT with a far-future exp and the shared test secret."""
    return make_token({"sub": "1", "exp": _FAR_FUTURE})
