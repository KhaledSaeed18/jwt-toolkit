"""Generated hostile input for the parsing and checking entry points.

Every entry point must either succeed or raise a JwtToolkitError; anything else
is a crash a hostile token could trigger. Examples are bounded so CI stays fast.
"""

import contextlib
import json

from click.testing import CliRunner
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from jwt_toolkit.cli import cli
from jwt_toolkit.core.auditor import run_audit
from jwt_toolkit.core.decoder import DecodedToken, decode_token
from jwt_toolkit.core.diff import diff_tokens
from jwt_toolkit.core.encoding import base64url_encode, strict_json_loads
from jwt_toolkit.core.errors import JwtToolkitError, TokenDecodeError
from jwt_toolkit.core.forge import generate_variants
from jwt_toolkit.core.jwks import jwk_to_public_key
from jwt_toolkit.core.keys import HmacKey
from jwt_toolkit.core.timestamps import describe_time_claims
from jwt_toolkit.core.verifier import Expectations, verify_token

_FAST = settings(max_examples=150, deadline=None)
_CLI = settings(
    max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
_NOW = 1_700_000_000.0

_ALGS = ["HS256", "HS384", "HS512", "RS256", "PS256", "ES256", "EdDSA", "Ed25519", "none",
         "NONE", "hs256", "", "HS999"]  # fmt: skip

_numbers = st.one_of(
    st.integers(min_value=-(10**30), max_value=10**30),
    st.floats(allow_nan=False, allow_infinity=False),
)
_scalars = st.one_of(st.none(), st.booleans(), _numbers, st.text(max_size=20))
_json_values = st.recursive(
    _scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(max_size=8), children, max_size=4),
    ),
    max_leaves=20,
)
_claim_values = st.one_of(_json_values, _numbers)

_headers = st.fixed_dictionaries(
    {"alg": st.one_of(st.sampled_from(_ALGS), _json_values)},
    optional={
        "typ": _json_values,
        "kid": _json_values,
        "crit": _json_values,
        "b64": _json_values,
        "jku": _json_values,
        "jwk": _json_values,
        "x5u": _json_values,
        "x5c": _json_values,
        "cty": _json_values,
    },
)
_payloads = st.fixed_dictionaries(
    {},
    optional={
        "exp": _claim_values,
        "nbf": _claim_values,
        "iat": _claim_values,
        "iss": _json_values,
        "aud": _json_values,
        "sub": _json_values,
        "jti": _json_values,
        "password": _json_values,
    },
).flatmap(
    lambda fixed: st.dictionaries(st.text(max_size=8), _json_values, max_size=3).map(
        lambda extra: {**extra, **fixed}
    )
)
_signatures = st.text(
    alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", max_size=90
) | st.text(max_size=12).filter(lambda s: "." not in s and not any(c.isspace() for c in s))


def _segment(value: object) -> str:
    return base64url_encode(json.dumps(value).encode())


@st.composite
def _tokens(draw: st.DrawFn) -> str:
    return f"{_segment(draw(_headers))}.{_segment(draw(_payloads))}.{draw(_signatures)}"


# Raw text and raw segments: decoding fails only with TokenDecodeError.


@_FAST
@given(st.text(max_size=200))
def test_decode_arbitrary_text(text: str) -> None:
    with contextlib.suppress(TokenDecodeError):
        decode_token(text, tolerate_whitespace=True)


@_FAST
@given(st.lists(st.binary(max_size=60), min_size=3, max_size=3))
def test_decode_arbitrary_segment_bytes(parts: list[bytes]) -> None:
    with contextlib.suppress(TokenDecodeError):
        decode_token(".".join(base64url_encode(part) for part in parts))


@_FAST
@given(st.text(alphabet='{}[]",:0123456789.eE-+ntrufalsN\\', max_size=60))
def test_strict_json_on_json_like_text(text: str) -> None:
    with contextlib.suppress(ValueError):
        strict_json_loads(text)


@_FAST
@given(_json_values)
def test_strict_json_round_trips_valid_json(value: object) -> None:
    assert strict_json_loads(json.dumps(value)) == value


# Well-formed tokens with hostile contents: every check returns a result.


@_FAST
@given(_tokens())
def test_core_checks_never_crash(token: str) -> None:
    decoded = decode_token(token)
    run_audit(decoded.header, decoded.payload, signature=decoded.signature)
    describe_time_claims(decoded.payload, now=_NOW)
    diff_tokens(decoded, decoded)
    with contextlib.suppress(JwtToolkitError):
        verify_token(
            decoded,
            key=HmacKey(b"testsecret"),
            now=_NOW,
            expected=Expectations(issuer="iss", audience="aud", leeway=0),
        )


@_FAST
@given(_tokens())
def test_forge_static_variants_never_crash(token: str) -> None:
    decoded: DecodedToken = decode_token(token)
    for variant in generate_variants(decoded):
        assert variant.token.count(".") == 2


@_FAST
@given(
    st.dictionaries(
        st.sampled_from(["kty", "crv", "n", "e", "x", "y", "use", "key_ops", "alg", "kid"]),
        _json_values | st.text(alphabet="AQIDBAUG-_", max_size=40),
    ),
    st.sampled_from(_ALGS),
)
def test_jwk_shapes_fail_only_with_typed_errors(jwk: dict[str, object], alg: str) -> None:
    with contextlib.suppress(JwtToolkitError):
        jwk_to_public_key(jwk, alg)


# The CLI: every outcome is a documented exit code and a JSON document.


@_CLI
@given(_tokens(), st.sampled_from([["decode"], ["audit"], ["verify", "--secret", "testsecret"]]))
def test_cli_json_output_for_hostile_tokens(token: str, command: list[str]) -> None:
    result = CliRunner().invoke(cli, [command[0], token, *command[1:], "--json"])
    assert result.exit_code in (0, 1, 2), result.exception
    if result.exception is not None:
        assert isinstance(result.exception, SystemExit)
    assert "schema_version" in json.loads(result.stdout)
