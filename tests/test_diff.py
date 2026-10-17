import json

from jwt_toolkit.core.decoder import decode_token
from jwt_toolkit.core.diff import FieldChange, diff_tokens
from jwt_toolkit.core.encoding import base64url_encode
from tests.helpers import make_token


def _diff(before: str, after: str):
    return diff_tokens(decode_token(before), decode_token(after))


def _changes(before_payload: dict, after_payload: dict) -> tuple[FieldChange, ...]:
    return _diff(make_token(before_payload), make_token(after_payload)).changes


def test_identical_tokens_have_no_differences():
    token = make_token({"sub": "1"})
    result = _diff(token, token)
    assert result.identical
    assert result.changes == ()
    assert not result.signature_changed


def test_reports_added_removed_and_changed_claims():
    changes = _changes({"sub": "1", "name": "a"}, {"sub": "2", "email": "e"})
    assert [(c.path, c.kind) for c in changes] == [
        ("/sub", "changed"),
        ("/name", "removed"),
        ("/email", "added"),
    ]
    sub, name, email = changes
    assert (sub.before, sub.after) == ("1", "2")
    assert name.before == "a"
    assert email.after == "e"


def test_new_claims_change_the_signature():
    result = _diff(make_token({"sub": "1"}), make_token({"sub": "2"}))
    assert result.signature_changed
    assert not result.identical


def test_nested_objects_use_json_pointer_paths():
    changes = _changes({"ctx": {"org": {"id": 1}}}, {"ctx": {"org": {"id": 2}}})
    assert [c.path for c in changes] == ["/ctx/org/id"]


def test_pointer_escapes_slash_and_tilde():
    changes = _changes({"a/b": 1, "c~d": 1}, {"a/b": 2, "c~d": 2})
    assert [c.path for c in changes] == ["/a~1b", "/c~0d"]


def test_arrays_are_compared_in_order():
    changes = _changes({"roles": ["user", "admin"]}, {"roles": ["admin", "user"]})
    assert [(c.path, c.kind) for c in changes] == [
        ("/roles/0", "changed"),
        ("/roles/1", "changed"),
    ]


def test_array_growth_and_shrink():
    grown = _changes({"roles": ["user"]}, {"roles": ["user", "admin"]})
    assert [(c.path, c.kind, c.after) for c in grown] == [("/roles/1", "added", "admin")]

    shrunk = _changes({"roles": ["user", "admin"]}, {"roles": ["user"]})
    assert [(c.path, c.kind, c.before) for c in shrunk] == [("/roles/1", "removed", "admin")]


def test_json_types_are_not_conflated():
    changes = _changes({"a": 1, "b": 1, "c": 0}, {"a": True, "b": 1.0, "c": False})
    assert [c.path for c in changes] == ["/a", "/b", "/c"]


def test_null_differs_from_missing():
    changes = _changes({"a": None}, {})
    assert [(c.path, c.kind) for c in changes] == [("/a", "removed")]


def test_type_change_between_object_and_array_is_a_change():
    changes = _changes({"aud": ["x"]}, {"aud": "x"})
    assert [(c.path, c.kind) for c in changes] == [("/aud", "changed")]


def test_notable_claims_are_marked_including_nested_paths():
    changes = _changes(
        {"iss": "a", "roles": ["user"], "theme": "dark"},
        {"iss": "b", "roles": ["admin"], "theme": "light"},
    )
    assert {c.path: c.notable for c in changes} == {
        "/iss": True,
        "/roles/0": True,
        "/theme": False,
    }


def test_header_changes_are_reported_separately():
    before = make_token({"sub": "1"})
    after = make_token({"sub": "1"}, header_override={"alg": "HS256", "kid": "k2"})
    result = _diff(before, after)
    assert [(c.section, c.path, c.kind, c.notable) for c in result.changes] == [
        ("header", "/typ", "removed", True),
        ("header", "/kid", "added", True),
    ]
    assert not result.payload_encoding_changed


def test_serialization_only_change_is_flagged_without_field_changes():
    token = make_token({"a": 1, "b": 2})
    header, _, signature = token.split(".")
    reordered = base64url_encode(json.dumps({"b": 2, "a": 1}).encode())
    result = _diff(token, f"{header}.{reordered}.{signature}")
    assert result.changes == ()
    assert result.payload_encoding_changed
    assert not result.header_encoding_changed
    assert not result.signature_changed
    assert not result.identical


def test_signature_only_change():
    token = make_token({"sub": "1"})
    other = make_token({"sub": "1"}, secret="another-secret")
    result = _diff(token, other)
    assert result.changes == ()
    assert result.signature_changed
    assert not result.payload_encoding_changed
