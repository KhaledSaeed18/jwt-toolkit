import hmac
from dataclasses import dataclass
from typing import Literal

from jwt_toolkit.core.decoder import DecodedToken

type Section = Literal["header", "payload"]
type ChangeKind = Literal["added", "removed", "changed"]

_MISSING = object()

# Fields whose changes usually matter for trust decisions. Marking them is a reading aid only;
# the diff never claims that a change grants or removes access.
NOTABLE_HEADER_FIELDS = frozenset(
    {"alg", "b64", "crit", "cty", "jku", "jwk", "kid", "typ", "x5c", "x5t", "x5t#S256", "x5u"}
)
NOTABLE_PAYLOAD_FIELDS = frozenset(
    {
        "aud",
        "azp",
        "client_id",
        "exp",
        "groups",
        "iat",
        "iss",
        "jti",
        "nbf",
        "permissions",
        "roles",
        "scope",
        "scp",
        "sub",
    }
)


@dataclass(frozen=True)
class FieldChange:
    # `path` is an RFC 6901 JSON Pointer into the section. `before` is unset for
    # added fields and `after` is unset for removed ones.
    section: Section
    path: str
    kind: ChangeKind
    before: object = None
    after: object = None
    notable: bool = False


@dataclass(frozen=True)
class TokenDiff:
    changes: tuple[FieldChange, ...]
    signature_changed: bool
    header_encoding_changed: bool
    payload_encoding_changed: bool

    @property
    def identical(self) -> bool:
        return not (
            self.changes
            or self.signature_changed
            or self.header_encoding_changed
            or self.payload_encoding_changed
        )


def diff_tokens(before: DecodedToken, after: DecodedToken) -> TokenDiff:
    changes = [
        *_diff_section("header", before.header, after.header),
        *_diff_section("payload", before.payload, after.payload),
    ]
    return TokenDiff(
        changes=tuple(changes),
        signature_changed=not _same_segment(before.signature, after.signature),
        header_encoding_changed=_encoding_only_change(
            before.header_b64, after.header_b64, changes, "header"
        ),
        payload_encoding_changed=_encoding_only_change(
            before.payload_b64, after.payload_b64, changes, "payload"
        ),
    )


def _diff_section(section: Section, before: dict, after: dict) -> list[FieldChange]:
    notable_fields = NOTABLE_HEADER_FIELDS if section == "header" else NOTABLE_PAYLOAD_FIELDS
    changes: list[FieldChange] = []
    for key in _ordered_keys(before, after):
        notable = key in notable_fields
        changes.extend(_diff_value(section, _pointer("", key), before, after, key, notable=notable))
    return changes


def _diff_value(
    section: Section,
    path: str,
    before: dict | list,
    after: dict | list,
    key: str | int,
    *,
    notable: bool,
) -> list[FieldChange]:
    old = _lookup(before, key)
    new = _lookup(after, key)
    if new is _MISSING:
        return [FieldChange(section, path, "removed", before=old, notable=notable)]
    if old is _MISSING:
        return [FieldChange(section, path, "added", after=new, notable=notable)]
    if isinstance(old, dict) and isinstance(new, dict):
        return [
            change
            for child in _ordered_keys(old, new)
            for change in _diff_value(
                section, _pointer(path, child), old, new, child, notable=notable
            )
        ]
    # Arrays stay ordered: a reordered list of roles is reported, not normalized away.
    if isinstance(old, list) and isinstance(new, list):
        return [
            change
            for index in range(max(len(old), len(new)))
            for change in _diff_value(
                section, _pointer(path, index), old, new, index, notable=notable
            )
        ]
    if _same_value(old, new):
        return []
    return [FieldChange(section, path, "changed", before=old, after=new, notable=notable)]


def _same_value(old: object, new: object) -> bool:
    # JSON true, 1, and 1.0 are different values even though Python compares them equal.
    return type(old) is type(new) and old == new


def _same_segment(old: str, new: str) -> bool:
    return hmac.compare_digest(old.encode(), new.encode())


def _encoding_only_change(
    old_b64: str, new_b64: str, changes: list[FieldChange], section: Section
) -> bool:
    # Same decoded JSON but different bytes, e.g. reordered keys or extra whitespace.
    if any(change.section == section for change in changes):
        return False
    return not _same_segment(old_b64, new_b64)


def _ordered_keys(before: dict, after: dict) -> list[str]:
    return [*before, *(key for key in after if key not in before)]


def _lookup(container: dict | list, key: str | int) -> object:
    if isinstance(container, dict):
        return container.get(key, _MISSING)
    if isinstance(key, int) and key < len(container):
        return container[key]
    return _MISSING


def _pointer(parent: str, key: str | int) -> str:
    token = str(key).replace("~", "~0").replace("/", "~1")
    return f"{parent}/{token}"
