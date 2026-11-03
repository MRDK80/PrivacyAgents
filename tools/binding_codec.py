"""Repository-only structural LA1.0 codec, never a permission or lifecycle check.

A returned record or digest does not authenticate its owner, resolve its source,
validate a time window, or authorize any effect. Other record families are not
supported here. No filesystem, clock or runtime consumer is involved.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import NoReturn, cast

_FIELDS = frozenset({
    "schema_id", "schema_version", "binding_intent_digest", "owner_identity",
    "approved_at", "not_before", "expires_at", "revoked", "action",
})
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class CodecError(ValueError):
    """Fixed diagnostic with no supplied record or native parser exception."""

    def __init__(self) -> None:
        super().__init__("Invalid binding record")


def _reject_number(_text: str) -> NoReturn:
    raise CodecError()


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise CodecError()
        value[key] = item
    return value


def _check_json(value: object) -> None:
    """Reject unsupported primitives, NUL and escaped surrogate codepoints."""
    if type(value) is str:
        text = value
        if "\0" in text:
            raise CodecError()
        text.encode("utf-8", errors="strict")
    elif type(value) is dict:
        for key, item in cast(dict[object, object], value).items():
            if type(key) is not str:
                raise CodecError()
            _check_json(key)
            _check_json(item)
    elif type(value) is list:
        for item in cast(list[object], value):
            _check_json(item)
    elif value is not None and type(value) not in (bool, int):
        raise CodecError()


def _strict_json(payload: bytes, byte_cap: int) -> object:
    if type(payload) is not bytes or type(byte_cap) is not int or byte_cap <= 0:
        raise CodecError()
    if len(payload) > byte_cap:
        raise CodecError()
    failed = False
    value: object = None
    try:
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(
            text, object_pairs_hook=_pairs, parse_float=_reject_number,
            parse_constant=_reject_number,
        )
        _check_json(value)
    except (ValueError, UnicodeError, RecursionError):
        failed = True
    # Raise after leaving the handler: no raw parser exception remains as context.
    if failed:
        raise CodecError()
    return value


def _launch_shape(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise CodecError()
    record = cast(dict[str, object], value)
    if record.keys() != _FIELDS:
        raise CodecError()
    if (
        record["schema_id"] != "privacyagents.launch-approval"
        or record["schema_version"] != "1.0"
        or record["action"] != "launch-bound-synthetic-run"
    ):
        raise CodecError()
    digest = record["binding_intent_digest"]
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise CodecError()
    owner = record["owner_identity"]
    if not isinstance(owner, str) or not owner.isascii():
        raise CodecError()
    for field in ("approved_at", "not_before", "expires_at"):
        timestamp = record[field]
        if type(timestamp) is not int or timestamp < 0:
            raise CodecError()
    if type(record["revoked"]) is not bool:
        raise CodecError()
    return record


def _canonical_json(value: object) -> bytes:
    """Private encoding primitive, not an arbitrary-family record digest API."""
    failed = False
    encoded = b""
    try:
        _check_json(value)
        encoded = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        failed = True
    if failed:
        raise CodecError()
    return encoded


def read_launch_approval(payload: bytes, *, byte_cap: int) -> dict[str, object]:
    """Decode ONE structural family only; this does not establish valid approval."""
    return _launch_shape(_strict_json(payload, byte_cap))


def canonical_launch_approval(payload: bytes, *, byte_cap: int) -> bytes:
    """Encode all nine checked fields without normalization or exclusions."""
    return _canonical_json(read_launch_approval(payload, byte_cap=byte_cap))


def launch_approval_digest(payload: bytes, *, byte_cap: int) -> str:
    """Hash all structural LA fields; the digest confers no authority or readiness."""
    return "sha256:" + hashlib.sha256(
        canonical_launch_approval(payload, byte_cap=byte_cap)
    ).hexdigest()
