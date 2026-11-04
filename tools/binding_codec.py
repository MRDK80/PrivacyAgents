"""Repository-only structural binding codecs, never permission/lifecycle checks.

A returned record or digest does not authenticate its owner, resolve its source,
validate a time window, or authorize any effect. Only named LA/IA/HA/RC1.0
entry paths are supported. No filesystem, clock or runtime consumer is involved.
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


def _approval_leaf(
    value: object, *, family: str, digest_fields: tuple[str, ...], window: bool
) -> dict[str, object]:
    """Shared shape checks for the two explicitly selected new leaf entry paths."""
    if type(value) is not dict:
        raise CodecError()
    record = cast(dict[str, object], value)
    fields = {"schema_id", "schema_version", "owner_identity", "approved_at"}
    fields.update(digest_fields)
    if window:
        fields.update({"not_before", "expires_at", "revoked", "action"})
    if record.keys() != fields:
        raise CodecError()
    if record["schema_id"] != family or record["schema_version"] != "1.0":
        raise CodecError()
    for field in digest_fields:
        digest = record[field]
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise CodecError()
    owner = record["owner_identity"]
    if not isinstance(owner, str) or not owner.isascii():
        raise CodecError()
    timestamps = ("approved_at", "not_before", "expires_at") if window else (
        "approved_at",
    )
    for field in timestamps:
        timestamp = record[field]
        if type(timestamp) is not int or timestamp < 0:
            raise CodecError()
    if window and (
        type(record["revoked"]) is not bool or record["action"] != "install-candidate"
    ):
        raise CodecError()
    return record


def read_install_approval(payload: bytes, *, byte_cap: int) -> dict[str, object]:
    """Decode structural IA1.0 only; no source/window or install permission check."""
    return _approval_leaf(
        _strict_json(payload, byte_cap), family="privacyagents.install-approval",
        digest_fields=("engine_manifest_digest", "destination_digest"), window=True,
    )


def canonical_install_approval(payload: bytes, *, byte_cap: int) -> bytes:
    """Encode all ten checked IA fields without normalization or exclusions."""
    return _canonical_json(read_install_approval(payload, byte_cap=byte_cap))


def install_approval_digest(payload: bytes, *, byte_cap: int) -> str:
    """Hash structural IA fields; this digest does not approve installation."""
    return "sha256:" + hashlib.sha256(
        canonical_install_approval(payload, byte_cap=byte_cap)
    ).hexdigest()


def read_host_admission(payload: bytes, *, byte_cap: int) -> dict[str, object]:
    """Decode structural HA1.0 only; no actual host probe or admission is performed."""
    return _approval_leaf(
        _strict_json(payload, byte_cap), family="privacyagents.host-admission",
        digest_fields=("host_plan_digest", "probe_receipt_digest"), window=False,
    )


def canonical_host_admission(payload: bytes, *, byte_cap: int) -> bytes:
    """Encode all six checked HA fields without normalization or exclusions."""
    return _canonical_json(read_host_admission(payload, byte_cap=byte_cap))


def host_admission_digest(payload: bytes, *, byte_cap: int) -> str:
    """Hash structural HA fields; this digest does not prove host capability."""
    return "sha256:" + hashlib.sha256(
        canonical_host_admission(payload, byte_cap=byte_cap)
    ).hexdigest()


_CORE_DIGEST_FIELDS = (
    "run_origin_digest", "engine_manifest_digest", "installation_receipt_digest",
    "host_admission_digest", "target_profile_digest", "mandate_record_digest",
    "mandate_authority_digest", "runtime_adapter_digest", "approved_plans_digest",
)
_CORE_PROFILES = frozenset({
    "planning", "wait", "quota", "continuation", "learning", "final_preparation",
})
_CORE_FIELDS = frozenset(_CORE_DIGEST_FIELDS) | {
    "schema_id", "schema_version", "feature_profiles",
}


def _runtime_core_shape(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise CodecError()
    record = cast(dict[str, object], value)
    if record.keys() != _CORE_FIELDS:
        raise CodecError()
    if (
        record["schema_id"] != "privacyagents.runtime-core"
        or record["schema_version"] != "1.0"
    ):
        raise CodecError()
    for field in _CORE_DIGEST_FIELDS:
        digest = record[field]
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise CodecError()
    profiles = record["feature_profiles"]
    if type(profiles) is not dict:
        raise CodecError()
    features = cast(dict[str, object], profiles)
    if features.keys() != _CORE_PROFILES or any(
        value is not None for value in features.values()
    ):
        raise CodecError()
    return record


def read_runtime_core(payload: bytes, *, byte_cap: int) -> dict[str, object]:
    """Decode structural RC1.0 only; no pointed source or runtime is validated."""
    return _runtime_core_shape(_strict_json(payload, byte_cap))


def canonical_runtime_core(payload: bytes, *, byte_cap: int) -> bytes:
    """Encode nine checked pointers and the mandatory six-null feature map."""
    return _canonical_json(read_runtime_core(payload, byte_cap=byte_cap))


def runtime_core_digest(payload: bytes, *, byte_cap: int) -> str:
    """Hash structural RC fields; no source/authority/readiness proof is implied."""
    return "sha256:" + hashlib.sha256(
        canonical_runtime_core(payload, byte_cap=byte_cap)
    ).hexdigest()
