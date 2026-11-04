"""Repository-only structural binding codecs, never permission/lifecycle checks.

A returned record or digest does not authenticate its owner, resolve its source,
validate a time window, or authorize any effect. Only named LA/IA/HA/RC/BI/AW1.0
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


_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_GIT_OBJECT = re.compile(r"[0-9a-f]{40}\Z")
_INTENT_GROUPS = {
    "engine": {
        "repository": "R", "source_sha": "G", "source_tree": "G",
        "manifest_digest": "D",
    },
    "installation": {
        "installation_id": "I", "receipt_digest": "D", "destination_digest": "D",
        "interpreter_digest": "D", "toolchain_digest": "D",
        "host_admission_digest": "D",
    },
    "target": {
        "repository": "R", "epic": "E", "roadmap_ref": "I", "policy_sha": "G",
        "initial_base_sha": "G", "initial_head_sha": "G", "profile_digest": "D",
    },
    "authority": {
        "owner_identity": "O", "mandate_record_digest": "D",
        "mandate_authority_digest": "D", "run_origin_digest": "D",
        "control_namespace_digest": "D", "revocation_namespace_digest": "D",
    },
}
_INTENT_FIELDS = frozenset(_INTENT_GROUPS) | {
    "schema_id", "schema_version", "runtime_core_digest",
}
_ACTIVATION_FIELDS = frozenset({
    "schema_id", "schema_version", "run_id", "runtime_core_digest",
    "binding_intent_digest", "launch_approval_digest",
})


def _spine_scalar(value: object, kind: str) -> bool:
    """Finite structural primitives only; no source, Git or trust observation."""
    if kind == "E":
        return type(value) is int and value > 0
    if not isinstance(value, str):
        return False
    if kind == "D":
        return _DIGEST.fullmatch(value) is not None
    if kind == "G":
        return _GIT_OBJECT.fullmatch(value) is not None
    if kind == "R":
        return _REPOSITORY.fullmatch(value) is not None
    if kind == "I":
        return bool(value)
    if kind == "O":
        return value.isascii()
    return False


def _binding_intent_shape(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise CodecError()
    record = cast(dict[str, object], value)
    if record.keys() != _INTENT_FIELDS:
        raise CodecError()
    if (
        record["schema_id"] != "privacyagents.binding-intent"
        or record["schema_version"] != "1.0"
        or not _spine_scalar(record["runtime_core_digest"], "D")
    ):
        raise CodecError()
    for name, fields in _INTENT_GROUPS.items():
        group = record[name]
        if type(group) is not dict:
            raise CodecError()
        members = cast(dict[str, object], group)
        if members.keys() != fields.keys() or any(
            not _spine_scalar(members[field], kind) for field, kind in fields.items()
        ):
            raise CodecError()
    return record


def _activation_shape(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise CodecError()
    record = cast(dict[str, object], value)
    if record.keys() != _ACTIVATION_FIELDS:
        raise CodecError()
    if (
        record["schema_id"] != "privacyagents.activation"
        or record["schema_version"] != "1.0"
        or not _spine_scalar(record["run_id"], "I")
    ):
        raise CodecError()
    for field in (
        "runtime_core_digest", "binding_intent_digest", "launch_approval_digest"
    ):
        if not _spine_scalar(record[field], "D"):
            raise CodecError()
    return record


def read_binding_intent(payload: bytes, *, byte_cap: int) -> dict[str, object]:
    """Decode structural BI1.0; no actual source, owner or Git fact is checked."""
    return _binding_intent_shape(_strict_json(payload, byte_cap))


def canonical_binding_intent(payload: bytes, *, byte_cap: int) -> bytes:
    """Encode every closed BI field with exact codepoints and no exclusions."""
    return _canonical_json(read_binding_intent(payload, byte_cap=byte_cap))


def binding_intent_digest(payload: bytes, *, byte_cap: int) -> str:
    """Hash structural BI bytes; this digest confers no authority or readiness."""
    return "sha256:" + hashlib.sha256(
        canonical_binding_intent(payload, byte_cap=byte_cap)
    ).hexdigest()


def read_activation(payload: bytes, *, byte_cap: int) -> dict[str, object]:
    """Decode structural AW1.0; run identity and actual activation are unverified."""
    return _activation_shape(_strict_json(payload, byte_cap))


def canonical_activation(payload: bytes, *, byte_cap: int) -> bytes:
    """Encode all six checked AW fields, with no normalization or exclusions."""
    return _canonical_json(read_activation(payload, byte_cap=byte_cap))


def activation_digest(payload: bytes, *, byte_cap: int) -> str:
    """Hash structural AW bytes; no source or actual activation is established."""
    return "sha256:" + hashlib.sha256(
        canonical_activation(payload, byte_cap=byte_cap)
    ).hexdigest()


def check_envelope_consistency(
    runtime_core: bytes, binding_intent: bytes, launch_approval: bytes,
    activation: bytes, *, byte_cap: int,
) -> None:
    """Check twelve pointers among four supplied records, solely as data.

    None means partial data consistency, never a trusted binding or permission.
    No expected LA/owner, source kind/resolver, window/revocation, RO/run identity,
    Git, installation or host fact is validated. Forged or revoked/expired records
    can be consistent. No effect follows this pure check.
    """
    rc = read_runtime_core(runtime_core, byte_cap=byte_cap)
    bi = read_binding_intent(binding_intent, byte_cap=byte_cap)
    la = read_launch_approval(launch_approval, byte_cap=byte_cap)
    aw = read_activation(activation, byte_cap=byte_cap)
    rc_h = "sha256:" + hashlib.sha256(_canonical_json(rc)).hexdigest()
    bi_h = "sha256:" + hashlib.sha256(_canonical_json(bi)).hexdigest()
    la_h = "sha256:" + hashlib.sha256(_canonical_json(la)).hexdigest()
    engine = cast(dict[str, object], bi["engine"])
    installation = cast(dict[str, object], bi["installation"])
    target = cast(dict[str, object], bi["target"])
    authority = cast(dict[str, object], bi["authority"])
    if not all((
        bi["runtime_core_digest"] == rc_h,
        rc["engine_manifest_digest"] == engine["manifest_digest"],
        rc["installation_receipt_digest"] == installation["receipt_digest"],
        rc["host_admission_digest"] == installation["host_admission_digest"],
        rc["target_profile_digest"] == target["profile_digest"],
        rc["mandate_record_digest"] == authority["mandate_record_digest"],
        rc["mandate_authority_digest"] == authority["mandate_authority_digest"],
        rc["run_origin_digest"] == authority["run_origin_digest"],
        la["binding_intent_digest"] == bi_h,
        aw["runtime_core_digest"] == rc_h,
        aw["binding_intent_digest"] == bi_h,
        aw["launch_approval_digest"] == la_h,
    )):
        raise CodecError()
