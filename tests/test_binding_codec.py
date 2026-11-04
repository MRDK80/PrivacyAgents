"""Structural codec vectors; no fixture represents authority to launch."""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Callable
from typing import cast

import pytest
from tools.binding_codec import (
    CodecError,
    _canonical_json,
    _strict_json,
    canonical_host_admission,
    canonical_install_approval,
    canonical_launch_approval,
    canonical_runtime_core,
    host_admission_digest,
    install_approval_digest,
    launch_approval_digest,
    read_host_admission,
    read_install_approval,
    read_launch_approval,
    read_runtime_core,
    runtime_core_digest,
)

EXPECTED = (
    b'{"action":"launch-bound-synthetic-run","approved_at":2,'
    b'"binding_intent_digest":"sha256:' + b"a" * 64
    + b'","expires_at":8,"not_before":1,"owner_identity":"fixture-owner",'
    b'"revoked":false,"schema_id":"privacyagents.launch-approval",'
    b'"schema_version":"1.0"}'
)
FIELDS = (
    "action", "approved_at", "binding_intent_digest", "expires_at", "not_before",
    "owner_identity", "revoked", "schema_id", "schema_version",
)


def record() -> dict[str, object]:
    return {
        "schema_id": "privacyagents.launch-approval",
        "schema_version": "1.0",
        "binding_intent_digest": "sha256:" + "a" * 64,
        "owner_identity": "fixture-owner",
        "approved_at": 2,
        "not_before": 1,
        "expires_at": 8,
        "revoked": False,
        "action": "launch-bound-synthetic-run",
    }


def raw(value: object) -> bytes:
    return json.dumps(value).encode("utf-8")


def reject(payload: bytes) -> None:
    for operation in (read_launch_approval, canonical_launch_approval,
                      launch_approval_digest):
        with pytest.raises(CodecError) as error:
            operation(payload, byte_cap=len(payload) + 1)
        assert str(error.value) == "Invalid binding record"
        assert repr(error.value) == "CodecError('Invalid binding record')"
        assert error.value.__context__ is None
        assert error.value.__cause__ is None


def test_independent_canonical_vector() -> None:
    payload = raw(record())
    assert read_launch_approval(payload, byte_cap=len(payload)) == record()
    assert canonical_launch_approval(payload, byte_cap=len(payload)) == EXPECTED
    assert launch_approval_digest(payload, byte_cap=len(payload)) == (
        "sha256:" + hashlib.sha256(EXPECTED).hexdigest()
    )


@pytest.mark.parametrize("payload", [
    EXPECTED,
    b"\r\n  " + EXPECTED + b"\r\n",
    raw(dict(reversed(list(record().items())))),
    raw(record()).replace(b"fixture-owner", b"fixture-\\u006fwner"),
])
def test_equivalent_json_has_same_semantic_digest(payload: bytes) -> None:
    assert canonical_launch_approval(payload, byte_cap=len(payload)) == EXPECTED
    assert launch_approval_digest(payload, byte_cap=len(payload)) == (
        "sha256:" + hashlib.sha256(EXPECTED).hexdigest()
    )


@pytest.mark.parametrize("field", FIELDS)
def test_missing_field(field: str) -> None:
    value = record()
    del value[field]
    reject(raw(value))


@pytest.mark.parametrize("field", ["extra", "self_digest", "launch_approval_digest"])
def test_unknown_field(field: str) -> None:
    value = record()
    value[field] = "synthetic-invalid-marker"
    reject(raw(value))


@pytest.mark.parametrize(("field", "value"), [
    ("schema_id", "privacyagents.activation"),
    ("schema_id", "unknown-family"), ("schema_id", None),
    ("schema_version", "2.0"), ("schema_version", 1),
    ("schema_version", True), ("action", "other-action"),
    ("action", 1), ("action", True),
])
def test_fixed_tags(field: str, value: object) -> None:
    changed = record()
    changed[field] = value
    reject(raw(changed))


@pytest.mark.parametrize("value", [
    "a" * 64, "sha256:" + "a" * 63, "sha256:" + "a" * 65,
    "sha256:" + "A" * 64, "sha256:" + "g" * 64,
    "sha512:" + "a" * 64, 0, None, True,
])
def test_digest_shape(value: object) -> None:
    changed = record()
    changed["binding_intent_digest"] = value
    reject(raw(changed))


@pytest.mark.parametrize("field", ["approved_at", "not_before", "expires_at"])
@pytest.mark.parametrize("value", [-1, 1.0, True, False, None, "1"])
def test_integer_fields(field: str, value: object) -> None:
    changed = record()
    changed[field] = value
    reject(raw(changed))


@pytest.mark.parametrize("value", [0, 1, "false", None, []])
def test_exact_boolean(value: object) -> None:
    changed = record()
    changed["revoked"] = value
    reject(raw(changed))


@pytest.mark.parametrize("value", [0, None, True, "non-ascii-\u00e9", "nul\0owner"])
def test_owner_type_and_encoding(value: object) -> None:
    changed = record()
    changed["owner_identity"] = value
    reject(raw(changed))


@pytest.mark.parametrize("owner", ["", "  owner  ", "MiXeD", "owner/name"])
def test_ascii_owner_is_preserved_without_invented_syntax(owner: str) -> None:
    changed = record()
    changed["owner_identity"] = owner
    payload = raw(changed)
    decoded = read_launch_approval(payload, byte_cap=len(payload))
    assert decoded["owner_identity"] == owner


@pytest.mark.parametrize(("field", "value"), [
    ("binding_intent_digest", "sha256:" + "b" * 64),
    ("owner_identity", "another-owner"), ("approved_at", 3),
    ("not_before", 0), ("expires_at", 9), ("revoked", True),
])
def test_every_variable_field_participates_in_digest(field: str, value: object) -> None:
    changed = record()
    changed[field] = value
    payload = raw(changed)
    encoded = canonical_launch_approval(payload, byte_cap=len(payload))
    assert encoded != EXPECTED
    assert launch_approval_digest(payload, byte_cap=len(payload)) != (
        "sha256:" + hashlib.sha256(EXPECTED).hexdigest()
    )


def test_structural_result_does_not_enforce_lifecycle_or_owner_authority() -> None:
    changed = record()
    changed.update(revoked=True, approved_at=99, not_before=100, expires_at=0,
                   owner_identity="untrusted-fixture")
    payload = raw(changed)
    assert read_launch_approval(payload, byte_cap=len(payload)) == changed


@pytest.mark.parametrize("payload", [
    b"null", b"[]", b"1", b'"synthetic-invalid-marker"', b"true",
    b"\xffsynthetic-invalid-marker", b'{"synthetic-invalid-marker":',
    EXPECTED + b" trailing", b'{"x":1,"x":1}', b'{"x":1,"x":2}',
    b'{"x":1,"\\u0078":2}', b'{"nested":{"x":1,"x":2}}',
    b'{"nested":[{"x":1,"x":2}]}', b'{"x":1.5}', b'{"x":1e2}',
    b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}',
    b'{"nested":[0.5]}', b'{"nul\\u0000key":1}', b'{"x":"nul\\u0000"}',
    b'{"x":"\\ud800"}', b'{"\\udfff":1}',
])
def test_strict_json_and_safe_errors(payload: bytes) -> None:
    reject(payload)


@pytest.mark.parametrize("duplicate", [
    b',"approved_at":2}',
    b',"approved_at":3}',
    b',"appr\\u006fved_at":3}',
])
def test_duplicate_known_fields_in_supported_family(duplicate: bytes) -> None:
    # Without duplicate rejection each vector would retain a valid LA shape.
    reject(EXPECTED[:-1] + duplicate)


@pytest.mark.parametrize("payload", [
    b'{"nested":{"x":1,"x":1}}',
    b'{"nested":[{"x":1,"x":2}]}',
    b'{"x":1,"\\u0078":2}',
    b"1.5", b"1e2", b"NaN", b"Infinity", b"-Infinity",
    b'{"nested":[0.5]}', b'{"nested":{"x":1e2}}',
    b'{"nested":[NaN]}', b'{"nested":{"x":Infinity}}',
    b'{"nul\\u0000key":1}', b'{"x":"nul\\u0000"}',
    b'{"x":"\\ud800"}', b'{"\\udfff":1}',
])
def test_parser_rejections_independent_of_record_shape(payload: bytes) -> None:
    # The plain JSON layer accepts objects/lists/scalars; LA shape cannot mask
    # disabled duplicate, number or Unicode checks in these parser vectors.
    with pytest.raises(CodecError) as error:
        _strict_json(payload, len(payload))
    assert str(error.value) == "Invalid binding record"
    assert error.value.__context__ is None
    assert error.value.__cause__ is None


def test_private_parser_accepts_plain_nested_json_without_la_shape() -> None:
    payload = b'{"nested":[{"x":1},"text",true,null]}'
    assert _strict_json(payload, len(payload)) == {
        "nested": [{"x": 1}, "text", True, None]
    }


@pytest.mark.parametrize("cap", [True, False, 0, -1, None, "1000", 1.5])
def test_invalid_cap(cap: object) -> None:
    with pytest.raises(CodecError):
        read_launch_approval(EXPECTED, byte_cap=cast(int, cap))


def test_bytecap_is_enforced_before_parsing() -> None:
    with pytest.raises(CodecError):
        read_launch_approval(EXPECTED, byte_cap=len(EXPECTED) - 1)
    with pytest.raises(CodecError):
        read_launch_approval(cast(bytes, "not-bytes"), byte_cap=100)


def test_private_canonical_encoding_preserves_unicode_and_string_whitespace() -> None:
    assert _canonical_json({"x": " \u00e9 "}) == b'{"x":" \xc3\xa9 "}'
    assert _canonical_json({"x": "e\u0301"}) == b'{"x":"e\xcc\x81"}'
    assert _canonical_json({"x": "\u00e9"}) != _canonical_json({"x": "e\u0301"})


def test_native_parser_limits_are_redacted_without_changing_them() -> None:
    recursion_limit = sys.getrecursionlimit()
    integer_limit = sys.get_int_max_str_digits()
    reject(b"[" * (recursion_limit + 1) + b"0" + b"]" * (recursion_limit + 1))
    if integer_limit:
        reject(b'{"synthetic-invalid-marker":' + b"1" * (integer_limit + 1) + b"}")
    assert sys.getrecursionlimit() == recursion_limit
    assert sys.get_int_max_str_digits() == integer_limit


@pytest.mark.parametrize("operation", [read_launch_approval, canonical_launch_approval,
                                       launch_approval_digest])
def test_cap_has_no_implicit_default(operation: Callable[..., object]) -> None:
    with pytest.raises(TypeError):
        operation(EXPECTED)


INSTALL_EXPECTED = (
    b'{"action":"install-candidate","approved_at":2,"destination_digest":"sha256:'
    + b"b" * 64 + b'","engine_manifest_digest":"sha256:' + b"a" * 64
    + b'","expires_at":8,"not_before":1,"owner_identity":"fixture-owner",'
    b'"revoked":false,"schema_id":"privacyagents.install-approval",'
    b'"schema_version":"1.0"}'
)
HOST_EXPECTED = (
    b'{"approved_at":2,"host_plan_digest":"sha256:' + b"c" * 64
    + b'","owner_identity":"fixture-owner","probe_receipt_digest":"sha256:'
    + b"d" * 64 + b'","schema_id":"privacyagents.host-admission",'
    b'"schema_version":"1.0"}'
)


def leaf_record(family: str) -> dict[str, object]:
    if family == "install":
        return {
            "schema_id": "privacyagents.install-approval",
            "schema_version": "1.0",
            "engine_manifest_digest": "sha256:" + "a" * 64,
            "destination_digest": "sha256:" + "b" * 64,
            "owner_identity": "fixture-owner", "approved_at": 2,
            "not_before": 1, "expires_at": 8, "revoked": False,
            "action": "install-candidate",
        }
    return {
        "schema_id": "privacyagents.host-admission", "schema_version": "1.0",
        "host_plan_digest": "sha256:" + "c" * 64,
        "probe_receipt_digest": "sha256:" + "d" * 64,
        "owner_identity": "fixture-owner", "approved_at": 2,
    }


def leaf_operations(family: str) -> tuple[
    Callable[..., dict[str, object]], Callable[..., bytes], Callable[..., str]
]:
    if family == "install":
        return (read_install_approval, canonical_install_approval,
                install_approval_digest)
    return (read_host_admission, canonical_host_admission, host_admission_digest)


def reject_leaf(family: str, payload: bytes) -> None:
    for operation in leaf_operations(family):
        with pytest.raises(CodecError) as error:
            operation(payload, byte_cap=len(payload) + 1)
        assert str(error.value) == "Invalid binding record"
        assert error.value.__context__ is None
        assert error.value.__cause__ is None


@pytest.mark.parametrize(("family", "expected"), [
    ("install", INSTALL_EXPECTED), ("host", HOST_EXPECTED),
])
def test_two_leaf_independent_vectors(family: str, expected: bytes) -> None:
    value = leaf_record(family)
    payload = raw(value)
    read, canonical, digest = leaf_operations(family)
    assert read(payload, byte_cap=len(payload)) == value
    assert canonical(payload, byte_cap=len(payload)) == expected
    assert digest(payload, byte_cap=len(payload)) == (
        "sha256:" + hashlib.sha256(expected).hexdigest()
    )


@pytest.mark.parametrize("family", ["install", "host"])
def test_leaf_equivalent_json(family: str) -> None:
    _, canonical, digest = leaf_operations(family)
    expected = INSTALL_EXPECTED if family == "install" else HOST_EXPECTED
    changed = dict(reversed(list(leaf_record(family).items())))
    payload = b"\r\n" + raw(changed).replace(b"fixture-owner", b"fixture-\\u006fwner")
    assert canonical(payload, byte_cap=len(payload)) == expected
    assert digest(payload, byte_cap=len(payload)) == (
        "sha256:" + hashlib.sha256(expected).hexdigest()
    )


@pytest.mark.parametrize(("family", "field"), [
    ("install", field) for field in (
        "schema_id", "schema_version", "engine_manifest_digest", "destination_digest",
        "owner_identity", "approved_at", "not_before", "expires_at",
        "revoked", "action",
    )
] + [
    ("host", field) for field in (
        "schema_id", "schema_version", "host_plan_digest", "probe_receipt_digest",
        "owner_identity", "approved_at",
    )
])
def test_leaf_missing_required_key(family: str, field: str) -> None:
    changed = leaf_record(family)
    del changed[field]
    reject_leaf(family, raw(changed))


@pytest.mark.parametrize("family", ["install", "host"])
@pytest.mark.parametrize("field", ["extra", "self_digest"])
def test_leaf_extra_key(family: str, field: str) -> None:
    changed = leaf_record(family)
    changed[field] = "synthetic-invalid-marker"
    reject_leaf(family, raw(changed))


@pytest.mark.parametrize("field", ["not_before", "expires_at", "revoked", "action"])
def test_host_is_not_an_install_approval_union(field: str) -> None:
    changed = leaf_record("host")
    changed[field] = leaf_record("install")[field]
    reject_leaf("host", raw(changed))


@pytest.mark.parametrize("family", ["install", "host"])
@pytest.mark.parametrize(("field", "value"), [
    ("schema_id", "privacyagents.activation"), ("schema_id", "unknown-family"),
    ("schema_id", None), ("schema_version", "2.0"),
    ("schema_version", True), ("schema_version", 1), ("schema_version", None),
    ("owner_identity", None), ("owner_identity", 1),
    ("owner_identity", "non-ascii-\u00e9"), ("owner_identity", "nul\0owner"),
])
def test_leaf_fixed_tags_and_owner(family: str, field: str, value: object) -> None:
    changed = leaf_record(family)
    changed[field] = value
    reject_leaf(family, raw(changed))


@pytest.mark.parametrize(("field", "value"), [
    ("action", "launch-bound-synthetic-run"), ("action", None),
    ("action", True), ("action", 1),
    ("revoked", 0), ("revoked", 1), ("revoked", None), ("revoked", "false"),
])
def test_install_action_and_exact_boolean(field: str, value: object) -> None:
    changed = leaf_record("install")
    changed[field] = value
    reject_leaf("install", raw(changed))


@pytest.mark.parametrize(("family", "field"), [
    ("install", "engine_manifest_digest"), ("install", "destination_digest"),
    ("host", "host_plan_digest"), ("host", "probe_receipt_digest"),
])
@pytest.mark.parametrize("value", [
    "a" * 64, "sha256:" + "a" * 63, "sha256:" + "a" * 65,
    "sha256:" + "A" * 64, "sha256:" + "g" * 64,
    "sha512:" + "a" * 64, None, 0,
])
def test_leaf_digest_fields(family: str, field: str, value: object) -> None:
    changed = leaf_record(family)
    changed[field] = value
    reject_leaf(family, raw(changed))


@pytest.mark.parametrize(("family", "field"), [
    ("install", "approved_at"), ("install", "not_before"),
    ("install", "expires_at"), ("host", "approved_at"),
])
@pytest.mark.parametrize("value", [-1, 1.0, True, False, None, "1"])
def test_leaf_timestamp_fields(family: str, field: str, value: object) -> None:
    changed = leaf_record(family)
    changed[field] = value
    reject_leaf(family, raw(changed))


@pytest.mark.parametrize("family", ["install", "host"])
@pytest.mark.parametrize("owner", ["", "  owner  ", "MiXeD", "owner/name"])
def test_leaf_owner_has_no_added_syntax(family: str, owner: str) -> None:
    changed = leaf_record(family)
    changed["owner_identity"] = owner
    payload = raw(changed)
    read, _, _ = leaf_operations(family)
    assert read(payload, byte_cap=len(payload))["owner_identity"] == owner


@pytest.mark.parametrize(("family", "field", "value"), [
    ("install", "engine_manifest_digest", "sha256:" + "e" * 64),
    ("install", "destination_digest", "sha256:" + "e" * 64),
    ("install", "owner_identity", "another-owner"),
    ("install", "approved_at", 3), ("install", "not_before", 0),
    ("install", "expires_at", 9), ("install", "revoked", True),
    ("host", "host_plan_digest", "sha256:" + "e" * 64),
    ("host", "probe_receipt_digest", "sha256:" + "e" * 64),
    ("host", "owner_identity", "another-owner"), ("host", "approved_at", 3),
])
def test_all_leaf_variable_fields_participate(family: str, field: str,
                                             value: object) -> None:
    changed = leaf_record(family)
    changed[field] = value
    payload = raw(changed)
    _, canonical, digest = leaf_operations(family)
    expected = INSTALL_EXPECTED if family == "install" else HOST_EXPECTED
    assert canonical(payload, byte_cap=len(payload)) != expected
    assert digest(payload, byte_cap=len(payload)) != (
        "sha256:" + hashlib.sha256(expected).hexdigest()
    )


@pytest.mark.parametrize("family", ["install", "host"])
@pytest.mark.parametrize("duplicate", [
    b',"approved_at":2}', b',"approved_at":3}', b',"appr\\u006fved_at":3}',
])
def test_leaf_duplicate_known_field(family: str, duplicate: bytes) -> None:
    expected = INSTALL_EXPECTED if family == "install" else HOST_EXPECTED
    reject_leaf(family, expected[:-1] + duplicate)


@pytest.mark.parametrize(("expected_family", "payload_family"), [
    ("install", "host"), ("host", "install"),
    ("install", "launch"), ("host", "launch"),
    ("launch", "install"), ("launch", "host"),
])
def test_expected_family_is_never_inferred_from_payload(expected_family: str,
                                                       payload_family: str) -> None:
    value = record() if payload_family == "launch" else leaf_record(payload_family)
    payload = raw(value)
    if expected_family == "launch":
        reject(payload)
    else:
        reject_leaf(expected_family, payload)


@pytest.mark.parametrize("family", ["install", "host"])
def test_leaf_structure_does_not_validate_context(family: str) -> None:
    changed = leaf_record(family)
    changed["owner_identity"] = "untrusted-fixture"
    changed["approved_at"] = 99
    if family == "install":
        changed.update(not_before=100, expires_at=0, revoked=True)
    payload = raw(changed)
    read, _, _ = leaf_operations(family)
    assert read(payload, byte_cap=len(payload)) == changed


@pytest.mark.parametrize("family", ["install", "host"])
@pytest.mark.parametrize("payload", [b"null", b"[]", b"0", b'"string"'])
def test_leaf_requires_object(family: str, payload: bytes) -> None:
    reject_leaf(family, payload)


@pytest.mark.parametrize("family", ["install", "host"])
def test_leaf_entries_require_explicit_valid_bytecap(family: str) -> None:
    payload = raw(leaf_record(family))
    for operation in leaf_operations(family):
        with pytest.raises(TypeError):
            operation(payload)
        with pytest.raises(CodecError):
            operation(payload, byte_cap=False)
        with pytest.raises(CodecError):
            operation(payload, byte_cap=len(payload) - 1)


CORE_DIGEST_FIELDS = (
    "run_origin_digest", "engine_manifest_digest", "installation_receipt_digest",
    "host_admission_digest", "target_profile_digest", "mandate_record_digest",
    "mandate_authority_digest", "runtime_adapter_digest", "approved_plans_digest",
)
CORE_PROFILES = (
    "planning", "wait", "quota", "continuation", "learning", "final_preparation",
)
CORE_EXPECTED = (
    b'{"approved_plans_digest":"sha256:' + b"a" * 64
    + b'","engine_manifest_digest":"sha256:' + b"b" * 64
    + b'","feature_profiles":{"continuation":null,"final_preparation":null,'
    b'"learning":null,"planning":null,"quota":null,"wait":null},'
    b'"host_admission_digest":"sha256:' + b"d" * 64
    + b'","installation_receipt_digest":"sha256:' + b"c" * 64
    + b'","mandate_authority_digest":"sha256:' + b"a" * 64
    + b'","mandate_record_digest":"sha256:' + b"f" * 64
    + b'","run_origin_digest":"sha256:' + b"a" * 64
    + b'","runtime_adapter_digest":"sha256:' + b"e" * 64
    + b'","schema_id":"privacyagents.runtime-core","schema_version":"1.0",'
    b'"target_profile_digest":"sha256:' + b"e" * 64 + b'"}'
)


def core_record() -> dict[str, object]:
    return {
        "schema_id": "privacyagents.runtime-core", "schema_version": "1.0",
        "run_origin_digest": "sha256:" + "a" * 64,
        "engine_manifest_digest": "sha256:" + "b" * 64,
        "installation_receipt_digest": "sha256:" + "c" * 64,
        "host_admission_digest": "sha256:" + "d" * 64,
        "target_profile_digest": "sha256:" + "e" * 64,
        "mandate_record_digest": "sha256:" + "f" * 64,
        "mandate_authority_digest": "sha256:" + "a" * 64,
        "runtime_adapter_digest": "sha256:" + "e" * 64,
        "approved_plans_digest": "sha256:" + "a" * 64,
        "feature_profiles": {
            "planning": None, "wait": None, "quota": None,
            "continuation": None, "learning": None, "final_preparation": None,
        },
    }


def reject_core(payload: bytes) -> None:
    for operation in (read_runtime_core, canonical_runtime_core, runtime_core_digest):
        with pytest.raises(CodecError) as error:
            operation(payload, byte_cap=len(payload) + 1)
        assert str(error.value) == "Invalid binding record"
        assert error.value.__context__ is None
        assert error.value.__cause__ is None


def test_core_independent_literal_and_hash_vector() -> None:
    payload = raw(core_record())
    assert read_runtime_core(payload, byte_cap=len(payload)) == core_record()
    assert canonical_runtime_core(payload, byte_cap=len(payload)) == CORE_EXPECTED
    assert runtime_core_digest(payload, byte_cap=len(payload)) == (
        "sha256:" + hashlib.sha256(CORE_EXPECTED).hexdigest()
    )


def test_core_equivalent_json_has_same_semantic_hash() -> None:
    changed = dict(reversed(list(core_record().items())))
    changed["feature_profiles"] = dict(reversed(list(
        cast(dict[str, object], changed["feature_profiles"]).items()
    )))
    payload = b"\r\n" + raw(changed).replace(b'"planning"', b'"plann\\u0069ng"')
    assert canonical_runtime_core(payload, byte_cap=len(payload)) == CORE_EXPECTED
    assert runtime_core_digest(payload, byte_cap=len(payload)) == (
        "sha256:" + hashlib.sha256(CORE_EXPECTED).hexdigest()
    )


@pytest.mark.parametrize("field", CORE_DIGEST_FIELDS)
def test_every_core_pointer_participates_in_hash(field: str) -> None:
    changed = core_record()
    changed[field] = "sha256:" + "0" * 64
    payload = raw(changed)
    assert canonical_runtime_core(payload, byte_cap=len(payload)) != CORE_EXPECTED
    assert runtime_core_digest(payload, byte_cap=len(payload)) != (
        "sha256:" + hashlib.sha256(CORE_EXPECTED).hexdigest()
    )


@pytest.mark.parametrize("field", CORE_DIGEST_FIELDS + (
    "schema_id", "schema_version", "feature_profiles",
))
def test_core_missing_top_level_field(field: str) -> None:
    changed = core_record()
    del changed[field]
    reject_core(raw(changed))


@pytest.mark.parametrize("field", [
    "extra", "self_digest", "binding_intent_digest", "launch_approval_digest",
    "activation_digest", "launch_control_digest", "state_anchor_digest",
    "owner_revocations_digest", "current_head_sha", "current_ledger_digest",
    "demo_result_digest",
])
def test_core_rejects_extra_and_backreference_fields(field: str) -> None:
    changed = core_record()
    changed[field] = "sha256:" + "a" * 64
    reject_core(raw(changed))


@pytest.mark.parametrize("field", CORE_DIGEST_FIELDS)
@pytest.mark.parametrize("value", [
    None, True, 0, "a" * 64, "sha256:" + "a" * 63,
    "sha256:" + "a" * 65, "sha256:" + "A" * 64, "sha256:" + "g" * 64,
    "sha512:" + "a" * 64,
])
def test_core_digest_fields(field: str, value: object) -> None:
    changed = core_record()
    changed[field] = value
    reject_core(raw(changed))


@pytest.mark.parametrize(("field", "value"), [
    ("schema_id", "privacyagents.activation"), ("schema_id", None),
    ("schema_id", True), ("schema_version", "2.0"),
    ("schema_version", 1), ("schema_version", True), ("schema_version", None),
])
def test_core_fixed_family_tags(field: str, value: object) -> None:
    changed = core_record()
    changed[field] = value
    reject_core(raw(changed))


@pytest.mark.parametrize("value", [None, False, True, 0, "", [], {}])
def test_core_profiles_require_closed_object(value: object) -> None:
    changed = core_record()
    changed["feature_profiles"] = value
    reject_core(raw(changed))


@pytest.mark.parametrize("profile", CORE_PROFILES)
def test_core_requires_each_explicit_null_profile(profile: str) -> None:
    changed = core_record()
    profiles = cast(dict[str, object], changed["feature_profiles"])
    del profiles[profile]
    reject_core(raw(changed))


@pytest.mark.parametrize("profile", CORE_PROFILES)
@pytest.mark.parametrize("value", [False, True, "", {}, [], {"profile": "enabled"}])
def test_core_cannot_enable_or_default_any_profile(profile: str, value: object) -> None:
    changed = core_record()
    profiles = cast(dict[str, object], changed["feature_profiles"])
    profiles[profile] = value
    reject_core(raw(changed))


def test_core_profile_map_has_no_unknown_key() -> None:
    changed = core_record()
    profiles = cast(dict[str, object], changed["feature_profiles"])
    profiles["unknown"] = None
    reject_core(raw(changed))


@pytest.mark.parametrize("duplicate", [
    b',"run_origin_digest":"sha256:' + b"a" * 64 + b'"}',
    b',"run_origin_digest":"sha256:' + b"0" * 64 + b'"}',
    b',"run_\\u006frigin_digest":"sha256:' + b"a" * 64 + b'"}',
])
def test_core_duplicate_top_level_known_field(duplicate: bytes) -> None:
    reject_core(CORE_EXPECTED[:-1] + duplicate)


@pytest.mark.parametrize("replacement", [
    b'"planning":null,"planning":null',
    b'"planning":false,"planning":null',
    b'"planning":null,"plann\\u0069ng":null',
])
def test_core_nested_duplicate_cannot_hide_behind_valid_final_shape(
    replacement: bytes,
) -> None:
    reject_core(CORE_EXPECTED.replace(b'"planning":null', replacement))


@pytest.mark.parametrize("payload", [b"null", b"[]", b"0", b'"string"'])
def test_core_requires_object(payload: bytes) -> None:
    reject_core(payload)


@pytest.mark.parametrize("family", ["launch", "install", "host"])
def test_core_and_leaf_entries_are_isolated(family: str) -> None:
    value = record() if family == "launch" else leaf_record(family)
    reject_core(raw(value))
    if family == "launch":
        reject(raw(core_record()))
    else:
        reject_leaf(family, raw(core_record()))


def test_core_entries_require_explicit_valid_bytecap() -> None:
    payload = raw(core_record())
    for operation in (read_runtime_core, canonical_runtime_core, runtime_core_digest):
        with pytest.raises(TypeError):
            cast(Callable[..., object], operation)(payload)
        with pytest.raises(CodecError):
            operation(payload, byte_cap=False)
        with pytest.raises(CodecError):
            operation(payload, byte_cap=len(payload) - 1)


def test_core_shape_does_not_establish_pointed_source_or_permission() -> None:
    # The fixture pointers name no source materialization/host/mandate. Parsing
    # only proves this record's shape; no runtime or source consumer is invoked.
    payload = raw(core_record())
    assert read_runtime_core(payload, byte_cap=len(payload)) == core_record()
