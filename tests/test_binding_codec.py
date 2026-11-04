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
    activation_digest,
    binding_intent_digest,
    canonical_activation,
    canonical_binding_intent,
    canonical_host_admission,
    canonical_install_approval,
    canonical_launch_approval,
    canonical_runtime_core,
    check_envelope_consistency,
    host_admission_digest,
    install_approval_digest,
    launch_approval_digest,
    read_activation,
    read_binding_intent,
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


def fixture_D(symbol: str) -> bytes:
    return b"sha256:" + symbol.encode("ascii") * 64


def literal_H(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


SPINE_RC = (
    b'{"approved_plans_digest":"' + fixture_D("8")
    + b'","engine_manifest_digest":"' + fixture_D("1")
    + b'","feature_profiles":{"continuation":null,"final_preparation":null,'
    b'"learning":null,"planning":null,"quota":null,"wait":null},'
    b'"host_admission_digest":"' + fixture_D("3")
    + b'","installation_receipt_digest":"' + fixture_D("2")
    + b'","mandate_authority_digest":"' + fixture_D("6")
    + b'","mandate_record_digest":"' + fixture_D("5")
    + b'","run_origin_digest":"' + fixture_D("0")
    + b'","runtime_adapter_digest":"' + fixture_D("7")
    + b'","schema_id":"privacyagents.runtime-core","schema_version":"1.0",'
    b'"target_profile_digest":"' + fixture_D("4") + b'"}'
)
SPINE_BI = (
    b'{"authority":{"control_namespace_digest":"' + fixture_D("c")
    + b'","mandate_authority_digest":"' + fixture_D("6")
    + b'","mandate_record_digest":"' + fixture_D("5")
    + b'","owner_identity":"fixture-untrusted-owner",'
    b'"revocation_namespace_digest":"' + fixture_D("d")
    + b'","run_origin_digest":"' + fixture_D("0")
    + b'"},"engine":{"manifest_digest":"' + fixture_D("1")
    + b'","repository":"Fixture.Engine/repo_name","source_sha":"' + b"a" * 40
    + b'","source_tree":"' + b"b" * 40
    + b'"},"installation":{"destination_digest":"' + fixture_D("9")
    + b'","host_admission_digest":"' + fixture_D("3")
    + b'","installation_id":"install-\xc3\xa9","interpreter_digest":"'
    + fixture_D("a") + b'","receipt_digest":"' + fixture_D("2")
    + b'","toolchain_digest":"' + fixture_D("b")
    + b'"},"runtime_core_digest":"' + literal_H(SPINE_RC).encode("ascii")
    + b'","schema_id":"privacyagents.binding-intent","schema_version":"1.0",'
    b'"target":{"epic":1,"initial_base_sha":"' + b"c" * 40
    + b'","initial_head_sha":"' + b"d" * 40 + b'","policy_sha":"' + b"e" * 40
    + b'","profile_digest":"' + fixture_D("4")
    + b'","repository":"./..","roadmap_ref":" \\t"}}'
)
SPINE_LA = (
    b'{"action":"launch-bound-synthetic-run","approved_at":2,'
    b'"binding_intent_digest":"' + literal_H(SPINE_BI).encode("ascii")
    + b'","expires_at":8,"not_before":1,'
    b'"owner_identity":"fixture-untrusted-owner","revoked":false,'
    b'"schema_id":"privacyagents.launch-approval","schema_version":"1.0"}'
)
SPINE_AW = (
    b'{"binding_intent_digest":"' + literal_H(SPINE_BI).encode("ascii")
    + b'","launch_approval_digest":"' + literal_H(SPINE_LA).encode("ascii")
    + b'","run_id":"run-\xc3\xa9","runtime_core_digest":"'
    + literal_H(SPINE_RC).encode("ascii")
    + b'","schema_id":"privacyagents.activation","schema_version":"1.0"}'
)
BI_SLOTS = {
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
SpineData = tuple[
    dict[str, object], dict[str, object], dict[str, object], dict[str, object]
]


def spine_data() -> SpineData:
    return (
        cast(dict[str, object], json.loads(SPINE_RC)),
        cast(dict[str, object], json.loads(SPINE_BI)),
        cast(dict[str, object], json.loads(SPINE_LA)),
        cast(dict[str, object], json.loads(SPINE_AW)),
    )


def bi_group(value: dict[str, object], group: str) -> dict[str, object]:
    return cast(dict[str, object], value[group])


def envelope_operations(family: str) -> tuple[Callable[..., object], ...]:
    if family == "BI":
        return (read_binding_intent, canonical_binding_intent, binding_intent_digest)
    return (read_activation, canonical_activation, activation_digest)


def reject_envelope_record(family: str, payload: bytes) -> None:
    for operation in envelope_operations(family):
        with pytest.raises(CodecError) as error:
            operation(payload, byte_cap=len(payload) + 1)
        assert str(error.value) == "Invalid binding record"
        assert error.value.__context__ is None
        assert error.value.__cause__ is None


def check_spine(data: SpineData) -> None:
    r, b, la, a = (raw(record) for record in data)
    checker: Callable[..., object] = check_envelope_consistency
    result = checker(r, b, la, a, byte_cap=max(map(len, (r, b, la, a))))
    assert result is None


def fixture_hash(value: dict[str, object]) -> str:
    """Build mutated INPUT pointers only; wire golden oracles above are literals."""
    data = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return literal_H(data.encode("utf-8"))


def rebind_fixture(data: SpineData, *, bind_la: bool = True) -> None:
    r, b, la, a = data
    if bind_la:
        la["binding_intent_digest"] = fixture_hash(b)
    a["runtime_core_digest"] = fixture_hash(r)
    a["binding_intent_digest"] = fixture_hash(b)
    a["launch_approval_digest"] = fixture_hash(la)


def fixture_join_oracles(data: SpineData) -> list[bool]:
    r, b, la, a = data
    engine = bi_group(b, "engine")
    installation = bi_group(b, "installation")
    target = bi_group(b, "target")
    authority = bi_group(b, "authority")
    return [
        b["runtime_core_digest"] == fixture_hash(r),
        r["engine_manifest_digest"] == engine["manifest_digest"],
        r["installation_receipt_digest"] == installation["receipt_digest"],
        r["host_admission_digest"] == installation["host_admission_digest"],
        r["target_profile_digest"] == target["profile_digest"],
        r["mandate_record_digest"] == authority["mandate_record_digest"],
        r["mandate_authority_digest"] == authority["mandate_authority_digest"],
        r["run_origin_digest"] == authority["run_origin_digest"],
        la["binding_intent_digest"] == fixture_hash(b),
        a["runtime_core_digest"] == fixture_hash(r),
        a["binding_intent_digest"] == fixture_hash(b),
        a["launch_approval_digest"] == fixture_hash(la),
    ]


@pytest.mark.parametrize(("family", "expected"), [("BI", SPINE_BI), ("AW", SPINE_AW)])
def test_envelope_independent_canonical_literals(family: str, expected: bytes) -> None:
    read, canonical, digest = envelope_operations(family)
    value = cast(dict[str, object], json.loads(expected))
    payload = raw(dict(reversed(list(value.items()))))
    assert read(payload, byte_cap=len(payload)) == value
    assert canonical(payload, byte_cap=len(payload)) == expected
    assert digest(payload, byte_cap=len(payload)) == literal_H(expected)


def test_explicit_acyclic_spine_is_only_data_consistency() -> None:
    data = spine_data()
    assert all(fixture_join_oracles(data))
    check_spine(data)


@pytest.mark.parametrize("field", (
    "schema_id", "schema_version", "runtime_core_digest",
    "engine", "installation", "target", "authority",
))
def test_bi_missing_top_key(field: str) -> None:
    _, b, _, _ = spine_data()
    del b[field]
    reject_envelope_record("BI", raw(b))


@pytest.mark.parametrize(("group", "field"), [
    (group, field) for group, fields in BI_SLOTS.items() for field in fields
])
def test_bi_missing_nested_key(group: str, field: str) -> None:
    _, b, _, _ = spine_data()
    del bi_group(b, group)[field]
    reject_envelope_record("BI", raw(b))


@pytest.mark.parametrize("group", [None, *BI_SLOTS])
@pytest.mark.parametrize("extra", ["extra", "self_digest", "launch_approval_digest"])
def test_bi_closed_objects(group: str | None, extra: str) -> None:
    _, b, _, _ = spine_data()
    target = b if group is None else bi_group(b, group)
    target[extra] = "synthetic-invalid-marker"
    reject_envelope_record("BI", raw(b))


@pytest.mark.parametrize("group", BI_SLOTS)
@pytest.mark.parametrize("value", [None, False, [], "", 0])
def test_bi_nested_group_requires_object(group: str, value: object) -> None:
    _, b, _, _ = spine_data()
    b[group] = value
    reject_envelope_record("BI", raw(b))


@pytest.mark.parametrize("field", (
    "schema_id", "schema_version", "run_id", "runtime_core_digest",
    "binding_intent_digest", "launch_approval_digest",
))
def test_aw_missing_key(field: str) -> None:
    _, _, _, a = spine_data()
    del a[field]
    reject_envelope_record("AW", raw(a))


@pytest.mark.parametrize("family", ["BI", "AW"])
@pytest.mark.parametrize("field", [
    "self_digest", "activation_digest", "current_head_sha", "state_anchor_digest",
])
def test_envelope_rejects_mutable_or_cyclic_extra(family: str, field: str) -> None:
    _, b, _, a = spine_data()
    value = b if family == "BI" else a
    value[field] = "sha256:" + "f" * 64
    reject_envelope_record(family, raw(value))


INVALID_BY_TYPE: dict[str, list[object]] = {
    "D": [None, True, 0, "a" * 64, "sha256:" + "a" * 63,
          "sha256:" + "A" * 64, "sha256:" + "g" * 64],
    "G": [None, True, 0, "a" * 39, "a" * 41, "A" * 40, "g" * 40],
    "I": [None, False, 0, "", "nul\0id", "\ud800"],
    "R": [None, False, 0, "", "/repo", "owner/", "o/r/x", "\u00e9/repo", "o/r x"],
    "E": [None, True, False, 0, -1, 1.0, "1"],
    "O": [None, True, 0, "non-ascii-\u00e9", "nul\0owner"],
}


@pytest.mark.parametrize(("group", "field", "value"), [
    (group, field, value) for group, fields in BI_SLOTS.items()
    for field, kind in fields.items() for value in INVALID_BY_TYPE[kind]
])
def test_each_bi_typed_slot(group: str, field: str, value: object) -> None:
    _, b, _, _ = spine_data()
    bi_group(b, group)[field] = value
    reject_envelope_record("BI", raw(b))


@pytest.mark.parametrize(("family", "field", "value"), [
    ("BI", "runtime_core_digest", value) for value in INVALID_BY_TYPE["D"]
] + [
    ("AW", field, value) for field in (
        "runtime_core_digest", "binding_intent_digest", "launch_approval_digest"
    ) for value in INVALID_BY_TYPE["D"]
] + [("AW", "run_id", value) for value in INVALID_BY_TYPE["I"]])
def test_each_envelope_top_typed_slot(family: str, field: str, value: object) -> None:
    _, b, _, a = spine_data()
    changed = b if family == "BI" else a
    changed[field] = value
    reject_envelope_record(family, raw(changed))


@pytest.mark.parametrize("family", ["BI", "AW"])
@pytest.mark.parametrize(("field", "value"), [
    ("schema_id", "unknown-family"), ("schema_id", "privacyagents.entry-result"),
    ("schema_id", None), ("schema_version", "2.0"), ("schema_version", 1),
    ("schema_version", True), ("schema_version", None),
])
def test_envelope_exact_family_version(family: str, field: str, value: object) -> None:
    _, b, _, a = spine_data()
    changed = b if family == "BI" else a
    changed[field] = value
    reject_envelope_record(family, raw(changed))


@pytest.mark.parametrize("identity", [" ", "\t\n", "MiXeD", "\u00e9", "e\u0301"])
def test_approved_I_and_ref_boundaries_preserved(identity: str) -> None:
    _, b, _, a = spine_data()
    bi_group(b, "installation")["installation_id"] = identity
    bi_group(b, "target")["roadmap_ref"] = identity
    a["run_id"] = identity
    payload_b, payload_a = raw(b), raw(a)
    decoded = read_binding_intent(payload_b, byte_cap=len(payload_b))
    assert bi_group(decoded, "installation")["installation_id"] == identity
    assert bi_group(decoded, "target")["roadmap_ref"] == identity
    assert read_activation(payload_a, byte_cap=len(payload_a))["run_id"] == identity


@pytest.mark.parametrize("repository", ["./..", "Dot.Owner/repo_name-1", "../."])
def test_repository_lexical_shape_is_not_actual_Git(repository: str) -> None:
    _, b, _, _ = spine_data()
    bi_group(b, "engine")["repository"] = repository
    bi_group(b, "target")["repository"] = repository
    payload = raw(b)
    decoded = read_binding_intent(payload, byte_cap=len(payload))
    assert bi_group(decoded, "target")["repository"] == repository


def test_O_keeps_existing_ASCII_boundary_independent_of_I() -> None:
    _, b, _, _ = spine_data()
    bi_group(b, "authority")["owner_identity"] = ""
    payload = raw(b)
    decoded = read_binding_intent(payload, byte_cap=len(payload))
    assert bi_group(decoded, "authority")["owner_identity"] == ""


def test_unicode_I_has_no_normalization_in_canonical_bytes() -> None:
    _, b, _, a = spine_data()
    payload = raw(b)
    assert canonical_binding_intent(payload, byte_cap=len(payload)) == SPINE_BI
    bi_group(b, "installation")["installation_id"] = "install-e\u0301"
    decomposed = raw(b)
    expected = SPINE_BI.replace(b"install-\xc3\xa9", b"install-e\xcc\x81")
    assert canonical_binding_intent(decomposed, byte_cap=len(decomposed)) == expected
    assert binding_intent_digest(decomposed, byte_cap=len(decomposed)) == (
        literal_H(expected)
    )
    assert literal_H(expected) != literal_H(SPINE_BI)
    a["run_id"] = "run-e\u0301"
    payload_a = raw(a)
    expected_a = SPINE_AW.replace(b"run-\xc3\xa9", b"run-e\xcc\x81")
    assert canonical_activation(payload_a, byte_cap=len(payload_a)) == expected_a
    assert activation_digest(payload_a, byte_cap=len(payload_a)) == (
        literal_H(expected_a)
    )


@pytest.mark.parametrize(("group", "field"), [
    (group, field) for group, fields in BI_SLOTS.items() for field in fields
])
def test_every_bi_nested_field_participates_in_hash(group: str, field: str) -> None:
    _, b, _, _ = spine_data()
    kind = BI_SLOTS[group][field]
    value: object = {"D": "sha256:" + "f" * 64, "G": "f" * 40,
                     "I": "changed-I", "R": "changed/repo", "E": 2,
                     "O": "changed-owner"}[kind]
    bi_group(b, group)[field] = value
    payload = raw(b)
    assert binding_intent_digest(payload, byte_cap=len(payload)) != literal_H(SPINE_BI)


@pytest.mark.parametrize("field", (
    "run_id", "runtime_core_digest", "binding_intent_digest", "launch_approval_digest",
))
def test_every_aw_variable_field_participates_in_hash(field: str) -> None:
    _, _, _, a = spine_data()
    a[field] = "changed-I" if field == "run_id" else "sha256:" + "f" * 64
    payload = raw(a)
    assert activation_digest(payload, byte_cap=len(payload)) != literal_H(SPINE_AW)


@pytest.mark.parametrize("family", ["BI", "AW"])
@pytest.mark.parametrize("payload", [b"null", b"[]", b"0", b'"string"'])
def test_envelope_record_requires_object(family: str, payload: bytes) -> None:
    reject_envelope_record(family, payload)


@pytest.mark.parametrize(("family", "payload"), [
    ("BI", SPINE_BI[:-1] + b',"runtime_core_digest":"' + fixture_D("f") + b'"}'),
    ("BI", SPINE_BI.replace(b'"epic":1', b'"epic":1,"epic":2')),
    ("BI", SPINE_BI.replace(b'"epic":1', b'"epic":1,"\\u0065pic":1')),
    ("AW", SPINE_AW[:-1] + b',"run_id":"another"}'),
    ("AW", SPINE_AW[:-1] + b',"run_\\u0069d":"run-\xc3\xa9"}'),
])
def test_envelope_duplicate_known_key_valid_final_shape(family: str,
                                                       payload: bytes) -> None:
    reject_envelope_record(family, payload)


@pytest.mark.parametrize(("family", "other"), [
    (family, other) for family in ("BI", "AW")
    for other in ("LA", "IA", "HA", "RC", "BI", "AW") if family != other
])
def test_new_expected_family_slots_are_closed(family: str, other: str) -> None:
    payload = {"LA": SPINE_LA, "IA": INSTALL_EXPECTED, "HA": HOST_EXPECTED,
               "RC": SPINE_RC, "BI": SPINE_BI, "AW": SPINE_AW}[other]
    reject_envelope_record(family, payload)


@pytest.mark.parametrize(("group", "field"), [
    ("engine", "manifest_digest"), ("installation", "installation_id"),
    ("target", "epic"), ("authority", "owner_identity"),
])
def test_each_bi_group_rejects_duplicate_valid_known_key(
    group: str, field: str,
) -> None:
    _, b, _, _ = spine_data()
    original = raw(bi_group(b, group))
    member = raw({field: bi_group(b, group)[field]})[1:-1]
    duplicated = original[:-1] + b"," + member + b"}"
    payload = raw(b).replace(original, duplicated, 1)
    reject_envelope_record("BI", payload)


def test_bi_runtime_core_pointer_participates_in_hash() -> None:
    _, b, _, _ = spine_data()
    b["runtime_core_digest"] = "sha256:" + "f" * 64
    payload = raw(b)
    assert binding_intent_digest(payload, byte_cap=len(payload)) != literal_H(SPINE_BI)


@pytest.mark.parametrize("payload", [SPINE_BI, SPINE_AW])
def test_existing_family_entries_do_not_accept_new_families(payload: bytes) -> None:
    reject(payload)
    reject_leaf("install", payload)
    reject_leaf("host", payload)
    reject_core(payload)


@pytest.mark.parametrize("join", range(1, 13))
def test_each_of_twelve_joins_fails_independently(join: int) -> None:
    data = spine_data()
    _, b, la, a = data
    other = "sha256:" + "f" * 64
    if join == 1:
        b["runtime_core_digest"] = other
    elif 2 <= join <= 8:
        group, field = (
            ("engine", "manifest_digest"), ("installation", "receipt_digest"),
            ("installation", "host_admission_digest"), ("target", "profile_digest"),
            ("authority", "mandate_record_digest"),
            ("authority", "mandate_authority_digest"),
            ("authority", "run_origin_digest"),
        )[join - 2]
        bi_group(b, group)[field] = other
    elif join == 9:
        la["binding_intent_digest"] = other
    rebind_fixture(data, bind_la=join != 9)
    if join >= 10:
        a[("runtime_core_digest", "binding_intent_digest",
           "launch_approval_digest")[join - 10]] = other
    expected = [True] * 12
    expected[join - 1] = False
    assert fixture_join_oracles(data) == expected
    with pytest.raises(CodecError):
        check_spine(data)


def test_same_named_full_MD_and_legacy_A_slots_are_not_swapped() -> None:
    data = spine_data()
    r, b, _, _ = data
    authority = bi_group(b, "authority")
    authority["mandate_record_digest"], authority["mandate_authority_digest"] = (
        authority["mandate_authority_digest"], authority["mandate_record_digest"]
    )
    rebind_fixture(data)
    with pytest.raises(CodecError):
        check_spine(data)
    r["mandate_record_digest"], r["mandate_authority_digest"] = (
        r["mandate_authority_digest"], r["mandate_record_digest"]
    )
    b["runtime_core_digest"] = fixture_hash(r)
    rebind_fixture(data)
    check_spine(data)  # Pure consistency still cannot prove either typed source.


def test_forged_revoked_expired_different_run_spine_is_not_authority() -> None:
    data = spine_data()
    _, _, la, a = data
    la.update(approved_at=9, not_before=10, expires_at=0, revoked=True)
    a["run_id"] = "different-from-intended-run"
    rebind_fixture(data)
    check_spine(data)
    # No trusted expectedLA/owner/RO/source exists; successful None grants no effect.


@pytest.mark.parametrize("slot", range(4))
def test_pure_checker_requires_exact_family_in_each_slot(slot: int) -> None:
    values = [SPINE_RC, SPINE_BI, SPINE_LA, SPINE_AW]
    values[slot] = values[(slot + 1) % 4]
    r, b, la, a = values
    with pytest.raises(CodecError):
        check_envelope_consistency(r, b, la, a, byte_cap=max(map(len, values)))


def test_new_entries_and_checker_require_explicit_bytecap() -> None:
    for family, payload in (("BI", SPINE_BI), ("AW", SPINE_AW)):
        for operation in envelope_operations(family):
            with pytest.raises(TypeError):
                operation(payload)
            with pytest.raises(CodecError):
                operation(payload, byte_cap=False)
            with pytest.raises(CodecError):
                operation(payload, byte_cap=len(payload) - 1)
    unsafe_check = cast(Callable[..., object], check_envelope_consistency)
    with pytest.raises(TypeError):
        unsafe_check(SPINE_RC, SPINE_BI, SPINE_LA, SPINE_AW)
    with pytest.raises(CodecError):
        unsafe_check(SPINE_RC, SPINE_BI, SPINE_LA, SPINE_AW, byte_cap=False)
    with pytest.raises(CodecError):
        unsafe_check(SPINE_RC, SPINE_BI, SPINE_LA, SPINE_AW,
                     byte_cap=len(SPINE_AW) - 1)
