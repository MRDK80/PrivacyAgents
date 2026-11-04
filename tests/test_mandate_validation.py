"""Synthetic legacy semantics; projection and lifecycle do not grant authority."""

import copy
import hashlib
from typing import Any

import pytest
from tools import mandate_validation as mandate


def document() -> dict[str, Any]:
    return {
        "schema_version": "3.0",
        "issued_at": 100,
        "expires_at": 1000,
        "owner_identity": "Fixture",
        "revoked": False,
        "limits": {
            "max_duration_seconds": 600,
            "max_task_iterations": 10,
            "max_follow_up_issues": 3,
        },
        "approval": {
            "mandate_digest": "synthetic unverified projection",
            "approved_by": "Fixture",
            "approved_at": 120,
        },
    }


def context(**changes: Any) -> mandate.MandateContext:
    values: dict[str, Any] = {
        "now": 200, "owner_identity": "Fixture", "started_at": 150,
        "task_iterations": 0, "follow_up_issues": 0,
    }
    return mandate.MandateContext(**(values | changes))


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"schema_version": "1.0"}, "MANDATE_SCHEMA_UNSUPPORTED"),
        ({"revoked": 0}, "MANDATE_INVALID"),
        ({"revoked": 1}, "MANDATE_INVALID"),
        ({"revoked": True}, "MANDATE_REVOKED"),
        ({"owner_identity": "Other"}, "MANDATE_OWNER_MISMATCH"),
        ({"owner_identity": ""}, "MANDATE_INVALID"),
        ({"issued_at": -1}, "MANDATE_INVALID"),
        ({"issued_at": 1000}, "MANDATE_INVALID"),
        ({"expires_at": 100}, "MANDATE_INVALID"),
        ({"approval": {}}, "MANDATE_INVALID"),
        ({"limits": None}, "MANDATE_INVALID"),
    ],
)
def test_original_document_failures(change: dict[str, Any], expected: str) -> None:
    assert mandate.mandate_lifecycle_code(document() | change, context()) == expected


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"now": 99}, "MANDATE_NOT_YET_VALID"),
        ({"now": 119}, "MANDATE_NOT_YET_VALID"),
        ({"now": 120}, None),
        ({"now": 749}, None),
        ({"now": 750}, "MANDATE_DURATION_LIMIT"),
        ({"now": 1000}, "MANDATE_EXPIRED"),
        ({"now": 1001}, "MANDATE_EXPIRED"),
        ({"started_at": 99}, "MANDATE_INVALID"),
        ({"task_iterations": -1}, "MANDATE_INVALID"),
        ({"follow_up_issues": -1}, "MANDATE_INVALID"),
        ({"task_iterations": 11}, "MANDATE_TASK_LIMIT"),
        ({"follow_up_issues": 3}, None),
        ({"follow_up_issues": 4}, "MANDATE_FOLLOW_UP_LIMIT"),
        ({"owner_identity": "Other"}, "MANDATE_OWNER_MISMATCH"),
    ],
)
def test_original_context_boundaries(
    changes: dict[str, Any], expected: str | None,
) -> None:
    assert mandate.mandate_lifecycle_code(document(), context(**changes)) == expected


@pytest.mark.parametrize("version", ["2.0", "3.0"])
@pytest.mark.parametrize("at_task_start", [False, True])
def test_equal_task_limit_distinguishes_pinned_finalization(
    version: str, at_task_start: bool,
) -> None:
    value = document() | {"schema_version": version}
    expected = None if version == "3.0" and not at_task_start else "MANDATE_TASK_LIMIT"
    assert mandate.mandate_lifecycle_code(
        value, context(task_iterations=10), at_task_start=at_task_start,
    ) == expected
    assert mandate.mandate_lifecycle_code(
        value, context(task_iterations=11), at_task_start=at_task_start,
    ) == "MANDATE_TASK_LIMIT"


@pytest.mark.parametrize("field", ["issued_at", "expires_at"])
@pytest.mark.parametrize("invalid", [True, False, None, "100", 100.0])
def test_document_numeric_types(field: str, invalid: Any) -> None:
    assert mandate.mandate_lifecycle_code(
        document() | {field: invalid}, context(),
    ) == "MANDATE_INVALID"


@pytest.mark.parametrize(
    "field", ["max_duration_seconds", "max_task_iterations", "max_follow_up_issues"],
)
@pytest.mark.parametrize("invalid", [True, False, None, "1", 1.0])
def test_limit_numeric_types(field: str, invalid: Any) -> None:
    value = document()
    value["limits"][field] = invalid
    assert mandate.mandate_lifecycle_code(value, context()) == "MANDATE_INVALID"


@pytest.mark.parametrize(
    "field", ["now", "started_at", "task_iterations", "follow_up_issues"],
)
@pytest.mark.parametrize("invalid", [True, False, None, "1", 1.0])
def test_context_numeric_types(field: str, invalid: Any) -> None:
    assert mandate.mandate_lifecycle_code(
        document(), context(**{field: invalid}),
    ) == "MANDATE_INVALID"


@pytest.mark.parametrize("invalid", [True, False, None, "120", 120.0, 99, 1001])
def test_approval_time_validation(invalid: Any) -> None:
    value = document()
    value["approval"]["approved_at"] = invalid
    assert mandate.mandate_lifecycle_code(value, context()) == "MANDATE_INVALID"


@pytest.mark.parametrize("section", ["limits", "approval"])
@pytest.mark.parametrize("mutation", ["missing", "extra"])
def test_nested_objects_retain_exact_keys(section: str, mutation: str) -> None:
    value = document()
    if mutation == "missing":
        value[section].pop(next(iter(value[section])))
    else:
        value[section]["extra"] = None
    assert mandate.mandate_lifecycle_code(value, context()) == "MANDATE_INVALID"


def test_original_precedence_and_partial_semantics() -> None:
    value = document()
    value["approval"]["approved_by"] = "Other"
    value["revoked"] = True
    assert mandate.mandate_lifecycle_code(value, context()) == (
        "MANDATE_APPROVAL_IDENTITY_MISMATCH"
    )
    value["owner_identity"] = "Other"
    assert mandate.mandate_lifecycle_code(value, context()) == "MANDATE_OWNER_MISMATCH"
    value["schema_version"] = "unsupported"
    assert mandate.mandate_lifecycle_code(value, context()) == (
        "MANDATE_SCHEMA_UNSUPPORTED"
    )
    # Root extras and an unverified digest are not rejected by this partial predicate.
    value = document() | {"extra_root": "retained", "operations": []}
    original = copy.deepcopy(value)
    assert mandate.mandate_lifecycle_code(value, context()) is None
    assert value == original


@pytest.mark.parametrize(
    ("value", "expected_bytes"),
    [
        (
            {"schema_version": "3.0", "approval": {
                "mandate_digest": "excluded",
                "approved_by": "Fixture", "approved_at": 12,
            }, "revoked": False},
            b'{"approval":{"approved_at":12,"approved_by":"Fixture"},'
            b'"revoked":false,"schema_version":"3.0"}',
        ),
        (
            {"mandate_digest": "top", "approval": {
                "mandate_digest": "excluded", "approved_by": "Fixture",
            }},
            b'{"approval":{"approved_by":"Fixture"},"mandate_digest":"top"}',
        ),
        (
            {"owner_identity": "Фикстура", "approval": {
                "mandate_digest": "excluded", "approved_by": "Фикстура",
            }},
            (
                '{"approval":{"approved_by":"Фикстура"},'
                '"owner_identity":"Фикстура"}'
            ).encode(),
        ),
        (
            {"approval": "opaque", "schema_version": "3.0"},
            b'{"approval":"opaque","schema_version":"3.0"}',
        ),
        ({"schema_version": "3.0"}, b'{"schema_version":"3.0"}'),
        (
            {"approval": {"mandate_digest": "excluded", "extra": [1, None]}},
            b'{"approval":{"extra":[1,null]}}',
        ),
    ],
)
def test_independent_legacy_projection_bytes_and_nonmutation(
    value: dict[str, Any], expected_bytes: bytes,
) -> None:
    original = copy.deepcopy(value)
    approval = value.get("approval")
    expected = "sha256:" + hashlib.sha256(expected_bytes).hexdigest()
    assert mandate.mandate_digest(value) == expected
    assert value == original
    assert value.get("approval") is approval


def test_only_nested_digest_is_excluded_from_legacy_projection() -> None:
    value = document()
    before = mandate.mandate_digest(value)
    value["approval"]["mandate_digest"] = "different excluded value"
    assert mandate.mandate_digest(value) == before
    value["approval"]["approved_by"] = "Other"
    expected = (
        b'{"approval":{"approved_at":120,"approved_by":"Other"},"expires_at":1000,'
        b'"issued_at":100,"limits":{"max_duration_seconds":600,'
        b'"max_follow_up_issues":3,'
        b'"max_task_iterations":10},"owner_identity":"Fixture",'
        b'"revoked":false,"schema_version":"3.0"}'
    )
    expected_digest = "sha256:" + hashlib.sha256(expected).hexdigest()
    assert mandate.mandate_digest(value) == expected_digest
    assert mandate.mandate_digest(value) != before


@pytest.mark.parametrize(
    ("field", "number", "expected"),
    [
        ("max_duration_seconds", 0, "MANDATE_INVALID"),
        ("max_duration_seconds", -1, "MANDATE_INVALID"),
        ("max_task_iterations", 0, "MANDATE_INVALID"),
        ("max_task_iterations", -1, "MANDATE_INVALID"),
        ("max_follow_up_issues", -1, "MANDATE_INVALID"),
        ("max_follow_up_issues", 0, None),
    ],
)
def test_limit_value_boundaries(field: str, number: int, expected: str | None) -> None:
    value = document()
    value["limits"][field] = number
    assert mandate.mandate_lifecycle_code(value, context()) == expected


def test_approval_identity_and_revocation_precede_time_and_counters() -> None:
    value = document()
    value["revoked"] = True
    assert mandate.mandate_lifecycle_code(
        value, context(now=1000, task_iterations=11),
    ) == "MANDATE_REVOKED"
    value["revoked"] = False
    value["approval"]["approved_by"] = None
    assert mandate.mandate_lifecycle_code(
        value, context(now=1000),
    ) == "MANDATE_APPROVAL_IDENTITY_MISMATCH"


def test_future_start_is_retained_original_partial_behavior() -> None:
    # This predicate does not reject started_at > now; do not invent a new check.
    assert mandate.mandate_lifecycle_code(document(), context(started_at=300)) is None
