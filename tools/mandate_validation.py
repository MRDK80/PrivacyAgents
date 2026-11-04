"""Pure legacy mandate primitives; no full authentication or runtime authority.

Copyright (c) 2026 MRDK80 (Михаил Иофик). MIT License; see LICENSE.
Extracted unchanged from privacy-gateway tools/agent_epic_handover.py;
source fragments and immutable revision are recorded in PROVENANCE.json.
Legacy approval projection A(MD) is distinct from new typed full-record H.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

MANDATE_SCHEMA_VERSION = "2.0"
PINNED_MANDATE_SCHEMA_VERSION = "3.0"


@dataclass(frozen=True)
class MandateContext:
    now: int
    owner_identity: str
    started_at: int
    task_iterations: int
    follow_up_issues: int


def mandate_lifecycle_code(
    mandate: Mapping[str, Any], context: MandateContext, *, at_task_start: bool = True
) -> str | None:
    """Return the fail-closed lifecycle reason for one imminent side effect."""
    if mandate.get("schema_version") not in {
        MANDATE_SCHEMA_VERSION,
        PINNED_MANDATE_SCHEMA_VERSION,
    }:
        return "MANDATE_SCHEMA_UNSUPPORTED"
    limits = mandate.get("limits")
    approval = mandate.get("approval")
    if not isinstance(limits, Mapping) or set(limits) != {
        "max_duration_seconds",
        "max_task_iterations",
        "max_follow_up_issues",
    }:
        return "MANDATE_INVALID"
    if not isinstance(approval, Mapping) or set(approval) != {
        "mandate_digest",
        "approved_by",
        "approved_at",
    }:
        return "MANDATE_INVALID"
    integer_values = (
        mandate.get("issued_at"),
        mandate.get("expires_at"),
        approval.get("approved_at"),
        limits.get("max_duration_seconds"),
        limits.get("max_task_iterations"),
        limits.get("max_follow_up_issues"),
        context.now,
        context.started_at,
        context.task_iterations,
        context.follow_up_issues,
    )
    if any(
        not isinstance(value, int) or isinstance(value, bool)
        for value in integer_values
    ):
        return "MANDATE_INVALID"
    issued_at = cast(int, mandate["issued_at"])
    expires_at = cast(int, mandate["expires_at"])
    approved_at = cast(int, approval["approved_at"])
    duration = cast(int, limits["max_duration_seconds"])
    task_limit = cast(int, limits["max_task_iterations"])
    follow_up_limit = cast(int, limits["max_follow_up_issues"])
    if (
        issued_at < 0
        or expires_at <= issued_at
        or approved_at < issued_at
        or approved_at > expires_at
        or duration <= 0
        or task_limit <= 0
        or follow_up_limit < 0
        or context.started_at < issued_at
        or context.task_iterations < 0
        or context.follow_up_issues < 0
        or not isinstance(mandate.get("owner_identity"), str)
        or not mandate["owner_identity"]
        or type(mandate.get("revoked")) is not bool
    ):
        return "MANDATE_INVALID"
    if mandate["owner_identity"] != context.owner_identity:
        return "MANDATE_OWNER_MISMATCH"
    if approval["approved_by"] != context.owner_identity:
        return "MANDATE_APPROVAL_IDENTITY_MISMATCH"
    if mandate["revoked"] is True:
        return "MANDATE_REVOKED"
    if context.now < issued_at or context.now < approved_at:
        return "MANDATE_NOT_YET_VALID"
    if context.now >= expires_at:
        return "MANDATE_EXPIRED"
    if context.now - context.started_at >= duration:
        return "MANDATE_DURATION_LIMIT"
    if context.task_iterations > task_limit or (
        context.task_iterations == task_limit
        and (
            at_task_start or mandate["schema_version"] != PINNED_MANDATE_SCHEMA_VERSION
        )
    ):
        return "MANDATE_TASK_LIMIT"
    if context.follow_up_issues > follow_up_limit:
        return "MANDATE_FOLLOW_UP_LIMIT"
    return None


def mandate_digest(value: Mapping[str, Any]) -> str:
    """Bind approval to every authority-bearing mandate field."""
    payload = dict(value)
    approval = payload.get("approval")
    if isinstance(approval, Mapping):
        payload["approval"] = {
            key: item for key, item in approval.items() if key != "mandate_digest"
        }
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
