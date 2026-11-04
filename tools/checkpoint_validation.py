"""Original legacy checkpoint predicates, not trusted run or durable-state proof.

MIT source fragments from MRDK80/privacy-gateway; see LICENSE and PROVENANCE.json.
No store, lock, migration, effect, authority observation or runtime activation.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, cast

SCHEMA_VERSION = "1.0"

BOOTSTRAP_SCHEMA_VERSION = "2.0"

PINNED_SCHEMA_VERSION = "3.0"

SHA_RE = re.compile(r"[0-9a-f]{40}")

PHASES = (
    "PLAN",
    "RUN_TASK",
    "PR_CI",
    "MERGE",
    "POST_MERGE",
    "DEMO",
    "TASK_DONE",
    "NEXT_TASK",
)

CHECKPOINT_KEYS = {
    "schema_version",
    "repository",
    "epic",
    "task",
    "pr",
    "base_ref",
    "base_sha",
    "head_ref",
    "head_sha",
    "phase",
    "completed_phases",
    "pending_phase",
    "merge_sha",
    "status",
    "rate_limit_pause",
}

class LoopError(Exception):
    """Fail-closed supervisor error safe to expose as a machine code."""

    def __init__(self, machine_code: str) -> None:
        super().__init__(machine_code)
        self.machine_code = machine_code

def _exact(value: Any, keys: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise LoopError(code)
    return cast(Mapping[str, Any], value)

def _next_phase(phase: str) -> str | None:
    index = PHASES.index(phase)
    return PHASES[index + 1] if index + 1 < len(PHASES) else None

def validate_checkpoint(value: Any) -> dict[str, Any]:
    """Validate the closed authority and progress checkpoint."""
    pinned = (
        isinstance(value, Mapping)
        and value.get("schema_version") == PINNED_SCHEMA_VERSION
    )
    item = _exact(
        value,
        CHECKPOINT_KEYS | ({"policy_sha"} if pinned else set()),
        "CHECKPOINT_INVALID",
    )
    if pinned and (
        not isinstance(item["policy_sha"], str)
        or SHA_RE.fullmatch(item["policy_sha"]) is None
    ):
        raise LoopError("CHECKPOINT_INVALID")
    phase = item["phase"]
    completed = item["completed_phases"]
    pending = item["pending_phase"]
    if not isinstance(phase, str) or phase not in PHASES:
        raise LoopError("CHECKPOINT_INVALID")
    expected_completed = list(PHASES[1 : PHASES.index(phase) + 1])
    merge_required = PHASES.index(phase) >= PHASES.index("POST_MERGE")
    if (
        item["schema_version"]
        not in {SCHEMA_VERSION, BOOTSTRAP_SCHEMA_VERSION, PINNED_SCHEMA_VERSION}
        or not isinstance(item["repository"], str)
        or item["repository"].count("/") != 1
        or not all(
            isinstance(item[key], int)
            and not isinstance(item[key], bool)
            and item[key] > 0
            for key in ("epic", "task")
        )
        or not (
            _positive_id(item["pr"])
            or (
                item["schema_version"]
                in {BOOTSTRAP_SCHEMA_VERSION, PINNED_SCHEMA_VERSION}
                and item["pr"] is None
                and phase == "PLAN"
            )
        )
        or item["epic"] == item["task"]
        or not isinstance(item["base_ref"], str)
        or not item["base_ref"].startswith(f"roadmap/{item['epic']}-")
        or not isinstance(item["head_ref"], str)
        or item["head_ref"].startswith("roadmap/")
        or not isinstance(item["base_sha"], str)
        or SHA_RE.fullmatch(item["base_sha"]) is None
        or not isinstance(item["head_sha"], str)
        or SHA_RE.fullmatch(item["head_sha"]) is None
        or not isinstance(completed, list)
        or completed != expected_completed
        or (pending is not None and pending != _next_phase(phase))
        or (
            item["merge_sha"] is not None
            and (
                not isinstance(item["merge_sha"], str)
                or SHA_RE.fullmatch(item["merge_sha"]) is None
            )
        )
        or (merge_required != (item["merge_sha"] is not None))
        or item["status"]
        not in {
            "READY",
            "RUNNING",
            "ESCALATE",
            "BLOCKED",
            "PAUSED_RATE_LIMIT",
            "TASK_DONE",
        }
        or not _valid_rate_limit_pause(item["rate_limit_pause"], item["status"])
        or (phase == "NEXT_TASK" and item["status"] != "TASK_DONE")
    ):
        raise LoopError("CHECKPOINT_INVALID")
    return dict(item)

def _positive_id(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0

def _valid_rate_limit_pause(value: Any, status: Any) -> bool:
    if value is None:
        return bool(status != "PAUSED_RATE_LIMIT")
    if status != "PAUSED_RATE_LIMIT" or not isinstance(value, Mapping):
        return False
    if set(value) != {"exhausted_windows", "resets_at", "next_check_at"}:
        return False
    windows = value["exhausted_windows"]
    resets_at = value["resets_at"]
    next_check_at = value["next_check_at"]
    return bool(
        isinstance(windows, list)
        and bool(windows)
        and all(window in {"primary", "secondary"} for window in windows)
        and (resets_at is None or isinstance(resets_at, int))
        and (next_check_at is None or isinstance(next_check_at, int))
    )
