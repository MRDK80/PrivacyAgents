"""Partial original legacy predicates, not permission to perform a delivery.

MIT source fragments from MRDK80/privacy-gateway; see LICENSE and PROVENANCE.json.
No ledger, binding, effect, reconciliation, transport or live-state observation.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from tools.mandate_validation import (
    MandateContext,
    mandate_digest,
    mandate_lifecycle_code,
)

SHA_RE = re.compile(r"[0-9a-f]{40}")

DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")

OPERATIONS = frozenset(
    {
        "commit_task",
        "push_task",
        "create_task_pr",
        "merge_task_pr",
        "close_task",
        "update_epic",
    }
)

POST_MERGE_OPERATIONS = frozenset({"close_task", "update_epic"})

@dataclass(frozen=True)
class Request:
    operation_id: str
    operation: str
    repository: str
    epic: int
    task: int
    pr: int | None
    base_ref: str
    base_sha: str
    head_ref: str
    head_sha: str
    merge_sha: str | None = None
    schema_version: str = "1.0"
    policy_sha: str | None = None

def _valid_request(request: Request) -> bool:
    return (
        request.schema_version in {"1.0", "2.0", "3.0"}
        and (
            (
                request.schema_version == "3.0"
                and isinstance(request.policy_sha, str)
                and SHA_RE.fullmatch(request.policy_sha) is not None
            )
            or (request.schema_version != "3.0" and request.policy_sha is None)
        )
        and request.operation in OPERATIONS
        and bool(request.operation_id)
        and request.repository.count("/") == 1
        and request.epic > 0
        and request.task > 0
        and (
            (
                isinstance(request.pr, int)
                and not isinstance(request.pr, bool)
                and request.pr > 0
            )
            or (
                request.schema_version in {"2.0", "3.0"}
                and request.pr is None
                and request.operation in {"commit_task", "push_task", "create_task_pr"}
            )
        )
        and request.base_ref.startswith(f"roadmap/{request.epic}-")
        and not request.head_ref.startswith("roadmap/")
        and SHA_RE.fullmatch(request.base_sha) is not None
        and SHA_RE.fullmatch(request.head_sha) is not None
        and (
            request.merge_sha is None or SHA_RE.fullmatch(request.merge_sha) is not None
        )
        and (
            (request.operation in POST_MERGE_OPERATIONS)
            == (request.merge_sha is not None)
        )
    )

def _authorized(
    request: Request,
    mandate: Mapping[str, object],
    approved_mandate_digest: str,
    mandate_context: MandateContext,
) -> str | None:
    if mandate.get("schema_version") == "3.0" and set(mandate) != MANDATE_FIELDS:
        return "MANDATE_INVALID"
    if DIGEST_RE.fullmatch(approved_mandate_digest) is None:
        return "MANDATE_APPROVAL_MISMATCH"
    lifecycle = mandate_lifecycle_code(mandate, mandate_context)
    if lifecycle is not None:
        return lifecycle
    approval = mandate.get("approval")
    operations = mandate.get("operations")
    grants = mandate.get("task_grants")
    if (
        mandate_digest(mandate) != approved_mandate_digest
        or not isinstance(approval, Mapping)
        or approval.get("mandate_digest") != approved_mandate_digest
    ):
        return "MANDATE_APPROVAL_MISMATCH"
    if (
        mandate.get("schema_version")
        != ("3.0" if request.schema_version == "3.0" else "2.0")
        or mandate.get("repository") != request.repository
        or mandate.get("epic") != request.epic
        or mandate.get("roadmap_ref") != request.base_ref
        or mandate.get("policy_sha")
        != (request.policy_sha if request.schema_version == "3.0" else request.base_sha)
        or not isinstance(grants, Mapping)
        or str(request.task) not in grants
    ):
        return "MANDATE_IDENTITY_MISMATCH"
    if not isinstance(operations, list) or request.operation not in operations:
        return "MANDATE_AUTHORITY_MISSING"
    return None

def _assessment_code(request: Request, assessment: Mapping[str, object]) -> str | None:
    if request.operation not in {"merge_task_pr", *POST_MERGE_OPERATIONS}:
        return None
    expected_phase = (
        "post-merge" if request.operation in POST_MERGE_OPERATIONS else "pr"
    )
    if (
        assessment.get("schema_version") != "1.0"
        or assessment.get("phase") != expected_phase
        or assessment.get("status") != "pass"
        or assessment.get("machine_code") != "OK"
    ):
        return "GATE_INVALID"
    identity = {
        "repository": request.repository,
        "epic": request.epic,
        "task": request.task,
        "pr": request.pr,
        "base_ref": request.base_ref,
        "base_sha": request.base_sha,
        "head_ref": request.head_ref,
        "head_sha": request.head_sha,
        "merge_sha": request.merge_sha,
    }
    if any(assessment.get(key) != value for key, value in identity.items()):
        return "STALE_IDENTITY"
    raw_checks = assessment.get("github_checks")
    if not isinstance(raw_checks, list):
        return "GATE_INVALID"
    states: dict[str, object] = {}
    for item in raw_checks:
        if not isinstance(item, Mapping) or not isinstance(item.get("name"), str):
            return "GATE_INVALID"
        name = item["name"]
        if name in states:
            return "GATE_INVALID"
        states[name] = item.get("state")
    if set(states) != set(REQUIRED_CHECKS) or set(states.values()) != {"SUCCESS"}:
        return "GATE_INVALID"
    return None

MANDATE_FIELDS = {
    "schema_version",
    "repository",
    "epic",
    "roadmap_ref",
    "policy_sha",
    "issued_at",
    "expires_at",
    "owner_identity",
    "limits",
    "revoked",
    "operations",
    "task_grants",
    "approval",
}

REQUIRED_CHECKS = frozenset(
    {
        "test (ubuntu-latest, 3.11)",
        "test (ubuntu-latest, 3.12)",
        "test (windows-latest, 3.11)",
        "test (windows-latest, 3.12)",
        "pre-commit",
    }
)
