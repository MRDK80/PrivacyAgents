"""Legacy partial report/verdict validation with source-owned schema lookup.

MIT source fragments from MRDK80/privacy-gateway; see LICENSE/PROVENANCE.json.
Resource I/O occurs at explicit lookup, not import. No runtime or review authority.
"""

from __future__ import annotations

import functools
import json
from pathlib import Path
from typing import Any, Protocol, cast

from tools.schema_validate import SchemaError, load_schema


class _ReportContract(Protocol):
    """Private static read-only seam; no operational defaults or runtime guard."""

    @property
    def issue(self) -> int:
        ...

    @property
    def base_sha(self) -> str:
        ...

    @property
    def max_report_chars(self) -> int:
        ...


CONTROLLER_VERDICT_SCHEMA = Path("docs") / "schemas" / "controller-verdict.schema.json"


TRUST_BOUNDARY_INVARIANTS = {
    "head_policy_applied": False,
    "executor_self_assessment_treated_as_evidence_only": True,
}


class OrchestrationError(Exception):
    """Controlled failure whose message is safe to report."""

    def __init__(self, machine_code: str) -> None:
        super().__init__(machine_code)
        self.machine_code = machine_code


def _validate_report(value: Any, contract: _ReportContract, head_sha: str) -> None:
    if not isinstance(value, dict):
        raise OrchestrationError("MALFORMED_OUTPUT")
    required = {
        "schema_version",
        "role",
        "task_issue",
        "base_sha",
        "head_sha",
        "status",
        "acceptance_criteria",
        "changed_files",
        "checks",
        "residual_risks",
        "stop_reason",
    }
    if set(value) != required:
        raise OrchestrationError("MALFORMED_OUTPUT")
    expected = ("1.0", "executor", contract.issue, contract.base_sha, head_sha)
    actual = tuple(
        value[key]
        for key in ("schema_version", "role", "task_issue", "base_sha", "head_sha")
    )
    if actual != expected or value["status"] not in {
        "completed",
        "blocked",
        "needs_human",
    }:
        raise OrchestrationError("MALFORMED_OUTPUT")
    if len(json.dumps(value, ensure_ascii=False)) > contract.max_report_chars:
        raise OrchestrationError("OUTPUT_LIMIT")


@functools.lru_cache(maxsize=1)
def _canonical_trust_source_kinds() -> frozenset[str]:
    """Return the canonical ``trust_source_kind`` enum, fail-closed on any doubt.

    The schema is read from the orchestrator's own trusted checkout, never from
    the task head worktree, so a task branch cannot widen the accepted set.
    """

    schema_path = Path(__file__).resolve().parents[1] / CONTROLLER_VERDICT_SCHEMA
    try:
        schema = load_schema(schema_path)
        node = schema["properties"]["review_basis"]["properties"]["trust_source_kind"]
        values = node["enum"]
    except (OSError, ValueError, KeyError, TypeError, SchemaError) as error:
        raise OrchestrationError("TRUST_SCHEMA_UNAVAILABLE") from error
    if not isinstance(values, list) or not values:
        raise OrchestrationError("TRUST_SCHEMA_UNAVAILABLE")
    if not all(isinstance(item, str) and item for item in values):
        raise OrchestrationError("TRUST_SCHEMA_UNAVAILABLE")
    return frozenset(str(item) for item in values)


def _validate_verdict(value: Any, contract: _ReportContract, head_sha: str) -> str:
    if not isinstance(value, dict):
        raise OrchestrationError("MALFORMED_OUTPUT")
    required = {
        "schema_version",
        "role",
        "task_issue",
        "base_sha",
        "head_sha",
        "review_basis",
        "verdict",
        "repair_iteration",
        "escalation_reason",
        "blocking_findings",
        "notes",
    }
    if set(value) != required:
        raise OrchestrationError("MALFORMED_OUTPUT")
    expected = ("1.0", "controller", contract.issue, contract.base_sha, head_sha)
    actual = tuple(
        value[key]
        for key in ("schema_version", "role", "task_issue", "base_sha", "head_sha")
    )
    basis = value.get("review_basis")
    valid_basis = (
        isinstance(basis, dict)
        and set(basis) == {"trust_source_kind", *TRUST_BOUNDARY_INVARIANTS}
        and all(
            basis[key] is expected
            for key, expected in TRUST_BOUNDARY_INVARIANTS.items()
        )
        and basis["trust_source_kind"] in _canonical_trust_source_kinds()
    )
    verdict = value.get("verdict")
    if (
        actual != expected
        or not valid_basis
        or verdict not in {"PASS", "PASS_WITH_NOTES", "FAIL_RETRY", "FAIL_ESCALATE"}
    ):
        raise OrchestrationError("MALFORMED_OUTPUT")
    findings = value.get("blocking_findings")
    if not isinstance(findings, list):
        raise OrchestrationError("MALFORMED_OUTPUT")
    if verdict in {"PASS", "PASS_WITH_NOTES"} and findings:
        raise OrchestrationError("MALFORMED_OUTPUT")
    if verdict in {"FAIL_RETRY", "FAIL_ESCALATE"} and not findings:
        raise OrchestrationError("MALFORMED_OUTPUT")
    if len(json.dumps(value, ensure_ascii=False)) > contract.max_report_chars:
        raise OrchestrationError("OUTPUT_LIMIT")
    return cast(str, verdict)
