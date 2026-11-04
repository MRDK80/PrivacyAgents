"""Private pure protocol data; no source authentication or runtime dispatch."""

from __future__ import annotations

import json
import os.path
import re
from collections.abc import Sequence
from dataclasses import dataclass

_COMMANDS = frozenset(("validate", "initialize", "resume", "status", "pause", "stop"))
_FLAGS = frozenset(("--context", "--approved-context-digest", "--record-limit-bytes"))
_FIELDS = (
    "schema_id", "schema_version", "status", "machine_code", "run_id", "phase",
    "observed_control_generation",
)
_PHASES = frozenset((
    "PLAN", "RUN_TASK", "PR_CI", "MERGE", "POST_MERGE", "DEMO", "TASK_DONE",
    "NEXT_TASK",
))
_DENIALS = frozenset((
    "SOURCE_UNVERIFIED", "IDENTITY_MISMATCH", "OWNER_APPROVAL_MISMATCH",
    "OWNER_STOPPED", "OWNER_PAUSED", "GRANT_EXPIRED", "COUNTER_EXHAUSTED",
    "CLOCK_UNCONFIRMED", "STATE_UNKNOWN", "PROCESS_OWNERSHIP_UNKNOWN",
    "CAPABILITY_UNSUPPORTED",
))
# This is a partial private formatter matrix, not control transition semantics.
_POSITIVE = {
    "validate": frozenset((("VALIDATED", "OK"),)),
    "initialize": frozenset((("INITIALIZED", "OK"),)),
    "resume": frozenset((
        ("PAUSED", "OWNER_PAUSED"), ("STOPPED", "OWNER_STOPPED"), ("TERMINAL", "OK"),
    )),
    "status": frozenset((
        ("OBSERVED", "OK"), ("PAUSED", "OWNER_PAUSED"),
        ("STOPPED", "OWNER_STOPPED"), ("TERMINAL", "OK"),
    )),
    "pause": frozenset((("PAUSED", "OWNER_PAUSED"),)),
    "stop": frozenset((("STOPPED", "OWNER_STOPPED"),)),
}


@dataclass(frozen=True, slots=True, repr=False)
class ParsedInvocation:
    """Untrusted lexical data; construction does not establish any authority."""

    command: str
    context: str
    approved_context_digest: str
    record_limit_bytes: int

    def __repr__(self) -> str:
        return "ParsedInvocation()"

    def __str__(self) -> str:
        return "ParsedInvocation()"


@dataclass(frozen=True, slots=True, repr=False)
class OutputPlan:
    """Inert output bytes, never a proof that their subject was authenticated."""

    stdout: bytes
    stderr: bytes
    exit_code: int

    def __repr__(self) -> str:
        return "OutputPlan()"

    def __str__(self) -> str:
        return "OutputPlan()"


def _text(value: object) -> bool:
    if type(value) is not str or not value or "\x00" in value:
        return False
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        return False
    return True


def parse_invocation(tokens: Sequence[str]) -> ParsedInvocation | None:
    """Parse native lexical grammar without reading context or trusting its data."""
    if not isinstance(tokens, Sequence) or isinstance(tokens, (str, bytes, bytearray)):
        return None
    if len(tokens) != 7 or any(type(item) is not str for item in tokens):
        return None
    command = tokens[0]
    if command not in _COMMANDS:
        return None
    pairs: dict[str, str] = {}
    for index in (1, 3, 5):
        flag, value = tokens[index], tokens[index + 1]
        if flag not in _FLAGS or flag in pairs:
            return None
        pairs[flag] = value
    context = pairs["--context"]
    digest = pairs["--approved-context-digest"]
    limit = pairs["--record-limit-bytes"]
    if not os.path.isabs(context):
        return None
    if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        return None
    if re.fullmatch(r"[1-9][0-9]*", limit) is None:
        return None
    try:
        limit_bytes = int(limit)
    except ValueError:
        return None
    return ParsedInvocation(command, context, digest, limit_bytes)


def malformed_plan() -> OutputPlan:
    """Fixed malformed-invocation response, independent of private input bytes."""
    return OutputPlan(b"", b"INPUT_INVALID\n", 2)


def format_result(command: str, result_data: dict[str, object]) -> OutputPlan | None:
    """Format closed data only; a caller must authenticate subject facts first.

    Until it has independently authenticated actual subject facts, a trusted
    wrapper must pass null subject fields. This formatter cannot enforce that
    provenance, establish a durable outcome, or authorize any operation.
    """
    if type(command) is not str or command not in _COMMANDS:
        return None
    if type(result_data) is not dict:
        return None
    if (
        any(type(name) is not str for name in result_data)
        or set(result_data) != set(_FIELDS)
    ):
        return None
    for name in ("schema_id", "schema_version", "status", "machine_code"):
        if type(result_data[name]) is not str:
            return None
    if (
        result_data["schema_id"] != "privacyagents.entry-result"
        or result_data["schema_version"] != "1.0"
    ):
        return None
    status, code = result_data["status"], result_data["machine_code"]
    if (status, code) in _POSITIVE[command]:
        exit_code = 0
    elif status == "BLOCKED" and code in _DENIALS:
        exit_code = 1
    elif status == "INVALID" and code in ("INPUT_INVALID", "UNSUPPORTED_VERSION"):
        exit_code = 2
    else:
        return None
    run_id = result_data["run_id"]
    if run_id is not None and not _text(run_id):
        return None
    phase = result_data["phase"]
    if phase is not None and (type(phase) is not str or phase not in _PHASES):
        return None
    generation = result_data["observed_control_generation"]
    if generation is not None and (type(generation) is not int or generation < 0):
        return None
    ordered = {name: result_data[name] for name in _FIELDS}
    try:
        encoded = json.dumps(
            ordered, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8", "strict")
    except (ValueError, UnicodeEncodeError):
        return None
    return OutputPlan(encoded + b"\n", b"", exit_code)
