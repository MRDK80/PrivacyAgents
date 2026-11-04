"""Pure protocol oracles; synthetic subjects never establish authentication."""

from __future__ import annotations

import ast
import itertools
import os.path
import sys
from collections.abc import Callable
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import cast

import pytest
from tools.generic_entry import format_result, malformed_plan, parse_invocation

COMMANDS = ("validate", "initialize", "resume", "status", "pause", "stop")
PAIRS = (
    ("--context", os.path.abspath("synthetic/operator/context.json")),
    ("--approved-context-digest", "sha256:" + "a" * 64),
    ("--record-limit-bytes", "17"),
)
POSITIVE = (
    ("validate", "VALIDATED", "OK"),
    ("initialize", "INITIALIZED", "OK"),
    ("resume", "PAUSED", "OWNER_PAUSED"),
    ("resume", "STOPPED", "OWNER_STOPPED"),
    ("resume", "TERMINAL", "OK"),
    ("status", "OBSERVED", "OK"),
    ("status", "PAUSED", "OWNER_PAUSED"),
    ("status", "STOPPED", "OWNER_STOPPED"),
    ("status", "TERMINAL", "OK"),
    ("pause", "PAUSED", "OWNER_PAUSED"),
    ("stop", "STOPPED", "OWNER_STOPPED"),
)
DENIALS = (
    "SOURCE_UNVERIFIED", "IDENTITY_MISMATCH", "OWNER_APPROVAL_MISMATCH",
    "OWNER_STOPPED", "OWNER_PAUSED", "GRANT_EXPIRED", "COUNTER_EXHAUSTED",
    "CLOCK_UNCONFIRMED", "STATE_UNKNOWN", "PROCESS_OWNERSHIP_UNKNOWN",
    "CAPABILITY_UNSUPPORTED",
)
PHASES = (
    "PLAN", "RUN_TASK", "PR_CI", "MERGE", "POST_MERGE", "DEMO", "TASK_DONE",
    "NEXT_TASK", None,
)
FIELDS = (
    "schema_id", "schema_version", "status", "machine_code", "run_id", "phase",
    "observed_control_generation",
)


def tokens(command: str = "status") -> list[str]:
    return [command, *(part for pair in PAIRS for part in pair)]


def result(status: str = "OBSERVED", code: str = "OK") -> dict[str, object]:
    return {
        "schema_id": "privacyagents.entry-result",
        "schema_version": "1.0",
        "status": status,
        "machine_code": code,
        "run_id": None,
        "phase": None,
        "observed_control_generation": None,
    }


def expected(status: str, code: str) -> bytes:
    # These closed literal fragments are independent of the production serializer.
    return (
        b'{"schema_id":"privacyagents.entry-result","schema_version":"1.0",'
        b'"status":"' + status.encode("ascii") + b'","machine_code":"'
        + code.encode("ascii") + b'","run_id":null,"phase":null,'
        b'"observed_control_generation":null}\n'
    )


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("pairs", tuple(itertools.permutations(PAIRS)))
def test_all_commands_and_pair_orders(
    command: str, pairs: tuple[tuple[str, str], ...]
) -> None:
    supplied = [command, *(part for pair in pairs for part in pair)]
    original = supplied.copy()
    parsed = parse_invocation(supplied)
    assert parsed is not None
    assert parsed.command == command
    assert parsed.context == PAIRS[0][1]
    assert parsed.approved_context_digest == "sha256:" + "a" * 64
    assert parsed.record_limit_bytes == 17
    assert supplied == original
    assert parse_invocation(tuple(supplied)) == parsed


@pytest.mark.parametrize("index", range(7))
def test_every_missing_token(index: int) -> None:
    supplied = tokens()
    del supplied[index]
    assert parse_invocation(supplied) is None


@pytest.mark.parametrize("index", range(8))
def test_every_extra_token(index: int) -> None:
    supplied = tokens()
    supplied.insert(index, "synthetic-extra")
    assert parse_invocation(supplied) is None


@pytest.mark.parametrize("index", range(7))
@pytest.mark.parametrize("bad", [None, True, 1, 1.5, b"status", [], {}])
def test_non_string_tokens(index: int, bad: object) -> None:
    supplied: list[object] = list(tokens())
    supplied[index] = bad
    assert cast(Callable[..., object], parse_invocation)(supplied) is None


@pytest.mark.parametrize("supplied", [None, True, 7, "1234567", b"1234567", {}])
def test_non_sequence_invocation(supplied: object) -> None:
    assert cast(Callable[..., object], parse_invocation)(supplied) is None


@pytest.mark.parametrize("bad", [
    "", "STATUS", "run", "--help", "--version", " status", "status ",
    "@synthetic", "status\x00", "\ud800",
])
def test_exact_command(bad: str) -> None:
    assert parse_invocation(tokens(bad)) is None


@pytest.mark.parametrize("position", [1, 3, 5])
@pytest.mark.parametrize("bad", [
    "--", "--help", "--version", "--ctx", "--context=x", "@response",
    "context", "--unknown", "--Context",
])
def test_exact_flags(position: int, bad: str) -> None:
    supplied = tokens()
    supplied[position] = bad
    assert parse_invocation(supplied) is None


@pytest.mark.parametrize(
    "source,target", [(1, 3), (1, 5), (3, 1), (3, 5), (5, 1), (5, 3)]
)
def test_duplicate_flags(source: int, target: int) -> None:
    supplied = tokens()
    supplied[target] = supplied[source]
    assert parse_invocation(supplied) is None


@pytest.mark.parametrize("bad", [
    "context.json", ".", "..", "~/context.json", "$HOME/context.json",
    "%HOME%/context.json", "--context", "", "\x00/absolute", "\ud800",
])
def test_context_lexical_negatives(bad: str) -> None:
    supplied = tokens()
    supplied[2] = bad
    assert parse_invocation(supplied) is None


def test_context_native_spelling_preserved_without_normalizing() -> None:
    supplied = tokens()
    supplied[2] = os.path.abspath("synthetic") + "/../synthetic//e\u0301\t.json"
    assert os.path.isabs(supplied[2])
    parsed = parse_invocation(supplied)
    assert parsed is not None and parsed.context == supplied[2]


def test_native_absolute_surrogate_spelling_is_lexical_data_only() -> None:
    supplied = tokens()
    supplied[2] = os.path.abspath("synthetic") + "/surrogate-\ud800.json"
    assert os.path.isabs(supplied[2])
    parsed = parse_invocation(supplied)
    assert parsed is not None and parsed.context == supplied[2]


@pytest.mark.parametrize("bad", [
    "", "SHA256:" + "a" * 64, "sha256:" + "A" * 64,
    "sha256:" + "g" * 64, "sha256:" + "a" * 63, "sha256:" + "a" * 65,
    " " + "sha256:" + "a" * 64, "sha256:" + "a" * 64 + "\n", "--help",
])
def test_digest_complete_ascii_grammar(bad: str) -> None:
    supplied = tokens()
    supplied[4] = bad
    assert parse_invocation(supplied) is None


@pytest.mark.parametrize("bad", [
    "", "0", "00", "01", "+1", "-1", " 1", "1 ", "1\n", "١", "１",
    "1.0", "1_0", "1e1", "--help", "\x001",
])
def test_record_limit_complete_ascii_grammar(bad: str) -> None:
    supplied = tokens()
    supplied[6] = bad
    assert parse_invocation(supplied) is None


def test_native_integer_failure_safe_without_changing_limits() -> None:
    original_limit = sys.get_int_max_str_digits()
    if original_limit == 0:
        pytest.skip("Host integer-string limit is disabled; do not alter it")
    supplied = tokens()
    supplied[6] = "1" * (original_limit + 1)
    assert parse_invocation(supplied) is None
    assert sys.get_int_max_str_digits() == original_limit


def test_no_artificial_record_limit_cap() -> None:
    supplied = tokens()
    supplied[6] = "9" * 100
    parsed = parse_invocation(supplied)
    assert parsed is not None and parsed.record_limit_bytes == int("9" * 100)


@pytest.mark.parametrize("command,status,code", POSITIVE)
def test_positive_matrix_literal_bytes(command: str, status: str, code: str) -> None:
    supplied = result(status, code)
    original = supplied.copy()
    plan = format_result(command, supplied)
    assert plan is not None
    assert (plan.stdout, plan.stderr, plan.exit_code) == (
        expected(status, code), b"", 0
    )
    assert supplied == original


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("code", DENIALS)
def test_denial_matrix_literal_bytes(command: str, code: str) -> None:
    plan = format_result(command, result("BLOCKED", code))
    assert plan is not None
    assert (plan.stdout, plan.stderr, plan.exit_code) == (
        expected("BLOCKED", code), b"", 1
    )


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("code", ["INPUT_INVALID", "UNSUPPORTED_VERSION"])
def test_invalid_matrix_literal_bytes(command: str, code: str) -> None:
    plan = format_result(command, result("INVALID", code))
    assert plan is not None
    assert (plan.stdout, plan.stderr, plan.exit_code) == (
        expected("INVALID", code), b"", 2
    )


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("status,code", sorted({(row[1], row[2]) for row in POSITIVE}))
def test_cross_command_positive_rejection(command: str, status: str, code: str) -> None:
    if (command, status, code) not in POSITIVE:
        assert format_result(command, result(status, code)) is None


@pytest.mark.parametrize("field", FIELDS)
def test_every_result_field_required(field: str) -> None:
    supplied = result()
    del supplied[field]
    assert format_result("status", supplied) is None


@pytest.mark.parametrize("field", ["extra", "verified", "authenticated", "context"])
def test_result_unknown_fields_rejected(field: str) -> None:
    supplied = result()
    supplied[field] = "synthetic-private-marker"
    assert format_result("status", supplied) is None


@pytest.mark.parametrize(
    "field", ["schema_id", "schema_version", "status", "machine_code"]
)
@pytest.mark.parametrize(
    "bad", [None, True, 1, 1.5, float("nan"), [], {}, "", "unknown"]
)
def test_result_tags_closed_types(field: str, bad: object) -> None:
    supplied = result()
    supplied[field] = bad
    assert format_result("status", supplied) is None


@pytest.mark.parametrize("status,code", [
    ("RUNNING", "OK"), ("OBSERVED", "OWNER_PAUSED"), ("BLOCKED", "OK"),
    ("INVALID", "OK"), ("OBSERVED", "STATE_UNKNOWN"),
    ("OBSERVED", "PROCESS_OWNERSHIP_UNKNOWN"), ("TERMINAL", "OWNER_STOPPED"),
    ("PAUSED", "OK"), ("STOPPED", "OK"),
])
def test_status_code_pairs_cannot_claim_safe_unknown(status: str, code: str) -> None:
    assert format_result("status", result(status, code)) is None


@pytest.mark.parametrize("phase", PHASES)
def test_all_exact_phases_and_null(phase: str | None) -> None:
    supplied = result()
    supplied["phase"] = phase
    plan = format_result("status", supplied)
    assert plan is not None
    phase_bytes = b"null" if phase is None else b'"' + phase.encode("ascii") + b'"'
    assert plan.stdout == expected("OBSERVED", "OK").replace(
        b'"phase":null', b'"phase":' + phase_bytes
    )


@pytest.mark.parametrize(
    "phase", ["RUNNING", "FINAL", "WAITING_OWNER", "status", "plan", "", 0, True, []]
)
def test_wrong_phase_rejected(phase: object) -> None:
    supplied = result()
    supplied["phase"] = phase
    assert format_result("status", supplied) is None


@pytest.mark.parametrize(
    "bad", ["", "\x00", "bad\x00id", "\ud800", "\udfff", True, 1, [], {}]
)
def test_run_id_exact_scalar_type(bad: object) -> None:
    supplied = result()
    supplied["run_id"] = bad
    assert format_result("status", supplied) is None


@pytest.mark.parametrize("identifier,encoded", [
    (" e\u0301\t\n", b" e\xcc\x81\\t\\n"),
    ("é", b"\xc3\xa9"),
    ("e\u0301", b"e\xcc\x81"),
    ("\x01", b"\\u0001"),
    ('"\\', b'\\"\\\\'),
])
def test_subject_unicode_bytes_do_not_establish_authentication(
    identifier: str, encoded: bytes
) -> None:
    supplied = result()
    # Synthetic caller data, never verified by formatting.
    supplied["run_id"] = identifier
    plan = format_result("status", supplied)
    assert plan is not None
    assert plan.stdout == expected("OBSERVED", "OK").replace(
        b'"run_id":null', b'"run_id":"' + encoded + b'"'
    )


@pytest.mark.parametrize("generation", [0, 1, 10**100])
def test_generation_exact_nonnegative_integer(generation: int) -> None:
    supplied = result()
    supplied["observed_control_generation"] = generation
    plan = format_result("status", supplied)
    assert plan is not None
    assert plan.stdout == expected("OBSERVED", "OK").replace(
        b'"observed_control_generation":null',
        b'"observed_control_generation":' + str(generation).encode("ascii"),
    )


@pytest.mark.parametrize(
    "generation", [-1, True, False, 1.0, float("inf"), "0", [], {}]
)
def test_wrong_generation_rejected(generation: object) -> None:
    supplied = result()
    supplied["observed_control_generation"] = generation
    assert format_result("status", supplied) is None


@pytest.mark.parametrize("command", ["STATUS", "", "run", None, True, []])
def test_format_command_closed(command: object) -> None:
    assert cast(Callable[..., object], format_result)(command, result()) is None


@pytest.mark.parametrize("supplied", [None, [], True, 7, "synthetic-private-marker"])
def test_non_mapping_result(supplied: object) -> None:
    assert cast(Callable[..., object], format_result)("status", supplied) is None


def test_redacted_immutable_data_and_fixed_malformed_plan() -> None:
    supplied = tokens()
    supplied[2] = os.path.abspath("synthetic-private-context-marker")
    parsed = parse_invocation(supplied)
    assert parsed is not None
    assert repr(parsed) == str(parsed) == "ParsedInvocation()"
    with pytest.raises(FrozenInstanceError):
        cast(Callable[..., object], setattr)(parsed, "command", "stop")
    plan = malformed_plan()
    assert (plan.stdout, plan.stderr, plan.exit_code) == (b"", b"INPUT_INVALID\n", 2)
    assert repr(plan) == str(plan) == "OutputPlan()"
    with pytest.raises(FrozenInstanceError):
        cast(Callable[..., object], setattr)(plan, "exit_code", 0)
    subject = result()
    subject["run_id"] = "synthetic-private-subject-marker"
    handled = format_result("status", subject)
    assert handled is not None and repr(handled) == str(handled) == "OutputPlan()"


def test_source_import_closure_has_no_runtime_effect_paths() -> None:
    source = Path(__file__).resolve().parents[1] / "tools/generic_entry.py"
    tree = ast.parse(source.read_text())
    imports = {
        node.module if isinstance(node, ast.ImportFrom) else alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imports <= {
        "__future__", "collections.abc", "dataclasses", "json", "os.path", "re"
    }
    assert not any(isinstance(node, ast.If) for node in tree.body)
    assert not any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "main"
        for node in ast.walk(tree)
    )
    forbidden = {
        "open", "print", "input", "exec", "eval", "__import__", "getenv",
        "resolve", "absolute", "expanduser", "normpath", "stat", "read_text",
        "write_text", "read_bytes", "write_bytes", "set_int_max_str_digits",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else (
                node.func.attr if isinstance(node.func, ast.Attribute) else ""
            )
            assert name not in forbidden
