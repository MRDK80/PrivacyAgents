"""Literal legacy predicate oracles, not run authority or durable-state proof."""

from __future__ import annotations

import ast
import copy
from pathlib import Path
from types import MappingProxyType

import pytest
from tools.checkpoint_validation import (
    PHASES,
    LoopError,
    _next_phase,
    validate_checkpoint,
)

# Inputs compact the separately reviewed handwritten literals; no production
# function computes expected outcomes, prefixes, pending phases or merge domains.
BASE: dict[str, object] = (
    {'schema_version': '1.0',
     'repository': 'SYNTHETIC/checkpoint-fixture',
     'epic': 2,
     'task': 3,
     'pr': 5,
     'base_ref': 'roadmap/2-checkpoints',
     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
     'head_ref': 'codex/3-checkpoint-fixture',
     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
     'phase': 'PLAN',
     'completed_phases': [],
     'pending_phase': 'RUN_TASK',
     'merge_sha': None,
     'status': 'READY',
     'rate_limit_pause': None}
)

ACCEPTED_CASES: list[tuple[str, dict[str, object], tuple[str, ...]]] = (
    [('phase_PLAN', {}, ()),
     ('phase_RUN_TASK',
      {'phase': 'RUN_TASK',
       'completed_phases': ['RUN_TASK'],
       'pending_phase': 'PR_CI',
       'status': 'RUNNING'},
      ()),
     ('phase_PR_CI',
      {'phase': 'PR_CI',
       'completed_phases': ['RUN_TASK', 'PR_CI'],
       'pending_phase': 'MERGE',
       'status': 'BLOCKED'},
      ()),
     ('phase_MERGE',
      {'phase': 'MERGE',
       'completed_phases': ['RUN_TASK', 'PR_CI', 'MERGE'],
       'pending_phase': 'POST_MERGE',
       'status': 'ESCALATE'},
      ()),
     ('phase_POST_MERGE',
      {'phase': 'POST_MERGE',
       'completed_phases': ['RUN_TASK', 'PR_CI', 'MERGE', 'POST_MERGE'],
       'pending_phase': 'DEMO',
       'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc'},
      ()),
     ('phase_DEMO',
      {'phase': 'DEMO',
       'completed_phases': ['RUN_TASK',
                            'PR_CI',
                            'MERGE',
                            'POST_MERGE',
                            'DEMO'],
       'pending_phase': 'TASK_DONE',
       'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc'},
      ()),
     ('phase_TASK_DONE',
      {'phase': 'TASK_DONE',
       'completed_phases': ['RUN_TASK',
                            'PR_CI',
                            'MERGE',
                            'POST_MERGE',
                            'DEMO',
                            'TASK_DONE'],
       'pending_phase': 'NEXT_TASK',
       'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc',
       'status': 'TASK_DONE'},
      ()),
     ('phase_NEXT_TASK',
      {'phase': 'NEXT_TASK',
       'completed_phases': ['RUN_TASK',
                            'PR_CI',
                            'MERGE',
                            'POST_MERGE',
                            'DEMO',
                            'TASK_DONE',
                            'NEXT_TASK'],
       'pending_phase': None,
       'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc',
       'status': 'TASK_DONE'},
      ()),
     ('v1_plan_no_pending', {'pending_phase': None}, ()),
     ('v2_bootstrap_null_pr',
      {'schema_version': '2.0', 'pr': None, 'pending_phase': None},
      ()),
     ('v3_bootstrap_null_pr_policy',
      {'schema_version': '3.0',
       'pr': None,
       'pending_phase': None,
       'policy_sha': 'dddddddddddddddddddddddddddddddddddddddd'},
      ()),
     ('v3_positive_pr_policy',
      {'schema_version': '3.0',
       'pending_phase': None,
       'policy_sha': 'dddddddddddddddddddddddddddddddddddddddd'},
      ()),
     ('legacy_repository_slash_only',
      {'repository': '/', 'pending_phase': None},
      ()),
     ('legacy_refs_minimal',
      {'base_ref': 'roadmap/2-', 'head_ref': '', 'pending_phase': None},
      ()),
     ('task_done_status_before_terminal_phase',
      {'pending_phase': None, 'status': 'TASK_DONE'},
      ()),
     ('ready_postmerge_with_merge',
      {'phase': 'POST_MERGE',
       'completed_phases': ['RUN_TASK', 'PR_CI', 'MERGE', 'POST_MERGE'],
       'pending_phase': None,
       'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc'},
      ()),
     ('paused_boolean_times_repeated_windows',
      {'pending_phase': None,
       'status': 'PAUSED_RATE_LIMIT',
       'rate_limit_pause': {'exhausted_windows': ['primary', 'primary'],
                            'resets_at': False,
                            'next_check_at': True}},
      ()),
     ('paused_negative_unordered_times',
      {'pending_phase': None,
       'status': 'PAUSED_RATE_LIMIT',
       'rate_limit_pause': {'exhausted_windows': ['secondary', 'primary'],
                            'resets_at': -1,
                            'next_check_at': -9}},
      ()),
     ('paused_null_times',
      {'pending_phase': None,
       'status': 'PAUSED_RATE_LIMIT',
       'rate_limit_pause': {'exhausted_windows': ['secondary'],
                            'resets_at': None,
                            'next_check_at': None}},
      ())]
)

CONTROLLED_CASES: list[tuple[str, dict[str, object], tuple[str, ...]]] = (
    [('missing_schema_version',
      {'pending_phase': None},
      ('schema_version',)),
     ('missing_repository', {'pending_phase': None}, ('repository',)),
     ('missing_epic', {'pending_phase': None}, ('epic',)),
     ('missing_task', {'pending_phase': None}, ('task',)),
     ('missing_pr', {'pending_phase': None}, ('pr',)),
     ('missing_base_ref', {'pending_phase': None}, ('base_ref',)),
     ('missing_base_sha', {'pending_phase': None}, ('base_sha',)),
     ('missing_head_ref', {'pending_phase': None}, ('head_ref',)),
     ('missing_head_sha', {'pending_phase': None}, ('head_sha',)),
     ('missing_phase', {'pending_phase': None}, ('phase',)),
     ('missing_completed_phases',
      {'pending_phase': None},
      ('completed_phases',)),
     ('missing_pending_phase', {}, ('pending_phase',)),
     ('missing_merge_sha', {'pending_phase': None}, ('merge_sha',)),
     ('missing_status', {'pending_phase': None}, ('status',)),
     ('missing_rate_limit_pause',
      {'pending_phase': None},
      ('rate_limit_pause',)),
     ('unknown_key', {'pending_phase': None, 'extra': None}, ()),
     ('v1_extra_policy',
      {'pending_phase': None,
       'policy_sha': 'dddddddddddddddddddddddddddddddddddddddd'},
      ()),
     ('v2_extra_policy',
      {'schema_version': '2.0',
       'pending_phase': None,
       'policy_sha': 'dddddddddddddddddddddddddddddddddddddddd'},
      ()),
     ('v3_missing_policy',
      {'schema_version': '3.0', 'pending_phase': None},
      ()),
     ('version_unsupported',
      {'schema_version': '4.0', 'pending_phase': None},
      ()),
     ('version_null',
      {'schema_version': None, 'pending_phase': None},
      ()),
     ('version_bool',
      {'schema_version': True, 'pending_phase': None},
      ()),
     ('repository_null', {'repository': None, 'pending_phase': None}, ()),
     ('repository_bool',
      {'repository': False, 'pending_phase': None},
      ()),
     ('repository_none',
      {'repository': 'no-slash', 'pending_phase': None},
      ()),
     ('repository_two',
      {'repository': 'a/b/c', 'pending_phase': None},
      ()),
     ('epic_true', {'epic': True, 'pending_phase': None}, ()),
     ('epic_false', {'epic': False, 'pending_phase': None}, ()),
     ('epic_zero', {'epic': 0, 'pending_phase': None}, ()),
     ('epic_negative', {'epic': -1, 'pending_phase': None}, ()),
     ('epic_float', {'epic': 2.0, 'pending_phase': None}, ()),
     ('epic_string', {'epic': '2', 'pending_phase': None}, ()),
     ('task_true', {'task': True, 'pending_phase': None}, ()),
     ('task_false', {'task': False, 'pending_phase': None}, ()),
     ('task_zero', {'task': 0, 'pending_phase': None}, ()),
     ('task_negative', {'task': -1, 'pending_phase': None}, ()),
     ('task_float', {'task': 2.0, 'pending_phase': None}, ()),
     ('task_string', {'task': '2', 'pending_phase': None}, ()),
     ('same_epic_task', {'task': 2, 'pending_phase': None}, ()),
     ('v1_pr_true', {'pr': True, 'pending_phase': None}, ()),
     ('v1_pr_false', {'pr': False, 'pending_phase': None}, ()),
     ('v1_pr_zero', {'pr': 0, 'pending_phase': None}, ()),
     ('v1_pr_negative', {'pr': -1, 'pending_phase': None}, ()),
     ('v1_pr_null', {'pr': None, 'pending_phase': None}, ()),
     ('v1_pr_string', {'pr': '5', 'pending_phase': None}, ()),
     ('v1_pr_float', {'pr': 5.0, 'pending_phase': None}, ()),
     ('v2_null_pr_not_plan',
      {'schema_version': '2.0',
       'pr': None,
       'phase': 'RUN_TASK',
       'completed_phases': ['RUN_TASK'],
       'pending_phase': None},
      ()),
     ('v3_null_pr_not_plan',
      {'schema_version': '3.0',
       'pr': None,
       'phase': 'RUN_TASK',
       'completed_phases': ['RUN_TASK'],
       'pending_phase': None,
       'policy_sha': 'dddddddddddddddddddddddddddddddddddddddd'},
      ()),
     ('base_sha_uppercase',
      {'base_sha': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
       'pending_phase': None},
      ()),
     ('base_sha_short',
      {'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
       'pending_phase': None},
      ()),
     ('base_sha_long',
      {'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
       'pending_phase': None},
      ()),
     ('base_sha_typed_digest',
      {'base_sha': ('sha256:aaaaaaaaaaaaaaaaaaaaaaa'
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
       'pending_phase': None},
      ()),
     ('base_sha_null', {'base_sha': None, 'pending_phase': None}, ()),
     ('base_sha_integer', {'base_sha': 7, 'pending_phase': None}, ()),
     ('head_sha_uppercase',
      {'head_sha': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
       'pending_phase': None},
      ()),
     ('head_sha_short',
      {'head_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
       'pending_phase': None},
      ()),
     ('head_sha_long',
      {'head_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
       'pending_phase': None},
      ()),
     ('head_sha_typed_digest',
      {'head_sha': ('sha256:aaaaaaaaaaaaaaaaaaaaaaa'
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
       'pending_phase': None},
      ()),
     ('head_sha_null', {'head_sha': None, 'pending_phase': None}, ()),
     ('head_sha_integer', {'head_sha': 7, 'pending_phase': None}, ()),
     ('policy_uppercase',
      {'schema_version': '3.0',
       'pending_phase': None,
       'policy_sha': 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD'},
      ()),
     ('policy_short',
      {'schema_version': '3.0',
       'pending_phase': None,
       'policy_sha': 'ddddddddddddddddddddddddddddddddddddddd'},
      ()),
     ('policy_long',
      {'schema_version': '3.0',
       'pending_phase': None,
       'policy_sha': 'ddddddddddddddddddddddddddddddddddddddddd'},
      ()),
     ('policy_typed_digest',
      {'schema_version': '3.0',
       'pending_phase': None,
       'policy_sha': ('sha256:ddddddddddddddddddddddd'
                      'ddddddddddddddddddddddddddddddddddddddddd')},
      ()),
     ('policy_null',
      {'schema_version': '3.0',
       'pending_phase': None,
       'policy_sha': None},
      ()),
     ('policy_integer',
      {'schema_version': '3.0', 'pending_phase': None, 'policy_sha': 7},
      ()),
     ('base_ref_wrong_epic',
      {'base_ref': 'roadmap/3-checkpoints', 'pending_phase': None},
      ()),
     ('base_ref_main', {'base_ref': 'main', 'pending_phase': None}, ()),
     ('base_ref_null', {'base_ref': None, 'pending_phase': None}, ()),
     ('base_ref_integer', {'base_ref': 5, 'pending_phase': None}, ()),
     ('head_ref_roadmap',
      {'head_ref': 'roadmap/2-other', 'pending_phase': None},
      ()),
     ('head_ref_null', {'head_ref': None, 'pending_phase': None}, ()),
     ('head_ref_integer', {'head_ref': 5, 'pending_phase': None}, ()),
     ('phase_unknown', {'phase': 'RUNNING', 'pending_phase': None}, ()),
     ('phase_case', {'phase': 'plan', 'pending_phase': None}, ()),
     ('phase_null', {'phase': None, 'pending_phase': None}, ()),
     ('phase_integer', {'phase': 5, 'pending_phase': None}, ()),
     ('completed_not_list',
      {'completed_phases': None, 'pending_phase': None},
      ()),
     ('completed_includes_plan',
      {'completed_phases': ['PLAN'], 'pending_phase': None},
      ()),
     ('plan_completed_future',
      {'completed_phases': ['RUN_TASK'], 'pending_phase': None},
      ()),
     ('phase_skipped_completed',
      {'phase': 'PR_CI',
       'completed_phases': ['PR_CI'],
       'pending_phase': None},
      ()),
     ('phase_reordered_completed',
      {'phase': 'PR_CI',
       'completed_phases': ['PR_CI', 'RUN_TASK'],
       'pending_phase': None},
      ()),
     ('phase_duplicate_completed',
      {'phase': 'PR_CI',
       'completed_phases': ['RUN_TASK', 'RUN_TASK', 'PR_CI'],
       'pending_phase': None},
      ()),
     ('pending_current_phase', {'pending_phase': 'PLAN'}, ()),
     ('pending_skips_phase', {'pending_phase': 'PR_CI'}, ()),
     ('merge_too_early',
      {'pending_phase': None,
       'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc'},
      ()),
     ('postmerge_missing_merge',
      {'phase': 'POST_MERGE',
       'completed_phases': ['RUN_TASK', 'PR_CI', 'MERGE', 'POST_MERGE'],
       'pending_phase': None},
      ()),
     ('merge_uppercase',
      {'phase': 'POST_MERGE',
       'completed_phases': ['RUN_TASK', 'PR_CI', 'MERGE', 'POST_MERGE'],
       'pending_phase': None,
       'merge_sha': 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'},
      ()),
     ('merge_short',
      {'phase': 'POST_MERGE',
       'completed_phases': ['RUN_TASK', 'PR_CI', 'MERGE', 'POST_MERGE'],
       'pending_phase': None,
       'merge_sha': 'ccccccccccccccccccccccccccccccccccccccc'},
      ()),
     ('merge_typed_digest',
      {'phase': 'POST_MERGE',
       'completed_phases': ['RUN_TASK', 'PR_CI', 'MERGE', 'POST_MERGE'],
       'pending_phase': None,
       'merge_sha': ('sha256:ccccccccccccccccccccccc'
                     'ccccccccccccccccccccccccccccccccccccccccc')},
      ()),
     ('merge_integer',
      {'phase': 'POST_MERGE',
       'completed_phases': ['RUN_TASK', 'PR_CI', 'MERGE', 'POST_MERGE'],
       'pending_phase': None,
       'merge_sha': 3},
      ()),
     ('status_unknown',
      {'pending_phase': None, 'status': 'TERMINAL'},
      ()),
     ('status_case', {'pending_phase': None, 'status': 'ready'}, ()),
     ('status_null', {'pending_phase': None, 'status': None}, ()),
     ('status_integer', {'pending_phase': None, 'status': 0}, ()),
     ('next_task_not_done_status',
      {'phase': 'NEXT_TASK',
       'completed_phases': ['RUN_TASK',
                            'PR_CI',
                            'MERGE',
                            'POST_MERGE',
                            'DEMO',
                            'TASK_DONE',
                            'NEXT_TASK'],
       'pending_phase': None,
       'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc'},
      ()),
     ('next_task_has_pending',
      {'phase': 'NEXT_TASK',
       'completed_phases': ['RUN_TASK',
                            'PR_CI',
                            'MERGE',
                            'POST_MERGE',
                            'DEMO',
                            'TASK_DONE',
                            'NEXT_TASK'],
       'pending_phase': 'PLAN',
       'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc',
       'status': 'TASK_DONE'},
      ()),
     ('paused_missing_pause',
      {'pending_phase': None, 'status': 'PAUSED_RATE_LIMIT'},
      ()),
     ('ready_has_pause',
      {'pending_phase': None,
       'rate_limit_pause': {'exhausted_windows': ['primary'],
                            'resets_at': None,
                            'next_check_at': None}},
      ()),
     ('pause_null',
      {'pending_phase': None, 'status': 'PAUSED_RATE_LIMIT'},
      ()),
     ('pause_empty_map',
      {'pending_phase': None,
       'status': 'PAUSED_RATE_LIMIT',
       'rate_limit_pause': {}},
      ()),
     ('pause_empty_windows',
      {'pending_phase': None,
       'status': 'PAUSED_RATE_LIMIT',
       'rate_limit_pause': {'exhausted_windows': [],
                            'resets_at': None,
                            'next_check_at': None}},
      ()),
     ('pause_unknown_window',
      {'pending_phase': None,
       'status': 'PAUSED_RATE_LIMIT',
       'rate_limit_pause': {'exhausted_windows': ['tertiary'],
                            'resets_at': None,
                            'next_check_at': None}},
      ()),
     ('pause_string_reset',
      {'pending_phase': None,
       'status': 'PAUSED_RATE_LIMIT',
       'rate_limit_pause': {'exhausted_windows': ['primary'],
                            'resets_at': '0',
                            'next_check_at': None}},
      ()),
     ('pause_float_next',
      {'pending_phase': None,
       'status': 'PAUSED_RATE_LIMIT',
       'rate_limit_pause': {'exhausted_windows': ['primary'],
                            'resets_at': None,
                            'next_check_at': 0.5}},
      ()),
     ('pause_extra_key',
      {'pending_phase': None,
       'status': 'PAUSED_RATE_LIMIT',
       'rate_limit_pause': {'exhausted_windows': ['primary'],
                            'resets_at': None,
                            'next_check_at': None,
                            'extra': 0}},
      ())]
)

OUTER_CASES: list[tuple[str, object]] = (
    [('outer_null', None),
     ('outer_list', []),
     ('outer_string', 'checkpoint'),
     ('outer_integer', 7)]
)

NATIVE_CASES: list[tuple[str, dict[str, object], tuple[str, ...]]] = (
    [('unhashable_schema_version',
      {'schema_version': [], 'pending_phase': None},
      ()),
     ('unhashable_status', {'pending_phase': None, 'status': []}, ()),
     ('unhashable_pause_window',
      {'pending_phase': None,
       'status': 'PAUSED_RATE_LIMIT',
       'rate_limit_pause': {'exhausted_windows': [[]],
                            'resets_at': None,
                            'next_check_at': None}},
      ())]
)

PHASE_ROWS: list[dict[str, object]] = (
    [{'phase': 'PLAN',
      'completed': [],
      'next': 'RUN_TASK',
      'merge': None,
      'status': 'READY'},
     {'phase': 'RUN_TASK',
      'completed': ['RUN_TASK'],
      'next': 'PR_CI',
      'merge': None,
      'status': 'RUNNING'},
     {'phase': 'PR_CI',
      'completed': ['RUN_TASK', 'PR_CI'],
      'next': 'MERGE',
      'merge': None,
      'status': 'BLOCKED'},
     {'phase': 'MERGE',
      'completed': ['RUN_TASK', 'PR_CI', 'MERGE'],
      'next': 'POST_MERGE',
      'merge': None,
      'status': 'ESCALATE'},
     {'phase': 'POST_MERGE',
      'completed': ['RUN_TASK', 'PR_CI', 'MERGE', 'POST_MERGE'],
      'next': 'DEMO',
      'merge': 'cccccccccccccccccccccccccccccccccccccccc',
      'status': 'READY'},
     {'phase': 'DEMO',
      'completed': ['RUN_TASK', 'PR_CI', 'MERGE', 'POST_MERGE', 'DEMO'],
      'next': 'TASK_DONE',
      'merge': 'cccccccccccccccccccccccccccccccccccccccc',
      'status': 'READY'},
     {'phase': 'TASK_DONE',
      'completed': ['RUN_TASK',
                    'PR_CI',
                    'MERGE',
                    'POST_MERGE',
                    'DEMO',
                    'TASK_DONE'],
      'next': 'NEXT_TASK',
      'merge': 'cccccccccccccccccccccccccccccccccccccccc',
      'status': 'TASK_DONE'},
     {'phase': 'NEXT_TASK',
      'completed': ['RUN_TASK',
                    'PR_CI',
                    'MERGE',
                    'POST_MERGE',
                    'DEMO',
                    'TASK_DONE',
                    'NEXT_TASK'],
      'next': None,
      'merge': 'cccccccccccccccccccccccccccccccccccccccc',
      'status': 'TASK_DONE'}]
)


def checkpoint(
    updates: dict[str, object] | None = None, missing: tuple[str, ...] = ()
) -> dict[str, object]:
    supplied = copy.deepcopy(BASE)
    if updates is not None:
        supplied.update(copy.deepcopy(updates))
    for name in missing:
        del supplied[name]
    return supplied


@pytest.mark.parametrize(
    "updates,missing",
    [
        pytest.param(updates, missing, id=name)
        for name, updates, missing in ACCEPTED_CASES
    ],
)
def test_accepted_literal_semantics_are_not_authority(
    updates: dict[str, object], missing: tuple[str, ...]
) -> None:
    supplied = checkpoint(updates, missing)
    original = copy.deepcopy(supplied)
    validated = validate_checkpoint(supplied)
    assert validated == supplied == original
    assert type(validated) is dict and validated is not supplied
    assert validated["completed_phases"] is supplied["completed_phases"]
    assert len(validated) == (16 if supplied["schema_version"] == "3.0" else 15)
    # A shallow structural return is not source, state durability or effect proof.


@pytest.mark.parametrize(
    "updates,missing",
    [
        pytest.param(updates, missing, id=name)
        for name, updates, missing in CONTROLLED_CASES
    ],
)
def test_original_controlled_failures(
    updates: dict[str, object], missing: tuple[str, ...]
) -> None:
    supplied = checkpoint(updates, missing)
    original = copy.deepcopy(supplied)
    with pytest.raises(LoopError) as error:
        validate_checkpoint(supplied)
    assert error.value.machine_code == "CHECKPOINT_INVALID"
    assert str(error.value) == "CHECKPOINT_INVALID"
    assert supplied == original


@pytest.mark.parametrize(
    "supplied", [pytest.param(value, id=name) for name, value in OUTER_CASES]
)
def test_original_non_mapping_failures(supplied: object) -> None:
    with pytest.raises(LoopError) as error:
        validate_checkpoint(supplied)
    assert error.value.machine_code == "CHECKPOINT_INVALID"


@pytest.mark.parametrize(
    "updates,missing",
    [
        pytest.param(updates, missing, id=name)
        for name, updates, missing in NATIVE_CASES
    ],
)
def test_original_native_type_errors_are_not_silently_normalized(
    updates: dict[str, object], missing: tuple[str, ...]
) -> None:
    supplied = checkpoint(updates, missing)
    original = copy.deepcopy(supplied)
    with pytest.raises(TypeError):
        validate_checkpoint(supplied)
    assert supplied == original


@pytest.mark.parametrize(
    "row", PHASE_ROWS, ids=[str(row["phase"]) for row in PHASE_ROWS]
)
def test_handwritten_phase_prefix_pending_and_merge_oracles(
    row: dict[str, object],
) -> None:
    assert PHASES == (
        "PLAN", "RUN_TASK", "PR_CI", "MERGE", "POST_MERGE", "DEMO", "TASK_DONE",
        "NEXT_TASK",
    )
    supplied = checkpoint({
        "phase": row["phase"], "completed_phases": row["completed"],
        "pending_phase": row["next"], "merge_sha": row["merge"],
        "status": row["status"],
    })
    assert validate_checkpoint(supplied) == supplied
    assert _next_phase(str(row["phase"])) == row["next"]


def test_mapping_proxy_is_accepted_with_fresh_shallow_dict_return() -> None:
    supplied = checkpoint()
    original = copy.deepcopy(supplied)
    proxy = MappingProxyType(supplied)
    validated = validate_checkpoint(proxy)
    assert validated == supplied == original
    assert type(validated) is dict
    assert validated is not supplied
    assert validated["completed_phases"] is supplied["completed_phases"]


def test_completed_tuple_rejected_by_original_list_guard() -> None:
    with pytest.raises(LoopError) as error:
        validate_checkpoint(checkpoint({"completed_phases": ()}))
    assert error.value.machine_code == "CHECKPOINT_INVALID"


def test_pause_window_tuple_rejected_by_original_list_guard() -> None:
    supplied = checkpoint({
        "status": "PAUSED_RATE_LIMIT",
        "rate_limit_pause": {
            "exhausted_windows": ("primary",), "resets_at": None, "next_check_at": None,
        },
    })
    with pytest.raises(LoopError) as error:
        validate_checkpoint(supplied)
    assert error.value.machine_code == "CHECKPOINT_INVALID"


def test_string_subclasses_keep_original_isinstance_semantics() -> None:
    class SyntheticString(str):
        pass

    supplied = checkpoint()
    for name in (
        "schema_version", "repository", "base_ref", "base_sha", "head_ref", "head_sha",
        "phase", "status",
    ):
        supplied[name] = SyntheticString(str(supplied[name]))
    supplied["pending_phase"] = SyntheticString("RUN_TASK")
    validated = validate_checkpoint(supplied)
    assert validated == supplied
    assert validated["repository"] is supplied["repository"]


def test_source_closure_is_only_pinned_pure_predicate_dependencies() -> None:
    source = Path(__file__).resolve().parents[1] / "tools/checkpoint_validation.py"
    tree = ast.parse(source.read_text())
    imports = {
        node.module if isinstance(node, ast.ImportFrom) else alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imports <= {"__future__", "collections.abc", "typing", "re"}
    names = {
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef))
    }
    assert names == {
        "LoopError", "_exact", "_next_phase", "validate_checkpoint", "_positive_id",
        "_valid_rate_limit_pause",
    }
    assert not any(isinstance(node, ast.If) for node in tree.body)
