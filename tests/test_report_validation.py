"""Literal partial legacy validation; no source authority or actual review proof."""

from __future__ import annotations

import ast
import copy
import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest
from tools import report_validation as subject
from tools.schema_validate import SchemaError, load_schema

SEEDS: Any = {'status': 'INERT_HANDWRITTEN_LITERAL_INPUTS_NOT_TESTED',
 'contract': {'issue': 3,
              'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
              'max_report_chars': 10000},
 'head_sha_argument': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
 'report': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
 'verdict': {'schema_version': '1.0',
             'role': 'controller',
             'task_issue': 3,
             'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
             'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
             'review_basis': {'trust_source_kind': 'base_sha',
                              'head_policy_applied': False,
                              'executor_self_assessment_treated_as_evidence_only':
                                  True},
             'verdict': 'PASS',
             'repair_iteration': 0,
             'escalation_reason': None,
             'blocking_findings': [],
             'notes': ['synthetic note']},
 'expected_source_owned_enum': ['base_sha', 'local_read_only_bundle'],
 'budget_qualification': '10000 '
                         'isuntrustedsyntheticcontractfixtureonly, '
                         'notproductiondefault/runtimebudget/permission; '
                         'no operationalTaskContract constructed',
 'scope_qualification': 'FutureprivateProtocolhasthree '
                        'readonlyproperties only; annotationseam '
                        'createsno constructor/default/effectgrant'}

REPORT_ROWS: Any = [{'id': 'status_completed',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_return': None},
 {'id': 'status_blocked',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'blocked',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_return': None},
 {'id': 'status_needs_human',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'needs_human',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_return': None},
 {'id': 'nested_shapes_not_validated_here',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': None,
            'changed_files': 123,
            'checks': True,
            'residual_risks': {'not': 'deeply-validated'},
            'stop_reason': False},
  'expected_return': None,
  'qualification': 'Originalpartialroot/sizeguard, notfull executor '
                   'schema approval'},
 {'id': 'task_bool_equality',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': True,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'contract_updates': {'issue': 1},
  'expected_return': None,
  'qualification': 'Originaltupleequality True==1; no '
                   'addedinttypeguard'},
 {'id': 'task_float_equality',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3.0,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_return': None,
  'qualification': 'Originaltupleequality 3.0==3; no all-schema '
                   'validation claim'},
 {'id': 'missing_schema_version',
  'input': {'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'missing_role',
  'input': {'schema_version': '1.0',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'missing_task_issue',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'missing_base_sha',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'missing_head_sha',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'status': 'completed',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'missing_status',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'missing_acceptance_criteria',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'missing_changed_files',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['synthetic criterion'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'missing_checks',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'residual_risks': [],
            'stop_reason': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'missing_residual_risks',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'stop_reason': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'missing_stop_reason',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': []},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'unknown_review_basis',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None,
            'review_basis': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'unknown_extra',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None,
            'extra': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'wrong_schema_version_2.0',
  'input': {'schema_version': '2.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'wrong_role_controller',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'wrong_task_issue_4',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 4,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'wrong_base_sha_cccccccccccccccccccccccccccccccccccccccc',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'cccccccccccccccccccccccccccccccccccccccc',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'wrong_head_sha_cccccccccccccccccccccccccccccccccccccccc',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'cccccccccccccccccccccccccccccccccccccccc',
            'status': 'completed',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'wrong_status_PASS',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'PASS',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'wrong_status_None',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': None,
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'wrong_status_False',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': False,
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'wrong_status_0',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 0,
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'wrong_status_Completed',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'Completed',
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'outer_null',
  'input': None,
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'outer_list',
  'input': [],
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'outer_string',
  'input': 'synthetic',
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'outer_integer',
  'input': 3,
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'wrong_identity_precedes_unhashable_status',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 4,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': [],
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_machine_code': 'MALFORMED_OUTPUT'}]

VERDICT_ROWS: Any = [{'id': 'PASS_base_sha',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_return': 'PASS'},
 {'id': 'PASS_WITH_NOTES_local_read_only_bundle',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'local_read_only_bundle',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS_WITH_NOTES',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_return': 'PASS_WITH_NOTES'},
 {'id': 'FAIL_RETRY_base_sha',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'FAIL_RETRY',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': ['synthetic finding'],
            'notes': ['synthetic note']},
  'expected_return': 'FAIL_RETRY'},
 {'id': 'FAIL_ESCALATE_local_read_only_bundle',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'local_read_only_bundle',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'FAIL_ESCALATE',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': ['synthetic finding'],
            'notes': ['synthetic note']},
  'expected_return': 'FAIL_ESCALATE'},
 {'id': 'unvalidated_fields_preserved',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': {'ignored': 'shape'},
            'escalation_reason': 123,
            'blocking_findings': [],
            'notes': False},
  'expected_return': 'PASS',
  'qualification': 'Repairiteration/escalation/notes contents '
                   'notindependentlyvalidatedbyoriginalfunction'},
 {'id': 'nonempty_findings_children_not_validated',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'FAIL_RETRY',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [None, {'synthetic': 'value'}],
            'notes': ['synthetic note']},
  'expected_return': 'FAIL_RETRY'},
 {'id': 'task_bool_equality',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': True,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'contract_updates': {'issue': 1},
  'expected_return': 'PASS'},
 {'id': 'task_float_equality',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3.0,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'contract_updates': {'issue': 3},
  'expected_return': 'PASS'},
 {'id': 'missing_schema_version',
  'input': {'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED rootkeycheckfirst'},
 {'id': 'missing_role',
  'input': {'schema_version': '1.0',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED rootkeycheckfirst'},
 {'id': 'missing_task_issue',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED rootkeycheckfirst'},
 {'id': 'missing_base_sha',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED rootkeycheckfirst'},
 {'id': 'missing_head_sha',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED rootkeycheckfirst'},
 {'id': 'missing_review_basis',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED rootkeycheckfirst'},
 {'id': 'missing_verdict',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED rootkeycheckfirst'},
 {'id': 'missing_repair_iteration',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED rootkeycheckfirst'},
 {'id': 'missing_escalation_reason',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED rootkeycheckfirst'},
 {'id': 'missing_blocking_findings',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED rootkeycheckfirst'},
 {'id': 'missing_notes',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': []},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED rootkeycheckfirst'},
 {'id': 'unknown_root_key',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note'],
            'extra': None},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED'},
 {'id': 'wrong_schema_version_2.0',
  'input': {'schema_version': '2.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED ifcachecold becausebasisvalid '
                               'beforeidentity/verdictcheck'},
 {'id': 'wrong_role_executor',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED ifcachecold becausebasisvalid '
                               'beforeidentity/verdictcheck'},
 {'id': 'wrong_task_issue_4',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 4,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED ifcachecold becausebasisvalid '
                               'beforeidentity/verdictcheck'},
 {'id': 'wrong_base_sha_cccccccccccccccccccccccccccccccccccccccc',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'cccccccccccccccccccccccccccccccccccccccc',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED ifcachecold becausebasisvalid '
                               'beforeidentity/verdictcheck'},
 {'id': 'wrong_head_sha_cccccccccccccccccccccccccccccccccccccccc',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'cccccccccccccccccccccccccccccccccccccccc',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED ifcachecold becausebasisvalid '
                               'beforeidentity/verdictcheck'},
 {'id': 'wrong_verdict_pass',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'pass',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED ifcachecold becausebasisvalid '
                               'beforeidentity/verdictcheck'},
 {'id': 'wrong_verdict_None',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': None,
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED ifcachecold becausebasisvalid '
                               'beforeidentity/verdictcheck'},
 {'id': 'wrong_verdict_False',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': False,
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED ifcachecold becausebasisvalid '
                               'beforeidentity/verdictcheck'},
 {'id': 'wrong_verdict_UNKNOWN',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'UNKNOWN',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED ifcachecold becausebasisvalid '
                               'beforeidentity/verdictcheck'},
 {'id': 'basis_null',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': None,
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED '
                               'duebasisstructuralshortcircuit'},
 {'id': 'basis_list',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': [],
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED '
                               'duebasisstructuralshortcircuit'},
 {'id': 'basis_missing_kind',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED '
                               'duebasisstructuralshortcircuit'},
 {'id': 'basis_extra',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only': True,
                             'extra': None},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED '
                               'duebasisstructuralshortcircuit'},
 {'id': 'literal_bool_head_policy_applied_True',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': True,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED '
                               'dueis-identityinvariantshortcircuit'},
 {'id': 'literal_bool_head_policy_applied_0',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': 0,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED '
                               'dueis-identityinvariantshortcircuit'},
 {'id': 'literal_bool_head_policy_applied_None',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': None,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED '
                               'dueis-identityinvariantshortcircuit'},
 {'id': 'literal_bool_executor_self_assessment_treated_as_evidence_only_False',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                 False},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED '
                               'dueis-identityinvariantshortcircuit'},
 {'id': 'literal_bool_executor_self_assessment_treated_as_evidence_only_1',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only': 1},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED '
                               'dueis-identityinvariantshortcircuit'},
 {'id': 'literal_bool_executor_self_assessment_treated_as_evidence_only_None',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only': None},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED '
                               'dueis-identityinvariantshortcircuit'},
 {'id': 'unknown_source_kind_head_sha',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'head_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED ifcachecold '
                               'thenmembershipfalse'},
 {'id': 'unknown_source_kind_model_output',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'model_output',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED ifcachecold '
                               'thenmembershipfalse'},
 {'id': 'unknown_source_kind_',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': '',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED ifcachecold '
                               'thenmembershipfalse'},
 {'id': 'unknown_source_kind_None',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': None,
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED ifcachecold '
                               'thenmembershipfalse'},
 {'id': 'unknown_source_kind_False',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': False,
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED ifcachecold '
                               'thenmembershipfalse'},
 {'id': "findings_PASS_['synthetic finding']",
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': ['synthetic finding'],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED ifcachecold '
                               'beforefindingscheck'},
 {'id': "findings_PASS_WITH_NOTES_['synthetic finding']",
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS_WITH_NOTES',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': ['synthetic finding'],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED ifcachecold '
                               'beforefindingscheck'},
 {'id': 'findings_FAIL_RETRY_[]',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'FAIL_RETRY',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED ifcachecold '
                               'beforefindingscheck'},
 {'id': 'findings_FAIL_ESCALATE_[]',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'FAIL_ESCALATE',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED ifcachecold '
                               'beforefindingscheck'},
 {'id': 'findings_PASS_None',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': None,
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED ifcachecold '
                               'beforefindingscheck'},
 {'id': 'findings_PASS_{}',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': {},
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED ifcachecold '
                               'beforefindingscheck'},
 {'id': 'findings_PASS_synthetic',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': 'synthetic',
            'notes': ['synthetic note']},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED ifcachecold '
                               'beforefindingscheck'},
 {'id': 'outer_null',
  'input': None,
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED'},
 {'id': 'outer_list',
  'input': [],
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED'},
 {'id': 'outer_string',
  'input': 'synthetic',
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED'}]

REPORT_NATIVE: Any = [{'id': 'unhashable_status',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': [],
            'acceptance_criteria': ['synthetic criterion'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'expected_exception': 'TypeError',
  'because': 'Identitymatches thenoriginalsetmembership; no catch'},
 {'id': 'nonserializable_nested_set',
  'construction': 'Base report checks={synthetic}; identity/status '
                  'valid',
  'expected_exception': 'TypeError',
  'because': 'Originaljson.dumps outsidecatch'},
 {'id': 'max_chars_wrongtype',
  'construction': 'Base report andprivatecontract '
                  'max_report_chars="large"',
  'expected_exception': 'TypeError',
  'because': 'OutsidedeclaredintProtocoldomain; originalcomparison '
             'outsidecatch'}]

VERDICT_NATIVE: Any = [{'id': 'unhashable_kind',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': [],
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_exception': 'TypeError',
  'because': 'Reader evaluatedfirstrightoperand '
             'thensetmembershiphashfails ifresourceworking'},
 {'id': 'unhashable_verdict',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': [],
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'expected_exception': 'TypeError',
  'because': 'validbasis computed thenverdictsetmembership; no '
             'normalization'},
 {'id': 'nonserializable_notes_set',
  'construction': 'Base verdict notes={synthetic}, otherguardsvalid',
  'expected_exception': 'TypeError',
  'because': 'Originaljson.dumps outsidecatch'}]

SIZE_ROWS: Any = [{'id': 'report_equal',
  'operation': 'report',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['é'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'contract_updates': {'max_report_chars': 320},
  'expected_return': None,
  'expected_machine_code': None,
  'literal_serialized_text': '{"schema_version": "1.0", "role": '
                             '"executor", "task_issue": 3, '
                             '"base_sha": '
                             '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", '
                             '"head_sha": '
                             '"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", '
                             '"status": "completed", '
                             '"acceptance_criteria": ["é"], '
                             '"changed_files": ["synthetic.txt"], '
                             '"checks": [], "residual_risks": [], '
                             '"stop_reason": null}',
  'literal_character_count': 320,
  'literal_utf8_byte_count': 321,
  'qualification': 'Handwrittenserializedliteral/count '
                   'isindependentofprojectvalidator; stdlibjson '
                   'reencoding onlyverifiedinputcorrespondence. '
                   'Characterlimit, notUTF8bytelimit; fixturevalue '
                   'notruntimebudget.'},
 {'id': 'report_one_less',
  'operation': 'report',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['é'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'contract_updates': {'max_report_chars': 319},
  'expected_return': None,
  'expected_machine_code': 'OUTPUT_LIMIT',
  'literal_serialized_text': '{"schema_version": "1.0", "role": '
                             '"executor", "task_issue": 3, '
                             '"base_sha": '
                             '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", '
                             '"head_sha": '
                             '"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", '
                             '"status": "completed", '
                             '"acceptance_criteria": ["é"], '
                             '"changed_files": ["synthetic.txt"], '
                             '"checks": [], "residual_risks": [], '
                             '"stop_reason": null}',
  'literal_character_count': 320,
  'literal_utf8_byte_count': 321,
  'qualification': 'Handwrittenserializedliteral/count '
                   'isindependentofprojectvalidator; stdlibjson '
                   'reencoding onlyverifiedinputcorrespondence. '
                   'Characterlimit, notUTF8bytelimit; fixturevalue '
                   'notruntimebudget.'},
 {'id': 'report_one_more',
  'operation': 'report',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['é'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'contract_updates': {'max_report_chars': 321},
  'expected_return': None,
  'expected_machine_code': None,
  'literal_serialized_text': '{"schema_version": "1.0", "role": '
                             '"executor", "task_issue": 3, '
                             '"base_sha": '
                             '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", '
                             '"head_sha": '
                             '"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", '
                             '"status": "completed", '
                             '"acceptance_criteria": ["é"], '
                             '"changed_files": ["synthetic.txt"], '
                             '"checks": [], "residual_risks": [], '
                             '"stop_reason": null}',
  'literal_character_count': 320,
  'literal_utf8_byte_count': 321,
  'qualification': 'Handwrittenserializedliteral/count '
                   'isindependentofprojectvalidator; stdlibjson '
                   'reencoding onlyverifiedinputcorrespondence. '
                   'Characterlimit, notUTF8bytelimit; fixturevalue '
                   'notruntimebudget.'},
 {'id': 'verdict_equal',
  'operation': 'verdict',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['é']},
  'contract_updates': {'max_report_chars': 426},
  'expected_return': 'PASS',
  'expected_machine_code': None,
  'literal_serialized_text': '{"schema_version": "1.0", "role": '
                             '"controller", "task_issue": 3, '
                             '"base_sha": '
                             '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", '
                             '"head_sha": '
                             '"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", '
                             '"review_basis": {"trust_source_kind": '
                             '"base_sha", "head_policy_applied": '
                             'false, '
                             '"executor_self_assessment_treated_as_evidence_only": '
                             'true}, "verdict": "PASS", '
                             '"repair_iteration": 0, '
                             '"escalation_reason": null, '
                             '"blocking_findings": [], "notes": '
                             '["é"]}',
  'literal_character_count': 426,
  'literal_utf8_byte_count': 427,
  'qualification': 'Handwrittenserializedliteral/count '
                   'isindependentofprojectvalidator; stdlibjson '
                   'reencoding onlyverifiedinputcorrespondence. '
                   'Characterlimit, notUTF8bytelimit; fixturevalue '
                   'notruntimebudget.'},
 {'id': 'verdict_one_less',
  'operation': 'verdict',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['é']},
  'contract_updates': {'max_report_chars': 425},
  'expected_return': None,
  'expected_machine_code': 'OUTPUT_LIMIT',
  'literal_serialized_text': '{"schema_version": "1.0", "role": '
                             '"controller", "task_issue": 3, '
                             '"base_sha": '
                             '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", '
                             '"head_sha": '
                             '"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", '
                             '"review_basis": {"trust_source_kind": '
                             '"base_sha", "head_policy_applied": '
                             'false, '
                             '"executor_self_assessment_treated_as_evidence_only": '
                             'true}, "verdict": "PASS", '
                             '"repair_iteration": 0, '
                             '"escalation_reason": null, '
                             '"blocking_findings": [], "notes": '
                             '["é"]}',
  'literal_character_count': 426,
  'literal_utf8_byte_count': 427,
  'qualification': 'Handwrittenserializedliteral/count '
                   'isindependentofprojectvalidator; stdlibjson '
                   'reencoding onlyverifiedinputcorrespondence. '
                   'Characterlimit, notUTF8bytelimit; fixturevalue '
                   'notruntimebudget.'},
 {'id': 'verdict_one_more',
  'operation': 'verdict',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['é']},
  'contract_updates': {'max_report_chars': 427},
  'expected_return': 'PASS',
  'expected_machine_code': None,
  'literal_serialized_text': '{"schema_version": "1.0", "role": '
                             '"controller", "task_issue": 3, '
                             '"base_sha": '
                             '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", '
                             '"head_sha": '
                             '"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", '
                             '"review_basis": {"trust_source_kind": '
                             '"base_sha", "head_policy_applied": '
                             'false, '
                             '"executor_self_assessment_treated_as_evidence_only": '
                             'true}, "verdict": "PASS", '
                             '"repair_iteration": 0, '
                             '"escalation_reason": null, '
                             '"blocking_findings": [], "notes": '
                             '["é"]}',
  'literal_character_count': 426,
  'literal_utf8_byte_count': 427,
  'qualification': 'Handwrittenserializedliteral/count '
                   'isindependentofprojectvalidator; stdlibjson '
                   'reencoding onlyverifiedinputcorrespondence. '
                   'Characterlimit, notUTF8bytelimit; fixturevalue '
                   'notruntimebudget.'},
 {'id': 'report_identity_before_size',
  'operation': 'report',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'status': 'completed',
            'acceptance_criteria': ['é'],
            'changed_files': ['synthetic.txt'],
            'checks': [],
            'residual_risks': [],
            'stop_reason': None},
  'contract_updates': {'max_report_chars': 0},
  'expected_machine_code': 'MALFORMED_OUTPUT'},
 {'id': 'verdict_identity_before_size_resource_working',
  'operation': 'verdict',
  'input': {'schema_version': '1.0',
            'role': 'executor',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['é']},
  'contract_updates': {'max_report_chars': 0},
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED beforeidentity '
                               'becausebasisvalid'}]

PRECEDENCE_ROWS: Any = [{'id': 'wrong_identity_resource_failure_first',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 4,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'resource_fixture': 'load_schema raisesfixedsyntheticOSError '
                      'ifcalled aftercache_clear',
  'expected_machine_code': 'TRUST_SCHEMA_UNAVAILABLE',
  'canonical_reader_expected': 'CALLED '
                               'beforeidentity/verdict/findings'},
 {'id': 'wrong_verdict_resource_failure_first',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'unknown',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'resource_fixture': 'load_schema raisesfixedsyntheticOSError '
                      'ifcalled aftercache_clear',
  'expected_machine_code': 'TRUST_SCHEMA_UNAVAILABLE',
  'canonical_reader_expected': 'CALLED '
                               'beforeidentity/verdict/findings'},
 {'id': 'bad_findings_resource_failure_first',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': None,
            'notes': ['synthetic note']},
  'resource_fixture': 'load_schema raisesfixedsyntheticOSError '
                      'ifcalled aftercache_clear',
  'expected_machine_code': 'TRUST_SCHEMA_UNAVAILABLE',
  'canonical_reader_expected': 'CALLED '
                               'beforeidentity/verdict/findings'},
 {'id': 'unknown_kind_resource_failure_first',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'model_output',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'resource_fixture': 'load_schema raisesfixedsyntheticOSError '
                      'ifcalled aftercache_clear',
  'expected_machine_code': 'TRUST_SCHEMA_UNAVAILABLE',
  'canonical_reader_expected': 'CALLED beforemembershipcanbefalse'},
 {'id': 'unhashable_kind_resource_failure_first',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': [],
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'resource_fixture': 'load_schema raisesfixedsyntheticOSError '
                      'ifcalled aftercache_clear',
  'expected_machine_code': 'TRUST_SCHEMA_UNAVAILABLE',
  'canonical_reader_expected': 'CALLED '
                               'beforesetmembershipcanraiseTypeError'},
 {'id': 'bad_bool_basis_shortcircuits_resource',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': 0,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'resource_fixture': 'load_schema raisesfixedsyntheticOSError '
                      'ifcalled aftercache_clear',
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED'},
 {'id': 'missing_basis_key_shortcircuits_resource',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'resource_fixture': 'load_schema raisesfixedsyntheticOSError '
                      'ifcalled aftercache_clear',
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED'},
 {'id': 'extra_basis_key_shortcircuits_resource',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only': True,
                             'extra': None},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'resource_fixture': 'load_schema raisesfixedsyntheticOSError '
                      'ifcalled aftercache_clear',
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED'},
 {'id': 'missing_root_key_before_resource',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': 'PASS',
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': []},
  'resource_fixture': 'load_schema raisesfixedsyntheticOSError '
                      'ifcalled aftercache_clear',
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED'},
 {'id': 'wrong_identity_precedes_unhashable_verdict_resource_working',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 4,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': False,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': [],
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'resource_fixture': 'Genuinepinnedownedresource works',
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'CALLED '
                               'thenactualidentityshortcircuitsverdictset'},
 {'id': 'bad_basis_precedes_unhashable_verdict',
  'input': {'schema_version': '1.0',
            'role': 'controller',
            'task_issue': 3,
            'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'review_basis': {'trust_source_kind': 'base_sha',
                             'head_policy_applied': 0,
                             'executor_self_assessment_treated_as_evidence_only':
                                  True},
            'verdict': [],
            'repair_iteration': 0,
            'escalation_reason': None,
            'blocking_findings': [],
            'notes': ['synthetic note']},
  'resource_fixture': 'irrelevant',
  'expected_machine_code': 'MALFORMED_OUTPUT',
  'canonical_reader_expected': 'NOT_CALLED; '
                               'notvalid_basisshortcircuitsverdictset'}]

RESOURCE_ROWS: Any = [{'id': 'load_schema_raises_OSError',
  'fixture_boundary': 'Explicitnegative internalresource-loader '
                      'fault injection, notactualsource/authproof; '
                      'cache_clear before/after',
  'construction': 'Makeonlyload_schema raise syntheticfixedmessage '
                  'OSError insideoriginaltry',
  'expected_machine_code': 'TRUST_SCHEMA_UNAVAILABLE',
  'expected_cause': 'Exactcaught exception object; do notflatten '
                    'nestedactualschema-load errorchain '
                    'orformatitscausepublicly'},
 {'id': 'load_schema_raises_ValueError',
  'fixture_boundary': 'Explicitnegative internalresource-loader '
                      'fault injection, notactualsource/authproof; '
                      'cache_clear before/after',
  'construction': 'Makeonlyload_schema raise syntheticfixedmessage '
                  'ValueError insideoriginaltry',
  'expected_machine_code': 'TRUST_SCHEMA_UNAVAILABLE',
  'expected_cause': 'Exactcaught exception object; do notflatten '
                    'nestedactualschema-load errorchain '
                    'orformatitscausepublicly'},
 {'id': 'load_schema_raises_KeyError',
  'fixture_boundary': 'Explicitnegative internalresource-loader '
                      'fault injection, notactualsource/authproof; '
                      'cache_clear before/after',
  'construction': 'Makeonlyload_schema raise syntheticfixedmessage '
                  'KeyError insideoriginaltry',
  'expected_machine_code': 'TRUST_SCHEMA_UNAVAILABLE',
  'expected_cause': 'Exactcaught exception object; do notflatten '
                    'nestedactualschema-load errorchain '
                    'orformatitscausepublicly'},
 {'id': 'load_schema_raises_TypeError',
  'fixture_boundary': 'Explicitnegative internalresource-loader '
                      'fault injection, notactualsource/authproof; '
                      'cache_clear before/after',
  'construction': 'Makeonlyload_schema raise syntheticfixedmessage '
                  'TypeError insideoriginaltry',
  'expected_machine_code': 'TRUST_SCHEMA_UNAVAILABLE',
  'expected_cause': 'Exactcaught exception object; do notflatten '
                    'nestedactualschema-load errorchain '
                    'orformatitscausepublicly'},
 {'id': 'load_schema_raises_SchemaError',
  'fixture_boundary': 'Explicitnegative internalresource-loader '
                      'fault injection, notactualsource/authproof; '
                      'cache_clear before/after',
  'construction': 'Makeonlyload_schema raise syntheticfixedmessage '
                  'SchemaError insideoriginaltry',
  'expected_machine_code': 'TRUST_SCHEMA_UNAVAILABLE',
  'expected_cause': 'Exactcaught exception object; do notflatten '
                    'nestedactualschema-load errorchain '
                    'orformatitscausepublicly'},
 {'id': 'enum_empty',
  'fixture_boundary': 'Explicitinternalresource-result structure '
                      'fixture only; no productionroot/enumparameter',
  'construction': {'load_schema_result_enum': []},
  'expected_machine_code': 'TRUST_SCHEMA_UNAVAILABLE',
  'expected_cause': None,
  'qualification': 'Failureaftertry inoriginallist/nonemptystring '
                   'checks; no newall-errorcatch'},
 {'id': 'enum_null',
  'fixture_boundary': 'Explicitinternalresource-result structure '
                      'fixture only; no productionroot/enumparameter',
  'construction': {'load_schema_result_enum': None},
  'expected_machine_code': 'TRUST_SCHEMA_UNAVAILABLE',
  'expected_cause': None,
  'qualification': 'Failureaftertry inoriginallist/nonemptystring '
                   'checks; no newall-errorcatch'},
 {'id': 'enum_not_list',
  'fixture_boundary': 'Explicitinternalresource-result structure '
                      'fixture only; no productionroot/enumparameter',
  'construction': {'load_schema_result_enum': {}},
  'expected_machine_code': 'TRUST_SCHEMA_UNAVAILABLE',
  'expected_cause': None,
  'qualification': 'Failureaftertry inoriginallist/nonemptystring '
                   'checks; no newall-errorcatch'},
 {'id': 'enum_string',
  'fixture_boundary': 'Explicitinternalresource-result structure '
                      'fixture only; no productionroot/enumparameter',
  'construction': {'load_schema_result_enum': 'base_sha'},
  'expected_machine_code': 'TRUST_SCHEMA_UNAVAILABLE',
  'expected_cause': None,
  'qualification': 'Failureaftertry inoriginallist/nonemptystring '
                   'checks; no newall-errorcatch'},
 {'id': 'enum_nonstring_item',
  'fixture_boundary': 'Explicitinternalresource-result structure '
                      'fixture only; no productionroot/enumparameter',
  'construction': {'load_schema_result_enum': ['base_sha', 1]},
  'expected_machine_code': 'TRUST_SCHEMA_UNAVAILABLE',
  'expected_cause': None,
  'qualification': 'Failureaftertry inoriginallist/nonemptystring '
                   'checks; no newall-errorcatch'},
 {'id': 'enum_empty_item',
  'fixture_boundary': 'Explicitinternalresource-result structure '
                      'fixture only; no productionroot/enumparameter',
  'construction': {'load_schema_result_enum': ['base_sha', '']},
  'expected_machine_code': 'TRUST_SCHEMA_UNAVAILABLE',
  'expected_cause': None,
  'qualification': 'Failureaftertry inoriginallist/nonemptystring '
                   'checks; no newall-errorcatch'},
 {'id': 'enum_bool_item',
  'fixture_boundary': 'Explicitinternalresource-result structure '
                      'fixture only; no productionroot/enumparameter',
  'construction': {'load_schema_result_enum': [True]},
  'expected_machine_code': 'TRUST_SCHEMA_UNAVAILABLE',
  'expected_cause': None,
  'qualification': 'Failureaftertry inoriginallist/nonemptystring '
                   'checks; no newall-errorcatch'},
 {'id': 'missing_properties',
  'fixture_boundary': 'Negativeinternalresource-result indexing '
                      'fixture',
  'construction': {'load_schema_result': {}},
  'expected_machine_code': 'TRUST_SCHEMA_UNAVAILABLE',
  'expected_cause_class': 'KeyError'},
 {'id': 'wrong_schema_type',
  'fixture_boundary': 'Negativeinternalresource-result indexing '
                      'fixture',
  'construction': {'load_schema_result': None},
  'expected_machine_code': 'TRUST_SCHEMA_UNAVAILABLE',
  'expected_cause_class': 'TypeError'},
 {'id': 'missing_kind_enum',
  'fixture_boundary': 'Negativeinternalresource-result indexing '
                      'fixture',
  'construction': {
      'load_schema_result': {
          'properties': {'review_basis': {
              'properties': {'trust_source_kind': {}}
          }}
      }
  },
  'expected_machine_code': 'TRUST_SCHEMA_UNAVAILABLE',
  'expected_cause_class': 'KeyError'},
 {'id': 'duplicate_values_collapse',
  'fixture_boundary': 'Internalstructuralresourcefixture only; no '
                      'newtrustedkind orauthproof',
  'construction': {'load_schema_result_enum': ['base_sha',
                                               'base_sha',
                                               'local_read_only_bundle']},
  'expected_return_frozenset': ['base_sha', 'local_read_only_bundle'],
  'qualification': 'Originalfrozenset collapse, '
                   'notenumuniquenesshardening'}]



@dataclass(frozen=True)
class Contract:
    issue: int
    base_sha: str
    max_report_chars: int


def contract(updates: dict[str, Any] | None = None) -> Contract:
    fields = copy.deepcopy(SEEDS["contract"])
    fields.update(updates or {})
    return Contract(**fields)


def call(operation: str, value: Any, current: Any = None) -> Any:
    current = contract() if current is None else current
    function = (
        subject._validate_report if operation == "report" else subject._validate_verdict
    )
    return function(value, current, SEEDS["head_sha_argument"])


@pytest.fixture(autouse=True)
def isolated_cache() -> Iterator[None]:
    subject._canonical_trust_source_kinds.cache_clear()
    yield
    subject._canonical_trust_source_kinds.cache_clear()


@pytest.mark.parametrize(
    "operation,rows", [("report", REPORT_ROWS), ("verdict", VERDICT_ROWS)]
)
def test_literal_table_inventory_is_closed(operation: str, rows: Any) -> None:
    assert len(rows) == (34 if operation == "report" else 54)
    assert len({row["id"] for row in rows}) == len(rows)


@pytest.mark.parametrize("row", REPORT_ROWS, ids=[row["id"] for row in REPORT_ROWS])
def test_report_literal_outcomes(row: Any) -> None:
    value = copy.deepcopy(row["input"])
    before = copy.deepcopy(value)
    current = contract(row.get("contract_updates"))
    if "expected_machine_code" in row:
        with pytest.raises(subject.OrchestrationError) as error:
            call("report", value, current)
        assert error.value.machine_code == row["expected_machine_code"]
    else:
        assert call("report", value, current) == row["expected_return"]
    assert value == before


@pytest.mark.parametrize("row", VERDICT_ROWS, ids=[row["id"] for row in VERDICT_ROWS])
def test_verdict_literal_outcomes(row: Any) -> None:
    value = copy.deepcopy(row["input"])
    before = copy.deepcopy(value)
    current = contract(row.get("contract_updates"))
    if "expected_machine_code" in row:
        with pytest.raises(subject.OrchestrationError) as error:
            call("verdict", value, current)
        assert error.value.machine_code == row["expected_machine_code"]
    else:
        assert call("verdict", value, current) == row["expected_return"]
    assert value == before


@pytest.mark.parametrize(
    "operation,rows", [("report", REPORT_NATIVE), ("verdict", VERDICT_NATIVE)]
)
@pytest.mark.parametrize("index", range(3))
def test_original_native_errors(operation: str, rows: Any, index: int) -> None:
    row = rows[index]
    value = copy.deepcopy(row.get("input", SEEDS[operation]))
    current: Any = contract()
    if row["id"] == "nonserializable_nested_set":
        value["checks"] = {"synthetic"}
    elif row["id"] == "nonserializable_notes_set":
        value["notes"] = {"synthetic"}
    elif row["id"] == "max_chars_wrongtype":
        current = contract({"max_report_chars": "large"})
    with pytest.raises(TypeError):
        call(operation, value, current)


@pytest.mark.parametrize("row", SIZE_ROWS, ids=[row["id"] for row in SIZE_ROWS])
def test_literal_character_size_boundaries(row: Any) -> None:
    value = copy.deepcopy(row["input"])
    if "literal_serialized_text" in row:
        literal = row["literal_serialized_text"]
        assert json.dumps(value, ensure_ascii=False) == literal
        assert len(literal) == row["literal_character_count"]
        assert len(literal.encode("utf-8")) == row["literal_utf8_byte_count"]
    if row["expected_machine_code"] is not None:
        with pytest.raises(subject.OrchestrationError) as error:
            call(row["operation"], value, contract(row["contract_updates"]))
        assert error.value.machine_code == row["expected_machine_code"]
    else:
        observed = call(row["operation"], value, contract(row["contract_updates"]))
        assert observed == row["expected_return"]


def enum_schema(value: Any) -> dict[str, Any]:
    return {"properties": {"review_basis": {"properties": {
        "trust_source_kind": {"enum": value},
    }}}}


@pytest.mark.parametrize("row", RESOURCE_ROWS, ids=[row["id"] for row in RESOURCE_ROWS])
def test_internal_loader_faults_and_structure(
    row: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    identifier = row["id"]
    cause: BaseException | None = None
    if identifier.startswith("load_schema_raises_"):
        exception_types: dict[str, type[Exception]] = {
            "OSError": OSError, "ValueError": ValueError, "KeyError": KeyError,
            "TypeError": TypeError, "SchemaError": SchemaError,
        }
        exception_type = exception_types[identifier.removeprefix("load_schema_raises_")]
        cause = exception_type("synthetic")
        def loader(_path: Path) -> Any:
            assert cause is not None
            raise cause
    else:
        construction = row["construction"]
        value = construction.get("load_schema_result")
        if "load_schema_result_enum" in construction:
            value = enum_schema(construction["load_schema_result_enum"])
        def loader(_path: Path) -> Any:
            return value
    # Explicit internal negative fixture, never caller-provided production enum.
    monkeypatch.setattr(subject, "load_schema", loader)
    if "expected_return_frozenset" in row:
        expected = frozenset(row["expected_return_frozenset"])
        assert subject._canonical_trust_source_kinds() == expected
    else:
        with pytest.raises(subject.OrchestrationError) as error:
            subject._canonical_trust_source_kinds()
        assert error.value.machine_code == row["expected_machine_code"]
        if cause is not None:
            assert error.value.__cause__ is cause
        elif row.get("expected_cause_class") is not None:
            assert type(error.value.__cause__).__name__ == row["expected_cause_class"]
        else:
            assert error.value.__cause__ is None


@pytest.mark.parametrize(
    "row", PRECEDENCE_ROWS, ids=[row["id"] for row in PRECEDENCE_ROWS]
)
def test_resource_and_identity_precedence(
    row: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[Path] = []
    genuine = vars(subject)["load_schema"]
    def loader(path: Path) -> Any:
        calls.append(path)
        if "resource_working" not in row["id"]:
            raise OSError("synthetic")
        return genuine(path)
    monkeypatch.setattr(subject, "load_schema", loader)
    with pytest.raises(subject.OrchestrationError) as error:
        call("verdict", copy.deepcopy(row["input"]))
    assert error.value.machine_code == row["expected_machine_code"]
    expected_call = not row["canonical_reader_expected"].startswith("NOT_CALLED")
    assert bool(calls) is expected_call


def test_real_owned_resource_and_private_loader_wiring() -> None:
    assert vars(subject)["load_schema"] is load_schema
    assert vars(subject)["SchemaError"] is SchemaError
    expected = frozenset(("base_sha", "local_read_only_bundle"))
    assert subject._canonical_trust_source_kinds() == expected


def test_success_cached_and_failure_not_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = frozenset(("base_sha", "local_read_only_bundle"))
    assert subject._canonical_trust_source_kinds() == expected
    def failure(_path: Path) -> Any:
        raise OSError("synthetic")
    with monkeypatch.context() as patch:
        patch.setattr(subject, "load_schema", failure)
        assert subject._canonical_trust_source_kinds() == expected
        subject._canonical_trust_source_kinds.cache_clear()
        with pytest.raises(subject.OrchestrationError):
            subject._canonical_trust_source_kinds()
    # Failure was not cached; no runtime retry policy is inferred.
    assert subject._canonical_trust_source_kinds() == expected


def test_cwd_decoy_cannot_widen_owned_enum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    decoy = tmp_path / "docs/schemas/controller-verdict.schema.json"
    decoy.parent.mkdir(parents=True)
    decoy.write_text(json.dumps(enum_schema(["model_output"])))
    monkeypatch.chdir(tmp_path)
    expected = frozenset(("base_sha", "local_read_only_bundle"))
    assert subject._canonical_trust_source_kinds() == expected


@pytest.mark.parametrize("kind", [
    "malformed_json", "unsupported_keyword", "unreadable_resource",
    "existing_document_limit", "invalid_utf8_resource",
])
def test_genuine_loader_negative_temp_resources(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    resource = tmp_path / "negative-schema.json"
    if kind == "malformed_json":
        resource.write_text("{")
    elif kind == "unsupported_keyword":
        resource.write_text('{"type":"object","unsupported":true}')
    elif kind == "existing_document_limit":
        resource.write_text(" " * 1_000_001)
    elif kind == "invalid_utf8_resource":
        resource.write_bytes(b"\xff")
    # Explicit negative loader adapter: never rewrite actual owned schema/file/root.
    def loader(_owned_path: Path) -> Any:
        return load_schema(resource)
    monkeypatch.setattr(subject, "load_schema", loader)
    with pytest.raises(subject.OrchestrationError) as error:
        subject._canonical_trust_source_kinds()
    assert error.value.machine_code == "TRUST_SCHEMA_UNAVAILABLE"
    assert error.value.__cause__ is not None


@pytest.mark.parametrize("stage", [
    "factory", "resolve_os", "parents", "loader_runtime", "resolve_runtime",
])
def test_native_path_and_loader_failures_not_normalized(
    stage: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SyntheticPath:
        def resolve(self) -> Any:
            if stage == "resolve_os":
                raise OSError("synthetic")
            if stage == "resolve_runtime":
                raise RuntimeError("synthetic")
            return self
        @property
        def parents(self) -> Any:
            return []
    def factory(_value: Any) -> Any:
        if stage == "factory":
            raise TypeError("synthetic")
        return SyntheticPath()
    def failure(_path: Path) -> Any:
        raise RuntimeError("synthetic")
    if stage == "loader_runtime":
        monkeypatch.setattr(subject, "load_schema", failure)
    else:
        monkeypatch.setattr(subject, "Path", factory)
    exception = {"factory": TypeError, "resolve_os": OSError, "parents": IndexError,
                 "loader_runtime": RuntimeError, "resolve_runtime": RuntimeError}[stage]
    with pytest.raises(exception):
        subject._canonical_trust_source_kinds()


@pytest.mark.parametrize("operation", ["report", "verdict"])
def test_mappingproxy_and_dict_subclass_domains(operation: str) -> None:
    value = copy.deepcopy(SEEDS[operation])
    with pytest.raises(subject.OrchestrationError) as error:
        call(operation, MappingProxyType(value))
    assert error.value.machine_code == "MALFORMED_OUTPUT"
    class BenignDict(dict[str, Any]):
        pass
    supplied = BenignDict(value)
    if operation == "verdict":
        supplied["review_basis"] = BenignDict(supplied["review_basis"])
    assert call(operation, supplied) == (None if operation == "report" else "PASS")


def test_mappingproxy_basis_rejected() -> None:
    value = copy.deepcopy(SEEDS["verdict"])
    value["review_basis"] = MappingProxyType(value["review_basis"])
    with pytest.raises(subject.OrchestrationError):
        call("verdict", value)


@pytest.mark.parametrize("operation", ["report", "verdict"])
@pytest.mark.parametrize("item", [float("nan"), "\ud800"])
def test_original_serializer_does_not_add_strict_json_or_utf8_guards(
    operation: str, item: Any,
) -> None:
    value = copy.deepcopy(SEEDS[operation])
    value["checks" if operation == "report" else "notes"] = [item]
    assert call(operation, value) == (None if operation == "report" else "PASS")


def test_contract_is_static_protocol_not_runtime_guard() -> None:
    class Broken:
        @property
        def issue(self) -> int:
            raise RuntimeError("synthetic")
    with pytest.raises(RuntimeError):
        call("verdict", SEEDS["verdict"], Broken())
    class MissingBase:
        issue = 3
    with pytest.raises(AttributeError):
        call("report", SEEDS["report"], MissingBase())
    # No operational constructor/defaults or runtime Protocol instantiation.
    current: subject._ReportContract = Contract(3, "a" * 40, 10000)
    assert current.issue == 3


def test_source_closure_and_annotation_only_seam() -> None:
    path = Path(__file__).resolve().parents[1] / "tools/report_validation.py"
    tree = ast.parse(path.read_text())
    imports = {node.module if isinstance(node, ast.ImportFrom) else alias.name
               for node in ast.walk(tree)
               if isinstance(node, (ast.Import, ast.ImportFrom))
               for alias in node.names}
    assert imports <= {
        "__future__", "functools", "json", "pathlib", "typing", "tools.schema_validate",
    }
    assert not any(isinstance(node, ast.If) for node in tree.body)
    names = {
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef))
    }
    assert names == {"_ReportContract", "OrchestrationError", "_validate_report",
                     "_canonical_trust_source_kinds", "_validate_verdict"}
