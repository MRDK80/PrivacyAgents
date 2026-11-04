"""Synthetic partial predicates; supplied data is never delivery permission."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest
from tools import delivery_validation as delivery
from tools import mandate_validation as mandate

# The following data compact separately reviewed, inert literal oracles. No
# production helper calculates expected decisions, identities, or check names.
BASE_REQUEST: dict[str, Any] = (
    {'operation_id': 'synthetic-operation',
     'operation': 'merge_task_pr',
     'repository': 'SYNTHETIC/delivery-fixture',
     'epic': 2,
     'task': 3,
     'pr': 5,
     'base_ref': 'roadmap/2-delivery',
     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
     'head_ref': 'codex/3-delivery',
     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
     'merge_sha': None,
     'schema_version': '1.0',
     'policy_sha': None}
)

REQUEST_CASES: list[tuple[str, dict[str, Any], bool]] = (
    [('1.0_commit_task', {'operation': 'commit_task'}, True),
     ('1.0_push_task', {'operation': 'push_task'}, True),
     ('1.0_create_task_pr', {'operation': 'create_task_pr'}, True),
     ('1.0_merge_task_pr', {}, True),
     ('1.0_close_task',
      {'operation': 'close_task',
       'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc'},
      True),
     ('1.0_update_epic',
      {'operation': 'update_epic',
       'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc'},
      True),
     ('2.0_commit_task',
      {'operation': 'commit_task', 'schema_version': '2.0'},
      True),
     ('2.0_push_task',
      {'operation': 'push_task', 'schema_version': '2.0'},
      True),
     ('2.0_create_task_pr',
      {'operation': 'create_task_pr', 'schema_version': '2.0'},
      True),
     ('2.0_merge_task_pr', {'schema_version': '2.0'}, True),
     ('2.0_close_task',
      {'operation': 'close_task',
       'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc',
       'schema_version': '2.0'},
      True),
     ('2.0_update_epic',
      {'operation': 'update_epic',
       'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc',
       'schema_version': '2.0'},
      True),
     ('3.0_commit_task',
      {'operation': 'commit_task',
       'schema_version': '3.0',
       'policy_sha': 'dddddddddddddddddddddddddddddddddddddddd'},
      True),
     ('3.0_push_task',
      {'operation': 'push_task',
       'schema_version': '3.0',
       'policy_sha': 'dddddddddddddddddddddddddddddddddddddddd'},
      True),
     ('3.0_create_task_pr',
      {'operation': 'create_task_pr',
       'schema_version': '3.0',
       'policy_sha': 'dddddddddddddddddddddddddddddddddddddddd'},
      True),
     ('3.0_merge_task_pr',
      {'schema_version': '3.0',
       'policy_sha': 'dddddddddddddddddddddddddddddddddddddddd'},
      True),
     ('3.0_close_task',
      {'operation': 'close_task',
       'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc',
       'schema_version': '3.0',
       'policy_sha': 'dddddddddddddddddddddddddddddddddddddddd'},
      True),
     ('3.0_update_epic',
      {'operation': 'update_epic',
       'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc',
       'schema_version': '3.0',
       'policy_sha': 'dddddddddddddddddddddddddddddddddddddddd'},
      True),
     ('2.0_bootstrap_commit_task',
      {'operation': 'commit_task', 'pr': None, 'schema_version': '2.0'},
      True),
     ('2.0_bootstrap_push_task',
      {'operation': 'push_task', 'pr': None, 'schema_version': '2.0'},
      True),
     ('2.0_bootstrap_create_task_pr',
      {'operation': 'create_task_pr',
       'pr': None,
       'schema_version': '2.0'},
      True),
     ('3.0_bootstrap_commit_task',
      {'operation': 'commit_task',
       'pr': None,
       'schema_version': '3.0',
       'policy_sha': 'dddddddddddddddddddddddddddddddddddddddd'},
      True),
     ('3.0_bootstrap_push_task',
      {'operation': 'push_task',
       'pr': None,
       'schema_version': '3.0',
       'policy_sha': 'dddddddddddddddddddddddddddddddddddddddd'},
      True),
     ('3.0_bootstrap_create_task_pr',
      {'operation': 'create_task_pr',
       'pr': None,
       'schema_version': '3.0',
       'policy_sha': 'dddddddddddddddddddddddddddddddddddddddd'},
      True),
     ('legacy_repository_slash_only', {'repository': '/'}, True),
     ('legacy_minimal_refs',
      {'base_ref': 'roadmap/2-', 'head_ref': ''},
      True),
     ('legacy_operation_id_whitespace', {'operation_id': ' '}, True),
     ('legacy_equal_epic_task', {'task': 2}, True),
     ('legacy_bool_positive_ids',
      {'epic': True, 'task': True, 'base_ref': 'roadmap/True-'},
      True),
     ('unknown_version', {'schema_version': '4.0'}, False),
     ('legacy_policy_extra',
      {'policy_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'},
      False),
     ('v2_policy_extra',
      {'schema_version': '2.0',
       'policy_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'},
      False),
     ('v3_missing_policy', {'schema_version': '3.0'}, False),
     ('v3_wrong_policy',
      {'schema_version': '3.0',
       'policy_sha': ('sha256:aaaaaaaaaaaaaaaaaaaaaaa'
                      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')},
      False),
     ('v3_upper_policy',
      {'schema_version': '3.0',
       'policy_sha': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'},
      False),
     ('prep_branch_not_delivery',
      {'operation': 'create_local_task_branch'},
      False),
     ('prep_handover_not_delivery',
      {'operation': 'build_task_handover'},
      False),
     ('unknown_operation', {'operation': 'run'}, False),
     ('empty_operation_id', {'operation_id': ''}, False),
     ('repository_no_slash', {'repository': 'repo'}, False),
     ('repository_two_slashes', {'repository': 'a/b/c'}, False),
     ('epic_zero', {'epic': 0}, False),
     ('task_negative', {'task': -1}, False),
     ('v1_null_pr', {'pr': None}, False),
     ('bool_pr', {'pr': True}, False),
     ('zero_pr', {'pr': 0}, False),
     ('negative_pr', {'pr': -1}, False),
     ('wrong_roadmap_epic', {'base_ref': 'roadmap/3-other'}, False),
     ('roadmap_head', {'head_ref': 'roadmap/2-other'}, False),
     ('base_sha_uppercase',
      {'base_sha': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'},
      False),
     ('base_sha_short',
      {'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'},
      False),
     ('head_sha_typed_digest',
      {'head_sha': ('sha256:bbbbbbbbbbbbbbbbbbbbbbb'
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')},
      False),
     ('merge_on_preoperation',
      {'operation': 'push_task',
       'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc'},
      False),
     ('merge_on_merge_operation',
      {'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc'},
      False),
     ('post_without_merge', {'operation': 'close_task'}, False),
     ('post_bad_merge',
      {'operation': 'close_task',
       'merge_sha': 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'},
      False),
     ('2.0_post_null_pr_merge_task_pr',
      {'pr': None, 'schema_version': '2.0'},
      False),
     ('2.0_post_null_pr_close_task',
      {'operation': 'close_task',
       'pr': None,
       'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc',
       'schema_version': '2.0'},
      False),
     ('2.0_post_null_pr_update_epic',
      {'operation': 'update_epic',
       'pr': None,
       'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc',
       'schema_version': '2.0'},
      False),
     ('3.0_post_null_pr_merge_task_pr',
      {'pr': None,
       'schema_version': '3.0',
       'policy_sha': 'dddddddddddddddddddddddddddddddddddddddd'},
      False),
     ('3.0_post_null_pr_close_task',
      {'operation': 'close_task',
       'pr': None,
       'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc',
       'schema_version': '3.0',
       'policy_sha': 'dddddddddddddddddddddddddddddddddddddddd'},
      False),
     ('3.0_post_null_pr_update_epic',
      {'operation': 'update_epic',
       'pr': None,
       'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc',
       'schema_version': '3.0',
       'policy_sha': 'dddddddddddddddddddddddddddddddddddddddd'},
      False)]
)

REQUEST_NATIVE: list[dict[str, Any]] = (
    [{'change': {'epic': '2'},
      'expected_exception': 'TypeError',
      'because': 'originalgreater-than ontypednumericfield; no '
                 'all-inputsafeparserclaim'},
     {'change': {'repository': 7},
      'expected_exception': 'AttributeError',
      'because': 'originalrepository.count ondeclaredstrfield'},
     {'change': {'base_sha': 7},
      'expected_exception': 'TypeError',
      'because': 'originalregexfullmatch requiresstr/bytes; no newguard'}]
)

AUTHORITY_CASES: list[dict[str, Any]] = (
    [{'id': 'v3_exact',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'expected': None,
      'qualification': 'Partialpurepredicatereturn only; not '
                       'authorization/effect grant/actualidentityproof'},
     {'id': 'v3_base_advances_policy_stable',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'request_updates': {'base_sha': 'cccccccccccccccccccccccccccccccccccccccc'},
      'expected': None,
      'qualification': 'Partialpurepredicatereturn only; not '
                       'authorization/effect grant/actualidentityproof'},
     {'id': 'v1_uses_v2_mandate_base_policy',
      'seed': 'legacy_mandate_2.0',
      'request_version': '1.0',
      'request_policy': None,
      'expected': None,
      'qualification': 'Partialpurepredicatereturn only; not '
                       'authorization/effect grant/actualidentityproof'},
     {'id': 'v2_uses_v2_mandate_base_policy',
      'seed': 'legacy_mandate_2.0',
      'request_version': '2.0',
      'request_policy': None,
      'expected': None,
      'qualification': 'Partialpurepredicatereturn only; not '
                       'authorization/effect grant/actualidentityproof'},
     {'id': 'v3_extra_root_precedes_bad_digest',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'mandate_updates': {'extra_root': None},
      'approved_digest_literal': 'bad',
      'expected': 'MANDATE_INVALID'},
     {'id': 'bad_digest_syntax_precedes_owner',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'approved_digest_literal': 'bad',
      'context_updates': {'owner_identity': 'OTHER'},
      'expected': 'MANDATE_APPROVAL_MISMATCH'},
     {'id': 'valid_wrong_digest_expired_lifecycle_first',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'approved_digest_literal': ('sha256:fffffffffffffffffffffff'
                                  'fffffffffffffffffffffffffffffffffffffffff'),
      'context_updates': {'now': 1000},
      'expected': 'MANDATE_EXPIRED'},
     {'id': 'owner_context_mismatch',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'context_updates': {'owner_identity': 'OTHER'},
      'expected': 'MANDATE_OWNER_MISMATCH'},
     {'id': 'changed_approver_stale_projection',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'nested_approval_updates': {'approved_by': 'OTHER'},
      'expected': 'MANDATE_APPROVAL_IDENTITY_MISMATCH'},
     {'id': 'revoked_precedes_expiry',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'mandate_updates': {'revoked': True},
      'context_updates': {'now': 1000},
      'expected': 'MANDATE_REVOKED'},
     {'id': 'not_yet_valid',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'context_updates': {'now': 119},
      'expected': 'MANDATE_NOT_YET_VALID'},
     {'id': 'expired_precedes_duration',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'context_updates': {'now': 1000},
      'expected': 'MANDATE_EXPIRED'},
     {'id': 'duration_precedes_task_count',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'context_updates': {'now': 750, 'task_iterations': 10},
      'expected': 'MANDATE_DURATION_LIMIT'},
     {'id': 'equal_task_limit_default_true',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'context_updates': {'task_iterations': 10},
      'expected': 'MANDATE_TASK_LIMIT'},
     {'id': 'task_limit_precedes_follow_up',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'context_updates': {'task_iterations': 11, 'follow_up_issues': 4},
      'expected': 'MANDATE_TASK_LIMIT'},
     {'id': 'follow_up_limit',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'context_updates': {'follow_up_issues': 4},
      'expected': 'MANDATE_FOLLOW_UP_LIMIT'},
     {'id': 'full_legacy_record_raw_digest_wrong_domain',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'approved_digest_from': 'contrasting_full_legacy_record_json_raw_digest',
      'expected': 'MANDATE_APPROVAL_MISMATCH'},
     {'id': 'valid_wrong_projection',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'approved_digest_literal': ('sha256:fffffffffffffffffffffff'
                                  'fffffffffffffffffffffffffffffffffffffffff'),
      'expected': 'MANDATE_APPROVAL_MISMATCH'},
     {'id': 'request_identity_repository',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'request_updates': {'repository': 'OTHER/repository'},
      'expected': 'MANDATE_IDENTITY_MISMATCH'},
     {'id': 'request_identity_epic',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'request_updates': {'epic': 4},
      'expected': 'MANDATE_IDENTITY_MISMATCH'},
     {'id': 'request_identity_task',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'request_updates': {'task': 4},
      'expected': 'MANDATE_IDENTITY_MISMATCH'},
     {'id': 'request_identity_base_ref',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'request_updates': {'base_ref': 'roadmap/4-other'},
      'expected': 'MANDATE_IDENTITY_MISMATCH'},
     {'id': 'request_identity_policy_sha',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'request_updates': {'policy_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'},
      'expected': 'MANDATE_IDENTITY_MISMATCH'},
     {'id': 'legacy_request_cannot_use_v3_mandate',
      'seed': 'legacy_mandate_3.0',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'request_updates': {'schema_version': '1.0', 'policy_sha': None},
      'expected': 'MANDATE_IDENTITY_MISMATCH'},
     {'id': 'operation_membership_missing',
      'seed': 'legacy_v3_missing_merge_operation',
      'request_version': '3.0',
      'request_policy': 'dddddddddddddddddddddddddddddddddddddddd',
      'expected': 'MANDATE_AUTHORITY_MISSING',
      'qualification': 'Independentlyconsistentliteralprojection/nestedapprovaldigest, '
                       'notstale-digestmutation'},
     {'id': 'v2_rootextras_not_newly_hardened',
      'seed': 'legacy_v2_extra_root',
      'request_version': '2.0',
      'request_policy': None,
      'expected': None,
      'qualification': 'Partiallegacyv2rootpermissiveness only; no '
                       'newgenericrecord/actualapprovalclaim'}]
)

ASSESSMENT_CASES: list[dict[str, Any]] = (
    [{'id': 'merge_task_pr_exactfive',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': None,
      'qualification': 'Suppliedsyntheticassessment shape only; '
                       'notactualchecks/currentrefs/controller/CIproof'},
     {'id': 'close_task_exactfive',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'close_task',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc',
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'post-merge',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc',
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': None,
      'qualification': 'Suppliedsyntheticassessment shape only; '
                       'notactualchecks/currentrefs/controller/CIproof'},
     {'id': 'update_epic_exactfive',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'update_epic',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc',
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'post-merge',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc',
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': None,
      'qualification': 'Suppliedsyntheticassessment shape only; '
                       'notactualchecks/currentrefs/controller/CIproof'},
     {'id': 'commit_task_assessment_ignored',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'commit_task',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': 'unsupported',
                     'status': 'not-a-gate'},
      'expected': None,
      'qualification': 'Originalnon-assessedoperation earlyreturn; '
                       'doesnotgrantwork orreplacefullpipelinegate '
                       'requirements'},
     {'id': 'push_task_assessment_ignored',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'push_task',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': 'unsupported',
                     'status': 'not-a-gate'},
      'expected': None,
      'qualification': 'Originalnon-assessedoperation earlyreturn; '
                       'doesnotgrantwork orreplacefullpipelinegate '
                       'requirements'},
     {'id': 'create_task_pr_assessment_ignored',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'create_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': 'unsupported',
                     'status': 'not-a-gate'},
      'expected': None,
      'qualification': 'Originalnon-assessedoperation earlyreturn; '
                       'doesnotgrantwork orreplacefullpipelinegate '
                       'requirements'},
     {'id': 'rootextras_taskstatus_policy_ignored',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}],
                     'extra_root': 'retained',
                     'task_status': 'not-validated-here',
                     'policy_sha': 'stale-not-assessed-here'},
      'expected': None,
      'qualification': 'Originalpredicatejoinsnineidentityfields only; '
                       'requestedpolicy isauthorizedseparately, no '
                       'newassessmentfields/hardening'},
     {'id': 'invalid_schema_version',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '2.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': 'GATE_INVALID'},
     {'id': 'invalid_phase',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'post-merge',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': 'GATE_INVALID'},
     {'id': 'invalid_status',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'PASS',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': 'GATE_INVALID'},
     {'id': 'invalid_machine_code',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'CI_FAILED',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': 'GATE_INVALID'},
     {'id': 'stale_repository',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'OTHER/repository',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': 'STALE_IDENTITY'},
     {'id': 'stale_epic',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 4,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': 'STALE_IDENTITY'},
     {'id': 'stale_task',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 4,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': 'STALE_IDENTITY'},
     {'id': 'stale_pr',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 6,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': 'STALE_IDENTITY'},
     {'id': 'stale_base_ref',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/4-other',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': 'STALE_IDENTITY'},
     {'id': 'stale_base_sha',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'dddddddddddddddddddddddddddddddddddddddd',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': 'STALE_IDENTITY'},
     {'id': 'stale_head_ref',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/4-other',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': 'STALE_IDENTITY'},
     {'id': 'stale_head_sha',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'dddddddddddddddddddddddddddddddddddddddd',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': 'STALE_IDENTITY'},
     {'id': 'stale_merge_sha',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': 'cccccccccccccccccccccccccccccccccccccccc',
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': 'STALE_IDENTITY'},
     {'id': 'checks_missing_one',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': 'GATE_INVALID'},
     {'id': 'checks_duplicate_name',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': 'GATE_INVALID'},
     {'id': 'checks_extra_name',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'extra',
                                        'state': 'SUCCESS'}]},
      'expected': 'GATE_INVALID'},
     {'id': 'checks_empty',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': []},
      'expected': 'GATE_INVALID'},
     {'id': 'checks_not_list',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': None},
      'expected': 'GATE_INVALID'},
     {'id': 'checks_nonmapping_item',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [None]},
      'expected': 'GATE_INVALID'},
     {'id': 'checks_nonstr_name',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 1, 'state': 'SUCCESS'}]},
      'expected': 'GATE_INVALID'},
     {'id': 'one_state_PENDING',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'PENDING',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': 'GATE_INVALID'},
     {'id': 'one_state_FAILURE',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'FAILURE',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': 'GATE_INVALID'},
     {'id': 'one_state_success',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': 'success',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': 'GATE_INVALID'},
     {'id': 'one_state_None',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': None,
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected': 'GATE_INVALID'}]
)

ASSESSMENT_NATIVE: list[dict[str, Any]] = (
    [{'id': 'unhashable_state',
      'request_fields': {'operation_id': 'synthetic-operation',
                         'operation': 'merge_task_pr',
                         'repository': 'SYNTHETIC/delivery-fixture',
                         'epic': 2,
                         'task': 3,
                         'pr': 5,
                         'base_ref': 'roadmap/2-delivery',
                         'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         'head_ref': 'codex/3-delivery',
                         'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                         'merge_sha': None,
                         'schema_version': '1.0',
                         'policy_sha': None},
      'assessment': {'schema_version': '1.0',
                     'phase': 'pr',
                     'status': 'pass',
                     'machine_code': 'OK',
                     'repository': 'SYNTHETIC/delivery-fixture',
                     'epic': 2,
                     'task': 3,
                     'pr': 5,
                     'base_ref': 'roadmap/2-delivery',
                     'base_sha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'head_ref': 'codex/3-delivery',
                     'head_sha': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'merge_sha': None,
                     'github_checks': [{'name': 'test (ubuntu-latest, '
                                                '3.11)',
                                        'state': [],
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (ubuntu-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.11)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'test (windows-latest, '
                                                '3.12)',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')},
                                       {'name': 'pre-commit',
                                        'state': 'SUCCESS',
                                        'link': ('https://example.invalid/synthe'
                                                 'tic-check')}]},
      'expected_exception': 'TypeError',
      'qualification': 'Originalset(states.values()) '
                       'permitsnativeTypeError; no newnormalization'}]
)

EXPECTED_OPERATIONS: list[str] = (
    ['commit_task',
     'push_task',
     'create_task_pr',
     'merge_task_pr',
     'close_task',
     'update_epic']
)

EXPECTED_CHECKS: list[str] = (
    ['test (ubuntu-latest, 3.11)',
     'test (ubuntu-latest, 3.12)',
     'test (windows-latest, 3.11)',
     'test (windows-latest, 3.12)',
     'pre-commit']
)

# Independent hand-ordered canonical approval projections. Hash only these
# literal bytes for the expected A(MD), not a production serialization helper.
PROJECTIONS: dict[str, str] = {
    'legacy_mandate_2.0': (
        '{"approval":{"approved_at":120,"approved_by":"SYNTHETIC"},"e'
        'pic":2,"expires_at":1000,"issued_at":100,"limits":{"max_dura'
        'tion_seconds":600,"max_follow_up_issues":3,"max_task_iterati'
        'ons":10},"operations":["commit_task","push_task","create_tas'
        'k_pr","merge_task_pr","close_task","update_epic"],"owner_ide'
        'ntity":"SYNTHETIC","policy_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaa'
        'aaaaaaaaaaaaa","repository":"SYNTHETIC/delivery-fixture","re'
        'voked":false,"roadmap_ref":"roadmap/2-delivery","schema_vers'
        'ion":"2.0","task_grants":{"3":{"allowed_paths":["synthetic.t'
        'xt"],"causal_scope":["synthetic delivery predicate"]}}}'
    ),
    'legacy_mandate_3.0': (
        '{"approval":{"approved_at":120,"approved_by":"SYNTHETIC"},"e'
        'pic":2,"expires_at":1000,"issued_at":100,"limits":{"max_dura'
        'tion_seconds":600,"max_follow_up_issues":3,"max_task_iterati'
        'ons":10},"operations":["commit_task","push_task","create_tas'
        'k_pr","merge_task_pr","close_task","update_epic"],"owner_ide'
        'ntity":"SYNTHETIC","policy_sha":"ddddddddddddddddddddddddddd'
        'ddddddddddddd","repository":"SYNTHETIC/delivery-fixture","re'
        'voked":false,"roadmap_ref":"roadmap/2-delivery","schema_vers'
        'ion":"3.0","task_grants":{"3":{"allowed_paths":["synthetic.t'
        'xt"],"causal_scope":["synthetic delivery predicate"]}}}'
    ),
    'legacy_v3_missing_merge_operation': (
        '{"approval":{"approved_at":120,"approved_by":"SYNTHETIC"},"e'
        'pic":2,"expires_at":1000,"issued_at":100,"limits":{"max_dura'
        'tion_seconds":600,"max_follow_up_issues":3,"max_task_iterati'
        'ons":10},"operations":["commit_task","push_task","create_tas'
        'k_pr","close_task","update_epic"],"owner_identity":"SYNTHETI'
        'C","policy_sha":"dddddddddddddddddddddddddddddddddddddddd","'
        'repository":"SYNTHETIC/delivery-fixture","revoked":false,"ro'
        'admap_ref":"roadmap/2-delivery","schema_version":"3.0","task'
        '_grants":{"3":{"allowed_paths":["synthetic.txt"],"causal_sco'
        'pe":["synthetic delivery predicate"]}}}'
    ),
    'legacy_v2_extra_root': (
        '{"approval":{"approved_at":120,"approved_by":"SYNTHETIC"},"e'
        'pic":2,"expires_at":1000,"extra_root":"retained","issued_at"'
        ':100,"limits":{"max_duration_seconds":600,"max_follow_up_iss'
        'ues":3,"max_task_iterations":10},"operations":["commit_task"'
        ',"push_task","create_task_pr","merge_task_pr","close_task","'
        'update_epic"],"owner_identity":"SYNTHETIC","policy_sha":"aaa'
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","repository":"SYNTHET'
        'IC/delivery-fixture","revoked":false,"roadmap_ref":"roadmap/'
        '2-delivery","schema_version":"2.0","task_grants":{"3":{"allo'
        'wed_paths":["synthetic.txt"],"causal_scope":["synthetic deli'
        'very predicate"]}}}'
    ),
}


def request(updates: dict[str, Any] | None = None) -> delivery.Request:
    fields = copy.deepcopy(BASE_REQUEST)
    if updates is not None:
        fields.update(copy.deepcopy(updates))
    return delivery.Request(**fields)


def seed(name: str) -> tuple[dict[str, Any], str, dict[str, Any]]:
    literal = PROJECTIONS[name]
    value = json.loads(literal)
    assert isinstance(value, dict)
    approved = "sha256:" + hashlib.sha256(literal.encode("utf-8")).hexdigest()
    value["approval"]["mandate_digest"] = approved
    context = {
        "now": 200, "owner_identity": "SYNTHETIC", "started_at": 150,
        "task_iterations": 0, "follow_up_issues": 0,
    }
    return value, approved, context


@pytest.mark.parametrize(
    "updates,expected",
    [
        pytest.param(updates, expected, id=name)
        for name, updates, expected in REQUEST_CASES
    ],
)
def test_original_typed_request_literals(
    updates: dict[str, Any], expected: bool
) -> None:
    value = request(updates)
    assert delivery._valid_request(value) is expected


@pytest.mark.parametrize(
    "row", REQUEST_NATIVE,
    ids=["epic_wrongtype", "repository_wrongtype", "base_sha_wrongtype"],
)
def test_request_native_errors_outside_typed_domain(row: dict[str, Any]) -> None:
    value = request(row["change"])
    exception = (
        TypeError if row["expected_exception"] == "TypeError" else AttributeError
    )
    with pytest.raises(exception):
        delivery._valid_request(value)


def test_original_request_defaults_repr_and_six_operation_boundary() -> None:
    fields = copy.deepcopy(BASE_REQUEST)
    for name in ("merge_sha", "schema_version", "policy_sha"):
        del fields[name]
    value = delivery.Request(**fields)
    assert (value.merge_sha, value.schema_version, value.policy_sha) == (
        None, "1.0", None
    )
    assert repr(value).startswith("Request(")
    assert "synthetic-operation" in repr(value)  # Original repr, not a redaction claim.
    assert delivery.OPERATIONS == frozenset(EXPECTED_OPERATIONS)
    assert delivery.POST_MERGE_OPERATIONS == frozenset(("close_task", "update_epic"))
    assert delivery.REQUIRED_CHECKS == frozenset(EXPECTED_CHECKS)


@pytest.mark.parametrize("name", tuple(PROJECTIONS))
def test_literal_approval_projection_is_distinct_from_full_record_hash(
    name: str,
) -> None:
    value, approved, _context = seed(name)
    assert mandate.mandate_digest(value) == approved
    assert vars(delivery)["mandate_digest"] is mandate.mandate_digest
    assert vars(delivery)["mandate_lifecycle_code"] is mandate.mandate_lifecycle_code
    assert vars(delivery)["MandateContext"] is mandate.MandateContext
    full_legacy_json = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    assert "sha256:" + hashlib.sha256(full_legacy_json).hexdigest() != approved
    # Full legacy JSON is not new typed H(record) or a raw source file hash.


@pytest.mark.parametrize(
    "row", AUTHORITY_CASES, ids=[row["id"] for row in AUTHORITY_CASES]
)
def test_original_authority_and_lifecycle_precedence(row: dict[str, Any]) -> None:
    value, approved, context = seed(row["seed"])
    fields = {
        "schema_version": row["request_version"], "policy_sha": row["request_policy"],
        **row.get("request_updates", {}),
    }
    current = request(fields)
    value.update(copy.deepcopy(row.get("mandate_updates", {})))
    value["approval"].update(copy.deepcopy(row.get("nested_approval_updates", {})))
    context.update(copy.deepcopy(row.get("context_updates", {})))
    if "approved_digest_literal" in row:
        approved = row["approved_digest_literal"]
    elif row.get("approved_digest_from") == ('contrasting_full_legacy_record'
                                             '_json_raw_digest'):
        full = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        approved = "sha256:" + hashlib.sha256(full).hexdigest()
    original = copy.deepcopy(value)
    observed = delivery._authorized(
        current, value, approved, mandate.MandateContext(**context)
    )
    assert observed == row["expected"]
    assert value == original
    # Even None is not source identity, grant-content, binding or effect proof.


@pytest.mark.parametrize("operation", ["merge_task_pr", "close_task", "update_epic"])
def test_equal_task_limit_stays_default_task_start_even_at_finalization(
    operation: str,
) -> None:
    value, approved, context = seed("legacy_mandate_3.0")
    context["task_iterations"] = 10
    current = request({
        "operation": operation, "schema_version": "3.0", "policy_sha": "d" * 40,
        "merge_sha": None if operation == "merge_task_pr" else "c" * 40,
    })
    assert delivery._valid_request(current)
    assert delivery._authorized(
        current, value, approved, mandate.MandateContext(**context)
    ) == "MANDATE_TASK_LIMIT"


def test_raw_source_digest_does_not_substitute_for_legacy_projection() -> None:
    value, _approved, context = seed("legacy_mandate_3.0")
    current = request({"schema_version": "3.0", "policy_sha": "d" * 40})
    raw_digest = "sha256:" + hashlib.sha256(b"synthetic source bytes").hexdigest()
    assert delivery._authorized(
        current, value, raw_digest, mandate.MandateContext(**context)
    ) == "MANDATE_APPROVAL_MISMATCH"


@pytest.mark.parametrize(
    "row", ASSESSMENT_CASES, ids=[row["id"] for row in ASSESSMENT_CASES]
)
def test_supplied_assessment_literals_are_not_primary_evidence(
    row: dict[str, Any],
) -> None:
    current = delivery.Request(**copy.deepcopy(row["request_fields"]))
    supplied = copy.deepcopy(row["assessment"])
    original = copy.deepcopy(supplied)
    assert delivery._assessment_code(current, supplied) == row["expected"]
    assert supplied == original


@pytest.mark.parametrize(
    "row", ASSESSMENT_NATIVE, ids=[row["id"] for row in ASSESSMENT_NATIVE]
)
def test_unhashable_assessment_state_keeps_original_native_typeerror(
    row: dict[str, Any],
) -> None:
    current = delivery.Request(**copy.deepcopy(row["request_fields"]))
    supplied = copy.deepcopy(row["assessment"])
    with pytest.raises(TypeError):
        delivery._assessment_code(current, supplied)


def test_mapping_proxy_assessment_preserves_original_mapping_domain() -> None:
    row = ASSESSMENT_CASES[0]
    supplied = copy.deepcopy(row["assessment"])
    supplied["github_checks"] = [
        MappingProxyType(item) for item in supplied["github_checks"]
    ]
    assert delivery._assessment_code(
        delivery.Request(**row["request_fields"]), MappingProxyType(supplied)
    ) is None


def test_source_import_closure_and_lifecycle_call_are_unchanged() -> None:
    source = Path(__file__).resolve().parents[1] / "tools/delivery_validation.py"
    tree = ast.parse(source.read_text())
    imports = {
        node.module if isinstance(node, ast.ImportFrom) else alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imports <= {
        "__future__", "collections.abc", "dataclasses", "re",
        "tools.mandate_validation",
    }
    names = {
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef))
    }
    assert names == {"Request", "_valid_request", "_authorized", "_assessment_code"}
    assert not any(isinstance(node, ast.If) for node in tree.body)
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "mandate_lifecycle_code"
    ]
    assert len(calls) == 1 and not calls[0].keywords and len(calls[0].args) == 2
