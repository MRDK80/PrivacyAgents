# Generic profile and operation contract

Design accepted on 2026-11-03; implementation and execution require their own
bounded review, gates and applicable approval. This contract enables no real
GitHub runtime transport, production provider, main/final action or PGW cutover.

See [record definitions](BINDING_RECORDS.md) and [the ADR](ADR-001-generic-binding.md).
The eight outer names below are split into six unchanged delivery protocols and
two separate preparation protocols; they are not a widened delivery-ledger enum.

## Target/profile and adapter closure

TP exact schema_id=privacyagents.target-profile,version1.0 plus profile_id:I,
repository:R,target_policy_files:list[Rel],protected_target_paths:list[Rel],
package_probe,gate,ci,report_metadata,synthetic_boundary.
package_probe exact module:"synthetic_consumer",import_root:"src",mode:"snapshot-owned".
Gate exact profile_id:"repository-full",profile_version:"1",
required_check_ids:[pytest,ruff,mypy,pre-commit] in thatorder. Pinned enginecanonical
argvtemplates remain pytest-q/ruffcheck./mypy./precommitrun--all-files, resolved to
approvedTC tools. No arbitraryprofile shell/command/PATH resolution.
CI exact source_repository:R,workflow_paths:{matrix:Rel,precommit:Rel},
required_checks:list,allowed_events:[pull_request,push]. Each row exactworkflow_path:Rel,
workflow_name:string,check_name:string,os:string,python_minor:string,kind:matrix|singleton.
Five exactrows: Ubuntu3.11/3.12,Windows3.11/3.12 testcells and the explicitprecommit
singleton. Join workflow/event/head/base/repo/source objects; no name-only acceptance.
Report metadata exact project_label:string,package_label:"synthetic_consumer",
evidence_origin:"synthetic". Synthetic evidence NEVER satisfies primaryGitHub gates.
Synthetic boundary exact fixture_manifest_digest:D,role_template_digest:D,
transport_template_digest:D,external_effects:"forbidden",evidence_origin:"synthetic".

Fixture manifest FM exact schema_id=privacyagents.synthetic-fixture,version1.0 plus
fixture_id:I,target_repository:R,files:list. Rows exact path:Rel,mode:100644|100755,
content_digest:D,size:N. Files are own tinygenericpackage, tests,pyproject, policy
and syntheticworkflow inputs; no PGWsource/metadata/SMOKE/keys/state. FM excludes
FM/TP rootrecords themselves to avoid hashcycles; generate FM,thenTP,then targetGit
policycommit,thenBI pins that commit. Every materializedfixture byte independently
matches; missingresource isdeny. No wholecheckout fallback.

Adapter AD exact schema_id=privacyagents.synthetic-adapter,version1.0 plus
fixture_id:I,engine_manifest_digest:D,role_template_digest:D,transport_template_digest:D,
local_bare_repository_descriptor_digest:D,fake_service_descriptor_digest:D,
timeout_seconds:P,output_limit:P.
Localbare descriptor exact schema_id=privacyagents.synthetic-bare-repository,
version1.0,fixture_id:I,directory:Abs,git_seed_digest:D,network:"none".
Fake-service descriptor exact schema_id=privacyagents.synthetic-service,version1.0,
fixture_id:I,directory:Abs,engine_manifest_digest:D,network:"none".
Gitseed GS exact schema_id=privacyagents.synthetic-git-seed,version1.0 plus
repository:R,refs:list,commits:list; each ref exactref:string,sha:G; each commit
exactsha:G,tree:G,parents:list[G]. VerifyactualisolatedGitobjects/refsbeforestart.
Gitseed pins INITIALstate; expectedlaterrefs advance onlyviaoriginalledger, not
by requiringmutableGitstorage to equalinitialinventory. Servicecode pins exactM;
servicejournal is separatemutableprotectedstate under its admittedfixture namespace.
Template entries are pinned M resources;
service is localin-process/subprocess fake with exact finite request/receipt shape,
no credentials, inbound approvals or network. Actual required process/namespace
admission precedes execution; declareddescriptor is notproof.

Plans PL exact schema_id=privacyagents.synthetic-plans,version1.0 plus repository:R,
epic:E,run_id:I,tasks:list. Exactly the two owner-admitted newtask IDs in approvedorder.
Each task exact task:E,causal_scope:list[string],allowed_paths:list[Rel],
base_ref:string,head_ref:string,criteria_source_digest:D,expected_demo_digest:D,
role_contract_template_digest:D. The closed template/mapping below materializes
the existing reviewed task-contract1.0 shape with explicit ownervalues; no default
repair/time budget or precomputed unknown futuremerge SHA.
Each task must be subset of NEWMD.task_grants and targetpolicy; protectedsource
changes denied. PL contains no LA/BI digest; BI binds H(PL) through RC.
The exact own criteria/demobytes are FM resources, not GitHubissue-providedauthority.

## Closed delivery EF and receipt types

EF exact schema_id=privacyagents.effect-frame,version1.0 plus run_id:I,
binding_intent_digest:D,launch_approval_digest:D,task:E,pr:E-or-null,
phase:PLAN|RUN_TASK|PR_CI|MERGE|POST_MERGE|DEMO|TASK_DONE|NEXT_TASK,
operation:ONE exact registryname below,base_ref:string,base_sha:G,
head_ref:string,head_sha:G,merge_sha:G-or-null,checkpoint_digest:D,
ledger_digest:D,pending_effects_digest:D,observed_at:T,control_generation:N.
EF is fresh fact/data, never approval and never hashed into immutableBI.

Synthetic receipt SR exact schema_id=privacyagents.synthetic-effect-result,
version1.0 plus operation_id:I,operation:registryname,request_digest:D,
fixture_id:I,evidence_origin:"synthetic",status:"APPLIED",result:object.
Result fields are operation-specific below, no unknownfields/rawlogs. Requestdigest
binds full EF. Actual locallyobservedobjects/fakejournal must equal SR; textPASS alone
cannot justify APPLIED. Exceptions/timeouts leaveUNKNOWN and require read-only
reconciliation. No syntheticSR enters realGitHub-primary validation.

## Exact finite registry / preconditions / result oracles

All eight require currentMD.operations membership, currenttaskgrant/PL subset,
fullbinding/LC/clock/counter/source checks, no unresolvedpending effect, and no
other activewriter. No finaloperation or freeform operation name is allowed.

1 create_local_task_branch — phasePLAN; pr=null;merge_sha=null. base_ref exactbound
roadmap; base_sha actual current admittedlocalroadmap; head_ref exactPL taskref,
head_sha initialbase. Check branch absent or exactknownapplied result. Result exact
head_ref:string,head_sha:G; actual localbranch points base. No externalpush.
2 build_task_handover — phasePLAN; pr=null;merge=null. Exacttaskcriteria/allowedpaths/
base/head +reviewedsource handovercontract; newprivate artifact only. Result exact
handover_digest:D; actual persistedartifact matches and no authorityfield expansion.
3 commit_task — phaseRUN_TASK; pr=null;merge=null. Mandatory actual fullgate current
snapshot + independentcontrollerPASS, exactsnapshot tree/allowedpaths/parent pinned.
Headbefore commit is the admittedtaskparent. Result exact head_sha:G,tree_sha:G,
parent_sha:G; actual isolatedGitcommit has exactparent/tree and canonicalhooks.
No executor Gitwrite; only trusteddriver can perform this localoperation.
4 push_task — phaseRUN_TASK; pr=null;merge=null. head_sha is the verifiedcommit;
base/ref/source unchanged. Only bound localbare fixture destination; no network.
Result exact head_ref:string,head_sha:G; actual barefixture ref equals expected.
5 create_task_pr — phaseRUN_TASK; pr=null;merge=null. Bound head/base branches and
verifiedlocalbare head; fake-service source knows exacttask/project. Result exact
pr:E,head_sha:G,base_sha:G; actualfakejournal has onePR with matchingimmutableidentity.
6 merge_task_pr — phaseMERGE; prpositive;merge=null. ExactcurrentPR identity, retained
localgate/controller, five matching syntheticPR checks, matchingallowedtask scope.
Result exact merge_sha:G,parents:[G,G],tree_sha:G. Actual isolatedGitmerge/fixture
facts equal base/head parents and headtree. No main/ref rename or realGitHubmerge.
7 close_task — phaseTASK_DONE; prpositive;mergepositiveG. Require five synthetic
ACTUALpostmerge fixture checks on that newmerge SHA, applicableactualgenericdemo,
parent/childsource identity and retainedoriginalcounterevidence. Result exact task:E,
state:"closed",reason:"completed"; fakejournal recorded one matching closure.
8 update_epic — phaseTASK_DONE; prpositive;mergepositiveG. Must have verifiedAPPLIED
close_task for THIStask/mergeidentity. Result exact epic:E,completed_task:E;
fakejournal records the limitedchild update, never parentepic closure.

No delivery operation allowed in PR_CI,POST_MERGE,DEMO,NEXT_TASK: those phases
perform only admitted read/gate/demo/transition work with their original counters.
Read/fakepoll/gate/role calls have their own reservebeforecall CR category, not a
newoperation string masquerading as an approved deliveryname.

Reconciliation is readonly against exact localGit/fakejournal identities. Ifeffect
applied before timeout, same operation_id becomesAPPLIED withoutsecondcall. Ifnot
provablyapplied/notapplied, remainUNKNOWN; no automaticduplicate, clockreset orrefund.
Currenthead/base changes follow checked per-tasktransition/plan protocol; BIinitial
anchors unchanged and targetpolicy ancestorofcurrentroadmap still required.

## Minimal boundary and deferred features

Only this generic synthetic mode is runnable under the specified new binding.
Disabledplanning/wait/quota/continuation/learning/finalpreparation profiles cannot
be enabled by filepresence, issuetext or nullfallback. CorePAUSE/manualrestart is
not scheduledwakeup or quota/recovery acceptance. FullE3parent remains OPEN until
its promised wholecomposition/parity is actually demonstrated. E4PGW consumer
profile/productSMOKE remain later. E5realinstallation/activation/cutover require
separateownerapproval; realGitHubdeliverymain/finalepic effects are absent here.


## Criteria/template/demo referenced record closure

Criteria K exact schema_id=privacyagents.synthetic-criteria,version1.0 plus task:E,
body:string,acceptance_criteria:list[string]. Every criterion nonempty and occurs
in body; source is an FM-pinned ownerapproved fixture record, never issueauthority.

Role contract template RT exact schema_id=privacyagents.task-contract-template,
version1.0 plus task:E,epic:E,acceptance_criteria:list[string],allowed_paths:list[Rel],
excluded_changes:list[string],allowed_tools:[workspace,git-read,quality-gate],
workspace_write:true,budget:object,required_checks:[pytest,ruff,mypy,pre-commit],
trust_source_kind:"local_read_only_bundle".
Budget exact max_minutes:P,max_repair_iterations:N,max_report_chars:P, all actual
owner-admitted within existing source-supported bounds. Commit/push/merge/external
write permissions for the role are FALSE; only the trusted driver gets separateMD
operations. No role can obtain a private OC or change a tool/template.

Materialization is an engine-owned deterministic procedure, not a modeltemplate:
use RTtask/epic/criteria/scope/budget, exact current boundroadmap base SHA proven by
fresh target ancestry+acceptedpreviousmerge, and PLtaskhead ref to build the existing
pinned task-contract.schema.json1.0 object. git.head_sha is null before branchfirst
materialization, then exact checkedhead when phase requires it. permissions explicitly
set external_write/commit/push/mergefalse, workspace_writetrue. trust_source
pinned_before_head_checkouttrue. Validate against the original closed schema and
policy/scope checks; persist exact resulting contractdigest in handover/checkpoint
before work. Task2 may therefore derive verifiednewbase after task1merge without
BI rewriting or guessing a futuremerge SHA at launch. No other field substitution.

Demo plan DP exact schema_id=privacyagents.synthetic-demo-plan,version1.0 plus task:E,
required_oracles:[source-inventory,snapshot-import-root,gate-four-commands,
exact-child-reap,counter-conservation,synthetic-effect-trace],expected_trace:list
of the eight registrynames in the declared sequence for that task. Observed task
outputs are constrained by the exact FM fixture bytes/taskcriteria, not arbitrary
commands in DP. PL.expected_demo_digest points only H(DP), a PRELAUNCH plan.

Demo result DR exact schema_id=privacyagents.synthetic-demo-result,version1.0 plus
run_id:I,binding_intent_digest:D,launch_approval_digest:D,task:E,merge_sha:G,
demo_plan_digest:D,oracles:object,evidence_origin:"synthetic",status:"PASS".
Oracles exact six DPnames, each status:"PASS",evidence_digest:D, with actually
inspected process/source/trace receipts. DR is a POSTLAUNCH leaf and NEVER referenced
from RC/BI/DP. A declared result is not source evidence. Pre-launch plans and post-launch results remain distinct record families; a
launch-bound result cannot be a pre-launch input.

Pinned executor-report/controller-verdict schemas stay original1.0 for the basic
role reports, with all their closed fields/repairiterations/reviewbasis checks.
The new outer binding does not make a fake role into actual production controller
proof. Such fake boundaries remain labelled; independent REAL project controller
and GitHub CI are separate causal project-delivery evidence.

## Dispatch mapping: six delivery operations and two preparation operations

The eight-name OUTER registry above is NOT an expansion of
agent_epic_delivery.OPERATIONS. There are two distinct sourceprotocol paths:

### D — exactly six delivery operations

commit_task,push_task,create_task_pr,merge_task_pr,close_task,update_epic use the
UNCHANGED source v3 Request/validator and delivery-ledger layout. Construct Request
fields operation_id,operation,repository,epic,task,pr,base_ref,base_sha,head_ref,
head_sha,merge_sha,schema_version="3.0",policy_sha from the validated sourcecontext.
Every shared identity equals EF/BI/currentfacts; operation_id equals the original
CR.operation_id and satisfies the original sourcevalidator (including its exact
source format), not merely the outer opaqueID type. Canonical existing operationID
construction is preserved; freshness-only EF timestamps/observation digests do not
produce a new operationID or refund an existing reservation on reconciliation.
The request's policy_sha is BI.target.policy_sha; request.repository/epic/ref are
BI.target identity; task/pr/head/base/merge are exact operation-specific liveframe
joins. Original source type/null/phase/evidence guards apply without relaxation.

Only these six are persisted in the existing v3 delivery-ledger operation entries.
Outer SR is a synthetic wrapper/evidence record, not a replacement v3 request or
a reason to bypass original ledger validation. It joins the original reserved EF
and CR.operation_id, operation name, fixture identity and exact operation-specific
result; source-ledger request/receipt plus actual localGit/fakejournal are checked.
After UNKNOWN, currentfresh facts may be newer than the stored originalEF, but
stable requestidentity must match that originalreservation/request. Never derive
a secondID from observed_at merely to replay an already applied operation.

### P — exactly two preparation operations

create_local_task_branch and build_task_handover NEVER create an
agent_epic_delivery.Request and NEVER enter that six-operation delivery ledger.
They use source branch/handover protocol + their original OUTER CR/SR reservation
and sourceartifact/result joins. No changes to six-operation validator allowed.

Input materialized pinned plan is the existing closed agent_epic_handover
PLAN_FIELDS plus policy_sha, schema_version="2.0". Its exact fields are
repository,epic,task,criteria_source,acceptance_criteria,delivery_criterion_indices,
default_ref,default_sha,base_ref,base_sha,head_ref,causal_scope,allowed_paths,
changes_policy_or_architecture,budgets,task_class,policy_sha,schema_version.
It is deterministically materialized from approved PL/RT/K, exact currenttarget
and fixture default/base Git facts, and the fresh targetpolicy ancestry guard.
changes_policy_or_architecture isFalse; allowedpaths/causalscope/budgets remain
within the new MD/task grant and pinned source constraints. No arbitrarydefault
ref or taskbody becomes authority. No legacy plan migration/approval translation.
This runtime-generated sourceplan is not an RV input of an invented legacykind:
validate it directly with the exact sourceprotocol. The finite RV kindregistry
remains the registry in BINDING_RECORDS.md only.

For create_local_task_branch:
- EF phasePLAN/prnull/mergenull, task/base/head identity equals that sourceplan.
- Source BranchOptions map repository/epic/task/default_ref/default_sha/base_ref/
  base_sha/head_ref exactly from validated plan; root/remote from admitted fixture,
  approvedTrue ONLY after full new binding+MD/source preconditions. Do not infer
  this boolean from modeltext or SR. The original before_create guard performs
  the final freshauthority/STOP/source checks under the OUTER reserved operation.
- Original source Result schema/version/status/machinecode/exit/identity checked;
  CREATED or proven matching NO_OP must have exact headref/baseSHA, preserved
  currentbranch and no unexpected upstream. SR.result uses the alreadydeclared
  head_ref/head_sha subset only after all sourcefields/actualGit facts are checked.
- CR.operation_id is allocated and persisted ONCE with the original operation
  context before invocation; all reuse/reconciliation refers to that same retained
  reservation, never a newlygenerated time-based identifier. Failed/unknownattempts
  remain consumed. No missing branch is recreated without its original outcome
  being reconciled and original remaining authority confirmed.

For build_task_handover:
- EF phasePLAN/prnull/mergenull and identity equals the same validated sourceplan.
- Require the create_local_task_branch preparation outcome already proven APPLIED
  for this task/base/head, and actuallocalbranch still exactly equals admittedbase.
- Existing prepare_handover internally calls prepare_branch; the new trusted
  wrapper MUST require its verified NO_OP branch path here. Its before_create
  callback denies any unexpected creation attempt, rather than nesting an unseen
  second branch effect under a handover reservation. A missing/moved branch is
  drift/UNKNOWN/deny, not silently recreated during handover. This is an external
  guarding precondition, not a modification or weakening of original source rules.
- Validate complete source handover2.0, trusted_policy pinned_policy_sha equal
  BI.target.policy_sha, mandate_provenance for exact new MD, denied permissions,
  fullgate profile and source handover_digest approvalprojection. Actual source
  coordinator_handover.handover_digest excludes ONLY approval object, and its
  approval.plan_digest must equal that sourceprojection. Do not confuse it with
  H(fullhandover), H(EF), H(MD) or A(MD).
- Source handover output stateHANDOVER/machinecodeOK/mandate_digest/Handover identity
  and persistedartifact bytes must match before SR.result.handover_digest is
  accepted. SR is not owner approval; its own request_digest joins H(originalEF),
  CR.operation_id/operation and the exact actual source result/plan context.
- Preparation artifacts/reservations stay in the admitted private sourceprotocol
  namespace; they are not inserted as unrecognized v3 delivery-ledger requests.
  The outer CR/SR status consumes/resolves its original operation, preserving all
  counters. No APPLIED SR may be fabricated from a matching branch name alone.

In both P paths, every authority-bearing sourceplan field is revalidated against
BI/MD/PL/RT plus actual currentfacts before use. EF alone intentionally does not
carry all planfields, and is never used as a substitute for sourceplan validation.
The new typed outer binding wrapper does not coerce prep into delivery requests.

### Required negative composition cases

Attempt either preparation name in the six-operation delivery Request/ledger:
reject by unchanged sourcevalidator. Attempt one delivery operation in preparation
protocol: reject outer dispatch. Change EF/CR.operation_id/task/base/head/policy or
sourceplan fields independently: no effect. Force build_handover's nested branch
create callback: deny; exactexistingbranch NO_OP remains allowed. Replay a source
handover approvalprojection as new owner LA: reject wrongtype/subject. Change a
fresh observation timestamp after UNKNOWN: original operationID/reservation remains,
no second effect. Keep both preparation cases and six delivery cases separately
observable; a union eight-operation oldvalidator is explicitly forbidden.
