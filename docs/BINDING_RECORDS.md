# Generic binding record contract

Design accepted on 2026-11-03. This documentation specifies the bounded generic
synthetic design before production implementation. It does not claim that the
record schemas, validators, installer, entry point or runnable engine exist.

Scope: two newly admitted generic tasks, owner-controlled pause/manual restart
and terminal owner wait, with isolated local Git and explicitly fake external
transport. Full E3 parity, PGW integration, advanced features, automatic wakeup,
installation/activation, host probes, launch, numeric runtime budgets, main and
publishing remain outside this documentation delivery.

See [the ADR](ADR-001-generic-binding.md), [operations/profile contract](BINDING_OPERATIONS.md)
and the immutable [source references](ADR-001-generic-binding.md#source-references).
The record layouts below preserve the accepted field/type/identity rules. They
are not an executable JSON Schema or an owner approval payload.

## 1. Inherited types and strict encoding

All specified new records use separately named schema_id + schema_version string1.0.
Every set below is CLOSED and every field mandatory. No optional unknown field or
fallback. D=sha256:<64lowercasehex>;G=40lowercasehex verified Git objectID;R=owner/name;
E=positiveint;N=nonnegativeint;P=positiveint;T=nonnegative Unixseconds;I=opaque exact
trusted-preparation ID;O=expected ASCIIowneridentity;Rel=safe relativePOSIX path;
Abs=canonical absoluteprivate path. Bool is never int. Null only where explicit.

Reject duplicate JSONkeys, float/NaN/Infinity, nullcharacters, ambiguous/escaping
paths, symlink ancestors, specialfiles and wrongobjecttypes before consuming bytes.
H(record)=tagged SHA256 UTF8 canonical JSON ensure_asciiFalse,sort_keysTrue,
separatorscomma/colon,allow_nanFalse after closed type validation. New schema_id
supplies domainseparation. No record includes its own H slot. No identity string
normalization. Legacymandate authorityprojection remains separately named A(MD).

Actual byte,record,output,call/time/memory/CPU caps are externally owner-admitted
VALUES in the records below, not default numbers from E2 or historical runs.
Missing values or actual capabilityproof means no executable admission.

## 2. Immutable source/install records — fixes C1

Engine manifest M exact schema_id=privacyagents.engine-manifest,version1.0 plus
repository:R,source_sha:G,source_tree:G,files:list.
Each row exact path:Rel,kind:"regular",mode:100644|100755,blob:G,content_digest:D,
size:N. Sorted unique paths; all execute/schema/catalog/template bytes covered.
M itself is a separately hashed root record, never a selfhash row. Git commit/tree/
blob kinds and actual bytes/modes must match engine repository. No target fallback.

Destination descriptor Dst exact schema_id=privacyagents.install-destination,
version1.0 plus installation_id:I,owner_identity:O,directory:Abs,
interpreter_digest:D,toolchain_digest:D,host_plan_digest:D.
Actual directory privateowned outside everytargetGit tree; immutable payload and
records directories have exact layout below, no ambient candidate discovery.

Install approval IA exact schema_id=privacyagents.install-approval,version1.0 plus
engine_manifest_digest:D,destination_digest:D,owner_identity:O,approved_at:T,
not_before:T,expires_at:T,revoked:bool,action:"install-candidate".
Trusted operator expected H(IA) must match. Its time window authorizes ACTUAL
materialization only (specified policyA); IR.installed_at must be inside it.
Later launches still require current installed-byte/revocation verification plus
NEW launch approval/mandate. IA alone never grants run authority. Expiry policyA
is a specified owner choice, not inherited from legacy --approved-digest behavior.

Materialization inventory MI exact schema_id=privacyagents.materialized-inventory,
version1.0 plus installation_id:I,engine_manifest_digest:D,destination_digest:D,
files:list,observed_at:T.
MI file rows exact path:Rel,kind:"regular",mode:100644|100755,content_digest:D,size:N.
MI has NO Gitblob field. Compare row-for-row to M after dropping ONLY M.blob;
all paths/types/modes/bytes/sizes must match. H(MI) is a NEW typedrecord digest,
NOT H(M), legacy path->rawhash digest, or an arbitrary equivalent byte map.

Installation receipt IR exact schema_id=privacyagents.installation-receipt,
version1.0 plus installation_id:I,engine_manifest_digest:D,install_approval_digest:D,
destination_digest:D,materialized_inventory_digest:D,installed_at:T,status:"INSTALLED".
The materialized_inventory_digest field always refers to H(MI), and only that
typed record; H(M) and the legacy raw path-map digest cannot substitute.

Actual installed root allowed layout:
- payload/ contains EXACT M.paths, including the frozen bootstrap entry as an
  ordinary M-pinned file; no pycache, generated output, logs or hiddenresources.
- records/ contains exactly engine-manifest.json,materialization-inventory.json,
  installation-receipt.json, respectively checked against H(M),H(MI),H(IR).
These root records are not included in MI.files, avoiding MI/IR/selfhash cycles.
No other rootfiles/directories are accepted. Actual pre-entry verification rejects
partialinstallation/missing/extra/type/mode drift; receipt alone is insufficient.
Use -B/PYTHONDONTWRITEBYTECODE for immutable payload. No claim of a multiartifact
transaction or crashdurability: partialinstallation is blocked and preserved.

## 3. Exact foundational descriptors — closes bounded C4 references

Interpreter IP exact schema_id=privacyagents.interpreter,version1.0 plus
executable:Abs,content_digest:D,implementation:string,version:string,
abi:string,platform:string. Values checked against actual approved executable;
versionlabel alone is not proof. No PATH interpreter substitution.

Toolchain TC exact schema_id=privacyagents.toolchain,version1.0 plus root:Abs,
interpreter_digest:D,files:list,tools:object.
File rows same MI rowtype; tools exact pytest,ruff,mypy,pre-commit; each exact
executable:Rel,argv_prefix:list[string],content_digest:D. All resolve under pinned
root/approvedinterpreter and inspected inventory; no symlink/namespaceescape.
argv_prefix is owner-reviewed data, never issue/head/model choice or shelltext.
It composes only with enginecanonical checkarguments; no arbitrary profile command.

Namespace/process plan NP exact schema_id=privacyagents.namespace-plan,version1.0
plus os:"linux",network:"deny",engine_mount:"read-only",toolchain_mount:"read-only",
role_workspace:"task-workspace-only",private_state_visibility:"driver-only",
executor_git_write:false,executor_github_write:false,supervisor_path:Rel,supervisor_content_digest:D,
resource_limits_digest:D. This is a requested profile, NOT proof capabilities exist.

Resource limits RL exact schema_id=privacyagents.resource-limits,version1.0 plus
memory_bytes:P,swap_bytes:N,cpu_quota_percent:P,cpu_set:list[N],process_limit:P,
output_bytes:P,record_bytes:P. Values require new owner/resource admission and
actual enforcement/source observation; no values are assigned in this design.

Host plan HP exact schema_id=privacyagents.host-plan,version1.0 plus os:"linux",
architecture:string,kernel_release:string,uid:N,boot_id:string,
namespace_plan_digest:D,interpreter_digest:D,toolchain_digest:D.

Probe receipt PRb exact schema_id=privacyagents.host-probe,version1.0 plus
host_plan_digest:D,namespace_plan_digest:D,resource_limits_digest:D,observed_at:T,
boot_id:string,checks:object,source_inventory_digest:D (must equal H(M)).
checks exact namespace,network_denial,engine_readonly,toolchain_readonly,
private_state_hidden,executor_git_denial,executor_github_denial,process_ownership,
resource_enforcement; each exact status:"PASS",evidence_digest:D.
Actual bounded synthetic probes and independently inspected source/evidence are
required before using PRb. A JSONdeclared PASS is not actual admission.
HP/NP contain no PRb digest. A host admission HA record below can reference all.

Host admission HA exact schema_id=privacyagents.host-admission,version1.0 plus
host_plan_digest:D,probe_receipt_digest:D,owner_identity:O,approved_at:T.
It is a separate inspected source/admission record. New launch intent includes
H(HA) through installation bindings; actual host/boot and enforcement revalidated.
No Windowsruntime support is inferred from package CI. Unsupportedhost isdeny.

## 4. Trusted entry/operator/resolver root — explicit, not self-granted

Specified frozen entry interface (not current metadataCLI; no publiccommand added):
owner-pinned interpreter -I -B installed payload/bootstrap/binding-entry.py
COMMAND --context ABS --approved-context-digest D --record-limit-bytes P.
COMMAND closed validate|initialize|resume|status|pause|stop.
Only the trusted operator/driver supplies approved-context-digest/recordlimit,
from explicit owner/native authority outside task/model inputs. The role sandbox
cannot access/modify operatorcontext/controlnamespace or invoke a privilegeddriver
channel. Same-account/OS/driver compromise remains outside base trust boundary;
this is not a new remote authentication or cryptographic-signature claim.

Frozenentry bytes and interpreter are verified by the trusted pre-entry driver
against installation records BEFORE executing it. Entry parses stdlib-only until
ALL binding/source/namespace/approval guards pass, then imports pinned engine.
No config8 facade or mutabletarget sys.path fallback is permitted.

Operator context OC exact schema_id=privacyagents.operator-context,version1.0 plus
owner_identity:O,owner_uid:N,mode:"synthetic-only",command:COMMAND,
expected_install_approval_digest:D,expected_launch_approval_digest:D,
expected_entry_digest:D,resolver_digest:D,control_namespace_digest:D,
revocation_namespace_digest:D,
record_limit_bytes:P,issued_at:T,expires_at:T,invocation_id:I.
H(OC) must equal the external approved-context-digest; CLIcap equals record_limit.
Clock valid; owner/UID/command/expectedleafdigests must match trusted invocation.
OC is generated after leafapprovals and is not hashed into RC/BI/LA. JSONownername
or passing a selfmade OC does not establish a trusted operator caller/channel.

Resolver RV exact schema_id=privacyagents.record-resolver,version1.0 plus bindings:list.
Each binding exact digest:D,record_type:the exact CLOSED registry below,source:object.
A digest has exactly ONE type/sourcebinding; duplicate digestentries are rejected,
including repeatedidenticalentries. Differentdigests MAY have the SAME record_type.
Thus two taskcriteria, two tasktemplates and two demoplans are all resolvable.
Claiming one digest under differenttypes/sources is alwaysdeny.
Source exact class:engine|target-git|owner-private|toolchain,namespace_id:I,path:Rel,
repository:R-or-null,revision:G-or-null,blob:G-or-null. Non-Git source fields allnull;
target/engineGit sources require repository/revision/blob kinds/bytes verified.
No glob/similarname/fallback. The authoritative finite kind registry is the registry section below. Unknownkind isdeny.
The caller requires its exactexpectedkind before reading/parsing. RV never lists OC/RV
itself as a subject dependency, and no candidate may replace the trusted RV root.

Control namespace CN exact schema_id=privacyagents.control-namespace,version1.0 plus
namespace_id:I,directory:Abs,owner_identity:O,owner_uid:N,run_id:I,
allowed_names:list[Rel]. Allowednames are exact runcontrol/journal/anchor
names in section7; no task workspace files. Privateowned0700dir/0600regularsinglelink
files/noGit/symlinkancestor checks before access. CN is trusted operator context,
not issueinput. Rootmatches only the admitted run; no ambientnamespace discovery.

Owner revocation namespace ON exact schema_id=privacyagents.revocation-namespace,
version1.0 plus namespace_id:I,directory:Abs,owner_identity:O,owner_uid:N,
record_name:"owner-revocations.json",anchor_name:"revocation-anchor.json",
lock_name:"owner.lock". This is an owner-global protected source, distinct from
per-run CN; BI and OC bind its exact digest so a different empty store cannot
silently clear revocations. Private source rules/actualdescriptor ownership apply.

Revocation anchor RA exact schema_id=privacyagents.revocation-anchor,version1.0
plus namespace_id:I,owner_identity:O,generation:N,record_digest:D.

Owner revocations OR exact schema_id=privacyagents.owner-revocations,version1.0 plus
owner_identity:O,generation:N,revoked_approval_digests:list[D],
revoked_installation_ids:list[I],updated_at:T.
Read fresh from ON owner-revocations.json before entry/effects, check observed
monotonicgeneration against durabletrustedanchor. Reject rollback/unknown state.
OR is mutable control, never hashed into immutable BI/RC; descriptor/namespace is
bound separately. Current ownerrevocation fact is not inferred from oldIA.revoked. The trusted owner-native operator, not task/model or engine runtime, updates ON:
under exclusive owner.lock verify old OR/RA, add revokedsubjects monotonically,
incrementgeneration, atomically write/fsync OR then matching RA. Readers use that
lock and require RA.generation/hash == OR; partialcrash is UNKNOWN/deny requiring
owner reconciliation. No claim of an atomic twofile transaction. New OR cannot
remove existing revocations; new grants use new leaf identities, not unrevocation.

## 5. Original clock, limits, state and digest DAG

Clock origin CO exact schema_id=privacyagents.clock-origin,version1.0 plus
run_id:I,boot_id:string,started_wall:T,started_monotonic_ns:N,
work_deadline_monotonic_ns:N,cleanup_deadline_monotonic_ns:N,
outer_deadline_monotonic_ns:N.
Require start<work<=cleanup<=outer and real monotonicclock/boot identity source.
New owner-admitted finite values only. Resume must have sameboot, time>=start and
no observed clock regression. CO.started_wall equals RO.started_at. Original
clocks begin at trusted preparation as approved, even if owner review takes time;
waiting for approval is not a reason to reset them. Wallclock must satisfy original mandate/LA windows;
restart does not change any original deadline. Crossboot/unknownclock blocks this
minimalprotocol, not recalibrates elapsedtime or refunds budgets. E5 may propose
other supported recovery, separately; no claim of transparent reboot recovery.

Run limits L exact schema_id=privacyagents.run-limits,version1.0 plus run_id:I,
max_task_iterations:P,max_follow_up_issues:N,max_executor_calls:P,
max_controller_calls:P,max_repairs:N,max_gate_invocations:P,
max_transport_attempts:P,max_reconciliation_reads:P,max_resume_invocations:P,
max_record_bytes:P,max_output_bytes:P.
Every value explicitly owner-admitted, bounded by the applicable installedengine
source policy, and crosschecked with MD limits/individual taskcontracts. Repairs
remain no greater than the existing source-supported bound, not a new runtime
threshold. This catalog assigns no actual values or new source maxima. No enabled
operation gets an untrackedbudget; exhausted or missingcounter denies nextreserve.

Run origin RO exact schema_id=privacyagents.run-origin,version1.0 plus run_id:I,
repository:R,epic:E,owner_identity:O,started_at:T,clock_origin_digest:D,
limits_digest:D,state_layout_digest:D,initial_state_digest:D,
initial_base_sha:G,initial_counters:object.
Counters exact task_iterations,follow_up_issues,executor_calls,controller_calls,
repairs,gate_invocations,transport_attempts,reconciliation_reads,resume_invocations;
each N. Initial values are independently checked new-run state; not copies of
old PGW counters. Each currentvalue must be >=original and <=its originalcap.
All historical runs remain in their old namespace/format; no translation exists.

State layout SL exact schema_id=privacyagents.state-layout,version1.0 plus run_id:I,
namespace_id:I,directory:Abs,checkpoint_name:"checkpoint.json",
delivery_ledger_name:"delivery-ledger.json",reservation_directory:"reservations",
anchor_name:"state-anchor.json",lock_name:"writer.lock".
Directory privateowner-only/outsideGit; exact paths; no untrusted discovery. All
writes by one trusted driver; roles cannot see/change state or inherit ownerFDs.
The original engine's exact pinned v3 delivery request/ledger layout is retained
inside delivery-ledger.json for this new run, not augmented by guessedfields.
Its exact source shape is cited in the [source references](ADR-001-generic-binding.md#source-references).

Counter reservation CR exact schema_id=privacyagents.counter-reservation,version1.0
plus run_id:I,binding_intent_digest:D,reservation_id:I,category:oneofexecutor_calls|
controller_calls|repairs|gate_invocations|transport_attempts|reconciliation_reads|
resume_invocations|task_iterations|follow_up_issues,ordinal:P,
operation_id:I-or-null,started_monotonic_ns:N,status:RESERVED|APPLIED|FAILED|UNKNOWN,
outcome_digest:D-or-null.
Reservation is durable before the attempted operation. All attempts consume ordinal;
FAILED/UNKNOWN do not refund. Reconcile existingreservation before issuing another.
Copying a reservation/counter from another run, missing earlierordinals or changing
originalidentity denies. This new outer binding record is not retrofitted into old
PGW records. Exact integration with source task/role counters must preserve BOTH
original effects and constraints; no double-execution or silent reset is allowed.

State anchor SA exact schema_id=privacyagents.state-anchor,version1.0 plus run_id:I,
binding_intent_digest:D,launch_approval_digest:D,last_checkpoint_digest:D,
last_delivery_ledger_digest:D,counters:the exact ROcounterobject,
last_reservation_digest:D-or-null,last_control_generation:N,
last_revocation_generation:N,last_wall_seen:T,last_monotonic_seen_ns:N,
writer_lock_device:N,writer_lock_inode:N,generation:N.
SA is mutable owned state, not partof immutable RC/BI. Validate counters against
actual retained reservations/engine records and originalcaps. A naked newer
counter or checkpoint cannot create authority. Missing/inconsistent state isUNKNOWN
andblocks. Same-account rollback of all private records is outside base model;
no cryptographic antirollback guarantee is invented.

Runtime core RC exact schema_id=privacyagents.runtime-core,version1.0 plus
run_origin_digest:D,engine_manifest_digest:D,installation_receipt_digest:D,
host_admission_digest:D,target_profile_digest:D,mandate_record_digest:D,
mandate_authority_digest:D,runtime_adapter_digest:D,approved_plans_digest:D,
feature_profiles:object.
feature_profiles exact planning,wait,quota,continuation,learning,final_preparation;
ALL SIX are explicit null for this minimal specified protocol. No optional/inferred
legacycapability and no finalowner result in RC. Manual controlpause/restart is
provided by the corecontrol protocol, NOT claimed wait/quota/wakeup recovery.
Runtime adapter/plans use exact source-owned closed formats and explicit synthetic
scope in BINDING_OPERATIONS.md. No config8 façade or runtime9 selection.

BI exact schema_id=privacyagents.binding-intent,version1.0 plus runtime_core_digest:D,
engine,installation,target,authority objects:
- engine exact repository:R,source_sha:G,source_tree:G,manifest_digest:D.
- installation exact installation_id:I,receipt_digest:D,destination_digest:D,
  interpreter_digest:D,toolchain_digest:D,host_admission_digest:D.
- target exact repository:R,epic:E,roadmap_ref:string,policy_sha:G,
  initial_base_sha:G,initial_head_sha:G,profile_digest:D.
- authority exact owner_identity:O,mandate_record_digest:D,
  mandate_authority_digest:D,run_origin_digest:D,control_namespace_digest:D,
  revocation_namespace_digest:D.
All repeated values must equal their validated records. MD is NEWly approved
pinnedmandate3SHAPE only, never translated existinggrant. H(MDfull) and legacy
A(MDprojection) are checked distinctly. Policy ancestry target-local; targetprofile
is read from exact targetpolicyGit object, not taskhead. Initialrefs are immutable
startanchors; current effects join fresh actualrefs/approvedplans (section6).

LA exact schema_id=privacyagents.launch-approval,version1.0 plus
binding_intent_digest:D,owner_identity:O,approved_at:T,not_before:T,expires_at:T,
revoked:bool,action:"launch-bound-synthetic-run".
Trusted external expectedH(LA) required. Window/owner within MD authority and
originalCO/L constraints; no new scope/budget from LA. No LA/self/AW digest in BI.

Activation AW exact schema_id=privacyagents.activation,version1.0 plus run_id:I,
runtime_core_digest:D,binding_intent_digest:D,launch_approval_digest:D.
Only a locator/crosscheck container. It is NOT hashed back into RC/BI/LA. Every
pointer compared against complete validated records and trustedexpected H(LA).

Construction order is acyclic:
M/IP/TC/NP/RL/HP/Dst -> IA -> actualmaterialization -> MI -> IR;
actualprobes of HP/NP/RL -> PRb -> HA;
newtargetpolicy/fixture -> TP; newMD/CO/L/SL/initialstate -> RO;
these +closedadapter/plans -> RC -> BI -> trustedownerLA;
H(RC),H(BI),H(LA),runid -> AW; then OC/rootresolver and initial mutable LC/SA.
Initialstate is the approved empty/new engine state BEFORE BI; live SA/LC/CR are
not hashed into RO/RC/BI. MI/IR selfmetadata is likewise outside M.files.

## 6. Validation DAG and effect-time authority

Trusted driver verifies entry/interpreter/namespace beforeexec. Entry verifies
externalOC digest/cap, then privatefiles/closedtypes/resolver sources beforeimports.
Order: M/IP/TC/NP/RL/HP/Dst/IA/MI/IR -> actualhost PRb/HA -> targetGit/TP/newMD/
CO/L/SL/RO/adapter/plans -> RC -> BI -> LA -> AW -> freshOR/LC/SA/pendingeffects.
Every digest has one declaredrecordtype and sourcebinding; equal-looking alternative
maps never substitute. Actualbytes/modes/refs/capability source observations required.

Policy ancestry is always targetpolicy_sha->currenttargetbase in target Git graph.
Engine source repository/tree is checked separately. No cross-repository ancestry.
InitialBIhead/base are immutableanchors; currenttaskhead/roadmap may advance only
through acceptedplan/checkpoint/delivery transitions under originalMD grants.
Immediatelybefore EACH intent/call/effect: re-read trustedclock/OR/STOP/LCgeneration,
expectedoriginalrun/counters and freshactualtask/repo/head/base/effectframe sources.
PriorPASS, validBI, livePID or cachedcheckpoint never replace these checks.

UNKNOWN outcome is read-only reconciled first; APPLIED does not produce second
write/counterrefund. Unresolved/missing/partial state blocks. No currentstate,
ownerapproval, deadline or profile is changed by a serializer or automaticlegacy
migration. Any engine/install/profile/targetpolicy/scope change needs new decision
and new applicable run, preserving oldhistory. No library/runtime state translation.

## 7. LC initialization, durable generations and manual restart

LC exact schema_id=privacyagents.launch-control,version1.0 plus run_id:I,
binding_intent_digest:D,launch_approval_digest:D,state:RUNNING|PAUSED|STOPPED,
generation:N. MutableLC never hashed into RC/BI/LA.

Control journal row CJ exact schema_id=privacyagents.control-intent,version1.0 plus
run_id:I,command_id:I,operator_context_digest:D,from_generation:N,to_generation:N,
from_state:null|RUNNING|PAUSED|STOPPED,to_state:RUNNING|PAUSED|STOPPED,
previous_control_digest:D-or-null,status:"INTENT".
CJ is immutable; it is never rewritten fromINTENT toAPPLIED.
Control outcome CU exact schema_id=privacyagents.control-outcome,version1.0 plus
run_id:I,command_id:I,intent_digest:D,status:APPLIED|UNKNOWN,
result_control_digest:D-or-null,result_anchor_digest:D-or-null. ForAPPLIED both
digests required; UNKNOWN may not invent them. Outcome is a separateimmutableleaf.
Initialrow requires from_generation0/from_statenull/to_generation0/to_stateRUNNING,
no existingLC/SA/CR or activewriter; the trusted initialize command and entirebinding
must be approved before ANY operation. No arbitrary missing-control allow_initial.
Later transitions require to_generation=from_generation+1 and exactpreviousdigest.

Control anchor CA exact schema_id=privacyagents.control-anchor,version1.0 plus
run_id:I,last_generation:N,last_control_digest:D,last_command_id:I,
last_journal_digest:D,last_revocation_generation:N,lock_device:N,lock_inode:N.
LC,journal,CA live in CN exactallowednames: launch-control.json,control-anchor.json,
control-journal/,writer.lock. No task or model canselectpaths.
State namespace SL stays separate and is also admittedprivateowned. Its writer.lock
is the exclusive runtimewriter lock; CN writer.lock is the separate controlwriter
lock. initialize/resume require the SL lock and no active writer; pause/stop can
update control under CN lock while a runtimewriter is active. A fresh controlread
uses the CN lock to avoid consuming an in-progress multi-file control transition.
A newer consistent LC/CA/CU generation than SA.last_control_generation is accepted
as a real ownercontrol advance, then acknowledged in SA; a lowergeneration denies.

Protocol: acquire exclusive CN controlwriter lock, verify its inode/UID against anchor,
readall binding/clock/control/pendingstate first, record ownercommandINTENT durably,
write nextLC privately/atomically, verifyactualbytes, writeCA referencing immutable
CJ, then write separateCU APPLIED referencing H(CJ),H(LC),H(CA). No CA->CU backedge.
Perfile atomic visibility is not a multiartifact transaction or promisedcrashdurability.
After crash, any partiallyconsistent LC/CA/CJ isUNKNOWN; read-onlyreconciliation may
proveexactAPPLIED orNOT_APPLIED. Ambiguouspartial/controlrollback blocks andneeds
owner action, never automaticclockrenewal/generationreset or blindsecondcommand.
If a persistence/fsync/directorysync operation is unsupported/fails, do not claim
safecompletedinitialization or durablewait; stop/preserveactualfailure.
Normalcompletion requires the exact CJ/LC/CA/CU join. MissingCU after otherwise
consistentwrites can be identified readonly as actualcontrolAPPLIED, but remains
blocked for automaticresume until explicitly permitted receipt reconciliation;
never create a secondcontroltransition to repair a missingoutcome.

Allowed states: RUNNING->PAUSED, RUNNING->STOPPED, PAUSED->STOPPED, PAUSED->RUNNING
only by fresh trustedresumeOC whileoriginalLA/MD/CO/L valid and allunknownresolved.
STOPPED is terminal for THISrun; noSTOPPED->RUNNING. A newownerdecision/run cannot
rewrite the oldrun. SameRUNNING resume is allowed onlyafter proving no activewriter
and exactretainedcheckpoint/state consistency; a silent/liveunknownprocess blocks.

Manualpause/restartdemo: recordPAUSED +durablecheckpoint; exit/reap ownedprocesses;
new trustedresume invocation with sameboot/originalclocks/counters and currentvalid
approval revalidates then incrementscontrolgeneration andcontinues. No clienttimer
or scheduledwakeup is claimed. Automaticwakeup remains a later E5 actualcapability.
Counterreservation UNKNOWN and controlUNKNOWN both take precedence over resume.
Pause/stop are restrictive ownercommands: after trustedOC/entry/CN and existing
subjectidentity checks, they may deny/pause an expired or source-blocked run
without importing its payload. They do not need an otherwiseexpired run grant
to become valid for new work. initialize/resume require the complete current
valid DAG/authority/capability. No restrictivecontrolcommand can create RUNNING
except the full-authority resume protocol above.

Antirollback claim is limited: compareLC/CA/CJ/SA and lastseenOR generations in the
protectedcooperative namespace; detect inconsistent rollback. OSaccount/driver
compromise or wholesale maliciousrollback of ALL protectedrecords is outsidebase
trust. No unsignedfile promises cryptographic rollback resistance.

## 8. Entry result/exit/streams and no hidden authority

Specified entry COMMAND results are safeclosedJSON only, stdout oneJSONobject plus
newline; stderr empty for handledresults. Malformedinvocation emits only safecode
onstderr and no rawprivatepath/source/PII/log. No generalJSON/raw exception repr. A malformedCLI before a record is safelyparsed
returns only the safeINPUT_INVALID token onstderr/exit2; a handledINVALID record
result uses the closedJSONstdout shape/exit2 and emptystderr.
Result schema_id privacyagents.entry-result,version1.0, additional status,
machine_code,run_id:I-or-null,phase:the exact phaseenum in BINDING_OPERATIONS.md-or-null,observed_control_generation:N-or-null.
Status exactVALIDATED|INITIALIZED|PAUSED|STOPPED|TERMINAL|BLOCKED|INVALID.
Machine_code is an engine-owned closed registry established beforeimplementation;
the following exact specified codes OK,INPUT_INVALID,UNSUPPORTED_VERSION,SOURCE_UNVERIFIED,
IDENTITY_MISMATCH,OWNER_APPROVAL_MISMATCH,OWNER_STOPPED,OWNER_PAUSED,GRANT_EXPIRED,
COUNTER_EXHAUSTED,CLOCK_UNCONFIRMED,STATE_UNKNOWN,PROCESS_OWNERSHIP_UNKNOWN,
CAPABILITY_UNSUPPORTED. Do not use modeltext ascode or addcodes silently.

Exit0 for acceptedVALIDATED/INITIALIZED and provednormalPAUSED/STOPPED/TERMINAL
outcomes; exit1 for safeBLOCKED denial; exit2 for INVALIDinvocation/shape.
Minimalresume is synchronous: supervise its processes to PAUSED/STOPPED/TERMINAL
or concreteBLOCKED within originalbounds before returning its oneJSONresult. It
does not return backgroundRUNNING. PIDalone is notprogress. These are specified newentry contracts, not currentmetadata
CLI semantics. Owner approval of the exact entry contract is required beforecode.
The metadataCLI's --help/--version behavior is preserved; no newpubliccommands in
this contract. FinalCLI exposure/installerpackageintegration is a later
explicitcausalPR, not an inferred change from copying purefoundation sources.

## 9. Accepted design and execution boundary

The design was accepted on 2026-11-03 for subsequent bounded contract/schema/
validator/source PRs under the migration epic. Those PRs still require independent
review, complete local gates, exact PR CI and actual post-merge gates. Acceptance
of this document is not code readiness, an installation approval or a runtime grant.

The accepted choices are separately named version1.0 record families, the one-way
runtime core -> binding intent -> external launch approval -> activation wrapper,
a newly approved mandate3.0 shape with joint binding, install-action-only approval
expiry, and the synthetic-only generic subset described here. No numeric legacy
runtime9 version is selected, and no existing grants/state are translated.

Deferred-fullfeature boundary: no planning/wait/quota/continuation/learning/
final-preparation profile/result productionintegration, trueautomatedwakeup,
crossvendor provider, realGitHubruntime delivery, PGWactivation/cutover/pilot ormain.
A smallgenerictrace/foundation child does notclose parentE3/PGW394. Later enabling
any capability requires its complete source/record/guardcomposition review and
freshapplicable authority, never null->enabled because a file is present.

## 10. Remaining reference-type closure for this minimal protocol

Initial state IS exact schema_id=privacyagents.initial-state,version1.0 plus
run_id:I,checkpoint_digest:D,delivery_ledger_digest:D,counters:exactROcounterobject.
IS contains no BI/LA/SA/LC hashes. It describes newly prepared data under SL before
launchapproval, not any applied effect. The initial checkpoint is the exact source
v3 closed checkpoint layout (source citation agent_epic_loop.py38–65,validate_checkpoint
at659+) with PLAN/no completedphases/no pending operation; initial delivery ledger
is the approved fresh map. Resolver types legacy-checkpoint3.0 and
legacy-delivery-ledger3.0 are explicit expectedslots, not a globalaccept-any-legacy
switch. Old private records cannot be loaded as these newrun sources by name.
All actual source-defined nullable/type/status rules remain; do not fabricate a
valid legacycheckpoint by checkingonly itsdigest or extractingunknownfields.

Private probe evidence is observational, not a new authority record. PE exact
schema_id=privacyagents.host-probe-evidence,version1.0 plus check:oneof PRbchecks,
subject_digest:D,observer_identity:O,observed_at:T,source_inventory_digest:D,
native_identity:object,exit_code:int,reaped:bool,artifact_digests:list[D].
Native identity exact boot_id:string,pid:P,birth:string,pgid:P,session_id:P.
Artifactdigests resolve only to private bounded actual captures/probe receipts;
they grant no authority and are never exported as rawlogs. Observations must be
independently checked against exact owner-installed probe/source and actualhost
before HA is accepted into an owner-approvedBI. A fabricated PE/PRb/PASS record
cannot supply trusted expectedH(LA) or replace actual admission. This is not a
cryptographic proof system and does not broaden same-account trust guarantees.

All raw byte digests (templates/supervisor/entry/files) must resolve to the typed
M/file inventory or privateevidence slot explicitly named by the caller. They are
not interchangeable with H(record), despite sharing sha256 textualsyntax. The authoritative finitekindregistry is the registry section below only. Its raw kinds
raw-template-bytes/private-evidence are validated as bounded bytes, not JSONrecords.
Every other kind is parsed under its exact closed typedrecord validator. Unknown
kind, wrongexpectedkind or rawbytes supplied where JSONrecord expected isdeny
beforeimports. Multiple distinctrecords of one kind are permitted as section4states.


# Authoritative resolver kind registry

This is the ONE finite record_type registry for this bounded design. It names
only record/byte kinds used by this contract. No fallback, prefix match, arbitrary
schema_id string or future kind is admitted. The expected kind at each reference
is mandatory; identical digest text cannot substitute another kind/source.

## New-family JSON kinds (exact schema_id, schema_version1.0)

- privacyagents.activation
- privacyagents.binding-intent
- privacyagents.clock-origin
- privacyagents.control-anchor
- privacyagents.control-intent
- privacyagents.control-namespace
- privacyagents.control-outcome
- privacyagents.counter-reservation
- privacyagents.effect-frame
- privacyagents.engine-manifest
- privacyagents.entry-result
- privacyagents.host-admission
- privacyagents.host-plan
- privacyagents.host-probe
- privacyagents.host-probe-evidence
- privacyagents.initial-state
- privacyagents.install-approval
- privacyagents.install-destination
- privacyagents.installation-receipt
- privacyagents.interpreter
- privacyagents.launch-approval
- privacyagents.launch-control
- privacyagents.materialized-inventory
- privacyagents.namespace-plan
- privacyagents.operator-context
- privacyagents.owner-revocations
- privacyagents.record-resolver
- privacyagents.resource-limits
- privacyagents.revocation-anchor
- privacyagents.revocation-namespace
- privacyagents.run-limits
- privacyagents.run-origin
- privacyagents.runtime-core
- privacyagents.state-anchor
- privacyagents.state-layout
- privacyagents.synthetic-adapter
- privacyagents.synthetic-bare-repository
- privacyagents.synthetic-criteria
- privacyagents.synthetic-demo-plan
- privacyagents.synthetic-demo-result
- privacyagents.synthetic-effect-result
- privacyagents.synthetic-fixture
- privacyagents.synthetic-git-seed
- privacyagents.synthetic-plans
- privacyagents.synthetic-service
- privacyagents.target-profile
- privacyagents.task-contract-template
- privacyagents.toolchain

Operator-context and record-resolver are TRUSTED ROOT records: their types are
listed for exact validation but they may NOT be resolver subjects or participate
in an RV self-reference. The caller obtains those roots from external approved
operator context. All other listed kinds still require an actual reference slot
and the corresponding permitted source class; listing a kind grants no action.

## Existing pinned-source JSON kinds

- legacy-mandate3.0: exact agent_epic_handover.MANDATE_FIELDS/type/lifecycle/approval
  projection; full H and source authority A remain distinct.
- legacy-checkpoint3.0: exact pinned source checkpoint validator, including all
  phase/completed/pending/null/reference constraints, not hash-only acceptance.
- legacy-delivery-ledger3.0: exact source v3 DELIVERY requests and four-key ledger
  entries/statuses; preparation operations are not inserted in this record.

No other legacy version/type is implicitly accepted by RV. Fresh approval still
required; these kind names are not migration/reuse authority.

## Raw byte kinds

- raw-template-bytes: bounded regular source bytes whose digest/type/path/mode
  join an exact M inventory entry. Allowed sources engine/target-git only, at
  the approved template/fixture slot; no JSON parsing or ownerapproval inference.
- private-evidence: bounded observed artifact bytes from admitted owner-private
  namespace, read-only for the expected evidence slot. Not executable, JSONrecord
  authority, primaryGitHub proof or source template. If an artifact is a defined
  typed record, use that exact JSONkind instead of this raw fallback.

Raw kinds require sourcebytes SHA equality and applicable path/type/size checks.
JSON kinds additionally require exact schema_id/version or the named legacy
shape. A raw digest is not H(record) merely because both serialize as sha256 text.

## Resolver multiplicity

Uniqueness is by digest, not globally by record_type. For two tasks, K1/K2 may
both use privacyagents.synthetic-criteria, RT1/RT2 both task-contract-template,
and DP1/DP2 both synthetic-demo-plan. Their differentdigests resolve separately.
Each reference also joins the expected task ID, so a valid K1 cannot satisfy K2.
Same digest with conflicting type/source, duplicateentry or wrongtask isdeny.
