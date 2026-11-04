# ADR-001: generic synthetic binding contract

Status: design accepted on 2026-11-03. Implementation is pending separate bounded
contract/schema/validator/source PRs with independent review and full gates.
This ADR does not approve installation, activation, actual host probes, runtime
launch, numerical runtime budgets, real external transport, cutover, main or PyPI.

## Context

PrivacyAgents is being extracted from Privacy Gateway. A source digest describes
bytes; it does not provide owner approval. An engine Git revision cannot replace
a target repository's policy revision or its target-local ancestry proof.
Existing installs, mandates, ledgers, counters and deadlines keep their original
identities. Software must not translate old grants into a new installation/run.

The repository's package currently provides metadata/version/help. Existing
schema foundation and test examples do not make the orchestration engine available
or establish runtime readiness. The approved design is documented before adding
its executable schemas or guards.

## Decision

Separate four identity groups: engine provenance, actual installation, target
repository/policy/profile and run authority. Use separately named record families
with explicit version1.0 dispatch. Do not reinterpret legacy runtime configs1–8 or
choose an implied numeric runtime9.

The generic BI/AW identifier boundary is specified explicitly in BINDING_RECORDS:
nonempty exact Unicode I strings, coarse ASCII owner/name R syntax, and nonempty
roadmap_ref strings whose actual Git validity remains a source-consumer check.
These are structural input rules, not trusted preparation, repository ownership or
runtime permission. Existing legacy consumer-specific constraints remain intact;
no normalization, guessed length cap, path reinterpretation or grant translation
is introduced. Installation, probes, entry exposure and launch remain separate.

Use the one-way construction:

```text
immutable runtime core -> binding intent -> external owner launch approval
                                                |
                                   activation wrapper pointers
```

The core contains no intent/launch-approval/wrapper digest. The intent binds the
core and all four groups but contains no owner launch-approval back-reference.
The external approval leaf refers to that exact intent. The activation wrapper
is a lookup container, not a recursively hashed approval subject. Expected approval
identities come from a trusted owner/operator context, not issue/head/model data
or a self-consistent JSON file.

Installation has a separate exact approval and an inspected typed materialization
inventory. Its approval window authorizes the install action, not permanent run
permission. New launches require their own joint approval, current installed bytes
and revocation checks. Full mandate-record hash and the established authority
projection digest remain distinct.

Target policy ancestry remains inside the target Git graph. Initial binding refs
are immutable run-start anchors; each later effect joins current task/head/base
facts and the original approved scope. STOP, revocation, original clocks/counters,
namespace/source checks and read-only UNKNOWN reconciliation precede effects.
A valid old digest or checkpoint cannot renew authority or reset consumed limits.

## Bounded first consumer

The initial design is synthetic-only: a tiny generic consumer, two newly admitted
tasks, isolated local Git, clearly fake external transport, synchronous execution
and owner-controlled pause/manual restart. Its profile uses the original four
quality checks and explicit five CI source identities. Synthetic CI results cannot
satisfy real primary GitHub delivery evidence.

The eight outer operation names remain two distinct protocols: six original
v3 delivery request/ledger operations, and two separate branch/handover preparation
operations. The original six-operation validator is not widened.

Advanced planning/wait/quota/continuation/learning/final-preparation profiles are
explicitly null in this minimal core. That is an exclusion, not proof of their
migration or full E3 parity. Generic success does not establish PGW product API,
security, integration, automated wakeup or production readiness. Those require
separate composed contracts, tests, demos and applicable authority.

## Canonical contract documents

- [Record types, resolver registry and validation/control rules](BINDING_RECORDS.md).
- [Generic profile, operation dispatch and source/result joins](BINDING_OPERATIONS.md).

These documents specify the approved design. They are not executable JSON Schemas,
owner approval payloads, installed source or evidence of a completed run. Actual
source bytes, host capabilities and finite values need fresh source/resource and
owner admission before execution. Partial persistence and unresolved outcomes fail
closed; no global transaction, cryptographic rollback or same-account compromise
protection is added by the design.

## Source references

The following immutable public sources define the preserved behavior and the seams
being separated. They are provenance references, not runtime authority:

- [Installation candidate, inventory and external approved digest](https://github.com/MRDK80/privacy-gateway/blob/e0b13d1128c91350092a5f146343edfc02c324a8/tools/agent_epic_install.py): candidate1.0 and install/readiness behavior.
- [Target-local binding](https://github.com/MRDK80/privacy-gateway/blob/e0b13d1128c91350092a5f146343edfc02c324a8/tools/agent_epic_policy_binding.py): binding1.0 and target ancestry checks.
- [Runtime entry and launch/config/control guards](https://github.com/MRDK80/privacy-gateway/blob/e0b13d1128c91350092a5f146343edfc02c324a8/tools/agent_epic_runtime_cli.py): configs1–8, launch1.0 and the existing deliberate digest projection.
- [Pinned mandate and handover planning](https://github.com/MRDK80/privacy-gateway/blob/e0b13d1128c91350092a5f146343edfc02c324a8/tools/agent_epic_handover.py): mandate3.0 shape, lifecycle and scope checks.
- [Task phases and adapter guards](https://github.com/MRDK80/privacy-gateway/blob/e0b13d1128c91350092a5f146343edfc02c324a8/tools/agent_epic_loop.py): exact phase order and trusted argv/source conditions.
- [Six-operation delivery protocol](https://github.com/MRDK80/privacy-gateway/blob/e0b13d1128c91350092a5f146343edfc02c324a8/tools/agent_epic_delivery.py): v3 request identity and retained ledger semantics.
- [Branch preparation](https://github.com/MRDK80/privacy-gateway/blob/e0b13d1128c91350092a5f146343edfc02c324a8/tools/agent_coordinator_branch.py): exact branch facts and verified existing-branch NO_OP behavior.
- [Handover validation and digest projection](https://github.com/MRDK80/privacy-gateway/blob/e0b13d1128c91350092a5f146343edfc02c324a8/tools/agent_coordinator_handover.py): source plan/permissions and approval projection.
- [Snapshot-owned package and full gate](https://github.com/MRDK80/privacy-gateway/blob/e0b13d1128c91350092a5f146343edfc02c324a8/tools/agent_gate.py): foreign editable imports are not positive snapshot proof.
- [Final preparation record families](https://github.com/MRDK80/privacy-gateway/blob/e0b13d1128c91350092a5f146343edfc02c324a8/tools/agent_final_preparation_records.py): pre-launch PROFILE lacks launch_digest; launch-bound candidates, approvals and results are separate leaves.
- [Legacy continuation digest encoding](https://github.com/MRDK80/privacy-gateway/blob/e0b13d1128c91350092a5f146343edfc02c324a8/tools/agent_continuation.py): raw legacy digest format is not the new tagged record type by implication.

MIT notices and immutable source links remain preserved. No source reference grants
permission to install, launch, migrate existing state or perform external writes.
