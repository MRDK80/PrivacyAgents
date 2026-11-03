# Candidate architecture

The distribution currently provides package metadata and the version/help CLI.
The repository also contains a reviewed schema-validator foundation and synthetic
contract examples for development tests. Those repository sources are not an
installed orchestration engine and do not enable runtime actions.

Version comes from the static literal privacy_agents.__version__. The package
carries no PGW product package or runtime dependency. Distribution artifact selection
is explicit; repository-only documentation/schema/test sources must not silently
expand wheel/sdist payloads.

The [accepted generic binding design](ADR-001-generic-binding.md) separates engine
provenance/installation, target-local policy/profile and original run authority.
[Record definitions](BINDING_RECORDS.md) and [operation/profile rules](BINDING_OPERATIONS.md)
document the contract before executable schema/validator implementation. Digests,
target content, issues and this repository do not grant permission to act.

The first designed consumer is synthetic-only with local Git, fake external
transport and manual pause/restart. Installation, host probes, runtime launch,
advanced feature parity and real PGW integration are not implied by documentation
or pure schema tests. Main/cutover/publishing remain separately authorized work.

Legacy runs retain original identities, approvals, counters and deadlines.
No automatic state migration or simultaneous old/new writers is introduced.
Source origins remain public immutable references in PROVENANCE.json and the ADR.
