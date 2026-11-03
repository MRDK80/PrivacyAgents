# Candidate architecture

E2 contains only packaging and a metadata CLI. Engine source, schemas, templates
and target profile contracts are absent and must not be inferred from this shell.
Version comes from the static literal privacy_agents.__version__.
The distribution carries no runtime dependencies or PGW package.

The accepted E1 boundary separates immutable engine provenance/installation,
target-local policy ancestry/profile, and run authority. E3/E4 must specify and
review executable contracts before implementing that binding. Target content,
issues, digests and this repository cannot grant permission to act.

Legacy runs retain original identities, approvals, counters and deadlines.
No automatic state migration or simultaneous old/new writers is introduced.
Source origins are public immutable references in PROVENANCE.json.
