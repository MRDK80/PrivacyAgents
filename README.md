# PrivacyAgents

A standalone development orchestration project being extracted from
[Privacy Gateway](https://github.com/MRDK80/privacy-gateway).

This E2 candidate contains package metadata and a version/help entry point.
The orchestration engine is not included or activated. Engine transfer belongs
to E3; target profiles, trust binding and consumer integration belong to E4.
No runtime readiness or Windows orchestration support is claimed.

The package is `privacy-agents`; import namespace `privacy_agents`; executable
`privacy-agents --version`. No `pgw` entry point or product dependency is copied.
Python >=3.11 is the installation floor. The planned candidate packaging CI matrix is Python
3.11/3.12 on Linux and Windows; actual coverage requires primary successful CI.
Other combinations are unverified.

See PROVENANCE.json, docs/ARCHITECTURE.md and CONTRIBUTING.md.
This candidate is not a published PyPI release. Do not use it to resume old runs.
