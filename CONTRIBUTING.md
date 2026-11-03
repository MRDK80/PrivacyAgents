# Contributing

E2 packages a metadata-only shell. Engine migration is E3, profiles/integration
are E4 and actual installation/recovery/switch validation is E5.

Use an isolated environment and `python -m pip install -e ".[dev]"`, then
`pre-commit install`. Record actual Python and tool versions. Python >=3.11 is
the install floor; the proposed exact packaging matrix is 3.11/3.12 on Ubuntu
and Windows, plus separate pre-commit. Only primary successful runs establish
coverage; this is not an engine host-support claim.

Every source or documentation change requires `pytest -q`, `ruff check .`,
`mypy .`, `pre-commit run --all-files`. diff --check is supplementary.
Tests build sdist then wheel outside checkout, inspect exact archive membership,
retain license/provenance, compare repeated builds with fixed SOURCE_DATE_EPOCH,
and install into an isolated venv for installed-version/entrypoint checks.
Build output and venvs must remain outside the working tree.

Normal route: main <- roadmap/<epic>-<slug> <- codex/<task>-<slug>.
New-repository bootstrap requires an explicit owner decision about initial
history before any first push; the empty repository cannot supply a main SHA.
No direct task->main or force push. New security/public binding decisions require
an ADR and owner review before production implementation. Package publication,
runtime switch and final main merge are separate decisions.

Independent read-only controller reviews source, gate results and scope before
normal-hook commit/delivery. Record exact head/base/tree, local results separate
from five exact PR CI checks, then actual postmerge checks of the new roadmap SHA.
Merge and close each require owner approval and all applicable gates/demo.
Report GitHub Review only when an actual GitHub Review exists.

Reasoning repair policy: normal Low, at most Low->Medium->High for demonstrated
model repair failures when supported; preserve consumed attempts and ask owner
when exhausted or host switching is unavailable. Gate rerun alone is not evidence
of model failure. No inherited approvals/budgets from PGW.

Keep process/session identity and original clocks. Observe until terminal or a
concrete blocker. CI_PENDING needs primary read-only polling about once/minute.
Before leaving a live observation, verify client wakeup/recovery and handoff.
Reconcile UNKNOWN effects before any retry. STOP/revoke/expiry take priority.
