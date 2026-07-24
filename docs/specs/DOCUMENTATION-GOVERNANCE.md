# Meshrix, LicoUp, BadTower, and Fabrigent Documentation Governance Gate

This specification defines the documentation-governance checks applied by
Lico-Auditor to the `meshrix`, `licoup`, `badtower`, and `fabrigent` policy profiles. It audits the
tracked publication candidate of a checked-out target repository. It does not
move, rewrite, or publish target-repository content.

The implementation authority is
`lico_auditor/documentation_rules.py`. This document is a maintained
projection of that code. Update it together with the implementation and the
synthetic tests in `tests/test_documentation_governance.py`.

## Public document layout

The gate requires these tracked root entry points:

- `README.md`
- `README.zh-CN.md`
- `PRODUCT.md`
- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`
- `CHANGELOG.md`
- `LICENSE`
- `SECURITY.md`

It also requires:

- `docs/README.md`
- `docs/RUNBOOK.md`
- `docs/COMPATIBILITY.md`
- `docs/ENTITY-CONFIG-LAYOUT.md`
- `docs/adrs/README.md`
- at least one tracked Markdown document in each of
  `docs/architecture/`, `docs/functionality/`, `docs/protocols/`, and
  `docs/examples/`

Tracked formal Markdown under `docs/` must be one of the named documents above
or live under `architecture/`, `functionality/`, `protocols/`, `examples/`, or
`adrs/`.

## Language, index, and link integrity

- `README.md` and `README.zh-CN.md` must link to each other.
- The README pair must identify the normative language and localized language.
- Every formal Markdown document must be linked directly from
  `docs/README.md`.
- Every relative Markdown link or image target must resolve to a tracked file
  or tracked directory.

## Modules and generated projections

A direct child of `apps/`, `packages/`, `crates/`, or `modules/` is treated as
an independently maintained module when it owns a recognized package or module
manifest. A direct child of `plugins/` is treated the same way when it owns
`plugin.json`. Such a module must have a tracked `README.md`.

A Markdown file whose name ends in `.generated.md`, or whose content declares
that it is generated, must identify both its canonical generation source and
its update or regeneration process.

## Publication boundaries

The following directories must be ignored and must contain no tracked files:

- `docs/plans/`
- `docs/reports/`
- `cache/`
- `build/`

Tracked agent-skill copies under project-local skill roots are rejected.
Repository-level public tools remain under `tools/`. Stable public lifecycle
scripts remain under `scripts/`; module-only scripts may remain with their
owning module.

Product profiles do not admit JSON from local documentation plan,
scenario, or generated directories. Executable public JSON examples belong
under `docs/examples/` and remain subject to the existing configuration-shape
and privacy checks.

## Finding rules

The documentation gate emits fixed, redacted findings:

- `documentation-required-path-missing`
- `documentation-required-section-missing`
- `documentation-formal-path-invalid`
- `documentation-local-asset-tracked`
- `documentation-local-asset-not-ignored`
- `documentation-external-skill-tracked`
- `documentation-module-readme-missing`
- `documentation-readme-language-link-missing`
- `documentation-readme-language-role-missing`
- `documentation-index-entry-missing`
- `documentation-link-target-missing`
- `documentation-generated-source-missing`
- `documentation-generated-update-missing`
- `documentation-git-state-unavailable`
- `documentation-tracked-file-unavailable`

All documentation-governance findings are release-blocking. Paths are
repository-relative and messages never include document contents.

## Semantic review boundary

File layout cannot prove that a capability is implemented, that a technical
fact has one canonical authority, that an ADR has valid implementation
evidence, or that a release artifact is bound to immutable provenance. Those
claims remain subject to repository-owned schemas, registries, verifiers, and
review. Lico-Auditor continues to enforce privacy and data-publication rules on
the same candidate and reachable history; it does not infer semantic truth
from a filename.
