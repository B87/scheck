# scheck — roadmap to 0.0.4 (tentative)

**Status (2026-09-20):** planned operational features, deferred from 0.0.1. Release
assignment and ordering are tentative; no slice below is marked implemented.

## Release scope

The product sequence is [0.0.1](ROADMAP-0.0.1.md) for reliable core assessment,
[0.0.2](ROADMAP-0.0.2.md) for check packs, [0.0.3](ROADMAP-0.0.3.md) for inference
choices, then this release for repeated operational use and integrations.
Historical M4.1–M4.4 IDs are preserved. M4.5 regression coverage, M4.6 first-release
validation and M4.7 GitHub release delivery stay in 0.0.1; they are release requirements,
not deferred operational features.

This release adds SARIF, broader profile coverage, category filtering and drift
comparison. Existing profile thresholds and catalog filtering already belong to the
core: do not remove them or delay their tests until this release.

[SPEC.md](SPEC.md) remains the behavior contract. Update milestone/release references
and any changed CLI, schema or report contracts alongside implementation. Until a
feature ships, its registered CLI surface must fail explicitly as unavailable.
Product release numbers and report schema versions remain separate.

## M4.1 — SARIF renderer

Deliver a SARIF representation of the existing report without re-running checks or
re-grading findings. Define mappings for finding identity, severity, evidence and
assessment coverage; do not imply complete coverage from an incomplete assessment.

**Demo:** `scheck local --format sarif --out report.sarif`, validated against the SARIF
schema. An optional upload to a scratch code-scanning integration tests interoperability.

**Done when:** schema validation and fixtures cover rule/model findings, accepted risks,
incomplete runs and redacted evidence; severity and finding identity agree with JSON;
no renderer receives pre-redaction output. Document any mapping limitations.

**Spec:** §2 (`report/sarif`), §7.4, §8.

## M4.2 — expanded profile coverage (`baseline` / `hardened`)

Extend the useful check coverage selected by existing `MinProfile` filtering. Preserve
implemented profile thresholds and filtering semantics; this slice adds coverage and
validates its operational cost, rather than introducing profiles for the first time.
Choose additional checks from real host and application needs, using reviewed packs
where appropriate. Keep the baseline tier cap and shared execution/input budgets.

**Demo:** compare catalog contents and reports for `baseline` and `hardened`, with
additional hardened coverage visible and token, latency and cost differences recorded.

**Done when:** each new check has parser/rule fixtures as applicable and read-only
integration evidence; profile selection changes the menu predictably, existing severity
thresholds remain correct, and incomplete evidence is preserved in coverage reporting.

**Spec:** §3 tiers, §7.5, §8; use the M5 pack contract where applicable.

## M4.3 — category filters (`--only`)

Deliver category selection for baseline planning and the model's check menu through the
same catalog selection path. Filtering narrows the active assessment; it never authorizes
new checks or changes policy. Preserve any core bootstrap checks needed for safe execution.

**Demo:** `scheck local --only remote-access,updates` limits assessment to the selected
categories and makes its scope clear in the report.

**Done when:** tests cover invalid/empty selections, platform applicability, profiles,
disabled checks and pack contributions. Intentionally excluded domains cannot be
reported as assessed or problem-free; model calls cannot bypass the selected scope.

**Spec:** §3, §7.4, §7.5, §8.

## M4.4 — `scheck diff`

Deliver drift detection over two persisted runs: added/removed listeners, units, SUID
files and findings that appeared, disappeared or changed severity. Use typed records
from M1.7, not textual report diffs. Comparison performs no target execution.

Compare host identity, schema compatibility, selected scope, context and pack versions.
Distinguish evidence of removal or resolution from missing/unavailable evidence or an
excluded check. Explain comparability limitations rather than claiming false improvement.

**Demo:** collect two runs from a throwaway VM before and after an operator introduces
an unexpected listening service, then compare the persisted reports with `scheck diff`.
Only the operator changes the VM; scheck remains read-only.

**Done when:** fixtures cover additions/removals, severity and acceptance changes,
partial runs, scope/context/pack changes and incompatible schemas. Output preserves
redaction, identifies uncertain comparisons and does not mutate either persisted run.
Define the command's output and exit-code contract in the spec before implementation.

**Spec:** §7.4, §8, §10.

## Sequencing and release evidence

These features have distinct users and can be prioritized independently. Their current
0.0.4 grouping is tentative, not a reason to delay a valuable feature or ship an
unvalidated one. Any release reassignment should be explicit in the roadmaps.

Release sign-off requires relevant unit and golden tests, `make check`, read-only
integration evidence for new checks, and end-to-end demonstrations of the shipped CLI
features. Reuse existing security, report and AI quality gates; do not postpone those
gates from earlier releases. Record schema compatibility and integration limitations.

## Outside this release

Optional bounded assessment remains in [ROADMAP-RESEARCH.md](ROADMAP-RESEARCH.md).
Research success does not automatically add an integration to 0.0.4. Runtime executable
plugins, a marketplace and remediation are also outside this release's scope.
