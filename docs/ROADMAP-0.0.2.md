# scheck — roadmap to 0.0.2

**Status (2026-09-20):** planned. This release expands application assessment coverage
through reviewed check packs. No slice below is marked implemented.

## Release scope

The release sequence is:

- **0.0.1:** reliable core assessment and evaluated AI; see [ROADMAP-0.0.1.md](ROADMAP-0.0.1.md).
- **0.0.2:** M5 — reviewed check packs, one useful application pack and external authoring.
- **0.0.3:** M3 — additional providers and local inference; see
  [ROADMAP-0.0.3.md](ROADMAP-0.0.3.md).

Operational features are tentatively assigned to [0.0.4](ROADMAP-0.0.4.md).
Optional bounded assessment lives in the [research roadmap](ROADMAP-RESEARCH.md),
with no promised shipping version or dependency on this release.

Historical milestone IDs are preserved; M5 ships before M3. Product release numbers
are separate from the report's `schema_version`.

Prioritize useful new coverage: package one existing domain, add one real application
assessment, then extract the authoring API from those examples. This release must
produce more than a plugin framework. It uses the existing inference provider and
does not depend on additional providers, emulation or chunking.

`SPEC.md` remains the implementation contract. M5 is a new design proposal: update
relevant spec sections alongside each implementing slice before introducing public
contracts. This document does not authorize weakening the read-only boundary or
loading arbitrary third-party code at runtime.

## Shared requirements

- Every target command remains a reviewed catalog entry executed through the runner.
  Packs cannot execute commands directly, supply shell scripts, replace the canary,
  override core checks or change transport behavior.
- Policy retains ownership of path access, redaction, elevation and budgets. Selecting
  a pack does not grant new path access or increase execution budgets.
- Parsers receive only redacted, bounded evidence. Posture rules read facts, preserve
  unknown states and do not execute checks. Findings use the common store and grader.
- Full-request context guards from 0.0.1 remain enforced. Larger pack catalogs and
  evidence must not silently exceed model-input or execution budgets. Overflow preserves
  facts/findings and reports an incomplete assessment with exit 2.
- Existing report compatibility, fixture tests, AI quality/adversarial release checks
  and read-only integration guarantees continue to apply. Mock transcripts establish
  software behavior, not model quality. Run `make check` before implementation commits.

## M5 — reviewed check packs

Goal: an external contributor can add a reviewed application assessment pack without
modifying the runner, policy engine, agent loop or report renderer.

A pack bundles checks, parsing support, finding definitions, posture rules and fixtures
for a domain such as nginx or PostgreSQL. In 0.0.2 packs are reviewed and compiled into
the binary. Selecting among compiled packs may narrow the active catalog; configuration
does not introduce new commands. Arbitrary compiled Go code is trusted code, not a
sandbox: review and integration tests remain necessary.

Providers retain their separate `llm` contract. External exporters can consume report
JSON. Neither requires a universal plugin interface with access to all scheck internals.

### M5.1 — explicit catalog assembly and one built-in pack

Replace implicit global registration with explicit assembly of the reviewed built-in
packs into one validated, immutable catalog. Use that same catalog for planning,
execution, discovery and sudoers generation. Keep execution of resolved entries
internal to the runner so callers cannot pass an arbitrary check definition to execute.

Move one existing domain into a pack as the first consumer. Preserve its check and
finding IDs and observable behavior; packaging alone must not create report churn.

**Demo:** the existing domain produces the same plan, evidence, findings and text/JSON
reports before and after the move.

**Done when:** assembly rejects duplicate definitions, core overrides and invalid
catalog entries before execution; the core still owns exactly one canary; existing
fixtures and read-only integration tests pass. One authoritative catalog feeds every
consumer, and callers cannot mutate it after validation.

**Spec work:** §2, §3, §4 and §8; document pack assembly without changing command admission.

### M5.2 — first application assessment pack

Choose one concrete application and implement a complete assessment pack. Prefer a
small, useful set of checks and findings over introducing a generic rule language.
Review each new command's read-only behavior; passing the existing character and
denylist checks alone does not establish that an unfamiliar executable is safe.

**Demo:** fixtures for a configured application, a seeded issue, an absent application
and incomplete evidence produce useful, correctly attributed reports.

**Done when:** the pack adds coverage without special cases in runner, policy, agent or
renderer; new commands have read-only integration evidence; secrets remain redacted
across artifacts; rules distinguish absent, unavailable and unrecognized evidence.
Elevated checks work through existing sudoers generation and elevation enforcement.

**Spec work:** §3, §7.1, §7.5 and §11; define any new fact shapes with their consumers.

### M5.3 — external authoring contract and validation harness

Extract the smallest public contribution API demonstrated by M5.1 and M5.2. Keep
execution, transport and policy internals private. Document how an external source
package is reviewed and included in a build; adding arbitrary runtime loaders is not
part of this slice.

Provide a pack template and fixture-based validation workflow covering catalog
invariants, parsers, findings, redaction and incomplete evidence. Define compatibility
requirements for the contribution API without exposing internal implementation types.

**Demo:** an example maintained outside the core package tree is included in a custom
build using only the documented public API and passes the pack validation suite.

**Done when:** the example needs no imports from `internal/`, no edits to security
machinery and no global registration side effects. Documentation explains which
changes require core review, including new commands, parsers and fact shapes.

**Spec work:** §2, §3 and §11; explicitly revise the current all-internal package rule
only for the demonstrated contribution API.

### M5.4 — pack identity, compatibility and discovery

Give packs stable names, versions and reproducible content/build identities. Namespace
new external check and finding IDs; reserve existing core IDs. Record the contributing
pack in discovery and report metadata so results can be traced to the definitions used.

**Demo:** catalog/explain output identifies a check's pack; a persisted report identifies
the installed pack versions; a conflicting or incompatible pack prevents startup with
a clear error.

**Done when:** collision, compatibility and provenance tests pass; report schema and
goldens reflect the metadata under the established compatibility rules; pack selection
cannot silently exceed the catalog tier cap or execution/model budgets. Application
packs remain subject to the same model-input limits as built-in checks.

**Spec work:** §3, §7.4, §8 and §9.

## Sequencing and release evidence

1. M5.1 packages an existing domain and establishes one explicit catalog.
2. M5.2 delivers useful application coverage and tests the boundary against new needs.
3. M5.3 extracts a minimal public API and proves it with an external authoring example.
4. M5.4 finishes pack provenance, selection constraints and compatibility validation.

0.0.2 sign-off requires:

- One existing domain and one new application using the pack contract, with useful
  findings and coverage behavior demonstrated on clean, seeded and incomplete fixtures.
- An external authoring example using only the documented public contribution API.
- Pack provenance, conflict detection and compatibility validation.
- Unchanged security, redaction and read-only execution guarantees, with `make check`
  passing and relevant integration results recorded.
- Existing AI evaluations remain green; extend evidence and adversarial cases for the
  new application's contribution to model inputs where applicable.

M3 is not a dependency of this release. If actual users are blocked by inference
provider availability or data-egress restrictions, explicitly revisit release order
and prioritize the relevant M3 slices. Do not silently expand 0.0.2's scope.

## Outside 0.0.2

- Additional providers, tool-call emulation, guaranteed local-only inference and
  small-context chunking belong to the [0.0.3 roadmap](ROADMAP-0.0.3.md).
- Runtime installation of packs that introduce arbitrary commands or executable code.
- A plugin marketplace, automatic plugin updates or a general lifecycle-hook framework.
- Unrestricted scripts, custom transports or plugin-owned policy/elevation paths.
- A generic rule language or dynamically loaded parser runtime without demonstrated need.
- The optional bounded-assessment research track as a mandatory release dependency.

Runtime declarative packs may be considered after real authoring experience. They
require a separate command-admission design: using approved templates can preserve a
bounded surface, while admitting new command families changes the current compiled
catalog trust contract. A signature identifies a publisher; it does not prove that a
command is read-only.
