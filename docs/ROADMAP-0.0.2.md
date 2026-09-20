# scheck — roadmap to 0.0.2

**Status (2026-09-20):** proposed, not implemented. The first application is deliberately
undecided; M5.0 must select it and freeze its assessment scope before pack implementation.
The decisions below are the proposed release contract, not descriptions of current CLI
behavior. `SPEC.md` remains authoritative until each implementing slice updates it.

## What this release delivers

An operator can assess one additional application on a supported host, get actionable
findings without a model, and see exactly which reviewed definitions and evidence
produced the result. A Go contributor can build another pack against a documented
contribution API without importing `internal/` or changing security machinery. An operator
can also identify their own running application, such as a self-hosted Next.js service,
and assess its deployment using shipped checks without writing Go or rebuilding scheck.

The official binary ships the existing host coverage, an extracted `sshd` pack and
**one new application pack**. Packs are reviewed source compiled into the binary.
Installing a pack means reviewing and rebuilding source; there is no runtime installer.
Packaging existing checks alone does not satisfy this release. M5.2a additionally delivers
custom application assessment, with a running Next.js deployment as the required example.
This can reuse the selected application pack if M5.0 selects Next.js; otherwise it adds
bounded runtime coverage, not a second complete framework assessment pack.

The sequence remains [0.0.1](ROADMAP-0.0.1.md) (core assessment and evaluated AI) →
**0.0.2 / M5** (application packs) → [0.0.3](ROADMAP-0.0.3.md) (providers and local
inference). Operational features remain in [0.0.4](ROADMAP-0.0.4.md); bounded assessment
remains [research](ROADMAP-RESEARCH.md). Historical milestone IDs are retained.
Planning may proceed while 0.0.1 gates are open; 0.0.2 publication requires the 0.0.1
release gates to be satisfied first. Product versions and report schema versions differ.
The planned M2.6a slice in [0.0.1](ROADMAP-0.0.1.md#m26a--pre-release-evidence-and-execution-hardening-planned)
establishes observation references and ID-only runner execution; M4.5 records the host
behavior this release must preserve. The M5 slices build on those contracts.

## Decisions this plan makes

| Question | Proposed decision |
|---|---|
| First existing domain? | `sshd`: both platform definitions of `sshd.config`, its two posture rules and their finding definitions. Keep existing IDs, evidence, grading and default behavior. |
| First new application? | Selected in M5.0 using a written assessment brief; no placeholder application may survive that gate. |
| Custom applications? | Operator declarations bind one named running service per invocation to reviewed checks. Ship a Next.js deployment example; declarations contain identifiers and expected behavior, never commands or executable rules. |
| Who resolves a running application? | A bounded core workflow owns service/process binding and its uncertainty. It invokes catalog IDs through the runner; packs supply no orchestration hooks. |
| What identifies evidence? | A run-local observation reference identifies one check invocation, including its bound parameters and execution occurrence. Check IDs identify definitions, not individual observations. |
| What may a parser contribute? | A namespaced parser implementation producing a supported fact shape. Predicates depend on the shape and its completeness contract, not the parser's identity. |
| Supported deployments? | At least one named Linux distribution/application-version combination with local and SSH integration coverage. M5.0 names the exact matrix; macOS application support is optional, existing macOS host coverage is mandatory. |
| What is a pack? | Identity, checks, parsing support where needed, finding definitions, single-fact posture rules, fixtures and authoring documentation. No execution hooks. |
| What stays in core? | Bootstrap/canary, shared file primitives, remaining host checks, transport, runner, policy, agent, grading and rendering. Do not migrate every host domain in this release. |
| How are packs selected? | All compiled packs participate by default, subject to platform/profile. Add narrowing-only `disable_packs` config and repeatable `--disable-pack ID`; restrictions accumulate like `disable_checks`. Core cannot be disabled as a pack. |
| Pack dependencies? | Packs may use documented core definitions; no dependencies between optional packs, ordering hooks or dependency solver. |
| External contributions? | Reviewed Go source and a custom binary using the same public composition entry point as the official binary. No fork required for a pack using supported contribution features. |
| Compatibility promise? | A versioned contribution API and explicit supported API major per pack. No binary ABI or promise that arbitrary Go source works across future releases. |

These choices keep selection a subtraction from one reviewed command surface. An
explicitly disabled pack is outside assessment scope, not evidence of a healthy or
absent application. Disabling an individual check in an otherwise selected pack keeps
its selected rules visible as `not_assessed`, as required by SPEC §7.5. Accepted-risk
IDs are validated against the full compiled finding catalog, so disabling a pack does
not make an otherwise valid configuration invalid. Application declarations select typed parameters within the compiled surface; they do not
grant file access or make a claimed framework/runtime state an observed fact. The model
sees and may report only
the selected finding definitions (plus the existing `custom:` path); it cannot reactivate
a disabled pack by naming one of its findings.

## Security and evidence requirements for every slice

- Every target command is a literal, typed catalog entry executed through the runner.
  A pack cannot replace the canary, override core definitions, supply shell scripts,
  change transport behavior or execute a supplied check definition directly.
- Policy owns path access, redaction, elevation and budgets. Pack selection and pack
  metadata cannot add allowed paths, disable redactions or increase budgets. New command
  families need a read-only review; passing the metacharacter invariant is insufficient.
- Parsers receive only redacted, bounded captures. Rules read one fact and never execute.
  Pack findings use the common store, evidence validation, grader and accepted-risk logic.
- Compiled Go is trusted code, not a sandbox. Parser code and dependencies require review;
  a public API without an executor does not prevent malicious Go code from doing I/O.
- Preserve full-request model guards and execution limits. The composed baseline-tier
  on-demand catalog must remain at or below 40 entries. Runtime budget/context overflow
  preserves collected facts/findings, reports incompleteness and exits 2; do not silently
  remove evidence, raise caps or introduce chunking to make a pack fit.
- Preserve SSH canary-first behavior, `sudo -n --`, terminal escaping and redaction across
  reports, audit logs, persistence, verbose output, recordings and model inputs.
- Facts-only assessment needs no inference credentials. Missing tools, denied reads and
  unrecognized evidence retain coverage reasons; a missing binary alone does not prove
  `not_applicable`. Preserve existing exit-code semantics, including that individual
  unavailable checks do not by themselves force a facts-only run to exit 2.

## M5.0 — select the application and freeze the assessment brief

**Outcome:** a bounded application assessment that can be implemented and tested without
inventing requirements midway through M5.2.

Compare at least two candidates against: operator value, evidence available under
existing policy, read-only collection, deterministic findings, fixture reproducibility
and implementation size. Choose one; do not build both or a generic framework to avoid
the choice. If neither fits the security boundary, evaluate another candidate. Include a
self-hosted Next.js deployment among the candidates, without preselecting it. Independently
bound M5.2a's custom-application workflow so it remains achievable whichever pack wins.

**Deliverable:** `docs/packs/first-application.md`, containing:

1. Application, pack ID, intended operator and deployment scenario; supported distribution,
   application versions, installation layout and elevation requirements. State excluded
   layouts explicitly, including containers or nonstandard paths if unsupported.
2. At least three distinct, actionable misconfigurations assessed by posture rules.
   For each: proposed finding ID, exact condition, base severity/category, evidence
   check, recognized counterexample, abstention cases and remediation. Three is the
   release floor, not permission to pad the catalog with low-value findings.
3. A collection table: proposed check ID, literal argv and typed params, baseline or
   on-demand, parser, paths read (including indirect reads), privilege and expected
   output volume. Explain why each command cannot start services, write logs/config,
   load executable extensions or otherwise modify the target in supported deployments.
4. Treatment of absent installations, unsupported versions, includes/overrides, malformed
   configuration and incomplete reads. State whether evidence describes saved config or
   effective running state; do not claim the latter from the former.
5. A fixture manifest with expected findings, assessments and exits, plus the integration
   setup needed to prove read-only local and SSH collection. Include an output-size
   estimate against existing execution and model-input budgets.
6. The custom-application contract for M5.2a: one supported Next.js/Linux/service-manager
   combination, how a declaration identifies the process and listeners, and at least two
   useful deterministic deployment findings with counterexamples and abstention cases.
   Name which existing checks can supply evidence and which reviewed additions are needed.
   Do not require reading a project directory outside current path policy to meet the demo.
   Specify the bounded service-to-process binding sequence, evidence used to distinguish
   process lifetimes, maximum follow-up checks and when binding becomes uncertain. Walk
   through missing services, wrappers/children, PID reuse and a restart between reads.
   Each deterministic finding must name one observation that proves its condition;
   identity bookkeeping must not become a hidden cross-fact security predicate.
7. Parser contracts for the proposed checks: separate implementation IDs from output
   shapes, name the fields/completeness information consumed by each predicate, and
   identify any shape needing a reviewed core addition. Prefer an existing shape when
   it faithfully represents the evidence; do not encode a verdict to avoid adding one.

**Demo/review:** walk each proposed finding from one realistic evidence example to the
expected report. A reviewer can identify what will be assessed and what will remain
unknown without reading future code.

**Done when:** every item above is concrete, the selected commands have a documented
read-only rationale, and no required check needs a policy bypass or a new target
credential mechanism. Technical uncertainties are resolved with bounded experiments
on disposable integration targets, not left as M5.2 TODOs. Record the selection and
rejected alternative's tradeoff in the brief.

**Spec work:** identify required changes to §2–§4, §6, §7 and §11, including binding,
observation references and parser shapes. This gate records the design; implementation
and corresponding spec updates belong to M5.1, M5.2 and M5.2a.

## M5.1 — explicit composition, pack identity and the sshd extraction

**Depends on:** M5.0, so the internal boundary is informed by the new application's needs.
Keep the contribution interface internal until the two real packs exercise it.

**Deliver:**

- Replace `init()` registration in `internal/check/{common,linux,macos}` with explicit
  composition and validation of core plus packs. Assemble checks, finding definitions,
  parser bindings and rule references together; validating checks alone is insufficient.
- Separate parser implementation identity from output shape in that composition.
  A parser declares a supported shape and returns its defined value and completeness
  metadata; composition validates predicate compatibility against the shape. Core owns
  shape contracts, common predicates and summary behavior. Adding a parser for an
  existing shape must not require consumer branches keyed on its parser or pack ID.
  Unsupported shapes fail composition; a parser returning a value inconsistent with
  its declared shape produces unavailable evidence, never a predicate panic or pass.
- Make the validated catalog immutable, including nested argv/parameter slices and
  values returned to callers. Planning, runner lookup, agent menus, finding validation,
  discovery and sudoers generation consume this same composition.
- Preserve M2.6a's ID-only runner execution while replacing registry lookup with the
  validated composition. No exported path may execute a caller-supplied definition.
- Extract `sshd.config` for Linux and macOS and the `sshd.password_auth_enabled` and
  `sshd.root_login_enabled` findings/rules into the `sshd` pack. Leave `remote.*` checks
  and shared file primitives in core. Preserve check ordering and existing behavior.
- Establish identity now: stable pack ID, pack version, contribution API major, supported
  platforms and source/build identity. Reserve core and existing IDs; new external check,
  finding and parser IDs must use their pack's namespace under the existing ID grammar.
- Implement the selection semantics above across config inspection, plans, execution,
  model menus and sudoers. Unknown pack IDs or attempts to disable core fail with exit 3
  before target contact. Validate the full compiled composition even if a pack is disabled.

**Acceptance tests:**

1. Reject duplicate pack IDs, overlapping check ID/platform definitions (including `any`
   collisions), conflicting finding/parser IDs, missing references, incompatible parser/rule
   pairs, API-major mismatches, core overrides and an extra/missing canary before execution.
2. Mutating input definitions or returned definitions cannot change execution after validation.
   Two catalogs can coexist in tests without global registry resets or leakage.
3. With all packs enabled, existing fixtures retain their plans, command traces, facts,
   findings, assessments and text reports; JSON differs only by documented additive metadata
   and volatile run fields. Compare against M4.5's 0.0.1 regression artifacts, preserving
   observation links. No renamed historical IDs or changed severities.
4. Disabling `sshd` removes its checks from the plan/menu/sudoers and prevents runner calls
   to those IDs. It removes its rules from assessment scope and records that exclusion.
   `disable_checks`, path denials and profiles still narrow the selected surface.
5. Exactly one core canary runs first over SSH; existing redaction and read-only integration
   tests remain green. The tier cap is checked over the full composition per platform,
   not separately for each pack.
6. Distinct parser implementations producing the same supported shape work with the
   same predicates and summaries. Reject incompatible shape/predicate bindings before
   target contact; malformed parser results retain an explicit coverage limitation.

**Demo:** compare existing fixture reports before/after extraction, then show a local
plan with `--disable-pack sshd`. Attempt a model call to `sshd.config` in that selection
and show a denial with no target execution.

**Spec work:** §2–§4, §7.1, §7.4–§7.5, §8–§9 and §11. Pack identity is foundational;
M5.4 verifies its presentation and reproducibility rather than inventing it at the end.

## M5.2 — deliver the selected application's assessment

**Depends on:** M5.0 brief and M5.1 composition.

Implement the brief's checks, parsers, findings and fixtures as one application pack.
Reuse existing parsers and predicates where they express the evidence faithfully. Add
a typed shape only with a named consumer; do not introduce a generic rule language.
A needed reusable capability is a reviewed core change with its own tests/spec update,
not an application-name branch in runner, policy, agent or renderer.

**Required evidence matrix:**

| Case | Required result |
|---|---|
| Recognized configuration disproving all pack predicates | No pack findings; each predicate has recognized `not_matched` evidence. This is not a general security verdict. |
| Each seeded issue individually, plus a combined case | Exactly the labeled pack findings, evidence references and deterministic grades; no duplicates. |
| Application absent / binary missing | No fabricated finding or healthy verdict; `not_applicable` only when the rule's own evidence proves it, otherwise `not_assessed`. |
| Unsupported version, layout or syntax | Explicit coverage limitation; unknown values never become a pass. |
| Permission denied, sudo refused, disabled check or denied path | Existing reason codes and actionable missing-coverage explanation; no bypass. |
| Redacted, truncated, malformed or timed-out evidence | Abstain where the condition is unproven; a complete positive record may still prove an existential finding. |
| Secret and hostile instruction planted in application evidence | Secret absent from all downstream artifacts with its marker present; instruction text remains evidence and cannot widen execution or suppress rule findings. |
| Combined host and pack output exceeds a budget | No raised limits or silent omission; preserve evidence and report the applicable incomplete outcome. |

**Demo:** on a supported disposable target, run local and SSH facts-only assessments
without an API key. Show one recognized counterexample, one finding and one incomplete
evidence case. The issue case exits 1 when its grade reaches the selected profile threshold;
the other cases follow the existing exit table, not a new pack-specific exit scheme.

**Done when:** every finding in the brief is implemented with firing, disproving and
abstaining fixtures; schema-valid JSON, text and persistence agree; the matrix passes;
new commands have empty target filesystem diffs in controlled integration runs; and
sudoers fragments pass `visudo -cf` and support the elevated checks where applicable.
Freeze target state before collection so setup/service activity is not confused with
checker writes. Review command behavior as well as filesystem diffs.

Record supported versions, commands, observed coverage and limitations in the brief.
Exercise pack evidence and finding IDs through the existing agent and grader; real-model
quality evidence is a release gate in M5.4, not something mock transcripts can establish.

**Spec work:** §3, §4 if a reviewed common capability is needed, §7 and §11.

## M5.2a — assess a user's running application (Next.js example)

**Depends on:** M5.0's custom-application brief and M5.1 composition. May proceed alongside
M5.2; both must finish before the public contribution API is extracted.

**User outcome:** “Assess my running `storefront` application on this host.” The operator
uses the official binary, identifies the service and supplies expected deployment context.
They do not need to author a pack for each application they build.

**Proposed configuration and invocation** (implemented and specified in this slice):

```yaml
applications:
  storefront:
    framework: nextjs
    service: storefront.service
    expected_listener: {address: 127.0.0.1, port: 3000, proto: tcp}
```

```sh
scheck local --app storefront --stop-after facts
scheck ssh user@host --app storefront --stop-after facts
```

`--app` adds assessment of one declared application to the normal host assessment.
It does not start the service or restrict away host coverage. Without the flag, no
application-instance checks run; compiled host/application packs retain their default
behavior. `framework` is an operator hint, `service` a validated identifier and the
listener an expectation, not proof of identity or safety. Declarations cannot supply
argv, scripts, parsers, credentials or allowed paths. Disabled packs/checks stay disabled.
Validate unknown names and invalid bindings before target contact; expose the resolved
application selection through config inspection and plans.

**Binding ownership:** a bounded core application-binding workflow owns the transition
from a validated declaration to observed service/process identity. Configuration and
planning validate static identifiers without target contact; the workflow resolves
runtime-dependent parameters from recognized observations after normal target bootstrap.
It executes only catalog IDs through the runner under the same selection and budgets.
It exposes binding status and supporting observation references to evaluation and
reporting, so callers do not reconstruct service/PID relationships independently.

M5.0 fixes the supported service-manager sequence and its collection bound. Core checks
the observed service membership and process-lifetime evidence needed for attribution;
a PID alone does not establish continuity. Missing, ambiguous, inaccessible or changed
identity ends that binding attempt with an explicit reason, without an automatic retry
loop. Keep collected observations, but assessments requiring an unproven binding become
`not_assessed`; unrelated host assessments remain usable. Describe consistency as what
the observations establish, not as an atomic snapshot of a running service.

Binding establishes which subject evidence belongs to; it does not combine observations
into security conclusions. Rules still evaluate one observation. Do not synthesize a
single “fact” by joining service, process and listener outputs to evade that boundary.
This slice adds no generic dependency scheduler or pack-supplied execution callbacks.

**Observation identity:** reuse the store and citation contract established by
[M2.6a](ROADMAP-0.0.1.md#m26a--pre-release-evidence-and-execution-hardening-planned).
Application binding adds observations to the same store as baseline and agent calls;
it does not introduce another identity scheme or a map keyed only by check ID.
Application attribution references the binding evidence as well as the condition's
evidence. Extend reporting and persistence with that attribution while preserving exact
citation validation, distinct repeated observations and the existing evidence-inclusion
policy. Specify these application additions in this slice and apply SPEC §7.4 versioning;
the general observation/tool contract already belongs to 0.0.1.

**Deliver and demonstrate:**

- Collect service/process identity, runtime user, recognized launch mode and actual
  listener information through catalog checks. A process merely named `node`, a declared
  port or a source package dependency alone does not establish that this running service
  is Next.js. Report ambiguous identity, restarts and inaccessible process metadata.
- Implement the brief's two or more deployment findings. Candidate conditions are an
  explicitly recognized development-server invocation or an application process running
  as root; M5.0 fixes their exact evidence, grades and limitations. Report bind addresses
  as observed facts, not proof of internet reachability. Comparing separate service,
  listener and proxy facts remains phase 2 work; do not hide joins in single-fact rules.
- Keep expected and observed state distinct in the report. Attribute application facts,
  findings and coverage through the binding and observation contracts above. Preserve
  existing finding-ID merge semantics while retaining all distinct supporting observation
  references. Multiple application instances in one invocation and subject-specific
  finding deduplication remain deferred; repeated observations reuse M2.6a's contract.
- Read only policy-approved evidence. A project path is not a new allowed prefix; a
  deployment under `/srv` or a user's home may still be assessed from permitted runtime
  metadata, with file-based checks explicitly unavailable. Never execute `next.config.*`,
  package scripts, `npm`/`npx`, builds or application tests to discover configuration.
  Do not dump process environments or `.env` contents to discover secrets or runtime mode.
- Pin the tested Next.js version and deployment form. The framework's documented
  [development/production launch modes](https://nextjs.org/docs/app/api-reference/cli/next)
  and [self-hosting model](https://nextjs.org/docs/app/guides/self-hosting) inform the
  fixture design; standalone servers and custom wrappers require their own recognized
  evidence. A production-looking command is not proof that the application is secure.

**Done when:** an already-running Next.js fixture deployment is assessed locally and over
SSH without inference credentials or a custom build. Cover recognized production launch,
seeded development launch, a privileged process, service missing, wrong/ambiguous binding,
process replacement during collection, denied evidence and hostile/secret-bearing output.
Assert labeled findings and coverage, correct attribution, redaction, unchanged target
state and no requests to the application's HTTP endpoints. An unreadable project tree
must not prevent reporting the runtime evidence that was collected.

Extend M2.6a's repeated-check and citation tests to application binding: every observation
survives, citations resolve to the correct execution, and JSON/persistence preserve
application attribution. Include a PID-reuse/restart fixture where observations remain
available but application attribution cannot be established, and prove no unbounded
recollection occurs. Disabled checks/packs and exhausted budgets must also stop dependent
binding steps without a bypass or fabricated application assessment.

**Boundary:** this is deployment posture assessment. HTTP header/cookie/TLS probing,
authentication tests, route crawling, dependency vulnerability scanning and source-code
security review are outside this slice. Even GET/HEAD requests can execute application
logic, generate logs or populate caches; active web testing needs a separate explicit
side-effect and target-scope contract. Do not smuggle it in as a read-only catalog command.

**Spec work:** §2–§4, §6, §7.4–§7.6, §8–§9 and §11. Specify application declarations,
parameterized baseline planning, binding ownership and application report attribution
on M2.6a's observation contract. Update §5.7 and §7.3 where application attribution
extends evidence references, without introducing another execution path or changing
path-policy authority.

## M5.3 — public authoring API and an independently built example

**Depends on:** M5.1, M5.2 and M5.2a. Extract only contribution features demonstrated
by the packs and custom-application workflow. Do not publish internal runner, transport,
policy or report implementation types.

**Deliver:**

- Public definition types, explicit composition/CLI entry point and fixture validation
  helpers. A contributor supplies pack definitions and pure parsing support; core retains
  execution, rule evaluation, grading, evidence validation and rendering.
- Publish the supported fact shapes and their completeness contracts separately from
  parser implementation IDs. External parsers return those values; consumers use common
  predicates, summaries and serialization. New shapes or predicate capabilities require
  a reviewed core/API change, not arbitrary return types or pack-owned renderer hooks.
- A documented custom-build recipe with pinned module versions, source review steps and
  an explicit pack list. No blank imports, global registration, source-file patching or
  undocumented build tags to include a pack.
- A minimal template and authoring guide covering command review, IDs, parser completeness,
  rule recognition, redaction, supported platforms, sudoers binary metadata and compatibility.
  Reviewed sudoers metadata stays declarative and cannot grant anything beyond catalog argv.
- A validation harness accepting fixture transcripts and expected facts/findings/assessments.
  It runs composition invariants and positive, negative, incomplete and secret-bearing cases
  offline; it also proves intentionally invalid packs fail with useful diagnostics.

**Demo:** an example in a separate Go module imports the public API, builds a custom
`scheck` with core plus the example, and produces a fixture-backed report. A separate
module checked into the repository is sufficient; a separately hosted repository is not
required. It must define a distinct namespaced parser in that module, returning a
supported shape consumed by a core predicate and summary, and produce schema-valid JSON
and a persisted report with observation references. Cover complete, incomplete and
invalid parser results. It may reuse the first application's evidence format and need
not add a second production application, but merely importing its existing definitions
does not demonstrate the parser contribution boundary.

**Done when:** CI builds/tests that module without `internal/` imports or edits to core
source; the official binary uses the same composition path; validation catches broken
references and secret leaks; and documentation distinguishes supported contributions
from changes needing a core implementation review. An author can add a check using
supported parsing/rule features without editing runner, policy, agent or renderer.

Publish the contribution API major and version-change policy. Pack versions identify
content releases; API compatibility and report schema compatibility are separate checks.
Trusted code review remains required even when every harness test passes.

**Spec work:** §2–§3, §8.1 and §11. Revise the all-internal rule only for the demonstrated
public API; keep security enforcement private.

## M5.4 — operator discovery, provenance and release sign-off

**Depends on:** M5.1–M5.3. This closes the release, not a second framework-design phase.

**Operator contract:**

- `scheck catalog` and `scheck explain` identify each check/finding's owning pack and
  version. Discovery JSON also lists compiled packs, compatibility and selection state,
  including packs contributing no checks on the requested platform.
- `config show` explains accumulated pack exclusions; `config validate` rejects unknown
  names without executing checks. Plans and sudoers reflect the same effective selection.
- Persisted and emitted reports record compiled pack identities and effective selection,
  including disabled/unsupported packs. Verbose text shows provenance; default text keeps
  the existing findings-first layout and makes assessment exclusions visible without
  suggesting those packs were assessed.
- A report can map a check, assessment or finding back to its contributing definitions.
  Pack identity includes a pinned source revision/module checksum or deterministic source
  digest, plus the enclosing build revision and dirty/unknown status. A version label alone
  is insufficient. Repeating a build from the same pinned inputs yields the same pack
  identity; changing parser/rule code changes identity even if a version was not bumped.
- No network lookup is needed to inspect provenance or read a persisted report. Unknown
  development build provenance is labeled honestly; official release artifacts require
  complete identities. Provenance identifies source, not a security certification.

**Release record:** `docs/releases/0.0.2.md`, tied to the release commit and containing:

| Gate | Required recorded evidence |
|---|---|
| Useful assessment | M5.0 brief, supported deployment matrix and M5.2 expected/actual findings and coverage. |
| Custom application | M5.2a's Next.js local/SSH demo using the official binary, runtime finding/abstention fixtures, bounded binding and restart/PID-reuse attribution tests; no app code execution or HTTP probing. |
| Preserved host behavior | Before/after fixture comparison for Ubuntu, Fedora and macOS; reviewed schema/golden diffs. |
| Closed execution surface | Composition failures, mutation isolation, disabled-ID denials, canary, redaction and budget tests. |
| Read-only collection | Local/SSH integration results on every claimed application deployment; empty controlled filesystem diffs and sudoers validation where applicable. |
| External authoring | Separate-module build and validation using only the documented API, including its own parser consumed by core predicates, summaries and persistence. |
| Traceability | Discovery/report/persistence examples, pack identity repeat/change tests, distinct repeated observations with exact citation validation, and compatibility rejection tests. |
| AI regression | Existing live quality/adversarial criteria pass, extended with application cases; record model, prompt, pack/build identities, repetitions and failures. |
| Release hygiene | Green `make check` (including `go fix`), relevant integration results and the artifact checks established by 0.0.1. |

Freeze application evaluation cases and pass thresholds before running the live comparison;
reuse the 0.0.1 harness and criteria where applicable. Include clean, seeded, incomplete
and hostile/benign paired application evidence, including M5.2a runtime metadata. Mock tests run in ordinary CI; live tests
remain opt-in but their recorded results gate publication. No requirement that the new
pack demonstrate a new agent capability beyond its declared assessment scope.

**Done when:** all gates have evidence for the release commit. Unrun tests, unavailable
credentials or unsupported deployment combinations are not passes. A failing gate requires
a fix or an explicit revision of release scope, not a quieter report or weaker criterion.
Apply SPEC §7.4 compatibility rules and publish the actual report schema/API versions.

**Spec work:** §7.4, §7.6, §8–§9 and §11; update quick-start and authoring documentation.

## Sequence and scope control

M5.0 selection → M5.1 internal composition/sshd → M5.2 application pack and M5.2a
custom application assessment → M5.3 public API/example → M5.4 release evidence.
Each slice ends with its stated demo and checks; update status with implementation and validation evidence separately.
There are no calendar estimates until M5.0 bounds the application work.

The minimum release contains preserved host coverage, one useful new application pack,
custom application assessment demonstrated on Next.js, one authoritative execution
catalog, an independently usable authoring API and traceable results. If application
collection cannot satisfy read-only policy, return to M5.0. If the authoring boundary needs redesign, keep it internal until it is proven.
Do not ship a framework-only release under the same completion claim.

## Outside 0.0.2

- A second complete application pack beyond M5.2 and the bounded M5.2a workflow,
  migration of every existing domain, or a promise of every application version,
  installation layout or platform.
- Multiple application instances per run, managed-hosting control-plane integrations,
  active web testing, arbitrary source-tree reads and application code execution.
- Runtime loading/installing of new commands or executable code, pack marketplaces,
  automatic updates, signatures-as-command-approval or a generic lifecycle framework.
- Pack-owned policy, transports, credentials, elevation, model prompts/tools or exporters.
  Providers keep their separate inference contract; exporters can consume report JSON.
- Arbitrary scripts, a generic rule language, cross-fact deterministic rules, a dynamic
  parser runtime or dependency resolution between optional packs.
- Additional providers, emulation, local-only inference or small-context chunking (0.0.3).
- Category filtering, SARIF and posture diff (0.0.4), and mandatory bounded assessment.

Runtime declarative packs need a separate command-admission design after real authoring
experience. A signature identifies a publisher; it does not prove a command is read-only.
If provider availability blocks adoption, explicitly revisit release order rather than
silently expanding this release.
