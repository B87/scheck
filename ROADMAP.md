# scheck — roadmap to v1

This decomposes `SPEC.md`'s five milestones (§10) into slices small enough to ship and
demo individually. Each slice is vertical — it produces something runnable, not a layer
that only compiles. Slices are numbered in dependency order within their milestone;
milestones themselves are ordered, but a later milestone's early slices sometimes have
no dependency on the one before it, and that's noted where it matters for parallelizing
two people's work.

Every slice lists: what it delivers, a **demo** (a command that proves it works), what
must be true before it's done, and which spec section it implements. "Done" always
includes tests, not just code — the testing strategy in `SPEC.md` §11 is distributed
across slices below rather than saved for the end.

---

## M0 — walking skeleton (no model)

Goal: prove the security boundary and the transport layer before a single line of
agent code exists. Everything here is testable without any LLM and without a real SSH
target.

### M0.1 — `target.Target` over local exec
Deliver `target/local`: `Exec(ctx, argv) (stdout, stderr, code, error)` via `os/exec`,
no shell, with per-call timeout from a hardcoded budget.
**Demo:** a throwaway `main.go` that runs `target.Local{}.Exec(ctx, []string{"uname", "-a"})` and prints the result.
**Done when:** unit tests cover timeout, non-zero exit, missing binary, and stdout/stderr
truncation at a byte cap. No shell metacharacter in an argv element is ever
special-cased — prove it by running `Exec(ctx, []string{"echo", "$(whoami)"})` and
asserting the literal string comes back.
**Spec:** §2, §4.

### M0.2 — check type + catalog invariants test
Deliver the `check.Check` / `check.Param` types (§3) and the invariants test that scans
whatever catalog exists so far: no literal token contains shell metacharacters, every
`{placeholder}` binds exactly one typed `Param`, no binary from a hardcoded write-capable
denylist. Catalog itself is empty or has one dummy entry — this slice is the test
harness, not the content.
**Demo:** add a deliberately broken entry (`Argv: []string{"rm", "-rf", "{path}"}`) and
watch the invariants test fail with a specific rule name.
**Done when:** the invariants test is table-driven and fails loudly (not panics) on each
violation class: metacharacter in literal, unbound placeholder, multiply-bound
placeholder, mutating flag, disallowed binary.
**Spec:** §3 invariants, §11.

### M0.3 — `policy.PathPolicy`
Deliver path classification: allowed prefix / denied / sensitive-metadata-only, plus
symlink resolution before the decision and traversal rejection at the charset level.
**Demo:** a CLI-less test binary that takes a path on argv and prints
`allowed | denied | metadata-only` plus the matched rule.
**Done when:** the hostile-path corpus from §11 passes — traversal, symlink escape,
sensitive path via a resolved symlink from an allowed prefix.
**Spec:** §4.1.

### M0.4 — redactor with markers
Deliver the redaction pipeline: private keys, `AKIA…`, bearer tokens, `password=`-style
values, `redact_extra` regexes — every match replaced with
`[REDACTED:<rule>:<n bytes>]`, never silently dropped.
**Demo:** feed a fixture blob containing a seeded AWS key and a seeded private key
through the redactor and diff before/after.
**Done when:** seeded-secret test passes for every rule class, and a redaction always
leaves a marker (assert no rule produces empty output).
**Spec:** §4.2, §11 redaction tests.

### M0.5 — budgets + audit log
Deliver `policy.Budgets` as one struct (§4.4) and the JSONL audit logger: every
attempted check, decision, exit code, duration, output hash.
**Demo:** run three `Exec` calls (one allowed, one denied, one that hits the hard
timeout) and `cat` the resulting audit log.
**Done when:** a denied call never disappears silently — it's a logged line with
`decision: denied:<rule>`, and the hard-timeout call is logged as `unavailable`, not
as a crash.
**Spec:** §4.4, §4.5.

### M0.6 — first real checks + `scheck catalog`
Wire M0.1–M0.5 together: define ~10 real baseline checks (OS/kernel, listening sockets,
sshd config for one platform — pick Linux first), and ship `scheck catalog` printing
every check's id, params, and platform.
**Demo:** `scheck catalog --profile baseline` on a dev machine, and
`scheck local --stop-after plan` printing the same list gated by platform detection.
**Done when:** acceptance criterion 2's proof starts here — the catalog invariants test
now runs over real content, not a dummy entry.
**Spec:** §3 baseline table (Linux rows), §8 (`--stop-after plan`, `scheck catalog`).

### M0.7 — SSH transport + canary
Deliver `target/ssh` and the canary check (§4.3): first command on any session is the
round-trip string; a mismatch aborts with exit 3 before any other command is sent.
**Demo:** `scheck ssh user@vm --stop-after plan` against a real VM, and the same command
against a container whose login shell is `fish`, showing the abort.
**Done when:** the canary matrix test (sh, bash, zsh, fish, rbash in containers) passes
with the documented pass/fail split, and the quoting function's test covers the full
enumerable domain from the M0.6 catalog's literals and param charsets.
**Spec:** §4.3, §11 quoting tests, acceptance criterion 11.

### M0.8 — elevation prefix + `scheck sudoers`
Deliver `--elevate none|sudo` as an argv prefix, `unavailable: requires elevated read`
for gated checks under `none`, and `scheck sudoers` generating the NOPASSWD fragment
from every `Elevated: true` catalog entry.
**Demo:** mark `sshd.config` as elevated, run `scheck local` under both elevate modes,
then `scheck sudoers` and paste its output into a throwaway VM's sudoers.d to show the
elevated check going from `unavailable` to populated.
**Done when:** `sudo -n` failure (no NOPASSWD configured) degrades to `unavailable`
rather than hanging or prompting.
**Spec:** §8.1.

**M0 exit demo:** `scheck local --stop-after plan` and `scheck ssh user@vm --stop-after plan`
both print a real, non-empty check plan; `scheck catalog` and `scheck sudoers` both
work; the audit log and invariants test are the two things a reviewer checks to believe
the security boundary holds. This is acceptance criteria 2 and 3's foundation (the
before/after filesystem diff in criterion 3 can be run for the first time here, since
nothing yet writes to the target by construction).

---

## M1 — baseline (still no model)

Goal: `scheck` is useful today, offline, before phase 2 exists at all.

### M1.1 — macOS baseline checks
Port every macOS row of the baseline table (§3) through the M0 machinery.
**Demo:** `scheck local --stop-after facts` on a Mac.
**Done when:** platform detection picks the right check set automatically; fixture
tests exist for macOS parsing (no live Mac required in CI).
**Spec:** §3 baseline table (macOS rows).

### M1.2 — remaining Linux baseline checks
Fill in the rest of the Linux baseline table (accounts, sudoers, persistence units,
SUID scan, logging, time sync) — M0.6 only did a starter subset.
**Demo:** `scheck local --stop-after facts` on Ubuntu and on Fedora, diffing the
fact sheet shape between distros (apt vs. dnf pending-updates parsing).
**Done when:** fixture targets exist for both distros; a probe failure on one
(`ufw` absent on a `firewalld` box) shows up as `unavailable: <reason>`, never fatal.
**Spec:** §3 baseline table (Linux rows), acceptance criterion 1 (Ubuntu + Fedora).

### M1.3 — parsers (kv / lines / json / raw)
Deliver the four parser kinds as a tested, reusable component rather than ad hoc
per-check string munging — this should have been factored out already by M1.2, so this
slice is really "extract and harden" plus edge-case tests (empty output, truncated
output, malformed json from a check that unexpectedly changed format upstream).
**Demo:** unit tests only; no user-visible demo beyond M1.1/M1.2 already using it.
**Done when:** a malformed-input fixture for each parser kind degrades to
`unavailable: parse error`, never a panic.
**Spec:** §3 (`Parser` field).

### M1.4 — report envelope + text/JSON renderers
Deliver the `schema_version`-tagged envelope (§7.4): `host`, `run`, `facts`, empty
`findings` (phase 2 doesn't exist yet, so this is always `[]`). Text and JSON renderers.
**Demo:** `scheck local --stop-after facts --format json | jq .host` and
`scheck local --stop-after facts --format text`.
**Done when:** `host.id` is stable across two consecutive runs on the same machine;
JSON validates against a schema doc committed alongside the renderer.
**Spec:** §7.4, acceptance criterion 4.

### M1.5 — run persistence
Deliver the state directory writer: every run lands at
`<state-dir>/runs/<host.id>/<started>.json`, honoring `--state-dir` / `--no-persist`,
redacted the same as the report.
**Demo:** run `scheck local --stop-after facts` twice, `ls` the state dir, and diff the
two persisted files by hand to confirm the shape that `scheck diff` will need later.
**Done when:** persistence never blocks the run (a full disk degrades to a logged
warning, not a failure).
**Spec:** §7.4.

**M1 exit demo:** `scheck local --stop-after facts` and `scheck ssh user@vm --stop-after facts`
produce a complete, correctly-shaped report with zero API key configured, satisfying
acceptance criterion 4 outright. This is a shippable tool on its own — worth flagging to
whoever's tracking scope, since it's a natural place to pause and get real usage
feedback before M2 adds cost and variance.

---

## M2 — agent (model enters the picture)

Goal: phase 2 exists and can be tested entirely offline via the `mock` provider before
a single live API call is spent.

### M2.1 — `llm` interface + `mock` provider
Deliver the interface exactly as specified in §5.1 (`Stream`, package-level `Complete`,
`Limits`, `Native`) and the `mock` provider that replays a recorded transcript file.
**Demo:** a transcript fixture (JSON) driving `mock` through a 3-turn tool-calling
exchange, asserted turn-by-turn in a test — no CLI-visible demo yet.
**Done when:** `agent`, `policy`, `check`, `finding`, `report` all compile with zero
provider SDK import — enforce with a `go list` dependency check in CI, not just a code
review comment.
**Spec:** §5.1.

### M2.2 — finding id catalog + severity assignment
Deliver `finding.Def` (§7.1) with the base severity table, plus the deterministic
grader: base severity → structured-context adjustments → confidence cap → accepted-risk
status → final severity and exit code. No model involved yet — feed it synthetic
`(id, evidence, confidence)` tuples in tests.
**Demo:** a small CLI test harness: `scheck-devtool grade sshd.password_auth_enabled --exposure internet`
prints the adjustment chain.
**Done when:** the severity test table from §11 passes, and `--ignore-context` is
proven to reproduce base severity byte-for-byte in a test, not just by inspection.
**Spec:** §7.1, §7.2, §11 severity tests, acceptance criterion 9 (the deterministic half).

### M2.3 — the three tools + agent loop, single provider-agnostic pass
Deliver `run_check`, `read_file`, `report_finding` as the closed tool surface (§5.7),
and the ~150-line loop (§5.6) wired to `mock` only. No real provider yet — this proves
the loop's control flow (iteration budget, context chunking trigger, stop-on-no-tool-calls)
against scripted transcripts.
**Demo:** `scheck local --provider mock --transcript fixtures/correlated-finding.json`
producing a full report with a real finding in it, end to end through the renderers.
**Done when:** the loop enforces every budget in `policy.Budgets` against the mock
(assert a transcript that exceeds `MaxIterations` ends as `status: incomplete`).
**Spec:** §5.6, §5.7, §5.8 (system prompt, provider-neutral).

### M2.4 — context ingestion (structured + prose)
Deliver `--context` parsing for all four source forms (§6.1), the per-kind merge
semantics, the `<operator_context>` prompt block, and the context-injection corpus test
(§11) against the mock provider.
**Demo:** `scheck local --provider mock --context note:"public jump host" --context ./docs/arch.md --context-only`
prints the merged block.
**Done when:** the hostile-context corpus passes: none of the seeded prompt-injection
strings change the auditor role, suppress findings, or alter severity.
**Spec:** §6, §11 context-injection corpus.

### M2.5 — `anthropic` provider
Deliver the real adapter: native tool calling, prompt caching breakpoints, effort
mapping. First slice that costs real money.
**Demo:** `scheck local --provider anthropic` against a real (throwaway VM) target,
producing a real report.
**Done when:** the provider conformance suite (§11) is green for `anthropic`; a live
run's cost is measured and checked against the $0.50 budget (acceptance criterion 7).
**Spec:** §5.2, §5.5.

### M2.6 — phase-2-earns-its-cost fixture
Deliver the seeded cross-domain fixture host (password auth + empty-password account +
public listener) as a reusable fixture target, run both in agent mode and in a
stripped-down single-pass mode (a temporary code path or a feature flag — doesn't need
to be the final §5.3 single-pass, just enough to prove the comparison).
**Demo:** two `scheck` runs against the fixture, diffed: agent mode's findings list
contains the correlated finding, the single-pass one doesn't.
**Done when:** acceptance criterion 10 is demonstrated and recorded (not just believed).
This is the checkpoint where the project either confirms the two-phase design or
pivots — treat a failure here as a stop-the-line result, not a footnote.
**Spec:** §2.1 rationale, acceptance criterion 10.

**M2 exit demo:** `scheck local` and `scheck ssh` produce full agentic reports against
the `anthropic` provider on both a clean host and the seeded fixture, with attributed
severity adjustments visible in the JSON output. Acceptance criteria 5, 6, 7, 9 (model
half), and 10 are all checkable at this point.

---

## M3 — second provider

Goal: prove the abstraction by making it hold under a provider that lacks native tool
calling, parallel calls, and caching — all three at once, in the worst case (`ollama`).

### M3.1 — `openai-compatible` provider (native tool calling)
Deliver the adapter for a backend that *does* support tool calling natively (OpenAI or
a vLLM/Groq/Together endpoint) — this isolates "new provider, familiar capabilities"
from "new provider, emulated capabilities," which M3.2 adds next.
**Demo:** `scheck local --provider openai-compatible --base-url ... --model ...`
against the same fixture host as M2.6.
**Done when:** conformance suite green; the same fixture's findings are structurally
identical (schema, not content) to the `anthropic` run.
**Spec:** §5.2.

### M3.2 — tool-call emulation + `ollama`
Deliver the emulation layer (§5.3): render tools into the system prompt, parse a text
protocol into `ToolCalls`, serialize parallel calls one at a time. Wire it under
`ollama`, `Local: true`.
**Demo:** `scheck local --provider ollama --model llama3.1 --local-only` against the
fixture host, showing `native.tool_calling: false` in the report header and a
`confidence` cap of `medium` on any finding from an emulated call.
**Done when:** conformance suite green for `ollama` running the *same* table as
`anthropic` — no conditional skips. This is the actual proof the abstraction is real,
not M3.1.
**Spec:** §5.3, §11 provider conformance suite.

### M3.3 — `--local-only` / egress control
Deliver the hard-error path: any non-`Local` provider under `--local-only` or
`allow_egress: false` fails before one byte leaves the machine.
**Demo:** `scheck local --provider anthropic --local-only` — assert the failure happens
before the audit log shows any network-bound activity, and before the target is even
contacted for phase 1 if that ordering matters (decide and document which comes first).
**Done when:** acceptance criterion 8 passes in full: same fixture host, two providers,
one local, structurally valid reports from both, and the egress refusal proven with a
packet-capture-free assertion (e.g. a test double that panics on any dial attempt).
**Spec:** §5.4, acceptance criterion 8.

### M3.4 — small-context chunking
Deliver the one conditional path the loop is allowed to have (§5.3): fact-sheet
chunking by domain when the prefix would exceed half of `MaxContext`, plus the final
correlation pass.
**Demo:** run against `ollama` with a small-context model (a genuinely small local
model, e.g. a 4K-context one) and the M2.6 fixture; confirm the correlated finding still
surfaces via the correlation pass despite chunking.
**Done when:** a chunked run and an unchunked run over the same fact sheet on a
large-context model agree on the correlated finding — chunking shouldn't lose the
signal M2.6 exists to prove.
**Spec:** §5.3 (context size), ties back to acceptance criterion 10.

**M3 exit demo:** the exact same fixture host audited by `anthropic`, `openai-compatible`,
and `ollama` produces three structurally identical, schema-valid reports, with the
report headers showing the honest `native` capability differences between them.

---

## M4 — polish

Goal: the remaining acceptance criteria and CLI ergonomics that don't gate correctness
but do gate calling this v1.

### M4.1 — SARIF renderer
**Demo:** `scheck local --format sarif --out report.sarif`, validated against the SARIF
schema and (if convenient) uploaded to a GitHub code-scanning check on a scratch repo.
**Spec:** §2 (`report/sarif`).

### M4.2 — profile tiers (`baseline` / `hardened`)
Deliver `MinProfile` filtering on the catalog (§3) — this is where the catalog can
finally grow past the baseline-tier cap without bloating cheap runs.
**Demo:** `scheck catalog --profile baseline` vs. `--profile hardened`, showing the
menu size difference; a live run under each profile showing token/cost difference.
**Spec:** §3 tiers.

### M4.3 — category filters (`--only`)
**Demo:** `scheck local --only remote-access,updates` skipping unrelated baseline
checks and narrowing the model's menu to those domains.
**Spec:** §8.

### M4.4 — `scheck diff`
Deliver drift detection over two persisted runs (§7.4): added/removed listeners, units,
SUID files, and findings that appeared, disappeared, or changed severity.
**Demo:** run `scheck local` on a VM, install an unexpected package that opens a port,
run again, `scheck diff` between the two persisted files.
**Spec:** §7.4, §10 M4.

### M4.5 — golden-fixture regression suite
Deliver a committed set of golden reports (input fixtures → expected report JSON) that
CI diffs on every change, covering at least one fixture per platform and one per
provider category (native tool-calling, emulated, local).
**Spec:** §11 (ties together fixture targets, mock provider, and conformance suite into
one CI gate).

### M4.6 — full acceptance criteria pass
Not new code — a dedicated pass running every criterion in §12 end to end (including
the before/after filesystem diff on a throwaway VM for criterion 3, and both Ubuntu and
Fedora for criterion 1) and recording the result. This is the v1 sign-off gate.
**Spec:** §12, all eleven criteria.

**M4 exit demo:** all eleven acceptance criteria in §12 pass and are recorded. v1 ships.

---

## Sequencing notes

- **M0 and M1 have no model dependency and no live-API cost.** They can absorb as much
  calendar time as needed without burning budget, and are the right place to get the
  security boundary reviewed by someone other than its author before M2 starts spending
  money against it.
- **M2.6 (phase-2-earns-its-cost) is the highest-risk slice in the roadmap.** It's
  placed as late as reasonably possible within M2 — after the loop, tools, and context
  ingestion all work — so that a negative result is cheap to act on: the loop and tools
  built so far are needed either way (M1's `--stop-after facts` mode and the tool
  surface used for confirmation checks), but a negative result means `agent.Session`'s
  multi-turn correlation is what gets cut, not the checks or the reporting.
- **M3.1 before M3.2 is deliberate**, not filler: it separates "does a new provider
  slot into the interface at all" from "does the emulation layer work," so a conformance
  failure in M3.2 is unambiguously about emulation.
- **Nothing in M4 blocks anything else in M4** — those five slices can run in parallel
  across contributors once M3 is done.
