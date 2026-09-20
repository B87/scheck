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

**Status (2026-09-20):** M0 and M1 are done, one commit per slice, on `main`. Every
slice below carries a ✅ with what actually landed where it differs from the plan.
Using the M1 build on a real Mac produced M1.6–M1.8 (readable phase 1, posture rules);
those are next, then M2.1. Before the first GitHub release, breaking changes are
allowed without compatibility shims or mandatory major-version bumps; implement the
spec, schema and fixture changes together (SPEC §7.4). The second-person review of
the security boundary is still open; see `AGENTS.md` for how to work in the repo.

---

## M0 — walking skeleton (no model)

Goal: prove the security boundary and the transport layer before a single line of
agent code exists. Everything here is testable without any LLM and without a real SSH
target.

### M0.1 — `target.Target` over local exec ✅
Deliver `target/local`: `Exec(ctx, argv) (stdout, stderr, code, error)` via `os/exec`,
no shell, with per-call timeout from a hardcoded budget.
**Demo:** a throwaway `main.go` that runs `target.Local{}.Exec(ctx, []string{"uname", "-a"})` and prints the result.
**Done when:** unit tests cover timeout, non-zero exit, missing binary, and stdout/stderr
truncation at a byte cap. No shell metacharacter in an argv element is ever
special-cased — prove it by running `Exec(ctx, []string{"echo", "$(whoami)"})` and
asserting the literal string comes back.
**Spec:** §2, §4.
**Landed:** `internal/target` (interface, `CapWriter`, sentinel errors) and
`internal/target/local`. Also `internal/target/fixture`, the replay target every unit
test uses, which the plan had under M1.2.

### M0.2 — check type + catalog invariants test ✅
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
**Landed:** `internal/check` with `Bind` (charset, absolute path, `..` rejection) and
`Validate` (named rules incl. `canary-count`, `baseline-tier-cap`, `bad-extract`).
The struct gained `ExitOK`, `PathUse`, `Canary`, `Extract`, `Description` (spec §3).

### M0.3 — `policy.PathPolicy` ✅
Deliver path classification: allowed prefix / denied / sensitive-metadata-only, plus
symlink resolution before the decision and traversal rejection at the charset level.
**Demo:** a CLI-less test binary that takes a path on argv and prints
`allowed | denied | metadata-only` plus the matched rule.
**Done when:** the hostile-path corpus from §11 passes — traversal, symlink escape,
sensitive path via a resolved symlink from an allowed prefix.
**Spec:** §4.1.
**Landed:** `internal/policy/path.go`. Symlink resolution happens in the runner via the
`fs.realpath` check on the target, not in the policy, since the path lives remotely.

### M0.4 — redactor with markers ✅
Deliver the redaction pipeline: private keys, `AKIA…`, bearer tokens, `password=`-style
values, `redact_extra` regexes — every match replaced with
`[REDACTED:<rule>:<n bytes>]`, never silently dropped.
**Demo:** feed a fixture blob containing a seeded AWS key and a seeded private key
through the redactor and diff before/after.
**Done when:** seeded-secret test passes for every rule class, and a redaction always
leaves a marker (assert no rule produces empty output).
**Spec:** §4.2, §11 redaction tests.
**Landed:** `internal/policy/redact.go`, single pass over the original bytes so markers
are never re-matched. Rules: private-key, aws-access-key, github-token, slack-token,
bearer, jwt, kv-secret (trivial values like `password=no` are kept), `extra:<i>`.

### M0.5 — budgets + audit log ✅
Deliver `policy.Budgets` as one struct (§4.4) and the JSONL audit logger: every
attempted check, decision, exit code, duration, output hash.
**Demo:** run three `Exec` calls (one allowed, one denied, one that hits the hard
timeout) and `cat` the resulting audit log.
**Done when:** a denied call never disappears silently — it's a logged line with
`decision: denied:<rule>`, and the hard-timeout call is logged as `unavailable`, not
as a crash.
**Spec:** §4.4, §4.5.
**Landed:** `internal/policy/{budgets,audit}.go` and `internal/runner`, the single
enforcement point: bind → realpath → path policy → elevation → budgeted exec → redact
→ truncate → extract → parse → audit. Phase 2's `run_check` must call `Runner.Run`.

### M0.6 — first real checks + `scheck catalog` ✅
Wire M0.1–M0.5 together: define ~10 real baseline checks (OS/kernel, listening sockets,
sshd config for one platform — pick Linux first), and ship `scheck catalog` printing
every check's id, params, and platform.
**Demo:** `scheck catalog --profile baseline` on a dev machine, and
`scheck local --stop-after plan` printing the same list gated by platform detection.
**Done when:** acceptance criterion 2's proof starts here — the catalog invariants test
now runs over real content, not a dummy entry.
**Spec:** §3 baseline table (Linux rows), §8 (`--stop-after plan`, `scheck catalog`).
**Landed:** `internal/check/common` (canary, platform, uname, uid, shell, hostname,
which, realpath, stat, list, cat, head), a Linux starter set, `internal/baseline`,
the `catalog` command and `--stop-after plan`. Session facts (`sys.*`) and host
identity (`host.*`) are catalog checks, not side channels, so they are audited.

### M0.7 — SSH transport + canary ✅
Deliver `target/ssh` and the canary check (§4.3): first command on any session is the
round-trip string; a mismatch aborts with exit 3 before any other command is sent.
**Demo:** `scheck ssh user@vm --stop-after plan` against a real VM, and the same command
against a container whose login shell is `fish`, showing the abort.
**Done when:** the canary matrix test (sh, bash, zsh, fish, rbash in containers) passes
with the documented pass/fail split, and the quoting function's test covers the full
enumerable domain from the M0.6 catalog's literals and param charsets.
**Spec:** §4.3, §11 quoting tests, acceptance criterion 11.
**Landed:** `internal/target/ssh` and `test/containers/shell-matrix`. Two findings
changed the canary: fish only fails on a doubled backslash, and rbash only fails on a
path-qualified binary. Host-key algorithms are derived from `known_hosts` so the
server offers the key type the file holds (plain and `|1|` hashed entries).

### M0.8 — elevation prefix + `scheck sudoers` ✅
Deliver `--elevate none|sudo` as an argv prefix, `unavailable: requires elevated read`
for gated checks under `none`, and `scheck sudoers` generating the NOPASSWD fragment
from every `Elevated: true` catalog entry.
**Demo:** mark `sshd.config` as elevated, run `scheck local` under both elevate modes,
then `scheck sudoers` and paste its output into a throwaway VM's sudoers.d to show the
elevated check going from `unavailable` to populated.
**Done when:** `sudo -n` failure (no NOPASSWD configured) degrades to `unavailable`
rather than hanging or prompting.
**Spec:** §8.1.
**Landed:** `internal/sudoers` and `test/integ/sudoers_test.go` (visudo + elevated flip
in the Ubuntu container). The runner pre-checks the binary with `sys.which` because
sudo reports a missing binary as "a password is required". `grep -rH .` replaces the
empty-pattern form, which sudoers cannot express.

**M0 exit demo:** `scheck local --stop-after plan` and `scheck ssh user@vm --stop-after plan`
both print a real, non-empty check plan; `scheck catalog` and `scheck sudoers` both
work; the audit log and invariants test are the two things a reviewer checks to believe
the security boundary holds. This is acceptance criteria 2 and 3's foundation (the
before/after filesystem diff in criterion 3 can be run for the first time here, since
nothing yet writes to the target by construction).

---

## M1 — baseline (still no model)

Goal: `scheck` is useful today, offline, before phase 2 exists at all.

### M1.1 — macOS baseline checks ✅
Port every macOS row of the baseline table (§3) through the M0 machinery.
**Demo:** `scheck local --stop-after facts` on a Mac.
**Done when:** platform detection picks the right check set automatically; fixture
tests exist for macOS parsing (no live Mac required in CI).
**Spec:** §3 baseline table (macOS rows).
**Landed:** `internal/check/macos`, 33 checks visible at the baseline profile;
`testdata/fixtures/macos` recorded from a developer Mac and scrubbed.
`host.platform_uuid` uses `Extract` to keep one line of `ioreg` output.

### M1.2 — remaining Linux baseline checks ✅
Fill in the rest of the Linux baseline table (accounts, sudoers, persistence units,
SUID scan, logging, time sync) — M0.6 only did a starter subset.
**Demo:** `scheck local --stop-after facts` on Ubuntu and on Fedora, diffing the
fact sheet shape between distros (apt vs. dnf pending-updates parsing).
**Done when:** fixture targets exist for both distros; a probe failure on one
(`ufw` absent on a `firewalld` box) shows up as `unavailable: <reason>`, never fatal.
**Spec:** §3 baseline table (Linux rows), acceptance criterion 1 (Ubuntu + Fedora).
**Landed:** `internal/check/linux`, 38 checks at the baseline profile;
`testdata/fixtures/{ubuntu,fedora}` recorded from `test/containers` via
`make fixtures`. `ExitOK`/`AnyExit` cover `dnf check-update` (100), `find` (1),
`systemctl is-*`.

### M1.3 — parsers (kv / lines / json / raw) ✅
Deliver the four parser kinds as a tested, reusable component rather than ad hoc
per-check string munging — this should have been factored out already by M1.2, so this
slice is really "extract and harden" plus edge-case tests (empty output, truncated
output, malformed json from a check that unexpectedly changed format upstream).
**Demo:** unit tests only; no user-visible demo beyond M1.1/M1.2 already using it.
**Done when:** a malformed-input fixture for each parser kind degrades to
`unavailable: parse error`, never a panic.
**Spec:** §3 (`Parser` field).
**Landed:** `internal/check/parse.go`. `kv` splits on the first of `=`, `:`, space or
tab (needed for `sshd -T`), skips comments and redaction/truncation marker lines.

### M1.4 — report envelope + text/JSON renderers ✅
Deliver the `schema_version`-tagged envelope (§7.4): `host`, `run`, `facts`, empty
`findings` (phase 2 doesn't exist yet, so this is always `[]`). Text and JSON renderers.
**Demo:** `scheck local --stop-after facts --format json | jq .host` and
`scheck local --stop-after facts --format text`.
**Done when:** `host.id` is stable across two consecutive runs on the same machine;
JSON validates against a schema doc committed alongside the renderer.
**Spec:** §7.4, acceptance criterion 4.
**Landed:** `internal/report` and `docs/report-schema.json`, validated in tests with
`santhosh-tekuri/jsonschema`. `run.mode` is `facts` in this milestone.

### M1.5 — run persistence ✅
Deliver the state directory writer: every run lands at
`<state-dir>/runs/<host.id>/<started>.json`, honoring `--state-dir` / `--no-persist`,
redacted the same as the report.
**Demo:** run `scheck local --stop-after facts` twice, `ls` the state dir, and diff the
two persisted files by hand to confirm the shape that `scheck diff` will need later.
**Done when:** persistence never blocks the run (a full disk degrades to a logged
warning, not a failure).
**Spec:** §7.4.
**Landed:** `internal/state` (atomic temp+rename, mode 0600, `run.persisted` flag) and
the end-to-end redaction test over report, audit log and persisted run.

**M1 exit demo:** `scheck local --stop-after facts` and `scheck ssh user@vm --stop-after facts`
produce a complete, correctly-shaped report with zero API key configured, satisfying
acceptance criterion 4 outright. This is a shippable tool on its own — worth flagging to
whoever's tracking scope, since it's a natural place to pause and get real usage
feedback before M2 adds cost and variance.

**M1 exit evidence (2026-09-20):** `test/integ/facts_test.go` runs `scheck ssh
--stop-after facts` against the Ubuntu and Fedora containers, validates the report
against the schema, checks every audited argv is a catalog binding, and asserts an
empty `docker diff` afterwards. `make check` (vet, fix, lint, race tests) is green.

---

## M1, continued — readable before agentic

Added 2026-09-20 after running the M1 build on a real Mac: the fact sheet was correct
and unreadable. Every check showed `+`, including "Firewall is disabled"; summaries were
the first raw line ("134 lines: _accessoryupdater 278"); six checks said "requires
elevated read" with no remedy; the footer said "findings: none". Three slices fix that
before the model exists, using the M1 pause point. The decisions behind them (posture
rules in phase 1, exit `1` in facts mode, typed parsers, `-vv` for output) are in
SPEC §13.

### M1.6 — readable fact sheet
Deliver the §7.6 text contract minus anything that needs new parsers: two-line header,
status words, skipped-by-reason groups with the remedy line, human domain labels, `-v`
descriptions, `-vv` redacted output, colour on a tty with `NO_COLOR`, honest footer, no
trailing padding. Plus `scheck explain <check-id>` (description, platform, domain, argv
with placeholders, params, elevation, parser). No security surface changes.
**Demo:** `scheck local --stop-after facts` on this Mac reads top to bottom without the
JSON; `scheck local --stop-after facts -vv | grep -c REDACTED` shows `-vv` went through
the redactor; `scheck explain sshd.config`.
**Done when:** golden text reports for the ubuntu, fedora and macos fixtures at default,
`-v` and `-vv` are committed and diffed in `go test`; the end-to-end redaction test
also covers `-vv` output.
**Spec:** §7.6, §8.

### M1.7 — typed parsers + summaries
Deliver the typed shapes in §3 (`listeners`, `accounts`, `passwd_status`, `units`,
`updates`, `launchd`), the `Unit` field on every `lines` check (catalog test enforces),
the `summary` string per fact in the envelope, and `schema_version` 1.1 with
`docs/report-schema.json` updated.
**Demo:** `scheck local --stop-after facts` shows "26 listening sockets", "0 SUID
files", "3 updates available"; `--format json | jq '.facts["net.listeners"].parsed[0]'`
shows a record with named fields.
**Done when:** every baseline check on all three fixtures has a summary that is not
"N lines"; parser edge tests (empty, truncated mid-record, header-only, CRLF, unknown
states and redacted fields) pass; incomplete counts are labelled partial and parser
results retain enough completeness information for §7.5's evidence requirements;
the fixtures re-recorded with `make fixtures` show no diff in recorded bytes, only in
golden output.
**Spec:** §3 typed parsers, §7.4 schema 1.1.

### M1.8 — posture rules + finding id catalog
Deliver `internal/finding`: `Def` with title, base severity, impact and remediation
text (§7.1) for the seed ids in §7.5; `Rule` and its predicate kinds; the evaluator
over a fact sheet; findings in the envelope with `source: rule`; findings-first text
rendering; exit `1` under `--stop-after facts` when an open finding meets the profile
threshold (`medium` for baseline, `low` for hardened). Include the `assessments`
array and coverage rendering from §7.5; update the schema with the implementation.
Base severity only: context adjustments, confidence caps and accepted risks stay in M2.2.
**Demo:** `scheck local --stop-after facts` on a Mac with the application firewall off
shows one medium finding with the `fw.global` excerpt and the remediation, and exits
`1`; a Linux fixture with `PasswordAuthentication yes` does the same.
**Done when:** every rule has firing, non-firing and insufficient-evidence fixtures;
unknown, malformed, unavailable, denied, redacted and truncated evidence follow §7.5;
applicability and disabled checks have coverage tests; JSON and text agree on assessment
outcomes and finding counts; both profile thresholds and exit precedence are tested.
The invariants test extends to rules (every `Rule.Check` is a catalog id, every `Rule.Finding` a Def, predicate kind matches the
check's parser); acceptance criterion 4 passes as reworded in §12.
**Spec:** §7.1, §7.5, §8 exit codes, §12 criterion 4.

**M1 readability exit demo:** the M1 exit demo commands, read by someone who has not
seen the JSON, plus a CI job that fails (exit `1`) on a FileVault-off fixture.

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

### M2.2 — severity adjustments + accepted risks
`finding.Def` and the base severity table exist since M1.8. Deliver the rest of the
deterministic grader on top of them: base severity → structured-context adjustments →
confidence cap → accepted-risk status → final severity and exit code. No model involved
yet — feed it synthetic `(id, evidence, confidence)` tuples in tests, and assert that
rule findings from M1.8 pass through the same chain.
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
Rule findings (§7.5) are in the prompt; a `report_finding` on an existing rule id
merges under §7.5: curated rule text and source remain, validated context notes and
evidence append, and the shared grader owns severity. Test attempted replacements,
suppression and duplicate evidence.
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

### M2.6 — phase-2-earns-its-cost evaluation
Deliver a labeled fixture suite covering clean hosts, seeded issues and incomplete
or misleading evidence, including cases requiring follow-up catalog checks. Compare
posture rules alone, single-pass analysis and the agent with identical initial facts,
rule findings and context. Set success criteria before evaluating; record model and
prompt versions and repeat model runs. Mock transcripts validate plumbing only.
**Demo:** a comparison report of correct additional findings, false positives, missed
issues, justified abstentions, uncertainty resolved by follow-up checks, latency,
tokens and cost. Do not require single-pass analysis to miss a particular example.
**Done when:** acceptance criterion 10 is demonstrated and recorded: investigation
produces repeatable useful gains within budget. If it does not justify its cost,
retain posture rules and single-pass analysis and remove the loop from the design.
**Spec:** §2.1 rationale, §12 acceptance criterion 10.

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
model, e.g. a 4K-context one) and the M2.6 fixtures; confirm supported findings still
surface via the correlation pass despite chunking.
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
SUID files, and findings that appeared, disappeared, or changed severity. The typed
records from M1.7 make this a set difference per record kind, not a line diff.
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

## Optional research — bounded assessment (not on the v1 critical path)

This track implements SPEC §5.9 only as an experiment. Jev access is waitlisted.
M0–M4 continue independently; no release gate, default test or ordinary audit depends
on this track. Do not add an empty production abstraction in anticipation of access.

### R1 — labeled fixtures and offline assessment harness
Start after M1 facts are available; this does not gate M2. Build a small fixture corpus
for service/context relationships (`expected`, `unexpected`, `insufficient_context`),
with human labels and evidence references. Include absent context, unavailable checks,
truncation, contradictions and instruction-shaped content. Separate development cases
from held-out evaluation cases. Use authored synthetic responses to exercise the harness;
neither an API key nor a vendor capture is needed to create them.
**Demo:** an offline test runs fixture facts plus context through scripted assessments
and writes a separate evaluation artifact without changing the normal report.
**Done when:** evidence references and result shapes are validated; missing/invalid
answers and uncertainty leave normal findings, severity and exit codes unchanged.
Synthetic responses are clearly labeled; passing tests makes no model-quality claim.
**Spec:** §5.9.

### R2 — optional comparison with an available model
Once an existing generative/local adapter is usable, evaluate the same labeled cases
through it and compare with deterministic rules. Use this to improve task definitions
and the measurement harness, without claiming it simulates Jev's calibration or accuracy.
If no model is available, R1 still completes and mainline development continues.
**Demo:** an opt-in evaluation records model/question versions, per-case predictions,
precision/recall, false negatives, abstentions, latency and cost where available.
**Done when:** quality measurements are distinguishable from scripted plumbing tests;
no comparison run is required in default CI. Freeze evaluation criteria before R3.
**Spec:** §5.9.

### R3 — Jev adapter and live evaluation, deferred until access
Only when credentials are available, add a small Go HTTP adapter inside the experiment.
Use a local fake server for request/response validation, authentication failures,
rate limits, overload, timeouts and malformed responses. Enforce egress policy before
requests, bounded retries, and environment-only credentials. Pin model/question versions.
**Demo:** an explicitly enabled live run compares actual Jev against R2 and deterministic
baselines on the held-out cases, including hostile and incomplete evidence.
**Done when:** actual measurements establish whether accuracy, investigation effort and
cost/latency justify adoption. No arbitrary confidence threshold is treated as calibrated.
Access unavailable means this slice stays deferred; it does not block v1.
**Spec:** §5.9.

### R4 — decide whether to integrate
Write an evidence-backed decision: keep the experiment, remove it, or propose a bounded
production role with explicit fallback and coverage semantics. Any production integration
requires updating the spec, reporting contract and tests first. Do not silently promote
an experimental assessment into a finding filter or an investigation gate.
**Done when:** the decision cites actual evaluation results; no integration is required
for a successful experiment or for shipping v1.
**Spec:** §5.9.

---

## Sequencing notes

- **Jev is optional throughout.** R1 can proceed offline after M1; R2 uses an available
  model if desired; R3 waits for access. None is a dependency of M0–M4. Mock responses
  demonstrate software behavior, never semantic accuracy or prompt-injection robustness.

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
