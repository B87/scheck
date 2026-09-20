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

**Status (2026-09-20):** M0 and the original M1 slices are committed on `main`.
M1.6 and its diagnostics/agent-CLI follow-up are implemented and validated in the
working tree, not yet committed or released. Checkmarks indicate completed
implementation; each slice records validation separately.
Using the M1 build on a real Mac produced M1.6–M1.8 (readable phase 1, posture rules).
M1.7 (typed parsers and summaries) is next, then M1.8 and M2.1.
Before the first GitHub release, breaking changes are
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
before the model exists, using the M1 pause point. M1.6 fixed the marks, the remedies
and the footer; the raw-line summaries are M1.7's job and are still there. The decisions behind them (posture
rules in phase 1, exit `1` in facts mode, typed parsers, `-vv` for output) are in
SPEC §13.

### M1.6 — readable fact sheet ✅
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

**Landed (2026-09-20).** The renderer moved out of `internal/report/render.go` into
`text.go`, `text_layout.go`, `reasons.go` and `domains.go`; `render.go` keeps the JSON
writer and the interim shape-level summary that M1.7 replaces.

- **Two-line header** — `scheck <version> — <host> — <os> — <transport>, elevation <e>`
  then `N checks: R ran, S skipped, D denied by policy`. `host.id`, kernel, profile,
  mode, status, timings, remote shell, canary and the persisted path moved to `-v`.
  The bare platform is printed only when the OS string does not already name it.
- **Status words, not marks** — `ran` / `skipped` / `denied`, describing execution.
  The `+`/`-`/`!` marks are gone, and so is `findings: none`.
- **Flat table** (§7.6, revised during the slice after review of three layouts): header
  row `DOMAIN STATUS CHECK READING`, domain repeated per row so the report greps and
  pipes, READING wrapping into aligned continuation rows.
- **Skipped grouped by reason with a remedy**, denials in their own section naming the
  rule. `internal/report/reasons.go` classifies the runner's reason strings; a shell's
  `exit 127 … command not found` is recognised as a missing binary, which is what it
  means over SSH, so it groups with `not found:` rather than with real errors.
- **Human domain labels** from an ordered table in `internal/report/domains.go`; check
  ids stay verbatim, and an id the catalog does not know renders under "Other".
- **`-v` descriptions, `-vv` redacted output** behind a `  | ` gutter. `Fact.Output`
  carries the runner's already-redacted capture in process and is `json:"-"`.
  Default JSON and persisted runs omit the capture; the follow-up below adds optional
  JSON evidence and structured diagnostics without changing the audit command surface.
- **Colour/width are the CLI's decision** (`cmd/scheck/terminal.go`, `golang.org/x/term`):
  a tty and no `NO_COLOR`, else plain; terminal width, else 100. `internal/report`
  reads no descriptor and no environment. Until severities exist, only structure is
  styled (bold, dim) — severity colours stay the only colours.
- **Honest footer** — "assessment: none … posture rules and the agentic pass are not
  available in this build."
- **Two things the slice added beyond the contract**, both in §7.6 now: control
  characters in target-derived strings are escaped as `\xNN` before printing, so a
  check's stdout cannot drive the operator's terminal; and wrapping never splits a
  `[REDACTED:…]`/`[TRUNCATED:…]` marker.
- **`scheck explain CHECK-ID`** (`cmd/scheck/explain.go`): purpose, literal argv with
  its `{placeholders}`, platform, domain with its label, phase, elevation (naming the
  `sudo -n --` prefix and what happens without it), parser, exit codes, path use,
  extract, budget, canary and typed parameters — one section per platform-specific
  definition, announced up front. Unknown id exits 3 pointing at `scheck catalog`.

**Validation.** `make check` (vet, `go fix`, golangci-lint, `go test -race ./...`) green
with no `go fix` rewrites and 0 lint issues. Nine golden reports under
`internal/report/testdata/golden/` (ubuntu, fedora, macos × default/`-v`/`-vv`),
regenerated with `go test ./internal/report -update`. Every golden is re-rendered at
widths 60/80/100/200 asserting no overrun and no trailing padding. Focused tests cover
status words, the footer's refusal to claim a verdict, reason grouping and remedies,
verbosity levels, colour opt-in with escape-stripped equivalence, control-character
escaping, marker-safe wrapping, hanging-prefix width, domain labels, unknown checks and
warnings; `cmd/scheck` covers explain (whole entry, typed params, platform-specific
ids, elevation, unknown id, width over every catalog entry) and the tty/`NO_COLOR`/
`--out` decisions. `internal/state`'s end-to-end redaction test now renders `-vv` too:
the seeded key is absent from text, `-vv` text, JSON, audit log and persisted run, and
the marker is present in each. Verified by hand on a real Mac (`scheck local
--stop-after facts`, `-vv`, `scheck explain sshd.config`, `scheck explain fs.stat`).
Not run: `make integ` (needs Docker/Podman, not available in this session) — the text
renderer is not on the integration path, but the container demo of
`-vv | grep -c REDACTED` was verified against the recorded ubuntu fixture instead
(7 markers in `ubuntu-vv.txt`).

**Implementation validation: pass.** The demos work, golden files exist in the
working tree and are compared in `go test`, and redaction tests cover `-vv`.
The slice and golden files still need to be committed; no release has been made.

### M1.6 review follow-up — diagnostics and agent CLI ✅

- Escape target-controlled header fields and fold embedded newlines; cover Unicode
  control/formatting characters as well as terminal escape sequences.
- Preserve redacted diagnostics for attempted failures at `-vv`; preserve extraction
  minimization and explain why extraction failures cannot display full stdout.
- Assign structured diagnostic codes in the runner and distinguish per-check timeouts
  from run deadlines/cancellation. Expose `attempted` separately from result status.
- Add JSON for catalog, explain and plans with argv arrays and typed parameters;
  honor output files and reject unsupported formats. Add explicit `assessment: none`
  and opt-in JSON evidence that is not persisted.
- Document supported agent invocations, exit-code handling and missing-coverage
  remedies in the repository-local `scheck` skill
  (`.agents/skills/scheck/SKILL.md`) and CLI help. The skill replaces the standalone
  agent usage document and includes guidance for selecting targets and interpreting
  existing reports. No new check or execution path.

**Validation (2026-09-20):** `make check` passed (vet, fix, lint: 0 issues, race
suite), using writable Go/lint caches under `/tmp` after the default cache was denied.
Regression tests cover header injection, failed-check redaction and non-persistence,
extraction withholding, timeout scope, JSON discovery and output routing. Updated and
reviewed all nine golden reports. CLI smoke tests confirmed catalog, explain and local
plans emit valid JSON; unsupported SARIF exits 3 without stdout. The updated report
schema validates fixture reports with optional evidence. Docker integration was not
run: the Docker API socket was inaccessible in this sandbox.

M1.7 and M1.8 remain separate slices; typed posture facts and findings are not
implemented here.

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
Base severity only: context adjustments, confidence caps and accepted risks stay in M2.3.
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

Two slices here have no model dependency at all. Operator context is consumed by
`finding` deterministically (§6.3), so M2.2 and M2.3 improve `--stop-after facts` on
their own and can be built in parallel with M2.1 by a second person; M2.4 is the first
slice that needs both halves. M2.2 before M2.3 is deliberate: the grader's structured
input is a real merged context type, not a synthetic one invented ahead of its producer.

**Standing rules for every slice in this milestone.** They are the spec's, repeated here
because this is where a phase-2 implementation is most likely to breach one:

- Every execution goes through `runner.Run`. `run_check` and `read_file` are callers of
  the one enforcement point, never a second path (§4, AGENTS.md non-negotiable 3).
- The loop branches on nothing but the chunking budget (§5.1). A provider name, a
  `Native` flag or a capability boolean must never appear in an `if` inside `agent`;
  adapters absorb the difference (§5.3).
- Severity comes from code, never from the model (§7.2). `report_finding` has no
  `severity` field and a supplied one is ignored, not rejected.
- Any slice that changes the envelope bumps `schema_version`'s MINOR, updates
  `docs/report-schema.json` and regenerates the golden reports in the same commit
  (§7.4).

### M2.1 — `llm` interface, `mock` provider, `scheck providers`
Deliver the interface exactly as specified in §5.1 (`Stream`, package-level `Complete`,
`Limits`, `Native`), the `mock` provider that replays a recorded transcript file, and
`scheck providers` (§8), which lists what is configured with each one's `Limits` and
`Native` set. `scheck providers` is the slice's only user-visible surface and the smoke
test that an adapter registers correctly.
Also commit `docs/eval/phase2-criteria.md`: the success criteria M2.7 is judged against,
written now, while nothing is built and no result is known. M2.7 cites that file;
changing it later is a commit with a reason in the message, not a quiet edit.
**Demo:** `scheck providers` lists `mock` and `openai-compatible` (the latter
unconfigured, no key) with their limits; a transcript fixture drives `mock` through a
3-turn tool-calling exchange, asserted turn-by-turn in a test.
**Done when:** `agent`, `policy`, `check`, `finding`, `report` all compile with zero
provider SDK import — enforced by a `go list` dependency check in CI, not by a code
review comment. The §11 provider conformance table exists and is green for `mock`, so
every later adapter is written against a suite that already runs.
**Spec:** §5.1, §5.2 selection, §8.

### M2.2 — operator context: ingestion and merge (no model)
Deliver `--context` for all four source forms (§6.1) plus the two implicit sources
(`scheck.yaml`'s `context:` block and `./.scheck/context/**`), the per-kind merge
semantics, the §6.2 structured schema with validation, `Budgets.ContextBytes` truncation
recorded in `run.context_sources`, and `--stop-after context`.
Merge is defined per kind, not per source order: structured blocks merge as maps with
per-key override and lists concatenated and deduplicated by natural key; prose is never
merged and is carried verbatim under a heading naming its source. `target:PATH` is read
through `runner.Run` and the path policy like any other file — no new read path.
An `accepted_risks[].id` that is neither a catalog finding id nor `custom:`-prefixed is a
usage error at config load, exit 3 (§6.2), so a typo cannot silently leave a risk
un-accepted. Nothing in this slice reaches a model.
**Demo:** `scheck local --context note:"public jump host" --context ./docs/arch.md
--stop-after context` prints the merged block with per-source headings and the byte
budget; `--format json` shows `run.context_sources` with a sha256 per source.
**Done when:** merge order is tested per kind rather than per source; a `target:` source
appears in the audit log as an ordinary catalog binding; an over-budget context is
truncated with a warning and `truncated: true` in the report; an unknown accepted-risk id
exits 3 at load. Prose is inert in this slice by construction — the injection corpus
belongs to M2.5, where a model first sees it.
**Spec:** §6.1, §6.2, §4.4 `ContextBytes`, §7.4 `context_sources`.

### M2.3 — severity adjustments + accepted risks
`finding.Def` and the base severity table exist since M1.8; M2.2 now supplies real
structured context. Deliver the rest of the deterministic grader: base severity →
structured-context adjustments (§6.3) → confidence cap → accepted-risk status → final
severity → exit code. Still no model: the inputs are M1.8 rule findings and M2.2 context,
plus synthetic `(id, evidence, confidence)` tuples for the cases no rule can produce yet.
The debug affordance is a user-facing feature, not a second binary: extend `scheck
explain` to accept a finding id and print the adjustment chain, alongside the check ids
it already takes (§8).
**Demo:** `scheck explain sshd.password_auth_enabled --exposure internet` prints base →
adjustment → cap → status → final; `scheck local --stop-after facts --context ./ctx.yaml`
shows one finding escalated by `exposure: internet` and another at `status: accepted`,
excluded from the exit code.
**Done when:** the §11 severity test table passes; `--ignore-context` reproduces base
severity byte-for-byte in a test, not by inspection; an expired `accepted_risks` entry
produces `risk.acceptance_expired` and does **not** suppress its own finding;
`expected_services` matching, escalation and `svc.expected_missing` each have firing and
non-firing cases; a rule finding from M1.8 and an identical synthetic model finding grade
to the same severity through the same chain.
**Spec:** §6.3, §7.1, §7.2, §11 severity tests, acceptance criterion 9 (deterministic half).

### M2.4 — three tools + agent loop, mock only
Deliver `run_check`, `read_file`, `report_finding` as the closed tool surface (§5.7), the
provider-neutral system prompt (§5.8), and the loop (§5.6) wired to `mock` only. No real
provider — this slice proves control flow (iteration budget, chunking trigger,
stop-on-no-tool-calls) against scripted transcripts.
`run.mode` becomes `agent`, or `single-pass` when the iteration budget is 1. Single-pass
is the same loop with `MaxIterations: 1`, not a second code path; that is what makes
M2.7's comparison a one-variable experiment rather than two implementations.
**Merging is owned by `finding.Store`, not by the loop** (§7.2, §7.5). A `report_finding`
on an existing rule id keeps `source: rule`, the curated title, impact, remediation and
rule confidence, appends validated evidence and attributed model notes without
duplicates, and leaves severity to the grader. `agent` hands the store a candidate and
never edits a finding — if merge logic appears in the loop, the loop has stopped being
one path.
This is also the slice that populates `run.provider/model/effort/native/limits/usage` and
non-rule findings in the envelope, so it carries the schema bump and the golden
regeneration.
**Demo:** `scheck local --provider mock --transcript
testdata/transcripts/correlated-finding.json` produces a full report with a model finding
in it, end to end through both renderers.
**Done when:**
- every `policy.Budgets` field the loop owns is exhausted by a crafted transcript and
  each one ends the run `status: incomplete` with exit `2`, never a clean bill of health
  — `MaxIterations`, `AgentChecks`, `AgentWallClock`, `ModelInputTotal`, `MaxTokens`,
  `RunTimeout`;
- `read_file` and `text.cat {path}` produce byte-identical audit records apart from the
  tool name — the test that stops model-facing sugar from becoming a second enforcement
  path;
- a transcript that calls an unknown id, an invalid param kind, a denied path and an
  elevated check under `--elevate none` receives an error result it can correct from, and
  the audit log carries a line for each, including the denials;
- a `report_finding` carrying a `severity` field has it ignored, and `custom:<slug>`
  findings are capped at `medium` and flagged (§7.1);
- the rule-merge cases are covered: attempted text replacement, attempted suppression,
  duplicate evidence.
**Spec:** §5.6, §5.7, §5.8, §7.2, §7.5 merge, §7.4.

### M2.5 — operator context in the prompt + injection corpus
Deliver the `<operator_context>` prompt block (§6.3): the structured map rendered so the
model can reason about *why* a port is expected, prose passed through verbatim under
per-source headings, and the §11 context-injection corpus run against `mock`.
**Demo:** `scheck local --provider mock --transcript ... --context
./testdata/context/hostile/` produces the same findings, the same roles and the same
severities as the identical transcript run without the hostile context.
**Done when:** the corpus passes — no seeded string changes the auditor role, suppresses
findings wholesale, alters any severity, or produces a denied check attempt in the audit
log; and a test asserts severity is unreachable from prose by construction, because the
grader's only context input is the structured map merged in M2.2.
**Spec:** §6.3, §5.8, §11 context-injection corpus.

### M2.6 — `openai-compatible` provider
Deliver the real adapter for a backend with native tool calling (OpenAI, or a
vLLM/Groq/Together endpoint), selected with `--base-url` + `--model`: native tool
calling, the `Effort` mapping, and cache breakpoints honoured where the endpoint
supports them. This is the default provider and the reference implementation the
conformance suite is written against, and the first slice that costs real money.
**Demo:** `scheck local --provider openai-compatible --model ...` against a real
(throwaway VM) target, producing a real report.
**Done when:** the provider conformance suite (§11) is green for `openai-compatible`
running the same table `mock` has passed since M2.1; a live run's cost is measured and
checked against the $0.50 budget (acceptance criterion 7);
`Block.Cacheable` and `Effort` are each either exercised by the adapter or recorded as
unexercised in `Native`, so M3.1 does not discover that the interface cannot express a
feature no adapter has used yet.
**Spec:** §5.2, §5.5.

### M2.7 — phase-2-earns-its-cost evaluation
Deliver a labeled fixture suite covering clean hosts, seeded issues, and incomplete or
misleading evidence, including cases that can only be resolved by a follow-up catalog
check. Compare three arms over it with identical initial facts, rule findings and
context: **posture rules alone** (`--stop-after facts`), **single-pass**
(`MaxIterations: 1`), and **the agent**. The only variable is the iteration budget —
same prompt, same tools, same evidence — so a difference is attributable to
investigation and nothing else. Repeat model runs and record model and prompt versions.
Mock transcripts validate plumbing only and make no quality claim.
**Demo:** a comparison report of correct additional findings, false positives, missed
issues, justified abstentions, uncertainty resolved by a follow-up check, latency, tokens
and cost. Do not require single-pass analysis to miss any particular example.
**Done when:** acceptance criterion 10 is demonstrated and recorded against the criteria
frozen in `docs/eval/phase2-criteria.md` at M2.1 — investigation produces repeatable
useful gains within budget. If it does not, the loop is removed and posture rules plus
single-pass analysis are retained; that removal is a deletion, not a redesign, because
severity, the envelope and the tool surface never belonged to the loop.
**Spec:** §2.1 rationale, §12 acceptance criterion 10.

**M2 exit demo:** `scheck local` and `scheck ssh` produce full agentic reports against
the `openai-compatible` provider on both a clean host and the seeded fixture, with
attributed severity adjustments visible in the JSON output. Acceptance criteria 5, 6, 7,
9 (model half), and 10 are all checkable at this point.

---

## M3 — more providers

Goal: prove the abstraction from both directions — a provider whose native feature set
is *richer* than the reference implementation's (`anthropic`), and one that lacks native
tool calling, parallel calls, and caching all at once, the worst case (`ollama`).

### M3.1 — `anthropic` provider (richer native features)
Deliver the adapter for Claude API / Bedrock / Vertex / Foundry: adaptive thinking,
`output_config.effort`, native prompt caching breakpoints. This isolates "a provider the
interface must already be able to express" from "a provider whose capabilities must be
emulated," which M3.2 adds next.
**Demo:** `scheck local --provider anthropic` against the same fixture host as M2.7.
**Done when:** conformance suite green; the same fixture's findings are structurally
identical (schema, not content) to the `openai-compatible` run; `Block.Cacheable` maps to
a real cache breakpoint and `Effort` to `output_config.effort` with **no change to the
`llm` interface** — if either needs a new field, §5.1 was under-designed and that is the
finding this slice exists to produce.
**Spec:** §5.2.

### M3.2 — tool-call emulation + `ollama`
Deliver the emulation layer (§5.3): render tools into the system prompt, parse a text
protocol into `ToolCalls`, serialize parallel calls one at a time. Wire it under
`ollama`, `Local: true`.
**Demo:** `scheck local --provider ollama --model llama3.1 --local-only` against the
fixture host, showing `native.tool_calling: false` in the report header and a
`confidence` cap of `medium` on any finding from an emulated call.
**Done when:** conformance suite green for `ollama` running the *same* table as
`openai-compatible` — no conditional skips. This is the actual proof the abstraction is
real, not M3.1.
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
model, e.g. a 4K-context one) and the M2.7 fixtures; confirm supported findings still
surface via the correlation pass despite chunking.
**Done when:** a chunked run and an unchunked run over the same fact sheet on a
large-context model agree on the correlated finding — chunking shouldn't lose the
signal M2.7 exists to prove.
**Spec:** §5.3 (context size), ties back to acceptance criterion 10.

**M3 exit demo:** the exact same fixture host audited by `openai-compatible`, `anthropic`
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
- **M2.7 (phase-2-earns-its-cost) is the highest-risk slice in the roadmap.** It's
  placed as late as reasonably possible within M2 — after the loop, tools, and context
  ingestion all work — and its success criteria are frozen in M2.1, before any of them
  exists, so the slice cannot move its own goalposts — so that a negative result is cheap to act on: the loop and tools
  built so far are needed either way (M1's `--stop-after facts` mode and the tool
  surface used for confirmation checks), but a negative result means `agent.Session`'s
  multi-turn correlation is what gets cut, not the checks or the reporting.
- **`openai-compatible` is built before `anthropic`** (M2.6, then M3.1) because the
  widest-reach adapter should be the one the conformance suite is written against. The
  cost of that order is that the reference implementation is the *narrower* feature set,
  so `Block.Cacheable` and `Effort` — fields that exist in §5.1 because of `anthropic` —
  risk going unexercised until M3.1. The `llm` interface stays designed from the richest
  provider, and M2.6's done-when records which fields no adapter has exercised yet.
- **M3.1 before M3.2 is deliberate**, not filler: it separates "does a second provider
  slot into the interface at all" from "does the emulation layer work," so a conformance
  failure in M3.2 is unambiguously about emulation.
- **Nothing in M4 blocks anything else in M4** — those five slices can run in parallel
  across contributors once M3 is done.
