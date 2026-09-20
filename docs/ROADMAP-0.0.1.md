# scheck — roadmap to 0.0.1

This decomposes the first release's milestones from `SPEC.md` (§10) into slices small enough to ship and
demo individually. Each slice is vertical — it produces something runnable, not a layer
that only compiles. Slices are numbered in dependency order within their milestone;
the 0.0.1 sequence is M0 → M1 → M2 → M4.5–M4.7. Historical milestone IDs are preserved.
References to “v1” in the spec mean this first release, now named 0.0.1.

Every slice lists: what it delivers, a **demo** (a command that proves it works), what
must be true before it's done, and which spec section it implements. "Done" always
includes tests, not just code — the testing strategy in `SPEC.md` §11 is distributed
across slices below rather than saved for the end.

**Status (2026-09-20):** M0 and the original M1 slices are committed on `main`.
M1.6 with its diagnostics/agent-CLI follow-up, M1.7 and M1.8 are implemented and
validated in the working tree, not yet committed or released. Checkmarks indicate
completed implementation; each slice records validation separately.
Using the M1 build on a real Mac produced M1.6–M1.8 (readable phase 1, posture rules).
M2.1 is next.

**0.0.1 scope revision (2026-09-20):** M2 includes full-request context limits,
real-model quality/adversarial release gates and configuration usability (M2.2a).
Existing profile behavior, regression coverage, acceptance validation and the GitHub
release process complete the 0.0.1 scope.

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
two persisted files by hand to confirm stable host identity and inspectable run artifacts.
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
and the footer; M1.7 replaced the raw-line summaries with typed readings; M1.8 added the
posture rules, so the report now leads with what is wrong. The decisions behind them
(posture rules in phase 1, exit `1` in facts mode, typed parsers, `-vv` for output) are
in SPEC's change list.

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

M1.7 and M1.8 remained separate slices and landed after this one.

### M1.7 — typed parsers + summaries ✅
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

**Landed (2026-09-20).** `internal/check/typed.go` holds the shapes, `summary.go` the
one-line readings, and `check.Parse` now takes the whole `Check` rather than a
`ParserKind`.

- **Seven shapes**, one more than the plan: `listeners`, `accounts`, `passwd_status`,
  `units`, `updates`, `launchd` and `file_mode`. The last is new and exists because the
  §7.5 shadow-permissions rule is specified over a *parsed* mode; a regexp over a raw
  `stat` line cannot express "recognized and outside a set" without lookahead. Recorded
  in SPEC §3 and its change list.
- **A typed parser reads the check, not just its kind.** `ss` and `lsof` both answer
  `listeners`; `apt`, `dnf`, `zypper` and `softwareupdate` all answer `updates`. The
  format is selected from the catalog's own `Argv[0]`, never by sniffing the target's
  output, so target bytes cannot steer the parser.
- **`Records{kind, items, partial, note}`** rather than a bare slice: completeness
  travels with the records, because §7.5 lets a rule prove presence from partial output
  but never absence, and because an incomplete count must say so ("24 listening sockets
  (partial: output was truncated or redacted)").
- **`Unit` is required on `kv` checks too**, and rejected on typed shapes. "13 settings"
  is a reading; "13 keys" is a shape. New invariant `missing-unit`.
- **`parseKV` was rewritten**: `KEY=value`, then `Some Key: value` (the only form whose
  key may contain spaces), then `key value`. The old "split on the first of `=:` or
  whitespace" turned `sestatus`'s "SELinux status: enabled" into key `selinux` — which
  the §7.5 SELinux rule reads as `selinux status`, so the rule table could not have been
  written against the old parser. `sshd -T`'s "listenaddress [::]:22" still splits on
  the space.
- **`summary` per fact** in the envelope, in the text table and (from phase 2) in the
  prompt: one string, produced in `internal/check` beside the parsers.

**Validation.** `make check` green (vet, `go fix` with no rewrites, lint 0 issues, race
suite). Parser edge tests cover empty, truncated mid-record, header-only, CRLF, unknown
states, redacted fields and 1 MiB of garbage per kind; `internal/baseline/fixtures_test.go`
asserts record counts and populated fields on all three recorded fixtures;
`internal/report/summary_test.go` fails any fact whose reading is still shape-level on
any fixture. Nine golden reports regenerated and read as a review item. `make fixtures`
was re-run against the containers: the only diff in recorded bytes is the container's
own hostname in two `uname` captures, which changes on every container run, so it was
reverted to keep the goldens stable. Nothing in this slice changes what is executed,
only how the recorded bytes are parsed.

### M1.8 — posture rules + finding id catalog ✅
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

**Landed (2026-09-20).** `internal/finding`: `finding.go` (severity, the emitted
finding), `catalog.go` (15 `Def`s), `rule.go` (predicates and the rule table),
`evaluate.go` (the evaluator) and `invariants.go`. The package reads a fact sheet and
imports no target, no runner constructor and no argv.

- **A predicate answers three ways**, not two: `matched`, `not_matched`,
  `not_assessed`. That is what implements "evaluate recognized evidence, not failure to
  recognize a good state" (§7.5), so the recognizability lives in the predicate —
  `RawMatch.Requires`, `KeyEquals.Known`, `FieldEquals.Known`, `FieldOutside.Recognize`.
  An unknown FileVault state, a redacted value, a truncated capture, a missing key, a
  denied or unavailable check and a check disabled in config all end as `not_assessed`.
- **Coverage is a first-class array.** Every selected rule emits an `assessments` entry;
  only `matched` emits a finding. The text report closes the findings section with the
  not-assessed rules, grouped by check and reason, carrying that check's own remedy
  ("re-run with --sudo"), and `-v` prints the whole coverage table.
- **The seed table's `pkg.*` row is four rules**, one per concrete catalog id. Two
  package managers on one host produce one `updates.pending` finding with both excerpts.
- **Exit 1** from `reportAndExit` in `cmd/scheck`, after the report is written, with
  exit 2 taking precedence: an incomplete run's silence is not a clean bill of health.
- **Severity colours** arrive (the only colours in the report), and a fact whose rule
  fired carries `[finding: <severity>]` in its reading rather than a pass mark.
- **`scheck explain CHECK-ID`** now lists the posture rules that read the fact, and JSON
  discovery gains `posture_rules` per check, so an agent that sees a check skipped knows
  which conclusions went unassessed.
- **Not implemented, deliberately:** `finding.Def.References`. The field selects
  citations by `context.compliance`, which arrives in M2.2; inventing citations now
  would be worse than omitting the key (SPEC §7.1 and its change list say so).

**Validation.** `make check` green. `internal/finding` has firing, non-firing and
insufficient-evidence fixtures for every rule in the table, and a test that fails when a
new rule ships without all three; separate tests cover partial evidence proving presence
but not absence, applicability, disabled checks, evidence merging, severity ordering and
both profile thresholds. `ValidateRules` is asserted over the real catalog and
per-violation-class. `internal/report` covers findings-first rendering, the -v detail,
coverage grouping with remedies, the footer's refusal to claim a verdict, JSON/text
agreement and escaping of target-derived excerpts; `cmd/scheck` covers the exit-code
matrix and exit-2-over-1 precedence. Verified by hand on a real Mac: `scheck local
--stop-after facts` reports the application firewall as one medium finding with the
`fw.global` excerpt and the remediation, and exits 1. `make integ` is green (Ubuntu and
Fedora containers, schema validation, every audited argv a catalog binding, empty
`docker diff`, `visudo -cf`); no check, argv or execution path changed in either slice.
Acceptance criterion 4 is covered by a test in `cmd/scheck`: offline, with no model, a
FileVault-off macOS sheet and a `PasswordAuthentication yes` Linux sheet each yield
their finding with evidence and remediation and exit 1.

**M1 readability exit demo:** the M1 exit demo commands, read by someone who has not
seen the JSON, plus a CI job that fails (exit `1`) on a FileVault-off fixture.

---

## M2 — agent (model enters the picture)

Goal: phase 2 exists and can be tested entirely offline via the `mock` provider before
a single live API call is spent.

Context ingestion, configuration inspection and grading have no model dependency.
Operator context is consumed by `finding` deterministically (§6.3), so M2.2, M2.2a
and M2.3 improve `--stop-after facts` on
their own and can be built in parallel with M2.1 by a second person; M2.4 is the first
slice that needs both halves. M2.2 before M2.3 is deliberate: the grader's structured
input is a real merged context type, not a synthetic one invented ahead of its producer.

**Standing rules for every slice in this milestone.** They are the spec's, repeated here
because this is where a phase-2 implementation is most likely to breach one:

- Every execution goes through `runner.Run`. `run_check` and `read_file` are callers of
  the one enforcement point, never a second path (§4, AGENTS.md non-negotiable 3).
- Provider-dependent loop behavior is limited to context-size handling (§5.1, §5.3).
  A provider name, a `Native` flag or a capability boolean must never appear in an `if` inside `agent`;
  adapters absorb the difference (§5.3).
- Severity comes from code, never from the model (§7.2). `report_finding` has no
  `severity` field and a supplied one is ignored, not rejected.
- Any slice that changes the envelope bumps `schema_version`'s MINOR, updates
  `docs/report-schema.json` and regenerates the golden reports in the same commit
  (§7.4).

### M2.1 — `llm` interface, `mock` provider, `scheck providers` ✅
Deliver the interface exactly as specified in §5.1 (`Stream`, package-level `Complete`,
`Limits`, `Native`), the `mock` provider that replays a recorded transcript file, and
`scheck providers` (§8), which lists what is configured with each one's `Limits` and
`Native` set. `scheck providers` is the slice's only user-visible surface and the smoke
test that an adapter registers correctly.
Also commit `docs/eval/phase2-criteria.md`: the success criteria M2.7 is judged against,
written now, while nothing is built and no result is known. Include pass criteria for
repeated real-model adversarial evaluations over hostile operator prose and target
output, with benign paired controls; freeze these alongside quality and cost criteria.
M2.7 cites that file;
changing it later is a commit with a reason in the message, not a quiet edit.
**Demo:** `scheck providers` lists `mock` and `openai-compatible` (the latter
unconfigured, no key) with their limits; a transcript fixture drives `mock` through a
3-turn tool-calling exchange, asserted turn-by-turn in a test.
**Done when:** `agent`, `policy`, `check`, `finding`, `report` all compile with zero
provider SDK import — enforced by a `go list` dependency check in CI, not by a code
review comment. The §11 provider conformance table exists and is green for `mock`, so
every later adapter is written against a suite that already runs.
**Spec:** §5.1, §5.2 selection, §8.

**Landed (2026-09-20).** `internal/llm` (`llm.go`: the contract, `Complete`/`Drain`,
classified `Error`; `tokens.go`: `Estimate` and `CheckFit`; `registry.go`:
`Register`/`Build`/`Providers`), `internal/llm/mock` (transcript replay with `fail`
and `expect` turns, records every request), `internal/llm/conformance` (the §11 table
as a `Harness`-driven suite), `internal/llm/all` (links adapters, registers the
deferred names), `cmd/scheck/providers.go`, `scripts/depcheck.sh` wired into `make
check`, and `docs/eval/phase2-criteria.md`.

- `Provider` gained `Native()`; `scheck providers` builds each adapter from the current
  configuration without I/O and prints its status, limits and native set, never a
  credential value. `openai-compatible` is listed as unavailable until M2.6 so the
  default selection fails with the same message as any other missing adapter.
- The conformance suite is green for `mock`; every later adapter is written against a
  suite that already runs.

**Validation.** `make check` green including `depcheck`; `internal/llm` tests cover
the estimate's monotonicity and the fit check's three answers (unknown limit is a
configuration error, overflow, fit) and usage accumulation; the mock's transcript test
drives a three-turn tool-calling exchange with `expect` assertions and exhaustion;
`cmd/scheck` asserts every registered provider is listed and no credential is printed.

### M2.2 — operator context: ingestion and merge (no model) ✅
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

**Landed (2026-09-20).** `internal/operator` (`operator.go`: sources, the §6.2 schema
with validation, per-kind merge with per-key origins, the budget cut; `render.go`: the
`<operator_context>` block and the accounting line), `cmd/scheck/context.go`
(`--stop-after context` in text and JSON), `session.loadContext`, `report.Meta.Context`
and schema 1.2.

- **`target:` is prose only.** The structured block is what accepts risks and sets
  exposure; the host being audited must not be able to do either for itself. Recorded
  in SPEC §6.1 and its change list. The read is `runner.Run("text.cat")`, so the audit
  log shows it as an ordinary catalog binding and the path policy applies (a
  `target:/etc/shadow` is refused with exit 3).
- **Order is written down**: config block, `./.scheck/context/**` in lexical path
  order, then `--context` left to right. A YAML source's non-`context:` keys are
  carried as prose rather than dropped.
- `config.Validate` loads the `context:` block through the same code, so an unknown
  accepted-risk id fails at config load as well as from a `--context` file.

**Validation.** `make check` green. `internal/operator` tests cover per-kind merge with
origins, every schema validation failure, the budget cut across three sources (marker,
flags, warnings), deterministic implicit-directory order, target sources through an
injected reader and unresolved without one, expiry and unknown-key passthrough.
`cmd/scheck` asserts the target read is audited as `text.cat` and policed, that the
facts report carries `context_sources` with hashes and the truncated flag, that
`--stop-after context` prints the block and that `--ignore-context` reads nothing.
Demo verified by hand on this Mac with a note, a markdown file and a yaml file.

### M2.2a — configuration inspection, validation and walkthrough ✅

Deliver `scheck config show` and `scheck config validate`, using the same configuration
resolver and validation rules as ordinary runs. `show` supports text and JSON and
reports effective settings with provenance: built-in default, user-config file,
project `scheck.yaml`, or an explicit CLI flag. For accumulated restrictions and merged
context, retain contributing sources per entry/key rather than claiming one file owns
an entire merged value. Keep the existing slice IDs; this slice follows M2.2.

Align SPEC §9, help and implementation on precedence: built-in defaults → OS user
config → project `scheck.yaml` → explicitly supplied flags. Document the actual Linux
and macOS user-config locations. Defaults from flag registration must not accidentally
override file settings; restriction lists accumulate and context uses M2.2's per-kind
merge rules. Define deterministic ordering for implicit context files and conflict
resolution for duplicate expected-service and accepted-risk entries, then test it.

`config show` and `config validate` inspect local configuration without contacting a
model or target. Validate local context sources and report target-resident context as
unresolved, not successfully validated; resolving it remains the explicit
`--stop-after context` path through the runner. Credentials are never printed. Apply
redaction and terminal escaping to displayed values and diagnostics, including context
and credential-bearing URLs; source attribution must not leak inline secret values.

**Demo:** a user default selects a model, project configuration selects `hardened`, and
`scheck config show --profile baseline --format json` identifies the flag as the profile's
source while retaining the model's file origin. `scheck config validate` identifies an
invalid local context field with its source and exits 3. Then
`scheck local --context ./hosts/gateway.yaml --stop-after context` shows the merged
context that an assessment would consume.

**Done when:**

- tests establish identical effective settings for inspection and ordinary runs,
  including explicit flags, absent files, accumulated restrictions and context conflicts;
- validation exits 0 for valid local configuration and 3 for usage/config errors,
  without target commands or inference requests; unresolved remote context is explicit;
- seeded credentials are absent from text, JSON and diagnostics, and target-derived
  text cannot control the terminal;
- provider settings are inspected without credentials or network probes; M2.6 completes
  adapter-specific validation and tests unavailable features failing explicitly;
- a checked-in walkthrough covers personal defaults, team configuration, per-host
  context files, inline notes, expected services, expiring accepted risks and one-off
  CLI overrides. It distinguishes preferences, context and restrictions, and labels
  unavailable features honestly.

**Spec work:** align §6.1 and §9, add these CLI contracts to §8 and their tests to §11
when implementing this slice. No new configuration-loading or target-execution path.

**Landed (2026-09-20).** `internal/config/resolve.go` (`Layer`, `Overrides`,
`Resolve` with per-scalar origins and per-entry source lists, `Defaults`,
`StripUserInfo`), `cmd/scheck/configcmd.go` (`config show|validate` in text and JSON),
`docs/CONFIGURATION.md`, and SPEC §8/§9/§11. `loadConfig` in the CLI builds
`Overrides` from flags that were *changed*, so a registered default never overrides a
file; `LoadFiles` is now `Resolve` over layers with no overrides, so tests and the run
path share one fold.

- Provenance is per entry for accumulated lists ("`net.listeners <- user.yaml,
  scheck.yaml`") and per key for the merged context; a later file's `context:` block
  replaces an earlier one's whole, and the spec says so.
- `validate` names the source of the error and exits 3; `show` still renders a broken
  configuration with the error attached. `target:` context is listed as unresolved.
  Provider validation checks the name is registered and available and notes a missing
  model; adapter-specific validation is M2.6's.
- Every displayed string passes the redactor and the terminal escaper; credentials are
  presence-only; a base URL's user info is stripped.

**Validation.** `make check` green. `internal/config` tests cover provenance across
user, project and flag layers, absent files, accumulated entries with every source,
unset flags not overriding files, `--local-only` narrowing `allow_egress`, user-info
stripping, and effort/max_context validation. `cmd/scheck` runs the binary in a scratch
home: the demo (user model, project `hardened`, `--profile baseline` attributed to the
flag with the model keeping its file origin), the plan path honouring the same resolved
settings, validate's exit codes for an invalid context field and an invalid profile,
unresolved target context, and a leak test with a seeded key in the environment, a
credential in a URL, a secret in a note and a control character in a target name.

### M2.3 — severity adjustments + accepted risks ✅
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

**Landed (2026-09-20).** `internal/finding/grade.go` (`Grader`, `Step`, the §6.3 table,
`ExpiredAcceptances`), `internal/finding/store.go` (`Store`, `Candidate`, validation,
merge, `svc.expected_missing`), nine new `Def`s in `catalog.go`, `report.Build` grading
through the store, `cmd/scheck/explain_finding.go`, schema 1.3.

- **The store exists now, not in M2.4**, because the grader is its consumer: the merge
  contract (rule text retained, evidence appended without duplicates, notes
  attributed) and the evidence validation (an excerpt must appear in the cited check's
  redacted output) are what make a model finding and a rule finding grade alike.
- **Order in the table**: expected services, exposure, environment; custom findings
  are never escalated and capped at medium; the chain records a step that could not
  move (info cannot go lower) without an adjustment entry.
- **`svc.expected_missing` is a negative claim** and gets its own assessment entry:
  matched, not_matched, or not_assessed when `net.listeners` is unavailable or partial.
- `scheck explain FINDING-ID` takes `--exposure`, `--environment`,
  `--expected-service`, `--service`, `--accepted`, `--expires`, `--emulated-tools`
  over any `--context` sources; JSON is `kind: finding` with the `chain` array.

**Validation.** `make check` green; goldens unchanged (no context in the fixtures).
`internal/finding` has the §11 severity table (seventeen rows: neutral exposures,
escalation per category, de-escalation, clamping at both ends, expected and
undeclared services, acceptance, acceptance plus escalation, expired acceptance),
JSON attribution, nil context equals base for every def, custom caps, the confidence
cap, expired-acceptance findings, and rule-versus-model parity; the store tests cover
expected_missing firing, non-firing, partial and absent listeners, merge (text
replacement and suppression refused, duplicates collapsed, service kept) and every
rejection class. `cmd/scheck` runs the demo (escalated, accepted and excluded from the
exit code, expired not suppressed, declared service missing), asserts
`--ignore-context` findings are byte-identical to a run with no context, and covers
`explain FINDING-ID` in text and JSON with an invalid flag and an unknown id.

### M2.4 — three tools + agent loop, mock only
Deliver `run_check`, `read_file`, `report_finding` as the closed tool surface (§5.7), the
provider-neutral system prompt (§5.8), and the loop (§5.6) wired to `mock` only. No real
provider — this slice proves control flow (iteration budget, full-request context guards,
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
- before every model call, the entire serialized request plus output reservation is
  checked against a known `Limits.MaxContext` (§5.3); tests cover initial overflow,
  history/tool-result growth and tool/schema/framing overhead. Locally detected
  overflow sends no request, preserves facts/findings, explains the incomplete AI
  assessment and exits 2. Unknown limits fail configuration with exit 3. No silent
  evidence removal or chunking; token accounting stays within `llm`;
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
per-source headings, and the §11 injection corpus run against `mock`.
**Demo:** `scheck local --provider mock --transcript ... --context
./testdata/context/hostile/` produces the same findings, the same roles and the same
severities as the identical transcript run without the hostile context.
**Done when:** mock tests establish prompt/data boundaries and deterministic
protections: prose cannot reach severity grading, rule findings cannot be suppressed,
and hostile tool calls cannot bypass policy. Include instruction-shaped target output
as well as operator prose. Scripted transcripts do not prove that a model resists
injection; M2.7 must evaluate this corpus with the real model before 0.0.1.
**Spec:** §6.3, §5.8, §11 injection corpus.

### M2.6 — `openai-compatible` provider
Deliver the real adapter for a backend with native tool calling (OpenAI, or a
vLLM/Groq/Together endpoint), selected with `--base-url` + `--model`: native tool
calling (required in 0.0.1; unsupported endpoints fail explicitly), the `Effort` mapping,
and cache breakpoints honoured where the endpoint supports them. This is the default provider and the reference implementation the
conformance suite is written against, and the first slice that costs real money.
**Demo:** `scheck local --provider openai-compatible --model ...` against a real
(throwaway VM) target, producing a real report.
**Done when:** the provider conformance suite (§11) is green for `openai-compatible`
running the same table `mock` has passed since M2.1; token accounting includes provider
framing and reserved output, and provider context-overflow errors preserve the report
with incomplete status and exit 2. Deferred providers, `--local-only` and
`allow_egress: false` fail explicitly before inference, never silently enable egress.
A live run's cost is measured and
checked against the $0.50 budget (acceptance criterion 7);
`Block.Cacheable` and `Effort` are each either exercised by the adapter or recorded as
unexercised in `Native`; the report must not imply unsupported features were used.
**Spec:** §5.2, §5.5.

### M2.7 — phase-2-earns-its-cost evaluation
Deliver a labeled fixture suite covering clean hosts, seeded issues, and incomplete or
misleading evidence, including cases that can only be resolved by a follow-up catalog
check. Compare three arms over it with identical initial facts, rule findings and
context: **posture rules alone** (`--stop-after facts`), **single-pass**
(`MaxIterations: 1`), and **the agent**. The only variable is the iteration budget —
same prompt, same tools, same evidence — so a difference is attributable to
investigation and nothing else. Repeat model runs and record model and prompt versions.
Mock transcripts validate plumbing only and make no quality claim. Also run repeated
real-model adversarial evaluations on the M2.5 corpus, pairing hostile operator context
and check output with benign controls. Record failures and model/prompt versions;
these live evaluations are opt-in, but recorded passing results are required for 0.0.1.
**Demo:** a comparison report of correct additional findings, false positives, missed
issues, justified abstentions, uncertainty resolved by a follow-up check, latency, tokens
and cost. Do not require single-pass analysis to miss any particular example.
**Done when:** acceptance criteria 10 and 12 are demonstrated and recorded against the criteria
frozen in `docs/eval/phase2-criteria.md` at M2.1 — investigation produces repeatable
useful gains within budget. If it does not, the loop is removed and posture rules plus
single-pass analysis are retained; that removal is a deletion, not a redesign, because
severity, the envelope and the tool surface never belonged to the loop. The retained
single-pass mode must still pass the adversarial gate; removing the loop does not waive it.
**Spec:** §2.1 rationale, §11 injection corpus, §12 acceptance criteria 10 and 12.

**M2 exit demo:** `scheck local` and `scheck ssh` produce full agentic reports against
the `openai-compatible` provider on both a clean host and the seeded fixture, with
attributed severity adjustments visible in the JSON output. Acceptance criteria 5, 6, 7,
8, 9 (model half), 10 and 12 are all checkable at this point. Configuration inspection
and validation from M2.2a are complete, including provider settings. M4 follows.

---

## M4 — regression coverage and release validation

M4.5–M4.7 gate 0.0.1: regression coverage, acceptance validation and release delivery. Existing profile thresholds and catalog filtering remain
part of this release; no expanded profile catalog is required. Preserve their tests.
CLI features unavailable in 0.0.1 must fail explicitly rather than appear implemented.

### M4.5 — golden-fixture regression suite
Deliver a committed set of golden reports (input fixtures → expected report JSON) that
CI diffs on every change, covering at least one fixture per platform and one per
0.0.1 provider (`mock` and recorded native-tool-calling adapter responses). Live model
quality is evaluated separately in M2.7.
**Spec:** §11 (ties together fixture targets, mock provider, and conformance suite into
one CI gate).

### M4.6 — full acceptance criteria pass
Not new code — a dedicated pass running every criterion in §12 end to end (including
the before/after filesystem diff on a throwaway VM for criterion 3, and both Ubuntu and
Fedora for criterion 1) and recording the result. Also run the M2.2a configuration
walkthrough against the release build and verify its provenance and validation examples.
This is the 0.0.1 sign-off gate.
**Spec:** §12, all twelve criteria.

### M4.7 — GitHub release process

Deliver a documented, repeatable GitHub release process for `v0.0.1` and subsequent
version tags. Add CI and a release workflow under `.github/workflows/`, plus a maintainer
runbook in `docs/RELEASING.md`. This slice plans release automation; it does not publish
anything merely by implementing the workflow.

Build archives for Linux and macOS on `amd64` and `arm64`, containing the `scheck`
binary and the repository's license. Name assets consistently, for example
`scheck_0.0.1_linux_amd64.tar.gz`, and attach a SHA-256 checksum file. Inject the tagged
version through the existing `internal/version.Version` linker variable; release builds
must not report a development version or a dirty working tree. Use the repository's
Go toolchain requirement and pin build tooling/actions to reviewed versions.

The runbook defines the sequence: select a clean commit, pass M4.6's acceptance gate,
create and push its `v0.0.1` tag, build and verify assets, prepare a draft GitHub Release,
review the artifacts and release notes, then explicitly publish it. Notes identify
supported platforms, installation/checksum instructions, first-release limitations,
report schema version and the recorded validation evidence. Publishing establishes the
first-release compatibility baseline from SPEC §7.4; product and schema versions remain
separate. Do not move an already published tag or silently replace its binaries.

**Demo:** rehearse the workflow against a non-production tag in a scratch repository or
an unpublished release, download the generated archives, verify checksums and run
`--version`, `catalog --format json` and `explain` on matching OS/architecture runners.
These artifact smoke checks require neither a model API key nor a real-host assessment.

**Done when:**

- CI runs `make check`, including `go fix`, and fails if required modernization leaves
  tracked source changes; relevant container integration results and M2.7's recorded
  live quality/adversarial evaluations are required release evidence;
- the release workflow builds the exact tagged commit, verifies tag/version agreement,
  and produces all four archives and checksums; each advertised platform has recorded
  execution evidence, using an appropriate runner or documented manual validation;
- checks gate asset creation, and missing/failed artifacts prevent publication;
  release-write permissions are scoped to the release job, ordinary CI cannot publish,
  and untrusted pull requests do not receive release credentials;
- a rehearsal proves draft creation, download verification and smoke checks; retries
  cannot overwrite an already published release, and the runbook covers recovering a
  failed draft build without moving a published tag;
- README installation instructions link to GitHub Releases and distinguish published
  binaries from source builds. Document macOS signing/notarization status accurately;
  do not imply it is supplied unless implemented and verified;
- M4.6 evidence is recorded for the release commit before publication. No production
  model credentials are needed for routine builds or artifact smoke tests.

**Spec work:** §7.4 compatibility baseline, §11 validation and §12 acceptance evidence;
document release mechanics in `docs/RELEASING.md` when implementing this slice.

**M4 exit demo:** all twelve acceptance criteria in §12 pass and are recorded, and
M4.7 produces verified artifacts with a completed release checklist. Publish `v0.0.1`
through the documented release process.

---

## Sequencing notes

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
- **Configuration usability follows context ingestion.** M2.2a uses the same resolver
  as real runs and adds inspection, validation and a walkthrough before M2.3. Its
  provider-specific validation is completed with M2.6; no live model is needed to
  inspect preferences or local context.
- **M4.5–M4.7 complete 0.0.1.** Regression coverage grows with M1/M2;
  M4.6 signs off those results, configuration usability and all twelve acceptance
  criteria. M4.7 can prepare automation earlier, but publication requires that sign-off
  for the release commit.
