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

**Status (2026-09-20):** M0, M1 (through M1.8) and all of M2 (through M2.8) are
committed on `main`, one commit per slice, `make check` green at each. The repeated live
release evaluation M2.7 called for is recorded in `docs/eval/phase2-results.md`: it
failed the frozen criteria, and M2.8 acted on it — **no model assesses a host in
0.0.1** (`SPEC.md` §2.1). That resolves acceptance criteria 7, 10 and 12 and closes the
loop-versus-single-pass question for this release. Checkmarks indicate completed
implementation; each slice records validation separately. M4.5–M4.7 are what remains.

**0.0.1 scope revision (2026-09-20):** M2 includes full-request context limits,
real-model quality/adversarial release gates and configuration usability (M2.2a).
M2.6a adds pre-release evidence and execution hardening before M2.7's qualifying live
runs. M4.5 captures collection behavior as well as reports, to support the later pack
extraction in [0.0.2](ROADMAP-0.0.2.md).
Existing profile behavior, regression coverage, acceptance validation and the GitHub
release process complete the 0.0.1 scope.

**M4 scope for 0.0.1 (2026-09-20):** M4.5–M4.7 are scoped to what a first release has
to be able to defend, not to everything a mature regression programme would keep. Three
requirements written into M4.5 before the phase 2 decision are dropped, each with its
reason recorded in the slice: golden provider responses (a host assessment reaches no
provider now), a golden matrix for disabled checks, profile selection and incomplete
evidence (unit tests assert those directly), and machinery to remap nondeterministic
observation references (they are deterministic, which the suite now asserts instead).
M4.6 is a recorded pass that cites the test proving each criterion rather than
re-deriving it, and narrows criterion 3's evidence to the container diff that already
runs on every change (`SPEC.md` §12). M4.7 keeps every gate and narrows only the
per-platform execution evidence it claims. Nothing in the security boundary — criteria
2, 6 and 11 — is relaxed.

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

### M2.4 — three tools + agent loop, mock only ✅
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

**Landed (2026-09-20).** `internal/agent` (`agent.go`: `Session`, `Run`, `Outcome`,
the budgets; `tools.go`: the three tools and their schemas; `prompt.go`: the §5.8
system prompt, `PromptVersion`, the facts/findings/catalog blocks and the run_check
menu), `runner.Origin`/`RunAs` (tool, rationale, profile gate, `tool` in the audit
line), `report.Phase2`/`AgentRun` and schema 1.4, agent mode in `cmd/scheck`
(`buildProvider` before any target contact, `runAgent`, `-v`/`-vv` progress), the
footer and "Model summary" section, `policy.Canonical` for macOS `/private`, and
`testdata/transcripts/correlated-finding-{linux,macos}.json`.

- **The gate is in the runner.** A model-initiated call carries its origin; a check
  outside the profile's tier, or the canary, is `denied:unknown_check` there, audited
  like any other denial. The tool never decides what may run.
- **Evidence is validated against output.** `finding.Store.Output` looks at phase 1 and
  the model's own checks; a fabricated excerpt is an error result the model can
  correct from, and never a finding.
- **Single-pass is the same loop.** `MaxIterations: 1`; a last turn that only reported
  is complete, one that asked for evidence is incomplete and says so.
- **Found by the demo on a real Mac:** the path policy did not recognise
  `/private/etc` as `/etc`. Fixed in the runner's decision path, macOS only.

**Validation.** `make check` green (`depcheck` included: `agent` has no provider
dependency). `internal/agent` covers the demo transcript end to end (merge into the
rule finding, a new model finding, the prompt's contents and the secret's absence),
`read_file`/`text.cat` audit identity, error results for an unknown id, an invalid
param, a denied path, a sensitive path (metadata, not error), an elevated check under
`--elevate none`, hidden and canary checks, an unknown tool and malformed input — each
with its audit line — the report_finding contract (severity ignored, custom capped,
rule text and confidence retained, fabricated evidence rejected), all six budgets
ending incomplete, the five context-limit cases (initial overflow with no request
sent and findings kept, history growth, output reservation, unknown limit, provider
overflow with no retry), single-pass complete/unanswered, refusal and error stops.
`cmd/scheck` validates a phase 2 envelope against the schema in both renderers, an
incomplete pass exiting 2 with facts and assessments kept, and every configuration
error exiting 3 with no report. Verified by hand on this Mac: `scheck local --provider
mock --transcript testdata/transcripts/correlated-finding-macos.json` reads
`/etc/ssh/sshd_config` and lists `/etc/ssh` through the runner, reports the custom
finding capped at medium, and exits 1.

### M2.5 — operator context in the prompt + injection corpus ✅
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

**Landed (2026-09-20).** `testdata/context/hostile/` (eight files: role override,
report nothing, downgrade and accept, run a command, fetch a URL, read sensitive
paths, fabricated evidence, the schema written as prose) each paired with a benign
control of the same name under `benign/`; `internal/agent/injection_test.go`; one
added sentence in the system prompt declaring check output to be data. The prompt
block itself (structured YAML the model can reason about, prose verbatim under
per-source headings, the §6.4 declaration first) landed with M2.4 through
`operator.Merged.Block`, the same text `--stop-after context` prints.

**Validation.** `make check` green. The tests establish, with a scripted model, what
policy guarantees regardless of the model: the identical transcript run with the
hostile corpus, the benign corpus and no context produces byte-identical findings and
severities, and the hostile prose appears in the prompt only inside the declared block;
the schema-as-prose file stays prose; a transcript that obeys the corpus (a shell, a
metadata URL, `/etc/shadow`, a private key, `~/.aws`, a traversal, a metacharacter in a
path, a glob) is denied or answered with metadata at every call, each with an audit
line, and every argv the target saw starts with a catalog binary; a transcript that
tries to accept, downgrade or fabricate leaves the rule finding at its grade with its
curated text; planted instruction text in a baseline fact and in a read file reaches
the model only inside `<facts>` and a transcript that obeys it is denied. None of this
is a claim about model resistance: M2.7 runs the corpus against the real model.

### M2.6 — `openai-compatible` provider ✅ (live cost measurement pending)
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

**Landed (2026-09-20).** `internal/llm/openai` (`openai.go`: construction from
configuration with no I/O, the wire encoding, streaming SSE decoding, tool-call
assembly by index, error classification, the two absorbed capability differences;
`models.go`: context windows and list prices per family), registered as the default
in `internal/llm/all`; `test/live` behind the `live` build tag with `make live`.

- **Native tool calling required**: an endpoint that rejects `tools` fails as
  `unsupported`; nothing emulates. `max_completion_tokens` falls back to `max_tokens`
  once; a rejected `reasoning_effort` is dropped and `Native.Reasoning` set false, so
  the report never claims a feature that was not exercised. `Block.Cacheable` is
  recorded as unexercised (`PromptCaching: false`); automatic cache hits show in
  `cache_read`.
- **Pricing only where the table applies**: `cost_usd` is computed on OpenAI's
  endpoint for known families and null everywhere else, never an invented number.
- **Configuration errors are usage errors before any target contact**: no model on a
  non-OpenAI endpoint, an unknown window without `max_context`, no key on OpenAI's
  endpoint, credentials in the URL. OpenAI's endpoint defaults to `gpt-5.6-luna`.
  `--local-only` and `allow_egress: false` were already exit 3 from M2.4.

**Validation.** `make check` green. The conformance suite (§11) is green for
`openai-compatible` through a fake chat-completions server that streams text and
tool-call fragments the way the endpoint does — the same table `mock` passes.
Adapter tests cover configuration validation, the request encoding (one system
message, tool messages, functions, `max_completion_tokens`, `reasoning_effort`, the
bearer header), the `max_tokens` fallback and its persistence, the `reasoning_effort`
retreat recorded in `Native`, tools rejected as unsupported, usage with cached tokens
and cost on the priced path versus null on a custom endpoint, error classification
per status and message, a stream that ends without `[DONE]`, malformed tool
arguments, and the model table. `cmd/scheck` covers the exit-3 cases and `scheck
providers` reporting the adapter ready with its window and native set.
**Not done:** the live run. `test/live/TestLiveLocalRun` performs one `scheck local`
against this machine, asserts the report shape, cost under $0.50 and no denied
model-initiated check, but needs `SCHECK_LIVE=1` and a credential and was not
executed in this environment. Acceptance criterion 7 is unrecorded until it is.

### M2.6a — pre-release evidence and execution hardening ✅

**Depends on:** the implemented M2 tool loop. Complete before M2.7's qualifying live
evaluation and before freezing the first published report contract. Historical slice
IDs remain unchanged; the sequence is M2.6 → M2.6a → M2.7 live evaluation.

**Outcome:** repeated parameterized checks retain independently citable evidence, and
every caller asks the runner to execute a catalog ID. Previously, the agent indexed
results by check ID, so a second `text.cat` read replaced the first result used for
citation validation. Neither fix depends on application packs.

**Deliver:**

- Core assigns an immutable run-local observation reference to each check invocation
  and result. Record the requested check ID, parameters, execution occurrence and result,
  linking to the catalog definition and validated bindings when available. Retain denied
  and unavailable outcomes without implying they passed validation or executed. Repeated
  calls remain distinct, including calls with identical parameters; later observations
  never overwrite earlier ones. A reference is unique within its run, not a stable
  cross-run identity. Parameter storage obeys the existing redaction policy.
- Baseline and agent collection use the same observation store. Tool results expose
  observation references; findings cite them, and `finding.Store` validates model excerpts
  against the exact cited observation's redacted capture. Assessments identify supporting
  observations or explain why none was obtained. Preserve finding-ID merge semantics
  while retaining distinct supporting references. Check IDs still identify definitions.
- Emitted and persisted reports keep observation references resolvable, including agent
  evidence. Preserve the existing evidence-inclusion policy: raw captures are not required
  in default JSON or persistence. Update the report schema, tool contract, prompt version,
  mock transcripts and fixtures together; add no development-format compatibility shim.
  Keep collected observations within existing budgets; do not truncate history silently
  or raise limits to accommodate the new store.
- Replace baseline's `Runner.RunCheck(check.Check, ...)` calls with ID-based execution
  and remove that exported definition-taking path. Definition resolution remains inside
  the runner; retain its private execution implementation and the existing registry.
  Preserve phase-specific origin/profile checks, canary ordering and the policy pipeline.

**Demo:** a fixture-backed mock session reads two different permitted files through
`text.cat`, then reports findings citing both observations after the second read. Show
that both references resolve in JSON and persistence and that an excerpt found only in
the other observation is rejected. No live inference or target is needed.

**Done when:** tests cover different parameters, repeated identical parameters with
changed output, unknown references, denied/unavailable calls, cross-observation citation
rejection, and redaction across report, audit, persistence and model input. Baseline
findings/coverage and command traces remain unchanged; schema/golden changes are reviewed.
Unknown catalog IDs cannot execute, no exported runner method accepts an executable
definition, and `make check` plus relevant runner/SSH integration checks pass. M2.7's
offline harness and transcripts use the new contract without changing frozen success
criteria. Earlier live observations remain historical evidence, not validation of the
changed prompt/tool contract.

**Scope:** explicit pack composition, application binding, public parser contracts and
the contribution API remain in 0.0.2, informed by M5.0's application brief. This slice
does not introduce a plugin framework or parameterized application planning.

**Implementation and validation (2026-09-20, working tree):** the runner owns an
immutable observation store shared by baseline, agent and report construction. Exact
references flow through tools, findings, coverage, audit and schema 1.5 reports;
`RunCheck` is removed. The spec, prompt, offline transcripts and golden reports are
updated together. `make check` passes, including the offline evaluation harness.
SSH integration passes for Ubuntu/Fedora reports with empty filesystem diffs, the
five-shell canary matrix, exit-code handling and sudoers/elevation. A comparison with
the pre-change commit on all three host fixtures found identical command traces,
finding content and coverage after excluding the new observation fields. Text golden
diffs contain reference labels and their resulting line wraps only.

Run the offline two-file demo with:

```sh
go test ./internal/agent -run TestObservationCitationsEndToEnd -v
```

It verifies both citations after the second read, rejects wrong/unknown/unusable
observations, checks persistence and default/opt-in JSON, and asserts redaction across
model requests, reports, audit and persistence. Runner tests cover identical requests
with changed output, immutable copies, and redacted denied requests. A baseline test
proves a modified plan cannot supply executable argv. No live inference was run for
this slice; qualifying M2.7 runs must use the changed prompt/tool contract.

**Spec:** §2–§3, §4.5, §5.7–§5.8, §7.3–§7.6 and §11.

### M2.7 — phase-2-earns-its-cost evaluation ✅ (recorded; the gate fails, see M2.8)

**Release-evaluation prerequisite:** M2.6a is implemented and validated in the working tree. Record the resulting prompt/tool
contract and build versions in the qualifying repeated runs. Preserve the frozen pass
criteria; a preliminary run on the earlier contract does not satisfy this prerequisite.

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

**Landed (2026-09-20): the harness, not the result.** `internal/eval` (`eval.go`: suite
loading with label validation and the §2 minimums, the three arms over identical
facts/rules/context, the §3 metrics, the §4 pairs; `report.go`: per-arm medians, the
frozen verdicts, the markdown comparison), the hidden `scheck eval` command,
`testdata/eval` with fifteen cases (2 clean, 3 single-fact, 3 correlated, 3 follow-up,
4 misleading) built on the recorded ubuntu and macos fixtures through the new
`base:`/`absent:` manifest fields, four scripted transcripts that exercise every metric
(a resolved follow-up, a missed one, a false positive, a correlated hit), and
`docs/eval/phase2-results.md`.

**Recorded (2026-09-20): the three-repeat run fails the gate.** Two `--repeat 1`
observation runs against `gpt-5.6-luna` found a redaction false positive on sudoers
`NOPASSWD:` lines, two gaps in `finding.Store` (another platform's id, an id the rule
had disproved) and the model filing ruled-out hypotheses through `report_finding`;
those are fixed in the spec's "first live evaluation" change entry. The three-repeat
record (`docs/eval/results-2026-09-20-gpt-5.6-luna.{json,md}`, summarized in
`docs/eval/phase2-results.md`) then fails §3.1 decisively: in 9 of 9 follow-up agent
runs the model made no tool call, so the loop was not used. §3.2, §3.5 and §4.4 also
fail, for reasons the record separates into model behaviour, label questions and
natural drift. Single-pass fails its own bar. Criterion 7 passes (`make live`,
$0.0079). Read literally, the criteria say 0.0.1 ships posture rules only; the
decision — delete the loop, keep single-pass, or change what the model is told and
measure again without loosening a criterion — was taken through the next steps
below: measured again on a changed contract, and decided by the second record.

**Next steps (2026-09-20), in order.** Every live record so far is one-repeat or
predates M2.6a's prompt/tool contract; the first live run on that contract
(`sp-bb2762146136`, one repeat) accepted observation-referenced citations end to end
and told the same story as the three-repeat record. What follows is the path to a
decision, without loosening a criterion:

1. **Find out whether the loop is model-limited** — done (2026-09-20, recorded in
   `docs/eval/phase2-results.md`). The three follow-up cases at three repeats, no
   pairs, on the M2.6a contract: `gpt-5.6-luna` investigates (median agent tokens four
   times single-pass; the expected id in 3 of 9 agent runs against 0 of 9 single-pass;
   no run resolved by the harness's definition because the cron listing alone gives
   the entry away) and `gpt-5.6-terra` does not (no tool call in 9 of 9, no finding in
   18 of 18, at ten times the price). Neither branch of the rule applies: the stronger
   model does not rescue the loop, and Luna does use it. The gate is re-run on Luna
   with the next contract.
2. **Give the model a channel for a ruled-out hypothesis** — done. `report_finding`
   carries `verdict: open|ruled_out` (§5.7); `finding.Store.RuleOut` validates it like
   a finding and files nothing; the report carries `run.agent.ruled_out` (schema 1.6),
   the text report lists it under the model summary, the harness logs it and never
   scores it. `PromptVersion` is `sp-e0d904499422`. One diagnostic run on
   `linux-cron-fetch` used it as intended: two hypotheses ruled out, none filed, the
   script read, the entry reported and resolved.
3. **Record the two label decisions** — done, in `testdata/eval` and the results
   record: the clean Mac's third-party launch daemons are masked (a clean case holds
   nothing to flag without context), and a declared listener reported as
   `net.unexpected_listener` is a false positive at any severity.
4. **Run the gate at three repeats** — done (2026-09-20, the deciding record in
   `docs/eval/phase2-results.md`, raw `results-2026-09-20-gpt-5.6-luna-ruledout.*`;
   `make live` $0.0071). §3.2, §3.3, §3.5, §3.7 and all of §4 pass; §3.1 fails because
   the loop made no `run_check`/`read_file` call in 45 of 45 runs, spending its
   iterations on `ruled_out` verdicts instead; single-pass fails its own bar (forbidden
   ids in 5 of 45 runs against the rules arm's zero; one correlated case of three in the
   majority). The run also exposed a fixture defect (two firewall cases recorded the
   same argv twice and the first, "ufw active", answered), fixed with a harness guard;
   re-run on the repaired cases, the agent finds the no-firewall case 3 of 3 and
   single-pass 0 of 3, which changes no verdict.

**Decision (2026-09-20).** Read literally, the frozen criteria say **0.0.1 ships
posture rules only**: the loop is removed and single-pass with it. Five prompt
contracts, a stronger model and a dedicated channel for the behaviour that produced the
false positives did not make the model investigate; the criteria said a failure here is
a deletion, not a redesign. What is kept: the `llm` contract and adapters, the operator
context, the grader, the finding store with its guards, the injection corpus and the
harness, all of which are exercised offline and cost nothing to carry; the release path
is `--stop-after facts` behaviour by default. The removal is the next slice (M2.8, to
be written): `scheck local` without a provider runs phase 1 and the rules, the agent
flags stay registered and exit 3 as "not available in this build", and the spec's §2.1
records that phase 2 did not earn its place in 0.0.1 and why. The roadmap owner may
instead keep the loop as an opt-in experiment behind a flag; the criteria do not
provide for that, so it would be a stated deviation, recorded in the criteria's
history, not a quiet one.

**Validation of the harness.** `make check` green. `internal/eval` asserts the suite
meets the minimums, that every case's rules arm produces exactly the rule findings its
labels expect (the fixtures say what they claim), that a mock run scores each metric as
the scripted transcripts intend (resolved, missed, false positive, abstention,
correlated hit), that the pairs are identical by construction, that the summary and
verdicts compute and that §3.1 does **not** pass on the mock; `cmd/scheck` runs `scheck
eval --provider mock` in both formats.

### M2.8 — act on the evaluation: no model assesses a host in 0.0.1 ✅

M2.7's record fails the frozen criteria on the one condition that matters, and the
criteria call that a deletion rather than a redesign. This slice carries it out at the
product surface and nowhere else.

**What changed.** `scheck local` and `scheck ssh` collect facts and assess them with
the posture rules, graded through operator context; a default run and `--stop-after
facts` are the same run. They build no provider, need no credential and send nothing a
check observed off the machine. The six flags that select a model (`--provider`,
`--model`, `--base-url`, `--effort`, `--transcript`, `--max-context`) exit 3 on those
two commands with a message that says where they still work, following the convention
that a flag for something this build does not do is registered and rejected, never a
silent no-op. The same keys in a configuration file are unused rather than fatal, so an
operator who configured a model for an earlier build is not blocked by it.
`--include-evidence` is accepted on a default run as well as after `--stop-after facts`,
since they collect the same facts. `allow_egress: false` is satisfied by construction
on `local` and `ssh`; `scheck eval` still rejects it, and `--local-only` still exits 3
everywhere because its full contract is post-v1.

**What was kept, deliberately.** `internal/agent` with its three tools, the `llm`
contract and its adapters, the operator context, the grader, the finding store with its
guards, the injection corpus and `internal/eval` behind the hidden `scheck eval`. The
harness is now the only caller of phase 2, so the provider pre-flight that a run used to
perform (registered and available adapter, a model for a non-mock provider, a known
context limit) moved into `cmd/scheck/evalcmd.go` unchanged. Everything stays under
`make check`: the loop's report envelope and its schema validation moved from
`cmd/scheck` to `internal/agent`, where the code still lives, and `make live` now drives
the harness on one labeled case instead of `scheck local`, which is the only path left
that can spend money. Deleting the loop instead would have thrown away the apparatus a
future decision has to be measured with, and the criteria ask for the loop to stop
assessing hosts, not for the measurement to become impossible.

**Spec work:** §2.1 records the outcome, what it means for the two commands and what
"kept" covers; §7.6 drops the stale "not available in this build" clause for the
footer's actual wording; §8 annotates the model flags and `--stop-after facts`; §11
describes the live test's new target; §12 resolves criteria 7, 10 and 12 instead of
leaving them open; the change list carries the entry.

**Validation:** `make check` green, including the moved envelope and schema tests. New
CLI tests assert that every model flag exits 3 on `local` and `ssh` with no output,
that a configured provider and model cannot fail a run, and that the harness rejects a
deferred adapter, an unknown provider, a missing transcript, a missing credential, an
unknown context window and `allow_egress: false` before a case runs. A rules-only
`scheck local` on this Mac exits 1 with one finding and no provider built.

**M2 exit demo:** `scheck local` and `scheck ssh` produce a rules-only report with
attributed severity adjustments visible in the JSON output, and the phase 2 comparison
that acceptance criterion 10 asks for is recorded in `docs/eval/phase2-results.md` with
the decision it produced. Acceptance criteria 5, 6, 7, 8, 9, 10 and 12 are all decided
at this point. Configuration inspection and validation from M2.2a are complete,
including provider settings. M4 follows.

---

## M4 — regression coverage and release validation

M4.5–M4.7 gate 0.0.1: regression coverage, acceptance validation and release delivery. Existing profile thresholds and catalog filtering remain
part of this release; no expanded profile catalog is required. Preserve their tests.
CLI features unavailable in 0.0.1 must fail explicitly rather than appear implemented.

### M4.5 — golden-fixture regression suite ✅
Deliver a committed set of golden artifacts (recorded fixture → expected output) that
`make check` diffs on every change, covering Ubuntu, Fedora and macOS. Live model
quality was evaluated separately in M2.7 and no longer touches this slice.

Three artifacts per platform, each pinning what the others cannot:

- the **text report** at default, `-v` and `-vv`, committed under
  `internal/report/testdata/golden/`: the §7.6 operator contract;
- the **JSON report** without `--include-evidence`: facts, findings, assessments and
  their coverage reasons, observation references and the resolution between them. The
  committed file is itself validated against `docs/report-schema.json`, so a golden left
  behind by a schema change fails instead of rotting;
- the **command trace**, which is the run's own audit log, committed under
  `internal/baseline/testdata/golden/`: one line per attempted check in execution order
  with the observation reference, the bound parameters, the actual argv, the decision
  (`run`, or `unavailable:<reason>` with the reason the check produced), the exit code,
  the elevation and the SHA-256 of the redacted output. This is the artifact that fails
  when the tool quietly starts running something else, and its hash is why the JSON
  golden need not also carry the captured bytes. A baseline plan binds no parameters, so
  it produces no `denied:` line; `internal/runner` asserts that format directly —
  unknown check, `path.not_allowed` and bad parameter — which is why it is not
  goldened.

Normalize only start time and durations. Do not normalize command order, parameters,
selection, coverage reasons or evidence links. Observation references are assigned in
execution order and are stable across a replay, which the suite asserts directly; there
is no remapping step and 0.0.1 needs none. Regeneration (`go test ./internal/report
-update`, `go test ./internal/baseline -update`) means reviewing a behavioral change,
not accepting new files.

**Dropped for 0.0.1**, with the reason: golden provider responses for `mock` and for a
recorded native-tool-calling adapter — no host assessment builds a provider (§2.1), and
the adapters are pinned by the conformance suite and the mock transcripts; and a
separate golden per configuration variant (disabled checks, profile selection,
incomplete evidence, M2.6a's repeated observations) — `internal/finding`,
`internal/baseline`, `internal/runner` and `cmd/scheck` assert each of those directly,
so goldens there would multiply artifacts without adding signal.

**Demo:** replay the fixtures offline and obtain identical artifacts; a deliberate
command-order or coverage change produces a focused diff in the trace even when the
final finding list is unchanged.

**Done when:** `make check` diffs all three artifact kinds with no target contact and no
model credential, the committed JSON validates against the schema, and the fixtures
still carry the raw recorded output that 0.0.2's `sshd` extraction (M5.1) has to be
verified against. No pack-aware test framework is required.
**Spec:** §11 (fixture targets, golden reports, redaction).

**Delivered (2026-09-20):** `TestGoldenJSONReports` (`internal/report`) and
`TestGoldenCommandTrace` (`internal/baseline`) beside the existing
`TestGoldenTextReports`, with 12 committed artifacts — nine text reports, three JSON
reports and three traces. Both new tests run in `make check` with no target and no
credential; the trace test replays twice and fails if the two differ, which is the
determinism the dropped remapping step would have papered over.

### M4.6 — full acceptance criteria pass ✅
Not new code — a dated pass over every criterion in §12, recorded in
`docs/eval/acceptance-0.0.1.md`: for each criterion, the command or the named test that
proves it, the evidence it produced, and a verdict. Criteria 7, 10 and 12 are cited
from `docs/eval/phase2-results.md` rather than re-run. Also run the M2.2a configuration
walkthrough against the release build and verify its provenance and validation
examples. This is the 0.0.1 sign-off gate.

**Relaxed for 0.0.1:** criterion 3's before/after diff is the empty `docker diff` across
a full run on Ubuntu and Fedora that `make integ` already asserts, on containers as
throwaway as the VM the criterion imagined; the macOS leg is recorded honestly as
catalog inspection plus the audit log of a real local run, because no filesystem diff
exists for it. Criterion 1's macOS leg is one developer machine, not a matrix. Both
narrowings are stated in the record and noted in §12, and neither touches criteria 2, 6
or 11.
**Spec:** §12, all twelve criteria.

**Delivered (2026-09-21):** `docs/eval/acceptance-0.0.1.md`, walked against
`scheck 683aac2`. All twelve criteria pass. Two items are carried out of the pass rather
than closed by it, both decisions for M4.7: `pkg.dnf_check_update` run unprivileged
leaves a dnf metadata cache under `/var/tmp`, which is the one write scheck can cause
and is not reconciled with §1's unqualified promise; and `config show` displays
`port 0` for a target with no explicit port. The integration test now logs the diff
lines it tolerates, so criterion 3's evidence is visible rather than implied. The pass
has to be repeated at the release commit before publication.

### M4.7 — GitHub release process

**Implementation prepared; hosted rehearsal pending.** GoReleaser configuration,
CI and draft-release workflows, MIT license, artifact verification and the
[maintainer runbook](RELEASING.md) are present. This slice remains open until an
unpublished-tag rehearsal records successful download and, on the platforms below,
execution. M4.5, M4.6 and M2.7 remain separate publication gates; no release has
been published by this implementation.

**Relaxed for 0.0.1:** execution evidence is required on the two platforms available
here — `linux/amd64` (the CI runner) and `darwin/arm64` (the development machine).
`linux/arm64` and `darwin/amd64` are built and checksum-verified only, and the release
notes must say exactly that rather than imply a smoke test that did not happen. Every
other gate in this slice stands.

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
  evidence at the level the relaxation above defines — execution on `linux/amd64` and
  `darwin/arm64`, build and checksum verification on the other two — and the notes
  state which is which;
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
- **M2.7 was the highest-risk slice, and it came back negative.** M2.8 acted on it: the
  loop no longer assesses a host, and the code, corpus and harness behind it stay for
  whatever reopens the question. The note below is why the sequencing made that cheap.
- **M2.7 (phase-2-earns-its-cost) is the highest-risk slice in the roadmap.** It's
  placed as late as reasonably possible within M2 — after the loop, tools, and context
  ingestion all work — and its success criteria are frozen in M2.1, before any of them
  exists, so the slice cannot move its own goalposts — so that a negative result is cheap to act on: the loop and tools
  built so far are needed either way (M1's `--stop-after facts` mode and the tool
  surface used for confirmation checks), but a negative result means `agent.Session`'s
  multi-turn correlation is what gets cut, not the checks or the reporting.
- **M2.6a precedes the qualifying live evaluation.** Establish observation references
  and ID-only runner execution before spending on release evidence or publishing the
  report contract. M4.5 then records the behavior that 0.0.2's pack extraction must
  preserve. Application binding and extensibility design remain in M5.
- **Configuration usability follows context ingestion.** M2.2a uses the same resolver
  as real runs and adds inspection, validation and a walkthrough before M2.3. Its
  provider-specific validation is completed with M2.6; no live model is needed to
  inspect preferences or local context.
- **M4.5–M4.7 complete 0.0.1.** Regression coverage grows with M1/M2;
  M4.6 signs off those results, configuration usability and all twelve acceptance
  criteria. M4.7 can prepare automation earlier, but publication requires that sign-off
  for the release commit.
