# Working on scheck as an agent

scheck is a **read-only** security posture checker for one macOS or Linux host, local or
over SSH. Read `docs/SPEC.md` before changing anything; `docs/ROADMAP-0.0.1.md` says what is
built (M0, M1 through M1.8, and M2 including its live evaluation and M2.8's decision)
and what is pending (M4). This file is the operating manual for a coding agent in this
repository. The spec wins on any conflict.

**No model assesses a host in this build.** The live evaluation failed the frozen
criteria and the criteria called that a deletion (`docs/SPEC.md §2.1`,
`docs/eval/phase2-results.md`), so `scheck local` and `scheck ssh` collect facts and
assess them with the posture rules. Phase 2 — `internal/agent`, the three tools, the
`llm` adapters — is kept, tested offline, and reachable only from the hidden `scheck
eval`. Do not wire it back into a run, and do not delete it either: reviving it takes a
new record that passes the criteria, and removing it would throw away what that record
has to be produced with.

## Non-negotiables

These are the security boundary. A change that weakens one is wrong even if every test
passes.

1. **The tool never modifies the target.** No check may write, and no code path may
   run anything that is not a catalog entry. Integration tests diff the container before
   and after a full run and fail on any change outside sshd's own login noise, which
   they log; keep that assertion true and never widen its tolerances. One write is known
   and unresolved: `dnf -q check-update` run unprivileged leaves a metadata cache under
   `/var/tmp` (`docs/eval/acceptance-0.0.1.md`, open item 1).
2. **The catalog is the whole command surface.** Every executable command is a
   `check.Check` with literal argv tokens and typed `{name}` placeholders. Never build
   argv by concatenation, never accept a command string from a model or a user, never
   call `target.Exec` from anywhere but `internal/runner`.
3. **`runner.Runner.Run` is the single enforcement point.** Bind → realpath → path
   policy → elevation → budgeted exec → redact → truncate → extract → parse → audit.
   Phase 2's `run_check` and `read_file` tools must go through it. Do not add a second
   path "for a special case".
4. **Policy owns sensitivity, redaction and budgets** (`internal/policy`). Config knobs
   only narrow (disable checks, deny paths, add redactions). Never add a knob that
   widens what may run or what may be revealed.
5. **Redact before truncate; mark everything.** Output is redacted as
   `[REDACTED:<rule>:<n bytes>]` and cut as `[TRUNCATED:<n bytes>]`. Nothing downstream
   (report, audit log, persisted run, verbose output, fixtures) may see pre-redaction
   bytes.
6. **SSH: canary first.** The first command on a session is `sys.canary`; a mismatch
   exits 3 before any other command. Do not weaken the canary string or make the quoter
   "smarter"; both are tested over the whole catalog.
7. **Elevation is `sudo -n --` as a prefix, nothing else.** Never prompt for, read, or
   transmit a password. Never read credentials from a config file.
8. **Exactly one catalog entry has `Canary: true`.** It is the only literal allowed to
   contain shell metacharacters. The invariants test enforces this; do not add
   exemptions.

## Layout

| Path | Owns |
|---|---|
| `cmd/scheck` | cobra commands: `local`, `ssh`, `catalog`, `explain`, `sudoers`; flag parsing; exit codes; the tty/`NO_COLOR`/width decision (`terminal.go`) |
| `internal/target` | `Target` interface; `local`, `ssh`, `fixture` implementations |
| `internal/check` | `Check`/`Param` types, registry, `Bind`, invariants `Validate`, parsers |
| `internal/check/{common,linux,macos}` | the catalog itself; `internal/check/all` imports them and runs the invariants test |
| `internal/policy` | path policy, redactor, budgets, JSONL audit log |
| `internal/runner` | the one exec path (see rule 3) |
| `internal/baseline` | phase 1: plan, run, fact sheet; the golden command traces in `testdata/golden` (M4.5) |
| `internal/report` | envelope (§7.4), JSON renderer, and the text report under the §7.6 contract (`text.go`, `text_layout.go`, `reasons.go`, `domains.go`); golden text and JSON reports in `testdata/golden`; `docs/report-schema.json` |
| `internal/finding` | finding id catalog with base severities, posture rules and their evaluator (§7.1, §7.5); reads the fact sheet, never executes. `ValidateRules` is its invariants test |
| `internal/state` | run persistence under the state dir |
| `internal/config` | yaml chain, validation, narrowing only |
| `internal/sudoers` | NOPASSWD fragment generator from elevated checks |
| `internal/llm` | the provider contract (§5.1), token accounting (`CheckFit`), the registry; `mock` (transcript replay), `openai` (the default adapter), `conformance` (the suite every adapter passes), `all` (links adapters, registers deferred names) |
| `internal/operator` | operator context: sources, the §6.2 schema, per-kind merge, budget, the `<operator_context>` block |
| `internal/agent` | phase 2: the system prompt, the three tools, the loop; every execution through `runner.RunAs`, every finding through `finding.Store`. No CLI run reaches it in 0.0.1; `internal/eval` is its only caller |
| `internal/eval` | the M2.7 harness: arms, metrics, adversarial pairs, the comparison report |
| `internal/bounded` | the research track's R1 (`docs/ROADMAP-RESEARCH.md`, §5.9): code enumerates candidates, runs a fixed follow-up table through `runner.RunAs`, asks a few yes/no questions per item and decides in code. Offline, scripted answers, `internal/eval` its only caller |
| `testdata/context`, `testdata/eval`, `testdata/transcripts` | injection corpus with benign controls; labeled evaluation cases (`base:` a recorded fixture); mock transcripts |
| `docs/eval` | the frozen phase 2 criteria and the results record |
| `test/live` | opt-in tests that spend real money (`make live`, build tag `live`) |
| `test/containers`, `test/integ` | Docker images and `integration`-tagged tests |
| `testdata/fixtures/<name>` | recorded exec fixtures (`manifest.yaml` + files) |
| `docs/` | `SPEC.md`, `ROADMAP-0.0.1.md`, `report-schema.json`; root `README.md` is the quick start |

Everything is under `internal/`; nothing is importable from outside the module.

For agents operating the CLI, use the `scheck` skill at
[.agents/skills/scheck/SKILL.md](.agents/skills/scheck/SKILL.md). It covers collecting
and interpreting host evidence, not implementation work on this repository. Prefer
JSON, inspect `run.assessment` and coverage, and never treat exit 0 as a security verdict.

## Commands

```sh
make check      # vet + go fix + golangci-lint + go test -race ./...   (must be green before every commit)
make build      # bin/scheck
make integ      # integration tests; needs Docker or Podman running
make fixtures   # re-record testdata/fixtures/{ubuntu,fedora} from the containers
go run ./cmd/scheck local --stop-after plan
go run ./cmd/scheck local --stop-after facts --format json --audit-log /tmp/audit.jsonl
go run ./cmd/scheck ssh user@host --stop-after facts
go run ./cmd/scheck catalog --profile hardened
go run ./cmd/scheck explain sshd.config --format json
go run ./cmd/scheck catalog --platform linux --format json
go run ./cmd/scheck local --stop-after facts --format json --include-evidence --no-persist
go run ./cmd/scheck sudoers --platform macos
go run ./cmd/scheck providers
go run ./cmd/scheck config show --format json
go run ./cmd/scheck local --context hosts/gateway.yaml --stop-after context
go run ./cmd/scheck explain sshd.password_auth_enabled --exposure internet
go run ./cmd/scheck local                         # facts + posture rules; no model, no key, free
go run ./cmd/scheck eval --provider mock          # the harness on the mock; no claim
go run ./cmd/scheck eval --provider mock --arms rules,bounded --no-pairs   # the research arm, scripted
go run ./cmd/scheck eval --cases linux-clean --no-pairs --out /tmp/r.md   # one case, live; spends money
make live                                        # opt-in live tests
make probe                                       # the R3 recall probe; needs TYPESAFE_API_KEY, spends cents
go test ./internal/report -update    # rewrite the golden text and JSON reports, then read the diff
go test ./internal/baseline -update  # rewrite the golden command traces, then read the diff
```

`make check` also runs `scripts/depcheck.sh`: `agent`, `policy`, `check`, `finding`,
`report`, `llm` and `bounded` must have no adapter or SDK in their dependency graph, and
none of the first six may import `internal/bounded`.

`make check` includes the user's `fix` target (`go fix ./...`); keep it in the chain.
If `go fix` proposes conflicting rewrites and never converges, apply the modernization
by hand (this happened with `slices.Contains` in `internal/check`).

## Adding a catalog check

1. Add the entry in `internal/check/{common,linux,macos}` with `ID`, `Description`,
   `Domain`, literal `Argv`, `Parser`, `Baseline`, `MinProfile`. Set `ExitOK` when a
   non-zero exit is an answer (`check.AnyExit` for `systemctl is-*`). Set `Elevated`
   when root is needed. Set `PathUse` on any check with a `Path` param. Set `Extract`
   to keep one line of a chatty command. Set `Unit` on a `lines` or `kv` check (the
   plural noun for one record), or pick a typed shape when a summary, a rule or a
   future diff needs fields; a typed parser keyed to a new tool's output format goes in
   `internal/check/typed.go` and is selected from `Argv[0]`, never by sniffing output.
2. Run `make check`. The invariants test names the rule you broke; fix the entry, not
   the rule.
3. If the check is elevated, `internal/sudoers` needs the binary's absolute path in its
   per-platform table, and `scheck sudoers` must still pass `visudo -cf` (integration).
4. Record it into the fixtures with `make fixtures` (Linux) and review the diff; for
   macOS, run with `--record-fixtures DIR` locally and scrub hostname, user and
   serial numbers before committing.
5. Keep the baseline tier at or under the cap (40 on-demand entries at `baseline`).

## Adding a posture rule

1. Add or reuse a `finding.Def` in `internal/finding/catalog.go`: a rule finding has no
   model to write its text, so title, category, base severity, impact and remediation
   are all required.
2. Add the `Rule` in `internal/finding/rule.go`. One rule reads one check; a conclusion
   needing two facts is phase 2's job. Pick the predicate that matches the check's
   parser and fill in what makes the evidence *recognizable* (`Requires`, `Known`,
   `Recognize`) — without it the predicate cannot abstain, and an answer scheck does not
   understand would be read as a pass (§7.5).
3. Add all three fixtures to `TestEveryRuleFiresDisprovesAndAbstains`: firing,
   disproved, and insufficient evidence. The test fails when a rule has no fixtures.
4. Run `make check`; `ValidateRules` names the invariant you broke. Regenerate the
   golden reports and read the diff.

## Testing rules

- Unit tests never touch the network or a real target; use `internal/target/fixture`.
- Anything that needs a real shell, sshd or sudo goes in `test/integ` behind the
  `integration` build tag and runs in `test/containers`.
- A seeded secret in any fixture must be asserted absent from report, audit log and
  persisted run, and its marker asserted present. See `internal/state/redaction_test.go`.
- Run `go test` with `set -o pipefail` if you pipe it; a piped `grep` hides failures.
- `--sudo` cannot be exercised non-interactively on a workstation where sudo prompts.
  Use `sudo -v` first, or install the `scheck sudoers` fragment, or rely on the Ubuntu
  container test.

## Conventions

- One commit per roadmap slice, `make check` green at every commit, message in the
  imperative describing the slice.
- Exit codes: 0 ok, 1 findings, 2 incomplete, 3 usage/policy/canary. Do not invent a
  fifth.
- Until the first GitHub release, breaking CLI, config and report changes are allowed;
  do not build compatibility shims or migrations for development artifacts. Keep the
  spec, implementation, schema and fixtures aligned when implementing a change.
  After that release, report `schema_version` is `MAJOR.MINOR`: additions bump MINOR;
  renames, removals and type changes bump MAJOR (`docs/SPEC.md §7.4`).
- Posture rules require recognized evidence; unknown is not safe or unsafe. Preserve
  assessment coverage in JSON and text, and test partial evidence (§7.5).
- The text report is a contract (§7.6) pinned by the golden files. Regenerate with
  `go test ./internal/report -update` and read the diff as a review item. Two more
  goldens sit beside it (§11): the JSON report, validated against
  `docs/report-schema.json` as committed, and the command trace in `internal/baseline`,
  which is the run's audit log — argv, decision and output hash per attempted check, in
  order. A diff there means what reaches the target changed; explain it or fix it, never
  regenerate past it. Three rules hold for the text report: a status word describes execution, never posture; target-derived text is
  control-character escaped before it is printed; and the terminal decisions (width,
  tty, `NO_COLOR`) stay in `cmd/scheck`, never in `internal/report`.
- Code comments cite the spec section (`docs/SPEC.md §4.3`) for anything that exists
  because of a security decision.
- Flags for later milestones stay registered and exit 3 with "not available in this
  build". Do not remove them and do not half-implement them.
- Design lens: keep modules deep, pull complexity into the runner and policy rather
  than out to callers, and define errors out of existence where the spec allows
  (`unavailable` is a result, not an error). The `.claude/skills/software-design-philosophy`
  skill has the vocabulary.
- When the implementation has to deviate from the spec, update `docs/SPEC.md` in the
  same commit and add a line to its change list. The spec is the contract; silent
  drift is a bug.

## Adding a provider adapter

1. Implement `llm.Provider` under `internal/llm/<name>` with net/http, not an SDK, and
   register it in `init` with `llm.Register`; import it from `internal/llm/all`.
   Construction takes `llm.Config` and performs no I/O; credentials are read from the
   environment at request time and never printed.
2. Absorb capability differences inside the adapter (§5.3) and record what was not
   exercised in `Native()`. Never add a provider name or capability boolean to an `if`
   in `internal/agent`.
3. Pass `conformance.Run` through a fake server that speaks the protocol the way the
   endpoint does; classify failures as `llm.Error` kinds so the loop can end a run
   honestly.

## Phase 2 rules

These hold for `internal/agent` and the harness that drives it. They are not dead
letters: the code is tested offline in `make check`, and a change that breaks one is
still wrong.

- `run_check` and `read_file` call `runner.RunAs` with an `Origin`; the menu gate (profile
  tier, no canary) is enforced there, not in the tool. `report_finding` goes through
  `finding.Store.Report`, which validates every excerpt against the exact cited observation's output and
  refuses an id the posture rules already settled: another platform's id, an id whose
  rule returned `not_matched`, or a judgement whose `Def.Premise` the rule disproved.
  Put a new deterministic guard there, never in the prompt alone. A `verdict: ruled_out`
  call goes through `finding.Store.RuleOut`: validated the same way, never a finding,
  surfaced as `run.agent.ruled_out`.
- Severity never comes from the model. A `severity` in `report_finding` is ignored.
- Every budget in `policy.Budgets` ends the run `incomplete` by name; a request is
  checked with `llm.CheckFit` before it is sent, and overflow never drops evidence.
- The `<operator_context>` block and check output are data; `testdata/context` is the
  corpus and `internal/agent/injection_test.go` the boundary tests. They prove policy,
  not model resistance: only a live run recorded in `docs/eval/phase2-results.md` does.
- A model flag on `local` or `ssh` exits 3 (`modelFlags` in `cmd/scheck/root.go`); the
  provider pre-flight lives in `cmd/scheck/evalcmd.go`. Keep both there.

## The research arm (`internal/bounded`)

R1 of `docs/ROADMAP-RESEARCH.md` is implemented and offline. Three rules hold there, and
a change that breaks one is wrong even if the arm scores better:

- **Nothing is filed from the absence of an explanation.** Every decision rule needs an
  affirmative signal; "nobody declared this" is a property of the operator's notes, not
  of the host, and it is what produced the phase 2 false positives.
- **Insufficient evidence is never sent and never filed.** An `unavailable`, truncated
  or redacted record is settled by code as `insufficient` before any question exists.
- **The follow-up table is a table.** No model picks a check, a path or an argument, and
  every read goes through `runner.RunAs` with the arm's `Origin`.

A question that names a state field must not be asked when that field is empty, or when
the command that produced it is known to degrade it: the candidate is `insufficient`
instead. Listeners are the worked example both ways — `ss` names no process unprivileged,
and `lsof` shortens the name without `+c 0` — and the second test reads the argv that
produced the capture, so it lifts by itself when the catalog entry improves. Skipping
these is what keeps the phase 2 false positive from returning by another route.

Questions, criteria and thresholds are versioned data (`bounded.QuestionsVersion`);
changing any of them invalidates a threshold measured against the old ones. Answer
sources are attributed separately in every record — scripted answers make no quality
claim of any kind.

## Out of scope until the roadmap slice that introduces them

`--only`, SARIF, `scheck diff`, `--local-only` and `allow_egress: false` (exit 3 now),
`anthropic` and `ollama` (registered, exit 3), tool-call emulation, chunking, the
§5.9 track's R2 and R3 answer sources (`--bounded-source openai|jev`, exit 3 now). Do not scaffold empty abstractions for any of them.
A posture rule reads the fact sheet only; if a rule seems to need a new command, add a
catalog check first and keep the rule single-fact (§7.5). A conclusion that needs two
facts is the model's, through a judgement finding id in `internal/finding/catalog.go`.
