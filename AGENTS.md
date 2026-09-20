# Working on scheck as an agent

scheck is a **read-only** security posture checker for one macOS or Linux host, local or
over SSH. Read `docs/SPEC.md` before changing anything; `docs/ROADMAP.md` says what is
built (M0, M1) and what is next (M2). This file is the operating manual for a coding
agent in this repository. The spec wins on any conflict.

## Non-negotiables

These are the security boundary. A change that weakens one is wrong even if every test
passes.

1. **The tool never modifies the target.** No check may write, and no code path may
   run anything that is not a catalog entry. Integration tests assert an empty
   `docker diff` after a full run; keep that true.
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
| `cmd/scheck` | cobra commands: `local`, `ssh`, `catalog`, `sudoers`; flag parsing; exit codes |
| `internal/target` | `Target` interface; `local`, `ssh`, `fixture` implementations |
| `internal/check` | `Check`/`Param` types, registry, `Bind`, invariants `Validate`, parsers |
| `internal/check/{common,linux,macos}` | the catalog itself; `internal/check/all` imports them and runs the invariants test |
| `internal/policy` | path policy, redactor, budgets, JSONL audit log |
| `internal/runner` | the one exec path (see rule 3) |
| `internal/baseline` | phase 1: plan, run, fact sheet |
| `internal/report` | envelope (§7.4), text and JSON renderers; `docs/report-schema.json` |
| `internal/state` | run persistence under the state dir |
| `internal/config` | yaml chain, validation, narrowing only |
| `internal/sudoers` | NOPASSWD fragment generator from elevated checks |
| `test/containers`, `test/integ` | Docker images and `integration`-tagged tests |
| `testdata/fixtures/<name>` | recorded exec fixtures (`manifest.yaml` + files) |
| `docs/` | `SPEC.md`, `ROADMAP.md`, `report-schema.json` |

Everything is under `internal/`; nothing is importable from outside the module.

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
go run ./cmd/scheck sudoers --platform macos
```

`make check` includes the user's `fix` target (`go fix ./...`); keep it in the chain.
If `go fix` proposes conflicting rewrites and never converges, apply the modernization
by hand (this happened with `slices.Contains` in `internal/check`).

## Adding a catalog check

1. Add the entry in `internal/check/{common,linux,macos}` with `ID`, `Description`,
   `Domain`, literal `Argv`, `Parser`, `Baseline`, `MinProfile`. Set `ExitOK` when a
   non-zero exit is an answer (`check.AnyExit` for `systemctl is-*`). Set `Elevated`
   when root is needed. Set `PathUse` on any check with a `Path` param. Set `Extract`
   to keep one line of a chatty command.
2. Run `make check`. The invariants test names the rule you broke; fix the entry, not
   the rule.
3. If the check is elevated, `internal/sudoers` needs the binary's absolute path in its
   per-platform table, and `scheck sudoers` must still pass `visudo -cf` (integration).
4. Record it into the fixtures with `make fixtures` (Linux) and review the diff; for
   macOS, run with `--record-fixtures DIR` locally and scrub hostname, user and
   serial numbers before committing.
5. Keep the baseline tier at or under the cap (40 on-demand entries at `baseline`).

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
- Report `schema_version` is `MAJOR.MINOR`; an additive field bumps MINOR and
  `docs/report-schema.json`; a rename or removal bumps MAJOR.
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

## Out of scope until the roadmap says otherwise

`llm`, agent loop, finding catalog, severity, `--context`, `--only`, SARIF,
`scheck diff`, `--local-only`, the optional §5.9 assessment track. Do not scaffold
empty abstractions for them.
