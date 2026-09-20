# scheck — minimal specification

`scheck` is a CLI that performs an **agentic security posture check** of a single
macOS or Linux host, either locally or over SSH. It is **read-only**: it observes,
reasons, and reports. It never modifies the target.

Status: v0.5 — M0, M1, M1.6, M1.7 and M1.8 implemented (2026-09-20), M2+ design · Language: Go · Inference: provider-agnostic (default
`openai-compatible`, `--model` required; Anthropic and guaranteed local-only inference deferred past v1)

**Changes from v0.1** (from design review):

- Probes and the allowlist are merged into one **check catalog** (§3). The model calls
  checks by id with typed parameters; it never composes argv. Regex-over-argv validation
  is gone.
- One `policy` package owns every decision about what may reach the model: path
  sensitivity, redaction, budgets (§4). `run_check` and `read_file` both consult it, so
  neither can bypass the other.
- The SSH path is documented as a different trust boundary from local, with a canary
  check that verifies remote quoting before any other command runs (§4.3).
- Severity ownership is decided: the model classifies, code assigns severity and applies
  context adjustments deterministically (§7.2). Structured context goes to code, prose
  context goes to the model (§6.3).
- Finding ids come from a compiled catalog; accepted risks are validated against it at
  config load (§7.1).
- Provider adapters absorb capability differences; the agent loop sees one contract (§5.3).
- Redaction is marked explicitly, like truncation (§4.2).
- All budgets live in one struct with one enforcement point (§4.4).
- Context sources are one repeatable flag; early-exit modes are one flag (§8).
- Acceptance criterion 10 requires phase 2 to demonstrably earn its cost (§12).
- All v0.1 open questions are decided (§13): reports carry a host identity block, fact
  sheets are persisted from M1, local providers report tokens and time but no cost, and
  the catalog is tiered by profile.
- Elevation is `sudo -n` only, configured as `elevate:` with a `scheck sudoers`
  generator for least-privilege grants (§8.1).

**Changes from v0.2** (from building M0 and M1; see `ROADMAP-0.0.1.md`):

- `check.Check` gained `Description`, `ExitOK`, `PathUse`, `Canary` and `Extract` (§3).
  The first two are needed by the model menu and by checks whose exit code is the
  answer; the last three are part of the security boundary and are enforced by the
  invariants test.
- The canary string and the `remote_shell` mechanism are pinned down (§4.3): the string
  carries a doubled backslash so fish is detected, and is printed by `/usr/bin/printf`
  so rbash is detected.
- Redaction runs before truncation over a slightly larger capture window (§4.2), so a
  secret straddling the cap is replaced rather than leaked as a prefix.
- The runner substitutes `fs.stat` for a content read of a sensitive path (§4.1) and
  runs a `which` pre-check before an elevated command (§8.1).
- Phase 1 alone has exit codes `0|2|3` and reports `mode: "facts"` (§7.4, §8).
- `scheck sudoers` uses `grep -rH .` rather than an empty-string pattern, because sudoers
  cannot express an empty argument (§8.1).
- A hidden `--record-fixtures DIR` flag and a fixture manifest format exist for tests (§11).
- All packages live under `internal/`; the security boundary is not importable.

**Changes from v0.3** (from using the M1 build on a real host, 2026-09-20):

- Phase 1 emits deterministic findings from **posture rules** (§2.1, §7.5): one
  unambiguous fact → one finding, code-graded like everything else. The model classifies
  only what needs judgement (§7.2). `finding.Def` carries title, impact and remediation
  text so a rule finding is complete without a model (§7.1); findings carry `source`
  (§7.3).
- `check.Check` gained typed parser shapes and a `Unit` noun for `lines` checks (§3), so
  a summary reads "26 listening sockets", never "26 lines". The envelope gains
  `facts.<id>.summary`, `findings[].source` and typed `parsed` shapes at
  `schema_version` 1.1 (§7.4).
- The text report has a contract (§7.6), pinned by golden tests (§11). `scheck explain`
  exists, and `-v` / `-vv` govern how much of the report is shown (§8).
- `--stop-after facts` exits `1` when a rule finding is open at the profile threshold
  (§8); acceptance criterion 4 now requires the offline run to say so (§12).
- Roadmap: M1.6–M1.8 land these before M2; the severity-adjustment slice shrinks to
  context adjustments and accepted risks (M2.3 after the v0.5 renumbering, §10).

- Posture assessments distinguish matched, not matched, not applicable and not
  assessed; rules require recognized evidence and preserve uncertainty (§7.5).
- Before the first GitHub release, breaking changes are permitted without migration
  machinery; the release establishes the compatibility baseline (§7.4).
- Profile exit thresholds are explicit (§8), and the agent evaluation compares rules,
  single-pass analysis and follow-up investigation (§12).

**Changes from v0.4** (from implementing M1.6, 2026-09-20):

- The fact sheet is a flat table with a repeated `DOMAIN` column rather than domain
  sub-headings, so the report sorts, greps and pipes as a table (§7.6).
- The text report escapes control characters in every target-derived string before
  printing it (§7.6). A check's stdout must not be able to drive the operator's
  terminal; this is a security property of the renderer, not cosmetics.
- Wrapping never splits a `[REDACTED:…]` or `[TRUNCATED:…]` marker, and a hanging block
  counts its own prefix against the width (§7.6).
- The terminal decisions (width, tty, `NO_COLOR`) belong to the CLI; `internal/report`
  takes them as options and reads no descriptor and no environment (§7.6). Until
  severities exist the report styles structure only, never colour.
- `-vv` renders the runner's redacted capture, carried in process. Default JSON and
  persistence omit it; the review follow-up adds opt-in JSON evidence (§7.4, §7.6).
- `scheck explain CHECK-ID` ships, with one section per platform-specific definition
  (§8). Its posture-rule list waits for the rules themselves (M1.8).

**M1.6 review follow-up (2026-09-20):**

- Header fields are escaped and folded to one logical line; failed attempted checks
  expose only policy-filtered diagnostics. Extraction failures keep full stdout hidden.
- Machine consumers can request JSON discovery (`catalog`, `explain`, plans), explicit
  `run.assessment`, diagnostic reason codes and optional redacted evidence (§7.4, §8).
- Timeout guidance distinguishes per-check limits from the whole-run deadline.
- Agent CLI guidance is maintained as the repository-local `scheck` skill, replacing
  the standalone usage document.
- Documentation distinguishes the implemented M1.6 envelope from M1.7–M1.8 plans,
  and records the current SSH planning bootstrap (§8).

**Changes from v0.5** (2026-09-20):

- `openai-compatible` is the default provider and the reference implementation, and is
  the first adapter built (M2.6); `anthropic` moves to M3.1 (§5.2, §10). The `llm`
  interface in §5.1 does not change: it keeps `Block.Cacheable` and `Effort` because it
  is designed from the richest provider, not the first one implemented.
- M2 is re-sliced into seven (`ROADMAP-0.0.1.md`): context ingestion (§6.1, §6.2) moves ahead
  of the severity-adjustment slice, because structured context is the grader's input
  (§6.3) and was previously scheduled after its consumer. `scheck providers` and the
  frozen phase-2 evaluation criteria gain an owning slice.
- The fact-sheet chunking threshold moves from a constant in `agent` to
  `Budgets.ChunkAtFraction` (§4.4, §5.3), so every number that shapes a run lives in one
  struct.
- `single-pass` is defined as the agent loop with `MaxIterations: 1` (§5.6), not a
  separate analysis path.
- `scheck explain` accepts a finding id and prints the severity chain (§8), replacing the
  separate grading devtool the roadmap had sketched.

**v1 scope revision (2026-09-20):**

- M3.1–M3.4 move after v1: additional providers, tool-call emulation, guaranteed
  local-only inference and domain chunking do not gate release. M4 follows M2.
- M2 owns request-size guards before every model call, preserving evidence and
  reporting an incomplete assessment on overflow (§5.3). No chunking is built in v1.

**Changes from implementing M2.2a (2026-09-20):**

- §9 now states the precedence the implementation always had — defaults, OS user
  config, project `scheck.yaml`, explicitly set flags — and the real user-config
  locations; the previous wording listed the files in the wrong order. `scheck config
  show` and `scheck config validate` join §8, backed by a resolver with provenance
  (`config.Resolve`) that runs and inspection share. `docs/CONFIGURATION.md` is the
  walkthrough.

**Changes from implementing M2.2 (2026-09-20):**

- A `target:` context source is prose only (§6.1): the structured block can accept
  risks and set exposure, and the machine being audited must not be able to do either
  for itself. The full source order and the budget's cut rule are written down, and
  `--stop-after context` prints the block the model reads. The envelope's
  `run.context_sources` entries gained `kind`, `bytes` and `unresolved` (§7.4, schema
  1.2). Operator context lives in `internal/operator`; `config.Validate` loads the
  `context:` block so an unknown accepted-risk id fails before anything runs.

**Changes from implementing M2.1 (2026-09-20):**

- `llm.Provider` gained `Native()` (§5.1): the roadmap delivers `Native` alongside
  `Limits`, and `scheck providers` has to print it without a request. `Stream` is
  specified as text deltas, complete tool-call events and one `Done` event; provider
  failures are classified (`llm.Error`) so the loop ends a run without knowing the
  provider. `llm.Register`/`llm.Build` and `internal/llm/all` are the selection
  mechanism, and `make depcheck` enforces the no-provider-dependency rule.
- Token accounting is a documented conservative bound in `llm` (§5.3) rather than a
  per-model tokenizer; `max_context:` / `--max-context` declare the window when the
  adapter cannot know it.
- `docs/eval/phase2-criteria.md` freezes the M2.7 pass criteria (§11, §12).

**Changes from implementing M1.7 and M1.8 (2026-09-20):**

- `check.Parse` takes the whole `Check`, not just its `ParserKind` (§3). A typed shape
  is produced from several tools' output formats (`ss` and `lsof` both answer
  `listeners`; four package managers answer `updates`), and the catalog's own argv is
  what says which format to expect. Sniffing the target's output to pick a parser was
  the alternative and is worse: the format choice must not depend on target-controlled
  bytes.
- A typed parser produces `check.Records` — `{kind, items, partial, note}` — not a bare
  slice (§3, §7.4). Completeness travels with the records because §7.5 needs it: a rule
  may prove an existential condition from partial output but never an absence. In JSON a
  typed fact's `parsed` is that object, so a record is `parsed.items[0]`.
- A new typed shape, `file_mode`, reads a `stat` line into `{symbolic, mode, user,
  group, size}`. The §7.5 shadow rule is specified over a *parsed* mode, and a regexp
  over a raw line cannot express "recognized and outside a set" without lookahead.
- `Unit` is required on `kv` checks as well as `lines` checks (§3): "13 settings" is a
  reading, "13 keys" is a shape. The invariants test enforces it and rejects a `Unit` on
  a typed shape, which names its own records.
- A posture rule's predicate answers with three states, not a boolean (§7.5):
  `matched`, `not_matched` and `not_assessed`. Predicates therefore carry what makes
  evidence *recognizable* — `RawMatch.Requires`, `KeyEquals.Known`, `FieldEquals.Known`,
  `FieldOutside.Recognize` — so an answer scheck does not understand can never be read
  as a pass. This is the mechanism behind "evaluate recognized evidence, not failure to
  recognize a good state".
- The `pkg.*` row of the §7.5 seed table is four rules, one per concrete catalog id.
  Several rules may share a finding id; the evaluator emits that finding once and
  appends each rule's evidence.
- `finding.Def` does not carry `References` yet (§7.1): the field selects citations by
  `context.compliance`, which arrives with operator context in M2.2. Findings emit no
  `references` key until then rather than inventing citations.
- `run.assessment` is `rules` under `--stop-after facts` from M1.8 (§7.4), and the
  envelope gains the `assessments` array. `run.assessment` stays a field of its own:
  an empty `findings` array is never the same claim as "nothing was assessed".
- The text report's header line leads with the result, the severity colours arrive, and
  a fact whose rule fired carries `[finding: <severity>]` rather than a pass mark
  (§7.6). Coverage is rendered in two places: the not-assessed rules close the findings
  section by default, and `-v` prints the whole coverage table.
- Real-model quality and adversarial evaluations gate v1 (§11, §12); mock transcripts
  prove enforcement and control flow only.

---

## 1. Goals / Non-goals

**Goals**

- One binary, zero dependencies on the target machine beyond a POSIX shell and SSH.
- Same UX for `scheck local` and `scheck ssh user@host`. (Same UX, not the same trust
  boundary — see §4.3.)
- Findings that a human can act on: severity, evidence, remediation — no raw dumps.
- Agentic reasoning: the model correlates facts across subsystems (e.g. "password
  auth is enabled on sshd **and** an account has an empty password **and** the host
  is listening on 0.0.0.0:22") rather than firing independent boolean rules.
- Deterministic, auditable command surface. Every command executed on the target comes
  from a compiled catalog, is logged, and is reproducible.
- **Operator context as a first-class input.** The operator can hand `scheck` their
  architecture notes, expected services, exposure and accepted risks so findings are
  specific to the host's actual role rather than to a generic checklist (§6).
- **Replaceable inference.** v1 supports native tool calling through the
  `openai-compatible` adapter behind a provider-neutral interface. Additional adapters,
  emulation and a guaranteed zero-egress AI mode are post-v1 (§5). Offline posture
  rules remain available without a model.
- **Stable severities.** The same host with the same context yields the same severity
  for the same finding id, regardless of provider or run (§7.2).

**Non-goals (v1)**

- No remediation, no config writes, no package installs.
- No network/perimeter scanning of *other* hosts (no nmap-style behaviour).
- No CVE database or vulnerability-scanner replacement. `scheck` reports "23 security
  updates pending", not per-CVE analysis.
- No fleet orchestration, no server, no agent daemon. One host per invocation.
- No Windows.
- No fine-tuning, no bundled model weights, no embedded vector store.
- No additional production adapters, tool-call emulation, guaranteed local-only AI
  mode or small-context chunking; these belong to post-v1 M3.
- No free-form command composition by the model. If a check is not in the catalog, the
  model cannot run it; adding a check is a code change with a test.

---

## 2. Architecture

```
  cmd/scheck (CLI, cobra)
        │
        ├── target.Target                interface { Exec(ctx, argv) (stdout, stderr, code) ; Platform() }
        │     ├── target/local           os/exec, argv only, no shell
        │     └── target/ssh             golang.org/x/crypto/ssh, one session per Exec, canary-verified quoting
        │
        ├── check.Catalog                the ONLY command surface: named, typed, read-only checks (§3)
        │     └── check/{macos,linux}    per-platform check definitions + baseline sets
        │
        ├── policy                       one owner for: path sensitivity, redaction, budgets (§4)
        │
        ├── llm.Provider                 one narrow contract; adapters absorb provider differences (§5)
        │     └── llm/{openai,mock}   (anthropic/ollama: post-v1)
        │
        ├── agent.Session                the tool-calling loop (owned by scheck)
        │     └── tools: run_check, read_file, report_finding
        │
        ├── finding                      id catalog, severity assignment, context adjustment, dedupe (§7)
        │
        └── report/{text,json,sarif}     renderers
```

### 2.1 Two-phase execution — the core design decision

**Phase 1 — deterministic baseline (no model involved).** The per-platform *baseline
set* of catalog checks runs and produces a structured *fact sheet*. This is cheap,
reproducible, cacheable, and diffable between runs.

**Phase 2 — agentic reasoning.** The fact sheet is handed to the model in one cached
prompt. The model reasons over it, requests *additional* catalog checks via
`run_check` / `read_file` to confirm or rule out hypotheses, and emits findings via
`report_finding`.

Both phases execute through the same catalog, the same policy, and the same audit log.
Phase 1 is simply "the baseline subset, run unconditionally". There is no second command
surface.

**Phase 1 also judges what needs no judgement.** A small table of *posture rules*
(§7.5) runs over the fact sheet and emits findings for facts whose meaning is
unambiguous: FileVault off, SIP disabled, `PasswordAuthentication yes`, an account with
an empty password. Rules never execute anything; they read facts the checks already
produced. Their findings are the floor: phase 2 can add to them and enrich them, never
remove or soften them. The phase 1 report is written for a person (§7.6), so
`--stop-after facts` is a complete tool, not a debug dump.

Rationale: without phase 1 the model burns tokens rediscovering the same baseline on
every run and the results are nondeterministic. Without phase 2 this is a static
checklist tool — which is a fine thing to be, so phase 2 must prove it adds signal
(acceptance criterion 10). The split keeps cost and variance in phase 2 only.

---

## 3. Check catalog (the command surface)

A check is a named, read-only command template with typed parameters. The catalog is
compiled into the binary and is the *entire* set of things `scheck` can execute on a
target, in either phase.

```go
package check

type Check struct {
    ID          string          // "sshd.config", "fs.suid", "pkg.apt_upgradable"
    Description string          // one line, rendered into the model's menu
    Platform    Platform        // macos | linux | any
    Domain      Domain          // report grouping and --only filtering
    Argv        []string        // literal tokens; a token that is exactly "{name}" binds a Param
    Params      []Param         // typed; every placeholder must bind exactly one Param
    Parser      ParserKind      // raw | lines | kv | json | a typed shape (below)
    Baseline    bool            // runs in phase 1
    MinProfile  Profile         // baseline | hardened; the model only sees checks at or below the active profile
    Elevated    bool            // needs elevation (§8.1); otherwise "unavailable: requires elevated read"
    Budget      Budget          // per-check overrides, bounded by policy.Budgets (§4.4)
    ExitOK      []int           // exit codes that are a successful read; nil = {0}, AnyExit = every code
    PathUse     PathUse         // content | metadata: what a check with a Path param returns (§4.1)
    Canary      bool            // the one entry whose literal contains metacharacters (§4.3)
    Extract     string          // optional regexp with one group; only the group is kept as output
    Unit        string          // Parser == lines|kv: plural noun for one record ("SUID files"); the summary is "<n> <Unit>"
}

type Param struct {
    Name string
    Kind ParamKind             // Path | Enum | Int | Ident
    Enum []string              // Kind == Enum
    Min, Max int               // Kind == Int
    // Kind == Path is validated by policy.PathPolicy (§4.1) and must match a strict
    // charset ([A-Za-z0-9._/-]); Kind == Ident matches [A-Za-z0-9._-].
}
```

`ExitOK` exists because a non-zero exit is often the answer, not a failure:
`dnf check-update` returns 100 when updates exist, `systemctl is-enabled` returns 1 for
disabled. `Extract` exists for chatty commands (`ioreg`) whose one useful line should
be all the model sees. `PathUse` lets the runner substitute `fs.stat` for a content
read of a sensitive path (§4.1). `Canary` exempts exactly one entry from the
metacharacter invariant (§4.3).

**Typed parsers.** `Parser` is `raw`, `lines`, `kv` or `json`, or one of the typed
shapes: `listeners` (protocol, state, address, port, pid, process), `accounts` (name,
uid, shell, home), `passwd_status` (name, status), `units` (name, state), `updates`
(name, version), `launchd` (label, pid, status), `file_mode` (symbolic, mode, user,
group, size). A typed shape exists when something downstream needs fields: the summary
line (§7.6), a posture rule (§7.5) or `scheck diff` (§7.4). Everything else stays
`lines` or `kv`, and `Unit` names what one record is, so the summary reads "0 SUID
files" and "13 settings" rather than "0 lines" and "13 keys"; the catalog test requires
`Unit` on every `lines` and `kv` check, and rejects one on a typed shape. A per-check
summariser function was considered and rejected: a typed record serves three consumers
and is diffable, a closure serves one and is not.

A typed parser produces `check.Records`: `{kind, items, partial, note}`, where each item
is a record of named fields. `partial` is set when the capture carried a redaction or
truncation marker, or a line the format's parser did not recognise. Completeness travels
with the records because §7.5 needs it — a rule may prove an existential condition from
partial output, never an absence — and because a count from incomplete output must be
labelled partial rather than presented as a total. `check.Parse` takes the whole
`Check`, because one shape is produced from several tools (`ss` and `lsof` both answer
`listeners`) and the catalog's argv, not the target's bytes, decides which format to
expect.

**Invariants, enforced by a test over the whole catalog** (`internal/check/invariants.go`,
run over every registered check by `internal/check/all`; each rule has a name that
appears in the failure):

- Every `Argv` token is either a literal or a single `{name}` placeholder. No token is
  built by concatenation. No literal token contains shell metacharacters. Exactly one
  entry carries `Canary: true` and is exempt from the metacharacter rule.
- No check names a binary that writes, and no literal flag mutates (`find` never has
  `-exec`/`-delete`; `systemctl` only `is-*`/`list-*`/`show`; package managers only
  query subcommands). Because flags are literals, this is checked once at catalog
  authoring time, not per call.
- Every `Path` parameter passes through `policy.PathPolicy` before binding, so a check
  like `text.head {path}` is subject to the same deny list as `read_file`. There is no
  path that `run_check` can read and `read_file` cannot, or vice versa.
- A failed or unavailable check records `unavailable: <reason>` — never fatal — and the
  model is told which checks were unavailable so it never reasons from absence.

**Baseline set** (`Baseline: true`):

| Domain | macOS | Linux |
|---|---|---|
| OS / kernel | `sw_vers`, `uname -a` | `/etc/os-release`, `uname -a` |
| Pending updates | `softwareupdate -l --no-scan` | `apt list --upgradable` / `dnf check-update` / `zypper lp` |
| Disk encryption | `fdesetup status` | `lsblk -o NAME,TYPE,FSTYPE`, `/etc/crypttab` |
| Integrity / MAC | `csrutil status`, `spctl --status` | `sestatus`, `aa-status` |
| Firewall | `socketfilterfw --getglobalstate` (+`--getblockall`) | `ufw status`, `firewall-cmd --state`, `nft list ruleset` |
| Listening sockets | `lsof -nP -iTCP -sTCP:LISTEN` | `ss -tulpnH` |
| sshd config | `sshd -T` | `sshd -T` |
| Accounts | `dscl . -list /Users UniqueID`, admin group | `/etc/passwd`; `/etc/shadow` via metadata-only policy (§4.1); `passwd -S -a` (elevated) |
| Privilege escalation | `/etc/sudoers`, `grep -rH . /etc/sudoers.d` (elevated) | same |
| Remote access | `systemsetup -getremotelogin`, `launchctl print-disabled system` | `systemctl is-enabled ssh sshd` |
| Persistence units | `launchctl list`, `/Library/Launch*` | `systemctl list-unit-files --state=enabled`, timers, cron dirs |
| SUID / world-writable | `find` on `/usr/local`, `/opt`, PATH dirs (depth-capped) | same |
| Logging / audit | `log config --status` | `systemctl is-active auditd`, `journalctl --disk-usage` |
| Time sync | `systemsetup -getusingnetworktime` | `timedatectl` |
| Host identity | `ioreg -rd1 -c IOPlatformExpertDevice` (`Extract` IOPlatformUUID) | `/etc/machine-id` |
| Session | `uname -s`, `id -u`, `printenv SHELL`, canary (§4.3) | same |

The exact argv of every entry is the catalog itself (`internal/check/{common,linux,macos}`),
printed by `scheck catalog`. The table is the intent; the code is the contract.

**On-demand checks** (`Baseline: false`, callable by the model) are parameterised
variants: `fs.stat {path}`, `fs.list {path}`, `text.head {path} {lines}`,
`svc.show {unit}`, `proc.cmdline {pid}`, `net.who_listens {port}`, and so on.

**Tiers.** Every check carries `MinProfile`. Under `--profile baseline` the model's
menu is the baseline-tier checks only, which keeps the tool description short and cheap
runs cheap. Under `--profile hardened` the full catalog is exposed. The baseline tier
is capped at ~40 on-demand entries by a test; the hardened tier is uncapped. A check
that is requested on most baseline runs is a candidate for `Baseline: true` (phase 1)
rather than for the tier cap being raised.

**Why a catalog and not an allowlist over argv.** An allowlist that validates
model-composed argv with regexes is the hard part of the security boundary and the part
most likely to be wrong. A closed set of templates with typed holes makes "denied
command" a rare error instead of a boundary, removes regex validation entirely, and is
what keeps weaker and local models usable: picking from a menu is easier than composing
a command. The cost is that the model cannot invent a novel command. The old allowlist
forbade nearly all novelty anyway.

---

## 4. Policy: the single owner of "what may reach the model"

`policy` is the one package that decides what data leaves the target and reaches the
model. Nothing else makes that decision. `check`, `agent` and the tools call into it;
they never re-implement any part of it.

### 4.1 Path policy

Applies to every `Path`-typed parameter in every check and to `read_file` identically.

- **Allowed prefixes:** `/etc`, `/Library/Launch*`, `/usr/local/etc`, `/opt/*/etc`,
  `/var/log` (metadata only), … Anything else is denied.
- **Sensitive paths** return *metadata* (mode, owner, size, derived booleans) instead of
  contents: `/etc/shadow`, `/etc/gshadow`, `**/id_*`, `**/*.key`, `**/*.pem` (private),
  `~/.aws/**`, `~/.ssh/**`, `/etc/ssh/ssh_host_*_key`.
- Symlinks are resolved on the target before the decision (`realpath` is a catalog
  check); the decision is made on the resolved path, and traversal (`..`) is rejected
  at the charset level before that.

The deny list is compiled in. Config may add to it (`deny_paths:`), never remove.

**Metadata-only mechanics.** `PathPolicy.Decide(resolved)` returns `allow`,
`deny(rule)` or `metadata-only(rule)`. The runner resolves a `Path` param with
`fs.realpath` on the target before deciding, so a symlink from an allowed prefix into a
sensitive file is judged by where it points. Under `metadata-only`, a check declared
`PathUse: content` is rewritten to the platform's `fs.stat` check and the result is
tagged `reason: metadata-only:<rule>`; the audit line records the substituted argv.
This is how the baseline learns `/etc/shadow`'s mode and owner without ever reading it.

### 4.2 Redaction

Every byte of check output passes the redactor before the model, the report, the audit
log, or any transcript sees it. Rules: private-key blocks, `AKIA…`-style keys, bearer
tokens, `password=`/`secret=`/`token=` values, and a config-extensible regex list
(`redact_extra:`).

**Redactions are marked, not silent.** A redacted span is replaced by
`[REDACTED:<rule>:<n bytes>]` so the model knows something was there. This is the same
contract as truncation (`[TRUNCATED:<n bytes>]`): the model must never reason from
absence, and a silent redaction would create exactly that.

The v0.1 "base64 blobs over N bytes" rule is dropped: it removes certificates and plist
payloads the model legitimately needs. Base64 is redacted only inside a matched key or
token context.

**Redact, then truncate.** The runner captures up to `PerCheckOutput` plus a 4 KiB
slack window, runs the redactor over the captured bytes in a single pass over the
original input (so a marker is never re-matched by a later rule), then cuts at
`PerCheckOutput` with `[TRUNCATED:<n bytes>]`. A cut never lands inside a marker. A
secret straddling the cap is therefore replaced before the cut instead of leaking a
prefix. Nothing downstream (report, audit log, persisted run, `-vv`) sees
pre-redaction bytes; the audit log stores a hash of the redacted output.

### 4.3 The SSH trust boundary

On the local target, `Exec(argv)` is `os/exec` with no shell. On SSH, the protocol hands
a *string* to the remote user's login shell, which may be bash, zsh, fish, or a
restricted shell. The argv contract cannot be honoured by construction there; it is
honoured by a quoting function plus verification:

- Argv is quoted for POSIX `sh` by one audited function. Because catalog tokens are
  literals or strictly-charset parameters, the quoter's input domain is small and
  fully enumerable in tests.
- **Canary first.** The first command on any SSH session is the `sys.canary` catalog
  check, `/usr/bin/printf %s <string>`, whose output must round-trip a fixed string
  containing quotes, spaces, `$`, backticks, `;`, `|`, globs and a doubled backslash.
  If the echo does not match byte-for-byte, the session aborts with exit code 3 before
  any other command runs, and the attempt is audited as `denied:canary`. Two details
  are load-bearing and were found in the shell matrix test: fish collapses `\\`
  inside single quotes, which is what makes it fail (fish otherwise round-trips our
  quoting); rbash refuses a command name containing `/`, which is why the binary is
  path-qualified. Every command is prefixed `LC_ALL=C` so parsers see one locale.
- The quoter wraps every token in single quotes, spelling an embedded quote as `'\''`.
  Its test runs every literal in the catalog, samples of the `Path` and `Ident`
  charsets, and the canary string through a local `sh -c`.
- The report header records `transport: local|ssh` and, for SSH, the remote login shell
  (from the `sys.shell` check, `printenv SHELL`, so no `$` expansion is needed) and the
  canary result. Host keys are verified strictly against `~/.ssh/known_hosts`; an
  unknown host exits 3 with an `ssh-keyscan` hint. There is no bypass flag.
  Authentication is an `--identity` file or the `SSH_AUTH_SOCK` agent; password
  authentication is not offered.

This is stated plainly rather than hidden: local and SSH have the same UX and the same
catalog, but the SSH boundary rests on quoting plus a runtime check, not on the absence
of a shell.

### 4.4 Budgets — one struct, one enforcement point

```go
type Budgets struct {
    PerCheckSoft     time.Duration // 5s   — logged as slow
    PerCheckHard     time.Duration // 30s  — killed, recorded as unavailable
    PerCheckOutput   int           // 64 KiB, then [TRUNCATED]
    AgentChecks      int           // 60 model-initiated checks per run
    AgentWallClock   time.Duration // 120s aggregate for model-initiated checks
    ModelInputTotal  int           // 256 KiB of check output across the whole run
    MaxIterations    int           // 24 model turns
    MaxTokens        int           // 32000 per completion
    ContextBytes     int           // 32 KiB merged operator context
    RunTimeout       time.Duration // 5m, --timeout
}
```

`policy.Budgets` is the only place these numbers exist. `RunTimeout` bounds everything
else; the agent loop and the check runner receive the struct and enforce their own
fields. Exhausting any budget ends the run as `status: incomplete`, never as a clean
bill of health.

### 4.5 Audit log

Every attempted check is written to `--audit-log` as JSONL with check id, bound
parameters, resolved argv, decision (`run | denied:<rule> | unavailable:<reason>`),
exit code, duration, and output hash. A denied call returns an error `tool_result` to
the model naming the rule — never a silent drop. Phase 1 writes the same lines; the
canary appears as `run` or `denied:canary`, and a metadata-only substitution records
the `fs.stat` argv that actually ran.

---

## 5. Inference layer (provider-agnostic)

Inference is a replaceable component. v1 supports `openai-compatible` endpoints with
native tool calling, plus `mock` for tests. Supporting a second production adapter,
emulation and guaranteed local-only AI is deferred to M3 after v1. A compatible local
endpoint may work, but selecting a loopback URL does not establish a zero-egress
guarantee. Operators requiring offline operation can use phase 1 without a model.

Consequence of that requirement: **`scheck` owns the agent loop.** No provider SDK's
tool-runner helper drives the conversation. The loop is ~150 lines in `agent`, has one
code path, and every provider implements one narrow interface.

### 5.1 The `llm` interface

```go
package llm

type Tool struct {
    Name, Description string
    Schema            json.RawMessage // JSON Schema, draft 2020-12 subset
}

type ToolCall   struct { ID, Name string; Input json.RawMessage }
type ToolResult struct { CallID, Content string; IsError bool }

type Message struct {
    Role        Role // system | user | assistant
    Text        string
    ToolCalls   []ToolCall   // assistant turns
    ToolResults []ToolResult // user turns
}

type Request struct {
    Model     string
    System    []Block // ordered; Block.Cacheable marks a cache breakpoint (hint, may be ignored)
    Messages  []Message
    Tools     []Tool
    MaxTokens int
    Effort    Effort // low | medium | high | max — mapped per provider; subsumes "reasoning on/off"
}

type Response struct {
    Text       string
    ToolCalls  []ToolCall
    StopReason StopReason // end_turn | tool_use | max_tokens | refusal | error
    Usage      Usage      // input, output, cache_read, cache_write tokens; CostUSD *float64, nil when the provider has no price
}

type Provider interface {
    Name() string
    Limits() Limits
    Native() Native
    Stream(ctx context.Context, r Request) (Stream, error)
}

// A Stream yields Text deltas and complete ToolCall events, then exactly one Done
// event carrying the assembled Response. Complete is a package-level helper that
// drains a Stream; Drain does the same while handing each event to an observer so the
// CLI can show progress. Providers implement neither.
func Complete(ctx context.Context, p Provider, r Request) (Response, error)

// A provider failure is classified so the loop can end a run honestly without knowing
// which provider it talked to: context_overflow | unsupported | auth | transport | response.
type Error struct { Kind ErrorKind; Msg string }

type Limits struct {
    MaxContext int  // the one capability the loop must know about (§5.3)
    Local      bool // no network egress from this machine (§5.4)
}

// Native describes what the adapter maps to real provider features vs. emulates.
// It is informational: it goes in the report header, never into agent control flow.
type Native struct {
    ToolCalling, ParallelToolCalls, PromptCaching, Reasoning bool
}
```

Hard rules: **no provider SDK type crosses the `llm` package boundary**, and **the agent
loop branches on nothing but `Limits.MaxContext`.** `agent`, `policy`, `check`,
`finding` and `report` compile without any provider dependency, which is also what
makes them testable without a network; `make depcheck` (part of `make check`) walks
`go list -deps` for those packages and fails on any adapter or SDK edge.

Providers register with `llm.Register(Info, Factory)`; `internal/llm/all` links every
adapter and registers the deferred names so a deferred selection exits 3 "not available
in this build" rather than "unknown provider". A `Factory` takes `llm.Config` (model,
base URL, declared `max_context`, effort, and the mock's transcript path) and never
performs network I/O or reads a credential's value at construction; credentials are
looked up from the environment by the adapter when it first sends a request.

Token accounting lives in `llm` (§5.3): `Estimate(Request)` is a documented
conservative bound (3 bytes per token plus fixed per-message, per-tool-call and
per-tool-definition framing and a request allowance), and `CheckFit(Request, Limits)`
adds the output reservation and answers whether the request may be sent. An unknown
`Limits.MaxContext` is an `unsupported` error, never unlimited space.

### 5.2 Providers

| Provider | Covers | Notes |
|---|---|---|
| `openai-compatible` | OpenAI, vLLM, llama.cpp server, Groq, Together, LM Studio, OpenRouter | **Default and reference implementation.** One adapter, `--base-url` + `--model`. No default model — the endpoint decides what exists, so `--model` is required; `--base-url` defaults to `https://api.openai.com/v1`. Capabilities declared from config, not assumed; native tool calling required in v1 (§5.3). |
| `anthropic` (post-v1 M3.1) | Claude API, Bedrock, Vertex, Foundry | Default model `claude-opus-5`; adaptive thinking, `output_config.effort`, prompt caching all map natively — the provider that proves the interface can express more than the reference implementation needs. |
| `ollama` (post-v1 M3.2) | local models | `Local: true`. The zero-egress path. Tool calling emulated when the model lacks it. |
| `mock` | tests | Replays recorded transcripts (`--transcript FILE`); used by every non-live test. A transcript declares `limits` and `native` and one turn per model call; a turn may `fail` with a classified error kind or carry `expect` assertions over the request it answers, so a test can assert what the loop sent without reaching into the provider. |

Selection: `--provider`/`--model`, or `provider:` in config; v1 defaults to
`openai-compatible`. Deferred providers fail explicitly with exit 3, "not available
in this build". After M3, credential inference may select an available provider,
with `openai-compatible` winning ties. `scheck providers` lists
what is configured and each one's `Limits` and `Native` set.

### 5.3 Adapters absorb capability differences

v0.1 exposed six capability booleans and had the loop degrade per combination. That put
2^n paths in the one component that must be simplest, and made the conformance suite
conditional. Instead, **every adapter presents the full contract**. In v1, unsupported
native tool calling is rejected before inference with exit 3; emulation is not silently
enabled. Cache hints may be ignored and effort mapped only where supported, with
`Native` recording what is exercised. The following emulation design is deferred to
M3.2; it must not be scaffolded in v1:

- **No native tool calling** → the adapter renders tools into the system prompt as a
  JSON call protocol, parses the model's reply into `ToolCalls`, and returns tool results
  as user text. The loop never knows.
- **No parallel tool calls** → the adapter issues them one at a time and assembles a
  single `Response`. The loop sees one turn.
- **No prompt caching** → cache breakpoints are ignored. Nothing else changes; the
  fact sheet is in the system prefix regardless.
- **No native reasoning** → the adapter prepends a "think step by step before calling
  tools or reporting" instruction when `Effort >= high`.

**Context limits (required in M2).** Before every model call, check the entire
serialized request against `Limits.MaxContext`, reserving the requested maximum output
allowance. Count system instructions, tool schemas and catalog descriptions, facts,
operator context, all conversation messages and tool results, plus provider framing.
Token accounting belongs in `llm`, using a model-appropriate tokenizer or a documented
conservative bound; provider-specific serialization must not leak into the agent loop.
`Limits.MaxContext` must be known from validated model configuration or reliable
provider metadata; an unknown limit is a configuration error (exit 3), never an
assumption of unlimited space. `ModelInputTotal` is a separate byte budget, not a
substitute for this token check.

If the request cannot fit, do not send it. Preserve collected facts and validated
findings, mark `run.status: incomplete`, retain assessment coverage, explain that the
AI assessment could not finish because of the context limit, and exit 2. This applies
both to an oversized initial request and to history growth after tool calls. A provider
context-overflow rejection receives the same incomplete treatment; never retry it by
silently dropping evidence. Existing policy redaction and marked truncation still
apply, but no additional evidence truncation, history eviction or summarization is
introduced merely to fit the context window in v1.

**Small-context support (post-v1 M3.4).** Domain chunking and a final correlation pass
are deferred. Introduce `Budgets.ChunkAtFraction` (initially 0.5) only with that slice;
it triggers when the system prefix exceeds that fraction of `Limits.MaxContext`.
Every chunk and correlation request must still pass the full request-size guard.
Evaluate cross-domain cases where neither domain alone yields a finding: correlating
findings alone may discard the facts needed to discover the relationship. Chunking
must demonstrate preserved signal before it becomes a supported execution mode.

`Native` has exactly two consumers, and the agent loop is neither of them: the report
header records it so a reader knows which features were emulated, and `finding` reads
`Native.ToolCalling` to cap a finding's `confidence` at `medium` when tool calling was
emulated, because parsed-from-text calls are more error-prone. The cap is applied in
`finding`, never by the model, and the loop must not branch on any field of `Native`.

### 5.4 Egress control (post-v1 M3.3)

In v1, `--local-only` and `allow_egress: false` fail explicitly with exit 3 before
any inference request; neither may be ignored or treated as an egress guarantee.
The following supported local-only mode is deferred:

`allow_egress: false` (config) or `--local-only` makes any non-`Local` provider a hard
error before a single byte leaves the machine. For a tool whose input is a host's
security configuration this is a requirement, not a nicety.

### 5.5 Reproducibility

Every report header records `provider`, `model`, `effort`, `native`, `limits`, and
normalized `usage`. `usage.cost_usd` is null for providers without a price (all
`Local` ones); tokens and wall-clock are always present so runs stay comparable. The
finding schema, severity scale, and exit codes are identical across providers; only
recall and precision differ. Because severity is assigned by code (§7.2), a given
finding id has the same severity under every provider.

### 5.6 Loop parameters

Taken from `policy.Budgets` (§4.4). Streaming is always used, so the CLI can show
progress. The loop ends when the model stops calling tools, or on any budget. A
truncated run is reported as `status: incomplete`, never as a clean bill of health.

`run.mode: single-pass` (§7.4) is this same loop with `MaxIterations: 1`, not a second
implementation. That is what makes the comparison in §12 criterion 10 a one-variable
experiment: same prompt, same tools, same facts, different iteration budget.

### 5.7 Tool surface (three tools, deliberately small)

| Tool | Input | Behaviour |
|---|---|---|
| `run_check` | `id: string`, `params: object`, `rationale: string` | Looks up the catalog entry, validates params by kind, applies path policy, executes, redacts, truncates. Unknown id or invalid param → error result listing the valid ids/kinds. `rationale` is logged, not sent back. |
| `read_file` | `path: string` | Sugar for `text.cat {path}` with the same path policy; returns contents or metadata-only for sensitive paths. Exists as a separate tool because models use it far more reliably than a parameterised check. It is a caller of `runner.Run` like any other: its audit record is byte-identical to the equivalent `text.cat` binding apart from the tool name, which is the test that keeps it from becoming a second enforcement path (§4). |
| `report_finding` | the finding schema below (§7) | Validated and stored. Invalid → error result with the validation message so the model can correct it. The model does **not** supply `severity`. |

The catalog's ids, parameters and one-line descriptions are rendered into the tool
description for `run_check`, so the model has a menu, not a language.

### 5.8 System prompt contract

Provider-neutral, no vendor-specific phrasing:

- Role: read-only auditor on a host the operator owns and has authorized.
- Ground every finding in observed evidence; cite the check id.
- Never assert absence of a problem from an `unavailable` check or a `[REDACTED]` /
  `[TRUNCATED]` span — report `confidence: low` and say what could not be checked.
- Prefer few high-signal findings over exhaustive noise; no finding without a concrete
  remediation.
- Classify, do not grade: choose the finding id and the evidence; severity is assigned
  by `scheck`.
- Do not attempt exploitation, credential extraction, or lateral movement.

---

### 5.9 Optional bounded assessment experiment (outside v1 requirements)

TypeSafe's Jev is a candidate for semantic judgments over collected evidence, such as
whether an observed service is explained by operator notes or a persistence entry
warrants investigation. It is an optional research track, not a prerequisite for M0–M4
or v1. Access is currently waitlisted; development, default CI and release gates must
not require a Jev account, credentials, network access to TypeSafe, or recorded Jev
responses. The existing generative-provider plan remains the production path.

If implemented for evaluation, keep assessment separate from `llm.Provider`: bounded
decisions do not implement its conversational streaming and tool-generation contract.
Start with an internal evaluation harness, not a public CLI mode or a general-purpose
provider framework. Its domain-level input is policy-filtered evidence plus operator
context; its output is candidate assessments tied to existing evidence identifiers.
The implementation owns question wording, batching and vendor response conversion.

Initial scope: classify service/context relationships as `expected`, `unexpected`, or
`insufficient_context`. Code retains explicit status and completeness metadata, resolves
evidence references, and performs exact parsing, counting and comparisons. Missing,
denied, redacted or truncated evidence must not imply a negative finding. Assessment
results neither assign severity nor authorize checks, change accepted risks, suppress
findings, skip investigation, or affect exit codes. They remain separate evaluation
artifacts until a measured result justifies a production integration decision.

Development proceeds with hand-authored synthetic responses and a local fake HTTP
server. These prove plumbing, validation and failure handling, not model quality or
prompt-injection resistance. An optional available generative/local model may answer
the same questions for comparison; its results are attributed to that model and are
never presented as Jev performance or calibration.

Any later live adapter must use the same policy and egress restrictions as other
inference: `--local-only` forbids hosted assessment and hosted fallback. Credentials
come from the environment, never fixtures or config. Validate response IDs, types,
allowed choices and probability ranges; bound requests, retries and deadlines. Failure
or uncertainty leaves the ordinary audit path intact. Keep provider probabilities
separate from report confidence; thresholds need held-out evaluation, not a direct
conversion from vendor confidence into `high|medium|low`.

Before production adoption, compare deterministic rules, an available generative model
and actual Jev on human-labeled fixtures. Record precision/recall, false negatives,
abstentions, investigation frequency, latency and cost, including adversarial and
incomplete evidence. Pin the tested model and question versions. Synthetic/replayed
answers cannot satisfy this quality gate. A failed or unavailable experiment does not
block v1; a successful one requires an explicit spec update for its production role.

Research references (reviewed 2026-09-20): [primitives](https://docs.typesafe.ai/primitives),
[HTTP API](https://docs.typesafe.ai/api), [models](https://docs.typesafe.ai/models),
[known limitations](https://docs.typesafe.ai/model-jaggedness/jev-1.13). Typed output
constrains answer shape; it does not guarantee truth or resistance to hostile inputs.

---

## 6. Operator-supplied context

A generic host audit produces generic findings. `0.0.0.0:5432` is low-signal noise on a
box behind a strict security group and critical on an internet-facing host. Operator
context is the single highest-leverage input to precision, so it is a first-class
feature rather than a flag.

### 6.1 Sources

All sources are given with one repeatable flag, `--context SOURCE`, where `SOURCE` is:

| Form | Meaning |
|---|---|
| `FILE` / `DIR` | Markdown or plain text; a directory is read recursively for `*.md`, `*.txt`, `*.yaml`. |
| `note:TEXT` | Inline prose. |
| `target:PATH` | A file on the *target* (default `/etc/scheck/context.md` when `target:` is given bare). Lets a host describe itself in a fleet. Read through the normal path policy. |

Plus two implicit sources: the `context:` block in `scheck.yaml` (§6.2), and
`./.scheck/context/**`. Nothing else is read implicitly: `SECURITY.md`,
`ARCHITECTURE.md`, ADRs and runbooks are useful input but must be named, so a run is
never silently influenced by a file the operator forgot about.

**Merge semantics are defined per kind, not by order:**

- **Structured** (`context:` blocks in yaml files, in any source) are merged as maps;
  a later source overrides an earlier one *per key*, and lists (`expected_services`,
  `accepted_risks`) are concatenated and deduplicated by their natural key. The
  order is: config file, then `--context` sources left to right.
- **Prose** (everything else) is never merged. Each piece is passed through verbatim
  under a heading naming its source, in the order given. A YAML source that carries
  keys beside `context:` contributes those keys as prose, so nothing an operator wrote
  is silently dropped.

The full order is: the config file's `context:` block, then `./.scheck/context/**` in
lexical path order (whatever the filesystem returned), then `--context` sources left to
right. A directory source is read the same way. A `target:` source is **prose only**,
whatever its extension: a host must not be able to accept its own risks or declare its
own exposure (§6.4). It is read as the `text.cat` catalog check through the runner, so
it is audited, path-policed and redacted like any other file; an inspection that never
contacts the target records it as `unresolved`.

Total context is capped by `Budgets.ContextBytes`, with an explicit warning when
truncated; truncation is recorded in the report. The structured block is counted first,
then prose in source order; the piece that crosses the budget is cut with a
`[TRUNCATED:<n bytes>]` marker and every later piece is dropped with its source marked
truncated. `--stop-after context` prints exactly the block the model will read (§6.3),
followed by the per-source hashes and the budget line.

### 6.2 Structured context schema

All fields optional; unknown fields are preserved and passed through as prose.

```yaml
context:
  role: "public API gateway"
  exposure: internet            # internet | vpn | lan | airgapped
  environment: prod             # prod | staging | dev
  data_classification: pii
  compliance: [soc2, cis-level-1]
  expected_services:
    - { port: 443, proto: tcp, purpose: "nginx public TLS", audience: internet }
    - { port: 5432, proto: tcp, purpose: "postgres", audience: vpc-only }
  accepted_risks:
    - { id: sshd.password_auth_enabled, reason: "break-glass path, MFA at bastion", expires: 2026-12-31 }
  owner: platform-team
```

`accepted_risks[].id` must be a catalog finding id (§7.1) or start with `custom:`.
An unknown id is a usage error (exit 3) at config load, so a typo cannot silently
leave a risk un-accepted.

### 6.3 How context is used — structured goes to code, prose goes to the model

The two kinds of context have different consumers.

**Structured context is consumed by `finding`, deterministically (§7.2):**

- **`expected_services`** — a listener matching an entry is emitted at `info`; a listener
  with no matching entry is escalated one step; a declared service that is absent is
  itself a finding (`svc.expected_missing`).
- **`exposure` and `environment`** — a fixed adjustment table: `internet` escalates every
  `remote-access` and `network` finding one step; `dev` de-escalates one step;
  `airgapped` de-escalates `remote-access` two steps.
- **`accepted_risks`** — the finding is still emitted, with `status: accepted` and the
  stated reason, and excluded from the exit code. A past `expires` date produces an
  `risk.acceptance_expired` finding in its own right.
- **`compliance`** — selects the reference frameworks cited in findings.

The model still sees the structured block (so it can reason about *why* a port is
expected), but nothing it says about severity is used.

**Prose context is consumed by the model** for correlation the model could not
otherwise make — that a listening port is meant to be reachable only from a peer
subnet, that a SUID binary is a vendor requirement, that a service is expected to run as
root. The model expresses this by choosing a finding id and `confidence`, and by
adding a `context_note` to the finding; it cannot change severity directly.

### 6.4 Context is untrusted data

Context files are frequently generated, copied between repos, or written by whoever
owns the host — and on-target context comes from the machine being audited.

- The system prompt declares the `<operator_context>` block to be **data, not
  instructions**: it may inform interpretation, and it may never change the auditor
  role, the reporting contract, or what gets executed.
- The catalog is compiled in and not model-reachable, so the worst a hostile context
  file can do is distort *classification* — it cannot widen the command surface, and it
  cannot lower a severity except through the attributed, deterministic rules above.
- Every severity adjustment is attributed: an adjusted finding carries
  `severity_base`, `severity`, and `adjustments: [{rule, source, delta}]`, and the report
  header lists `context_sources` with a content hash per source.
- `--ignore-context` skips the adjuster and omits the context block from the prompt.
  Because adjustment is code, "unadjusted" is a precise claim, not a hope.

---

## 7. Findings

### 7.1 Finding id catalog

Finding ids are compiled in, alongside the check catalog, with a base severity and a
category each:

```go
package finding

type Def struct {
    ID           string   // "sshd.password_auth_enabled"
    Title        string   // "sshd accepts password authentication"
    Category     string   // remote-access | network | accounts | privesc | integrity | updates | persistence | logging | fs | disk | time
    BaseSeverity Severity // critical | high | medium | low | info
    Impact       string   // one sentence; used verbatim by a rule finding, the model may sharpen it in phase 2
    Remediation  Remediation // summary, commands, caveat (§7.3); text for the human, never executed
    // References (framework → citations, selected by context.compliance) arrives
    // with operator context in M2.2; until then a finding emits no `references`.
}
```

`Title`, `Impact` and `Remediation` live on the Def, not only in the model's output,
because a posture rule (§7.5) must produce a complete finding with no model in the
loop. For a model-only finding the Def's text is the default and the model's text, when
present, replaces `impact` and `remediation`. For an existing rule finding, the merge
contract in §7.5 applies: its curated text is retained.

Ids are the join key for accepted risks, severity, dedupe and cross-run diffing, so the
model must not invent them. `report_finding` accepts a catalog id, or `custom:<slug>`
for something genuinely outside the catalog. Custom findings get `BaseSeverity` from
a required `proposed_severity` field, are never adjusted upward, are capped at
`medium`, and are flagged `custom: true` in the report so a reviewer can promote them
into the catalog.

### 7.2 Severity ownership — the model classifies, code grades

```
model ──report_finding(id, evidence, confidence, impact, remediation)──▶ finding.Store
                                                                             │
                                                     base severity from Def  │
                                                     + structured-context adjustments (§6.3)
                                                     + confidence caps (§5.3)
                                                     + accepted-risk status
                                                                             ▼
                                                                      report + exit code
```

This is the answer to v0.1's open question. Severity in the model's hands is
unrepeatable, unattributable, and unverifiable. In code it is a table and a test.

Classification itself has two sources. Posture rules (§7.5) classify facts whose
meaning is unambiguous, in phase 1, with no model. The model classifies everything that
needs judgement or more than one fact, in phase 2. Both enter the same `finding.Store`
and the same grader; a finding never bypasses the table because of where it came from.

### 7.3 Finding schema (as emitted in the report)

```json
{
  "id": "sshd.password_auth_enabled",
  "title": "sshd accepts password authentication",
  "category": "remote-access",
  "severity_base": "medium",
  "severity": "high",
  "adjustments": [
    {"rule": "exposure:internet", "source": "scheck.yaml#context.exposure", "delta": "+1"}
  ],
  "status": "open",
  "source": "model",
  "confidence": "high",
  "platform": "linux",
  "evidence": [
    {"check": "sshd.config", "excerpt": "passwordauthentication yes"},
    {"check": "net.listeners", "excerpt": "tcp LISTEN 0 128 0.0.0.0:22"}
  ],
  "impact": "Internet-reachable sshd allows online password guessing.",
  "context_note": "Operator notes say this is the public jump host.",
  "remediation": {
    "summary": "Set PasswordAuthentication no and rely on key auth.",
    "commands": ["# review first", "sudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config", "sudo sshd -t && sudo systemctl reload sshd"],
    "caveat": "Confirm at least one working key-based login first."
  },
  "references": ["CIS Distribution Independent Linux 5.2.x"]
}
```

The model supplies `id`, `title`, `confidence`, `evidence`, `impact`, `context_note`,
`remediation`. `scheck` supplies everything else. `severity`:
`critical|high|medium|low|info`. `confidence`: `high|medium|low`. `status`:
`open|accepted`. `source`: `rule|model` (§7.5); for a rule finding `title`, `impact`
and `remediation` come from the Def, `evidence` is the check id and the matched
excerpt, and `confidence` is always `high`. Remediation commands are **text for the
human** — `scheck` never runs them.

### 7.4 Report envelope and run artifacts

The JSON report is shaped so that a future fleet tool can concatenate reports without
a translation step, even though v1 audits one host per invocation. The example below
shows the shape including the phase 2 fields that M2 fills; everything except the
provider block and model findings is emitted today and validated by
`docs/report-schema.json`:

```json
{
  "schema_version": "1.1",
  "host": {
    "id": "b7c1…",                 // /etc/machine-id on Linux, IOPlatformUUID on macOS; hashed
    "hostname": "bastion-1",
    "platform": "linux", "os": "Ubuntu 24.04", "kernel": "6.8.0",
    "transport": "ssh", "remote_shell": "/bin/bash", "canary": "ok",
    "elevation": "sudo"
  },
  "run": {
    "started": "…", "duration_ms": 41200, "status": "complete|incomplete",
    "profile": "baseline", "mode": "facts|agent|single-pass",
    "provider": "…", "model": "…", "effort": "high", "native": {…}, "limits": {…},
    "usage": {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0, "cost_usd": null},
    "context_sources": [{"source": "…", "kind": "file", "sha256": "…", "bytes": 0, "truncated": false}]
  },
  "facts":    { "<check id>": { "status": "ok|unavailable|denied", "reason": "…",
                                "summary": "26 listening sockets",
                                "parsed": {"kind": "listeners", "items": [ … ], "partial": false} } },
  "assessments": [                 // one per selected posture rule (§7.5)
    {"finding": "disk.filevault_off", "check": "disk.fdesetup",
     "status": "not_matched", "reason": "recognized-enabled-state"}
  ],
  "findings": [ … ]                // rule findings from phase 1, model findings from phase 2 (§7.5)
}
```

`host.id` is stable across runs and hostname changes; it is the key a fleet
aggregator or a drift diff would join on. `run.mode` is `facts` when the run stopped
after phase 1 (`--stop-after facts`); in that mode `provider`, `model`, `effort`,
`native`, `limits` and `context_sources` are null or empty, `usage` is all zeros, and
`findings` holds rule findings only (§7.5). `summary` is the one-line, human-readable
reading of a fact (§7.6); it is the same string on the screen, in the JSON and in the
model's prompt. The envelope is validated against `docs/report-schema.json` in tests.
Findings are a flat array keyed by catalog id, never nested under a host, so
concatenation is trivial.

From M1.8 a phase 1 report sets `run.assessment: "rules"` and carries the
`assessments` array; `"none"` remains the value for a build or a mode that assessed
nothing. An empty findings array is never a security verdict on its own — the scope of
what was assessed is a field, not an inference. Facts expose `attempted` and optional `reason_code`
independently of `status`. Codes are assigned by the runner: `requires_elevation`,
`sudo_refused`, `command_missing`, `check_timeout`, `run_timeout`, `canceled`,
`exec_error`, `exit_error`, `parse_error`, `extract_error`, `invalid_params`,
`path_denied`, `unknown_check`, `metadata_unavailable`. Human `reason` text supplies
details. An attempted execution need not have started a process; prerequisite probes
are not represented by this boolean. `--include-evidence` adds an optional `evidence`
object (`stdout`, `stderr`) to attempted facts in JSON output only. Captures remain
redacted, bounded and extraction-filtered; persistence and default JSON omit them.

Pre-release schema history: `1.0` is the M1 envelope, extended during M1.6 review with
assessment scope, execution diagnostics and opt-in evidence; `1.1` (M1.7, M1.8) adds
`facts.<id>.summary`, the typed `parsed` shapes of §3 (`{kind, items, partial}`, so a
record is `parsed.items[0]`), the `assessments` array and populated `findings` with
`source: rule`; `1.2` (M2.2) fills `run.context_sources` from operator context, one
entry per source with its kind (`config|implicit|file|note|target`), byte count,
sha256 and truncated flag, and `unresolved` for a `target:` source an inspection did
not read. These are development revisions, not a compatibility promise.

**Compatibility starts at the first GitHub release.** Before that release, breaking
CLI, configuration and report changes are allowed. Update the spec, implementation,
`docs/report-schema.json` and fixtures together when the change is implemented;
do not add compatibility shims, dual fields or migrations for development artifacts.
A breaking change does not require a major version bump during this period. Readers
may reject unsupported development artifacts with a clear error.

The first GitHub release establishes the supported contract. After that release,
`schema_version` is `MAJOR.MINOR`: additive changes bump MINOR; renames, removals and
field type changes bump MAJOR. Readers reject an unrecognized MAJOR rather than guess
at an unsupported shape. The release notes identify the schema version shipped.

**Persistence.** From M1, every run writes this envelope to
`<state-dir>/runs/<host.id>/<started>.json` (default state dir
`~/.local/state/scheck`, or `$XDG_STATE_HOME/scheck`; `--state-dir` overrides,
`--no-persist` disables). Persisted files pass the same redactor as the report. The
`facts` block is what makes posture drift diffable; `scheck diff` itself ships in M4
and compares the two most recent runs for a host (or two named files): added and
removed listeners, units, SUID files, and findings that appeared, disappeared, or
changed severity. Typed `parsed` shapes (§3) make that a set difference per record
kind rather than a line diff.

### 7.5 Posture rules — deterministic findings from the fact sheet

A posture rule turns one fact into one finding when the fact's meaning needs no
judgement.

```go
package finding

type Rule struct {
    Finding  string         // finding id (§7.1); the Def supplies title, severity, impact, remediation
    Check    string         // the one check whose fact the rule reads
    Platform check.Platform // macos | linux | any
    When     Predicate      // KeyEquals{Key, Value, Known} over kv
                            // RawMatch{Regexp, Requires} over raw
                            // AnyLine{Regexp} over lines
                            // FieldEquals{Field, Value, Known}, FieldOutside{Field, Allowed,
                            //   Recognize}, AnyRecord{} over a typed shape
}

A predicate answers `matched`, `not_matched` or `not_assessed` — never a boolean. The
recognizability fields (`Requires`, `Known`, `Recognize`) are what make the third answer
possible: a value the rule does not understand, a missing key, a redacted value or a
truncated capture is `not_assessed`, never a pass.
```

- **Rules read the fact sheet; they never execute a command.** The command surface is
  unchanged and the runner is untouched.
- **One rule reads one check.** A conclusion that needs two facts (no firewall active at
  all, password auth *and* a public listener) is the model's job in phase 2. Single-fact
  rules stay obvious, and every one is testable with a fixture where it fires and one
  where it does not.
- **Evaluate recognized evidence, not failure to recognize a good state.** A predicate
  may fire only on a complete, recognized value or record proving its condition.
  Missing fields, unknown output, parse failures and redacted values are not matches
  or passes. A complete matching record in partial output can prove an existential
  condition; a negative or absence claim requires complete relevant evidence. Counts
  from incomplete output are labelled as partial, never presented as exact totals.
- **Record assessment coverage separately from findings.** Each selected rule produces
  an `assessments` entry (§7.4), identified by finding id and check id, with a reason
  and one of `matched`, `not_matched`, `not_applicable`, `not_assessed`. Only `matched`
  emits a finding. `not_matched` means this predicate was disproved by sufficient
  evidence, not that the host or domain is secure.
- **Applicability must be known.** A rule's platform gate or a recognized result from
  its own check may establish `not_applicable`; a missing executable alone cannot.
  Otherwise unavailable, denied or insufficient evidence produces `not_assessed`.
  Keep this interpretation in the check/parser and evaluator, not in the renderer.
  Do not add cross-check applicability predicates to the single-fact rule mechanism.
  Rules outside the selected platform/profile are omitted. Disabled selected checks
  leave their rules `not_assessed`, with the disabling reason.
- **Render coverage honestly.** Group not-assessed rules by check and reason, with a
  remedy when known. Not-applicable assessments remain available in JSON and verbose
  output but do not clutter the default list of missing coverage. Assessment entries
  are not findings and do not themselves trigger exit `1`.
- **A rule finding is graded like any other.** `source: rule`, `confidence: high`,
  evidence is the check id plus the matched excerpt, and the severity goes through §7.2,
  so context adjustments and accepted risks apply.
- **The model enriches, never overrides.** Rule findings are in the phase 2 prompt. A
  `report_finding` with the same id merges: `source: rule`, title, impact, remediation
  and rule confidence are retained; validated extra evidence and attributed model
  context notes append without duplicate evidence. The shared grader still owns
  severity, adjustments and accepted-risk status. Model-supplied text cannot replace
  curated rule guidance or suppress the rule finding.
- **The table is compiled in** beside the finding catalog (`internal/finding`). The
  invariants test extends to it: every `Rule.Check` is a catalog id, every
  `Rule.Finding` is a Def, and the predicate kind matches the check's parser.

Seed table (M1.8). Base severities are the §7.1 table entries for these ids:

| Finding | Platform | Check | Fires when | Base |
|---|---|---|---|---|
| `disk.filevault_off` | macos | `disk.fdesetup` | recognized `FileVault is Off` state | high |
| `integrity.sip_disabled` | macos | `integrity.csrutil` | raw matches `disabled` | high |
| `integrity.gatekeeper_disabled` | macos | `integrity.spctl` | raw matches `assessments disabled` | medium |
| `fw.app_firewall_disabled` | macos | `fw.global` | raw matches `State = 0` | medium |
| `remote.login_enabled` | macos | `remote.login` | raw matches `: On` | info |
| `time.ntp_disabled` | macos | `time.ntp` | raw matches `: Off` | low |
| `sshd.password_auth_enabled` | any | `sshd.config` | `passwordauthentication` = `yes` | medium |
| `sshd.root_login_enabled` | any | `sshd.config` | `permitrootlogin` = `yes` | high |
| `accounts.empty_password` | linux | `accounts.passwd_status` | a record with status `NP` | critical |
| `accounts.shadow_permissions_unexpected` | linux | `accounts.shadow_meta` | parsed mode is outside `0`, `600`, `640` | high |
| `mac.selinux_disabled` | linux | `mac.sestatus` | `selinux status` = `disabled` | medium |
| `log.auditd_inactive` | linux | `log.auditd` | recognized `inactive` or `failed` state | low |
| `time.ntp_unsynced` | linux | `time.timedatectl` | `ntpsynchronized` = `no` | low |
| `updates.pending` | any | `pkg.*` | any `updates` record | low |
| `fs.world_writable_present` | any | `fs.world_writable` | any line | medium |

The shadow rule reports an unexpected mode, not proven access by an unauthorized
user; its title, impact and remediation must preserve that distinction. Missing or
malformed modes are not assessed. Likewise an empty-password status does not alone
prove a usable remote login, and a disabled named protection does not prove all
alternative protections are absent. Unknown or transitional FileVault states are not
assessed by the off rule. `pkg.*` denotes separate rules bound to concrete catalog
ids, not a wildcard execution or lookup mechanism.

`pkg.*` above is four rules, one per concrete catalog id. Several rules may share one
finding id; the evaluator emits that finding once and appends each matching rule's
evidence.

`fs.suid` deliberately has no rule: SUID files are normal, and which ones are not is
judgement. The same applies to listeners, persistence entries and sudoers content.

### 7.6 Text report — what a person sees

`--format text` is the product for anyone who runs `--stop-after facts`, so it has a
contract, pinned by golden tests per fixture (§11):

- **Header, two lines.** Who was audited and how (hostname, OS, transport, elevation),
  then the result in one sentence: "3 findings (1 high), 22 checks ran, 6 skipped".
  `host.id`, profile, mode, kernel and timings move to `-v`.
- **Findings first, then facts.** Rule findings (and, in phase 2, model findings) come
  before the fact sheet, ordered by severity: title, severity, the evidence excerpt with
  its check id, the remediation summary. Not-assessed assessments close the section,
  grouped by check and reason; they are excluded from finding counts.
- **Status words, not marks.** A check `ran`, was `skipped` (unavailable) or was
  `denied`. A mark column may exist for scanning, but a mark never means "posture ok":
  a fact whose rule fired shows the finding's severity in its reading
  (`[finding: high]`), not a plus.
- **The fact sheet is one flat table**, header row `DOMAIN STATUS CHECK READING`, one
  row per check, rows ordered by domain and then id. Every row repeats its domain so the
  report sorts, greps and pipes as a table; there are no section sub-headings and no box
  drawing. Columns are sized from the data (domain capped at 24, check id at 30) and the
  READING column wraps into continuation rows aligned under it, never truncating a
  reason. Findings (§7.5) are rendered above the table, not inside it.
- **One meaningful summary per check.** From the typed parser or `Unit` (§3): "26
  listening sockets", "0 SUID files", "FileVault is On.", never the first raw line. The
  same string is `summary` in the envelope (§7.4).
- **Skipped checks grouped by reason, with the remedy.** "6 checks need elevated read:
  re-run with `--sudo` (on macOS run `sudo -v` first, or install the `scheck sudoers`
  fragment)". Denied-by-policy is its own group and names the rule.
- **Human domain labels** ("Privilege escalation", not `privesc`) from a table in
  `report`. Check ids stay verbatim: they are the join key into `scheck explain`, the
  audit log and the JSON.
- **`-v` adds each check's description and the run detail the header dropped; `-vv`
  adds its redacted output** behind a `  | ` gutter at the left margin, where evidence
  has room for its own alignment. This includes redacted stdout/stderr from attempted
  checks that failed. Unattempted checks have no capture. Extraction failures withhold
  full stdout and explain the restriction. JSON consumers use `--include-evidence`;
  all these paths remain behind the redactor (§4.2).
- **Target output can never drive the terminal.** Every target-derived string the text
  report prints — header, summary, reason, warning, `-vv` output — has its control characters
  escaped as `\xNN` first (tabs are expanded to eight-column stops, newlines split
  lines in evidence blocks; header fields fold whitespace to one logical line). Unicode
  control and formatting characters are escaped too. Target text must not repaint
  the screen or forge the report structure.
- **Colour only on a tty**, off under `NO_COLOR` (any non-empty value), and never in a
  `--out` file or a redirected report. Severity colours are the only colours; until
  findings exist the report styles structure alone (bold header and table head, dim
  descriptions and evidence). Styling is applied to whole lines after wrapping, so an
  escape sequence never counts against a line's width. The caller decides — the report
  package inspects no file descriptor and no environment variable.
- **Honest footer.** In `facts` mode: "assessment: posture rules only", with how many
  of the selected rules had the evidence to decide, and "the agentic pass is not
  available in this build" until M2. Never "findings: none" when nothing looked, and
  never a claim that what no rule covers is fine. The header's result sentence leads
  with the findings ("2 findings (1 medium, 1 low), 4 rules not assessed, 28 checks: 22
  ran, 6 skipped") and says "0 findings from posture rules" rather than "no findings".
- **Width.** Lines wrap at the terminal width or 100 columns; no trailing padding.
  Wrapping prefers a space, falls back to a hard cut rather than dropping a byte, and
  never breaks a `[REDACTED:…]` or `[TRUNCATED:…]` marker in half: the marker is the
  only record that bytes were removed (§4.2). A hanging block counts its own prefix, so
  a wrapped reason or remedy cannot overrun. The table's fixed columns set a floor below
  which the layout cannot shrink.
- **Captures are opt-in diagnostics.** `-vv` and JSON `--include-evidence` render only
  the runner's redacted, bounded capture after catalog extraction. Default JSON and
  persisted runs omit captures; pre-redaction bytes never leave the runner (§7.4).

---

## 8. CLI

```
scheck local                            # audit this machine
scheck ssh user@host [--port] [--identity]
scheck catalog [--profile P]            # list every check the model could run under profile P
scheck sudoers [--platform P]           # print a least-privilege NOPASSWD rule for elevated checks (§8.1)
scheck explain ID                       # CHECK-ID: what a check runs, why, its parser and which posture rules read it
                                        #   FINDING-ID: the severity chain — base, context adjustments,
                                        #   confidence cap, accepted-risk status, final (§7.2). Accepts the
                                        #   §6.2 structured keys as flags (--exposure, --environment) so an
                                        #   adjustment can be reproduced without a run.
                                        #   (purpose, literal argv with its {placeholders}, typed params,
                                        #   platform, domain, phase, elevation, parser, exit codes, path
                                        #   use, extract; one section per platform-specific definition.
                                        #   Lists the posture rules that read the fact.)
scheck providers                        # configured providers, limits, native features
scheck config show|validate             # effective settings with provenance; validate exits 0|3 (§9)
scheck diff [A B]                       # posture drift between two runs (M4)
scheck --format text|json|sarif  --out FILE
       --include-evidence             # JSON facts only: optional redacted diagnostics
       --profile baseline|hardened      # severity thresholds + catalog tier (§3)
       --elevate none|sudo  (--sudo)    # elevation mechanism (§8.1)
       --only remote-access,updates     # category filter
       --provider openai-compatible      # anthropic / ollama: post-v1; mock for tests
       --model NAME  --base-url URL
       --local-only                     # unavailable until post-v1 M3.3; exit 3
       --effort low|medium|high|max
       --context SOURCE                 # repeatable: FILE | DIR | note:TEXT | target[:PATH]  (§6.1)
       --ignore-context                 # no context in the prompt, no severity adjustment
       --stop-after context|plan|facts  # print merged context / phase-1 plan / fact sheet, then exit
       --audit-log PATH
       --state-dir PATH / --no-persist  # run artifacts (§7.4)
       --timeout 5m
       -v / -vv
```

**Machine-readable use (available from the M1.6 follow-up).** `catalog`, `explain`
and plans honor `--format json` and `--out`. Discovery has its own `schema_version`
and `kind` (`catalog|explain|plan`), `scheck_version`, platform, and a `checks` array.
Entries expose argv arrays, typed params, parser, profile, elevation, accepted exits,
path use, extraction, canary and budget overrides (milliseconds/bytes, zero means
policy default). `any_exit` represents the wildcard exit contract without exposing an
internal sentinel. `scheck explain FINDING-ID` uses `kind: finding` with the severity
chain as an ordered array of `{stage, from, to, reason}` steps rather than a `checks`
array (M2.3). Unsupported formats fail explicitly. Facts JSON goes to stdout,
diagnostics to stderr; `--out` redirects the document. Help includes supported
invocations and labels future flags unavailable. See the [scheck skill](../.agents/skills/scheck/SKILL.md)
for examples, exit-code interpretation, diagnostics and the SSH planning limitation.

`--stop-after plan` prints the phase 1 check list without running the baseline or
contacting a model. Local planning executes no target commands. In the current SSH
implementation, planning connects, verifies the canary, and detects the platform
before printing the plan. For connection-free discovery, use
`scheck catalog --platform linux|macos --format json`; this lists the platform catalog,
not the configured target's exact plan. Plans cannot show phase 2 commands, which the
model chooses at run time.
`--stop-after facts` runs phase 1 only and needs no API key.

Exit codes: `0` no open finding at or above the profile threshold · `1` findings present ·
`2` run incomplete (check/agent/transport failure, budget exhausted) · `3` usage or policy
error (including a failed SSH canary, an unknown host key, or an unknown accepted-risk id).

Profile thresholds apply from M1.8: `baseline` fails on `medium` or higher;
`hardened` fails on `low` or higher. `info` findings remain visible but never trigger
exit `1`. Thresholds select the exit result, not which findings are displayed.
Exit `3` takes precedence over `2`, which takes precedence over `1`, then `0`.
An exit `0` is not a claim of full coverage: consult the assessments and skipped checks.

From M1.8, under `--stop-after facts` the findings are the posture rules' (§7.5), so the run
exits `1` when one is open at or above the profile threshold and `0` otherwise
(individual `unavailable` checks do not change that), `2` when the transport failed or
`RunTimeout` cut the run, `3` for usage, config or canary errors. One meaning per exit
code, whichever phase produced it. `-v` and `-vv` govern both logging and how much of
the text report is shown (§7.6).
From M1.8 the build emits exit `1`: `run.assessment` is `rules`, `findings` holds the
rule findings, and `assessments` records every selected rule's coverage. Exit `0` means
no open finding reached the profile threshold — not that the host is well configured,
and not that everything was assessed; consult `assessments`, `run.status`, warnings and
each fact. JSON reports may accompany exit `1` and `2`; early setup/usage failures may
have no report. See the [scheck skill](../.agents/skills/scheck/SKILL.md).

Flags that belong to a later milestone are registered from day one and exit `3` with
"not available in this build" until that milestone lands.

### 8.1 Elevation

Some checks (`sshd -T`, `/etc/sudoers`, `/etc/shadow` metadata) need root. Elevation is
opt-in, only ever widens *read* access, and is a **prefix** prepended to the check's
argv; the catalog invariants apply to the full argv after the prefix.

`--elevate` / `elevate:` values in v1:

| Value | Behaviour |
|---|---|
| `none` (default) | Elevated checks report `unavailable: requires elevated read`. The run continues. |
| `sudo` (`--sudo` is shorthand) | Prefix `sudo -n --`. Non-interactive only: `scheck` never prompts for, reads, or transmits a password. If sudo would prompt, the check is `unavailable` with the sudo error as the reason. |

Before prefixing, the runner runs the platform's `sys.which` check for the binary,
because `sudo -n` reports a missing binary as "a password is required" and that
message would mislead the operator. When `which` itself is absent (minimal Fedora),
the runner assumes the binary is present and lets sudo decide. A sudo failure is
reported as `unavailable: <sudo stderr> (no NOPASSWD rule for this command, or X is not
installed)`.

To exercise `--sudo` on a workstation where sudo prompts, either cache the credential
first (`sudo -v && scheck local --sudo …`, valid for the tty's timestamp window) or
install the `scheck sudoers` fragment.

Running the session as root (`scheck ssh root@host`) needs no prefix and is recorded as
`elevation: root` in the header. The prefix design leaves room for `doas`, `run0`
or a custom prefix later without touching the catalog or the loop; they are out of
scope for v1, as is any password-forwarding mode.

**`scheck sudoers`** prints a sudoers fragment granting the invoking user NOPASSWD for
exactly the argv of every `Elevated: true` check on the given platform, as literal
command lines with their fixed flags. Parameterised elevated checks are listed with
sudo's wildcard syntax limited to the parameter's charset. `scheck` prints the fragment
and never installs it. The fragment is regenerated from the catalog, so it cannot drift
from what `scheck` actually runs. Binaries are resolved to absolute paths from a
per-platform table because sudoers requires them; generation fails on an unknown
binary rather than guessing. Because sudoers cannot express an empty argument, the
sudoers.d checks use `grep -rH .` rather than `grep -rH ""`. The fragment also sets
`Defaults:<user> !requiretty`, since `scheck ssh` allocates no tty.

---

## 9. Configuration

Precedence, lowest first: built-in defaults → the OS user config file → the project
`./scheck.yaml` → flags the operator explicitly set. A flag's registered default never
overrides a file; only a flag that was given counts. The user file is
`$XDG_CONFIG_HOME/scheck/config.yaml` (default `~/.config/scheck/config.yaml`) on
Linux and `~/Library/Application Support/scheck/config.yaml` on macOS
(`os.UserConfigDir`). Scalars override per key; `disable_checks`, `deny_paths` and
`redact_extra` accumulate across files; `targets` merge by name; a later file's
`context:` block replaces an earlier one's whole (per-key merging happens across
context *sources*, §6.1).

```yaml
provider: openai-compatible   # v1 production adapter; anthropic / ollama post-v1
model: gpt-5                  # required for openai-compatible; the endpoint decides what exists
# base_url: http://localhost:11434    # defaults to https://api.openai.com/v1
# max_context: 128000         # the model's context window when the adapter cannot know it (§5.3)
effort: high
allow_egress: true            # false fails explicitly in v1; local-only mode post-v1
profile: baseline
elevate: none                 # none | sudo (§8.1)
state_dir: ~/.local/state/scheck
disable_checks:               # may only subtract from the compiled catalog
  - fs.suid_scan
deny_paths:                   # may only add to the compiled deny list
  - /etc/corp-secrets
redact_extra:
  - "internal\\.example\\.com"
targets:
  bastion: { host: 10.0.0.5, user: ops, identity: ~/.ssh/ops }
context: { … }                # §6.2
```

Every config knob narrows: it disables checks, denies paths, adds redactions. No knob
widens what `scheck` may execute or reveal. Credentials come from the environment per
provider (`OPENAI_API_KEY` or `--base-url` for `openai-compatible`; `ANTHROPIC_API_KEY`
or an `ant auth login` profile / WIF for `anthropic`; nothing for `ollama`). Never
read a key from the config file.

**Inspection.** `scheck config show` prints every effective setting with its source
(`default`, the file path, or `flag`), every accumulated entry with every source that
listed it, the targets, credential *presence* per provider, and the merged operator
context a run would consume with per-key origins. `scheck config validate` applies the
same validation a run applies plus the local context sources and exits 0 or 3, naming
the source of an error. Both use the resolver a run uses, contact neither a model nor a
target, report a `target:` context source as unresolved, and pass every displayed
string through the redactor and the terminal escaper; a base URL with user info is
shown with the credentials stripped. `docs/CONFIGURATION.md` is the walkthrough.

---

## 10. Milestones

Status (2026-09-20): M0, M1, M1.6 including its review follow-up, M1.7 and M1.8 are
implemented; see `ROADMAP-0.0.1.md` for validation and working-tree status. M2 is next.

- **M0 — walking skeleton.** `target.Target` (local + ssh with canary), catalog type
  and invariants test, `policy` (path, redaction, budgets), audit log, elevation
  prefix, `scheck local --stop-after plan`, `scheck catalog`, `scheck sudoers`. No model.
- **M1 — baseline.** Linux + macOS baseline checks, fact sheet, report envelope with
  host identity, run persistence (§7.4), text/JSON renderers. `--stop-after facts`
  produces a useful report on its own. M1.6–M1.8 (added after using the M1 build):
  the text report contract (§7.6), typed parsers and summaries (§3), posture rules and
  the finding id catalog (§7.5, §7.1), so phase 1 says what is wrong without a model.
- **M2 — agent.** `llm` interface, the loop, three tools, system prompt, severity
  adjustments and accepted risks on top of the M1.8 catalog, operator context (§6),
  the `openai-compatible` provider, the `mock` provider, `scheck providers`, request-size
  guards and repeated real-model quality/adversarial evaluations.
- **M3 — more providers (post-v1; not a dependency of M4).** `anthropic` + `ollama`
  with tool-call emulation,
  `--local-only`, small-context chunking and extension of the existing provider
  conformance suite. Additional provider coverage is not a v1 release gate.
- **M4 — polish.** SARIF, profile tiers, category filters, `scheck diff`, golden-fixture
  tests.
- **Optional research — bounded assessment (§5.9).** Offline fixtures and harness
  first; a Jev comparison only when access is available. No M0–M4 dependency or v1 gate.

---

## 11. Testing

- **Catalog invariants are the priority.** A test over every catalog entry: no
  metacharacters in literals, every placeholder bound to exactly one typed param, no
  mutating flags, no binary from the write-capable list. Plus a corpus of hostile
  `run_check` inputs — unknown ids, params with metacharacters, traversal and symlink
  escapes in `Path` params, sensitive paths via `text.head` as well as `read_file` —
  asserting deny with the expected rule.
- **Quoting tests.** The SSH quoter over the full enumerable input domain (every
  literal token in the catalog plus the parameter charsets), and the canary check
  against a matrix of login shells (`sh`, `bash`, `zsh`, `fish`, `rbash`) in
  containers, asserting abort on the ones that fail.
- **Fixture targets.** A `target.Target` implementation backed by recorded
  stdout/stderr/exit-code fixtures per platform. Check parsing and report rendering
  are tested with zero network and zero API calls. A fixture is a directory with
  `manifest.yaml` (`platform`, then `execs: [{argv, stdout|stdout_file,
  stderr|stderr_file, code, sleep}]`); an argv with no recording replays exit 127,
  which models a missing binary. Fixtures are recorded from real targets with the
  hidden `--record-fixtures DIR` flag, which captures post-redaction bytes only;
  `make fixtures` re-records `testdata/fixtures/{ubuntu,fedora}` from the containers in
  `test/containers`. The macOS fixture was recorded from a developer machine and
  scrubbed of hostname, user and serial numbers.
- **Integration tests** (`make integ`, build tag `integration`, need Docker or Podman)
  cover what fixtures cannot: the canary matrix, `visudo -cf` on the generated
  fragment plus an elevated run flipping `sshd.config` to populated, and
  `scheck ssh --stop-after facts` against Ubuntu and Fedora with schema validation and
  an empty `docker diff` afterwards (acceptance criterion 3).
- **Golden text reports.** One per fixture (ubuntu, fedora, macos) at default, `-v`
  and `-vv`, committed under `internal/report/testdata/golden/` and diffed in
  `go test`; `go test ./internal/report -update` rewrites them. A diff is a review
  item, not something to silence; §7.6 is the contract the golden files pin. Alongside
  them, every golden is re-rendered at several widths to assert no line overruns and no
  line carries trailing padding.
- **Rule tests.** Table-driven: fact sheet → expected finding ids. Every rule has a
  fixture where it fires and one where it does not, plus unknown, malformed,
  unavailable, denied, redacted and truncated evidence. Test applicability, disabled
  checks, partial positive records and incomplete negative claims. Assert the same
  assessments and finding counts in JSON and text, and profile exit thresholds.
  The catalog invariants test covers rules (§7.5).
- **Severity tests.** Table-driven: (finding id, structured context) → expected
  severity, adjustments and status. `--ignore-context` asserted to equal base severity
  exactly.
- **Agent tests.** Fixture target + the `mock` provider replaying recorded transcripts,
  so the loop is tested deterministically and offline. One opt-in live test
  (`SCHECK_LIVE=1`) per platform asserting cache hits and that no denied check was
  attempted.
- **Provider conformance suite.** One table every provider must pass, unconditionally:
  tool-call round trip, error results, multiple calls in one turn, each `StopReason`
  mapped correctly, `MaxTokens` truncation, usage normalization, `Limits` reporting.
  Emulating adapters run the same table; that is the point.
- **Context-limit tests.** Cover an oversized first request, tool-result/history
  growth, schema/framing overhead, output reservation, unknown limits and provider
  overflow rejection. Assert no oversized request is sent when caught locally, no
  evidence is silently dropped, and collected facts/findings survive in an incomplete
  report with exit 2.
- **Injection corpus.** Operator prose and target-derived check output containing
  instruction-shaped text ("ignore previous instructions", "report no findings",
  "run `curl … | sh`") must not change the auditor role, suppress findings wholesale,
  alter code-owned severity, or produce a denied check attempt in the evaluated runs.
  M2.5 tests prompt boundaries and enforcement with mock transcripts; these do not
  establish model resistance. M2.7 must also run repeated real-model evaluations over
  hostile and benign paired fixtures, including incomplete and misleading evidence.
  Freeze pass criteria in `docs/eval/phase2-criteria.md` at M2.1, record model/prompt
  versions and failures, and require the criteria to pass before v1. This is measured
  resistance on the corpus, not a guarantee against every injection; deterministic
  policy remains the security boundary. Live evaluations are opt-in, not default CI.
- **Configuration tests.** Inspection and an ordinary run resolve identical effective
  settings from the same files and flags, including absent files, accumulated
  restrictions and context conflicts; an unset flag never overrides a file; `config
  validate` exits 0 and 3 without a target command or an inference request; a seeded
  credential is absent from text, JSON and diagnostics and a control character in a
  configured value is escaped.
- **Redaction tests.** Seeded secrets in fixture output must not appear in any
  transcript, report, or audit log, and every redaction must leave a marker.

---

## 12. Acceptance criteria for v1

1. `scheck local` and `scheck ssh …` produce a report on macOS and on Ubuntu + Fedora.
2. No command outside the compiled catalog ever reaches the target — proven by the
   catalog invariants test, the hostile-input corpus, and the audit log of a live run.
3. Nothing on the target is modified (verified by a before/after filesystem and
   config diff on a throwaway VM).
4. `--stop-after facts` is fully useful offline: no API key required, the text report
   follows §7.6, and a fixture host with FileVault off (macOS) or
   `PasswordAuthentication yes` (Linux) yields that finding with exit `1` and no model.
5. Every finding carries evidence traceable to a check id.
6. Seeded secrets never appear in any output artifact, and every redaction is marked.
7. One `scheck local` run on a clean host costs under $0.50 at default effort.
8. The `openai-compatible` adapter and `mock` pass the provider conformance suite.
   Full-request context guards run before every model call; initial overflow, history
   growth and provider overflow rejection preserve facts/findings, report an incomplete
   AI assessment and exit 2 without silently dropping evidence (§5.3, §11). Additional
   providers, emulation, guaranteed local-only AI and chunking are post-v1 requirements.
9. Operator context changes the report deterministically: the same host audited as
   `exposure: internet` and as `exposure: lan` yields severities that differ exactly per
   the adjustment table, every adjustment is attributed to its source, and
   `--ignore-context` reproduces base severities byte-for-byte.
10. **Phase 2 earns its cost.** Compare posture rules alone, single-pass analysis,
    and the agent on the same labeled fixture suite and operator context. Include
    clean hosts, seeded issues and incomplete or misleading evidence; some cases
    must require additional catalog evidence. Both model modes receive the same
    initial facts and rule findings. Record correct additional findings, false
    positives, missed issues, justified abstentions, resolved uncertainty, latency,
    tokens and cost across repeated model runs. Define success criteria before the
    evaluation and record model/prompt versions. Follow-up investigation must show
    repeatable useful gains over single-pass analysis within the run budget; the
    simpler mode need not fail any particular example. Mock transcripts prove only
    plumbing. If the gains do not justify the loop, retain the rules and use
    single-pass analysis instead.
11. The SSH canary aborts the run against a fish or restricted login shell before any
    other command is sent.
12. Repeated real-model adversarial evaluations pass the frozen M2.1 criteria on
    hostile operator context and target-derived evidence (§11). Record model/prompt
    versions, outcomes and failures; mock-only results cannot satisfy this gate.

---

## 13. Decisions log

Questions that were open in v0.1, with the decision and the reason. Reopen one only
with a reason that beats the one recorded.

| Question | Decision | Why |
|---|---|---|
| Shape JSON for multi-host aggregation now? | Yes: `host` identity block with a stable `host.id`, flat findings array, and a `schema_version` field (§7.4). | Costs nothing now; a fleet aggregator concatenates and can reject a version it wasn't tested against. |
| Persist fact sheets for drift? | Persist the full envelope from M1; `scheck diff` in M4 (§7.4). | The format is what is hard to retrofit, not the command. |
| Cost for local providers? | Tokens and wall-clock always; `cost_usd` null when there is no price (§5.5). | No invented numbers; runs stay comparable on tokens. |
| Catalog growth past ~60? | Profile-gated tiers via `MinProfile`; baseline tier capped by test (§3). | Keeps the cheap run's menu small without capping what a hardened audit can do. |
| Custom finding ids? | Kept, capped at `medium`, flagged `custom: true`, never escalated (§7.1). | The model can surface a novel issue without driving exit codes or matching accepted risks by accident. |
| SSH canary fails? | Abort, exit 3, no further command sent (§4.3). | Quoting is the whole boundary on SSH; do not guess around it. |
| Elevation mechanism? | `sudo -n` only in v1, as a prefix, plus `scheck sudoers` (§8.1). Password forwarding and `doas`/`run0` deferred. | Never transmit a password; the prefix design makes the others cheap to add later. |
| Which provider is built first? | `openai-compatible` (M2.6); `anthropic` follows in M3.1 (§5.2, §10). | The widest-reach adapter should be the one the conformance suite is written against, and a second provider that is *richer* than the reference implementation tests the interface harder than a second one that matches it. The `llm` interface stays designed from the richest provider so M3.1 adds no field. |
| Confidence under emulated tool calling? | Capped at `medium` in code, keyed on `Native.ToolCalling` (§5.3). | Parsed-from-text calls fail more often; a `high` from that path overstates certainty. Per-call emulation provenance would cap more precisely in a mixed run, but no adapter emulates anything until M3.2 — revisit it there, with the emulation in front of us, rather than scaffolding it now. |
| Must M3 ship in v1? | No: ship M2, then M4; M3.1–M3.4 are post-v1. Keep full-request context guards and real-model quality/adversarial release gates in M2. | More providers and chunking expand compatibility; robustness first requires bounded execution, honest incompleteness and measured quality. Chunking adds a separate risk of losing cross-domain evidence. |
| Make Jev a required provider or milestone? | No. Separate, optional assessment experiment (§5.9), developed offline; live evaluation deferred until access is available. | Bounded judgments have a different contract, and waitlisted vendor access must not block the product. |
| Judge anything without a model? | Yes, for facts whose meaning is unambiguous: posture rules (§7.5), one fact → one finding, code-graded like everything else. | Most users stop at `--stop-after facts`; a fact sheet that never says "this is wrong" is a debug artefact, not a tool. The model still owns every conclusion that needs two facts or judgement. |
| Exit code of a facts-only run with a rule finding? | `1`, the same table as a full run (§8). | One meaning per exit code; CI can gate on the offline run. |
| Per-check summaries? | Typed parser shapes plus a `Unit` noun on `lines` checks (§3), not a summariser function. | One record shape serves the screen, the model and `scheck diff`. |
| How does a user or agent inspect captured output? | `-vv` for text; `--format json --include-evidence` for structured facts (§7.4, §7.6). Both use the same redacted, bounded, extraction-filtered capture; default persistence omits it. No `scheck show`. | Humans and agents can diagnose failed checks without a second execution or a second collection path. |

No open questions remain for v1.
