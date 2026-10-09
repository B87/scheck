# scheck — host collector specification

This is the contract for the host collector: the check catalog, the runner, policy,
the local and SSH targets, posture rules, grading, the host report, and the CLI that
drives them (`scheck local`, `scheck ssh`). It was released as v0.0.1.

In the engagement design ([../VISION.md](../VISION.md), [engagement.md](engagement.md),
[scope.md](scope.md)) this is the collector for host assets. Its guarantees hold
unchanged there. The model path (inference layer, agent loop, tools) is
[model.md](model.md); the bounded-assessment experiment is [bounded.md](bounded.md);
what is planned next is [../ROADMAP.md](../ROADMAP.md).

**Folding into `scheck run` (0.0.2).** From 0.0.2 the collector is driven by
`scheck run`, with an engagement file or `--host` (engagement.md, "One command, one
file"; ROADMAP E1b, E2). The catalog, runner, policy, SSH boundary, elevation, posture
rules, grading and the JSON envelope (§3, §4, §5.3–§5.4, §6.1–§6.5, §7.1) stay this
collector's contract. What drives them changes: the context sources (§5.1), the text
report (§6.6), `scheck local` and `scheck ssh` (§7) and the configuration file (§8)
are superseded, each marked where it is. Until the slice that replaces a section
lands, that section describes the build.

When the implementation has to deviate from a section, update that section in the same
commit; the history is git history. Code comments cite sections as
`docs/spec/host-collector.md §N`, so section numbers do not change.

---

## 1. Goals / Non-goals

These are the host collector's. The product's goals, its other asset types and its
active checks are in [../VISION.md](../VISION.md) and [scope.md](scope.md).

**Goals**

- One binary, zero dependencies on the target machine beyond a POSIX shell and SSH.
- Same UX for `scheck local` and `scheck ssh user@host`. (Same UX, not the same trust
  boundary — see §4.3.)
- Findings that a human can act on: severity, evidence, remediation — no raw dumps.
- Posture rules for facts whose meaning is unambiguous (§6.5). A conclusion that needs
  two facts is not filed by `local` or `ssh` (§2.1, model.md §1).
- Deterministic, auditable command surface. Every command executed on the target comes
  from a compiled catalog, is logged, and is reproducible.
- **Operator context as a first-class input.** The operator can hand `scheck` their
  architecture notes, expected services, exposure and accepted risks so findings are
  specific to the host's actual role rather than to a generic checklist (§5).
- **Inference stays behind one interface (model.md §1).** A `local` or `ssh` run does
  not build a provider; only the hidden `scheck eval` does.
- **Stable severities.** The same host with the same context yields the same severity
  for the same finding id, regardless of provider or run (§6.2).

**Non-goals (host collector)**

- No remediation, no config writes, no package installs.
- No network/perimeter scanning of *other* hosts (no nmap-style behaviour). Web,
  domain, cloud and SaaS assessment belong to other collectors under [scope.md](scope.md).
- No CVE database or vulnerability-scanner replacement. `scheck` reports "23 security
  updates pending", not per-CVE analysis.
- No fleet orchestration, no server, no agent daemon. One host per invocation.
- No Windows.
- No fine-tuning, no bundled model weights, no embedded vector store.
- No additional production adapters, tool-call emulation, guaranteed local-only AI
  mode or small-context chunking in this build (model.md §3–§5).
- No free-form command composition by the model. If a check is not in the catalog, the
  model cannot run it; adding a check is a code change with a test.

**What "read-only" means exactly.** scheck changes no configuration, package, unit,
credential or security state. Three of its commands leave a record of their own
invocation, all of it runtime or cache state. They are listed rather than qualified
away, because a promise with an unstated exception is worse than a narrower promise:

| Cause | Artefact | Why it cannot be avoided |
|---|---|---|
| `pkg.dnf_check_update` (`dnf -q check-update`) | dnf4: `/var/tmp/dnf-<user>-<random>/` (metadata, `*.solv`, four logs, a lock dir); dnf5: `~/.cache/libdnf5/` and `~/.local/state/dnf5.log` | `--cacheonly` still creates the directory and writes its logs, and pinning `cachedir`/`logdir` at the system paths fails with `Permission denied` *and* creates the directory anyway. The write is structural to dnf, not a missing flag. |
| Elevation (`sudo -n --`) | `/run/sudo/ts/<uid>` | sudo records its timestamp before running anything. Only with `--sudo`. |
| `fw.ufw` (`ufw status verbose`) | `/run/ufw.lock` | ufw takes its lock to read status. Only with `--sudo`. |

`test/integ` asserts this set exactly: after a full run the container diff may contain
an ssh login's own noise and these named paths, and nothing else. Any other write fails
the test. That is what makes the claim checkable rather than aspirational. Adding a
fourth artefact needs a decision recorded here, not a wider tolerance.

---

## 2. Architecture

A `local` or `ssh` run is phase 1 only (§2.1):

```
  cmd/scheck
        │
        ├── config            narrows only (§8)
        ├── target.Target     Exec(ctx, argv); Platform()
        │     ├── local       os/exec, argv only, no shell
        │     └── ssh         one session per Exec; canary first (§4.3)
        ├── check catalog     the only command surface (§3)
        ├── policy            paths, redaction, budgets, audit (§4)
        ├── runner            the only exec path
        ├── baseline          plan, fact sheet
        ├── finding           posture rules, then the grader (§6)
        ├── operator          context grades findings (§5)
        └── report            text and JSON (§6.4, §6.6); state dir
```

Phase 2 (`llm`, `agent` and its three tools, `internal/eval`) is in the tree and off
this path (model.md). `internal/bounded` is the research arm (bounded.md). SARIF is
not a renderer in this build (§7).

### 2.1 Two-phase execution — the core design decision

**Phase 1 — deterministic baseline (no model involved).** The per-platform *baseline
set* of catalog checks runs and produces a structured *fact sheet*. This is cheap,
reproducible, cacheable, and diffable between runs.

**Phase 2 — agentic reasoning** hands the fact sheet to a model, which may request
*additional* catalog checks and report findings (model.md). Both phases execute through
the same catalog, the same policy, and the same audit log; there is no second command
surface. Both call the runner by catalog ID; no exported execution method accepts a
check definition. The runner owns the run's observation store. The baseline fact sheet
retains its check-ID index for single-fact rules and shares the store with phase 2 and
report construction.

**Phase 1 also judges what needs no judgement.** A small table of *posture rules*
(§6.5) runs over the fact sheet and emits findings for facts whose meaning is
unambiguous: FileVault off, SIP disabled, `PasswordAuthentication yes`, an account with
an empty password. Rules never execute anything; they read facts the checks already
produced. Their findings are the floor: phase 2 can add to them and enrich them, never
remove or soften them. The phase 1 report is written for a person (§6.6), so
`--stop-after facts` is a complete tool, not a debug dump.

**Decision: `scheck local` and `scheck ssh` assess with the posture rules alone.**
The phase 2 evaluation failed its frozen criteria (`docs/eval/phase2-criteria.md`,
`docs/eval/phase2-results.md`), so no model assesses a host. These commands build no
provider, need no credential, and send nothing a check observed off the machine. The
flags that select a model (`--provider`, `--model`, `--base-url`, `--effort`,
`--transcript`, `--max-context`) exit 3 on those commands, and the same keys in a
configuration file are unused. Operator context, the grader and the finding store
still grade what the rules produce.

The model half stays in the tree, reachable only from the hidden `scheck eval`, which
runs against fixtures and owns the provider pre-flight (model.md). The report envelope
keeps its phase 2 fields (§6.4) because the harness still produces them; no `local` or
`ssh` path fills them. Reviving phase 2 on a host run means a new record that passes
those criteria, not a spec edit.

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
    Elevated    bool            // needs elevation (§7.1); otherwise "unavailable: requires elevated read"
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
line (§6.6), a posture rule (§6.5) or `scheck diff` (§6.4). Everything else stays
`lines` or `kv`, and `Unit` names what one record is, so the summary reads "0 SUID
files" and "13 settings" rather than "0 lines" and "13 keys"; the catalog test requires
`Unit` on every `lines` and `kv` check, and rejects one on a typed shape (§11).

A typed parser produces `check.Records`: `{kind, items, partial, note}`, where each item
is a record of named fields. `partial` is set when the capture carried a redaction or
truncation marker, or a line the format's parser did not recognise. Completeness travels
with the records because §6.5 needs it — a rule may prove an existential condition from
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

**Why a catalog and not an allowlist over argv.** Validating composed argv with
regexes is the part of a boundary most likely to be wrong. A closed set of templates
with typed holes removes that validation entirely, and picking from a menu is easier
for a model than composing a command. The cost is that no novel command can run.

### 3.1 Observations: evidence from an invocation

A check ID identifies a definition; an `observation` reference identifies one immutable
invocation/result within a run. The runner assigns references (currently
`<check-id>#<per-check-occurrence>`, or `unknown#<n>` for unknown IDs); consumers treat
them as opaque and never join them across runs. `occurrence` records collection order.
Each record retains the redacted requested check ID and parameters, resolved definition
(`ran_as`) when known, typed argv when binding succeeded, and the outcome. Denial or
unavailability does not imply validation or execution: `attempted` states whether an
exec was attempted. Metadata substitutions retain the requested ID and actual argv.
Internal realpath/availability probes also have observations, without changing command
order. SSH connection canary verification remains a transport prerequisite (§4.3).

The runner retains copies; callers cannot mutate stored evidence. A later invocation,
even with identical parameters, cannot replace an earlier capture. Both phases share
this store. Existing baseline selection, per-check output and agent check/time/input
budgets bound collection; references do not permit silent eviction or increased limits.
Request metadata and diagnostics pass through policy redaction before audit, storage,
return or logging. No application binding or plugin registry is introduced here.

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
- Traversal (`..`) is rejected at the charset level, and the decision is made on the
  resolved path (below). On macOS `/etc`, `/var` and `/tmp` resolve into
  `/private`, so the runner maps `/private/etc/...` back to `/etc/...` before the
  decision (`policy.Canonical`, macOS targets only): an allowed prefix still allows,
  and a sensitive file cannot escape its pattern by its canonical spelling.

The deny list is compiled in. Config may add to it (`deny_paths:`), never remove.

**Metadata-only mechanics.** `PathPolicy.Decide(resolved)` returns `allow`,
`deny(rule)` or `metadata-only(rule)`. The runner resolves a `Path` param with the
`fs.realpath` catalog check on the target before deciding, so a symlink from an allowed
prefix into a sensitive file is judged by where it points. Under `metadata-only`, a check declared
`PathUse: content` is rewritten to the platform's `fs.stat` check and the result is
tagged `reason: metadata-only:<rule>`; the audit line records the substituted argv.
This is how the baseline learns `/etc/shadow`'s mode and owner without ever reading it.

### 4.2 Redaction

Every byte of check output passes the redactor before the model, the report, the audit
log, or any transcript sees it. Rules: private-key blocks, `AKIA…`-style keys, bearer
tokens, `password=`/`secret=`/`token=` values, from 0.0.2 E4 a JSON key/value rule
(`json-secret`) and Google, Stripe, npm and Slack webhook shapes (`scope.md`,
"Responses"), and a config-extensible regex list (`redact_extra:`). The key/value rule keeps trivial values (`password=no` is a setting;
the list is host output's only: a JSON value the scope gate reads keeps far fewer, see
`scope.md`, "Responses")
and skips the sudoers tags `PASSWD:`/`NOPASSWD:`, whose value is the granted command:
redacting it would hide exactly what a sudoers reading has to judge.

**Redactions are marked, not silent.** A redacted span is replaced by
`[REDACTED:<rule>:<n bytes>]` so the model knows something was there. This is the same
contract as truncation (`[TRUNCATED:<n bytes>]`): the model must never reason from
absence, and a silent redaction would create exactly that.

Base64 is redacted only inside a matched key or token context, never as a bare blob:
a size-based rule would remove certificates and plist payloads that are evidence.

**Redact, then truncate.** The runner captures up to `PerCheckOutput` plus a 4 KiB
slack window, runs the redactor over the captured bytes in a single pass over the
original input (so a marker is never re-matched by a later rule), then cuts at
`PerCheckOutput` with `[TRUNCATED:<n bytes>]`. A cut never lands inside a marker, its
opening `[REDACTED:` included. A
secret straddling the cap is therefore replaced before the cut instead of leaking a
prefix. When the target stopped the capture at the slack window's end, the window's
last 4 KiB may hold the start of a secret whose end was never read, which no rule can
match: nothing derived from them is kept, even when redaction elsewhere (a private key
becoming a short marker) brings the output under the cap (0.0.2 E4, shared with the
scope gate through `policy.Redactor.Finish`). Nothing downstream (report, audit log, persisted run, `-vv`) sees
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
- **Jump hosts (0.0.2 E1c).** A host may be reached through one SSH hop
  (`engagement.md`, "Jump hosts"). The hop's key is verified the same way, before any
  connection to the host is made through it; the hop only forwards one TCP connection,
  so no command, session or canary runs on it, and the canary is still the first
  command on the host's own session. Quoting and the catalog are unchanged.
  Authentication is an `--identity` file or the `SSH_AUTH_SOCK` agent; password
  authentication is not offered.

Local and SSH have the same UX and catalog, but the SSH boundary rests on quoting plus
a runtime check, not on the absence of a shell.

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

Every runner invocation, including denials, is written to `--audit-log` as JSONL with
its observation reference, check id, bound
parameters, resolved argv, decision (`run | denied:<rule> | unavailable:<reason>`),
exit code, duration, and output hash. A denied call returns an error `tool_result` to
the model naming the rule — never a silent drop. Phase 1 writes the same lines; the
canary appears as `run` or `denied:canary`, and a metadata-only substitution records
the `fs.stat` argv that actually ran. A host reached through a jump host has `via:
user@address:port` on every line (0.0.2 E1c); the hop never appears as a target.

---

## 5. Operator-supplied context

A generic host audit produces generic findings. `0.0.0.0:5432` is low-signal noise on a
box behind a strict security group and critical on an internet-facing host. Operator
context is the single highest-leverage input to precision, so it is a first-class
feature rather than a flag.

### 5.1 Sources

> **Superseded in 0.0.2 (ROADMAP E1b, E2).** `scheck run` reads a host's context from
> its asset entry only (engagement.md, "Host context"); `--context`, the implicit
> sources and `target:` go with `scheck local` and `scheck ssh`.

All sources are given with one repeatable flag, `--context SOURCE`, where `SOURCE` is:

| Form | Meaning |
|---|---|
| `FILE` / `DIR` | Markdown or plain text; a directory is read recursively for `*.md`, `*.txt`, `*.yaml`. |
| `note:TEXT` | Inline prose. |
| `target:PATH` | A file on the *target* (default `/etc/scheck/context.md` when `target:` is given bare). Lets a host describe itself in a fleet. Read through the normal path policy. |

Plus two implicit sources: the `context:` block in `scheck.yaml` (§5.2), and
`./.scheck/context/**`. Nothing else is read implicitly: `SECURITY.md`,
`ARCHITECTURE.md`, ADRs and runbooks are useful input but must be named, so a run is
never silently influenced by a file the operator forgot about. Inside an engagement
neither implicit source nor `target:` is read: the host's context is the four fields of
its asset entry (`engagement.md`, "Host context").

**Merge semantics are defined per kind, not by order:**

- **Structured** (`context:` blocks in yaml files, in any source) are merged as maps;
  a later source overrides an earlier one *per key*, and lists (`expected_services`,
  `accepted_risks`) are concatenated and deduplicated by their natural key.
- **Prose** (everything else) is never merged. Each piece is passed through verbatim
  under a heading naming its source, in the order given. A YAML source that carries
  keys beside `context:` contributes those keys as prose, so nothing an operator wrote
  is silently dropped.

The full order is: the config file's `context:` block, then `./.scheck/context/**` in
lexical path order (whatever the filesystem returned), then `--context` sources left to
right. A directory source is read the same way. A `target:` source is **prose only**,
whatever its extension: a host must not be able to accept its own risks or declare its
own exposure (§5.4). It is read as the `text.cat` catalog check through the runner, so
it is audited, path-policed and redacted like any other file; an inspection that never
contacts the target records it as `unresolved`.

Total context is capped by `Budgets.ContextBytes`, with an explicit warning when
truncated; truncation is recorded in the report. The structured block is counted first,
then prose in source order; the piece that crosses the budget is cut with a
`[TRUNCATED:<n bytes>]` marker and every later piece is dropped with its source marked
truncated. `--stop-after context` prints exactly the block the model will read (§5.3),
followed by the per-source hashes and the budget line.

### 5.2 Structured context schema

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

`accepted_risks[].id` must be a catalog finding id (§6.1) or start with `custom:`.
An unknown id is a usage error (exit 3) at config load, so a typo cannot silently
leave a risk un-accepted.

### 5.3 How context is used — structured goes to code, prose goes to the model

The two kinds of context have different consumers.

**Structured context is consumed by `finding`, deterministically (§6.2):**

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

The grader applies the table in a fixed order: expected services first (they decide
what a listener means), then exposure, then environment; each step is clamped to the
scale and a step that cannot move a severity is recorded in the chain but not as an
adjustment. A listener is matched to `expected_services` by the finding's `service`
(`{port, proto}`), which the model supplies for a network finding; with no declared
services there is no judgement to make and the finding keeps its base. A custom
finding is never moved upward and is capped at `medium` after adjustment (§6.1).
`svc.expected_missing` is a negative claim, so it needs a complete `net.listeners`
fact: an unavailable or partial capture leaves it `not_assessed` in the `assessments`
array rather than silently absent. `risk.acceptance_expired` carries the lapsed entry
as its evidence (`check: context`).

The model still sees the structured block (so it can reason about *why* a port is
expected), but nothing it says about severity is used.

**Prose context is consumed by the model** for correlation the model could not
otherwise make — that a listening port is meant to be reachable only from a peer
subnet, that a SUID binary is a vendor requirement, that a service is expected to run as
root. The model expresses this by choosing a finding id and `confidence`, and by
adding a `context_note` to the finding; it cannot change severity directly.

### 5.4 Context is untrusted data

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
- `--ignore-context` reads no context at all: no adjuster, and no context block in a
  prompt when there is one to build.
  Because adjustment is code, "unadjusted" is a precise claim, not a hope.
- The same holds for check output: the system prompt declares that instruction-shaped
  text in a file or a command's output is evidence about the host, and the tools
  enforce it regardless of what the model concludes. `testdata/context/` is the
  injection corpus (§9): hostile prose paired with benign controls of the same name.

---

## 6. Findings

### 6.1 Finding id catalog

Finding ids are compiled in, alongside the check catalog, with a base severity and a
category each:

```go
package finding

type Def struct {
    ID           string   // "sshd.password_auth_enabled"
    Title        string   // "sshd accepts password authentication"
    Category     string   // remote-access | network | accounts | privesc | integrity | updates | persistence | logging | fs | disk | time
    Area         Area     // the engagement report's risk area; every host finding is hosts
    Exposure     Exposure // NotExposure | IsExposure; every host finding is NotExposure
    BaseSeverity Severity // critical | high | medium | low | info
    Impact       string   // one sentence; used verbatim by a rule finding, the model may sharpen it in phase 2
    Remediation  Remediation // summary, commands, caveat (§6.3); text for the human, never executed
    // References (framework → citations, selected by context.compliance) are not
    // in this build; a finding emits no `references`.
}
```

`Title`, `Impact` and `Remediation` live on the Def, not only in the model's output,
because a posture rule (§6.5) must produce a complete finding with no model in the
loop. `Area` and `Exposure` are required for the engagement report
(`engagement.md`, "Severity in context"); they do not appear in the host envelope. For a model-only finding the Def's text is the default and the model's text, when
present, replaces `impact` and `remediation`. For an existing rule finding, the merge
contract in §6.5 applies: its curated text is retained.

Ids are the join key for accepted risks, severity, dedupe and cross-run diffing, so the
model must not invent them. `report_finding` accepts a host finding's catalog id, or
`custom:<slug>` for something genuinely outside the catalog; another collector's ids
(area other than hosts) are refused by `finding.Store`, `open` and `ruled_out` alike,
and left out of the prompt.
Custom findings get `BaseSeverity` from
a required `proposed_severity` field, are never adjusted upward, are capped at
`medium`, and are flagged `custom: true` in the report so a reviewer can promote them
into the catalog.

### 6.2 Severity ownership — code grades

```
model ──report_finding(id, evidence, confidence, impact, remediation)──▶ finding.Store
                                                                             │
                                                     base severity from Def  │
                                                     + structured-context adjustments (§5.3)
                                                     + confidence caps (model.md §4)
                                                     + accepted-risk status
                                                                             ▼
                                                                      report + exit code
```

Severity in the model's hands is unrepeatable, unattributable, and unverifiable. In
code it is a table and a test.

Classification itself has two sources. Posture rules (§6.5) classify facts whose
meaning is unambiguous, in phase 1, with no model. The model classifies everything that
needs judgement or more than one fact, in phase 2. Both enter the same `finding.Store`
and the same grader; a finding never bypasses the table because of where it came from.
A `local` or `ssh` run uses the posture rules alone (§2.1), so a conclusion that needs
two facts is not filed.

### 6.3 Finding schema (as emitted in the report)

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
    {"check": "sshd.config", "observation": "sshd.config#1", "excerpt": "passwordauthentication yes"},
    {"check": "net.listeners", "observation": "net.listeners#1", "excerpt": "tcp LISTEN 0 128 0.0.0.0:22"}
  ],
  "impact": "Internet-reachable sshd allows online password guessing.",
  "context_note": "Operator notes say this is the public jump host.",
  "remediation": {
    "summary": "Set PasswordAuthentication no and rely on key auth.",
    "commands": ["# review first", "sudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config", "sudo sshd -t && sudo systemctl reload sshd"],
    "caveat": "Confirm at least one working key-based login first."
  }
}
```

The model supplies `id`, `title`, `confidence`, `evidence`, `impact`, `context_note`,
`remediation`, and for a network finding `service: {port, proto}`. `scheck` supplies
everything else, including `accepted_reason` (with `status: accepted`) and
`custom: true` on a `custom:` finding. `severity`:
`critical|high|medium|low|info`. `confidence`: `high|medium|low`. `status`:
`open|accepted`. `source`: `rule|model` (§6.5); for a rule finding `title`, `impact`
and `remediation` come from the Def, `evidence` is the check id, observation reference and matched
excerpt, and `confidence` is always `high`. Remediation commands are **text for the
human** — `scheck` never runs them.

### 6.4 Report envelope and run artifacts

The JSON report is shaped so that a future aggregator can concatenate reports without
a translation step, even though the collector audits one host per invocation. The
shape is `docs/report-schema.json`, which tests validate the emitted envelope against.
The rules below are the ones the schema does not state by itself.

`host.id` is a hash of the machine id (Linux) or platform UUID (macOS). It is stable
across runs and hostname changes, and it is the key a fleet aggregator or a drift
diff would join on. A `local` or `ssh` report sets `run.mode` to `facts` and
`run.assessment` to `rules`, and leaves the provider block empty (§2.1). `summary`
is the one-line reading of a fact (§6.6): the same string on the screen, in the JSON
and in a model prompt. Findings are a flat array keyed by catalog id, never nested
under a host, so concatenation is trivial. `parsed` is `{kind, items, partial}` (§3).

`"none"` remains the value of `run.assessment` for a build or a mode that assessed
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

`observations` is keyed by run-local reference and includes baseline, prerequisite,
context-collection and agent invocations. Every target-derived evidence entry and
assessment that read an outcome refers to this map; `facts.<id>.observation` names the
baseline occurrence, even after a follow-up read. Assessments with no observation name
why in `reason` (for example disabled or not run). Context-only expiration findings
cite `check: context` with their source excerpt and have no target observation.
Finding-ID merges deduplicate by observation, check and excerpt, retaining distinct
occurrences. Emitted and persisted envelopes retain observation metadata, outcomes and
summaries; `parsed` lives in `facts` only, since in `observations` it would duplicate
the baseline facts and, for a file read through a raw parser, would carry the whole
capture that default JSON and persistence omit by policy. Raw stdout/stderr remain
omitted by default. Opt-in `--include-evidence` adds captures to observations as well
as baseline facts.

`run.context_sources` is one entry per source: kind
(`config|implicit|file|note|target`), byte count, sha256 and truncated flag, with
`unresolved` when a `target:` source was not read. A phase 2 envelope, which only
the harness produces (§2.1), fills the provider block and `run.agent`, including
`ruled_out` (model.md §8), sets `run.mode` to `agent` or `single-pass` and
`run.assessment` to `agent`, and may carry `source: model` findings.

**Compatibility.** The first GitHub release (v0.0.1) established the supported
contract. `schema_version` is `MAJOR.MINOR`: additive changes bump MINOR; renames,
removals and field type changes bump MAJOR. Readers reject an unrecognized MAJOR rather
than guess at an unsupported shape. The release notes identify the schema version
shipped. Update the spec, implementation, `docs/report-schema.json` and fixtures
together when a change is implemented.

**Persistence.** *From 0.0.2 (E2) nothing is written under `runs/<host.id>/`: the
envelope is the host asset's evidence file in the engagement's run directory
(engagement.md, "Runs, state and configuration"). As built in 0.0.1:* every run wrote this envelope to
`<state-dir>/runs/<host.id>/<started>.json` (default state dir
`~/.local/state/scheck`, or `$XDG_STATE_HOME/scheck`; `--state-dir` overrides,
`--no-persist` disables). Persisted files pass the same redactor as the report. The
`facts` block is what makes posture drift diffable. `scheck diff` is not in this build;
as planned it compares the two most recent runs for a host (or two named files): added
and removed listeners, units, SUID files, and findings that appeared, disappeared, or
changed severity. Typed `parsed` shapes (§3) make that a set difference per record
kind rather than a line diff.

### 6.5 Posture rules — deterministic findings from the fact sheet

A posture rule turns one fact into one finding when the fact's meaning needs no
judgement.

```go
package finding

type Rule struct {
    Finding  string         // finding id (§6.1); the Def supplies title, severity, impact, remediation
    Check    string         // the one check whose fact the rule reads
    Platform check.Platform // macos | linux | any
    When     Predicate      // KeyEquals{Key, Value, Known} over kv
                            // RawMatch{Regexp, Requires} over raw
                            // AnyLine{Regexp} over lines
                            // FieldEquals{Field, Value, Known}, FieldOutside{Field, Allowed,
                            //   Recognize}, AnyRecord{} over a typed shape
}
```

A predicate answers `matched`, `not_matched` or `not_assessed` — never a boolean. The
recognizability fields (`Requires`, `Known`, `Recognize`) are what make the third answer
possible: a value the rule does not understand, a missing key, a redacted value or a
truncated capture is `not_assessed`, never a pass.

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
  an `assessments` entry (§6.4), identified by finding id and check id, with the observation read (if any), a reason
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
  evidence is the check id, exact observation reference and matched excerpt, and the severity goes through §6.2,
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

Seed table. Base severities are the §6.1 table entries for these ids:

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
assessed by the off rule.

`pkg.*` above is four rules, one per concrete catalog id, not a wildcard execution or
lookup mechanism. Several rules may share one finding id; the evaluator emits that
finding once and appends each matching rule's evidence.

`fs.suid` deliberately has no rule: SUID files are normal, and which ones are not is
judgement. The same applies to listeners, persistence entries and sudoers content.

### 6.6 Text report — what a person sees

> **Retired in 0.0.2 (ROADMAP E2).** The engagement report replaces it; the JSON
> envelope (§6.4) stays, as the host asset's evidence file in the run directory, and
> `runs/<host.id>/` persistence stopped. The fact table survives as the fact sheet the
> engagement report prints per host at `-v` (descriptions) and `-vv` (redacted
> captures), pinned by `internal/report/testdata/golden/*-facts-*.txt`; the status-word,
> escaping, width and colour rules below apply to it. The rest records 0.0.1.

`--format text` is the product for anyone who runs `--stop-after facts`, so it has a
contract, pinned by golden tests per fixture (§9):

- **Header, two lines.** Who was audited and how (hostname, OS, transport, elevation),
  then the result in one sentence that leads with the findings: "2 findings (1 medium,
  1 low), 4 rules not assessed, 28 checks: 22 ran, 6 skipped", or "0 findings from
  posture rules", never "no findings". `host.id`, profile, mode, kernel and timings
  move to `-v`.
- **Findings first, then facts.** Rule findings (and, in phase 2, model findings) come
  before the fact sheet, ordered by severity: title, severity, the evidence excerpt with
  its check id and observation reference (so repeated invocations can be told apart;
  context-only evidence keeps its context label), the remediation summary.
  Not-assessed assessments close the section, grouped by check and reason; they are
  excluded from finding counts.
- **Status words, not marks.** A check `ran`, was `skipped` (unavailable) or was
  `denied`. A mark column may exist for scanning, but a mark never means "posture ok":
  a fact whose rule fired shows the finding's severity in its reading
  (`[finding: high]`), not a plus.
- **The fact sheet is one flat table**, header row `DOMAIN STATUS CHECK READING`, one
  row per check, rows ordered by domain and then id. Every row repeats its domain so the
  report sorts, greps and pipes as a table; there are no section sub-headings and no box
  drawing. Columns are sized from the data (domain capped at 24, check id at 30) and the
  READING column wraps into continuation rows aligned under it, never truncating a
  reason. Findings (§6.5) are rendered above the table, not inside it.
- **One meaningful summary per check.** From the typed parser or `Unit` (§3): "26
  listening sockets", "0 SUID files", "FileVault is On.", never the first raw line. The
  same string is `summary` in the envelope (§6.4).
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
  full stdout and explain the restriction. Captures are opt-in diagnostics: `-vv` and
  JSON `--include-evidence` render only the runner's redacted, bounded capture after
  catalog extraction, default JSON and persisted runs omit them, and pre-redaction
  bytes never leave the runner (§4.2, §6.4).
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
- **Honest footer.** With no phase 2 in the report: "assessment: posture rules only",
  with how many of the selected rules had the evidence to decide, and "The agentic pass
  did not run." The renderer reads the envelope, so it says that the pass did not run
  and never why; for `local` and `ssh` the reason is always that no model assesses a
  host (§2.1). Never "findings: none" when nothing looked, and never a claim that what
  no rule covers is fine.
- **Width.** Lines wrap at the terminal width or 100 columns; no trailing padding.
  Wrapping prefers a space, falls back to a hard cut rather than dropping a byte, and
  never breaks a `[REDACTED:…]` or `[TRUNCATED:…]` marker in half: the marker is the
  only record that bytes were removed (§4.2). A hanging block counts its own prefix, so
  a wrapped reason or remedy cannot overrun. The table's fixed columns set a floor below
  which the layout cannot shrink.

---

## 7. CLI

> **Superseded in 0.0.2 (ROADMAP E2).** `scheck local` and `scheck ssh` are aliases of
> `scheck run --host` for 0.0.2, print a deprecation line, and are removed in 0.0.3; the
> flag mapping is in engagement.md, "One command, one file" (`--context`,
> `--ignore-context`, `--audit-log` and `--stop-after plan` exit 3 naming their
> replacement). `catalog`, `explain`, `sudoers`, `providers` and the exit codes stay;
> `config` was removed with §8. The block below records 0.0.1.

```
scheck local                            # audit this machine: facts + posture rules, no model (§2.1)
scheck ssh user@host [--port] [--identity]
scheck catalog [--profile P]            # list every check the model could run under profile P
scheck sudoers [--platform P]           # print a least-privilege NOPASSWD rule for elevated checks (§7.1)
scheck explain ID                       # CHECK-ID: what a check runs, why, its parser and which posture rules read it
                                        #   (purpose, literal argv with its {placeholders}, typed params,
                                        #   platform, domain, phase, elevation, parser, exit codes, path
                                        #   use, extract; one section per platform-specific definition.
                                        #   Lists the posture rules that read the fact.)
                                        #   FINDING-ID: the severity chain — base, context adjustments,
                                        #   confidence cap, accepted-risk status, final (§6.2). Accepts the
                                        #   §5.2 structured keys as flags (--exposure, --environment) so an
                                        #   adjustment can be reproduced without a run.
scheck providers                        # configured providers, limits, native features
scheck config show|validate             # effective settings with provenance; validate exits 0|3 (§8)
scheck diff [A B]                       # posture drift between two runs; not in this build, exit 3
scheck --format text|json|sarif  --out FILE    # sarif: not in this build, exit 3
       --include-evidence             # JSON facts only: optional redacted diagnostics
       --profile baseline|hardened      # severity thresholds + catalog tier (§3)
       --elevate none|sudo  (--sudo)    # elevation mechanism (§7.1)
       --only remote-access,updates     # category filter; not in this build, exit 3
       --provider openai-compatible      # anthropic / ollama registered, exit 3; mock for tests
       --model NAME  --base-url URL     # model defaults to gpt-5.6-luna on OpenAI's endpoint
       --local-only                     # not in this build, exit 3 (model.md §5)
       --effort low|medium|high|max
       #   the six model flags above (--provider, --model, --base-url, --effort,
       #   --transcript, --max-context) configure `scheck providers` and the
       #   evaluation harness. On local and ssh they exit 3: no model assesses a
       #   host in this build (§2.1)
       --context SOURCE                 # repeatable: FILE | DIR | note:TEXT | target[:PATH]  (§5.1)
       --ignore-context                 # no severity adjustment
       --stop-after context|plan|facts  # print merged context / phase-1 plan / fact sheet, then exit
       #   facts is what a run does anyway in this build; the flag stays because
       #   context and plan stop earlier and because a later build has a stage after it
       --audit-log PATH
       --state-dir PATH / --no-persist  # run artifacts (§6.4)
       --timeout 5m
       -v / -vv
```

**Machine-readable use.** `catalog`, `explain` and plans honor `--format json` and
`--out`. Discovery has its own `schema_version` and `kind` (`catalog|explain|plan`),
`scheck_version`, platform, and a `checks` array. Entries expose argv arrays, typed
params, parser, profile, elevation, accepted exits, path use, extraction, canary and
budget overrides (milliseconds/bytes, zero means policy default). `any_exit` represents
the wildcard exit contract without exposing an internal sentinel. `scheck explain
FINDING-ID` uses `kind: finding` with the severity chain as an ordered array of
`{stage, from, to, reason}` steps rather than a `checks` array. Unsupported formats
fail explicitly. Facts JSON goes to stdout, diagnostics to stderr; `--out` redirects
the document. Help includes supported invocations and labels future flags unavailable.
See the [scheck skill](../../.agents/skills/scheck/SKILL.md) for examples, exit-code
interpretation, diagnostics and the SSH planning limitation.

`--stop-after plan` prints the phase 1 check list without running the baseline or
contacting a model. Local planning executes no target commands. In the current SSH
implementation, planning connects, verifies the canary, and detects the platform
before printing the plan. For connection-free discovery, use
`scheck catalog --platform linux|macos --format json`; this lists the platform catalog,
not the configured target's exact plan. Plans cannot show phase 2 commands, which the
model chooses at run time.

A run needs no API key: it loads the operator context, runs phase 1 and assesses the
facts with the posture rules (§2.1). `--stop-after facts` is the same run named
explicitly; `context` and `plan` stop earlier. A model flag on `local` or `ssh` exits 3
with nothing executed. The text report closes with what assessed the host (§6.6). The
phase 2 wording it can also print ("posture rules and
the agent pass (provider, model; turns, model-initiated checks, tokens)", and why the
pass did not finish) belongs to the evaluation harness's envelopes, and `-v`/`-vv`
still show tool calls and streamed model text there. `-v` and `-vv` govern both
logging and how much of the text report is shown (§6.6).

Exit codes: `0` no open finding at or above the profile threshold · `1` findings present ·
`2` run incomplete (check/agent/transport failure, budget exhausted) · `3` usage or policy
error (including a failed SSH canary, an unknown host key, or an unknown accepted-risk id).
One meaning per exit code, whichever phase produced it.

Profile thresholds: `baseline` fails on `medium` or higher; `hardened` fails on `low`
or higher. `info` findings remain visible but never trigger exit `1`. Thresholds select
the exit result, not which findings are displayed. Exit `3` takes precedence over `2`,
which takes precedence over `1`, then `0`.

The findings of a `local` or `ssh` run are the posture rules' (§6.5): `run.assessment`
is `rules`, `findings` holds the rule findings, and `assessments` records every
selected rule's coverage. The run exits `1` when a finding is open at or above the
profile threshold and `0` otherwise (individual `unavailable` checks do not change
that), `2` when the transport failed or `RunTimeout` cut the run, `3` for usage, config
or canary errors. A session lost mid-run (an exec whose command could not be sent or
whose exit status never came back, including an availability probe's) stops the plan
there: the facts read before it are kept, the run is `incomplete` with a warning that
names the failure, and it exits `2` (0.0.2 E1b; before it, every later check read as
`unavailable` in a run that still said `complete`). A canary mismatch error quotes the
remote shell's echo only after redaction, cut to 120 bytes. Exit `0` means no open finding reached the profile threshold — not
that the host is well configured, and not that everything was assessed; consult
`assessments`, `run.status`, warnings and each fact. JSON reports may accompany exit
`1` and `2`; early setup/usage failures may have no report.

Flags reserved for a later build are registered and exit `3` with "not available in
this build".

### 7.1 Elevation

Some checks (`sshd -T`, `/etc/sudoers`, `/etc/shadow` metadata) need root. Elevation is
opt-in, only ever widens *read* access, and is a **prefix** prepended to the check's
argv; the catalog invariants apply to the full argv after the prefix.

`--elevate` / `elevate:` values:

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
or a custom prefix later without touching the catalog or the loop; they are not in
this build, and no password-forwarding mode is offered.

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

## 8. Configuration

> **Removed in 0.0.2 (ROADMAP E1b, E2).** scheck reads no configuration file:
> `internal/config`, `scheck config` and `docs/CONFIGURATION.md` are gone. Each key below
> has a home in the engagement file or a flag (engagement.md, "One command, one file");
> a file found where this section reads one makes `scheck run` and its aliases exit 3,
> naming where each key moved. The model keys are flags on `scheck providers` and the
> hidden `scheck eval`. The narrowing semantics below are what the engagement's
> `disable_checks`, `deny_paths` and `redact_extra` keep; the rest records 0.0.1.

Precedence, lowest first: built-in defaults → the OS user config file → the project
`./scheck.yaml` → flags the operator explicitly set. A flag's registered default never
overrides a file; only a flag that was given counts. The user file is
`$XDG_CONFIG_HOME/scheck/config.yaml` (default `~/.config/scheck/config.yaml`) on
Linux and `~/Library/Application Support/scheck/config.yaml` on macOS
(`os.UserConfigDir`). Scalars override per key; `disable_checks`, `deny_paths` and
`redact_extra` accumulate across files; `targets` merge by name; a later file's
`context:` block replaces an earlier one's whole (per-key merging happens across
context *sources*, §5.1).

```yaml
provider: openai-compatible   # read by `scheck eval` and `scheck providers` only (§2.1)
model: gpt-5.6-luna           # default on OpenAI's endpoint; required for any other --base-url
# base_url: http://localhost:11434    # defaults to https://api.openai.com/v1
# max_context: 128000         # the model's context window when the adapter cannot know it (model.md §4)
effort: high
allow_egress: true            # false exits 3: not in this build (model.md §5)
profile: baseline
elevate: none                 # none | sudo (§7.1)
state_dir: ~/.local/state/scheck
disable_checks:               # may only subtract from the compiled catalog
  - fs.suid_scan
deny_paths:                   # may only add to the compiled deny list
  - /etc/corp-secrets
redact_extra:
  - "internal\\.example\\.com"
targets:
  bastion: { host: 10.0.0.5, user: ops, identity: ~/.ssh/ops }
context: { … }                # §5.2
```

Every config knob narrows: it disables checks, denies paths, adds redactions. No knob
widens what `scheck` may execute or reveal. Credentials come from the environment per
provider (`OPENAI_API_KEY` for `openai-compatible`, model.md §3). Never read a key from
the config file.

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

## 9. Testing

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
- **Golden artifacts.** Three per fixture (ubuntu, fedora, macos), diffed in
  `go test`:
  - the **fact sheet** at default, `-v` and `-vv` under
    `internal/report/testdata/golden/` (`*-facts-*.txt`), what the engagement report
    prints per host (§6.6), re-rendered at several widths to assert no line overruns
    and none carries trailing padding;
  - the **JSON report** beside it, without `--include-evidence`: facts, findings,
    assessment coverage reasons and the observation references between them. The
    committed file is validated against `docs/report-schema.json`, so a golden left
    behind by a schema change fails;
  - the **command trace** under `internal/baseline/testdata/golden/`, the run's own
    audit log: one line per attempted check in execution order with observation
    reference, bound parameters, actual argv, decision, exit code, elevation and the
    SHA-256 of the redacted output. It fails if the tool ever starts running something
    else. Only the clock and durations are normalized; observation references are
    asserted stable across a replay. A baseline plan binds no parameters, so the
    `denied:` format is asserted directly in `internal/runner`.

  `go test ./internal/report -update` and `go test ./internal/baseline -update` rewrite
  the goldens; a diff is a review item, not something to silence.
- **Rule tests.** Table-driven: fact sheet → expected finding ids. Every rule has a
  fixture where it fires and one where it does not, plus unknown, malformed,
  unavailable, denied, redacted and truncated evidence. Test applicability, disabled
  checks, partial positive records and incomplete negative claims. Assert the same
  assessments and finding counts in JSON and text, and profile exit thresholds.
  The catalog invariants test covers rules (§6.5).
- **Severity tests.** Table-driven: (finding id, structured context) → expected
  severity, adjustments and status. `--ignore-context` asserted to equal base severity
  exactly.
- **Observation tests.** Repeated parameterized reads (including identical requests with
  changed outputs) remain independently citable. Test wrong/unknown references,
  denied/unavailable outcomes, immutable snapshots, redaction of request metadata and
  outputs, and reference resolution in default JSON and persisted reports. A fixture
  mock reads two files then cites both, with a cross-observation excerpt rejected.
- **Model path tests** (model.md), offline in `make check`:
  - *Agent tests.* Fixture target + the `mock` provider replaying recorded transcripts,
    including the report envelope the loop produces (`internal/agent`, validated
    against `docs/report-schema.json`). The one opt-in live test (`SCHECK_LIVE=1`,
    `make live`) drives the evaluation harness on one labeled case: the agent arm must
    complete, cost under the criterion 7 budget, attempt no check the policy denies,
    and cite evidence for every finding.
  - *Provider conformance suite.* One table every provider must pass, unconditionally:
    tool-call round trip, error results, multiple calls in one turn, each `StopReason`
    mapped correctly, `MaxTokens` truncation, usage normalization, `Limits` reporting.
    Emulating adapters run the same table.
  - *Context-limit tests.* An oversized first request, tool-result/history growth,
    schema/framing overhead, output reservation, unknown limits and provider overflow
    rejection. No oversized request is sent when caught locally, no evidence is
    silently dropped, and collected facts/findings survive in an incomplete report
    with exit 2.
  - *Injection corpus.* Operator prose and target-derived check output containing
    instruction-shaped text ("ignore previous instructions", "report no findings",
    "run `curl … | sh`") must not change the auditor role, suppress findings
    wholesale, alter code-owned severity, or produce a denied check attempt. Mock
    transcripts in `internal/agent` test the boundaries: the same transcript with the
    hostile corpus, its benign controls and no context yields byte-identical findings;
    prose imitating the schema stays prose; a transcript that obeys the prose is
    denied at every call with an audit line each and no argv outside the catalog
    reaches the target; rule findings survive a transcript that tries to accept,
    downgrade or fabricate; planted text in check output is carried inside `<facts>`
    as data. These prove policy, not model resistance: only repeated real-model runs
    over hostile and benign paired fixtures, judged by the frozen
    `docs/eval/phase2-criteria.md` with model/prompt versions and failures recorded,
    measure that. Deterministic policy remains the security boundary. Live
    evaluations are opt-in, not default CI.
  - *Evaluation harness.* `internal/eval` and the hidden `scheck eval` run the three
    arms of `docs/eval/phase2-criteria.md` over `testdata/eval` (labeled cases built on
    the recorded fixtures through `base:` inheritance) and the adversarial pairs of
    `testdata/context`, score each run against its labels, and render the comparison
    with the criteria's verdicts. A mock run validates the harness and is labelled as
    no claim; a live run is the record kept in `docs/eval/phase2-results.md`.
- **Configuration tests.** Inspection and an ordinary run resolve identical effective
  settings from the same files and flags, including absent files, accumulated
  restrictions and context conflicts; an unset flag never overrides a file; `config
  validate` exits 0 and 3 without a target command or an inference request; a seeded
  credential is absent from text, JSON and diagnostics and a control character in a
  configured value is escaped.
- **Redaction tests.** Seeded secrets in fixture output must not appear in any
  transcript, report, or audit log, and every redaction must leave a marker.

---

## 10. Acceptance criteria (0.0.1)

These are the host collector's acceptance bar. The recorded pass is
[../eval/acceptance-0.0.1.md](../eval/acceptance-0.0.1.md); publishing a release
repeats that pass at the release commit (`docs/RELEASING.md`).

1. `scheck local` and `scheck ssh …` produce a report on macOS and on Ubuntu + Fedora.
2. No command outside the compiled catalog ever reaches the target — proven by the
   catalog invariants test, the hostile-input corpus, and the audit log of a live run.
3. Nothing on the target is modified outside the writes named in §1. The evidence is
   the integration container diff around a full `scheck ssh` run, and on macOS the
   catalog invariants plus the audit log of a real local run. The recorded scope of
   that evidence is `docs/eval/acceptance-0.0.1.md`.
4. `--stop-after facts` is fully useful offline: no API key required, the text report
   follows §6.6, and a fixture host with FileVault off (macOS) or
   `PasswordAuthentication yes` (Linux) yields that finding with exit `1` and no model.
5. Every finding carries evidence traceable to a check id.
6. Seeded secrets never appear in any output artifact, and every redaction is marked.
7. One host run costs under $0.50 at default effort; met because no model assesses a
   host (§2.1), and the bar for any build that reopens phase 2 (model.md).
8. The `openai-compatible` adapter and `mock` pass the provider conformance suite, and
   the context guards hold (model.md §4).
9. Operator context changes the report deterministically: the same host audited as
   `exposure: internet` and as `exposure: lan` yields severities that differ exactly per
   the adjustment table, every adjustment is attributed to its source, and
   `--ignore-context` reproduces base severities byte-for-byte.
10. **Phase 2 earns its cost.** Decided: the rules / single-pass / agent comparison was
    run and failed, so the collector assesses with the posture rules alone (§2.1;
    model.md, `docs/eval/phase2-results.md`).
11. The SSH canary aborts the run against a fish or restricted login shell before any
    other command is sent.
12. Real-model adversarial evaluations pass the frozen criteria before any release
    sends evidence to a model; none does in this build (§9, model.md).

---

## 11. Decisions log

Decisions about the host collector, with the reason. Reopen one only with a reason that
beats the one recorded. Decisions about the model path are in model.md §10.

| Question | Decision | Why |
|---|---|---|
| Shape JSON for multi-host aggregation now? | Yes: `host` identity block with a stable `host.id`, flat findings array, and a `schema_version` field (§6.4). | Costs nothing now; an aggregator concatenates and can reject a version it wasn't tested against. |
| Persist fact sheets for drift? | Persist the full envelope on every run (§6.4). `scheck diff` is planned ([../ROADMAP.md](../ROADMAP.md)). | The format is what is hard to retrofit, not the command. |
| Catalog growth past ~60? | Profile-gated tiers via `MinProfile`; baseline tier capped by test (§3). | Keeps the cheap run's menu small without capping what a hardened audit can do. |
| Custom finding ids? | Kept, capped at `medium`, flagged `custom: true`, never escalated (§6.1). | The model can surface a novel issue without driving exit codes or matching accepted risks by accident. |
| SSH canary fails? | Abort, exit 3, no further command sent (§4.3). | Quoting is the whole boundary on SSH; do not guess around it. |
| Elevation mechanism? | `sudo -n` only, as a prefix, plus `scheck sudoers` (§7.1). Password forwarding and `doas`/`run0` deferred. | Never transmit a password; the prefix design makes the others cheap to add later. |
| Judge anything without a model? | Yes, for facts whose meaning is unambiguous: posture rules (§6.5), one fact → one finding, code-graded like everything else. For `local` and `ssh` that is the whole assessment (§2.1). | A fact sheet that never says a recognized fact is wrong is a debug artefact. A conclusion that needs two facts or judgement is not filed until a later record earns phase 2 back. |
| Exit code of a facts-only run with a rule finding? | `1`, the same table as a full run (§7). | One meaning per exit code; CI can gate on the offline run. |
| Per-check summaries? | Typed parser shapes plus a `Unit` noun on `lines` checks (§3), not a summariser function. | A typed record serves the screen, the model and `scheck diff`, and is diffable; a closure serves one consumer and is not. |
| Standalone commands and `scheck.yaml` after 0.0.2? | Folded into `scheck run`: `--host` is a one-root engagement built in memory, `local` and `ssh` are aliases for 0.0.2 and go in 0.0.3, and every key of `scheck.yaml` moves into the engagement file or a flag (engagement.md, "One command, one file"). | Two pipelines meant two reports, two run histories and two places to declare a host, and only one said what it did not assess. A client's restrictions have to travel with the engagement file; in a per-machine file they vanish when someone else runs it. |
| How does a user or agent inspect captured output? | `-vv` for text; `--format json --include-evidence` for structured facts (§6.4, §6.6). Both use the same redacted, bounded, extraction-filtered capture; default persistence omits it. No `scheck show`. | Humans and agents can diagnose failed checks without a second execution or a second collection path. |
