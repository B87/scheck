# M5.0 — the first application pack

**Status (2026-09-22):** selection frozen. This is the [0.0.2](../ROADMAP-0.0.2.md) M5.0
deliverable: it selects the application, fixes its assessment scope and records the
rejected alternative. Implementation belongs to M5.1/M5.2; nothing here is built yet.

**Selected:** the **`docker` pack** — Docker Engine daemon configuration, assessed from
files only, with no contact with the daemon.

**Rejected:** nginx, on measured evidence (§1.3). The rejection is the more useful half
of this brief, because it establishes three constraints that bind every future pack.

---

## 1. Selection

### 1.1 How this brief was produced

Every claim below about a command's behaviour was measured on a disposable container with
`docker diff`, the same assertion `test/containers` uses for the read-only invariant
(`AGENTS.md`, non-negotiable 1). No candidate command was accepted on reputation.

### 1.2 The three constraints the probes established

These are general, not nginx-specific. A future pack brief must answer all three before
it proposes a command.

**C1 — a daemon's own "dump my config" mode is presumed to write until proved otherwise.**
`sshd -T` is the exception, not the pattern; the pack contract must not be designed
around it. Measured on `ubuntu:24.04`:

| Command | Exit | `docker diff` after |
|---|---|---|
| `sshd -T` | 0 | *(empty)* |
| `nginx -T` (root) | 0 | `A /var/lib/nginx/{body,fastcgi,proxy,scgi,uwsgi}`, `A /run/nginx.pid` |
| `nginx -T` (unprivileged) | 1 | *(no output at all — `open() "/run/nginx.pid" failed (13)`)* |
| `apache2ctl -S` | 0 | `A /run/apache2`, `A /run/apache2/socks`, `A /run/lock/apache2` |
| `nginx -V` | 0 | *(empty)* |

Config parsing initializes runtime state as a side effect. Version/build introspection
(`-V`) does not parse config and is clean. There is no unprivileged escape: `nginx -T`
without root produces zero bytes, so "run it as the audit user" is not a mitigation.

**C2 — `grep -r` silently skips symlinks; `grep -R` escapes path policy.** Measured on
Ubuntu's nginx layout, where `sites-enabled/default` is a symlink into `sites-available`:

```
grep -rH . /etc/nginx | grep -c '^/etc/nginx/sites-enabled/'   ->  0
grep -RH . /etc/nginx | grep -c '^/etc/nginx/sites-enabled/'   ->  81
ln -s /etc/shadow /etc/nginx/sites-enabled/evil
grep -RH . /etc/nginx | grep -c 'sites-enabled/evil'           ->  20   # shadow contents
```

`-r` produced a capture that looked complete and omitted the file holding the server
configuration: a **silent false negative**, the worst outcome this project has. `-R` read
`/etc/shadow` through a symlink planted inside the scanned tree — the runner's realpath and
path policy apply to bound `{name}` parameters, not to files a recursive command reaches
indirectly, so `-R` is a policy bypass and must never appear in a catalog entry.

The existing `privesc.sudoers_d` and `persist.cron` entries use `-r`, which is the safe
half of this pair. The new rule is: **`-r` is permitted only where the layout does not use
symlinks as its enabling mechanism**, and that must be stated in the brief. `-R` is
forbidden outright.

**C3 — one rule reads one observation, so one command must carry the whole subject.**
`finding.Evaluate` reads `in.Sheet.Results[rule.Check]` (`internal/finding/evaluate.go:52`):
the fact sheet holds one result per check ID. A subject spread over N files read by N
invocations cannot be assessed by a posture rule until parameterized planning and
repeated-observation evaluation exist — which is M5.2a's and a later slice's work, not a
pack's. Combined with `PerCheckOutput = 64 KiB` (`internal/policy/budgets.go:31`), the
requirement is: **the assessable configuration must fit in one command's capture, under
64 KiB, with no symlink traversal.**

### 1.3 Candidates

| | **Docker (selected)** | nginx | Next.js as the pack | PostgreSQL / MySQL |
|---|---|---|---|---|
| Evidence under existing path policy | `/etc/docker`, `/etc/systemd/system`, `/etc/group` — all allowed today | `/etc/nginx` allowed | no config to read; `next.config.js` is code and outside `/etc` | effective settings need a DB session |
| C1 (read-only) | `cat`/`grep`/`getent` only, **no daemon contact** | `-T` writes; `-V` clean but carries no policy | n/a | n/a |
| C2 (symlinks) | drop-ins and `daemon.json` are real files | **enabling mechanism is symlinks** on Debian | n/a | real files |
| C3 (one capture) | yes, per check | Fedora whole tree = **103,602 B** > 64 KiB; scoping the tree breaks in-tree includes | n/a | yes |
| Elevation | none | none | none | new credential mechanism |
| ≥3 deterministic findings | yes (§3) | yes, but see below | 2, and they are M5.2a's | yes |
| Fixture reproducibility | files in the existing images; **no docker-in-docker** | containers | M5.2a's | needs a seeded server |
| Operator value | host root on compromise | high | already delivered by M5.2a | high |

**Next.js is excluded as the pack** because M5.2a already delivers it and the release
forbids the custom-application workflow doubling as the application pack ("Packaging
existing checks alone does not satisfy this release"). It remains in scope as M5.2a,
specified in §7 below.

**PostgreSQL/MySQL are excluded** because effective settings require a database session,
i.e. a new target credential mechanism, which M5.0's own "done when" forbids. Reading
`pg_hba.conf` alone is viable and is recorded as a future candidate, not this release's.

### 1.4 The rejected alternative: nginx, and its tradeoff

nginx was the initial recommendation and is the better-known application. It failed on
three independent measurements, any one of which is disqualifying:

1. **C1** — `nginx -T`, the only source of *effective* configuration, creates six
   filesystem entries and yields nothing without root.
2. **C2** — the file-read fallback loses `sites-enabled/*` under `-r`, and `-R` reads
   through planted symlinks. On Debian/Ubuntu that removes exactly the file that holds
   `ssl_protocols`, `autoindex` and `listen`.
3. **C3** — on Fedora the whole tree is 103,602 bytes and truncates at 64 KiB. Scoping the
   capture to `nginx.conf` + `conf.d` + `default.d` fits (3,180 bytes) but then Fedora's
   shipped `include /etc/nginx/mime.types` and `include /usr/share/nginx/modules/*.conf`
   point outside the captured set, and `/usr/share` is not in `policy.allowedPrefixes`.

**The tradeoff accepted by rejecting it:** scheck gives up the most common public-facing
service on Linux hosts, and gives up TLS-configuration findings entirely for 0.0.2. That
is a real coverage loss. It is accepted because the only honest nginx pack available today
would be Fedora-only, would abstain from every negative conclusion by default, and would
have a latent silent-false-negative mode on any host where an operator symlinks a config
file. An unreliable pack is worse than no pack for a tool whose exit codes are consumed by
automation.

**Revisit condition:** nginx becomes viable when either (a) parameterized planning plus
repeated-observation rule evaluation land, so a per-file `text.cat` with realpath and path
policy on every read replaces the recursive grep, or (b) a reviewed core addition supplies
a bounded, policy-checked "read this directory's files" primitive. Both are larger than a
pack and neither is promised here. Record it against 0.0.3 or later.

---

## 2. The pack

| | |
|---|---|
| Application | Docker Engine (`dockerd`) |
| Pack ID | `docker` |
| Contribution API major | 1 (set by M5.1) |
| Intended operator | anyone running Docker on a Linux host they administer — the deployment where a daemon misconfiguration is equivalent to host root |
| Platform | `linux` only. macOS Docker Desktop runs the daemon in a VM; `/etc/docker` on the Mac is not the daemon's configuration, so the pack contributes no checks on macOS and says so in discovery. |
| Supported matrix | **Ubuntu 24.04 / `docker.io` 29.1.3** and **Fedora 41 / `moby-engine`**, local and over SSH. Both were probed for file layout. |
| Elevation | **none.** Every check runs as the audit user. No sudoers fragment entry. |
| Excluded layouts, explicitly | Docker Desktop (any OS); rootless Docker (`~/.config/docker/daemon.json` is under `/home`, which is metadata-only by policy — the pack reports no coverage rather than guessing); Podman; Snap-packaged Docker (`/var/snap/...`, outside path policy); containers as the *target* of a scheck run. |

**Why files and not the daemon.** `docker info`/`docker ps` would give effective state, but
they require daemon socket access (root or `docker` group membership), they make the pack's
read-only proof depend on a daemon's own behaviour, and they would force docker-in-docker
into `test/containers`. Reading configuration keeps the pack inside C1–C3 and inside the
existing integration images. The cost is stated in §5: this is configuration as written,
not the running daemon's effective state.

---

## 3. Findings

Three findings, all **existential positives**: each fires only on an affirmative,
recognized record, never on the absence of an explanation. This is the rule the research
track (`../ROADMAP-RESEARCH.md`) established after the phase 2 false positives, and it
applies to deterministic rules just as much as to judgements.

### 3.1 `docker.daemon_tcp_exposed`

| | |
|---|---|
| Category / base severity | `network` / **critical** |
| Condition | the daemon is configured to listen on a TCP socket |
| Evidence A | `docker.daemon_json` — a `hosts` entry whose value matches `^tcp://` |
| Evidence B | `docker.service_dropins` — an `ExecStart=` line containing `-H tcp://` or `--host tcp://` |
| Excerpt | the matching record, redacted by the runner as usual |

Two rules, one finding ID. `finding.Evaluate` already merges evidence by finding ID
(`evaluate.go:62`), so a host configured both ways produces one finding citing both
observations. This is the pack contract's first real exercise of multi-rule evidence merge,
and it stays inside C3 because each rule still reads exactly one observation.

- **Recognized counterexample (`not_matched`):** `daemon.json` parses and its `hosts` array
  contains only `unix://` or `fd://` entries; the drop-in capture parses and no `ExecStart`
  names a TCP host.
- **Abstains (`not_assessed`):** `daemon.json` is present but not valid JSON; either capture
  carries a truncation or redaction marker; the drop-in directory read was denied.
- **Severity rationale:** an unauthenticated `tcp://0.0.0.0:2375` daemon is remote root on
  the host — container creation with `-v /:/host` is unrestricted. Critical is the base;
  the existing grader still adjusts for exposure and operator context.
- **Remediation.** Summary: bind the daemon to its unix socket and remove the TCP host, or
  put it behind TLS client-certificate verification. Caveat: removing a TCP host breaks
  remote clients configured against it; check `DOCKER_HOST` users first.

A deliberate non-finding: `tlsverify` is **not** used to downgrade this. A TCP daemon with
TLS is still an exposed control plane, and "TLS is configured" is a claim about a config
file, not about the running listener. Recording it would be a second fact smuggled into a
single-fact rule.

### 3.2 `docker.registry_insecure`

| | |
|---|---|
| Category / base severity | `integrity` / **medium** |
| Condition | `daemon.json` declares a non-empty `insecure-registries` array |
| Evidence | `docker.daemon_json` — a record with `setting = insecure-registries` |

- **Counterexample:** `daemon.json` parses and declares no `insecure-registries`, or an
  empty array.
- **Abstains:** malformed JSON, marker present.
- **Impact:** images pulled from a declared insecure registry are fetched over plaintext
  HTTP or with certificate verification disabled, so an on-path attacker chooses what code
  the host runs.
- **Remediation:** remove the entry and serve the registry over TLS with a trusted
  certificate; add the registry's CA to the host trust store if it is internal.

### 3.3 `docker.group_members`

| | |
|---|---|
| Category / base severity | `privesc` / **medium** |
| Condition | the `docker` group has at least one member |
| Evidence | `docker.group` — a `getent group docker` record with a non-empty member list |

- **Counterexample:** the group exists with no members (`docker:x:103:`, which is the
  packaged default — measured).
- **Abstains:** `getent` unavailable, or the record carries a marker.
- **Impact:** docker group membership is equivalent to root — a member can start a
  container that bind-mounts `/` and writes to it. The finding names the accounts.
- **Remediation:** remove members who do not need host-root equivalence; use rootless
  Docker or a brokered socket for the rest. Caveat: this is frequently intentional on
  developer and CI hosts.

**Noise tradeoff, stated rather than hidden.** This fires on most developer machines. It is
kept because the statement is factual and frequently surprising, not a judgement about
whether the membership is appropriate — the moment a rule tried to decide *that*, it would
be the phase 2 false positive again. Operators who have accepted it use the existing
accepted-risk mechanism, which is exactly what it is for. If review disagrees, drop this
one and promote a fourth candidate from §3.4; the release floor of three is then unmet, so
that decision has to be made here rather than during M5.2.

### 3.4 Considered and not included

- `no-new-privileges: false`, `selinux-enabled: false`, `icc: true`, `userns-remap` absent —
  each is defensible but low-yield, and `userns-remap` absent is an absence-based
  conclusion. Held as candidates if §3.3 is dropped.
- "daemon exposed on TCP *and* reachable from the internet" — a cross-fact correlation
  (config plus listener plus firewall). Explicitly out: `ROADMAP-0.0.2.md` lists cross-fact
  deterministic rules under "Outside 0.0.2", and this is the research track's multi-fact
  tier proposal.

---

## 4. Collection

| Check ID | Literal argv | Params | Tier | Parser | Paths read | Privilege | Volume (measured) |
|---|---|---|---|---|---|---|---|
| `docker.daemon_json` | `cat /etc/docker/daemon.json` | none | on-demand | `docker_json` (new shape, §8) | `/etc/docker/daemon.json` | none | 0 B when absent; < 2 KiB typical |
| `docker.service_dropins` | `grep -rH . /etc/systemd/system/docker.service.d` | none | on-demand | `lines` | `/etc/systemd/system/docker.service.d/**` (real files; no symlink convention) | none | 0 B when absent; < 4 KiB typical |
| `docker.group` | `getent group docker` | none | on-demand | `lines` | none (NSS) | none | < 200 B |

All three are on-demand, so the baseline-tier cap of 40 entries is untouched.

**`ExitOK`.** `cat` exits 1 on an absent file, `grep -r` exits 1 (no match) or 2 (missing
directory), and `getent` exits 2 when the group does not exist. All three are answers, not
failures, so each entry sets `ExitOK` — `{0,1}`, `{0,1,2}` and `{0,2}` respectively — in
the same way `fw.firewalld` and `privesc.sudoers_d` already do.

**Read-only rationale, per command.** `cat` and `getent` cannot write. `grep -r` cannot
write and, per C2, does not traverse symlinks; the drop-in directory's contents are real
files created by administrators or packages, so `-r` loses nothing here. **No command
contacts the Docker daemon**, so no container is created, started, inspected or logged,
and no daemon-side state changes. This is the property that makes the pack's read-only
proof independent of Docker's own behaviour.

**Indirect reads.** None. There is no include mechanism in `daemon.json`, and systemd
drop-ins are not followed by these commands — the pack reads the drop-in directory as
files, and does not attempt to compute systemd's effective `ExecStart`. §5 states what
that costs.

**Not collected, deliberately:** `/lib/systemd/system/docker.service` (the vendor unit) is
readable under the `/lib/systemd` prefix, but the vendor `ExecStart` is a constant of the
package, not operator configuration; including it would produce a finding about Ubuntu
rather than about this host. Only operator-supplied drop-ins are assessed.

---

## 5. What the evidence does and does not establish

**Saved configuration, not effective daemon state.** Every finding is a statement about
files on disk. The daemon may have been started before the file was edited, or started with
flags from a unit this pack does not read. The check descriptions, the finding impacts and
the report text all say "configured", never "the daemon is listening". M5.0 item 4 requires
this distinction to be stated, and it is the pack's principal limitation.

The upgrade path is named rather than improvised: correlating configuration with the
running daemon's actual argv and listeners requires M5.2a's binding workflow plus either
repeated-observation evaluation or the research track's multi-fact rule tier. It is not
approximated here, because a single-fact rule that joined two captures would be exactly the
boundary violation `ROADMAP-0.0.2.md` forbids.

**Absent installation.** `cat` exits 1 and the capture is empty. The pack cannot distinguish
"Docker is not installed" from "Docker is installed with default configuration" from this
evidence alone, and it does not try. Rules report `not_matched` with the reason
`no-records`, which is correct for the condition — nothing is exposed either way — and the
report does **not** claim `not_applicable`, because no evidence proves the application is
absent. Discovery output names the pack as selected so the operator can see what was
assessed. A future `sys.which docker` precondition would sharpen this; it is a cross-fact
concern today and is left out.

**Unsupported version or layout.** `daemon.json` has been format-stable across the
supported range; an unrecognized key is not an error, it is simply a record no rule reads.
Rootless and Snap layouts are excluded in §2 and produce no coverage claim.

**Malformed configuration.** Invalid JSON produces `Partial` records with a note and every
rule over that check abstains. A truncated or redacted capture does the same through the
existing marker machinery. Unknown is never a pass (SPEC §7.5).

**Incomplete reads.** A denied path or denied directory is recorded with the existing
reason codes and the rules become `not_assessed`. No bypass, no elevation retry.

---

## 6. Fixtures and integration

**Fixture cases** (`testdata/eval/cases/` and `testdata/fixtures/`), each with expected
findings, assessments and exit:

| Case | Content | Expected |
|---|---|---|
| `linux-docker-clean` | `daemon.json` with `hosts: ["unix:///var/run/docker.sock"]`, empty docker group, no drop-ins | no pack findings; all three rules `not_matched` with recognized evidence; exit 0 |
| `linux-docker-tcp-daemonjson` | `hosts` includes `tcp://0.0.0.0:2375` | `docker.daemon_tcp_exposed`, one evidence item; exit 1 |
| `linux-docker-tcp-dropin` | no `daemon.json`; `/etc/systemd/system/docker.service.d/override.conf` with `ExecStart=/usr/bin/dockerd -H tcp://0.0.0.0:2375` | same finding ID, cited from the drop-in observation |
| `linux-docker-tcp-both` | both of the above | **one** finding with **two** evidence items — the merge assertion |
| `linux-docker-insecure-registry` | `insecure-registries: ["reg.internal:5000"]` | `docker.registry_insecure` |
| `linux-docker-group` | `docker:x:103:alice,build` | `docker.group_members` naming both accounts |
| `linux-docker-absent` | no `/etc/docker`, no group | no findings; `not_matched`, not `not_applicable`; exit 0 |
| `linux-docker-malformed` | `daemon.json` containing `{"hosts": [` | both `daemon.json` rules `not_assessed`; the group rule unaffected |
| `linux-docker-truncated` | capture carrying a `[TRUNCATED:…]` marker | `not_assessed`; nothing filed |
| `linux-docker-hostile` | `daemon.json` with a planted secret in a string value and a planted instruction in a registry name | secret absent from report, audit log and persisted run with its marker present; the instruction is inert evidence and widens nothing |

The clean case satisfies M5.2's "recognized configuration disproving all pack predicates"
row — reachable here precisely because the pack has no unresolvable-include problem.

**Integration.** `test/containers/ubuntu` and `test/containers/fedora` gain the three files;
no new image and **no docker-in-docker**. The existing local and SSH facts tests cover the
pack automatically, and the target-diff assertion covers the read-only claim. No sudoers
work: nothing in the pack is elevated.

**Size estimate.** Worst realistic case is under 8 KiB across all three checks, against
`PerCheckOutput` 64 KiB and `ModelInputTotal` 256 KiB. No budget pressure, and the
baseline-tier cap is untouched because all three are on-demand.

---

## 7. The M5.2a custom-application contract (Next.js)

This section is M5.0 item 6 and is independent of the pack selection above.

**Supported combination:** Next.js 15 (standalone or `next start`) on Ubuntu 24.04, run
under **systemd** as a single unit. Other process managers (pm2, supervisor, a bare
`npm start` in a tmux session) are out of scope and must produce an explicit unresolved
binding, not a guess.

**Declaration** binds one name to one unit and one expected listener, as
`ROADMAP-0.0.2.md` proposes. `framework` is a hint, never a fact.

**Binding sequence**, bounded at **four** follow-up checks, each a catalog ID through the
runner:

1. `systemctl show <unit> --property=LoadState,ActiveState,MainPID,ExecStart,User` — one
   invocation, read-only, no dbus writes. Establishes that the unit exists, is active, and
   which PID it claims.
2. `ps -p <pid> -o comm=,args=,user=,lstart=` — the process's own account of itself. `lstart`
   is the lifetime evidence: a PID alone does not establish continuity.
3. `net.listeners` (already in the catalog) — the observed listener for that PID.
4. `sys.which node` — only to distinguish "node is absent" from "the unit is not a node
   service", so a missing binary is not read as a finding.

**Evidence that distinguishes process lifetimes.** `MainPID` from step 1 and `lstart` from
step 2 must agree across the two reads; the binding records both. If `systemctl show` is
re-read after step 3 and `MainPID` has changed, the binding is **unresolved** — a restart
occurred mid-collection and the observations describe two different processes.

**Binding becomes uncertain, and the attempt ends with a reason and no retry loop, when:**

| Situation | Outcome |
|---|---|
| Unit missing or `LoadState=not-found` | `unresolved:unit-absent`; application assessments `not_assessed`; host assessments unaffected |
| Unit inactive, `MainPID=0` | `unresolved:not-running` |
| `ps` shows a wrapper (`/bin/sh -c`, `npm`, `yarn`) rather than `node` | binding records the wrapper; a child is **not** followed. Without an affirmative `node` argv, the deployment findings abstain |
| PID reuse — `lstart` older than the unit's `ActiveEnterTimestamp` | `unresolved:lifetime-mismatch` |
| Restart between reads — `MainPID` differs on re-read | `unresolved:process-replaced` |
| Listener on the declared port owned by a different PID | binding resolved, listener evidence **not** attributed; the expectation mismatch is reported as observed, not as proof of identity |
| A budget is exhausted or a needed check is disabled | the binding step stops; no bypass, no fabricated attribution |

**Two deterministic findings**, each naming one observation that proves its condition:

- `app.dev_server_running` (**high**) — the bound process's `args` contain an explicitly
  recognized development invocation (`next dev`, or `node …/next dev`). Counterexample: a
  recognized production invocation (`next start`, `node server.js` from a standalone
  build). Abstains on a wrapper, an unreadable `args`, or an unrecognized argv shape —
  an argv scheck does not recognize is never a pass.
- `app.running_as_root` (**high**) — `ps` reports `user=root` for the bound PID.
  Counterexample: any other recognized user. Abstains when process metadata is inaccessible.

Both read one observation (`ps`), with the binding supplying the subject. Binding
establishes *whose* evidence this is; it does not combine observations into a conclusion.
A bind address is reported as an observed fact and never as proof of internet reachability.

**Not read:** the project directory, `next.config.*`, `package.json`, `.env`, or the process
environment. No `npm`/`npx`/build/test execution. No HTTP request of any kind, including
`GET`/`HEAD` — the boundary in `ROADMAP-0.0.2.md` is explicit and a read-only catalog entry
is not a loophole for it. A deployment under `/srv` or a home directory is still assessable
from runtime metadata, with file-based checks recorded as unavailable.

**New core checks required:** `proc.ps_pid` (step 2) — a parameterized, read-only check with
a typed `{pid}` parameter. `systemctl show` (step 1) is also new. Both are reviewed **core**
additions, not pack-owned, because the binding workflow is core.

---

## 8. Parser contracts

M5.1 separates parser implementation identity from output shape. The pack needs one new
shape and reuses one existing shape; this is the concrete case that slice should be
designed against.

**New shape `docker_json`** — implementation ID `docker.daemon_json_parser`, declared shape
`records`. It flattens `daemon.json` into `check.Records` with one record per configured
setting:

| Field | Meaning |
|---|---|
| `setting` | the top-level key, e.g. `hosts`, `insecure-registries` |
| `index` | array position, or empty for a scalar |
| `value` | the scalar value as written |

Predicates consume `setting` and `value`; nothing consumes the parser's identity, so a
second implementation producing the same shape would work with the same rules — which is
the property M5.1's acceptance test 6 asks for.

**Completeness.** `check.Records.Partial` already carries exactly the needed semantics
(`internal/check/typed.go:50`): a rule may prove an existential condition from a partial set
but never a negative one. The parser sets `Partial` when the JSON does not parse, when a
marker is present, or when a value is a nested object it does not flatten. That covers the
malformed and truncated fixture cases with no new machinery.

**Predicate gap.** The three findings need "a record whose `value` matches a pattern"
(`^tcp://`). Existing predicates are `FieldEquals` (exact) and `FieldOutside` (allowlist);
neither expresses it. This needs one new predicate, `FieldMatches{Field, Regexp, Recognize}`,
following `RawMatch`'s `Requires`/`Recognize` discipline so an unrecognized value abstains
rather than passing. That is a reviewed **core** addition with its own tests and spec
update, which M5.2 explicitly permits — not a pack-local predicate.

**Reused shape `lines`** for `docker.service_dropins` and `docker.group`, consumed by
`AnyLine`, whose partial-output handling (`internal/finding/rule.go:147`) is already
correct for existential conditions.

**Categories.** All three findings map onto existing categories (`network`, `integrity`,
`privesc`), so no report-schema category change is needed. A pack introducing a new category
would be a schema concern, and none does here.

---

## 9. Spec work identified (recorded, not applied)

M5.0 records the design; the implementing slices update the spec.

| Section | Change | Slice |
|---|---|---|
| §3 | pack-contributed checks in the catalog table; the `ExitOK` rationale for absent-file reads | M5.1/M5.2 |
| §4 | the C2 rule: `-r` permitted only where symlinks are not the enabling mechanism; `-R` forbidden | M5.1 |
| §7.1 | the three `docker.*` finding definitions | M5.2 |
| §7.4 | additive report metadata for pack identity and selection | M5.1/M5.4 |
| §7.5 | `FieldMatches` and its recognition contract | M5.2 |
| §6, §7.4–§7.6 | application declarations, binding status and application attribution | M5.2a |
| §11 | fixtures and goldens for the pack and the binding cases | M5.2/M5.2a |

---

## 10. Open items for review

1. ~~**§3.3 `docker.group_members`** fires on most developer hosts.~~ **Decided
   2026-09-22: keep it.** The statement is factual — these accounts hold root-equivalent
   access — and it is not a judgement about whether that is appropriate, which is the
   distinction that separates it from the phase 2 false positives. Operators who have
   accepted the membership use the accepted-risk mechanism, which exists for exactly
   this. The §3.4 candidates stay unused, so the pack ships three findings, not four.
2. **Fedora `moby-engine` version** is pinned in §2 by layout probe but not by a recorded
   fixture yet; M5.2 must record one and confirm the drop-in directory convention matches
   Ubuntu's.
3. **nginx revisit condition** (§1.4) should be filed against 0.0.3 or later so the coverage
   loss is tracked rather than forgotten.
