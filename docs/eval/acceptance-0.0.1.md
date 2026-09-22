# Acceptance pass for 0.0.1 (SPEC §12)

Roadmap slice M4.6, first pass 2026-09-21. This is the sign-off record: every criterion in `docs/SPEC.md §12`
with the command or the named test that proves it, the evidence that produced, and a
verdict. It is appended to, never rewritten.

**Build under test:** `scheck 683aac2` (`make build`, the M4.5 commit), macOS
`darwin/arm64` 25.6.0, Docker for the Linux legs. Live-run excerpts below are scrubbed
of hostname, user and serial numbers, as the macOS fixture is (`AGENTS.md`).

**What a re-run needs:** `make check`, `make integ` (Docker), a `scheck local` run on a
macOS host, and `docs/eval/phase2-results.md` for criteria 7, 10 and 12. No API key and
no spend: nothing in this pass contacts a provider.

**Scope of this record.** It validates the commit named above. M4.7 requires the same
pass at the release commit before publication, so this file gets a second dated section
then. Two narrowings agreed in the roadmap's M4 scope note apply, both stated in full
under the criteria they touch: criterion 3's diff is the container diff rather than a
separate VM, and criterion 1's macOS leg is one developer machine rather than a matrix.

## Verdict

| # | Criterion | Verdict |
|---|---|---|
| 1 | Reports on macOS, Ubuntu, Fedora | pass |
| 2 | No command outside the catalog reaches the target | pass |
| 3 | Nothing on the target is modified | pass, with one recorded exception: a package manager's own metadata cache (see below) |
| 4 | Offline facts run is fully useful | pass |
| 5 | Every finding's evidence traces to a check id | pass |
| 6 | Seeded secrets never appear; redactions marked | pass |
| 7 | A clean-host run costs under $0.50 | pass (trivially: no model, no credential) |
| 8 | Adapters pass conformance; context guards hold | pass |
| 9 | Operator context changes the report deterministically | pass |
| 10 | Phase 2 earns its cost | pass by having run the comparison and acted on it: it did not, and 0.0.1 ships rules only |
| 11 | The SSH canary aborts on a hostile login shell | pass |
| 12 | Repeated adversarial evaluations pass the frozen criteria | pass on the recorded corpus and model |

One item is carried out of this pass rather than closed by it: **`pkg.dnf_check_update`
leaves a dnf metadata cache under `/var/tmp` on Fedora.** It is written under criterion
3 and repeated in "Open items".

## 1. Reports on macOS and on Ubuntu + Fedora

**macOS**, release build, no key in the environment:

```
$ env -u OPENAI_API_KEY scheck local --no-persist --format json
exit 1
schema_version 1.6 · run.status complete · run.assessment rules · run.mode facts
run.provider null · run.model null · usage all zero, cost_usd null
28 facts · 29 observations · 10 rules assessed · 2 findings
  fw.app_firewall_disabled  medium  evidence fw.global#1
  updates.pending           low     evidence pkg.softwareupdate#1
assessment coverage: 2 matched, 4 not_matched, 4 not_assessed
6 checks skipped, all "requires an elevated read"
```

**Ubuntu and Fedora**, over SSH into the containers of `test/containers`, by
`TestSSHFactsReport` (`test/integ/facts_test.go`), which validates the JSON against
`docs/report-schema.json` and asserts `host.transport ssh`, `host.canary ok`,
`host.remote_shell /bin/bash`, `run.status complete` and a persisted envelope that
exists on disk:

```
$ go test -tags integration -count=1 -v -run TestSSHFactsReport ./test/integ/
--- PASS: TestSSHFactsReport (13.58s)
    --- PASS: TestSSHFactsReport/ubuntu (2.28s)
    --- PASS: TestSSHFactsReport/fedora (10.66s)
```

**Verdict: pass.** Narrowed as agreed: the macOS leg is one developer machine, not a
matrix of macOS versions. The recorded macOS fixture and its goldens (M4.5) are what
keep that leg from regressing between passes.

## 2. No command outside the compiled catalog reaches the target

Three legs, as the criterion asks.

*The catalog invariants test.* `TestCatalogInvariants` (`internal/check/all`): no
metacharacters in literals, every placeholder bound to exactly one typed param, no
mutating flags, no binary from the write-capable list, exactly one `Canary: true` entry.

*The hostile-input corpus.* `TestRunHostileParamDeniedBeforeAnyExec` (`internal/runner`)
plus the injection corpus in `internal/agent`:
`TestHostileToolCallsCannotBypassPolicy`, `TestHostileContextChangesNothing`,
`TestRuleFindingsCannotBeSuppressed`, `TestInstructionShapedTargetOutputIsData`,
`TestCorpusIsPaired`. All pass.

*The audit log of a live run.* The macOS run above wrote 29 lines: 23 `run`, 6
`unavailable:*`, no `denied:*`. Every line was checked against
`scheck catalog --platform macos --format json` (33 entries) — the check id must exist,
and the argv must match that entry's literal tokens position by position, with `{…}`
placeholders free and a leading `sudo -n --` stripped:

```
audit lines: 29 · decisions: {run: 23, unavailable: 6} · violations: []
```

The same property is asserted on every Linux run by `TestSSHFactsReport`, which fails on
any `denied:` line or any line without a check id and argv, and offline by M4.5's
command-trace goldens, which pin the exact argv of every attempted check per fixture.

**Verdict: pass.**

## 3. Nothing on the target is modified

**Agreed narrowing:** the before/after diff is `docker diff` across a full
`scheck ssh --stop-after facts` run on throwaway Ubuntu and Fedora containers, asserted
by `make integ` on every change, rather than a separate VM. The containers are as
disposable as the VM the criterion imagined, and the check runs continuously instead of
once at release. On macOS there is no equivalent diff; that leg is the catalog
invariants test plus the audit log of criterion 2, which together show that every argv
that reached the host was a read-only catalog command and that nothing else ran.

`TestSSHFactsReport` takes the diff before the run and after it, ignores lines already
present before, and fails on any remaining line outside sshd's own login noise. It now
logs what it tolerated, so the evidence is visible rather than implied:

```
ubuntu (5 lines): C /home | C /home/ops | A /home/ops/.cache |
                  A /home/ops/.cache/motd.legal-displayed | A /run/motd.dynamic
fedora (33 lines): C /var | C /var/tmp | A /var/tmp/dnf-ops-<random>/… (31 more)
```

Ubuntu's five lines are the login itself: the motd machinery, and the directory mtimes
above it. Nothing scheck ran wrote anything.

**Fedora's 33 lines are not login noise, and this is the one exception in the record.**
`pkg.dnf_check_update` runs `dnf -q check-update`; run unprivileged, dnf creates its own
cache directory `/var/tmp/dnf-<user>-<random>/` and fills it with repository metadata
(`repomd.xml`, primary and updateinfo indexes, `*.solv`, `hawkey.log`, a lock
directory). It survives the run. No configuration, package, unit or credential is
touched, and nothing outside that directory changes — but "it never modifies the
target" is stated without qualification in `SPEC.md §1` and `AGENTS.md`, and a
package manager's cache is a write.

**Verdict: pass, with that exception recorded**, because the criterion's subject —
configuration and system state — is intact on both distributions and on macOS, and the
diff proves it. The exception is a real gap between what the tool promises and what one
catalog entry does, so it is carried as an open item below rather than closed here. It
does not block 0.0.1 unless the promise is meant literally, which is the call to make
before publication.

## 4. `--stop-after facts` is fully useful offline

`TestAcceptanceCriterion4` (`cmd/scheck/posture_test.go`) is written against this
criterion: a fixture host with FileVault off (macOS) or `PasswordAuthentication yes`
(Linux) yields that finding, with its evidence and remediation, and exits 1, with no
model and no key. It passes.

On the release build, with the key removed from the environment, a default run and
`--stop-after facts` produce the same findings — they are the same run in this build
(§2.1) — and both exit 1:

```
$ env -u OPENAI_API_KEY scheck local --no-persist --stop-after facts --format json
exit 1 · run.mode facts · run.assessment rules · findings identical to the default run
$ scheck local --provider openai-compatible --no-persist
scheck: --provider selects a model, and no model assesses a host in this build …
exit 3
```

The text report follows §7.6, pinned by nine golden files at three verbosities (M4.5).

**Verdict: pass.**

## 5. Every finding carries evidence traceable to a check id

Checked on the live macOS report: for each finding, each evidence entry names a check
and an observation reference, and that reference resolves in `run.observations` to an
observation of exactly that check (`unresolved evidence: []`). `fw.app_firewall_disabled`
cites `fw.global#1`; `updates.pending` cites `pkg.softwareupdate#1`.

Offline, the same resolution is asserted over all three fixtures by
`TestEnvelopeMatchesSchema` (`internal/report`) for facts, findings and assessments, and
the references themselves are pinned by M4.5's JSON goldens. A model-supplied excerpt
cannot cite anything else: `finding.Store` validates every excerpt against the exact
cited observation's output.

**Verdict: pass.**

## 6. Seeded secrets never appear; every redaction is marked

Named tests, all passing: `TestSeededSecretNeverPersists`,
`TestFailedDiagnosticsRedactedAndNotPersisted`, `TestFindingEvidenceIsRedacted`
(`internal/state`); `TestRedactSeededSecrets`, `TestRedactMarkerCountsBytes`
(`internal/policy`); `TestRunRedactsBeforeAuditAndTruncates`,
`TestObservationDenialsAndMetadataAreRedacted` (`internal/runner`). Between them they
cover report, audit log, persisted envelope, verbose diagnostics and finding evidence,
and assert the `[REDACTED:<rule>:<n bytes>]` marker is present with the right byte count.

**Verdict: pass.**

## 7. One run on a clean host costs under $0.50

Met trivially: no model assesses a host, so a run builds no provider, reads no
credential and costs nothing. The macOS run above reports `usage` all zero and
`cost_usd: null`.

The measured number for one agent run of the evaluation harness is recorded in
`docs/eval/phase2-results.md` — **$0.0071** — and `make live` keeps it reproducible in
case a later build reopens the question.

**Verdict: pass.** Not re-run here; no spend in this pass.

## 8. Conformance suite and context guards

`TestConformance` passes for both adapters (`internal/llm/mock`,
`internal/llm/openai`) over the one table in `internal/llm/conformance`: tool-call round
trip, error results, multiple calls in one turn, every `StopReason`, `MaxTokens`
truncation, usage normalization, `Limits` reporting.

Full-request guards: `TestCheckFit` (`internal/llm`) and `TestContextLimitGuards`
(`internal/agent`) cover an oversized first request, history growth and provider
overflow rejection, asserting facts and findings survive into an incomplete report with
exit 2 and that no evidence is silently dropped.

**Verdict: pass.** Additional providers, emulation, guaranteed local-only inference and
chunking remain post-v1, as the criterion allows.

## 9. Operator context changes the report deterministically

One host, three runs on the release build, with a four-line context file:

| Run | `fw.app_firewall_disabled` | Attribution |
|---|---|---|
| `--context internet.yaml` (`exposure: internet`) | `high` | `{"rule":"exposure:internet","source":"internet.yaml#context.exposure","delta":"+1"}` |
| `--context lan.yaml` (`exposure: lan`) | `medium` | none |
| `--context internet.yaml --ignore-context` | `medium` | none |

`severity_base` stays `medium` in all three; the adjustment is exactly the `+1` the
table in §6.3 prescribes for an internet-exposed host, attributed to the file and the
field it came from. `updates.pending` is `low` throughout: the table adjusts it for
neither exposure.

On the byte-for-byte clause: a JSON diff of the no-context run against the
`--ignore-context` run differed in exactly three values, all one live fact — the
launchd job count moved from 546/194 to 544/192 between the two runs, seconds apart.
Every finding, severity, `severity_base`, adjustment list and assessment was identical.
The deterministic form of the claim, with the facts held fixed, is asserted by
`TestIgnoreContextReproducesBaseSeverity` (`cmd/scheck/grade_test.go`) and
`TestSeverityTable`, `TestAdjustmentAttributionInJSON`, `TestNilContextIsUnadjusted`
(`internal/finding`).

**Verdict: pass.**

## 10. Phase 2 earns its cost

Decided and recorded in `docs/eval/phase2-results.md`, and implemented in roadmap M2.8:
two three-repeat live evaluations failed the criteria frozen in
`docs/eval/phase2-criteria.md` before the loop existed — on the deciding record the
agent made no `run_check` or `read_file` call in 45 of 45 runs — and single-pass failed
its own bar. 0.0.1 therefore assesses with the posture rules alone (`SPEC.md §2.1`).

**Verdict: pass**, in the sense the criterion defines: the comparison was run against
criteria fixed in advance, and the result was acted on. It is not a claim that the loop
ships.

## 11. The SSH canary aborts on a hostile login shell

`TestCanaryMatrix` (`test/integ/ssh_test.go`) over the shell matrix of
`test/containers/shell-matrix`:

```
--- PASS: TestCanaryMatrix (1.38s)
    u_sh · u_bash · u_zsh · u_fish · u_rbash
```

`fish` and `rbash` abort with exit 3 before any other command is sent; the three POSIX
shells proceed. The canary is the first command on every SSH session, and its outcome is
audited like any check.

**Verdict: pass.**

## 12. Repeated adversarial evaluations pass the frozen criteria

Recorded as passing on 2026-09-20 in `docs/eval/phase2-results.md`: §4.1, §4.2 and §4.4
of the frozen criteria, with no drift in the benign controls, on that corpus and that
model, with model and prompt versions recorded. It bounds nothing for 0.0.1's release
path, which sends no evidence to a model at all; it is the measurement a later build
starts from.

**Verdict: pass** on the recorded corpus and model.

## Configuration walkthrough (M2.2a, against the release build)

`docs/CONFIGURATION.md` was walked end to end against `scheck 683aac2` on macOS, with a
scratch `HOME` and project directory.

- Provenance: with a user file and a project `scheck.yaml` present, `config show` names
  the file behind every scalar (`model`, `effort` from the user file; `profile`,
  `elevate` from `scheck.yaml`), names every source of each accumulated list, and
  reports credentials by presence only. Both configuration paths in §1 are correct:
  macOS reads `~/Library/Application Support/scheck/config.yaml`, and the walkthrough's
  example output uses the documented Linux path.
- Validation: the documented typo example reproduces byte for byte, including exit 3 —
  `accepted_risks[0]: "sshd.pasword_auth_enabled" is neither a catalog finding id nor a
  custom: id`.
- §6's "not available in this build" list matches the build: the six model flags exit 3
  on `local` and `ssh`, and the same keys in a file are unused rather than fatal.

One cosmetic defect found: `config show` renders a `targets:` entry with no explicit
port as `ops@10.0.0.5 port 0`, where 0 means "unset, use 22". It is display-only —
resolution defaults the port correctly — and it is listed below.

## Open items from the first pass

Both were closed on 2026-09-22, in the next section. The list is the first pass, left
as it was written.

1. **`pkg.dnf_check_update` leaves a metadata cache on the target** (criterion 3).
   `dnf -q check-update` run unprivileged writes `/var/tmp/dnf-<user>-<random>/` and
   leaves it there. Options, cheapest first: document the exception in `SPEC.md §1` and
   the README as the one write scheck can cause; add `-C`/`--cacheonly` so dnf reads an
   existing cache and the check reports `unavailable` when there is none; or drop the
   entry from the baseline tier. The first keeps the finding and tells the truth; the
   second makes the promise literal at the cost of answering less often on a host whose
   cache is cold.
2. **`config show` prints `port 0`** for a target with no explicit port. Display-only.

## M4.7 resolution of the open items (2026-09-22)

Both open items are closed here, before publication, as M4.7 requires. The first pass
above is left as written.

### Open item 1 — the dnf cache

**Decision: keep the check and document the write.** `-C`/`--cacheonly` was tried first
and is refuted by measurement, so the choice was between documenting the write and
losing Fedora's pending-update coverage entirely.

Measured 2026-09-22 with `docker diff`, unprivileged, on both dnf generations:

| Attempt | Result |
|---|---|
| `dnf -q -C check-update` on Fedora 40 (dnf 4.22) | still creates `/var/tmp/dnf-ops-<random>/`, adds a lock file and appends to `dnf.log`, `dnf.librepo.log`, `dnf.rpm.log`, `hawkey.log`. Exit 1 on a cold cache |
| `dnf -q -C check-update` on Fedora 44 (dnf5) | the write moves rather than disappearing: 30+ files under `~/.cache/libdnf5/` plus `~/.local/state/dnf5.log` |
| `dnf -q -C --setopt=cachedir=/var/cache/dnf --setopt=logdir=/var/log/dnf check-update` | `Config error: [Errno 13] Permission denied: '/var/log/dnf'`, exit 1 — **and the per-user directory is created anyway**, before config resolution |

The write is structural to dnf. `docs/SPEC.md §1` now states it, the README repeats it
and the release notes carry it.

### Two further artefacts, found by tightening the assertion

Documenting one exception is only worth anything if the test enforces the rest, and it
did not. `test/integ/facts_test.go` tolerated any diff line beginning `C /run`, `A /run`,
`C /var`, `A /var`, `C /home`, `A /home` or `C /etc` — whole trees. That is how the dnf
cache reached the first pass as a reading of the logged noise rather than a test failure.

The tolerance is now an exact allowlist of an ssh login's own artefacts plus a named
pattern per documented write, with a table test (`TestReadOnlyDiffClassification`)
asserting that plausible check-caused writes — `/etc/sudoers.d/evil`, `/run/nginx.pid`,
`/var/lib/nginx/body`, `/home/ops/.ssh/authorized_keys`, `/var/tmp/not-dnf` — are
rejected. Writing it caught one regexp of my own that was too loose.

Running it immediately failed `TestSudoersFragmentOnUbuntu` with five previously hidden
lines, and two of them are scheck's own writes that nobody had recorded:

| Cause | Artefact | Condition |
|---|---|---|
| Elevation, `sudo -n --` | `C /run/sudo`, `A /run/sudo/ts`, `A /run/sudo/ts/<uid>` | `--sudo` only |
| `fw.ufw`, `ufw status verbose` | `A /run/ufw.lock` | `--sudo` only |

(The fifth, `/run/sshd.pid`, is the container's own sshd and is login noise.)

So the count in `SPEC.md §1` is **three documented writes, not one**. None is
configuration, a package, a unit or a credential; all are a tool's record of its own
invocation in runtime or cache state. Criterion 3's verdict is unchanged — its subject,
the target's configuration and system state, is intact — but what satisfies it is now
enforced by the test instead of asserted in prose.

### Open item 2 — `config show` prints `port 0`

**Closed.** An unset port renders as `-` in text and is omitted from JSON, covered by
`TestConfigShowRendersAnUnsetPortAsAbsent`. A port of 0 is the absence of configuration,
and printing 0 read as a port the operator had written.

## Change log

- 2026-09-21 — first pass, on `scheck 683aac2` (committed 2026-09-20). All twelve criteria pass; one exception
  and one cosmetic defect recorded above.
- 2026-09-22 — M4.7 resolution of both open items. The dnf write is documented after
  `--cacheonly` was measured and refuted; tightening the read-only assertion to an exact
  allowlist revealed two further scheck-caused artefacts (sudo's timestamp directory,
  ufw's lock file), so `SPEC.md §1` now documents three. No criterion's verdict changes.
