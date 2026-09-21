# scheck — optional research roadmap

**Status (2026-09-21):** R1 is **implemented** (`internal/bounded`, the `bounded` arm of
`scheck eval`, offline, scripted answers, no quality claim). The pre-R3 recall probe has
**run against `jev-1.13.0`** and its result is recorded below. R2 and R3 are proposed and
not started. A **TypeSafe key now exists**, so R3 is no longer deferred for want of
access; it is gated on the `net.listeners` capture fix, on R1 being reviewed and on R2
freezing the question set. **Ordering is decided**: the research runs now, any production
integration waits until after 0.0.2 — see "Ordering" below. No product release version or
delivery date is assigned, and no product release gate depends on anything here.

This file is the **only home of this experiment's knowledge**: what was decided and why,
what the vendor's API and limits are, what R1 actually built, what it does on the
committed suite, what was tried and abandoned, and what is still open. Code comments
cite it; nothing about the experiment is recorded only in code, only in a commit message
or only in a conversation. A reader who has never seen `internal/bounded` should be able
to rebuild it from here.

## Scope and relationship to releases

This track explores bounded assessment under [SPEC.md §5.9](SPEC.md). It is independent
of the product sequence: [0.0.1](ROADMAP-0.0.1.md), [0.0.2](ROADMAP-0.0.2.md),
[0.0.3](ROADMAP-0.0.3.md) and tentative [0.0.4](ROADMAP-0.0.4.md).
No ordinary audit, default CI job or product release gate depends on this experiment.

The order relative to [0.0.2](ROADMAP-0.0.2.md)'s pack system is decided and recorded
under "Ordering: research now, integration after 0.0.2" below: the research slices run in
parallel with M5.0 and M5.1 because they touch no product code, and any integration waits
for the contracts 0.0.2 builds.

M2.7's real-model quality evaluation and the adversarial tests for shipped AI remain
mandatory in 0.0.1. They validate the production approach; this track explores an
alternative and cannot replace those release checks. A negative result is a valid
completed research outcome. Assign any proposed production integration to a future
release only after R4 establishes its value and scope. Do not scaffold an empty
production abstraction while waiting for access.

### Why this draft changed (2026-09-20)

The three-repeat live record in [docs/eval/phase2-results.md](eval/phase2-results.md)
fails the frozen gate, and the shape of the failure decides what this track should
test:

- **The loop is not used.** In 9 of 9 follow-up agent runs the model made no tool call.
  A System One model never chooses its next action either, so it cannot fix this as a
  drop-in. What it can do is invert control: code enumerates the candidates, code runs
  the bounded follow-up read, and the model answers one narrow question per candidate.
- **The false positives are context judgements.** A declared listener reported anyway,
  third-party launch daemons on a workstation filed as unexpected persistence, an
  active firewall filed as a finding with a note saying it was not one. Each is a
  yes/no question about one item against a few fields of context, which is the
  question shape System One models are built for. Filing stays with code, so the
  "ruled-out hypothesis" channel problem does not exist in this design.
- **Drift is indistinguishable from injection** at the level of binary findings. A
  probability per item gives §4.4 a continuous measure to read against.

The earlier draft scoped the experiment to "service/context relationship: expected,
unexpected, insufficient_context". SPEC §6.3 already decides that in code
(`expected_services` matching, `svc.expected_missing`), so that scope would have
measured nothing the product needs. It also proposed a second labeled corpus and a
separate harness; `internal/eval` and `testdata/eval` already exist and are the
comparison the decision needs.

## The shape under test

**Code owns the workflow; the model owns one judgement per item.** Nothing here adds
a second execution path or a model-selected command (AGENTS.md rules 2 and 3):

1. **Enumerate in code** from the fact sheet: every enabled unit and cron entry, every
   third-party launchd plist, every non-loopback listener, every SUID binary, every
   administrative account. Deterministic filters that already exist stay in code: path
   prefixes, `expected_services` port/proto matching, counts, dates, redaction and
   truncation markers. A candidate whose evidence is `unavailable`, truncated or
   redacted is recorded as `insufficient` by code and never sent.
2. **Follow up in code**, bounded: for a candidate whose baseline record is not enough
   (a unit's `ExecStart`, a cron script's content), run the labeled catalog check
   through `runner.RunAs` with its own `Origin`. The menu gate, path policy, redaction
   and audit apply unchanged. The set of follow-up checks per candidate kind is a fixed
   table, not a model decision.
3. **Ask per item.** One request per candidate: a `state` object holding that item's
   records and only the context fields that bear on it, with the independent Noul
   questions for that kind batched in the same request. Never the whole fact sheet:
   accuracy falls with unrelated detail and the state budget is bounded.
4. **Decide in code.** Probabilities are recorded raw. Thresholds decide whether
   `finding.Store.Report` is called with the judgement id; below them, nothing is filed
   and the item is listed as considered. Severity, the grader, the envelope and exit
   codes are untouched (§5.9).

Judgement ids in scope, all present in `internal/finding/catalog.go`:
`persist.unexpected_entry`, `net.unexpected_listener`, `fs.suid_unexpected`,
`accounts.unexpected_admin`. Rule-covered ids and `svc.expected_missing` stay with the
rules and §6.3. Finding text comes from the catalog `Def`; the model generates nothing.

### Three decisions taken while building R1 (2026-09-21)

**Decomposed questions, combined in code.** A candidate is judged by two or three
independent Nouls asked in one request, not by one "is this unexpected given the
context?" question. That single question asks a literal reader to recognize the item
*and* relate it to the operator's words in one hop — vendor limitation 4, and the shape
the phase 2 model already got wrong in prose. Code combines the answers.

**Nothing is filed from the absence of an explanation.** Every decision rule needs an
affirmative signal: hallmarks of persistence, a program the model does not recognize, a
world-writable directory code already found. "Nobody declared this" is a property of the
operator's notes, not of the host, and filing on it is exactly what produced the phase 2
false positives (`sshd` on `0.0.0.0:22` with no context, a workstation's own launch
daemons, an active firewall). `TestSilenceAloneFilesNothing` pins this down for every
kind.

**The follow-up table reads a directory, not a file per item.** Code lists
`/etc/systemd/system` once and reads only the unit files a host actually defines, so
`linux-unit-in-tmp` runs **one** bounded read where the first attempt ran 23, of which 22
returned nothing usable.

One question form throughout (a Noul, never a Noul and a Choice for the same judgement):
the vendor's limitations page says structural identities between forms do not hold, so a
threshold is never carried from one form to another.

## Vendor facts (docs.typesafe.ai, reviewed 2026-09-21)

Recorded here so no slice has to re-derive them and so a stale assumption is visible.
Sources: [api](https://docs.typesafe.ai/api.md), [models](https://docs.typesafe.ai/models.md),
[primitives/noul](https://docs.typesafe.ai/primitives/noul.md),
[state](https://docs.typesafe.ai/concepts/state.md),
[confidence](https://docs.typesafe.ai/confidence.md),
[jev-1.13 limitations](https://docs.typesafe.ai/model-jaggedness/jev-1.13.md),
[parallel questions cookbook](https://docs.typesafe.ai/cookbooks/parallel_questions.md).

| Fact | Value |
|---|---|
| Endpoint | `POST https://api.typesafe.ai/v1/systemone`, `Authorization: Bearer <key>` |
| Request | `{state, model, questions}`; `state` is a string, object or array of text; `questions` is a map of caller-chosen ids |
| Noul question | `{type: "noul", instructions, criteria: {true, false}}`; criteria optional but they are where the boundary is pinned |
| Noul answer | `{type: "noul", noul: <0..1>}` — **no separate confidence**: the probability is the answer and its certainty; ~0.5 means "similar probability either way", not "medium intensity" |
| Response | `{model, answers, usage: {input_tokens, output_tokens}}`; the `model` field is what to record per answer |
| Errors | 401 invalid key, 422 validation, 429 rate limit, 529 overloaded (backoff on the last two) |
| Model ids | `jev-1.13.0`; aliases `jev-latest` and `jev-preview` exist and **must not** be used in a record |
| Context | 64k total, of which **32k for state plus the longest question** |
| Price | **$42 per billion input tokens; output free** |
| Rate limits | 250k tokens/second, 1200 requests/minute (stated as variable under demand) |
| Input | Text only. English is most accurate; other languages work with lower reliability |
| Other primitives | Choice (max 255 options, returns a distribution plus confidence), Score (2–10 ordered levels) — neither is used here |
| Batching | Independent questions over one state go in **one** request and run in parallel; the vendor's own cookbook reports a 12.2× cost reduction from batching 13 questions |

**Known limitations, and where each one lands in this design.** The mitigation column is
the contract: a change that breaks it is wrong even if the arm scores better.

| Limitation | Where it is handled |
|---|---|
| 1. Literal reading — scoping words, negations and implied conditions are read at face value | Questions name the state field they are about; absent context is spelled out as `"not declared"` rather than omitted (`TestUndeclaredContextIsSpelledOut`) |
| 2. No counting or numeric comparison | Ports, counts, modes and the world-writable correlation are computed in code and passed as facts |
| 3. No date arithmetic | No question involves a date; expiry of an accepted risk stays with §6.3 |
| 4. One hop of indirection | The decomposition above: recognize the item, relate it to context, spot hallmarks — never in one question |
| 5. Accuracy falls with unrelated state | One item per request; the fact sheet is never sent; a follow-up capture is clipped to 4 KiB |
| 6. Adversarial state moves answers | Target-derived text and operator prose are data; `testdata/context` and the §4.4 pair runs measure it. Code, not the model, decides what is filed |
| 7. Contradictory instructions and criteria | Criteria are written as the complement of the instruction, and `TestQuestionSetIsWellFormed` requires both sides |
| 8. Structural invariants do not hold (P(noul) ≠ 1 − P(not_noul)) | One form per judgement; no rule subtracts one probability from another; thresholds are per question |
| 9. No generation | The model writes no text at all: finding title, impact and remediation come from the catalog `Def` |

## What R1 built

`internal/bounded`, imported by `internal/eval` only. `scripts/depcheck.sh` asserts both
directions: the package pulls in no provider adapter or SDK, and `agent`, `policy`,
`check`, `finding`, `report` and `llm` never import it.

| File | Owns |
|---|---|
| `bounded.go` | `Kind`, `Item`, `FollowUp`, `Request`, `Answerer`, `Options`, `Result`, and `Run` — enumerate → resolve → ask → decide → file |
| `enumerate.go` | candidate enumeration per kind and every deterministic filter |
| `followup.go` | the fixed per-kind follow-up table and the run-level resolver |
| `state.go` | the per-item state builder and its budget |
| `questions.go` | the question set, answer validation and `QuestionsVersion` |
| `decide.go` | thresholds and the per-kind decision rules |
| `scripted.go` | the R1 answer source (`<case>/bounded.yaml`) |

### Enumeration sources

| Kind | Linux | macOS |
|---|---|---|
| `listener` | `net.listeners` (`ss -tulpnH`) | `net.listeners` (`lsof`) |
| `persistence` | `persist.units` (enabled unit files) + `persist.cron` (`grep -rH . /etc/crontab /etc/cron.d`) | `persist.launch_dirs` (third-party LaunchDaemons and LaunchAgents) |
| `suid` | `fs.suid`, annotated from `fs.world_writable` | same |
| `admin` | `accounts.passwd` uid 0, plus principals of `privesc.sudoers` / `privesc.sudoers_d` | `accounts.admins` (admin group membership), plus `accounts.users` uid 0 |

Two sources are deliberately **not** enumerated. `persist.timers` is a schedule report of
units `persist.units` already lists, so it would only duplicate candidates. macOS
`persist.launchctl` is dominated by Apple's own loaded jobs; the plists on disk are the
inventory a judgement is about, and the catalog entry already limits them to third-party
directories.

### Deterministic filters (code settles it; no question is ever asked)

| Filter | Why |
|---|---|
| Listener bound to `127.0.0.0/8` or `::1` | Not reachable beyond the host |
| Listener matching an `expected_services` entry | §6.3 owns this, in code. Asking anyway was a phase 2 false positive (`linux-context-explains`) |
| `root` as an admin candidate | root *is* the account uid 0 names |
| `%sudo`, `%wheel`, `%admin` | A distribution's own administrative principals; the accounts behind them are candidates through their own records |
| A sudoers principal whose grant lists specific commands | `accounts.unexpected_admin` means "can escalate to root". scheck's own `/etc/sudoers.d/scheck` fragment is the worked example: seven named commands, no `ALL`, so `ops` is filtered |
| A listener whose capture does not name the owning process | Nothing to recognize. `ss` names the process only for a privileged session, so asking would answer "not a known component" for every Linux listener on an unprivileged run. Recorded `insufficient` — see "The defect the probe found" |
| Source check `unavailable`, `Truncated`, `Redactions > 0`, or `check.HasMarker` in the capture or the item's own line | Bytes were removed; what was removed cannot be judged. Recorded `insufficient`, never sent, never filed |

Listeners are deduplicated by `port/proto`, keeping the first record. **Known limitation:**
when the same port is bound on one family to loopback and on the other to a wildcard, the
first record decides — see "Open questions" below.

### The follow-up table

Every read goes through `runner.RunAs` with `Origin{Tool: "bounded_followup"}`, so the
menu gate, path policy, redaction, truncation and the audit trail apply unchanged.

| Kind | Read |
|---|---|
| persistence / systemd unit | `fs.list` on `/etc/systemd/system` **once per run**, then `text.cat` of `/etc/systemd/system/<unit>` only for units in that listing |
| persistence / cron entry | `text.cat` of the absolute program the entry runs, when the command begins with one and it holds no shell metacharacter |
| persistence / launchd job | `text.cat` of the plist path |
| listener, admin, suid | none |

**What was tried and abandoned**, measured on `linux-unit-in-tmp` (14 enabled units, 9
SUID binaries), because both dead ends look reasonable on paper:

- *A `text.cat` per enabled unit*: 14 reads, of which 12 were `unavailable` (vendor units
  live under `/lib/systemd`, not `/etc/systemd/system`), 1 was `denied:invalid_params`
  (`getty@.service` — a template unit's `@` is outside the path parameter's
  `^[A-Za-z0-9._/-]+$`), and 1 was the one that mattered. The directory listing replaced
  all 14 with 2 reads, one of them shared by every unit of the run.
- *An `fs.stat` per SUID binary*: 9 reads, **all 9 denied by path policy**. `/usr/bin`,
  `/opt/*/bin` and friends are neither content nor metadata prefixes, so there is nothing
  about a binary the policy admits. The SUID kind therefore has no follow-up at all, and
  the correlation it needs (`fs.world_writable`) comes from code.

Together those two were 23 reads per Linux case with 22 useless results — which is also a
reminder that a "bounded follow-up" is only bounded if code checks first whether the read
can succeed.

An unavailable or denied follow-up is not an error. It becomes `definition_note` in the
state ("could not be read: …"), and the affirmative-evidence rule then has nothing to
stand on (`TestUnreadableDefinitionIsRecordedNotConcluded`).

### The per-item state

```json
{ "host": {"platform","role","environment","exposure","owner"},
  "item": {…the candidate's own fields…},
  "evidence_line": "the verbatim line from the check output",
  "definition": "…follow-up capture, clipped to 4 KiB…",
  "definition_note": "could not be read: denied path.not_allowed",
  "declared_services": [ …only entries matching this listener… ],
  "operator_notes": "…operator prose…" }
```

Every `host` field is always present, as `"not declared"` when it is absent: a literal
reader can use that, an absent field it cannot. `declared_services` is carried for
listeners only — on any other kind it is unrelated detail, which limitation 5 calls a
distractor (`TestUnrelatedContextIsLeftOut`). `TestStateCarriesOnlyItsOwnItem` asserts
that no state mentions another candidate's evidence.

### The question set

Three Nouls per kind (two for `admin`), batched in one request. Ids are stable; the
wording lives in `questions.go` and is hashed into the version.

| Kind | Question ids and what each asks |
|---|---|
| `listener` | `explained` (does the context state a purpose for a service on this port), `vendor` (is the listening program a standard component or ordinary installed software), `sensitive` (does a service of this kind give another host administrative control, remote access or access to stored data) |
| `persistence` | `explained`, `hallmarks` (does the command or definition download and run code, run from a temporary or hidden directory, decode a payload, or imitate a system component), `vendor` |
| `suid` | `vendor` (is this a set-user-ID program the platform ships), `hallmarks` (does the path or ownership show a program copied or built in place rather than packaged), `explained` |
| `admin` | `explained`, `person` (is this the login of a person who administers the host, rather than a service, application or leftover account) |

### Decision rules and thresholds

Thresholds are **provisional** — chosen to express the rules, never measured. Nothing is
calibrated until a live record on held-out cases says so.

`Unexplained 0.2 · NotStandard 0.3 · Affirmative 0.6 · Strong 0.8`

| Kind | Files when | Confidence |
|---|---|---|
| `listener` | `vendor < 0.3 && explained < 0.2` | high when `sensitive ≥ 0.6`, else medium |
| `persistence` | `hallmarks ≥ 0.8`, or `hallmarks ≥ 0.6 && vendor < 0.3` | high on the first, medium on the second |
| `suid` | `vendor < 0.3 && (directory is world-writable || hallmarks ≥ 0.6) && explained < 0.2` | high when the directory is world-writable |
| `admin` | `person < 0.3 && explained < 0.2` | medium |

`sensitive` never files on its own: ssh and screen sharing are sensitive by design, so it
only raises confidence. Severity is always the catalog's (`medium` for all four ids); a
`severity` from any answer source is ignored, as it is everywhere else (§7.1).

### Versioning, budgets and the record

`bounded.QuestionsVersion()` hashes the question ids, types, instructions and both
criteria, the thresholds and the state-builder version into `bq-<12 hex>`. Its value at
R1 is **`bq-68cbe087c689`**; a record carries it so no threshold is ever read against a
question it was not measured on.

Budgets: `MaxItems` 128 judged candidates per run (ends the arm as `budget: items`),
follow-up reads bounded by `Budgets.AgentChecks` (60), follow-up text clipped to 4 KiB
per state, and the whole arm inside `RunTimeout`. A missing, malformed, out-of-range or
`NaN` answer files nothing and marks the item `no_answer`.

Each item is recorded with its kind, key, source check and observation, verbatim excerpt,
fields, follow-up, status (`judged` / `filtered` / `insufficient` / `no_answer` /
`over_budget`), **raw probabilities** and the decision sentence. The results file carries
`bounded_source` and `bounded_questions_version`; the report prints a `## Bounded arm`
section. The follow-up capture itself is never stored in the record — only cited through
its observation.

### The scripted answer source (R1)

`testdata/eval/cases/<case>/bounded.yaml`:

```yaml
defaults:                     # per candidate kind
  listener: { explained: 0.10, vendor: 0.95, sensitive: 0.30 }
  persistence: { explained: 0.10, hallmarks: 0.02, vendor: 0.95 }
  suid: { explained: 0.10, hallmarks: 0.03, vendor: 0.95 }
  admin: { explained: 0.10, person: 0.90 }
items:                        # per item key, overriding the kind default
  "unit:agent.service": { explained: 0.03, hallmarks: 0.96, vendor: 0.03 }
```

Item keys are `listener:<port>/<proto>`, `unit:<name>`, `cron:<file>:<command>`,
`launchd:<path>`, `suid:<path>`, `admin:<principal>`. Three cases carry an override:
`linux-unit-in-tmp` (the unit code read has `ExecStart=/tmp/.x/agent`),
`linux-cron-fetch` (the script pipes a download into a shell) and
`linux-suid-in-world-writable` (`/opt/tool/bin/helper`, where the world-writable
directory is code's contribution and `hallmarks` deliberately stays at 0.45 so the rule
must lean on the fact code supplied). An item with neither an override nor a kind default
gets no answer at all, which files nothing and marks it.

**Scripted answers are not a model's answers.** They say what this code does with a given
set of probabilities and nothing more. Every record built from them says so.

## What R1 does on the committed suite

`scheck eval --provider mock --arms rules,single-pass,agent,bounded --no-pairs`, one
repeat, scripted answers — plumbing, not quality:

| arm | correct | false positives | missed | abstentions | resolved follow-ups |
|---|---|---|---|---|---|
| rules | 0 | 0 | 0 | 0 | 0 |
| single-pass (mock transcripts) | 1 | 0 | 5 | 9 | 0 |
| agent (mock transcripts) | 2 | 1 | 4 | 8 | 1 |
| **bounded (scripted)** | **3** | **0** | 3, all outside its design | 9 | 2 of 2 in scope |

Enumeration volume, which is what R2 and R3 will pay for: **377 requests over the 15
cases at one repeat**, 28–29 per Linux case, 1 for `macos-clean`, 9 for
`macos-filevault-off`. Over the whole suite, 377 candidates are judged, 73 are settled by
the filters and 11 are `insufficient` (one truncated capture, and one Linux listener per
case with no process name). A state is small — the largest in the suite is 338 bytes,
about 84 tokens — which is the point of sending one item at a time. Follow-up reads are rare by design. Counted per item, and audited in full
(the directory listing is shared, so it is audited but not counted against an item):

| case | counted follow-ups | audited reads |
|---|---|---|
| `linux-unit-in-tmp` | 1 | 2 — `fs.list` of `/etc/systemd/system`, then `text.cat` of the unit |
| `linux-cron-fetch` | 1 | 2 — the listing (unavailable here), then `text.cat` of the script |
| every other Linux case | 0 | 1 — the listing alone |
| `macos-filevault-off` | 3 | 3 — one `text.cat` per third-party plist |
| `macos-clean` | 0 | 0 — nothing to follow up |

At the vendor's price, three repeats of the whole suite is on the order of **1,200
requests and a few cents** — cost is not what R3 risks; an unreviewed question set is.

## What this arm deliberately does not cover

Three expected ids in the suite are **deterministic correlations across two checks**,
not context judgements, and the bounded arm scores them as misses on purpose. The
comparison report names them so a reader does not read a miss as a failure:

| Case | Expected id | What it actually needs |
|---|---|---|
| `linux-no-firewall` | `fw.no_firewall_active` | ufw inactive **and** firewalld absent **and** an empty nft ruleset |
| `linux-password-auth-public` | `sshd.password_auth_exposed` | `passwordauthentication yes` **and** a non-loopback `listenaddress` |
| `linux-sshd-include` | `sshd.password_auth_enabled` | `sshd -T` refused **and** a drop-in under `sshd_config.d` that sets it |

No model is needed for any of them; what is missing is a **multi-fact rule tier**, which
today §7.5 forbids ("one rule reads one check"). That is a product proposal for a later
release, not research: it would need the `Rule` type to read several checks, a predicate
that abstains unless *every* input is recognized, and the same three fixtures per rule the
single-fact rules already require. R4 cites this; nothing is scaffolded for it now.

## Suite findings to act on before R2 spends money

- **The macOS false-positive surface is in the suite but unlabeled.**
  `macos-filevault-off` inherits the base `macos` fixture and therefore carries the
  workstation shape phase 2 got wrong: three third-party LaunchDaemons (docker ×2,
  nordvpn), wildcard listeners including AirPlay on 7000/5000 and postgres on 5432, and
  `alice` in the admin group. Its `forbid:` list is **empty**, so filing any of them
  costs nothing in the metrics. Either add the judgement ids to that case's `forbid:` or
  add a dedicated `macos-third-party-daemons` case labeled `misleading`. Until then, no
  arm is measured on the macOS false positives at all. (`macos-clean` masks the daemons
  away and binds every listener to loopback, so it measures nothing here either.)
- **The macOS fixtures do not record the plist reads.** The launchd follow-up returns
  `unavailable` for all three plists, so those items are judged on path and label alone.
  Re-record the macOS fixture with `--record-fixtures` including
  `cat /Library/LaunchDaemons/<label>.plist`, or accept it and say so in the record.
- **`net.listeners` truncates the process name on macOS, and it is the R3 blocker.**
  `lsof` caps its COMMAND column at nine characters, so the state says `ControlCe`, and
  the probe's only two false positives were exactly the two listeners with a truncated
  name. `lsof -nP -iTCP -sTCP:LISTEN +c 0` disables it. This is a catalog argv change:
  it needs a macOS fixture re-record (`--record-fixtures`, scrubbed) and a command-trace
  golden update, and it changes what reaches the target, so it is a product change to be
  made deliberately rather than folded into the experiment. Until it lands, the listener
  kind on macOS files false positives with real answers, and the listener kind on Linux is
  `insufficient` without elevation — which together mean **`net.unexpected_listener` has
  no working population today**.
- **Only `linux-unit-in-tmp` records `ls -la /etc/systemd/system`.** On every other
  Linux case the shared directory listing comes back `unavailable`, so **no unit
  definition is ever read there** — the units are judged on their names alone. That is a
  fixture gap, not a design one, and it flatters the arm's read volume while starving its
  evidence. Record the listing in the base `ubuntu` and `fedora` fixtures with
  `make fixtures` before R2, or R2 measures unit judgements on names only and must say so.
- **Only two cases carry operator context** (`linux-context-explains`,
  `linux-truncated-listeners`). Every other case answers `explained` against
  `"not declared"`, which exercises the conservative half of each rule and never the
  "context explains it" half. R2 should add context to at least one case per kind.

## Is Jev a good fit? (assessment, 2026-09-21)

Asked directly, before R2 or R3 has run. The answer has three parts and the middle one
matters most.

**The shape fits, and that is not a small claim.** Phase 2 failed because the model had to
choose actions and did not, in 45 of 45 runs. In this design nothing asks it to: planning,
tool selection and generation are code's, and what is left — one bounded yes/no about one
item against a few hundred tokens — is what a System One model is built for. The known
failure mode is designed out rather than mitigated. Cost and latency are not constraints
(a real host is ~40 requests, fractions of a cent against a $0.50 criterion), typed output
removes the whole "model wrote prose instead of calling a tool" class, and a probability
per item gives §4.4 a continuous drift measure that binary findings never gave it.

**Nothing here says it works.** R1 ran on scripted answers. The 3-correct / 0-false-positive
line is a statement about the decision rules, not about any model, and it must never be
quoted as one.

**The risk that could sink it is `vendor`.** That question asks Jev to recall what the
world ships — is `/usr/bin/sudo` a standard SUID binary, is `rapportd` an Apple component,
is `com.docker.vmnetd.plist` deliberately installed software. The vendor's own framing is
judgment *over supplied state*; "context rot" and the state-centric docs describe a model
tuned to reason about content it is handed, not to be a knowledge base about system
binaries. `vendor` is the one question in the set that leans on recall, and it is load-
bearing: of the four phase 2 false-positive classes, code now kills two deterministically
(the declared listener, and the firewall ids this arm cannot file at all) and the other
two — third-party launch daemons on a workstation, `sshd` on `0.0.0.0:22` — rest entirely
on `vendor` coming back high.

**A cheaper answer may exist for half of it.** `dpkg -S <path>` and `rpm -qf <path>` answer
"did a package install this?" deterministically, and `codesign -dv` gives the macOS
equivalent for a bundle. A package-provenance catalog check would turn most of `vendor`
into a code fact and leave the model only the genuinely contextual half (`explained`,
`hallmarks`). That would make the design better and the case for Jev smaller at once,
which is the honest shape of this assessment: every time work moved into code, the
model's addressable share shrank.

**Verdict after the probe ran (2026-09-21): yes, with one blocker that is ours, not the
vendor's.** The recall risk above did not materialise the way it was feared, and the
decomposition absorbed the case where it did. The remaining failure is a capture defect in
`net.listeners`. Details in the probe result below; the short form is that Jev answered
well wherever scheck handed it a clean identifier or readable evidence, and badly where
scheck handed it a truncated string. R3 is worth building once the listener capture is
fixed and R2 has frozen the questions.

### Ordering: research now, integration after 0.0.2 (decided 2026-09-21)

The question was whether to introduce Jev before or after [0.0.2](ROADMAP-0.0.2.md)'s
pack system. It splits in two, because finishing the research and shipping the feature
are different acts.

**R2, R3 and R4 run now, in parallel with M5.0 and M5.1.** They touch no product code:
`internal/bounded` is imported by `internal/eval` alone and `scripts/depcheck.sh` enforces
that in both directions, so the whole track produces records in `docs/eval`, not features.
They cost cents. Deferring them behind a five-slice release would let the question set,
the probe and the vendor facts go stale for no gain, and R4's answer is an **input** to
M5.1's API design rather than a consequence of it.

**Any production integration waits until after 0.0.2**, for three reasons that point the
same way:

1. **M5.1's parser-shape and completeness contracts are what this arm needs.** The probe's
   only two false positives came from a truncated capture, and R1's fix was a hand-written
   special case (a listener with no process name is `insufficient`). M5.1 separates parser
   identity from output shape and attaches completeness metadata to the shape, which turns
   that special case into a general rule: *a question naming a field is not asked when the
   shape reports that field incomplete*. Judgement built on that contract is safer than
   judgement retrofitted to it.
2. **M5.2a's binding workflow is the same architecture, and a prerequisite.** It is a
   bounded core workflow resolving service → process → listener through catalog IDs, and
   it deliberately stops short of cross-fact conclusions ("Comparing separate service,
   listener and proxy facts remains phase 2 work"). That is the gap a judgement layer
   fills, and it cannot be filled before the binding exists: without a bound subject there
   is nothing to ask a question about.
3. **Packs multiply the capture surface.** Every pack is another chance to hand a model a
   mangled or absent field, which is where this design's failures actually come from.
   Mature the capture contract before judgement becomes cross-cutting.

The converse holds too. Introducing Jev first would force 0.0.2 to answer "may a pack
contribute a candidate kind, its questions and its thresholds?" — a far larger
contribution API than the one it proposes (no execution hooks, no orchestration,
single-fact rules), frozen around a single untested consumer.

**If R4 says integrate, the home is [0.0.3](ROADMAP-0.0.3.md)**, which is already the
inference release (providers, emulation, local-only inference). A bounded answer source
belongs beside that contract, not bolted onto the pack release. Both roadmaps already say
bounded assessment ships on no promised version; this records *why* the order is what it
is. The middle path to avoid is half-integrating Jev into 0.0.2 to keep momentum, which
shapes the pack API around an experiment that has not passed its own gate.

**What 0.0.2 carries for this**, both recorded in that roadmap and neither dependent on
the experiment succeeding:

- the `net.listeners` `+c 0` capture fix, riding the macOS fixture re-record M5.4 already
  requires (it can also be done standalone sooner, if R3 runs first — it is R3's blocker);
- a forward-compatibility note so the contribution API does not promise packs that the
  assessment surface is single-fact rules forever.

### A check that would serve both arms: package provenance

`dpkg -S <path>`, `rpm -qf <path>` and `codesign -dv` answer "did a package install this?"
deterministically and read-only. It is a **core catalog check**, not a pack and not part of
this experiment, and it pays off twice:

- **Without any model**, it supports a single-fact posture rule that fits §7.5 exactly — a
  SUID binary that no package owns — which is most of what the `suid` kind is for.
- **With the model**, it removes the question this experiment is least sure of. The probe
  showed `vendor` recall is good, but a fact beats a probability, and moving provenance
  into code leaves the model only the genuinely contextual half (`explained`, `hallmarks`).

Proposing it here because the experiment surfaced it; implementing it is ordinary catalog
work under AGENTS.md's "adding a catalog check", with its own review, fixtures and rule
fixtures. It shrinks the model's addressable share, which is the honest direction of this
whole track.

### The recall probe (pre-R3 gate)

`make probe` — `test/live/jev_probe_test.go`, build tag `live`, needs
`TYPESAFE_API_KEY`, sends **recorded fixture data only**, costs a fraction of a cent.

It is deliberately not an adapter. It enumerates 30 labeled candidates from the committed
fixtures exactly as a run would, sends each one's **real state** (`bounded.StateFor`) and
the **frozen question wording** (`bounded.Questions`) to `jev-1.13.0`, and reads the
`vendor` answer. What it measures is therefore what a run would send, not a paraphrase.

The labels split into what a correct answer calls standard — Ubuntu's nine SUID binaries,
its thirteen enabled units, macOS's own listeners, and the three third-party
LaunchDaemons an administrator installed on purpose — and the two planted ones,
`unit:agent.service` and `suid:/opt/tool/bin/helper`, which nothing ships.

**The gate is what the decision rules do, not whether `vendor` separates on its own.**
That was the probe's first design and it was wrong: the whole claim of this arm is that
code combines several answers, so a weak `vendor` is survivable when an affirmative signal
carries the decision — and that is exactly what happened. The probe therefore fails on a
false positive or an uncaught planted item, and reports `vendor` separation as a
diagnostic. It prints every item with all its answers, so a failing run is still a
readable record.

Two fidelity rules the probe learned the hard way, both worth keeping: it must send the
state **after** follow-up reads (it now captures the real `bounded.Request` through a
capturing `Answerer` rather than rebuilding state by hand), and it must use
`bounded.Questions`, never a paraphrase. The first version violated the first rule and
measured something a run would never send — see the note at the end of this section.

#### Result — 2026-09-21, `jev-1.13.0`, 30 items, 19,405 input tokens, $0.0008, 8.5s

```
item                                                     want      vendor  other answers
unit:cron.service                                        standard   0.96   explained 0.02  hallmarks 0.03
unit:ssh.socket                                          standard   0.96   explained 0.02  hallmarks 0.03
unit:getty@.service                                      standard   0.97   explained 0.02  hallmarks 0.03
unit:ufw.service                                         standard   0.94   explained 0.02  hallmarks 0.03
unit:remote-fs.target                                    standard   0.95   explained 0.02  hallmarks 0.03
unit:e2scrub_all.timer / e2scrub_reap.service            standard   0.93–0.94
unit:apt-daily.timer / apt-daily-upgrade.timer           standard   0.95–0.96
unit:dpkg-db-backup.timer / fstrim.timer / motd-news…    standard   0.94–0.95
unit:systemd-pstore.service                              standard   0.92   explained 0.02  hallmarks 0.04
unit:agent.service                                       planted    0.39 <<explained 0.02  hallmarks 0.96
suid:/usr/bin/sudo / su / passwd                         standard   0.96–0.97
suid:/usr/bin/gpasswd / chfn / newgrp / mount            standard   0.84–0.94
suid:/usr/bin/chsh                                       standard   0.69
suid:/usr/bin/umount                                     standard   0.47
suid:/opt/tool/bin/helper                                planted    0.10   explained 0.02  hallmarks 0.19
launchd:com.docker.vmnetd / com.docker.socket            standard   0.90–0.93
launchd:com.nordvpn.macos.helper                         standard   0.88   explained 0.03  hallmarks 0.06
listener:53019/tcp  (rapportd)                           standard   0.55   explained 0.03  sensitive 0.17
listener:7000/tcp   (ControlCe)                          standard   0.27 <<explained 0.03  sensitive 0.40
listener:5000/tcp   (ControlCe)                          standard   0.20 <<explained 0.04  sensitive 0.34

decision rules: 2 planted items caught, 2 false positives over 30 items
  caught: suid:/opt/tool/bin/helper — not one this platform ships (0.10), directory /opt/tool/bin is world-writable
  caught: unit:agent.service — the entry's command shows hallmarks of persistence used by an intruder (0.96)
  FALSE POSITIVE: listener:5000/tcp — the listening program is not a recognized component (0.20)…
  FALSE POSITIVE: listener:7000/tcp — the listening program is not a recognized component (0.27)…
```

**What this establishes.**

- **Recall is strong where the identifier is clean.** All thirteen Ubuntu units 0.92–0.97,
  all nine standard SUID binaries 0.47–0.97 against the planted one at 0.10, and — the
  phase 2 false-positive class — all three third-party macOS LaunchDaemons at 0.88–0.93,
  correctly *not* filed. The fear that `vendor` asks for knowledge Jev does not have was
  largely wrong.
- **The decomposition did its job on the one case where `vendor` was wrong.** The planted
  `agent.service` got `vendor` 0.39 — a wrong answer, it is not a standard unit — but with
  the unit file in state `hallmarks` came back **0.96** and the rule
  (`hallmarks ≥ 0.8` files on its own) caught it anyway. This is the design's central
  claim, tested against a real model and holding: no single answer is load-bearing.
- **`hallmarks` is the sharpest signal in the set**: 0.03–0.07 across every legitimate
  unit and plist, 0.96 on the planted one. Nearly two orders of magnitude of separation.
- **`explained` is uniformly ~0.02–0.04** because no probe item carried operator context.
  That is the conservative half of every rule and says nothing about the other half;
  see the suite finding about context coverage.
- **Both false positives are scheck's fault, not Jev's.** `lsof` truncates its COMMAND
  column to nine characters, so the state for the AirPlay listeners says the process is
  **`ControlCe`** — a mangled token nothing can recognize. Jev scored the one unmangled
  macOS process (`rapportd`, 0.55) roughly twice as high as the two truncated ones. Fix
  the capture, not the question: `lsof -nP -iTCP -sTCP:LISTEN **+c 0**` disables the
  truncation. That is a catalog argv change to `net.listeners` on macOS, which needs a
  macOS fixture re-record and a command-trace golden update — a product change, not a
  research one, and **the blocker on R3**.
- **Run-to-run variance is small but real**: across three runs `vendor` on
  `unit:agent.service` was 0.77 / 0.40 / 0.39, on `listener:7000/tcp` 0.26 / 0.22 / 0.27.
  (The 0.77 is the first, non-faithful run — see below.) A record needs the frozen three
  repeats; a single run is an indication.

**Cost and latency, measured:** 30 requests, 19.4k input tokens, **$0.0008**, 8.5 seconds
wall-clock sequential. Extrapolating, the full suite at three repeats is roughly 1,130
requests and **under two cents**. Cost is not a consideration for this design.

#### The probe's own first result, and why it is not the record

The first run sent state built straight from `bounded.Enumerate`, **without the follow-up
reads a real run performs**. `unit:agent.service` was therefore judged on its name alone
and scored `vendor` 0.77 and `hallmarks` 0.05 — it looks like a plausible vendor unit if
all you see is "agent.service". Adding the follow-up moved `hallmarks` 0.05 → 0.96.

Keep the number: it is the measured value of the follow-up table. Reading a single unit
file turned an item the model would have waved through into the most confident detection
in the set. It also says something about the listener and admin kinds, which have no
follow-up: they are judged on an identifier alone, which is precisely where the two false
positives landed.

### The defect the probe found before it ran

Building the probe was worth it before a single request was sent. Its dry run printed the
state for `listener:22/tcp` from the Ubuntu fixture and the `process` field was **empty**:
`ss -tulpnH` names the owning process only for a privileged session, and `net.listeners`
is not an elevated check.

The `vendor` question names `item.process`, and its `false` criterion reads "or no program
name was captured" — so a real model would have answered low for **every Linux listener on
every unprivileged run**, and with `explained` low by default the rule would have filed
`net.unexpected_listener`. That is the phase 2 false positive (`sshd` on `0.0.0.0:22` with
no context) reproduced by a different route, in a design whose whole premise is that it
had fixed that class. It would have fired on `linux-clean`, where the id is forbidden.

Fixed: a listener whose capture does not name the owning process is `insufficient` —
unknown is neither safe nor unsafe (§7.5). `TestListenerWithoutAProcessIsNotJudged` pins
it. macOS is unaffected, because `lsof` names the command.

Two lessons worth keeping. **A question that names a state field must not be asked when
that field is empty** — the rest of the question set should be audited against this before
R2, and validation belongs in code, not in a criterion's wording. And **the listener kind
is effectively macOS-only without elevation**, which bears directly on the assessment
above: one of the four judgement ids barely has an addressable population on Linux, and it
is the id with no positive case in the suite.

## Open questions for R2

Recorded so they are decided with evidence rather than rediscovered:

1. **Thresholds are provisional.** Four numbers express the rules; none is measured.
   They need held-out cases, and the suite is currently too small to hold any out.
2. **How is a Noul-shaped answer obtained from a generative adapter?** R2 must force a
   bounded answer through `internal/llm` without inventing a second calibration story.
   Whatever it produces is that model's number, never a probability comparable to Jev's.
3. **Does `sensitive` earn its place?** It only raises confidence today. If it never
   changes an outcome on real answers, drop it and save a third of the listener tokens.
4. **Linux admin enumeration is incomplete by construction.** The catalog has no
   group-membership check (no `getent group sudo`), so a member of `%sudo` who is not
   uid 0 and not named in sudoers is never a candidate. Closing it means adding a catalog
   check first (AGENTS.md, "adding a catalog check"), which is a product change, not a
   research one.
5. **Listener deduplication by `port/proto` keeps the first record.** A port bound to
   loopback on one address family and to a wildcard on the other is decided by whichever
   line the tool printed first. Fix it by folding both records into one candidate whose
   `reachable` field is the widest of the two.
6. **Can Jev answer `vendor` at all?** **Answered 2026-09-21: yes, where the identifier
   is clean** (units 0.92–0.97, standard SUID 0.47–0.97, third-party plists 0.88–0.93,
   planted SUID 0.10). It answers badly where scheck's capture is mangled, which is a
   capture bug. See the probe result above. What remains open is whether `vendor` still
   earns its tokens once package provenance is available in code.
7. **The suite cannot measure recall.** Three positive labels exist in scope, and two of
   the four judgement ids have **none**:

   | judgement id | cases expecting it | cases forbidding it |
   |---|---|---|
   | `net.unexpected_listener` | **0** | 5 |
   | `persist.unexpected_entry` | 2 | 2 |
   | `fs.suid_unexpected` | 1 | 2 |
   | `accounts.unexpected_admin` | **0** | 2 |

   So the suite measures precision and abstention well (377 judged candidates, almost all
   of which should file nothing) and sensitivity hardly at all. An R3 record on today's
   suite could only say "it did not cry wolf" — worth something, not adoption evidence,
   and not enough to hold any case out for calibration. R2 adds a positive case for the
   two ids that have none before any threshold is called calibrated.
8. **Item volume on a real host is unmeasured.** 30 candidates per case is a container
   fixture; a workstation or a busy server will enumerate more, and `MaxItems` (128) has
   never been reached. Measure it before anyone proposes this for a production path.

## Research slices

### R1 — bounded arm in the existing harness, offline — implemented 2026-09-21
No key needed. A fourth arm, `bounded`, in `internal/eval` over the same fifteen cases,
identical facts, rule findings and context as the other three; the answer source is an
interface with a scripted implementation. An unqualified `scheck eval` still compares the
frozen three arms — the research arm is asked for by name, so a live phase 2 record never
grows a scripted column nobody asked for.
**Demo:** `scheck eval --provider mock --arms rules,single-pass,agent,bounded` prints the
comparison with the fourth row and the `## Bounded arm` section; the follow-up metric is
exercised because code ran the labeled `text.cat`.
**Done when** — all met: the arm runs in `make check`; every request's state is asserted
to hold only that item's records and the bearing context fields; `insufficient` items are
asserted never sent and never filed; missing, malformed and out-of-range answers file
nothing and mark the item; the audit log shows every follow-up read under the arm's
`Origin`; rule findings are byte-identical across arms. Scripted answers are labeled as
such in the record; a passing run makes no quality claim.
**Spec:** §5.9, §11.

### R2 — the same questions through the available generative adapter
No key needed; spends a few cents. Answer the R1 questions through the
`openai-compatible` adapter, with each Noul forced to a bounded answer, on the same
per-item state, and score the arm with the frozen §3 metrics at three repeats. This
measures whether the decomposition itself, not the vendor, removes the false positives
and resolves the follow-up cases; it says nothing about Jev's calibration.
**Demo:** `scheck eval --arms bounded --bounded-source openai --repeat 3` appends a
dated section to `docs/eval/phase2-results.md` attributed to that model.
**Done when:** the record shows correct additional findings, false positives, missed
issues, abstentions, resolved follow-ups, latency and cost for the bounded arm next to
the three existing arms, on the same cases and labels; the macOS labelling gap above is
closed; open questions 2 and 3 are answered. Freeze the question set and thresholds
before R3.
**Spec:** §5.9, §11.

### R3 — Jev adapter and live evaluation
A key exists and **`make probe` has passed on substance** (2026-09-21): both planted items
caught, 28 of 30 correctly left alone, and the two failures traced to a capture defect
rather than to the model. Gated now on three things, in order: the `net.listeners` `+c 0`
fix, R1 being reviewed, and R2 freezing the questions. Build the adapter against the
vendor facts above — the probe already exercises the request and response shapes, the
pinned model id, the error classes and the backoff, so it is the working reference. A small net/http adapter inside the experiment package, built against the
vendor facts above: `TYPESAFE_API_KEY` read from the environment at request time and
never printed, the model pinned to `jev-1.13.0` (never an alias) and the response's
`model` field recorded per answer. Validate every answer's id, type and range; classify
401, 422, 429 and 529 as error kinds with bounded backoff on the last two; check the
state and question budgets before sending; enforce egress policy before any request
(`--local-only` forbids it). A local fake server exercises all of it.
**Demo:** `scheck eval --arms bounded --bounded-source jev --repeat 3` with the
adversarial pairs, reading §4.4 against per-item probability drift as well as filed
findings.
**Done when:** the record answers whether accuracy, follow-up resolution and cost justify
adoption against the rules, single-pass, agent and R2 arms. No threshold is treated as
calibrated without the held-out cases.
**Spec:** §5.9, §4.4, §11.

### R4 — decide whether to integrate
Write an evidence-backed decision: keep the experiment, remove it, or propose a bounded
production role with explicit fallback and coverage semantics. Any production integration
requires updating the spec, reporting contract and tests first. Do not silently promote an
experimental assessment into a finding filter or an investigation gate. The decision also
says what to do with the multi-fact rule tier above, which is cheaper than any model and
covers three of the suite's cases.
**Done when:** the decision cites the R2 and, if run, R3 records; no integration is
required for a successful experiment or for shipping a product release. Land it before
M5.1 freezes the contribution API, so "may a pack contribute a candidate kind?" is
answered with evidence rather than guessed at (see "Ordering" above).
**Spec:** §5.9.

## Completion evidence

- Results, question versions, thresholds and model ids live in `docs/eval` next to the
  phase 2 records, never in a normal report.
- Scripted answers, generative answers and Jev answers are attributed separately and
  never presented as one another's performance.
- R4 records a decision to retain, remove or propose integration, with costs,
  uncertainty and limitations supported by results.
- An unavailable vendor leaves R3 deferred, without delaying a product release or
  implying that R1 or R2 validated that vendor.
