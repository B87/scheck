# scheck — optional research roadmap

**Status (2026-09-21):** R1 is **implemented** (`internal/bounded`, the `bounded` arm of
`scheck eval`, offline, scripted answers, no quality claim). R2 and R3 are proposed and
not started. A **TypeSafe key now exists**, so R3 is no longer deferred for want of
access; it stays gated on R1 being reviewed and on R2 freezing the question set. No
product release version or delivery date is assigned, and no product release gate
depends on anything here.

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

Enumeration volume, which is what R2 and R3 will pay for: **387 requests over the 15
cases at one repeat**, 28–30 per Linux case, 1 for `macos-clean`, 9 for
`macos-filevault-off`. The filters settle 4 to 6 candidates per Linux case, 3 of 4 on
`macos-clean` and 15 of 24 on `macos-filevault-off` (loopback listeners, mostly), and one
candidate in the whole suite is `insufficient` (`linux-truncated-listeners`). Follow-up reads are rare by design. Counted per item, and audited in full
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
6. **Item volume on a real host is unmeasured.** 30 candidates per case is a container
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
A key exists; this slice is ready to start once R1 is reviewed and R2 has frozen the
questions. A small net/http adapter inside the experiment package, built against the
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
required for a successful experiment or for shipping a product release.
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
