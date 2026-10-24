# scheck — bounded assessment specification

This is the contract and the evidence for **R1, the bounded arm**: an experiment in
which code owns the workflow and a System One model answers a few narrow yes/no
questions about one item at a time. R1 is implemented in `internal/bounded`, runs
offline on scripted answers, and is reachable only from the hidden `scheck eval`
(`--arms ...,bounded`). It makes no quality claim about any model.

The same pattern (code enumerates, Jev answers narrow yes/no questions, code decides)
is the design of the proposed `auto` gate for probes and scans in
[scope.md](scope.md#auto-an-experimental-decision-gate), planned for 0.0.4 in
[../ROADMAP.md](../ROADMAP.md). The rules and evidence recorded here carry over to it.

Answer sources are attributed separately in every record. Scripted answers, a
generative model asked the same questions, and Jev are never presented as one
another's performance; a scripted run says what this code does with a given set of
probabilities, nothing more. Code comments cite this file by heading.

## Boundaries

Bounded assessment is a research experiment, not a prerequisite for any release.
Development, default CI and release gates must not require a Jev account, credentials,
network access to TypeSafe, or recorded Jev responses. The offline arm runs in
`make check` with no network.

- **Separate from `llm.Provider`.** It does not implement the conversational,
  tool-calling contract of [model.md §2](model.md). `internal/eval` is its only caller;
  there is no public CLI mode. `scripts/depcheck.sh` asserts both directions: the
  package pulls in no adapter or SDK, and `agent`, `policy`, `check`, `finding`,
  `report` and `llm` never import it.
- **Input and output.** Input is policy-filtered evidence plus operator context; output
  is candidate assessments tied to existing observation ids. The package owns question
  wording, batching and answer validation.
- **No authority.** Results assign no severity, authorize no check, change no accepted
  risk, suppress no finding and do not affect exit codes. Severity is the catalog's
  ([host-collector.md §6.2](host-collector.md)); a `severity` from any source is ignored.
- **A live adapter** follows the egress rules of [model.md §5](model.md): `--local-only`
  forbids a hosted assessment, and credentials come from the environment, never from
  fixtures or config. Provider probabilities stay separate from report confidence.
- **A production role** requires an explicit spec update after a measured result. A
  failed or unavailable experiment blocks nothing.

## The shape under test

The phase 2 record ([../eval/phase2-results.md](../eval/phase2-results.md)) failed in
two ways: the model never chose to call a tool, and its false positives were context
judgements about single items (a declared listener reported anyway, a workstation's own
launch daemons filed as persistence, an active firewall filed as a finding). A model
that never chooses its next action cannot fix the first; the second is exactly a yes/no
question about one item against a few fields of context. So R1 inverts control, and
adds no second execution path and no model-selected command (AGENTS.md rules 2 and 3):

1. **Enumerate in code** from the fact sheet, and settle what code can settle with
   deterministic filters.
2. **Follow up in code**, bounded: read one labeled catalog check per candidate from a
   fixed per-kind table, through `runner.RunAs` with the arm's own `Origin`.
3. **Ask per item.** One request per candidate: a state holding that item's records and
   only the context fields that bear on it, with that kind's independent questions
   batched. Never the whole fact sheet.
4. **Decide in code.** Raw probabilities are recorded; thresholds decide whether
   `finding.Store.Report` is called. Below them nothing is filed and the item is listed
   as considered.

Each kind files exactly one id from `internal/finding/catalog.go`:
`net.unexpected_listener`, `persist.unexpected_entry`, `fs.suid_unexpected`,
`accounts.unexpected_admin`. No other id is filed from this path. Rule-covered ids,
`expected_services` matching and `svc.expected_missing` stay with the posture rules and
[host-collector.md §5.3](host-collector.md). Finding text comes from the catalog `Def`.

**Decomposed questions, combined in code.** A candidate is judged by two or three
independent questions, never by one "is this unexpected given the context?", which asks
a literal reader to recognize the item and relate it to the operator's words in one hop
(limitation 4 below). Every question is a Noul: one form per judgement, because the
vendor's structural identities between forms do not hold and a threshold must never be
carried from one form to another.

## Three rules

These bind the code. A change that breaks one is wrong even if the arm scores better.

- **Nothing is filed from the absence of an explanation.** Every decision rule needs an
  affirmative signal: hallmarks of persistence, a program the model does not recognize,
  a world-writable directory code found. "Nobody declared this" is a property of the
  operator's notes, not of the host, and filing on it is what produced the phase 2 false
  positives (`TestSilenceAloneFilesNothing`, for every kind).
- **Insufficient evidence is never sent and never filed.** A record whose capture is
  truncated or redacted, or whose own line lost bytes, is settled by code as
  `insufficient` before any question exists
  (`TestInsufficientEvidenceIsNeverSentOrFiled`).
- **The follow-up table is a table.** No model picks a check, a path or an argument,
  and every read goes through `runner.RunAs` with the arm's `Origin`.

A corollary: **a question that names a state field must not be asked when that field
is empty, or when the command that produced it is known to degrade it.** The candidate
is `insufficient` instead. Listeners are the worked example both ways. On Linux,
`ss -tulpnH` names the owning process only for a privileged session, so an unprivileged
capture has an empty `process` and `vendor` would answer "not a known component" for
every listener (`TestListenerWithoutAProcessIsNotJudged`). On macOS, `lsof` shortens the
COMMAND column to nine characters unless given `+c 0`, so `ControlCenter` arrives as
`ControlCe`: worse than absent, because it looks like an answer
(`TestTruncatedProcessNameIsNotJudged`). That test reads the argv that produced the
capture, so it lifts by itself when the catalog entry improves; the macOS entry now
passes `+c 0`. This validation belongs in code, never in a criterion's wording.

## Vendor facts (docs.typesafe.ai, reviewed 2026-09-21)

Sources: [api](https://docs.typesafe.ai/api.md),
[models](https://docs.typesafe.ai/models.md),
[primitives/noul](https://docs.typesafe.ai/primitives/noul.md),
[state](https://docs.typesafe.ai/concepts/state.md),
[confidence](https://docs.typesafe.ai/confidence.md),
[jev-1.13 limitations](https://docs.typesafe.ai/model-jaggedness/jev-1.13.md),
[parallel questions cookbook](https://docs.typesafe.ai/cookbooks/parallel_questions.md).

| Fact | Value |
|---|---|
| Endpoint | `POST https://api.typesafe.ai/v1/systemone`, `Authorization: Bearer <key>` |
| Request | `{state, model, questions}`; `state` is a string, object or array of text; `questions` is a map of caller-chosen ids |
| Noul question | `{type: "noul", instructions, criteria: {true, false}}`; criteria are optional but they pin the boundary |
| Noul answer | `{type: "noul", noul: <0..1>}`, with **no separate confidence**: the probability is the answer and its certainty; ~0.5 means "similar probability either way", not "medium intensity" |
| Response | `{model, answers, usage: {input_tokens, output_tokens}}`; record the `model` field per answer |
| Errors | 401 invalid key, 422 validation, 429 rate limit, 529 overloaded (back off on the last two) |
| Model ids | `jev-1.13.0`; the aliases `jev-latest` and `jev-preview` **must not** appear in a record |
| Context | 64k total, of which **32k for state plus the longest question** |
| Price | **$42 per billion input tokens; output free** |
| Rate limits | 250k tokens/second, 1200 requests/minute (stated as variable under demand) |
| Input | Text only; English is most accurate |
| Other primitives | Choice (up to 255 options, distribution plus confidence), Score (2–10 ordered levels); neither is used here |
| Batching | Independent questions over one state go in **one** request and run in parallel; the vendor's cookbook reports a 12.2× cost reduction from batching 13 questions |

### Known limitations

Each documented jev-1.13 limitation and where this design handles it. The right-hand
column is the contract: a change that breaks it is wrong even if the arm scores better.

| Limitation | Where it is handled |
|---|---|
| 1. Literal reading: scoping words, negations and implied conditions are read at face value | Questions name the state field they are about; absent context is spelled out as `"not declared"` rather than omitted (`TestUndeclaredContextIsSpelledOut`) |
| 2. No counting or numeric comparison | Ports, counts, modes and the world-writable correlation are computed in code and passed as facts |
| 3. No date arithmetic | No question involves a date; expiry of an accepted risk stays with [host-collector.md §5.3](host-collector.md) |
| 4. One hop of indirection | Decomposition: recognize the item, relate it to context, spot hallmarks, never in one question |
| 5. Accuracy falls with unrelated state | One item per request; the fact sheet is never sent; a follow-up capture is clipped to 4 KiB |
| 6. Adversarial state moves answers | Target-derived text and operator prose are data; `testdata/context` and the adversarial pairs ([../eval/phase2-criteria.md §4](../eval/phase2-criteria.md)) measure it; code decides what is filed |
| 7. Contradictory instructions and criteria | Criteria are the complement of the instruction; `TestQuestionSetIsWellFormed` requires both sides |
| 8. Structural invariants do not hold (P(noul) ≠ 1 − P(not_noul)) | One form per judgement; no rule subtracts one probability from another; thresholds are per question |
| 9. No generation | The model writes no text: title, impact and remediation come from the catalog `Def` |

## R1: the bounded arm

| File | Owns |
|---|---|
| `bounded.go` | `Kind`, `Item`, `FollowUp`, `Request`, `Answerer`, `Options`, `Result`, and `Run`: enumerate → resolve → ask → decide → file |
| `enumerate.go` | candidate enumeration per kind and every deterministic filter |
| `followup.go` | the fixed per-kind follow-up table and the run-level resolver |
| `state.go` | the per-item state builder and its budget |
| `questions.go` | the question set, answer validation and `QuestionsVersion` |
| `decide.go` | thresholds and the per-kind decision rules |
| `scripted.go` | the R1 answer source (`<case>/bounded.yaml`) |

`Answerer` is the only seam where an answer enters the package: one probability per
question id, and a source name for the record.

### Enumeration sources

| Kind | Linux | macOS |
|---|---|---|
| `listener` | `net.listeners` (`ss -tulpnH`) | `net.listeners` (`lsof -nP +c 0 -iTCP -sTCP:LISTEN`) |
| `persistence` | `persist.units` (enabled unit files) and `persist.cron` (`grep -rH . /etc/crontab /etc/cron.d`, executable entries only) | `persist.launch_dirs` (third-party LaunchDaemons and LaunchAgents) |
| `suid` | `fs.suid`, annotated from `fs.world_writable` | same |
| `admin` | uid 0 in `accounts.passwd`, plus principals of `privesc.sudoers` / `privesc.sudoers_d` | `accounts.admins` (admin group membership), plus uid 0 in `accounts.users` |

Two sources are deliberately left out. `persist.timers` reports the schedule of units
`persist.units` already lists, so it only duplicates candidates. macOS
`persist.launchctl` is dominated by Apple's own loaded jobs; the plists on disk are the
inventory a judgement is about.

A source check that did not complete (`unavailable`, denied, failed) contributes no
candidates. Listeners are deduplicated by `port/proto`, keeping the first record; an
account that is both uid 0 and a sudoers principal is one candidate.

### Deterministic filters

Code settles these, in this order; no question is ever asked.

| Filter | Status | Why |
|---|---|---|
| Listener bound to `127.*`, `::1` or `localhost` | filtered | Not reachable beyond the host |
| Listener matching an `expected_services` entry | filtered | [host-collector.md §5.3](host-collector.md) owns this, in code. Asking anyway was a phase 2 false positive (`linux-context-explains`) |
| `root` as an admin candidate | filtered | root *is* the account uid 0 names |
| `%sudo`, `%wheel`, `%admin` | filtered | A distribution's own administrative principals; the accounts behind them are candidates through their own records |
| A sudoers principal whose grant lists specific commands | filtered | `accounts.unexpected_admin` means "can escalate to root". scheck's own `/etc/sudoers.d/scheck` fragment names its commands and no `ALL`, so its principal is filtered |
| A listener whose capture came from `lsof` without `+c 0` | insufficient | The name is shortened (see "Three rules") |
| A listener whose capture does not name the owning process | insufficient | Nothing to recognize (see "The defect the probe found before it ran") |
| Source capture `Truncated`, `Redactions > 0` or carrying a marker; or the item's own line empty or marked | insufficient | Bytes were removed, and what was removed cannot be judged ([host-collector.md §4.2, §6.5](host-collector.md)) |

### The follow-up table

Every read goes through `runner.RunAs` with `Origin{Tool: "bounded_followup"}`, so the
menu gate, path policy, redaction, truncation and the audit trail apply unchanged.

| Kind | Read |
|---|---|
| persistence / systemd unit | `fs.list` of `/etc/systemd/system` **once per run**, then `text.cat` of `/etc/systemd/system/<unit>` only for units in that listing |
| persistence / cron entry | `text.cat` of the absolute program the entry runs, when the command begins with one and it holds no shell metacharacter |
| persistence / launchd job | `text.cat` of the plist path |
| listener, admin, suid | none |

A listener's owning process is not a file. A SUID binary's tree (`/usr/bin`,
`/opt/*/bin`) is outside the path policy's readable prefixes; the world-writable
correlation it needs comes from code.

**Tried and abandoned** on `linux-unit-in-tmp` (14 enabled units, 9 SUID binaries): a
`text.cat` per enabled unit made 14 reads, 12 `unavailable` (vendor units live under
`/lib/systemd`), 1 `denied:invalid_params` (the `@` of `getty@.service` is outside the
path parameter's `^[A-Za-z0-9._/-]+$`) and 1 that mattered; the directory listing
replaced them with 2. An `fs.stat` per SUID binary made 9 reads, all denied by path
policy. That was 23 reads per Linux case with 22 useless results: a follow-up is only
bounded if code checks first whether the read can succeed.

An unavailable or denied follow-up is not an error, and neither is a truncated or
redacted one, whose bytes are not sent. Each becomes `definition_note` in the state
("could not be read: …"), and the affirmative-evidence rule then has nothing to stand
on (`TestUnreadableDefinitionIsRecordedNotConcluded`).

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

Every `host` field is always present, as `"not declared"` when absent: a literal reader
can use that, an absent field it cannot. `declared_services` is carried for listeners
only; on any other kind it is a distractor (`TestUnrelatedContextIsLeftOut`).
`TestStateCarriesOnlyItsOwnItem` asserts that no state mentions another candidate's
evidence. Operator prose is data; the injection corpus is its boundary test.

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

Thresholds are **provisional**: chosen to express the rules, never measured. Nothing is
calibrated until a live record on held-out cases says so.

`Unexplained 0.2 · NotStandard 0.3 · Affirmative 0.6 · Strong 0.8`

| Kind | Files when | Confidence |
|---|---|---|
| `listener` | `vendor < 0.3 && explained < 0.2` | high when `sensitive ≥ 0.6`, else medium |
| `persistence` | `hallmarks ≥ 0.8`, or `hallmarks ≥ 0.6 && vendor < 0.3` | high on the first, medium on the second |
| `suid` | `vendor < 0.3 && (directory is world-writable \|\| hallmarks ≥ 0.6) && explained < 0.2` | high when the directory is world-writable, else medium |
| `admin` | `person < 0.3 && explained < 0.2` | medium |

`sensitive` never files on its own: ssh and screen sharing are sensitive by design. The
confidence word comes from the decision, never from the model; severity is the
catalog's (`medium` for all four ids). A filed candidate cites the source observation
and, when there is one, the follow-up's first meaningful line; `finding.Store.Report`
validates each excerpt against the observation it cites, and a refusal files nothing
and is recorded on the item.

### Versioning, budgets and the record

`bounded.QuestionsVersion()` hashes the question ids, types, instructions and both
criteria, the default thresholds and the state-builder version (`state-1`) into
`bq-<12 hex>`. Its value at R1 is **`bq-68cbe087c689`**. A record carries it so no
threshold is ever read against a question it was not measured on.

Budgets: `MaxItems` 128 judged candidates per run (reaching it ends the arm as
`budget: items` and marks the rest `over_budget`); follow-up reads, the shared listing
included, bounded by `Budgets.AgentChecks` (60); follow-up text clipped to 4 KiB per
state; the arm inside `RunTimeout` (ending as `budget: run timeout`). A missing,
malformed, out-of-range or `NaN` answer files nothing and marks the item `no_answer`
(`TestUnusableAnswersFileNothing`).

Each item records kind, key, source check and observation, verbatim excerpt, fields,
follow-up, status (`judged` / `filtered` / `insufficient` / `no_answer` /
`over_budget`), raw probabilities and the decision sentence. The results file carries
`bounded_source` and `bounded_questions_version`; the comparison report prints a
`## Bounded arm` section. The follow-up capture is never stored in the record, only
cited through its observation.

### The scripted answer source

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
`linux-unit-in-tmp` (the unit file has `ExecStart=/tmp/.x/agent`), `linux-cron-fetch`
(the script pipes a download into a shell) and `linux-suid-in-world-writable`
(`/opt/tool/bin/helper`, where `hallmarks` stays at 0.45 so the rule must lean on the
world-writable fact code supplied). An item with neither an override nor a kind default
gets no answer, which files nothing and marks it.

## What R1 does on the committed suite

`scheck eval --provider mock --arms rules,single-pass,agent,bounded --no-pairs`, one
repeat, scripted answers: plumbing, not quality. An unqualified `scheck eval` still
compares the three frozen arms; the research arm is asked for by name.

| arm | correct | false positives | missed | abstentions | resolved follow-ups |
|---|---|---|---|---|---|
| rules | 0 | 0 | 0 | 0 | 0 |
| single-pass (mock transcripts) | 1 | 0 | 5 | 9 | 0 |
| agent (mock transcripts) | 2 | 1 | 4 | 8 | 1 |
| **bounded (scripted)** | **3** | **0** | 3, all outside its design | 9 | 2 of 2 in scope |

**377 requests over the 15 cases**: 28–29 per Linux case, 1 for `macos-clean`, 9 for
`macos-filevault-off`. 73 candidates are filtered and 11 are `insufficient` (ten Linux
listeners with no process name, one truncated capture in `linux-truncated-listeners`).
The largest state is 338 bytes, about 84 tokens. Follow-ups are counted per item and
audited in full; the shared listing is audited but not counted against an item:

| case | counted follow-ups | audited reads |
|---|---|---|
| `linux-unit-in-tmp` | 1 | 2: `fs.list` of `/etc/systemd/system`, then `text.cat` of the unit |
| `linux-cron-fetch` | 1 | 2: the listing (unavailable here), then `text.cat` of the script |
| every other Linux case | 0 | 1: the listing alone |
| `macos-filevault-off` | 3 | 3: one `text.cat` per third-party plist |
| `macos-clean` | 0 | 0 |

### What this arm deliberately does not cover

Three expected ids are deterministic correlations across two checks, not context
judgements; the arm scores them as misses on purpose and the comparison report names
them.

| Case | Expected id | What it needs |
|---|---|---|
| `linux-no-firewall` | `fw.no_firewall_active` | ufw inactive **and** firewalld absent **and** an empty nft ruleset |
| `linux-password-auth-public` | `sshd.password_auth_exposed` | `passwordauthentication yes` **and** a non-loopback `listenaddress` |
| `linux-sshd-include` | `sshd.password_auth_enabled` | `sshd -T` refused **and** a drop-in under `sshd_config.d` that sets it |

None needs a model. What is missing is a multi-fact rule tier, which
[host-collector.md §6.5](host-collector.md) forbids today ("one rule reads one check"):
a rules change, with a predicate that abstains unless every input is recognized and the
same three fixtures per rule, not a question.

### Gaps in the suite

- **The macOS false-positive surface is unlabeled.** `macos-filevault-off` carries the
  workstation shape phase 2 got wrong (three third-party LaunchDaemons, wildcard
  listeners such as AirPlay on 7000/5000 and postgres on 5432, `alice` in the admin
  group), but its `forbid:` list is empty. `macos-clean` masks the daemons and binds
  every listener to loopback, so it measures nothing here either.
- **The macOS fixture does not record the plist reads**, so the three launchd items are
  judged on path and label.
- **Only `linux-unit-in-tmp` records a usable `/etc/systemd/system` listing**; elsewhere
  units are judged on their names alone.
- **Only two cases carry operator context** (`linux-context-explains`,
  `linux-truncated-listeners`); everywhere else `explained` is answered against `"not
  declared"`, which exercises only the conservative half of each rule.

## The recall probe

`make probe` runs `test/live/jev_probe_test.go` (build tag `live`): it needs
`TYPESAFE_API_KEY`, sends **recorded fixture data only**, and costs a fraction of a
cent. It is deliberately not an adapter. It enumerates 30 labeled candidates from the
committed fixtures as a run would, captures each one's real `bounded.Request` through a
capturing `Answerer` (state **after** follow-up reads), sends it with the frozen
`bounded.Questions` to `jev-1.13.0`, and applies `bounded.Decide`.

The labels: standard (Ubuntu's nine SUID binaries and thirteen enabled units, macOS's
own listeners, three third-party LaunchDaemons installed on purpose) and two planted
items nothing ships, `unit:agent.service` and `suid:/opt/tool/bin/helper`. Linux
listeners are absent because they are `insufficient` on an unprivileged capture.

**The gate is what the decision rules do**, not whether `vendor` separates on its own:
the probe fails on a false positive or an uncaught planted item, and reports `vendor`
separation as a diagnostic. It prints every item with all its answers.

### Result: 2026-09-21, 30 items, 19,405 input tokens, $0.0008, 8.5 s

```
item                                           want      vendor     other answers
unit: 13 Ubuntu units                          standard  0.92-0.97  hallmarks 0.03-0.04
unit:agent.service                             planted   0.39 <<    hallmarks 0.96
suid:/usr/bin/sudo, su, passwd                 standard  0.96-0.97
suid:/usr/bin/gpasswd, chfn, newgrp, mount     standard  0.84-0.94
suid:/usr/bin/chsh                             standard  0.69
suid:/usr/bin/umount                           standard  0.47
suid:/opt/tool/bin/helper                      planted   0.10       hallmarks 0.19
launchd: com.docker.vmnetd, com.docker.socket  standard  0.90-0.93
launchd: com.nordvpn.macos.helper              standard  0.88       hallmarks 0.06
listener:53019/tcp (rapportd)                  standard  0.55       sensitive 0.17
listener:7000/tcp  (ControlCe)                 standard  0.27 <<    sensitive 0.40
listener:5000/tcp  (ControlCe)                 standard  0.20 <<    sensitive 0.34

explained 0.02-0.04 on every item
decision rules: 2 planted items caught, 2 false positives over 30 items
  caught: suid:/opt/tool/bin/helper (vendor 0.10, directory is world-writable)
  caught: unit:agent.service (hallmarks 0.96)
  FALSE POSITIVE: listener:5000/tcp, listener:7000/tcp (not a recognized component)
```

### Result: 2026-09-22, after the capture fix

One input changed: `net.listeners` on macOS gained `+c 0`. Same questions, thresholds,
fixtures and model.

```
listener:7000/tcp   ControlCe -> ControlCenter        vendor 0.27 -> 0.65
listener:5000/tcp   ControlCe -> ControlCenter        vendor 0.20 -> 0.64
listener:53019/tcp  rapportd  -> rapportd (unchanged) vendor 0.55 -> 0.53

decision rules: 2 planted items caught, 0 false positives over 30 items   PASS
```

`rapportd`, the one macOS name never shortened, is the control: its score did not move,
while the two shortened names roughly tripled. The failure was the evidence, not the
judgement. The macOS fixture was updated by widening its five shortened names to their
live counterparts on the recording host (each an unambiguous prefix match); the
command-trace, report and JSON goldens changed by exactly one command.

### What the probe establishes

- **Recall is strong where the identifier is clean**, including the three third-party
  LaunchDaemons (a phase 2 false-positive class), correctly not filed.
- **The decomposition held where `vendor` was wrong.** The planted `agent.service` got
  `vendor` 0.39, but with the unit file in state `hallmarks` came back 0.96 and the rule
  caught it on that alone. No single answer is load-bearing.
- **`hallmarks` is the sharpest signal**: 0.03–0.07 on every legitimate unit and plist,
  0.96 on the planted one.
- **`vendor` separation is narrow.** In the second run the lowest standard item is 0.44
  and the planted unit 0.43; it works only because code combines it with other answers.
- **Variance is small but real** (`vendor` on `listener:7000/tcp`: 0.26 / 0.22 / 0.27
  over three runs), and **cost is not a constraint** (the suite at three repeats is
  about 1,200 requests and under two cents). A record needs three repeats.

The short form: Jev answers well where scheck hands it a clean identifier or readable
evidence and badly where scheck hands it a mangled one, so evidence quality is the
lever, not model choice. This is one run of 30 items on one model, not a calibration.

The probe's first run built state straight from `bounded.Enumerate`, without the
follow-up reads, and is not the record. Judged on its name alone, `unit:agent.service`
scored `vendor` 0.77 and `hallmarks` 0.05; the follow-up moved `hallmarks` to 0.96.
That is the measured value of the follow-up table. The listener and admin kinds have no
follow-up and are judged on an identifier alone, which is where the false positives
landed.

## The defect the probe found before it ran

The probe's dry run printed the state for `listener:22/tcp` from the Ubuntu fixture
with an **empty** `process` field: `ss -tulpnH` names the owning process only for a
privileged session, and `net.listeners` is not an elevated check.

The `vendor` question names `item.process`, and its `false` criterion reads "or no
program name was captured". A real model would have answered low for every Linux
listener on every unprivileged run, and with `explained` low by default the rule would
have filed `net.unexpected_listener`: the phase 2 false positive (`sshd` on
`0.0.0.0:22` with no context) by another route, firing on `linux-clean`, where the id
is forbidden.

Fixed: a listener whose capture does not name the owning process is `insufficient`;
unknown is neither safe nor unsafe ([host-collector.md §6.5](host-collector.md)).
macOS is unaffected because `lsof` names the command. The consequence: **the listener
kind is effectively macOS-only without elevation** until Linux captures name the
process (a `ps -p <pid> -o comm=` follow-up check would do it, and would serve the
report as much as a model).

## Open questions for R2

1. **Thresholds are provisional.** None is measured, and the suite is too small to hold
   cases out for calibration.
2. **How is a Noul-shaped answer obtained from a generative adapter** through
   `internal/llm` without a second calibration story? Its number is that model's, never
   a probability comparable to Jev's.
3. **Does `sensitive` earn its place?** If it never changes an outcome on real answers,
   drop it and save a third of the listener tokens.
4. **Linux admin enumeration is incomplete.** The catalog has no group-membership check,
   so a member of `%sudo` who is neither uid 0 nor named in sudoers is never a
   candidate. Closing it means adding a catalog check first.
5. **Listener deduplication keeps the first record**, so a port bound to loopback on
   one address family and a wildcard on the other is decided by print order. The fix is
   one candidate whose `reachable` is the wider of the two.
6. **Can Jev answer `vendor` at all?** Answered by the recall probe: yes, where the
   identifier is clean. Still open: whether `vendor` earns its tokens once package
   provenance (`dpkg -S`, `rpm -qf`, `codesign -dv`) is a catalog fact, which would
   also support a single-fact rule for a SUID binary no package owns.
7. **The suite cannot measure recall.** Two of the four ids have no positive case:

   | judgement id | cases expecting it | cases forbidding it |
   |---|---|---|
   | `net.unexpected_listener` | **0** | 5 |
   | `persist.unexpected_entry` | 2 | 2 |
   | `fs.suid_unexpected` | 1 | 2 |
   | `accounts.unexpected_admin` | **0** | 2 |

   A live record on this suite could only say "it did not cry wolf".
8. **Item volume on a real host is unmeasured.** About 30 candidates per case is a
   container fixture; `MaxItems` (128) has never been reached.

## Toward 0.0.4

The slices after R1 were meant to settle whether this shape earns a production role.
That work is now planned under the `auto` gate in [../ROADMAP.md](../ROADMAP.md).

- **R2, generative comparison:** the same frozen questions through an available
  generative adapter, on the same per-item state, scored with the frozen metrics
  ([../eval/phase2-criteria.md §3](../eval/phase2-criteria.md)) at three repeats. It
  measures whether the decomposition itself removes the false positives, says nothing
  about Jev, and freezes the questions and thresholds.
- **R3, Jev adapter and live evaluation:** a small net/http adapter built on the vendor
  facts above (key from the environment, model pinned and recorded per answer, answers
  validated, 401/422/429/529 classified with backoff on the last two, budgets and egress
  policy checked before sending), then three repeats with the adversarial pairs,
  reading drift per item as well as per finding. The recall probe is its reference.
- **R4, integrate or not:** an evidence-backed decision to keep, remove or propose a
  bounded production role with explicit fallback and coverage semantics, citing the R2
  and R3 records, and saying what to do with the multi-fact rule tier.
- Close the suite gaps and add a positive case for the two ids that have none before
  any threshold is called calibrated.
