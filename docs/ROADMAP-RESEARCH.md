# scheck — optional research roadmap

**Status (2026-09-20):** proposed experimental work, deferred from 0.0.1. No product
release version or delivery date is assigned. No slice below is marked implemented.
**No TypeSafe API key is held**; access is waitlisted and R3 stays deferred until a key
exists. R1 and R2 need no key.

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

1. **Enumerate in code** from the fact sheet: every enabled unit, timer, cron entry and
   launchd job; every non-loopback listener; every SUID binary; every administrative
   account. Deterministic filters that already exist stay in code: path prefixes,
   `expected_services` port/proto matching, counts, dates, redaction and truncation
   markers. A candidate whose evidence is `unavailable`, truncated or redacted is
   recorded as `insufficient` by code and never sent.
2. **Follow up in code**, bounded: for a candidate whose baseline record is not enough
   (a unit's `ExecStart`, a cron script's content, a sshd drop-in), run the labeled
   catalog check through `runner.RunAs` with its own `Origin`. The menu gate, path
   policy, redaction and audit apply unchanged. The set of follow-up checks per
   candidate kind is a fixed table, not a model decision.
3. **Ask per item.** One request per candidate: a `state` object holding that item's
   records and only the context fields that bear on it (`role`, `environment`,
   `exposure`, the matching `expected_services` entries, relevant prose), with the
   independent Noul questions for that kind batched in the same request. Never the
   whole fact sheet: accuracy falls with unrelated detail and the state budget is
   bounded (32k tokens for state plus the longest question at `jev-1.13`).
4. **Decide in code.** Probabilities are recorded raw. A threshold chosen on held-out
   cases decides whether `finding.Store.Report` is called with the judgement id; below
   it, nothing is filed and the item is listed as considered. Severity, the grader,
   the envelope and exit codes are untouched (§5.9).

Judgement ids in scope, all present in `internal/finding/catalog.go`:
`persist.unexpected_entry`, `net.unexpected_listener`, `fs.suid_unexpected`,
`accounts.unexpected_admin`. Rule-covered ids and `svc.expected_missing` stay with the
rules and §6.3. Finding text comes from the catalog `Def`; the model generates nothing.

Question wording, criteria, the per-kind follow-up table and the state builder are
versioned data with a hash recorded in every result, the way `agent.PromptVersion` is.
One question form per judgement (a Noul, not a Noul and a Choice): the vendor's own
limitations page says structural identities between forms do not hold, so a threshold
is never carried from one form to another.

Known limits to design around, from the vendor's limitations page (reviewed
2026-09-20): literal reading of instructions, no counting or numeric comparison, no
date arithmetic, one hop of indirection, context rot on large state, adversarial state
can move an answer, no generation. Every one of these lands in code under the shape
above; the injection corpus still applies because target-derived text is part of the
state.

## Research slices

### R1 — bounded arm in the existing harness, offline
No key needed. Add a fourth arm, `bounded`, to `internal/eval` over the same fifteen
cases, identical facts, rule findings and context as the other three. Implement the
enumeration, deterministic filters, per-kind follow-up table, per-item state builder
and the decision step; the answer source is an interface with a scripted
implementation that replays authored answers keyed by case and item. The experiment
lives in its own package that `agent`, `policy`, `check`, `finding`, `report` and
`llm` never import (`scripts/depcheck.sh` extends to it); `eval` imports it.
**Demo:** `scheck eval --provider mock --arms rules,single-pass,agent,bounded` prints
the comparison with the fourth column, and the follow-up metric is exercised because
code ran the labeled `text.cat`.
**Done when:** the arm runs in `make check`; every request's state is asserted to
contain only that item's records and the bearing context fields; `insufficient` items
are asserted never sent and never filed; missing, malformed and out-of-range answers
file nothing and mark the item; the audit log shows every follow-up read under the
arm's `Origin`; rule findings are byte-identical across arms. Scripted answers are
labeled as such; a passing run makes no quality claim.
**Spec:** §5.9, §11.

### R2 — the same questions through the available generative adapter
No key needed; spends a few cents. Answer the R1 questions through the
`openai-compatible` adapter with the answer forced to `yes`, `no` or `unsure` on the
same per-item state, and score the arm with the frozen §3 metrics at three repeats.
This measures whether the decomposition itself, not the vendor, removes the false
positives and resolves the follow-up cases; it says nothing about Jev's calibration.
**Demo:** `scheck eval --arms bounded --bounded-source openai --repeat 3` appends a
dated section to `docs/eval/phase2-results.md` attributed to that model.
**Done when:** the record shows correct additional findings, false positives, missed
issues, abstentions, resolved follow-ups, latency and cost for the bounded arm next to
the three existing arms, on the same cases and labels. Freeze the question set and
thresholds before R3.
**Spec:** §5.9, §11.

### R3 — Jev adapter and live evaluation, deferred until a key exists
Only when credentials are available. A small net/http adapter inside the experiment
package: `POST /v1/systemone`, `TYPESAFE_API_KEY` read at request time and never
printed, the model pinned to a versioned id (`jev-1.13.0`, never an alias) and the
response's `model` field recorded per answer. Validate every answer's id, type, and
range; classify 401, 422, 429 and 529 as error kinds with bounded backoff on the last
two; check the state and question budgets before sending; enforce egress policy before
any request (`--local-only` forbids it). A local fake server exercises all of it.
**Demo:** `scheck eval --arms bounded --bounded-source jev --repeat 3` with the
adversarial pairs, reading §4.4 against per-item probability drift as well as filed
findings.
**Done when:** the record answers whether accuracy, follow-up resolution and cost
justify adoption against the rules, single-pass, agent and R2 arms. No threshold is
treated as calibrated without the held-out cases. Access unavailable means this slice
stays deferred; it does not block any product release.
**Spec:** §5.9, §4.4, §11.

### R4 — decide whether to integrate
Write an evidence-backed decision: keep the experiment, remove it, or propose a bounded
production role with explicit fallback and coverage semantics. Any production
integration requires updating the spec, reporting contract and tests first. Do not
silently promote an experimental assessment into a finding filter or an investigation
gate.
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
