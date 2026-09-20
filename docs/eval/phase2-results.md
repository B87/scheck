# Phase 2 evaluation — results record

This file records the evaluations `docs/eval/phase2-criteria.md` requires before 0.0.1
(SPEC §12 criteria 7, 10 and 12). It is appended to, never rewritten: every live run
adds a dated section with its model, prompt version, scheck version, the command used
and the outcome per criterion, plus the failures.

## Status (2026-09-20)

**No live evaluation has been run.** The harness (`internal/eval`, `scheck eval`), the
labeled suite (`testdata/eval`, fifteen cases: 2 clean, 3 single-fact, 3 correlated,
3 follow-up, 4 misleading) and the adversarial corpus (`testdata/context`, eight
pairs) exist and are exercised in `make check` with the mock provider, which
validates the harness and makes no quality or resistance claim.

Consequences for the release gate:

- **Criterion 10 (phase 2 earns its cost): not decided.** Whether the agent loop stays,
  or single-pass replaces it, or neither ships, is unknown until a live run is recorded
  here and judged against §3 of the criteria.
- **Criterion 12 (adversarial): not passed.** The mock pairs are identical by
  construction; only a real model can fail or pass §4.
- **Criterion 7 (cost under $0.50): not measured.** `make live` runs one real `scheck
  local` and asserts it; it has not been executed.

## How to produce a record

With `OPENAI_API_KEY` in the environment (or `--base-url` for another endpoint):

```sh
go run ./cmd/scheck eval --model gpt-5-mini --repeat 3 --format json --out docs/eval/results-$(date +%F)-gpt-5-mini.json
go run ./cmd/scheck eval --model gpt-5-mini --repeat 3 > docs/eval/results-$(date +%F)-gpt-5-mini.md
make live
```

Then add a section below with the date, the model string the endpoint reported, the
`prompt_version` from the record, the scheck version, every criterion's PASS/FAIL line
from the markdown report, and the pairs or cases that failed. A criterion is judged as
frozen at M2.1; if the criteria file changed since, the commit that changed it and its
reason are cited here.

## Records

_None yet._
