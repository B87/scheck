# Evaluation suite (M2.7)

`cases/<name>/` is one labeled case: `manifest.yaml` inherits a recorded fixture
(`base:`) and overrides the few facts that make the case; `labels.yaml` says what a
correct assessment reports (`expect_model`), what it must not (`forbid`,
`forbid_custom`), which rule findings the rules arm produces (`expect_rules`), and for a
follow-up case the on-demand check that resolves it (`resolving_check`); `context/`
holds the operator context the case runs with. `transcripts/<arm>.json`, when present,
scripts the mock provider for that arm; mock runs validate the harness, never quality.
`bounded.yaml` holds the research arm's scripted answers for that case (defaults per
candidate kind, overridden per item key); they exercise `internal/bounded` end to end
and are never a model's answers.

`scheck eval --suite testdata/eval --model MODEL --repeat 3 --out results.json` runs
the three arms of `docs/eval/phase2-criteria.md` and the adversarial pairs from
`testdata/context`, then one benign control twice per repeat as the drift baseline, and
prints the comparison. Progress lines go to stderr as each run ends, with the ids the
model reported; `--out` is rewritten after every run, so an interrupted run leaves a
record; `--cases NAME,NAME` runs a subset while iterating on one case (the record is
then below the minimums and says so). The frozen criteria say what passes.
