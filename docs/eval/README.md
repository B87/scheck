# Evaluation records

Recorded evidence: frozen criteria, evaluation results and release acceptance passes.
Records are appended to, never rewritten, so they cite documents as they were when the
record was made. Before 2026-10-06 that meant `docs/SPEC.md`, `docs/ROADMAP-0.0.1.md` and
`docs/ROADMAP-RESEARCH.md`; read them at the record's commit in git history. Their
contracts now live in `docs/spec/` (`host-collector.md`, `model.md`, `bounded.md`).

| Record | What it is |
|---|---|
| `acceptance-0.0.1.md` | The 0.0.1 release acceptance pass |
| `phase2-criteria.md` | The criteria the model path was judged against, frozen before the run |
| `phase2-results.md` | The model path's evaluation: failed, so no model assesses a host |
| `results-*.md`, `results-*.json` | The raw records behind `phase2-results.md` |
| `lab-0.0.2-domain.md` | The 0.0.2 lab's domain part: where its sealed labels are, their hash, the seeder and the false-positive target |
| `e5-closing-review-2026-10-10.md` | E5 whole-slice offline review, wording fixes and pending token/lab/live acceptance prerequisites |

New releases add `acceptance-<version>.md` (see `../RELEASING.md`), and any model
feature that becomes a default adds its frozen criteria and results here first.
