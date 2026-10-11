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
| `e5-credential-decision-2026-10-10.md` | Owner-approved unranked credential warning, offline verification and honest postimplementation evaluation plan |
| `e6-authentication-definition-2026-10-10.md` | Targeted AI authentication DEFINE contract for E6 step 1; no measurements or acceptance |
| `e6-definition-2026-10-10.md` | E6 AI definition and wording reviews, the missed historical lab seal, and pending independent evaluation prerequisites; no measurements or acceptance |
| `e6-identity-definition-2026-10-10.md` | Targeted E6 step-3 AI parser, privilege, date and coverage DEFINE contract; implementation and verification pending |
| `e6-identity-verification-2026-10-10.md` | E6 step-3 offline rule verification, projection/login corrections and fresh follow-up review; no live or independent acceptance |
| `e6-inventory-review-2026-10-10.md` | E6 step-2 AI consultant/client/modularity reviews, software-check status and deferred report wording; no live or independent acceptance |
| `e6-inventory-verification-2026-10-10.md` | E6 step-2 adversarial cursor/refresh corrections, green final offline checks and fresh follow-up review; no live or independent acceptance |
| `e6-two-step-definition-2026-10-11.md` | Targeted E6 step-4 AI DEFINE contract for observed 2-step verification; no software tests, measurements or acceptance |
| `e6-two-step-verification-2026-10-11.md` | E6 step-4 implementation, DEFINE differences, AI consultant/client/modularity reviews, adversarial corrections, green offline checks and fresh follow-up review; no live or independent acceptance |
| `e6-oauth-definition-2026-10-11.md` | Targeted E6 step-5 AI DEFINE contract for optional OAuth grant metadata; no software tests, measurements or acceptance |
| `e6-oauth-verification-2026-10-11.md` | E6 step-5 implementation, DEFINE differences, AI consultant/client/modularity reviews, adversarial corrections, green offline checks and fresh follow-up review; no live or independent acceptance |
| `e6-forwarding-definition-2026-10-11.md` | Targeted E6 step-6 AI DEFINE contract for optional Gmail forwarding metadata and the owner's decisions; no software tests, measurements or acceptance |
| `e6-forwarding-verification-2026-10-11.md` | E6 step-6 implementation, DEFINE differences, AI consultant/client/modularity reviews, green offline checks; adversarial review pending; no live or independent acceptance |

New releases add `acceptance-<version>.md` (see `../RELEASING.md`), and any model
feature that becomes a default adds its frozen criteria and results here first.
