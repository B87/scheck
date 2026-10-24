# E6 tenant-inventory final software verification

Recorded 2026-10-10 on `e6-workspace-collector`. This supplements
[e6-inventory-review-2026-10-10.md](e6-inventory-review-2026-10-10.md), which remains
unchanged. Outcomes below are reported by the implementing session and AI Codex
reviewers; their exact model identifiers were not exposed. This is software
verification, not independent security acceptance, blind SEED/RANK work, a live
measurement or a release gate.

## Adversarial findings and corrections

The fresh AI adversarial reviewer `e6_step2_code_review` confirmed two defects:

- Present null or empty next-page cursors could be mistaken for a complete
  population, allowing dependent current-user admission without usable completion
  evidence.
- An earlier `NextOf` continuation could restore admission after an initial
  inventory refresh failed, because pending page state survived the refresh.

The implementing session corrected both. A present null, empty or non-string
Workspace next cursor is unreadable and incomplete. Binding bootstrap, unit refresh
and initial user refresh revoke the asset's pending continuations before contact;
an initial user refresh also resets its private current-user inventory before
sending. A failed refresh cannot restore admission through an older page.

Regression tests cover null, empty, numeric and object cursors; failed initial user
and unit refreshes; and rebootstrap followed by an old cursor. Dependent details
remain refused. The spec records these requirements under “Population bounds”.

## Final offline verification

| Verification | Result and attribution |
|---|---|
| Full `make check` after corrections | Green, exit 0; implementing-session log `/tmp/scheck-e6-step2-final-check.log` |
| Fresh adversarial follow-up | AI `e6_step2_fix_review`, fresh context; no confirmed findings and no must-fix items after examining the fixes and adjacent admission behavior |
| Focused boundary race tests | Reviewer reports `go test -race ./internal/engagement/gate -run TestWorkspace -count=1` passed and checked the final full-check log |
| Consultant/client/module reviews | Completed as attributed in the preceding review record; final code corrections preserve the defined inventory-only and no-reuse contract |

Step 2 collects tenant inventory and people-attribution evidence. It returns no
Workspace posture judgments. Security controls remain `not_assessed` with `no_rule`,
including when inventory completes and exit is 0. E6 step 3 is next: identity and
administrator rules, with their separate definition and implementation reviews.

No live Workspace API request, real tenant measurement, independent recall or
false-positive result, or release acceptance is recorded here. Root-unit
parent-sentinel compatibility remains unmeasured live. Client wording nits remain
E9 report-wide polish as recorded in the roadmap. E3's missed historical rest-lab
seal is neither repaired nor waived; independent lab preparation and acceptance
remain pending.
