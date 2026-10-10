# E6 tenant-inventory software review

Recorded 2026-10-10 on `e6-workspace-collector`. This records AI Codex role reviews
reported by the implementing session. It is not independent human security
acceptance, blind SEED/RANK work, a live measurement or a release gate. Exact model
identifiers were not supplied; the client role described its model as GPT-6.

## Definition and implementation

AI security-consultant `e6_inventory_define` supplied DEFINE guidance before step-2
inventory and admission were fixed, then reviewed the result. One collector call
owns ordered binding, domain/alias, organizational-unit and customer-bound user
inventory, people attribution and diagnostic notes. The gate owns customer/query
selectors, cursors, fresh current-user admission, exclusions before persistence and
service-account delegated-user verification. Workspace authenticated responses are
never reused on resume, including when a delegated account was freshly verified.

Step 2 introduces no Workspace posture judgments. Inventory completion does not
assess account security, administrative access, 2-step verification or optional
OAuth/Gmail metadata. Their rules remain later E6 work. A known exclusion drop can
leave retained coverage partial while admitting only current nonexcluded user
details; an actual cut, unknown identity or conflict prevents dependent details.
Provider root-unit parent-sentinel compatibility remains unmeasured live.

## Review results and corrections

| Review | Attribution and result reported by the implementing session |
|---|---|
| Security-consultant DEFINE/REVIEW | AI `e6_inventory_define`; REVIEW passed after partial-report and multiple-account attribution corrections |
| Client REPORT | AI `e6_step2_client_report`, fresh Brightcart operator roleplay; no blockers after regenerated report wording fixes |
| Modularity DESIGN/ASSESS | AI `e6_inventory_design`; unused person-kind input removed and collector-owned `InventoryComplete` summary implemented |

The partial Workspace report initially used host-specific missed-read wording.
That wording was corrected rather than implying a host had failed collection in a
Workspace-only run. Attribution was corrected to match each declared address
independently: one person can own multiple current accounts, while competing people
for the same account leave attribution unknown. Alias-only attribution still
requires a complete observed population. These corrections were reviewed by the
consultant; the client reviewed the corrected generated report.

The client retained nonblocking wording advice: explain credential permissions,
counts and operation names in plain words; reduce repeated Workspace labels; review
the generic "Fix these first" heading. These are carried to E9 report-wide polish,
not security findings or permission to soften unknown coverage.

## Verification status at this record

The implementing session reports one complete green `make check` and a subsequent
passing targeted cap regression. A final full repeat is running; this record does
not claim that repeat passed or that the fresh adversarial review completed. No live
Workspace API, real tenant, independent recall/false-positive measurement or release
acceptance was run. Final verification and adversarial outcomes must be recorded
separately once available.

E3's required rest-lab seal before the first E5/E6 implementation was missed before
E5. This software review cannot repair or waive that historical deadline. Independent
lab preparation and acceptance remain pending.
