# 0.0.2 release gates: not run, lab gates deferred to v1.0.0

Recorded 2026-10-25 on `docs-roadmap-cleanup`. The decisions are the maintainer's, given
to the recording session on 2026-10-25. The recording session is Claude (model id
`claude-sonnet-5-5`) acting as the spec-steward. This is not an acceptance pass and not a
measurement. No code ran and nothing was contacted for this record; it states decisions
and what the earlier records already say. It supplements them and rewrites none.

## Decisions

| Date | Decision |
|---|---|
| 2026-10-24 | `release/v0.0.2` was merged into `main` (pull request #21). The 0.0.2 gates 1 to 11 were not run. `docs/eval/acceptance-0.0.2.md` does not exist. No tag or release was cut for 0.0.2. |
| 2026-10-25 | The lab (E3's rest of the lab, G7's GCP lab, and every acceptance pass that needs one) is deferred as a gate for v1.0.0. There is no Google Workspace lab: Workspace is exercised read-only on the maintainer's production tenant and is not measured ([spec/lab.md](../spec/lab.md), "Google Workspace: no lab, observed on the production tenant"). The lab spec is merged. |

## The 0.0.2 gates, as recorded here

Each is *not run*. None is passed. The column says only why the gate is open; the
roadmap's "Release gates and the lab" holds the reconciliation.

| Gate | State | Why open |
|---|---|---|
| 1 `scheck init` and all seven stages on the lab | not run | needs the lab; deferred to v1.0.0 |
| 2 Recall | not run | needs sealed labels; deferred to v1.0.0 |
| 3 False positives | not run | needs the clean variant; deferred to v1.0.0 |
| 4 Context | not run | needs the lab; deferred to v1.0.0 |
| 5 Prioritization | not run | needs a blind ranker and the lab; deferred to v1.0.0 |
| 6 Coverage | not run | the lab half is deferred to v1.0.0; the half on a missing collector or withheld credentials needs no lab and was not run |
| 7 Scope | not run | the lab run's audit log is deferred to v1.0.0; the host integration diff was not run as a gate |
| 8 `make check`, host traces and facts unchanged | not run as a gate | not lab-bound |
| 9 Consumers | not run as a gate | not lab-bound |
| 10 One command on the lab host | not run | placement (lab-bound or not) undecided |
| 11 Mailbox authorization | done offline 2026-10-11, not an acceptance | see [e6-mailbox-authorization-2026-10-11.md](e6-mailbox-authorization-2026-10-11.md) |

## What was run, from the earlier records

- Offline tests (fake servers, fixtures, goldens) and `make check` at the slices' commits,
  recorded in the slice entries of `docs/ROADMAP.md` and in the `e5-*` and `e6-*` records
  listed in [README.md](README.md). A software test is not release acceptance.
- Live measurements on one authorized Workspace tenant, attributed in
  [e6-closing-review-2026-10-12.md](e6-closing-review-2026-10-12.md). That record states
  that recall, false positives and the E3 seal were not passed. The tenant was not a
  sealed lab.
- The federation fix of 2026-10-18 was offline only
  ([e6-federation-2026-10-18.md](e6-federation-2026-10-18.md)).

## What remains unmeasured

- Recall, false positives, context handling and prioritization, on every collector: no
  sealed labels exist for the rest of the lab, and the domain part's seal state is in
  [lab-0.0.2-domain.md](lab-0.0.2-domain.md).
- Workspace, in every respect a lab measures. "Workspace: exercised read-only on a real
  tenant, not measured."
- The pre-release live check of whether Google's mandatory 2-step verification for super
  admins shows in `isEnforcedIn2Sv` (roadmap, E6 federation notes): no result is recorded.
- The coverage table against a collector missing or credentials withheld, as a gate.
- Whether `scheck run --host` and the `scheck ssh` alias give the same report on a lab
  host, as a gate.

## Not decided here

Whether 0.0.2 is ever tagged or published, and which gates such a tag would need; what
v1.0.0 contains beyond the lab gate. Neither is decided.
