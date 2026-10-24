# E6 observed 2-step verification: implementation and reviews

Recorded 2026-10-11 on `e6-workspace-collector`, after step-3 commit `c69728e`. This
supplements [e6-two-step-definition-2026-10-11.md](e6-two-step-definition-2026-10-11.md)
and the earlier E6 records; it never rewrites them. Evidence comes from the
implementing session and AI subagents (security-consultant, client, modularity and
two fresh code-reviewer sessions); exact model identifiers were not given to the
document editor. These are
software verification and semantic reviews, not independent human acceptance or live
security measurements.

## Implemented step 4

`internal/collector/workspace/twostep.go` registers `workspace.two_step_not_enforced`
(high, `org_unit`) and `workspace.admin_without_two_step` (high, `account`) beside
`Judge`, and adds both to `workspace.RuleIDs()`. One view (`twoStepView`) decides each
account's state, the unit grouping, the tenant tally and the `access.mfa` comparison
once; rules and readout notes both read it. Step-3 administrative interpretation is
shared through one per-account view (`accountView`) rather than repeated.

The collector reads no new operation: the 2-step flags come from the users list and
the step-3 fresh details. A fresh detail fills only a missing list flag. A detail that
disagrees on either flag, carries a null or non-boolean flag, or was returned but
refused or rejected sets `AccountAccess.TwoStepUnknown`; only the 2-step rules abstain
on it. Engagement fills `Context.MFA` and `Context.MFASource` through the new
`Resolved.MFAFor`, and `Resolved.AdminsFor` likewise; the GitHub collector's context
uses the same two helpers. `workspace.Readout` returns the administrative and 2-step
notes. Coverage adds "Workspace 2-step verification (Google's enforcement and
enrollment flags)" with a fixed `no_rule` limits detail; coverage groups carry their
limits explicitly, and a report test ties every `workspace.RuleIDs()` id to exactly one
group. An abstained judgment's coverage detail is "<subject>: <first not-checked line>".

The contract is `spec/workspace-collector.md`, "Rules" and "Observed 2-step
verification".

### Differences from the DEFINE contract

| DEFINE | Implemented | Source |
|---|---|---|
| Changed-unit refused detail: unknown in both units | Unknown in its list unit only | Deferred limit, carried in `ROADMAP.md` E6 |
| Detail `enforcement_unknown` | `state_unknown`: unknown flags or activity | Implementation |
| Client paragraph "This does not say whether users have enrolled in it … Ask your Workspace administrator …" | "Enrollment, counted above, is a separate flag … Review these accounts … yourself, or with whoever administers your Workspace." | Consultant REVIEW M2 |
| Grace note ends "Ask your Workspace administrator to check these accounts." | "Check these accounts in the Admin console." | Client REPORT |
| Undeclared note "for this tenant" | "declare it under access.mfa in the engagement file" | Client REPORT |
| Matching notes "as you declared" | Each adds "Required is not the same as enrolled …" | Client REPORT |

## Consultant REVIEW

Conditional pass. Every item was applied:

| Item | Finding | Applied |
|---|---|---|
| M1 | Raise wording must follow the declaration that raised it | `raisedWhy` per `everyone`, `admins`, `some` |
| M2 | The fixed paragraph contradicted the enrollment breakdown beside it | New paragraph, verbatim in the spec's "Client-facing wording" |
| M3 | Abstained units were invisible in the text report | Unjudged-units note ending "Treat these units as not checked, not as fine." |
| M4 | Spec drift | Spec synced in this step |
| S1 | `admins` matching note too loose | Requires a complete population with no unknown super admin |
| S2 | Conflict cause unstated | Excerpts say whether account status or the 2-step flags conflicted |
| S3 | "at least" unexplained | Excerpt counts the unknown accounts or says the population was partial |
| S4 | Federation caveat wording | Reworded (`federationCaveat`) |
| S5 | Unenrolled accounts of unknown admin status unreported | Separate note listing them |
| S6 | Conflict note lacked the address | Names the address and account id |
| S7 | Golden notes hand-written | Goldens take their notes from the collector |

## Client REPORT

Played from the Brightcart profile (Dani). Collector-owned blockers, all applied: a
plain lead before flag names; notes that name the accounts; plain wording for two
units whose paths differ only in case; "as you declared" now says required is not
enrolled; "Check these accounts in the Admin console".

Report-wide items deferred to E9's report review: declaration evidence prints
"Operator declaration at access.mfa[0]" rather than the declared value; raw reason
codes in coverage text; the acceptance template for a unit that covers every account;
duplicate per-read `Observed` lines; "(as unknown)" principal wording; `-v` adds
nothing for Workspace; generic `no_rule` phrasing.

## Modularity assess

Must: one declaration comparison and tally in the view, applied (`twoStepView`).
Should, all applied: a single flag-conflict source (`TwoStepUnknown`), the shared
`accountView`, `Resolved.MFAFor` and `Resolved.AdminsFor`, and coverage group limits
with the one-group test. Follow-ups, not assigned to a slice: F1 GitHub MFA readout
notes live in engagement rather than the GitHub collector; F2 coverage groups and
limits should be registered by collectors; F3 a typed `access.mfa` declaration
vocabulary; F4 a collector-supplied asset status sentence.

## Fresh adversarial review

A fresh AI `code-reviewer` session reviewed step 4. No must-fix. One should-fix and
three nits, all corrected:

| Item | Finding | Correction |
|---|---|---|
| Should-fix | The 2-step coverage sub-item could be `not_applicable` with no 2-step judgment; the `workspace-identity` golden showed it | The group is flagged `always` in `internal/engagement/report/workspace_coverage.go`: with no 2-step outcome it is `not_assessed` with `unavailable:workspace_evidence`, "No 2-step verification outcome was recorded for this tenant", never `not_applicable`. Test `TestWorkspaceTwoStepWithoutOutcomesIsNotAssessed`; `workspace-identity` goldens updated |
| Nit | A refused or rejected fresh detail (`TwoStepUnknown`) was not cited | Cited in the account's reads and in the unit and admin abstentions |
| Nit | A partial population with no observed off account and undeclared or `unknown` `access.mfa` printed "at least 0" | The readout says "No observed active account in this Workspace was reported without the 2-step verification requirement, but the list of users was incomplete (see the inventory notes for why)." |
| Nit | The `workspace-two-step` golden fixture's inventory note did not match its 5 accounts | Note corrected |

A second fresh AI `code-reviewer` session reviewed those corrections. No must-fix or
should-fix. Two nits, both applied: the test now requires the sub-item and its reason;
the spec states the zero-outcome rule (`spec/workspace-collector.md`, "Reporting and
coverage"), which differs from `spec/report.md`'s general `not_applicable` rule
because every read account is judged for 2-step verification.

## Offline checks

`make check` was green after all corrections: vet, `go fix`, golangci-lint with 0
issues, `scripts/depcheck.sh` and the full race test suite. The log is local to the
implementing session and not committed. It is rerun after the documentation edits
that close this record, before the commit.

## Carried and deferred

Carried in `ROADMAP.md`, E6, "Carried from step 4": the federation release blocker
(owner, E8 question with the pending critical-context decision in E9), "Fix these
first" collapsing unit instances (E9), the changed-unit limit, the client REPORT items
above (E9) and the modularity follow-ups.

No live Google API or real tenant was contacted. Fake-server tests and pinned reports
are software evidence, not proof of live provider compatibility, tenant security,
recall or false-positive performance. No SEED or RANK work ran in this implementation
session. This work does not repair or waive the missed historical E3 rest-lab seal.
