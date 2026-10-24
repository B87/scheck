# E6 identity and administrator-access verification

Recorded 2026-10-10 on `e6-workspace-collector`, after inventory commit `04688ec`.
This supplements [e6-identity-definition-2026-10-10.md](e6-identity-definition-2026-10-10.md)
and the earlier E6 records; it never rewrites them. Evidence comes from the
implementing Codex session and AI role-review subagents. Exact model identifiers
were not exposed. These are software verification and semantic reviews, not
independent human acceptance or live security measurements.

## Implemented step 3

One `workspace.Collect` call owns binding and inventory, roles, a bounded recursive
privilege tree, admitted per-user direct/indirect assignments and eligible fresh
account details. `Judge` returns the nine frozen identity/admin outcomes. The
collector registers its Workspace definitions beside the rules through
`finding.Register`; shared identity prose is provider-neutral. Engagement supplies
people declarations, expected-admin context, assessment instant and timezone, then
appends collector evidence, notes and judgments.

The 13-operation surface does not include tenant-wide direct assignments, group
inventory or group-member reads. Current admitted-user responses are the source of
direct and indirect assignment association. Two-step verification, optional OAuth
and Gmail reads remain later steps. Unknown privilege interpretation keeps coverage
partial independently of individual settled flags; `InterpretationGaps` notes
identify unknown roles, privileges, conditions or expiry. Inventory completeness,
execution completeness and administrative interpretation remain distinct.

## Confirmed review defects and corrections

The fresh adversarial reviewer `e6_step3_code_review` confirmed three must-fix defects:

1. Scalar, boolean or numeric `expirationDetails` could disappear in projection and
   be read as no expiry, incorrectly establishing a current unconditional assignment.
2. A malformed role privilege member, such as `rolePrivileges:[true]`, could become
   an empty array and incorrectly disprove a suspended administrative assignment.
3. Fresh detail changing an actual list sign-in into the exact never-login marker
   could evade conflict recognition and incorrectly fire a never-signed-in finding.

The implementation opts role, privilege-tree and per-user assignment operations
into `PreserveMalformed`. Unsupported projected nested shapes and array members
become JSON null; undeclared siblings are dropped, while supported positive siblings
remain usable. Other operations retain their existing projection semantics. Null or
unreadable expiry and malformed privilege members remain unknown rather than
proving absence. Fresh actual-to-never sign-in transitions are conflicts; a
never-to-actual transition remains usable new evidence. Focused regression tests
cover each defect and supported positive siblings.

The review's should-fix evidence-provenance issue was also addressed:
unexpected-admin judgments cite the matched person's Workspace-address declaration
as well as `access.admins`.

## Offline checks and role reviews

| Verification | Result and attribution |
|---|---|
| `make check` | Green after the corrections: vet, `go fix`, lint with zero issues, dependency checks and the full race-test suite; local log `/tmp/scheck-step3-check.log` |
| Focused regressions | Passed for malformed projection, supported siblings, login regression and assignment scope/budget/cross-page cap boundaries, including exact cap without additional data and actual cuts |
| Rule outcomes | Every step-3 rule has firing, disproved and abstained fixtures; partial populations, expiry/conditions, unknown privileges, calendar boundaries, attribution/exemptions and fresh conflicts are exercised offline |
| Consultant review | Targeted semantic REVIEW passed; focused follow-up found no semantic must-fix after the projection and login corrections |
| Client report review | No remaining wording blockers after the corrected retained-assignment, role-password-reset and expected-person wording |
| Modularity assessment | Passed; one collector owns sequence, interpretation, definitions and notes |
| Fresh adversarial follow-up | `e6_step3_fix_review` found no confirmed must-fix or should-fix; it checked the green full-check log and passed targeted race regressions, including fake-HTTP assignment projection |

The fresh follow-up verified malformed expiry abstention, malformed privilege
members remaining unknown while positive siblings fire, undeclared sibling omission,
unchanged existing projection semantics, sign-in transition handling, declaration
provenance and intact assignment admission. It made no edits.

No live Google API or real tenant was contacted. Local fake-server tests and pinned
reports are software evidence, not proof of effective permissions, live provider
compatibility, tenant security, recall or false-positive performance.

## Carried and deferred items

Optional attribution caching is deferred; it has no security implication and does
not change ambiguous-identity abstention. E9 owns the nonblocking report wording
nits: vague generic `no_rule` phrasing, duplicated aggregate evidence and remaining
“current admitted users” wording. Scope and coverage limits remain explicit.

Independent evaluation, live measurements and release acceptance remain pending.
No SEED or RANK work ran in this implementation session. This work does not repair
or waive the missed historical E3 rest-lab seal. Step 3 is complete offline; step 4, observed 2-step verification, is next.
