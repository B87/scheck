# E6 identity and administrator-access definition

Recorded 2026-10-10 on `e6-workspace-collector`, after step-2 inventory commit
`04688ec`. The AI Codex security-consultant subagent `e6_step3_define` supplied the
targeted step-3 DEFINE contract before implementation. Its exact model identifier
was not exposed to the document editor. This supplements
[e6-definition-2026-10-10.md](e6-definition-2026-10-10.md); it never rewrites that
record or claims independent human approval, software-test success or acceptance.

## Approved step-3 contract

The existing nine identity/admin rules and their severities and three outcomes
remain frozen in [workspace-collector.md](../spec/workspace-collector.md), “Rules”:
expected, unattributed, external and shared administrators; departed-person access;
super-admin counts; stale accounts; never-signed-in accounts; and suspended accounts
retaining administrative assignments. Two-step verification, OAuth and Gmail rules
remain later steps.

The targeted definition fixes the recognition and reporting details:

- The collector owns role, bounded recursive privilege-tree, tenant direct and
  admitted per-user indirect-assignment reads. No group-member reads are declared.
  The existing exact privilege pair table remains version `2026-10-10`; display
  names and role ids alone never infer privilege.
- Roles retain ids, names, privilege service/name pairs, `isSuperAdminRole` and
  `kind`. Privilege trees retain recursive service/name pairs, `isOuScopable` and
  `kind`. Assignment evidence retains ids, role, assignee and type, scope and unit,
  condition presence and `expirationDetails.expireTime`.
- The privilege tree requires exact `admin#directory#privileges`, at most 1,000
  nodes, depth 32 and a 1 MiB single result. Existing role, assignment and per-user
  caps remain; 10,000 assignment observations bound the tenant across reads.
- A per-user `includeIndirectRoleAssignments=true` response associates a returned
  group assignment with the requested admitted stable user id. The collector does
  not infer that association from a tenant-wide group assignment or read members.
  Tenant-wide group grants and service-account assignees remain explicit limits.
- Absent `expirationDetails` means no recorded expiry; a present recognized object
  needs a valid RFC3339 `expireTime`. Projection preserves unknown shape rather than
  converting it to absence. Conditions and unknown, null or malformed expiry
  evidence are uninterpreted.
  Recognized expired assignments, including expiry exactly at assessment, are
  ignored. Unknown role or privilege evidence blocks negative conclusions; known
  supported positive privilege survives unknown siblings. The super-admin user
  flag is independent of role-read availability.
- `workspace.Context` receives declared person kinds, addresses, departure dates
  and shared-account users, explicit expected-admin-list presence and values, and
  one assessment instant and timezone. Engagement supplies context; the collector
  sequences reads and judges their evidence.
- Every inactivity verdict needs fresh user detail. Calendar 90/30-day boundaries
  use the assessment timezone, including daylight-saving changes; only the exact
  provider never-login marker `1970-01-01T00:00:00.000Z` supports never-signed-in
  evidence. Future dates,
  login before creation and conflicting list/detail security values are unknown.
  Passed leavers, administrators and contractors receive fresh reads before other
  accounts if the budget cannot cover everyone.
- Readouts cover expected administrators not observed, alias-only leaver limits,
  shared-account rotation when a declared user has left, break-glass recovery and
  sign-in, unsupported privileges and population cuts. Domain-wide delegation
  inventory remains unassessed, with its Admin console review path printed.

## Verification status

Step 3 is defined and implementation is underway. This record does not establish
that the new reads or rules are implemented, that tests or final reviews passed, or
that any live Google API or real tenant was contacted. Implementation still needs
firing, disproved and abstained fixtures, scope/redaction/resume evidence, consultant
REVIEW, client REPORT, spec synchronization, green `make check` and fresh adversarial
review under `AGENTS.md`.

No SEED or RANK work was run by this implementing session. Independent evaluation,
live measurements and release acceptance remain pending. This definition does not
repair or waive the missed historical E3 rest-lab seal.

## Final DEFINE clarification

Before implementation completed, the consultant clarified the targeted contract:
step 3 omits the redundant tenant-wide direct-assignment read. Per-user
`includeIndirectRoleAssignments=true` returns direct and indirect grants for current
admitted users; no tenant-wide assignment or group-member inventory is claimed.
Missing `assigneeType` is unknown, never inferred as `USER`.

Absent expiry means no recorded expiry. Present null, empty or unknown-only expiry
objects are unknown; a valid RFC3339 `expireTime` is recognized even with safely
discarded unknown siblings. An absent or explicit empty condition is unconditional;
nonempty, null or wrongly typed conditions remain unknown.

The exact recognized narrow pairs are Directory `00haapch16h1ysv` with
`USERS_RETRIEVE` or `ORGANIZATION_UNITS_RETRIEVE`, and Admin `01ci93xb3tmzyin` with
`ADMIN_DASHBOARD`. Unknown privilege pairs still prevent absence conclusions, while
a supported privileged descendant can prove presence beneath a known-service parent.
Ambiguous or partial service/break-glass attribution leaves both count exemptions
and inactivity eligibility unknown. A passed leaver lacking a usable Workspace
identifier receives an explicit abstention. These clarifications supersede broader
read/projection wording above; final implementation verification is not recorded here.
