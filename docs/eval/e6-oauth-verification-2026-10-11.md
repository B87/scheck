# E6 optional OAuth grant metadata: implementation and reviews

Recorded 2026-10-11 on `e6-workspace-collector`, after step-4 commit `8e03588`. This
supplements [e6-oauth-definition-2026-10-11.md](e6-oauth-definition-2026-10-11.md) and
the earlier E6 records; it never rewrites them. Evidence comes from the implementing
session and AI subagents (security-consultant, client and modularity); exact model
identifiers were not given to the document editor. These are software verification and
semantic reviews, not independent human acceptance or live security measurements.

## Implemented step 5

**Gate.** `Op.Surface` (`WorkspaceSurface`; the zero value `WorkspaceBaseline`, and
`WorkspaceOAuthGrants`) compiles the credential an operation uses. One table,
`workspaceSurfaces`, maps each surface to its one scope
(`admin.directory.user.security`), its audited exchange operation
(`workspace.credential_exchange_oauth_grants`) and the profiles that select it
(`directory_oauth`, `directory_oauth_mail`). `workspaceOptionalCredential` refuses
`unavailable:profile_not_selected` and, for a service account without a verified
delegated principal, `unavailable:principal_unknown`; then it makes one exchange: a
service account asserts exactly the one scope, an `authorized_user` refresh sends
`scope=` that scope, and the baseline `authorized_user` refresh still sends none. A
failure is remembered for the session and later reads send nothing. The optional
token's expiry is capped at the baseline's; `unbind()` clears it, and a remembered
failure, with the binding (bootstrap operations, 401, expiry), and `credential_changed`
clears it too. A refused optional scope (`invalid_scope`, `unauthorized_client`,
`access_denied`) is `insufficient_permission:admin.directory.user.security`, a 429
`limit_reached`, anything else `unavailable:credential_exchange`. A per-account 403 on an
optional-surface operation is `insufficient_permission:admin.directory.user.security`,
the scope named by the gate. `halt.reason` carries an earlier result's classification,
so a baseline exchange 429 now keeps `limit_reached` too.

`Result.Repeats` says every later request of the kind in the session would end the
same way (`credential_changed`, `bootstrap_required`, `no_credentials`, a session-level
tenant binding refusal, `exclusion_unknown`, the assignment budget,
`profile_not_selected`, `principal_unknown`, a remembered optional failure); a
per-account "not admitted" refusal does not repeat. `List.SelfRef`, a generic pipeline
filter, drops an item whose field is missing or differs from the bound `{user}` as
unattributable. The tokens operation's registration is pinned: path
`/admin/directory/v1/users/{user}/tokens`, no query, subject `users/{user}`, list
`items`, envelope `admin#directory#tokenList`, at most 1,000 items, no paging, `SelfRef:
userKey`, and kept fields only from `clientId`, `scopes`, `userKey`, `displayText`,
`anonymous` and `nativeApp`. The binding summary adds `assessment_client` (for
`authorized_user` only, after a successful refresh) and `surfaces` (the optional
surfaces the profile selects; profile names stay in the gate).

**Policy.** `policy.CutLabel` cuts a provider-chosen name on a character boundary,
never through a redaction marker, and marks the cut with `[TRUNCATED:<n> bytes]`. App
names are capped at 120 bytes.

**Collector.** `internal/collector/workspace/oauth.go` declares `OpUserTokens`
(`workspace.user_tokens`) and registers `workspace.oauth_broad_scope` beside `Judge`.
`collectGrants` runs after the baseline over every admitted account, suspended and
archived included, ordered passed leavers, super admins, contractors, then others,
active before inactive within each, and stops on `Result.Repeats`. `grantsOf` keeps a
read usable when a redaction is confined to `displayText`; a marker in any other field
leaves it unusable. A malformed grant (missing or non-string `clientId`, `scopes`
missing or not an array of non-empty strings, `userKey` other than the requested id, a
wrongly typed `displayText`, `anonymous` or `nativeApp`) makes the account incomplete,
with a note; an empty `scopes` array is a grant whose access is unknown. `oauthView`
decides once, for the rule and the notes: apps by client id, each classified as broad,
status unknown, unclassified, inactive only or sign-in only; the set-aside by
elimination; unread and partial accounts with their reasons. Scope table version
`2026-10-11`. `Evidence.NotOnPlan()` gives the report `not_on_plan:profile=<p>` with a
collector-worded detail when OAuth is not selected.

**Report and engagement.** Coverage splits "Workspace OAuth grants (third-party app
access)" (`always`, a limits detail, `not_on_plan` from `AssetInput.NotOnPlan`,
`unavailable:oauth_unclassified` abstentions collapsed into one detail line with the
new reason phrase "some apps hold scopes this version of scheck does not classify,
and none it classifies as broad") from "Workspace domain-wide delegation" (always *not assessed*, `no_rule`,
with the Admin console path). The row's reason names only the groups nothing decided,
and a group not on the plan is not called unassessed. `judged.go` maps the
`attribute:admin_grantor` raise, citing the admin's own tokens read. The remediation
says "Trusted" widens what an app may reach and the finding stays open either way. The
administrative note no longer says OAuth is not assessed. In engagement, any
`limit_reached` read makes the Workspace asset incomplete (exit 2), a refused optional
permission is a coverage gap only, and the status detail mentions OAuth when selected.

The contract is `spec/workspace-collector.md`, "Credential files and profiles",
"Reads and projections", "OAuth grants", "OAuth scope interpretation" and "Reporting
and coverage".

### Differences from the DEFINE contract

| DEFINE | Implemented | Source |
|---|---|---|
| App names capped at about 80 characters | 120 bytes, cut by `policy.CutLabel` | Implementation |
| Unset assessment client: "scheck authenticated with this client id. One of these grants may be the credential scheck used; scheck cannot tell whose sign-in its credential file holds, so none was set aside." | The fired excerpt leads with "scheck authenticated with this client id; one of these grants may be the credential this run used."; "Not checked" says "scheck cannot tell whose sign-in its credential file holds, so none of these grants was set aside as its own." | Consultant REVIEW S3 |
| Malformed: no or non-string `clientId`, `scopes` missing or not an array | Also an empty string in `scopes` and a wrongly typed `displayText`, `anonymous` or `nativeApp`; an empty `scopes` array is unknown access; the gate drops an item with no `userKey` too | Implementation |
| Inactive-only disproved on a complete population, else abstain | As defined; the partial-population abstention says "in the grants read", and no excerpt says "only sign-in scopes" when inactive grantors hold more | Consultant REVIEW must-fix |
| Any redaction in a tokens read | A redaction confined to `displayText` keeps the read usable | Consultant REVIEW S1 |
| The collector stops on a list of gate decisions | It stops on the gate's `Result.Repeats` | Modularity must-change |
| A per-account 403 classified by the collector | The gate names the scope | Modularity should-change |
| Not addressed: the admin raise on grants to the assessment client | Kept on those grants when they were not set aside | Implementer's decision, brought to the owner |

## Consultant REVIEW

Approve after two must-fixes, both fixed:

| Item | Finding | Applied |
|---|---|---|
| Must-fix | Excerpts said "only sign-in scopes" when inactive grantors held more | Inactive-only outcome with its own wording and the cleanup note |
| Must-fix | The asset abstention could say "0 accounts were not read", and a dropped item had no note | "App grants were read for every account listed, but the account list was incomplete."; a dropped-item note names the account |
| S1 | A redacted app name hid its grants | A redaction confined to `displayText` keeps the read usable |
| S2 | No note when every account's read was refused; credential warning only in some cases | All-403 note naming the role needed; the credential warning whenever a tokens read was sent or reused |
| S3 | The assessment client's grants were not flagged where read | The fired excerpt leads with it |
| S6 | Remediation wording on "Trusted" | Trusted widens, does not limit; the finding stays open either way |
| S8 | Installed apps read as unknown third parties | Hedge naming Google's and Apple's own apps, "where the risk is the device that holds the grant" |
| Nits | Set-aside disproval wording; delegated-admin sentence; per-account reasons; raise source; unknown-status grantors | "other than the grant set aside as scheck's own credential"; the sentence only when an unread super admin was permission-denied; per-account reasons in the partial note; the raise cites the admin's own tokens read; unknown-status grantors counted in the fired excerpt |

Not applied, for the owner: S5, further broad scopes in a later table version
(`spreadsheets`, `documents`, `presentations`, `calendar`, `admin.directory.group`; for
reading `spreadsheets.readonly`, `documents.readonly`, `calendar.readonly`,
`gmail.metadata`); S7, exit 2 when OAuth is selected and no account's grants were read
(DEFINE M4 says a coverage gap only; the consultant now recommends exit 2). Deferred to
E9: S4, collapse identical per-read `Observed` lines (OAuth is the first rule with high
fan-in, so its priority rises); plain-word scope descriptions; the OAuth sub-item
`partial` against `not_assessed` when no app was seen and some accounts were refused.

## Client REPORT

Played from the Brightcart profile (Dani). Blockers, all addressed: the raise wording
no longer implies Admin console power; "Trusted" is explained; the credential warning
names the permission and where to remove it; the selection note gives the benefit; the
not-on-plan detail no longer claims the operator chose ("The default Workspace profile,
directory, does not read…"); the permission-refused note warns of the permission's
powers.

Deferred to E9: acceptance template explanations (the handle, the indent, "this app for
every account that granted it"); where to see an app's grantors in the console; blocking
against per-person removal; one term for app access, grants, scopes and OAuth; a
one-line example of setting `SCHECK_WORKSPACE_PROFILE`; `-v` adds nothing for
Workspace; the "+1 attribute admin grantor" jargon; the Credential "unknown" line beside
the token warning; the report-wide phrase "not in the checks you chose". Profile gap:
Brightcart's Marketplace installs and who set up the credential.

## Modularity assess

Must-change, applied: `Result.Repeats` replaces the collector's list of gate decision
strings, which also fixes a per-account tenant-binding refusal stopping the sequence;
apps are classified once in `oauthView`, and the notes no longer re-run the rule.
Should-change, applied: `surfaces` in the binding summary, so profile names stay in the
gate; `AssetInput.NotOnPlan` from `Evidence.NotOnPlan()` instead of a report `optional`
flag; the gate names the scope on a per-account 403; `unbind()`; `workspaceTokenOps`
ranges over the surface table; shared `capped` and `shownNames`; `policy.CutLabel`.
Deferred, to be pulled into step 6: F2, the OAuth limit sentence is duplicated in the
collector's note and the report's group, and the `oauth_unclassified` collapse and
reason phrase live in the report; F4, the asset status sentence and the limit scan in
`collect_workspace.go`.

## Adversarial review

A fresh AI `code-reviewer` subagent reviewed the whole step after `make check` was
green. It confirmed one must-fix, one should-fix and two nits; it reported the security
boundary otherwise sound (no read for an excluded or unadmitted account, no token on
the wrong operation, one never-retried optional exchange, the optional token's lifetime
and clearing, no secret in report, audit or run directory, no disproval on incomplete
evidence, no app hidden by its name).

- **Must-fix, corrected.** A Google 403 whose error reason is `rateLimitExceeded` or
  `userRateLimitExceeded` on a Workspace read was classified as a missing permission:
  the gate replaced the error body with fixed text before classifying it, and step 5
  then named `admin.directory.user.security`, so the readout could push an operator to
  grant a powerful permission for a quota problem, and the run did not exit 2. The
  root cause predates step 5 and affected every Workspace read. The gate now redacts
  the error body, and when its reason is a rate limit keeps a fixed rate-limit body, so
  the read is retried and then `limit_reached`
  ([scope.md](../spec/scope.md), "Status codes that mislead").
- **Should-fix, corrected.** The end-to-end test asserted a seeded secret in an app's
  name absent from the run directory but not its redaction marker present; it now
  asserts both.
- **Nits, corrected.** A 404 on an optional-surface read no longer names the scope.
  A passed `limits.timeout`, a cancelled run and a provider stopped for its rate limit
  now set `Result.Repeats`, so the collector stops instead of writing one refused line
  per remaining account.

A fresh follow-up `code-reviewer` session reviewed those corrections and found no
must-fix or should-fix. Of its two nits, one was corrected (the result that stops a
provider for its rate limit now carries `Repeats`, not only the requests after it); the
other is deliberate: the pipeline checks the redacted error body for a rate limit while
the bootstrap path checks the raw one, which differs only if an operator's
`redact_extra` matches Google's reason code.

## Offline checks

`make check` was green after the review corrections, as reported by the implementing
session: vet, `go fix`, golangci-lint, `scripts/depcheck.sh` and the full race test
suite. The log is local to that session and not committed. New tests:
`internal/collector/workspace/oauth_test.go` (every app outcome, the raise and its
exclusions, set-aside by elimination, asset-level outcomes, malformed and foreign
grants, read order and stopping); `internal/engagement/gate/workspace_oauth_test.go`
(one-scope token used once, the remembered denied scope, profile and principal gates,
token lifetime, dropped foreign grants and the population cap, registry widening, the
exchange forms, per-account denial); `workspace_oauth_run_test.go` (one run through the
gate to the report); report `TestWorkspaceOAuthRaiseCoverageAndAcceptance`; an
engagement acceptance with realistic client ids; and `policy` `CutLabel`. New goldens
`workspace-oauth` (text, `-v`, JSON); the identity and 2-step goldens changed for the
split coverage sub-items and wording.

## Carried and deferred

Carried in `ROADMAP.md`, E6, "Carried from step 5": the owner's decisions (S5, S7, the
admin raise on assessment-client grants), F2 and F4 into step 6, the unmeasured
assumptions for step 7, the E8 and E9 items, the 0.0.3 candidates and the client
profile gap.

No live Google API or real tenant was contacted. Fake-server tests and pinned reports
are software evidence, not proof of live provider compatibility, tenant security,
recall or false-positive performance. No SEED or RANK work ran in this implementation
session. This work does not repair or waive the missed historical E3 rest-lab seal.
