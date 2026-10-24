# E6 optional OAuth grant metadata definition

Recorded 2026-10-11 on `e6-workspace-collector`, after step-4 commit `8e03588`. An AI
security-consultant subagent supplied the targeted step-5 DEFINE contract before
implementation; its exact model identifier was not given to the document editor. This
supplements [e6-definition-2026-10-10.md](e6-definition-2026-10-10.md) and the step-3
and step-4 definitions; it never rewrites them or claims independent human approval,
software-test success or acceptance. The editor worked from the summary handed to the
reviewers, not the full transcript. Where the implementation differs, the difference
is recorded in [e6-oauth-verification-2026-10-11.md](e6-oauth-verification-2026-10-11.md).

## Verdict

The proposal was sound, with four required changes before building:

1. The admin raise (`attribute:admin_grantor`) applies only when a known-active super
   admin (`isAdmin:true`) or declared break-glass account's **own** grant to that
   client holds a broad scope. Delegated admins do not count; they are listed as
   `delegated_admin_grantors`.
2. Suspended or archived grantors never make an app fire. An app broad only through
   known-inactive accounts is disproved on a complete population, otherwise abstains;
   those accounts are listed as `inactive_grantors`, with a cleanup note. A broad
   scope from a grantor of unknown activity abstains unless an active grant fires.
3. The assessment client is set aside by elimination only (decision 9 below).
4. An `authorized_user` baseline refresh without `scope` returns everything the grant
   holds. The spec must say that the service-account bootstrap asserts only baseline
   scopes, that the `authorized_user` baseline refresh sends no scope, and that the
   optional refresh downscopes with `scope=…admin.directory.user.security`, an
   unmeasured assumption.

## Approved step-5 contract

**Gate, must-fix:**

1. (M1) A typed operation surface compiled into the operation; the gate maps the
   surface to its scope and refuses cross use; `unavailable:profile_not_selected` as a
   defence when the profile does not select it.
2. (M2) The optional token's expiry is capped at the baseline token's and cleared on a
   401, on expiry, on the three bootstrap operations and on `credential_changed`; a
   remembered failure is cleared on the same events. A service account's optional
   exchange happens only after its delegated subject is verified.
3. (M3) Its own audited exchange operation id,
   `workspace.credential_exchange_oauth_grants`, never retried.
4. (M4) A failed optional exchange is never a refusal and never exits 3:
   `invalid_scope`, `unauthorized_client` and `access_denied` are
   `insufficient_permission:admin.directory.user.security`; a 429 is `limit_reached`
   (exit 2); anything else is `unavailable:credential_exchange`. The failure is
   remembered, and later reads send nothing.
5. (M5) The gate drops an item whose `userKey` differs from the requested admitted id.
   A malformed grant (no or non-string `clientId`, `scopes` missing or not an array)
   makes that account incomplete, with a note naming the account.
6. (M6) The raise rule of verdict item 1.

**Rule `workspace.oauth_broad_scope`:**

7. Area identity, category `third-party-apps`, not an exposure, subject `oauth_app`
   keyed by client id. Base medium for every broad scope; read against change is split
   in the excerpt. No grantor kind is exempt. `anonymous` and `nativeApp` are kept as
   context.
8. Asset-level outcomes: selected with no usable read gives one asset abstention; a
   complete population with zero grants gives one asset disproval; an incomplete
   population always gives one asset abstention naming the unread count.
9. Set-aside by elimination: after a successful client-authenticated
   `authorized_user` refresh, the file's `client_id` is the proven assessment client.
   A grant to it is a candidate when its scopes include
   `admin.directory.user.security`. When the users population is complete with no
   drops, every admitted account's grants were read usable, and exactly one candidate
   exists, that grant is set aside: not judged, with an unranked credential note naming
   the account and scopes. Other grants to that client are judged normally. Otherwise
   nothing is set aside and the finding carries: "scheck authenticated with this client
   id. One of these grants may be the credential scheck used; scheck cannot tell whose
   sign-in its credential file holds, so none was set aside." Service-account client
   ids are never set aside. Display names never select it.
10. Read order: after the baseline, in the existing priority, active first within each
    class; every admitted user, suspended and archived included.

**Coverage:**

11. The OAuth sub-item is `always`. Not selected: no judgment, coverage
    `not_on_plan:profile=<profile>`. Exchange denied: *not assessed* with
    `insufficient_permission:admin.directory.user.security`. Some per-user 403s:
    *partial*.
12. (S4) One abstention per unclassified app in JSON; coverage collapses them to one
    detail line.

**Should-fix:**

13. (S1) The spec wording of verdict item 4.
14. (S2) The spec says a single array over 1,000 is wholly
    `unavailable:limit_reached`, and positive findings in it are lost.
15. (S3) `displayText` is attacker-chosen: escaped, redacted, capped at about 80
    characters with a marker, always printed with the client id, never keying, matching
    or exempting anything.

**Scope table:** the user chose to bump the table to version `2026-10-11`, adding as
"can change" `gmail.settings.basic`, `gmail.settings.sharing`, `gmail.send`,
`gmail.compose` and `gmail.insert`.

## Wording

The finding title, impact, excerpt, raise clause and remediation, the selection,
permission, credential, limits, cleanup and partial notes, and the coverage sub-items
"Workspace OAuth grants (third-party app access)" and "Workspace domain-wide
delegation" were defined with the consultant and are recorded as implemented, in
`internal/collector/workspace/oauth.go` and
`internal/engagement/report/workspace_coverage.go`, and in
`spec/workspace-collector.md`, "OAuth grants" and "Client-facing wording".

## Not assessed

Domain-wide delegation, Marketplace domain installs, app access control settings, app
passwords, token age and last use, service-account keys, and what apps did with their
access.

## Deferred

- E8: no "which apps do you use" question, which would be theatre; `scheck init` prints
  how to enable `directory_oauth`.
- E9: group app findings in "Fix these first"; decide whether `data.matters_most` with
  `attribute:admin_grantor` may reach critical; lab-rank Drive for desktop and Apple
  Mail grants on admins.
- 0.0.3: a first-party client id table (wording only), legacy feed scopes, downscoping
  the baseline `authorized_user` refresh, app passwords, token activity (Reports API),
  Cloud Identity app-access policy reads.

## Unmeasured assumptions (live, step 7)

Google downscopes a refresh carrying `scope` and returns `invalid_scope` for an
ungranted scope; domain-wide delegation is absent from `tokens.list`; `tokens.list`
lists the caller's own grant; suspended accounts' tokens are blocked and restored on
restore; delegated admins get 403 on super admins' tokens; first-party client ids;
Admin console paths; whether unrelated anonymous apps share a client id.

No live tenant was contacted, no software test is recorded here, and no SEED or RANK
work ran.
