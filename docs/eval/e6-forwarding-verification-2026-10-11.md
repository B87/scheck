# E6 optional Gmail forwarding metadata: implementation and reviews

Recorded 2026-10-11 on `e6-workspace-collector`, after step-5 commit `7cbb65b`. This
supplements [e6-forwarding-definition-2026-10-11.md](e6-forwarding-definition-2026-10-11.md)
and the earlier E6 records; it never rewrites them. Evidence comes from the implementing
session and AI subagents: the security-consultant (model `claude-opus-5-5`), the client
(`claude-sonnet-5-5`, played as the Brightcart profile, Dani) and the modularity
reviewer (model identifier not given to the document editor). These are software
verification and semantic reviews, not independent human acceptance or live security
measurements.

## Implemented step 6

**Gate.** The OAuth branch of `workspaceOptionalCredential` moved into one data table,
`workspaceSurfaces`: each surface's scope, exchange operation, profiles, whether it is
per mailbox, the decision for a Google 400, whether it projects before redaction, and
its pinned reads (exact URL, kept fields, list shape). `checkSurfaceRead` holds every
optional read to its row, and nothing reaches `gmail.googleapis.com` but a pinned
Workspace read. `WorkspaceGmailForwarding` asks for exactly `gmail.readonly` under
`workspace.credential_exchange_gmail_forwarding`; it needs a service account
(`unavailable:needs_service_account` otherwise, remembered). Before each exchange
`mailboxSubject` admits the mailbox from the gate's own inventory (complete users
population, admitted current id, primary in a verified domain or alias, known active
with a mailbox), and the assertion's `sub` is that record's primary; an inactive or
mailbox-less account is `unavailable:mailbox_inactive`, not remembered. Tokens are
cached by admitted user id with the binding's lifetime. `failureScope`
(`failSurface`, `failMailbox`) is set where the exchange answer is read and
`mailboxOutcome` switches on it; the breaker is 5 first failures or 20 in a row, the
session cap 1,000 exchanges not reset by a rebind. The exchange is audited with the user
id as its only parameter. The two reads (`users/me/settings/autoForwarding` and
`filters`) project before redaction; a Google 400 on them is
`unavailable:mailbox_unavailable`. The binding summary gains `offers`, the profile that
adds each unselected surface, which the collector's advice uses. The gate now keeps
three list flags (`suspended`, `archived`, `isMailboxSetup`) in its admitted user
record, an exception to "posture fields are parsed only by the collector".

**Collector.** `internal/collector/workspace/mail.go` registers
`workspace.external_forwarding` and declares `OpMailAutoForwarding` and
`OpMailFilters`. `collectMail` reads each readable mailbox after every other read
through `readAccounts`, the optional-surface read order and `Repeats` stop shared with
OAuth. `mailView` decides once, for the rule and the notes: the read set, the
destination classes (internal, outside, subdomain, unplaceable), the per-mailbox gap,
a saved but disabled address and the one `refusal` that decides the surface's own
outcome. `refusalWording` words that refusal for the coverage gap and the readout note
alike. `Context.DeclaredDomains` is filled by the engagement from domain roots.

**Report and engagement.** `Evidence.Coverage()` returns a second plan, for the email
area. `feeds` is true for any asset whose collector gave a plan for the area; an asset
whose plan is wholly off plan is not counted as read for it, and the row takes the
not-on-plan reasons. An undecided group's gap and abstention reasons reach the row
named by the group; `Unassessed` (`no_rule`) applies only to a group with neither an
outcome nor a gap. A Workspace-only engagement keeps `not_declared` ("Domain email
settings (SPF, DKIM and DMARC)") beside the plan's reasons. `judged.go` maps
`attribute:admin` on `workspace.external_forwarding`, citing the mailbox's own read.
New reason phrases: `workspace_evidence`, `needs_service_account`,
`credential_exchange`, `mailbox_credential`, `mailbox_unavailable`, `mailbox_inactive`,
`forwarding_subdomain`. The subject kind `mail_forward` joins `finding.SubjectKinds` and
`docs/engagement-report-schema.json`.

The contract is `spec/workspace-collector.md`, "Boundary", "Credential files and
profiles", "Reads and projections", "Rules", "Forwarding interpretation" and "Reporting
and coverage"; `spec/report.md`, "Coverage"; and `spec/scope.md`.

### Differences from the DEFINE contract

| DEFINE | Implemented | Source |
|---|---|---|
| Disproof needs a complete domain set | A mailbox with forwarding off and no forwarding filter is disproved even when the alias list was cut; a mailbox with an internal destination still needs the complete set | Implementation; accepted by the consultant REVIEW ("the domain list only places destinations") |
| Per-mailbox outcomes always | When no settings read was usable at all (the surface refused before any read), only the asset-level judgment is emitted | Implementation; accepted by the consultant REVIEW, provided the reason is right |
| Group "Workspace mail forwarding (automatic forwarding and forwarding filters)" | "Workspace mail forwarding" | Consultant REVIEW |
| Gate admission reads no posture field | The gate keeps the three list flags in its admitted record, so it refuses an inactive or mailbox-less account itself as well as the collector not asking | Implementation; the spec names the exception |
| Not-selected note and warning wording | Reworded after the client REPORT (see below) | Client REPORT |
| The raise cites the read | `admin_mailbox_read` in the details | Implementation |

## Consultant REVIEW

Accepted both deviations above. Must-fix, both fixed:

| Item | Finding | Applied |
|---|---|---|
| Must-fix | An undecided group whose read was refused showed "no rule" in the row | Generic, in the report's plan marking: a group's gap and each abstention reason reach the row with the group name as detail; `no_rule` only with no outcome and no gap; new reason phrases; applies to OAuth's group too, so the identity rows in the workspace goldens gained a lifted "Workspace evidence missing (group)" reason |
| Must-fix | A tripped breaker was reported as one mailbox's failure | `Read.Repeats` carried from the gate; `MailEvidence.refusal()` is the read that stopped collection, else the first when none was usable; one `refusalWording` for gap and note; the breaker note "stopped after N mailboxes"; never-attempted mailboxes take the stopping read's reason |

Should-fixes and nits, fixed: administrator-policy refusals worded as API controls or
per-unit policy, not a missing scope; `hides_mail` also for automatic forwarding with
disposition `trash`, with the hiding clause; remediation order (ask in person or by
phone, contain before removing); `filters_read` omitted unless the filters were read;
the email row says why it is partial; Workspace-only engagements keep `not_declared`
beside `not_on_plan` (`declaredOnly`, `declaredFeeds`); `not_on_plan` rendered as
"<group>: not in the checks you chose (profile <p>)"; the mail golden built on the full
collector output with `gmail.googleapis.com` egress; per-mailbox labels "<account>
(mailbox)" with the key unchanged; the limits note rewritten ("read whole for N of M …;
not read whole: … Check those mailboxes … by hand"; "Not attempted, because not active
or without a mailbox: …"); "it also moves" for one filter; "except spam"; the
declared-root clause merged; `saved_external` in the disproval details; a saved-but-off
note also when the domain list is incomplete; fixture `FiltersSeen`; a key-file
sentence in the warning.

Deferred to E9: `Observed` lines that cite reads that did not observe the evidence
(report-wide); whether `hides_mail` raises or ranks; lab-rank forward-and-hide filters
against helpdesk and accounting forwards. Added unmeasured assumptions: whether
`admin_policy_enforced` appears for domain-wide-delegated service accounts at all;
whether Google's "internal addresses only" counts subdomains internal (bears on D6);
whether `disposition` values match `trash`, `archive` and `markRead`.

## Client REPORT

Played from the Brightcart profile (Dani), model `claude-sonnet-5-5`. Fixed in the
collector's wording: the credential warning leads "No message was opened or read." and
says who removes the permission and where; the not-selected note names the real
prerequisite (a service account most small companies lack, which the IT provider
creates) and the owner's approval; the refused and needs-service-account notes give a
next step and say nothing is wrong with the mail settings; "unrecognized settings"
became "settings scheck does not recognize" with "check by hand"; the subdomain note
says "ask whoever runs mail for that name"; the hiding clause adds "though some tools
are set up this way"; the remediation splits "set up on purpose" from "nobody set it
up".

Deferred to E9's report-wide polish: "as unknown" on `Observed` lines; duplicated
`Observed` lines; the "+1 attribute admin" arithmetic; the acceptance how-to (what
`accepted_by` takes and how to reach the file); "not in the checks you chose" for a
profile the operator never consciously chose and how to set an environment variable; a
Summary pointer to skipped forwarding; ranking two stacked permission warnings; naming
skipped mailboxes; "1 of 1 asset read" beside "no rule". Profile gap: Brightcart's
profile says nothing of a service account or of who would approve mail access.

## Modularity assess

Must-fix, applied: the refusal was decided four ways; there is now one `refusal()` and
one `refusalWording`. Should-fixes, applied: the gate's failure scope is an explicit
`failureScope`; the 400 mapping is the surface row's `badRequest`; the exchange is built
once for a mailbox or tenant-wide surface; `surfaceReason`, `unreadWhy` and `sent` are
shared by OAuth and mail; `readAccounts` takes account views with the person already
resolved, and `Collect` builds the views once.

Deferred, for the owner to confirm: S3, profile names live in several places (the
gate's `profileScopes` and surface table, the collector's `knownProfile` and `offer`
fallbacks, "directory" literals), with a gate `workspaceProfiles()` and a `notOnPlan`
helper recommended in step 7 or before a 0.0.3 surface; S6, the report maps attributes
by rule id and named `Details` keys, with `Judgment.AttributeRead` and a report `raises`
table recommended in E9 or when the next raise lands; L7, shared asset-level outcome and
unread wording between OAuth and mail, when the first 0.0.3 per-mailbox read lands.

## Offline checks

`make check` was green on the implemented step, as reported by the implementing session
(vet, `go fix`, golangci-lint, `scripts/depcheck.sh` and the full race test suite); the
log is local to that session and not committed. New tests:
`internal/collector/workspace/mail_test.go` (destination classes and outcomes, read set,
merge, parse, `hides_mail`, raise and exclusions, asset-level outcomes, notes, coverage
plan); `internal/engagement/gate/workspace_mail_test.go` (mailbox admission, token cache
and expiry, the breaker, the exchange cap, failure scopes, pinned registrations and the
widening test, projection before redaction, audit contents) and
`workspace_mail_run_test.go` (a run through the gate to the report); changes to the
binding, coverage-plan, OAuth, rules and report workspace tests. New goldens
`workspace-mail`, `workspace-mail-refused`, `workspace-mail-service-account`,
`workspace-mail-breaker` and `workspace-mail-with-domain` (text, `-v`, JSON); the
identity, 2-step and OAuth goldens changed for the lifted group reasons.

## Adversarial review

Two fresh code-reviewer runs (AI agent subagents; model identifier not given to the
document editor) followed the implementation, each on a subagent that wrote none of the
code. `make check` was green after each round's fixes, as reported by the implementing
session.

**Review 1:** one must-fix, two should-fix, four nits.

| Item | Finding | Applied |
|---|---|---|
| Must-fix | A per-mailbox exchange refused before it left the machine (`refused:deadline`, `rate_limit`, `canceled`) was rewritten to `mailbox_credential`, counted, and never `limit_reached`, so a timed-out run could exit 0 or 1 with "Google refused" wording | Refused before dialling is the surface's sticky failure with its own decision and reason (`limit_reached` exits 2), not counted toward the cap or the breaker |
| Should-fix | The credential warning counted only reads with decision sent or reused | The gate records each mailbox it asked Google to act as (session `actedAs`, kept for the session); every mail read's `Result` carries `ActedAsMailbox` (collector `Read.ActedAs`); the warning counts those and says "scheck asked Google to sign it in as each of N mailboxes" |
| Should-fix | Gmail API disabled in the project (403 `accessNotConfigured` or `SERVICE_DISABLED`) read as a missing permission | Fixed body, `unavailable:api_disabled`, `Repeats`, remembered for the surface, gap only; collector wording says to enable the Gmail API under APIs & Services → Library; report phrase "Google has not enabled the API this read needs in the credential's project" |
| Nits | Weak tests | Strengthened: the Gmail host pin's error text, 20 failures in a row tripping the breaker, a mail limit making the outcome `incomplete` |

**Review 2** (on the fixes above): no must-fix, three should-fix (all fixed), three nits.

| Item | Finding | Applied |
|---|---|---|
| Should-fix | A dialled exchange with no answer (dropped connection, timeout) or a Google 5xx at the token endpoint was classed `mailbox_credential` | That mailbox's failure (`failTransient`, mailbox surface only; OAuth's step-5 classification unchanged): not remembered, keeps its own reason (`unavailable:server_error`, connection codes), counts toward the cap and the breaker, and counts as asked Google to act as the mailbox |
| Should-fix | The breaker's wording blamed the key | Neutral: Google did not sign scheck in as one mailbox after another and may have been failing; run again later, and if it repeats check the key and delegation |
| Nit | The `ActedAsMailbox` comment; missing negative tests | Comment corrected; unanswered and negative tests added |

Tests that cover the fixes: `TestWorkspaceMailUnansweredSignInIsThatMailboxs`,
`TestWorkspaceMailDeadlineIsTheSurfacesLimit`, `TestWorkspaceMailAPIDisabledStopsTheSurface`,
`TestWorkspaceMailReadsSayTheyActedAsTheMailbox`, `TestWorkspaceMailBreakerTripsOnTwentyInARow`,
`TestWorkspaceGmailHostTakesOnlyPinnedWorkspaceReads` (gate) and
`TestForwardingOutcomeAndWarningCount` (collector).

**No third review ran** on review 2's should-fix fixes; they are covered by the tests
above, not by a fresh reviewer. This is recorded as not run, not as passed.

**Deferred**, carried in `ROADMAP.md`, E6, "Carried from step 6":

- a failed binding still shows mail forwarding on plan in the email row, as OAuth's group
  does in identity, because the profile is unknown before binding;
- the refusal wording follows the first failed read when failures differ (for example one
  `admin_policy_enforced`, then 400s);
- a deadline or cancel during the token body read is reported
  `unavailable:response_read_failed` (a surface gap) rather than `limit_reached`, a tiny
  window;
- per-mailbox Gmail 403s other than the API being disabled do not feed the breaker.

## Carried and deferred

Carried in `ROADMAP.md`, E6, "Carried from step 6": the release blocker (an explicit
engagement-file authorization entry recorded in the audit log, E8/E9), S7 still open for
OAuth and mail, the E8 and E9 items, the 0.0.3 candidates, the modularity deferrals S3,
S6 and L7, the unmeasured assumptions for step 7 and the Brightcart profile gap.

No live Google API or real tenant was contacted. Fake-server tests and pinned reports
are software evidence, not proof of live provider compatibility, tenant security,
recall or false-positive performance. No SEED or RANK work ran in this implementation
session. No independent acceptance is claimed. This work does not repair or waive the
missed historical E3 rest-lab seal.
