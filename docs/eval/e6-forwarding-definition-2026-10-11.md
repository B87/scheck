# E6 optional Gmail forwarding metadata definition

Recorded 2026-10-11 on `e6-workspace-collector`, after step-5 commit `7cbb65b`. An AI
security-consultant subagent (model `claude-opus-5-5`) supplied the targeted step-6
DEFINE contract before implementation, from the implementing session's proposal. This
supplements [e6-definition-2026-10-10.md](e6-definition-2026-10-10.md) and the step-3 to
step-5 definitions; it never rewrites them or claims independent human approval,
software-test success or acceptance. The document editor worked from the frozen
contract and the owner's answers, not the full transcript. Where the implementation
differs, the difference is recorded in
[e6-forwarding-verification-2026-10-11.md](e6-forwarding-verification-2026-10-11.md).

## Verdict

The proposal was sound with ten required changes before building:

1. Subject `mail_forward`, key `<account primary> -> <destination address lowercased>`,
   one instance per outside destination with automatic forwarding and filters merged;
   disproval per mailbox keyed `<account> -> none`.
2. A circuit breaker: it trips when a binding's first five exchanges all fail, or after
   20 consecutive per-mailbox failures; sticky `unavailable:credential_exchange`,
   remaining mailboxes not attempted, a coverage gap and not exit 2.
3. `admin_policy_enforced` on a mailbox exchange is that mailbox's
   `insufficient_permission:gmail.readonly`, and counts toward the breaker.
4. Only an explicit `enabled:false` disproves; an absent `enabled` abstains.
5. Every Gmail read's audit line names the admitted user id whose token it used.
6. A subdomain of a verified domain that is not itself verified abstains with
   `unavailable:forwarding_subdomain` and a readout note.
7. `+1 attribute:admin` only on a known-active super admin's mailbox; delegated admins
   are listed in the details, and a leaver gets an excerpt cross-reference and no extra
   raise.
8. The full destination address is printed everywhere.
9. Read set: unknown activity or conflict is not read and abstains;
   suspended, archived or `isMailboxSetup:false` is not read, not judged and counted;
   everyone else is read, a delegated admin included.
10. The not-selected note and the credential warning carry the approval and
    audit-trail sentences.

## Approved step-6 contract

**Gate, must-fix:**

1. (M1) Surface `gmail_forwarding`: scope exactly `gmail.readonly`, profiles
   `directory_mail` and `directory_oauth_mail`, exchange operation
   `workspace.credential_exchange_gmail_forwarding`; no other scope, no fallback.
2. (M2) Admission before each per-mailbox exchange: profile; service account; principal
   verified; bound; users complete; `{user}` an admitted current id (same customer,
   outside exclusions, known active, `isMailboxSetup` not false); the admitted primary
   in a verified domain or alias. The assertion's `sub` is the gate inventory record's
   primary. The "Boundary" amendment was approved: one exchange per compiled optional
   surface or, for a per-mailbox surface, one per admitted mailbox.
3. (M3) Token cache by bound customer and admitted user id with optional state; cleared
   with the binding (bootstrap, 401, baseline expiry, `credential_changed`, profile
   change); expiry capped at the baseline's; a token for one user is never used for
   another.
4. (M4) Surface-wide and sticky: `invalid_scope`, `unauthorized_client`,
   `access_denied` as `insufficient_permission:gmail.readonly` (gap); a token 429 as
   `limit_reached` (exit 2), never retried; the breaker as
   `unavailable:credential_exchange` (gap). Per mailbox: `invalid_grant` or other as
   `unavailable:mailbox_credential`; `admin_policy_enforced` and Gmail 403 as
   `insufficient_permission:gmail.readonly`; Gmail 400 as
   `unavailable:mailbox_unavailable`. A Google 403 rate limit is retried then
   `limit_reached`; a 401 drops authentication and binding. At most one exchange per
   admitted user per binding and 1,000 per session, not reset by a new binding, then
   sticky `limit_reached`.
5. (M5) The exchange is audited under the one operation with the admitted user id as its
   only parameter, never an address, assertion or body.
6. (M6) With `authorized_user`, every Gmail operation is refused before any exchange,
   sticky `unavailable:needs_service_account`, with a row in the report's reason
   wording.
7. (M7) Reads pinned, with a widening test: `GET gmail.googleapis.com/gmail/v1/users/me/settings/autoForwarding`
   keeping `enabled`, `emailAddress`, `disposition`; the filters list, key `filter`,
   keeping `id`, `action.forward`, `action.addLabelIds`, `action.removeLabelIds`; a
   single array of at most 1,000, over which the whole read is `limit_reached`; `{}`
   is empty; no envelope for these operations only; nothing else under `/gmail/`;
   `users/me` over `users/{user}`.
8. (M8) Projection before redaction for these two operations; a malformed body is a
   fixed diagnostic and is discarded.

**Rule `workspace.external_forwarding`:**

1. Email area, category `email`, not an exposure, subject `mail_forward`, base medium;
   `data.matters_most` is not applied.
2. Internal set: exact verified domains and verified aliases, complete only when both
   are complete. When incomplete the known set is internal and other destinations
   abstain. Engagement domain roots are never internal; the excerpt says when the
   destination's domain is a declared root.
3. Destination parse: one `@`, nonempty local part, DNS-valid domain; empty, malformed,
   non-string or redaction-marked is unknown. An absent `action.forward` is no
   forward; present but empty or non-string is malformed.
4. Fires per mailbox and outside destination: `enabled:true` or any filter; fire wins
   even if the other read failed.
5. Disproved per mailbox when both reads are usable and within the cap, no item is
   malformed, forwarding is off or goes only inside, every filter forward is inside and
   the internal set is complete. `enabled:false` with a saved outside address is
   disproved with a note.
6. Abstains per mailbox otherwise.
7. Asset-level judgment as for OAuth: none active, none read, N of M, and none when
   complete.
8. Details: `mechanisms`, `filters_forwarding`, `filters_read`, `auto_forward`,
   `destination_domain`, `domains_complete`, `population_complete`, `disposition`,
   `hides_mail`, `admin_mailbox_read` on a raise, `delegated_admin`, `filter_ids` (JSON
   only).

**Coverage and exit:**

1. An email-area plan with the group "Workspace mail forwarding (automatic forwarding
   and forwarding filters)" (renamed "Workspace mail forwarding" in implementation),
   always present, with limits; `not_on_plan:profile=<p>` when not selected;
   `needs_service_account` and `insufficient_permission:gmail.readonly` as gaps;
   *partial* on abstentions; the generic extension of `feeds` approved.
2. A limit exits 2; a refused permission, `needs_service_account` and the breaker are
   gaps only. The consultant's S7 question (exit 2 when the surface is selected and
   nothing could be read) stays open (owner's decision D4).

**Should-fix:** the declared-root clause (S1); the limits note counts skipped mailboxes
(S2); the registry refuses `forwardingAddresses`, delegates, send-as, POP and IMAP
paths (S3).

## Owner decisions

Attributed to the user, who answered through the implementing session's question tool
on 2026-10-11:

- **D1:** subject mailbox plus destination, the full address printed everywhere.
- **D2:** keep `disposition` and the filter label ids (only to derive `hides_mail`); no
  `forwardingAddresses` read.
- **D3:** `SCHECK_WORKSPACE_PROFILE` gates the surface in step 6, with the approval
  sentence in the not-selected note and the mailbox count in the warning and audit; an
  explicit engagement-file authorization entry, recorded in the audit log, is a 0.0.2
  release blocker (E8/E9).
- **D4:** a refused permission, `needs_service_account` or a tripped breaker is a
  coverage gap only; S7 stays open.

Decided by the consultant within the spec and not escalated: D5, `data.matters_most` is
not applied to email-area Workspace findings in 0.0.2; D6, an unverified subdomain of a
verified domain abstains; D7, the Cloud Identity Policy API read is a 0.0.3 priority.

## Wording

The finding title, impact, remediation, excerpts, notes and the email-area coverage
group were defined with the consultant and are recorded as implemented in
`internal/collector/workspace/mail.go` and `coverage_plan.go`, and in
[spec/workspace-collector.md](../spec/workspace-collector.md), "Forwarding
interpretation" and "Client-facing wording".

## Not assessed

Whether any message was forwarded; what each filter matches; the Admin console's
automatic forwarding setting; routing and compliance rules; mail delegates, POP and
IMAP; send-as addresses; where mail forwarded inside the domains goes next; suspended
and archived mailboxes.

## Deferred

- E8: no "do you forward on purpose?" question; `scheck init` explains `directory_mail`
  and the approval caveat.
- E9: `data.matters_most` for email-area Workspace findings; collapse many forwarding
  instances in "Fix these first"; lab-rank forward-and-hide filters and helpdesk or
  accounting forwards as false-positive traps.
- 0.0.3: the Cloud Identity Policy API (`gmail.auto_forwarding`, `mail_delegation`,
  POP/IMAP, per-user outbound gateway); `forwardingAddresses`, delegates, send-as and
  POP/IMAP per mailbox; a receiving-service table (wording only); a subdomain-destination
  rule joined with the web collector's MX reads; "new forwarding since the last run".

## Unmeasured assumptions (live, step 7)

1. `getAutoForwarding` returns `enabled:false` or omits it, and `filters.list` returns
   `{}` when there are none. 2. The exchange errors for suspended, archived, deleted,
   unlicensed and Gmail-disabled subjects (only "user doesn't exist" as `invalid_grant`
   is sourced). 3. Reads of a Gmail-disabled mailbox answer 400 `failedPrecondition`.
   4. A suspended mailbox bounces or stops forwarding. 5. An archived mailbox receives
   no new mail (sourced; confirm live). 6. Turning off automatic forwarding stops
   existing forwards. 7. A filter to a later-deleted address still lists. 8. The token
   endpoint limits at 100 to 1,000 sequential JWT exchanges. 9. Google's audit logs
   record per-user impersonation. 10. The Admin console paths (Email Log Search, End
   User Access, Manage Domain Wide Delegation). 11. `admin_policy_enforced` varies by
   organizational unit. 12. Gmail's per-user filter limit against the cap of 1,000.

No live tenant was contacted, no software test is recorded here, and no SEED or RANK
work ran.
