# E6 owner decisions: S7 and directory_oauth mailboxes

Recorded 2026-10-12 on `e6-workspace-collector`. The user decided both questions
through the implementing session on 2026-10-12. The implementing session is Grok 4.7.
The spec-steward recorded this file. No code changed: the behavior already matches
the specs and the tests. This is not an acceptance pass and not a live measurement.
No live tenant was contacted. Evidence is those existing specs and tests, not a new
run. This supplements the 2026-10-11 E6 records and does not rewrite them.

## S7: a refused surface is a coverage gap, not exit 2

A Workspace surface that was selected and then refused with no usable read stays a
coverage gap. It does not exit 2. This covers a refused permission,
`unavailable:needs_service_account` and a tripped breaker, for both the OAuth-grant
surface and the Gmail-forwarding surface. A rate limit remains `limit_reached` and
can still exit 2. Rate limits are not part of S7.

This confirms D4 in
[e6-forwarding-definition-2026-10-11.md](e6-forwarding-definition-2026-10-11.md): a
refused permission, `needs_service_account` or a tripped breaker is a coverage gap
only. It declines the later consultant recommendation of exit 2
([e6-oauth-verification-2026-10-11.md](e6-oauth-verification-2026-10-11.md),
consultant REVIEW, S7).

The behavior is already stated in `docs/spec/workspace-collector.md`, "Mailbox tokens
(step 6)", and in the `Evidence.Outcome()` paragraph under "Reporting and coverage":
a refused optional permission, `needs_service_account`, a disabled Gmail API and a
tripped breaker are coverage gaps only, and any `limit_reached` read makes the
Workspace asset incomplete, exit 2. `Evidence.Outcome` in
`internal/collector/workspace/coverage_plan.go` treats a refused optional permission
as a coverage gap and `limit_reached` as incomplete.

## directory_oauth does not need authorization.mailboxes

`directory_oauth` does not need an `authorization.mailboxes` entry. That profile
acts with the administrator credential and does not sign in as staff.
`authorization.mailboxes` stays the gate for profiles that select `gmail_forwarding`
(`directory_mail` and `directory_oauth_mail`), together with
`SCHECK_WORKSPACE_PROFILE`. Neither alone admits a mailbox sign-in.

This matches
[e6-mailbox-authorization-2026-10-11.md](e6-mailbox-authorization-2026-10-11.md)
("`directory_oauth` does not get an entry") and the consultant recommendation there.
The owner decided it on 2026-10-12.

## Brightcart profile

The step 6 gap is filled in `.agents/clients/brightcart.md`, as beliefs that may be
wrong, not as verified facts. Under People and access, a Google "service account" is
something Dani heard the MSP mention when they set mail up; Dani does not know
whether one was created, who holds the key or what it can open, and would not create
one. Under What Dani believes about security, letting a tool sign in as staff
mailboxes to read whether mail is forwarded somewhere else, Dani would not approve
that alone, would ask Sam and the MSP because the MSP set Google up, is not sure
"settings" leaves the messages unread, and would say no if it sounded like opening
people's mail.

The step 5 gap is not filled: Brightcart's profile still says nothing of its
Marketplace installs or of who set up the credential.
