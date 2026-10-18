# scheck — Google Workspace collector specification

Google Workspace assessment planned for 0.0.2 E6. The security-consultant DEFINE
review froze this design on 2026-10-10. Steps 1 and 2 implement credentials, tenant
binding and inventory through engagement Recon and report integration. Step 3
implements identity and administrator rules, with offline checks and reviews
completed on 2026-10-10. Step 4 implements observed 2-step verification offline on
2026-10-11. Step 5 implements optional OAuth grant metadata offline on 2026-10-11.
Step 6 implements optional Gmail forwarding metadata offline on 2026-10-11. The optional `access.mfa[].sign_in` declaration (federation) was built on 2026-10-18 (owner's decision). Step 6 D3
implements the mailbox-authorization gate offline on 2026-10-11 (owner's decision): the
profile alone does not admit a mailbox sign-in. The record is
[eval/e6-mailbox-authorization-2026-10-11.md](../eval/e6-mailbox-authorization-2026-10-11.md).
Step 7's offline closing review and the attributed measurements of one
authorized tenant are recorded in
[eval/e6-closing-review-2026-10-12.md](../eval/e6-closing-review-2026-10-12.md).
Those measurements are not a sealed lab and not acceptance. Release gate 11
is not accepted.

The gate owns admission, sending, credentials, redaction and persistence
([scope.md](scope.md#the-scope-gate)). Engagement supplies people declarations, admin
thresholds and severity adjustments ([engagement.md](engagement.md), "People",
"Admins", "Severity in context"). Engagement remains the only report author;
[report.md](report.md) and [runs.md](runs.md) govern report and resume behavior.

## Boundary

Every target operation is a compiled `GET` through the gate. The only `POST`s are the
separately declared, budgeted credential exchanges, the baseline one and one per
compiled optional surface or, for a per-mailbox surface (Gmail forwarding), one per
admitted mailbox, at the literal endpoint `https://oauth2.googleapis.com/token`. Its secret body and response never enter
evidence, audit output or persisted state. Assertions are signed in process with a
fixed audience and a 300-second lifetime. The gate signs `RS256` assertions with
`iss`, delegated `sub`, literal token-endpoint `aud`, compiled `scope`, `iat` and
`exp`; `kid` comes from the selected key. Credential exchange goes through `Send`,
sharing admission, authorization windows, throttling, timeouts, budgets, TLS checks
and audit with reads. The secret form body and token response are private, never
ordinary response evidence. A token `POST` is not retried, including on a rate limit;
no caller-supplied `POST` body is admitted. Target `GET` requests retain the standard
`Send` retries for 429, 502, 503, 504 and eligible connection resets. Private failures
expose typed execution status and fixed diagnostics, never `net/http` URL text that
could reveal an unbound customer selector. Recognized OAuth error codes select safe
fixed messages; returned error descriptions are discarded.

No SDK, subprocess, `gcloud`, metadata server, token introspection, interactive
consent, arbitrary token endpoint, external-account federation, executable credential
provider or impersonation ADC is supported. No target writes, message reads, backup
verification code reads, or automatic delegation setup are admitted. The only Gmail
requests are the two pinned settings reads of "Reads and projections"; nothing else
reaches `gmail.googleapis.com`.
The gate continues to refuse decoded `verificationCodes` paths.

### Credential files and profiles

E6 supports restricted ADC-file loading: `GOOGLE_APPLICATION_CREDENTIALS`, otherwise
the conventional local ADC file, with only `authorized_user` and `service_account`
JSON types. This is not full ADC support. The gate alone holds keys, refresh tokens,
client secrets, JWT assertions and access tokens. Credentials never come from the
engagement file. `SCHECK_WORKSPACE_SUBJECT` supplies the delegated administrator for
service-account authentication. `authorized_user` credentials refuse that variable;
this profile does not impersonate a user through a refresh token.

The selected credential file must be regular and at most 256 KiB. It is opened
read-only with `O_NOFOLLOW` and `O_NONBLOCK`; symlinks and nonregular files are refused.
An explicitly selected unreadable or unsupported file never falls back to another
credential. Parsing requires one JSON object, no duplicate keys or trailing data,
valid UTF-8, and only these string-valued fields. Every present field must be a
string, including optional metadata; JSON `null` is refused:

| Type | Allowed fields |
|---|---|
| Both | `type`, `universe_domain`, `quota_project_id`, `token_uri` |
| `authorized_user` | `client_id`, `client_secret`, `refresh_token`, `account` |
| `service_account` | `project_id`, `private_key_id`, `private_key`, `client_email`, `client_id`, `auth_uri`, `auth_provider_x509_cert_url`, `client_x509_cert_url` |

`token_uri`, when present, must equal the literal token endpoint; `universe_domain`,
when present, must be `googleapis.com`. Metadata URLs are not followed. The service
key must be one unencrypted PKCS#8 RSA private key of at least 2048 bits, with no
extra PEM block or header. Malformed credentials produce fixed diagnostic text,
never decoder excerpts or credential values.

The selected file is loaded once as an immutable credential snapshot for the gate
session. File replacement, rotation or a changed credential path takes effect in a
new gate session, not by silently replacing current authentication. A changed
profile or delegated subject stops dependent requests in the current session.

Token responses are limited to 64 KiB and must contain a recognized Bearer token and
integer expiry greater than 60 seconds. The gate subtracts a 60-second safety margin
and caps provider expiry at one hour from request start before subtracting that
margin. Returned scope evidence is known only when its explicit field is a usable
string; absent, `null` or malformed scope is unknown. Requested scopes do not fill
that gap. Tokens stay in session memory. Expiry or rejected authentication
requires a fresh ordered bootstrap before a later tenant read. The session's token lives
about an hour from Recon's bootstrap, so Workspace's Check reads run before GitHub's. A
read stopped by that expiry (`unavailable:bootstrap_required`) counts as a limit: the
tenant's outcome is `incomplete` with `limit_reached`, exit 2, and the detail "The
Workspace session's token expired before every Workspace read was made; resume to read the
rest."; a cut per-user population gains its selection. Once the token expired every later
read in the session halts the same way (`unavailable:bootstrap_required`, repeating) until
a new bootstrap is attempted, never as an unbound tenant. Expiry never preserves an
authorization.

`SCHECK_WORKSPACE_PROFILE` selects one compiled read profile:

| Profile | Reads selected |
|---|---|
| `directory` (default) | Baseline Directory inventory and identity |
| `directory_oauth` | Directory plus per-user OAuth grant metadata (step 5) |
| `directory_mail` | Directory plus per-mailbox Gmail forwarding settings (step 6) |
| `directory_oauth_mail` | All three selected surfaces |

The nonsecret profile is recorded for coverage and invalidation. A profile narrows
the operation catalog; it never widens tenant scope or permits a write. Missing
permissions remain a gap. No automatic broader-scope request or fallback to a
write-capable Gmail scope fills one.

Every profile authenticates the tenant-binding bootstrap with the baseline credential
only. A service-account bootstrap asserts only the baseline Directory scopes below. An
`authorized_user` baseline refresh sends no `scope` parameter, so Google returns a token
for everything the existing grant holds: it never adds scopes, and it is not narrowed to
the baseline either. Selecting optional checks does not add security or Gmail scopes to
the bootstrap and does not make baseline checks depend on those grants.

**Optional surface token.** An operation compiled with an optional surface
(`Op.Surface`) never uses the baseline token. The gate keeps a table of surfaces, each
with exactly one scope, its own audited exchange operation, the profiles that select it
and its pinned reads; a collector never names a scope.

| Surface | Scope | Exchange operation | Profiles |
|---|---|---|---|
| `oauth_grants` | `admin.directory.user.security` | `workspace.credential_exchange_oauth_grants` | `directory_oauth`, `directory_oauth_mail` |
| `gmail_forwarding` | `gmail.readonly`, no other scope, no fallback | `workspace.credential_exchange_gmail_forwarding` | `directory_mail`, `directory_oauth_mail` |

The gate refuses such an operation with `unavailable:profile_not_selected` when the
profile does not select the surface, and, for a service account, with
`unavailable:principal_unknown` until the delegated subject is verified ("Principal and
resume"). After baseline admission it makes the surface's exchange, never retried. A
service account asserts exactly the surface's one scope, with the same issuer and
subject. An `authorized_user` refresh sends `scope=` that one scope; that Google then
downscopes the token, and answers `invalid_scope` for a scope the grant lacks, is
assumed and not yet measured live. The optional token's expiry is capped at the baseline
token's. The token, and a remembered failure, are cleared with the tenant binding: on a
bootstrap operation, an HTTP 401, baseline expiry, `credential_changed` and a changed
profile.

A failed optional exchange is remembered for the session: later reads of the surface
send nothing and carry the same classification. It is never a refusal of the asset and
never exits 3. `invalid_scope`, `unauthorized_client` and `access_denied` are
`insufficient_permission:<the surface's scope>` (`admin.directory.user.security` or
`gmail.readonly`), a coverage gap; a rate limit is `limit_reached`, exit 2; any other
failure is `unavailable:credential_exchange`. A per-account 403 on an optional-surface
read is `insufficient_permission:<scope>` too, the scope named by the gate; a 404 names
no scope. A Workspace 403 whose error reason is `rateLimitExceeded` or
`userRateLimitExceeded` is a rate limit on every Workspace read, retried and then
`limit_reached` ([scope.md](scope.md), "Status codes that mislead"); its retained
error body stays fixed text.

**Mailbox tokens (step 6).** Gmail forwarding is a per-mailbox surface: the gate asks
for one token per admitted mailbox, a service-account assertion whose `sub` is that
account. It needs a service account with domain-wide delegation for `gmail.readonly`.
With an `authorized_user` credential every Gmail operation is refused before any
exchange, remembered as `unavailable:needs_service_account`; a refresh token never
impersonates a mailbox.

Before each exchange the gate admits the mailbox in this order: the profile selects
`gmail_forwarding`; a current `authorization.mailboxes` entry for this Workspace asset
is in the copy loaded for this gate session; the credential is a service account; the
delegated principal is verified; the tenant is bound; the users population is complete;
the `{user}` parameter is an admitted current id of the bound customer, outside every
exclusion, known active (not suspended, not archived) and not reported
`isMailboxSetup:false`; and the admitted primary address is in a verified domain or
verified alias of the tenant. The approval is checked on every mailbox read, including
one that would reuse a cached token, and again when the exchange itself is admitted.
Both checks use that loaded copy and the gate's clock. They do not re-read the
engagement file. A missing or not-current entry (`missing`, `expired`,
`not_yet_current`, `other_asset`) is `refused:mailbox_authorization` with that detail,
remembered for the surface (`Repeats`), so no subsequent exchange is attempted and no
mailbox is signed in as. `expired` and `not_yet_current` use the coverage reason
`unavailable:mailbox_authorization_expired`. `missing` and `other_asset` use
`unavailable:mailbox_authorization_missing`: an entry for a different Workspace asset
is not an approval for this one. The loaded entry's `asset` is the canonical id from
intake (`saas:google-workspace:*`), compared with the request's asset. An admitted exchange and each Gmail read
sent under it carry `asset`, `by`, `date` and `expires` on the audit line; a refusal
carries `state` as well. `by` is redacted like any other free-text parameter. The line
never carries a staff address. The collector words the refusal from those fields.

The assertion's `sub` is the primary address of the gate's own inventory record, never
an address a collector or a response supplied. An account that is inactive or has no
mailbox is refused `unavailable:mailbox_inactive`, without being remembered against the
surface. The exchange is audited under the surface's one operation with the admitted
user id as its only parameter, never an address, assertion or body, so each Gmail
read's audit line names the user whose token it used.

**Mailbox authorization.** A gate session loads `authorization.mailboxes` when the
session starts. A new session, including a resume, reads the engagement file again and
loads that copy. The running process does not re-read the file. On every mailbox read
and again on the exchange, the gate checks the loaded entry and the clock. The entry
is current on `[start of date, 24:00 on expires)` in `engagement.timezone`. A `date`
in the future is accepted at intake but is not yet current until that day. When the
approval ends mid-run, the gate drops the surface's cached mailbox tokens and issues
`refused:mailbox_authorization` with detail `expired`, remembered as `Repeats`. A read
already holding a credential finishes. Remaining mailboxes are not attempted. This
mid-run expiry is a coverage gap, not `limit_reached`, and does not exit 2.

A missing or not-current entry produces a named coverage gap:
`unavailable:mailbox_authorization_missing` (`missing` or `other_asset`) or
`unavailable:mailbox_authorization_expired` (`expired` or `not_yet_current`; each keeps
its own detail). A malformed entry exits 3 at intake, before any contact. An entry
that is expired or not yet current warns before contact, the same kind of warning as
`no_credentials`, and does not exit 3; Directory reads continue and the mailbox
surface does not. A missing entry does not warn at intake, because whether the profile
selects mail is an environment variable, not a fact in the file.

`directory_oauth` does not receive a `mailboxes` entry, and does not need one
(decided 2026-10-12): that profile acts with the administrator credential and does
not sign in as staff. `authorization.mailboxes` stays the gate for profiles that
select `gmail_forwarding` (`directory_mail` and `directory_oauth_mail`), together
with `SCHECK_WORKSPACE_PROFILE`. Neither alone admits a mailbox sign-in. There is no
skip list.

Tokens are cached by bound customer and admitted user id, never reused for another
user, cleared with the binding as above and capped at the baseline token's expiry. The
exchange count is at most one per admitted user per binding and at most 1,000 per
session, not reset by a new binding; the 1,001st is a remembered `limit_reached`.

Failures are the surface's or one mailbox's:

| Failure | Scope | Classification |
|---|---|---|
| Missing, expired, not-yet-current, or other-asset `authorization.mailboxes` entry | surface, remembered | `refused:mailbox_authorization` with detail `missing`, `expired`, `not_yet_current` or `other_asset`; `other_asset` and `missing` use `unavailable:mailbox_authorization_missing`; `expired` and `not_yet_current` use `unavailable:mailbox_authorization_expired` |
| `invalid_scope`, `unauthorized_client`, `access_denied` at the token endpoint | surface, remembered | `insufficient_permission:gmail.readonly`, gap |
| Token endpoint rate limit | surface, remembered, never retried | `limit_reached`, exit 2 |
| Circuit breaker | surface, remembered | `unavailable:credential_exchange`, gap |
| Refused before the request left this machine (deadline, rate limit, canceled, a stopped provider) | surface, remembered, not counted toward the cap or the breaker | its own decision and reason; `limit_reached` is exit 2 |
| Request sent and no answer (dropped connection, timeout), or a Google 5xx at the token endpoint | that mailbox, not remembered; counted toward the cap and the breaker | its own reason (`unavailable:server_error`, a connection code), never `mailbox_credential` |
| `invalid_grant` or any other exchange error Google answered | that mailbox | `unavailable:mailbox_credential` |
| `admin_policy_enforced` at the token endpoint | that mailbox | `insufficient_permission:gmail.readonly` |
| Gmail API not enabled in the credential's project (403 `accessNotConfigured` or `SERVICE_DISABLED`) | surface, remembered | `unavailable:api_disabled`, gap; fixed body; the collector says to enable the Gmail API under APIs & Services → Library |
| Gmail 403 on a read | that mailbox | `insufficient_permission:gmail.readonly` |
| Gmail 400 on a read | that mailbox | `unavailable:mailbox_unavailable` (no Gmail service for it) |
| Google 403 rate limit | every read | retried, then `limit_reached` |

The breaker trips when a binding's first five mailbox exchanges all fail, or after 20
consecutive mailbox failures (an `admin_policy_enforced` refusal and an unanswered or
5xx exchange count). A revoked key, a wrong clock or Google failing looks like one
mailbox failing after another, so the surface then stops, remaining mailboxes are not
attempted and each reads the breaker's classification; it is a coverage gap, not exit 2.
The breaker's wording is neutral: Google did not sign scheck in as one mailbox after
another and may have been failing, so run again later, and if it repeats check the key
and the delegation. An exchange counts as one scheck asked Google to act as the mailbox
when it left this machine, answered or not; the gate keeps that set for the session and
every mail read's result carries it (`ActedAsMailbox`). A refused permission,
`needs_service_account`, a disabled Gmail API and a tripped breaker are coverage gaps
only. A surface selected and then refused with no usable read does not exit 2, for
OAuth and for mail (decided 2026-10-12;
[e6-decisions-2026-10-12.md](../eval/e6-decisions-2026-10-12.md)). A rate limit remains
`limit_reached` and can still exit 2.

All baseline scope names below have the prefix
`https://www.googleapis.com/auth/`:

- `admin.directory.customer.readonly`
- `admin.directory.domain.readonly`
- `admin.directory.orgunit.readonly`
- `admin.directory.user.readonly`
- `admin.directory.rolemanagement.readonly`

Optional group context uses `admin.directory.group.readonly`. OAuth metadata needs
`admin.directory.user.security`, which has no read-only variant; the optional
profile requires an existing approved credential, and any token issued for it produces
the separate credential warning in "OAuth grants".
Gmail forwarding reads use `gmail.readonly`. An already approved credential carrying
`gmail.settings.basic` can permit the same compiled reads, but that scope is write
capable and is never requested as an automatic fallback. Domain-wide delegation must
already be approved; the collector never enables it.

Requested scopes or labels in a local file are not proof of granted capabilities.
Only usable returned scope evidence or an explicitly supported exact capability
signal informs the credential note. Known grants beyond reads produce an unranked
warning, as in E5. A known read-only set says "No recognized beyond-read scope
observed; effective permissions untested." Unknown grants provide no assurance.
No credential value or hash is persisted.

## Tenant binding and scope

The declared root is a Workspace domain; a returned customer id identifies the
tenant. Before binding, only minimal audited bootstrap is allowed:
`customers.get(my_customer)`, followed by that returned customer's domains and domain
aliases, in that order. All three responses must be recognized and usable, even
when the declared root was already a verified domain. Alias binding requires a
verified alias whose parent is a verified domain in the returned customer domain
set. Conflicting duplicate verification or alias-parent evidence refuses binding.
Malformed array members refuse binding rather than disappearing in projection.
Each domain and alias population is limited to 1,000 records; an actual excess is
`limit_reached`, not an empty inventory. Bootstrap bodies,
foreign names and ids, response headers and body hashes remain private; its audit
identifies the declared root and compiled path, not unbound tenant selectors. The
audit URL is sanitized during request binding, before any later refusal can record it. Only
the successfully bound customer id, declared root, selected profile, the optional
surfaces that profile selects (`surfaces`; profile names stay in the gate), for each
surface it does not select the profile that would add it to the current one (`offers`,
which the collector's advice names instead of hard-coding profile names), usable
returned scope evidence and, for an `authorized_user` credential, its client id as
`assessment_client` leave the private bootstrap. A successful client-authenticated
refresh proves that client id, never whose sign-in the refresh token holds. The
collector keeps `assessment_client` only from an unredacted summary, at most 256 bytes,
with no control character or whitespace.

`workspace.Bind` owns the three ordered sends through a small `Sender` interface;
engagement never sequences bootstrap operations. Bootstrap id constants are unexported
in the collector. The gate recognizes a closed set of three exact endpoint templates and
keeps Directory response recognition confined to them. `Bind` requires a usable final
summary: missing, malformed or incomplete summary evidence marks the final read
`unavailable:binding_summary` and returns no tenant or credential-summary fields.

This is a narrow bootstrap exception, never authorization to read users,
roles, grants or Gmail settings.

Binding requires a valid customer id and the exact declared root as a verified
domain or domain alias attached to that customer, with no contradictory evidence.
An email suffix, service-account project, local account or configured customer id is
not proof. A mismatch or unproved binding admits no further reads and prints no
unrelated tenant inventory. After binding, requests use the literal returned id.
Customer binding is freshly rechecked before retained evidence or follow-ups on resume.

The gate fills every `customer` parameter from its session; caller-supplied values
are refused, including the correct id. Ordinary bound reads use the standard
redaction and compiled `Keep` projection pipeline, not the private bootstrap parser.
An HTTP 401 clears both authentication and binding before any later read. Operation
paths, parameters and projections belong to the collector's catalog and are compiled
by registration. Gate validation retains the bootstrap endpoint exceptions and
structural restrictions: `GET` to the literal Directory host, a declared tenant or
admitted-user subject, and a required gate-filled customer selector for tenant lists. Compiled templates
contain no percent encoding or path traversal. Customer selection is gate-filled in
the path or the compiled users query. The users query fixes full admin projection,
100 records per page and at most 10 pages. The gate fills page tokens from its ledger;
collectors follow request ids rather than supplying cursors.

Organizational-unit exclusions match canonical subtree boundaries behind `Scope` and
the gate. The complete unit tree is recognized privately before exclusion filtering.
Canonical paths match case-insensitively by subtree boundary; opaque unit ids are
bounded. A missing root, unknown parent, conflicting identity or incomplete tree
blocks user reads. The customer-bound user inventory establishes excluded subjects before
persistence and follow-ups. Unrecognized user identities or conflicting current
ids, primary addresses or aliases prevent per-user admission. An unknown exclusion
set blocks dependent reads. Excluded people are never persisted; only dropped counts
remain. Per-user parameters refer only to admitted current inventory identities.
The gate parses no posture field except three list flags (`suspended`, `archived`,
`isMailboxSetup`), which it keeps in its own admitted record so that a mailbox surface
can refuse to act as an inactive account or one without a mailbox; every other posture
field is parsed only by the collector.
An external address or group member address never grants permission to read a user.
A provider-complete current inventory with only known exclusion drops may still admit
nonexcluded user details; retained coverage stays incomplete. Actual cuts, unknown
identities or conflicts block all dependent details. The root unit currently requires
absent or empty parent fields; compatibility with provider root-parent sentinels has
not been measured live.

Account subjects use current `primaryEmail`, with stable `subject.provider_id` beside
it. Renames can change the subject key; cross-run provider-id comparison belongs to
0.0.3. People match by primary address and the engagement's full alias rules. Display
names never attribute an account. A leaver's active alias match abstains rather than
proving that access was removed.

### Principal and resume

Customer binding is not caller identity. An `authorized_user` caller remains unknown,
so authenticated evidence is not reused across sessions. There is no invented
"whoami" read. A service-account issuer, configured client id and delegated subject
are distinct from the freshly verified Directory delegated user's stable id. A
successful JWT exchange does not provider-verify the JSON `client_id` field.

Step 2 establishes the complete unit tree and current customer-bound users before
a fresh `users.get` verifies a service account's configured delegated subject. The
subject must match an admitted primary address or alias, but the request selects its
current stable id. Detail must agree on the current id, primary address, customer
and unit and remain outside excluded subtrees. An incomplete or contradictory user
inventory permits no delegated-user follow-up. `authorized_user` identity remains
unknown; neither local account metadata nor a refresh proves the caller.

No Workspace response is eligible for authenticated ledger reuse, even after a
delegated user is verified or an earlier ledger row names a principal. Resume repeats
ordered tenant binding, unit and user admission and delegated verification. Changes
to issuer, subject, customer or profile require fresh evidence. The Gmail
per-mailbox token cache is keyed by bound customer and admitted user id ("Credential
files and profiles"). Current primary address, customer and exclusions are checked
before impersonation, never inferred from an arbitrary target-returned address.

## Reads and projections

Cheapest reads come first: bootstrap, complete unit tree and customer-bound users,
roles and privilege tree, assignments, fresh inactivity details, then selected OAuth
and Gmail reads. A primary-domain-only user list cannot inventory a tenant containing
secondary domains and aliases.

| Read | Compiled path or selector | Retained evidence |
|---|---|---|
| Customer | `/admin/directory/v1/customers/my_customer` for bootstrap; then `/admin/directory/v1/customers/{customer}` | Customer id and binding evidence |
| Domains | `/admin/directory/v1/customer/{customer}/domains` | Domain names and verification/binding fields |
| Domain aliases | `/admin/directory/v1/customer/{customer}/domainaliases` | Alias names and verification/binding fields |
| Units | `/admin/directory/v1/customer/{customer}/orgunits` | Unit ids, canonical paths and parent relationships |
| Users | `/admin/directory/v1/users`, fixed `customer={customer}` and full admin projection | Id, current primary email, relevant aliases, name label, customer/unit, suspension/archive/admin flags, creation/login/MFA flags and mailbox status |
| Optional group context (not compiled) | `/admin/directory/v1/groups`, fixed `customer={customer}`; planned, no op registered | Group id, email, aliases and label only |
| User detail | `/admin/directory/v1/users/{user}` | Same relevant fields; fresh login evidence and delegated-subject verification |
| Roles | `/admin/directory/v1/customer/{customer}/roles` | `kind`, `roleId`, `roleName`, `rolePrivileges.serviceId`, `rolePrivileges.privilegeName` and `isSuperAdminRole` |
| Privilege tree | `/admin/directory/v1/customer/{customer}/roles/ALL/privileges` | `kind`, `serviceId`, `privilegeName`, recursive `childPrivileges` and `isOuScopable` |
| Per-user role assignments | `/admin/directory/v1/customer/{customer}/roleassignments`, fixed `userKey={user}` and `includeIndirectRoleAssignments=true` | Assignment/assignee/role ids, assignee type, CUSTOMER/OU scope, condition presence and `expirationDetails.expireTime` |
| OAuth grants | `/admin/directory/v1/users/{user}/tokens`, no query, with the `oauth_grants` token | `clientId`, `scopes`, `userKey`, `displayText`, `anonymous` and `nativeApp`; no token value |
| Auto-forwarding | `/gmail/v1/users/me/settings/autoForwarding`, with the mailbox's own token | `enabled`, `emailAddress`, `disposition` |
| Forwarding filters | `/gmail/v1/users/me/settings/filters`, with the mailbox's own token | `id`, `action.forward`, `action.addLabelIds`, `action.removeLabelIds` |

Directory operations use `admin.googleapis.com`; Gmail operations use
`gmail.googleapis.com`. Credential exchange uses `oauth2.googleapis.com`. API bodies
are never retained wholesale. User recovery data, custom schemas, notes, home
addresses, passwords, SSH keys and photos are omitted. Secrets in retained fields are redacted before
parsing and persistence. API response headers, error bodies and unprojected hashes
are discarded. Account ids and name labels are redacted before persistence, as are
other retained fields.

Role, privilege-tree and per-user assignment operations opt into
`PreserveMalformed`: unsupported projected nested shapes, including array members,
become JSON null rather than disappearing. Malformed expiry therefore remains
unknown, and malformed privilege members cannot become an apparently empty
population. Undeclared siblings are discarded; supported positive siblings remain
usable. Other operations retain their existing projection semantics.

Step 3 declares no tenant-wide direct-assignment, group or group-member reads.
Per-user assignment reads include direct and indirect grants for current admitted
users only; there is no claim of a tenant-wide assignment inventory. The optional
group-context read in the table remains planned; it is not needed to interpret a
per-user assignment returned by Directory. Fresh user details take accounts in the order of "Per-user read order under caps"
below when a cap, the timeout or the rate limit prevents reading everyone.

**Per-user read order under caps** (step 6b, built; `UserTiersVersion`,
`internal/collector/workspace/selection.go`). Recon reads the users, roles and admin
assignments (inventory) and the per-user assignment and detail reads; Plan orders the
accounts (`Select`, `plan.json` `workspace[]`); Check, after Plan, reads the per-user
OAuth grants and then Gmail forwarding (`CollectUsers`). `Collect`, in Recon, reads
neither: when the profile reads them (`oauth.selected`, `mail.selected` in `recon.json`)
it writes no grant or forwarding readout and notes "Third-party app grants and mail
forwarding, which this profile reads, are read in Check, after Plan orders the accounts."
Check rewrites the notes over everything read; credential warnings its reads raise (the
OAuth token, `gmail.readonly`) are logged to stderr as Recon's are. Recon's per-user reads and Check's OAuth grants take accounts in
the order of [engagement.md](engagement.md), "Plan selection and follow-ups": 1 a person
who left, still active; 2 admin holders no `people` handle names; 3 super admins and
holders of delegated roles a handle names; 4 declared `contractor` and `shared` accounts;
5 `break_glass` and `service` accounts; 6 the rest. An admin holder, for ordering, has
`isAdmin`, `isDelegatedAdmin` or an observed role assignment; the identity rules' own
reading of an admin is unchanged. Recon orders before it has read any assignment, so
its admin holders are those Google's flags name; Plan and Check also count an observed
assignment. Within every tier: active first, then most recent sign-in, then
`primaryEmail`, then the account id. Gmail forwarding keeps its own order, from the
mailboxes Check reads: leavers still active first, then admin holders, then the rest,
active first within each tier, then `primaryEmail`. The order replaces the one named for
OAuth grants below; the sequence of reads (OAuth grants after every baseline read,
forwarding after every other read) and the `Repeats` stop are unchanged. There is no
Workspace request budget in 0.0.2. `OAuthEvidence.Selection` and `MailEvidence.Selection`
(`finding.Selection`, unit `users`, kind `oauth_grants` or `mail_forwarding`) are set
only when a read ended `limit_reached` (a cap, the timeout or the rate limit) before every
account was read: the reason is kept (exit 2) and the selection gives the tiers of the
accounts read; the session token's expiry is such a limit. Recon's per-user assignment cap
carries no selection. A `Repeats` stop that is not a limit is a failure and has no
selection. In
the report the plan coverage gives the sub-item that population and marks it at most
*partial*. A tenant Recon left `collected` becomes `incomplete` when Check's outcome is.

A fresh `users.get` is required for every inactivity verdict: Google's list
`lastLoginTime` can be inaccurate. Recognized 2-step flags in the current list suffice
for the 2-step rules; fresh detail only fills a flag the list lacks. Conflicting
list/detail identity or security values cause abstention and a diagnostic note.
Flag-specific conflicts are in "Observed 2-step verification".

Step 5 reads OAuth grants after every baseline read, for every admitted account,
suspended and archived included, in Plan's order above (a suspended leaver does not rank
first). Per-user OAuth and forwarding reads run in Check, after Plan; their requests carry
the audit stage `check`. A result the gate marks `Repeats` (every
later request of the kind would end the same way: a remembered optional failure, the
profile not selecting the surface, an unverified principal, binding or authentication
gone) is recorded once and stops the sequence; a per-account refusal does not. The gate
pins the registration: the path above with no query, subject `users/{user}`, list
`items` in an exact `admin#directory#tokenList` envelope, at most 1,000 items, no
paging, `SelfRef: userKey`, and kept fields only from the six above. The gate drops an
item whose `userKey` is missing or differs from the requested admitted id as
unattributable ([scope.md](scope.md), "Responses"); that account's grants are then
incomplete, and a note names it. A grant with a missing or non-string `clientId`,
`scopes` missing, not an array or holding an empty string, or a wrongly typed
`displayText`, `anonymous` or `nativeApp` is malformed: the account's grants are
incomplete and a note names it. An empty `scopes` array is a grant whose access is
unknown. A redaction marker confined to `displayText` keeps the read usable: an app
chooses its own name and must not hide its grants behind it. A marker in any other
field leaves the account's read unusable.

Step 6 reads Gmail forwarding for each readable mailbox after every other read, OAuth
grants included, in the same order and with the same `Repeats` stop. Only a known-active
account with a mailbox is read ("Forwarding interpretation"). Each path names
`users/me`, so a read can only reach the mailbox the gate signed in as; `{user}`
selects the token, not the path. The gate pins both registrations in its surface table:
the exact URL, the kept fields in the table above and nothing else, and for filters an
exact `filter` array of at most 1,000 items with no paging. Filter `id` and
`action.addLabelIds` / `action.removeLabelIds` are kept so that the collector can tell
that a forwarding filter also hides the message (`hides_mail`); filter criteria,
queries, subjects and every other action are discarded. `forwardingAddresses`,
delegates, send-as, POP and IMAP paths, and anything else under `/gmail/`, are not
declared and the gate refuses them. These two operations are projected before
redaction: fields outside the kept list never reach redaction, the audit log or
persistence. They have no envelope: automatic forwarding is one object, `{}` is an
empty answer, and an empty filter list arrives as `{}` or as HTTP 204 with no body.
A 204 with no body on the filters read is that empty list, and the stored status stays
204. The collector treats that one read as usable. A 204 that carries a body is not
that empty list: an object with no `filter` array would otherwise be read as no
filters. Any other empty body, and a body that is not the expected shape, is a fixed
diagnostic and is discarded. Automatic forwarding does not accept a 204.

### Population bounds

Pages continue through an empty list with a nonempty next token. The gate rebuilds
requests from compiled templates, never returned URLs. Directory list bodies require
the exact compiled `kind` envelope, including empty populations. Provider ids are
deduplicated; conflicting duplicates, unknown members, malformed cursors, loops and
actual cuts mark incomplete evidence. Redacted populations are incomplete; conflicting
duplicate identities revoke admission rather than selecting one version. Permission
failures are not empty lists. A
present null, empty or non-string next cursor is unreadable, not an end-of-population
signal. Refreshing binding, units or
the initial users page revokes pending continuations before contact, including when
the refresh fails. An earlier page cannot restore current-user admission.

| Population | Item cap | Page cap and size |
|---|---|---|
| Users and optional groups | 1,000 each | 10 pages of 100 |
| Units | 1,000 | Single list |
| Roles | 1,000 | 10 pages of 100 |
| Privilege tree | 1,000 nodes, depth 32, 1 MiB | Single result; exact `admin#directory#privileges` envelope |
| Per-user assignments | 1,000 per user | 10 pages of 100 |
| Assignment observations | 10,000 per tenant | Across assignment reads |
| OAuth grants | 1,000 per user | Single array; over the cap the whole read is `limit_reached` |
| Gmail filters | 1,000 per mailbox | Single `filter` array; over the cap the whole read is `limit_reached` |

The privilege-tree depth counts node levels. A level-32 node with an empty child
array is within the bound; a further child is not.

Additional data or a next token beyond a cap marks incomplete execution, exit 2,
without discarding positive findings from earlier pages. A single array over its cap is
not kept at all: the read is `limit_reached`, exit 2, and positive findings in it are
lost. For OAuth grants that loses every grant of that account, and for Gmail filters
every filter of that mailbox; the account or mailbox counts as not read. Reaching exactly a cap with no further data is
not itself proof of a cut. The global gate budget still takes precedence. Partial
populations prove presence, never absence; counts say "at least".

## Administrative privilege interpretation

`isAdmin:true` proves super-admin status. `isDelegatedAdmin` alone does not prove a
destructive privilege. The exact service/name table, version `2026-10-10`, recognizes:

| Service id | Privilege names |
|---|---|
| Directory `00haapch16h1ysv` | `ROOT_APP_ADMIN`, `ADMIN_APIS_ALL`, `USERS_ALL`, `USERS_CREATE`, `USERS_UPDATE`, `USERS_MOVE`, `USERS_ALIAS`, `USERS_RESET_PASSWORD`, `USERS_FORCE_PASSWORD_CHANGE`, `USERS_ADD_NICKNAME`, `USERS_SUSPEND`, `USER_SECURITY_ALL`, `ORGANIZATION_UNITS_ALL`, `ORGANIZATION_UNITS_CREATE`, `ORGANIZATION_UNITS_UPDATE`, `ORGANIZATION_UNITS_DELETE`, `GROUPS_ALL` |
| Admin `01ci93xb3tmzyin` | `SUPER_ADMIN`, `CHANGE_USER_GROUP_MEMBERSHIP` |

Recognized narrow pairs are Directory `00haapch16h1ysv` with `USERS_RETRIEVE` or
`ORGANIZATION_UNITS_RETRIEVE`, and Admin `01ci93xb3tmzyin` with `ADMIN_DASHBOARD`.
Unfamiliar pairs remain unknown even when returned in the tree. A known-service
parent can prove privilege through an exact supported privileged descendant;
unknown pairs still block an absence verdict.

The returned privilege tree supplies documented parent-child relationships only in
these known service families. Unknown pairs or conditions remain uninterpreted and
cannot support an absence verdict. Role display names or global numeric role ids
never infer privilege. Beta conditions, unsupported app/domain privileges and
service-account assignees remain gaps. CUSTOMER versus OU restrictions are preserved.

Supported privileged delegates count for unattributed-admin findings and a departed
person's `attribute:admin`; they do not count for expected-super-admin comparison or
the super-admin threshold. Complete per-user direct and indirect assignment reads are
needed for attribution. Optional group inventory supplies group-address context only.
No group-member reads are declared; arbitrary membership and effective group-granted
access remain unassessed. Group inventory is never proof of effective access. A
suspended account retaining an administrative assignment is cleanup evidence;
suspension still prevents ordinary sign-in.

Step 3 reads direct and indirect assignments through each admitted user's
per-user response. The request is selected by an admitted stable user id and fixes
`includeIndirectRoleAssignments=true`. A returned `GROUP` assignment whose
`assignedTo` differs from that id is Directory's contextual association with the
requested user, not a locally inferred membership edge. A tenant-wide direct
`GROUP` observation proves a group grant only; it never attributes a user. Unknown
assignee types, including a missing `assigneeType`, and service-account assignees
remain coverage gaps. A missing `assigneeType` is never read as `USER`. A present
type is `USER` or `GROUP` only, compared without regard to case, because Directory
returns `user` and `group`. Any other present value stays unrecognized. The drop
count names the check and never the field value: `assignee_type_missing`,
`assignee_type_unrecognized`, `scope_unrecognized`, `scope_customer_has_unit`,
`scope_unit_unknown` or `assignee_mismatch`. No group-member
read fills them.

Only current supported assignments establish retained administrative privilege.
An absent condition or explicit empty string is unconditional; a nonempty, null
or wrongly typed condition is unsupported. Absent `expirationDetails` means no
recorded expiry. When present, a valid RFC3339 `expireTime` is interpreted even if
unknown sibling fields are discarded. Null, empty, unknown-only or malformed
expiration structures remain unknown. Projection
must preserve that distinction rather than turning an unreadable shape into absence.
Unknown expiration metadata cannot establish current privilege or absence. A
recognized expiry at or before the collection time of the assignments read that
carried it is expired and is ignored; a later expiry preserves the supported
assignment. A read with no recorded collection time leaves the expiry unknown, and
the session start is never the fallback (`engagement.md`, "Severity in context",
"Time"). Unknown roles or privileges block absence verdicts, but a
known supported privilege can still prove presence when an unknown sibling is also
returned. `isAdmin:true` independently proves super-admin status even when role
reads are unavailable. The exact service/name table above remains version
`2026-10-10`.

## Rules

Every rule returns shared `finding.Judgment` evidence with a declared subject and
`fired`, `disproved` or `abstained`. Account subjects are current primary addresses;
unit subjects are canonical paths including `/`; OAuth app subjects are exact client
ids; forwarding subjects are `<account primary> -> <destination address>`, both
lowercased. Subject-specific acceptances name that exact instance. Missing, null, unfamiliar,
denied, redacted or truncated evidence is unknown.

Shared identity definitions use provider-neutral prose. Workspace-specific definitions
are registered from the collector beside `Judge` through `finding.Register`;
`finding.Lookup` remains the report and explain read path. Step 3 evaluates the first
nine rules below, step 4 the two 2-step-verification rules, step 5 the OAuth rule and
step 6 the forwarding rule.

| Rule | Base severity / subject | Fires | Disproves | Abstains |
|---|---|---|---|---|
| `identity.unexpected_admin` | medium / account | Attributed super admin absent from the tenant's declared expected list | Expected super admin or known not-super-admin | Missing expected list, unknown identity or admin status; passed leaver suppresses this duplicate |
| `identity.unattributed_admin` | high / account | Observed super admin or supported privileged delegate, complete alias attribution finds no person, and tenant people context exists | Unambiguous attribution or known not-privileged | No people context, partial aliases or unknown roles |
| `identity.external_admin` | medium / account | Declared contractor is a super admin | Known not-contractor or not-super-admin | Unknown kind, attribution or admin status |
| `identity.shared_admin` | medium / account | Declared shared account is a super admin | Individual account or known not-super-admin | Unknown kind or admin status |
| `identity.former_person_has_access` | high / account, `+1 attribute:admin` | `left` date passed at the collection time of the read that observed the account, exact primary match and active account | Positively suspended/archived, or recognized complete current-address absence as of the earliest read of the population, with removed-rename caveat | Future date at the observing read (`leaving_date_not_passed`), date within collection ("left date *d* falls within or after collection; re-run after *d*"), no recorded collection time, unknown status, active alias-only match, missing identifier or partial population. A person whose date had not passed, or whose users were not read, abstains once per declared address (or `declared:<handle>`) so the report's "People who left" line has a judgment to read. An abstained per-user judgment for an account read with the date passed says why in Not checked: "Declared account identity is missing or ambiguous." (alias-only active match), "The account was read, but its status or access evidence was not recognized." (conflicting evidence or unrecognized status), "The users were not read."; and, for a passed date, a declared address not found and an incomplete users list, "The users list was incomplete, so an address missing from it is not proven gone."; the line reads these, never the default reason |
| `workspace.too_many_super_admins` | medium / none | Count above 3, or at least 3 and above a third of active humans | Complete populations below the threshold | Unknown exemptions or incomplete absence; partial population can fire only on the absolute lower bound above 3 |
| `workspace.stale_account` | medium / account | Eligible active account; fresh detail has a valid actual sign-in more than 90 calendar days before the collection time of the per-account detail read that returned it and the creation time | Suspended, archived, exempt or recent actual sign-in | Unknown/future/inconsistent dates or status, list-only evidence, a sign-in or creation later than the detail read's collection time plus 5 minutes (malformed), no recorded collection time |
| `workspace.never_signed_in` | low / account | Eligible active account; fresh detail has exact epoch never marker and creation more than 30 calendar days before the detail read's collection time | Actual sign-in, creation at most 30 days ago, suspended, archived or exempt | Unknown creation/login or list-only evidence, a creation or sign-in later than the detail read's collection time plus 5 minutes (malformed), no recorded collection time |
| `workspace.suspended_admin_assignment` | medium / account | Suspended account retains super flag or supported privileged direct/indirect assignment | Complete admin metadata proves no assignment | Unknown suspension or partial/uninterpreted roles |
| `workspace.two_step_not_enforced` | high / org_unit | A known-active account in the unit explicitly has `isEnforcedIn2Sv:false`; fire wins inside a unit, "at least" with unknowns or a partial population | Complete users population, unit found exactly once in the unit tree, every account's activity known, every active account explicitly `true`, no conflicts | Otherwise; units with only inactive accounts or none produce no judgment; no active account at all gives one asset-level abstention |
| `workspace.admin_without_two_step` | high / account | Known-active super admin or supported privileged delegate explicitly has `isEnrolledIn2Sv:false`, enforced or not | Explicit enrollment `true`, known inactive, or admin status known false | Unknown admin status, enrollment, activity, or a conflict |
| `workspace.oauth_broad_scope` | medium / oauth_app, `+1 attribute:admin_grantor` when a known-active super admin's or declared break-glass account's own grant is broad | A known-active grantor's grant to the app holds a supported broad scope | On a complete grant population, the app holds only recognized sign-in scopes, or access beyond sign-in only through suspended or archived accounts | Broad only through accounts of unknown status, only unclassified scopes, or a partial population; asset-level outcomes in "OAuth grants" |
| `workspace.external_forwarding` | medium / mail_forward, `+1 attribute:admin` when the mailbox is a known-active super admin's | A read mailbox has enabled auto-forwarding, or a filter that forwards, to an address outside the verified domains | Per mailbox, both reads usable and whole, and every forward goes to a verified domain or none exists; outcomes in "Forwarding interpretation" | A read that failed, was cut or was not recognized; an unplaceable destination; unknown mailbox activity; a subdomain of a verified domain |

A fired `identity.former_person_has_access` names what was not read for that account
(E9 step 7; [engagement.md](engagement.md), "Plan selection and follow-ups", on F2, which
is not a follow-up row: the account's tier-1 reads are the answer). When the account's
OAuth grants were not read, Not checked gains "Third-party app grants of *address* were
not read: *reason*", and when its mail forwarding was not read, "Mail forwarding from
*address* was not read: *reason*". The reasons:

| Read | Reasons, in the order they are tried |
|---|---|
| OAuth grants | the profile is not selected: "the optional OAuth grants profile is not selected (`directory_oauth`)"; the account has no grants entry: "the run stopped first (*phrase*)"; its entry is not usable: "the read failed: *phrase*" |
| Forwarding | the mailbox's forwarding was read and usable: no line; the tenant has no `authorization.mailboxes` entry for it: "`authorization.mailboxes` does not name this mailbox"; its entry is not current: "`authorization.mailboxes` is not current"; the profile does not select forwarding: no line, since the profile's own coverage line says it; the mailbox was never asked: "the run stopped first (*phrase*)"; otherwise "the read failed: *phrase*" |

On a Workspace account the finding's remediation (`finding.RemediationFormerPersonWorkspace`,
used by the report) is: "Suspend the account now. Before deleting it, revoke its
third-party app tokens and remove any forwarding or delegation; deleting the account does
not tell you where its mail went." A raise for a left person's forwarding mailbox on
`workspace.external_forwarding` is deferred to the next severity-table change.

Admin counts follow [engagement.md](engagement.md), "Admins": exclude declared service
accounts and at most two break-glass accounts from the numerator; shared and
unattributed accounts count. Active users less service and break-glass accounts form
the denominator. No ratio is computed on partial populations. Inactivity exemptions
apply only to `service` and `break_glass`; no inactivity rule infers departure.
Ambiguous or partial attribution that could exempt an account as `service` or
`break_glass` leaves its count exemption and inactivity eligibility unknown. A zero
denominator never produces an administrator ratio.

### Dates and fresh evidence

All dates use one assessment instant in `engagement.timezone`, with strict 90/30-day
boundaries, subtracting calendar days in that timezone rather than fixed-hour
durations. Login times and creation times require valid RFC3339 timestamps; the
never-login marker is exactly `1970-01-01T00:00:00.000Z`. Future values, an actual
login before creation, or conflicting list/detail security values are unknown.
Valid list/detail creation times must agree. A fresh valid actual sign-in timestamp
earlier than the list's valid actual sign-in is contradictory, not fresh evidence of
inactivity. An actual list sign-in followed by the exact never-login marker in
fresh detail is also a conflict; a never-login marker followed by an actual sign-in
is usable new evidence. Missing detail flags alone never imply that a list flag changed.
The collector receives the assessment instant explicitly; rules do not independently
read the clock. New and break-glass admins are not exempt from enrollment findings.

### Observed 2-step verification

Directory flags establish current per-account enforcement and enrollment, not unit
policy, grace periods, configuration groups, IdP/SSO controls (only the operator's
`sign_in` declaration speaks to them), methods or phishing
resistance. Unit findings list affected accounts and lower bounds; they say Google
reports accounts not currently required to use 2-step verification, never that the
unit's policy is disabled. Disproval says Google reports every active account
observed in the unit as currently required, never that the unit is fine.

**Units.** The enforcement rule groups accounts by each account's direct
`orgUnitPath`; no subtree inheritance is claimed. The subject key is the lowercased
path and the label the observed path. A path not in the unit tree fires under the
observed path with "unit not found in the unit list"; a path that matches more than
one unit when case is ignored may fire, gets a diagnostic note, and is never disproved.
Any population drop, including exclusion drops the gate accepts for admission,
prevents disproval anywhere ([scope.md](scope.md), "Responses"). No person kind is
exempt. Detail counts are `affected`, `not_enrolled`, `enrolled`,
`enrollment_unknown`, `active_observed`, `state_unknown` (unknown flags or activity)
and `population_complete`. The account names, not enrolled first, then enrolled, then
unknown, alphabetical within each, are the judgment's listed subjects, which the
report stores as `affected.listed` ([report.md](report.md), the `affected` field).
The excerpt names them, capped at 20 with a pointer to the JSON report, because the
text renderer does not print `affected`; it explains an "at least" count by the
unknown accounts or the partial population.

**Admins.** The admin rule uses the step-3 administrative interpretation and its
privilege table. The excerpt names the privilege, or "super administrator (isAdmin:
true)". An admin Google requires but reports unenrolled still fires, with the clause
"Google requires 2-step verification for this account but reports it not yet
enrolled; until it enrolls, a password alone may sign it in." This id never carries
`contradiction`.

**Flags.** List values are used first; fresh detail fills only a missing list value.
Fresh detail that disagrees with the list on either 2-step flag, carries a present
null or non-boolean 2-step flag, or was returned (HTTP 200) but refused or rejected
marks the account's 2-step state unknown (`AccountAccess.TwoStepUnknown`); only the
2-step rules abstain on it, the unit and admin abstentions cite that detail read
whether it was used or refused, and a note names the address and account id. A denied or
failed detail read falls back to the list. A step-3 security conflict also makes both
2-step rules unknown for that account. Known limit: a detail refused because the
account's unit changed leaves the account unknown in its list unit only.

**Declaration.** Engagement fills `Context.MFA` and `Context.MFASource` from the
tenant's `access.mfa` entry ([engagement.md](engagement.md), "2-step verification").
The collector decides the comparison once per unit, for rules and notes alike:

| `access.mfa` | Raises a fired unit |
|---|---|
| `everyone` | every fired unit; with `sign_in: another_provider`, only a fired unit whose affected accounts include a known super admin (`isAdmin:true`, no security conflict) |
| `admins` | a fired unit whose affected accounts include a known `isAdmin:true` account; delegates do not count |
| `some` | every fired unit, only when a complete population has every active account explicitly off; never with `sign_in: another_provider`, since every active account off is what a federated tenant looks like |
| `none`, `unknown`, undeclared | never |

`access.mfa[i].sign_in` (`google`, `another_provider`, `unknown`; absent is decided as
`unknown`; [engagement.md](engagement.md), "2-step verification") changes only the
`everyone` and `some` rows, as shown. Unknown administrator status and delegated admins
do not keep an `everyone` raise under `another_provider`. Base severity, verdicts and
the other steps of the severity table are unchanged, and no "not applied" chain row is
written. A unit the comparison would have raised and `sign_in` stopped gets a "Not
checked" line (`stoppedLine`) saying so. Raised and stopped instances carry
`access.mfa[i]` as declared evidence, and `access.mfa[i].sign_in` too when it is present
and `enforced` is `everyone` or `some`. The stopped line also:

- names the affected super admins of the unit (possible only under `some`) as not
  protected by the provider, since they can still sign in with a Google password and
  Google's own requirement is their control;
- under `everyone` only, names the accounts that might be an affected super admin but
  could not be judged (unknown administrator status, activity or 2-step flags, or a
  security conflict; an account known not to be a super admin, or whose flags read as
  required, is left out), up to
  three then "and N more", and says one that is would rank the unit higher. Under
  `some` with `another_provider` nothing ranks higher, so the line claims no such
  consequence.

The Why of an `everyone` raise
under `another_provider` names up to three super admins, then "and N more".

A raised instance carries `contradiction`, cites the declaration, has a one-sentence
"Why here" naming the contradicting fact, and carries a caveat under "Not checked"
worded from `sign_in` (four wordings, `signInCaveat`):

| `sign_in` | The caveat says |
|---|---|
| absent | people who sign in through another identity provider that requires a second factor may make the raise inapplicable; scheck read neither that service nor Google's single sign-on settings; if they do, add `sign_in: another_provider` at `access.mfa[i]` and run scheck again |
| `unknown` | the operator answered that they do not know; the same possibility, for accounts other than super admins |
| `google` | the operator declared Google passwords; scheck did not read single sign-on settings to confirm it |
| `another_provider` | the raise ranks higher only because of the super admins in the unit, who can still sign in to Google with a Google password; for the other accounts a second factor at that provider may be the control |

`workspace.admin_without_two_step` is unchanged in verdict and severity and never
carries `contradiction`; under `another_provider` it gains a "Not checked" line on
delegated (non-super) admins, who may sign in through the provider. Workspace
enrollment alone never establishes an enforcement contradiction, even when the
admin-without-two-step finding fires.

**Pre-release live check (open).** Whether Google's own mandatory 2-step verification
for super admins shows in `isEnforcedIn2Sv`. If it does not, a super admin raise under
`another_provider` could be false. Recorded for the acceptance run
([ROADMAP.md](../ROADMAP.md), E6 "Carried from step 4"); not decided here.

**0.0.3 contract.** When the Cloud Identity SSO profile read lands, it takes precedence
over `sign_in`: a unit observed with no SSO profile re-raises whatever `sign_in` says.

**Readout notes.** The collector owns them (`workspace.Readout`):

- the limits note, whenever the users read was usable;
- a per-account flag-conflict note naming the address and account id;
- an ambiguous-unit note asking for one unit to be renamed;
- an unjudged-units note listing abstained units and ending "Treat these units as not
  checked, not as fine.";
- an incomplete-population note: no unit could be shown to require 2-step verification
  for every account;
- a possible-grace note for active, enforced, unenrolled non-admins: they are within an
  enrollment period, when a password alone signs them in, or locked out until they
  enroll, and scheck cannot read which; no grace window is inferred;
- a note for unenrolled accounts whose admin status is unknown;
- with no declaration or `unknown`, what scheck read in counts, and for no declaration
  "declare it under access.mfa in the engagement file"; a partial population with no
  observed account off says no observed active account was reported without the
  requirement but the list of users was incomplete, never "at least 0";
- with `none`, a note when Google requires more than declared;
- with `everyone`, `some` or `admins`, a matching note only on a complete population
  with no unknowns, each adding "Required is not the same as enrolled";
- with `sign_in: another_provider`, a note (`signInNote`) that the declaration was used and the provider
  was not read, how many active accounts Google does not require 2-step verification
  for ("at least" on a partial population), that whether the provider requires a second
  factor is not assessed, and how many super admins Google requires it for ("K of the S
  observed" on an incomplete user list, "K of S of them" on a complete one); for super
  admins whose requirement could not be read it adds "For N super administrator(s) the
  requirement could not be read.", for super admins of unknown activity "The
  activity of N super administrator(s) was unknown.", and for accounts whose
  administrator status is missing or in conflict "The administrative status of N
  account(s) was unknown."

Counts in notes say "at least" on a partial population. Remediation reviews current
flags and console policy/grace settings, and enrolls admins using hardware keys where
appropriate.

### OAuth grants

The rule is `workspace.oauth_broad_scope`: identity area, category
`third-party-apps`, not an exposure, subject `oauth_app` keyed by the exact client id,
base medium for every broad scope (read or change is said in the excerpt). Grants
aggregate once per client id across the tenant; the collector classifies each app once
(`oauthView`) and the rule and readout notes both read that. A grantor is known active,
known inactive (suspended or archived) or unknown (unknown status or a conflicting
fresh detail). Per app, the first matching row decides:

| Outcome | When | Judgment |
|---|---|---|
| Broad | a known-active grantor's own grant holds a supported broad scope | fires; `affected` lists those grantors, admin grantors first, with each super-admin or break-glass grantor also under `affected.of_note` |
| Status unknown | broad only through grantors of unknown status | abstains |
| Unclassified | no broad scope, and some active or unknown-status grant holds a scope outside the table, or Google reported it with none | abstains with `unavailable:oauth_unclassified` |
| Inactive only | beyond sign-in only through suspended or archived grantors | disproved on a complete population ("see the cleanup note"); abstains otherwise ("in the grants read") |
| Sign-in only | only recognized sign-in scopes | disproved on a complete population; abstains otherwise |

Suspended and archived grantors never make an app fire; they are listed as
`inactive_grantors` and in the cleanup note. A fired excerpt counts unknown-status
grantors that also granted broad access and names unclassified scopes the app also
holds. No grantor kind is exempt. `nativeApp` and `anonymous` are context in the
excerpt, never an outcome: an installed app may be Google's or Apple's own (Drive for
desktop, Mail), "where the risk is the device that holds the grant". Details are
scalars: `scopes_read`, `scopes_change`, `scopes_unknown` and `scopes_narrow`
space-separated; `admin_grantors`, `delegated_admin_grantors`, `inactive_grantors` and
`unknown_status_grantors` comma-separated, left out when empty; `native_app`,
`anonymous`, `assessment_client`, `population_complete`, `table_version`, `labels` (a
count, when Google reports more than one name) and, on a raise, `admin_grant_read`.

**Raise.** `+1 attribute:admin_grantor` applies only when a known-active super admin
(`isAdmin:true`, no conflict) or an account attributed to a declared `break_glass`
person granted the app a broad scope in its own grant. Delegated administrators never
raise; they are listed as `delegated_admin_grantors`. The raise cites that
administrator's own tokens read, and its "Why here" is "<account> is a super
administrator (or is declared as a break-glass account) and granted this app the
scope(s) <scopes>[, as did N other administrator accounts]: whoever controls the app
can use those scopes as <account>, though not that account's other administrator
rights." When one of those scopes is `admin.directory.*`, the clause ends "including
the administrator actions those scopes allow." The raise also applies to grants to the
assessment client that were not set aside.

**Asset-level outcomes.** When OAuth is selected, one judgment without a subject speaks
for the surface:

- no current account evidence: abstains;
- no account's grants usable: abstains with the gate's reason for the first failure
  (`insufficient_permission:admin.directory.user.security`, `limit_reached`) or
  `unavailable:workspace_evidence`;
- an incomplete grant population: always one abstention beside the per-app judgments,
  "App grants were read for N of M accounts." or, when every listed account was read,
  "App grants were read for every account listed, but the account list was incomplete.";
- a complete population with no app: disproved, "Google reports no third-party app
  grants for any of the N accounts read" (adding "other than the grant set aside as
  scheck's own credential" when one was).

Its details are `accounts_read`, `accounts`, `population_complete` and
`table_version`. An account whose read Google refused (403) is unread; the others are
judged, and coverage is partial. When the profile does not select OAuth there is no
judgment at all, and coverage says `not_on_plan:profile=<profile>` ("Reporting and
coverage").

**Readout notes** come from the same view:

- not selected: what the check finds (apps people allowed into their mail, Drive or
  calendar, a common way an attacker keeps access after a phishing email), that
  `admin.directory.user.security` comes only with the power to revoke app access, sign
  people out and turn off 2-step verification, that the checks above do not need it,
  and that a dedicated credential keeps the everyday one read-only; then the
  profile `offers` names, the one that adds this surface to the current profile,
  falling back to `directory_oauth`;
- the optional exchange refused: how an administrator grants the permission, its
  powers, a dedicated credential, and that nothing else in the run was affected; every
  account's read refused by Google: the administrator role the acting account needs;
- whenever a tokens read was sent or reused: a `workspace_credential_warning` that the
  separate token holds `admin.directory.user.security` and what that permission also
  allows, that scheck sent only declared reads, and where to remove the permission;
- when any grants were read: the limits note (checked, and not checked: domain-wide
  delegation, service-account keys, Marketplace installs for everyone, app passwords,
  when each app was authorized or last used, what any app did);
- the set-aside credential note;
- on an incomplete population: counts as lower bounds and the unread accounts, each
  with its reason (permission denied, limit, redacted, unreadable, not attempted),
  super admins marked; the delegated-administrator sentence only when an unread super
  admin was permission-denied;
- a note per malformed or dropped-item account, naming it;
- the cleanup note for suspended or archived accounts that still hold grants;
- the unclassified-apps note listing them with the Admin console path.

An app is always named by its client id. The name Google reports is chosen by whoever
registered the app: it is redacted, cut at 120 bytes on a character boundary and never
inside a redaction marker (`policy.CutLabel`, with `[TRUNCATED:<n> bytes]`), escaped
when printed, quoted beside the client id, and never keys, matches or exempts
anything. A fired excerpt with a name adds "The name is chosen by whoever registered
the app; it does not show who made it."

### OAuth scope interpretation

The exact table version is `2026-10-11`. Supported broad scopes have prefix
`https://www.googleapis.com/auth/`, except the full mail URI:

| Access | Scopes |
|---|---|
| can read | `drive.readonly`, `gmail.readonly` |
| can change | `drive`, `gmail.modify`, `admin.directory.user`, `admin.directory.user.security`, `admin.directory.rolemanagement`, `cloud-platform`, `https://mail.google.com/`, `gmail.settings.basic`, `gmail.settings.sharing`, `gmail.send`, `gmail.compose`, `gmail.insert` |

The only recognized
narrow scopes are `openid`, `email`, `profile`,
`https://www.googleapis.com/auth/userinfo.email` and
`https://www.googleapis.com/auth/userinfo.profile`. A broad scope plus unknown scopes
can fire on the known broad scope; unknown-only abstains. Unknown is never narrow.
Grants aggregate once per client id across the tenant, with scope union and grantor
ids; partial populations retain lower bounds. Display names prove neither publisher
identity, declared-tool matching nor approval. Changing either table changes its
version.

scheck's own grant is set aside only by elimination. After a successful
client-authenticated `authorized_user` refresh, the file's `client_id` is the proven
assessment client (`assessment_client`, "Tenant binding and scope"). A grant to it is a
candidate when its scopes include `admin.directory.user.security`. When the grant
population is complete (the users population whole with no drops, every admitted
account's grants read and recognized) and exactly one candidate exists, that grant is
set aside: it is not judged, and an unranked credential note names the account, the
client id and its scopes. Other grants to that client are judged normally. Otherwise
nothing is set aside: a fired excerpt leads with "scheck authenticated with this
client id; one of these grants may be the credential this run used.", and "Not
checked" says "scheck cannot tell whose sign-in its credential file holds, so none of
these grants was set aside as its own." A service-account client id is never set
aside: its JWT exchange proves the issuer assertion, not that local field. Display
names never select it. Unknown clients remain target OAuth applications rather than
guessed assessment identities.

### Forwarding interpretation

The rule is `workspace.external_forwarding`: email area, category `email`, not an
exposure, subject `mail_forward`, base medium. The subject key is `<account primary> ->
<destination address>`, both lowercased, one instance per outside destination of one
mailbox with automatic forwarding and filters merged; the full address is printed
everywhere. A mailbox with no outside destination has its outcome under the key
`<account primary> -> none`, labeled "<account> (mailbox)". The finding is not raised
by `data.matters_most`: that declaration reaches no email-area finding in 0.0.2
([engagement.md](engagement.md), "Severity in context"). Filter configuration shows a
forwarding rule, not that any message was forwarded; scheck says "read the setting, not
whether any message was forwarded".

**Read set.** A mailbox is read only when its account is known active (not suspended,
not archived, no conflicting fresh detail) and not reported `isMailboxSetup:false`; a
delegated administrator is read. Suspended, archived and mailbox-less accounts are not
read, get no judgment, and are counted in the readout. An account whose activity is
unknown or conflicting is not read and abstains under its mailbox key with
`unavailable:workspace_evidence`.

**Internal set.** A destination is internal when its domain equals, exactly, a
verified domain or a verified domain alias of the tenant. The set is complete only when
both lists were read whole. Suffix matching, trusted subdomains and the engagement's
domain roots never make a destination internal; when the destination's domain is a
declared root, the excerpt says it is declared in this engagement but is not a domain of
this Workspace. When the set is incomplete, a destination inside the known set is
internal and any other abstains with `unavailable:workspace_inventory`. A destination
under a verified domain that is not itself verified abstains with
`unavailable:forwarding_subdomain` and a readout note asking whoever runs mail for that
name where it goes: Google's own "internal addresses only" setting may count such names
internal, which is not measured.

**Parse.** An address has one `@`, a nonempty local part with no control or space
character, and a DNS-valid domain (at least two labels of letters, digits and hyphens,
at most 253 bytes; a trailing dot is removed and the domain lowercased). An empty,
malformed, non-string or redaction-marked address is unknown. In a filter, an absent
`action.forward` is a filter that does not forward; a present but empty or non-string
one makes that filter malformed, and the mailbox's filters incomplete. For automatic
forwarding, an absent `enabled` is unknown (Google is not yet measured to omit it for
off), a non-boolean or null one is malformed, and `enabled:true` with an unparseable
address is a gap.

| Outcome | When |
|---|---|
| Fires, per mailbox and outside destination | `enabled:true` to an outside address, or a filter that forwards to one. Fire wins even when the other read failed or was cut |
| Disproved, under `-> none` | both reads usable and within the cap, no malformed item, automatic forwarding off or every destination internal, every forwarding filter internal. A mailbox with an internal destination needs the complete domain set; one with forwarding off and no forwarding filter is disproved even when the domain list was cut, since the list only places destinations. Only an explicit `enabled:false` disproves |
| Abstains, per mailbox | a read that failed, was cut, held an unrecognized shape, or a destination scheck cannot place |
| Abstains, per destination | a subdomain of a verified domain, or a destination while the domain set is incomplete |

A saved but disabled automatic-forwarding address does not fire. When it is outside the
domains, or unplaceable, the disproved outcome records it as `saved_external` and the
readout says one switch turns it back on.

**Asset-level outcome.** When the surface is selected, one judgment without a subject
speaks for it: no current account evidence abstains; so does having no active mailbox, saying so; when no
mailbox's settings could be read whole it abstains with the reason of the read that
stopped collection, else the first failed read; when some were not read whole it
abstains with "Forwarding settings were read for N of M active mailboxes." or, when every
listed mailbox was read, "…for every active mailbox listed, but the account list was
incomplete." With every readable mailbox read whole on a complete list, the mailbox
outcomes speak alone. When the surface was refused before any settings read was usable,
only this judgment is emitted and no mailbox is named. Its details are `mailboxes_read`,
`mailboxes` and `population_complete`. When the profile does not select the surface
there is no judgment, and coverage says `not_on_plan:profile=<profile>` ("Reporting and
coverage").

**Details.** A fired instance carries `mechanisms` (`auto`, `filter`),
`filters_forwarding`, `filters_read` (only when the filters were read), `auto_forward`,
`destination_domain`, `domains_complete`, `population_complete`, `disposition` (only for
automatic forwarding), `hides_mail`, `delegated_admin` when the account is a delegated
administrator, `admin_mailbox_read` on a raise and `filter_ids` (JSON only). `hides_mail`
is true when automatic forwarding is set to move the original to Trash, or a forwarding
filter adds the Trash label or removes the Inbox label; the excerpt then says it is "a
pattern used to hide forwarded mail from the person, though some tools are set up this
way". Whether `hides_mail` raises or ranks is not decided (E9).

**Raise.** `+1 attribute:admin` applies only to a known-active super administrator's
mailbox (`isAdmin:true`, no conflict), citing that mailbox's own read, with "Why here":
mail sent to administrators, such as security alerts and password-reset links from other
services, goes to that mailbox. A delegated administrator never raises and is marked in
the details. An account belonging to a declared leaver whose date has passed gets an
excerpt cross-reference to that person and no further raise.

**Readout notes** come from the same view as the rule. A note about a departed person still observed uses the rule's clock and gating, is dated by the read that observed them, and is never emitted unless the left date had passed at that read (`engagement.md`, "Severity in context", "Time"):

- not selected: what the check finds, that it needs a service account with domain-wide
  delegation for `gmail.readonly`, which can read every message and which most small
  companies lack (whoever manages the Google setup creates it), and that scheck signs
  in as each active mailbox and reads only forwarding settings and filters. The ending
  depends on the entry. No entry: whoever approves access to staff mailboxes must
  approve it and add `authorization.mailboxes` (asset, by, date, expires) to the
  engagement file first, then run with that service account's key and
  `SCHECK_WORKSPACE_PROFILE=` the profile `offers` names. A current entry: the file
  already records a current approval to sign in as mailboxes, then the same run-with
  sentence, and it does not say to approve first. An entry that exists and is not
  current: the approval is not current, so scheck will not sign in as mailboxes until
  it is renewed or its date arrives, then the same run-with sentence. That sentence
  does not say the approval is already recorded;
- authorization missing (profile selects the surface; no entry for this asset, or only
  an entry for another asset): "Mail forwarding not checked: SCHECK_WORKSPACE_PROFILE
  (set in your environment) asks scheck to sign in as each mailbox, but the engagement
  file records no approval for <asset>. No mailbox was signed in as. Have whoever
  approves access to staff mailboxes approve it, add `authorization.mailboxes` (asset,
  by, date, expires), and run again."
- authorization expired (profile selects, entry exists but `expires` has passed):
  "Mail forwarding not checked: the approval by \"<by>\" ended on <expires>. No mailbox
  was signed in as. Renew the approval and update expires to check it."
- authorization not yet current: "Mail forwarding not checked: the approval by \"<by>\"
  starts on <date>. No mailbox was signed in as. Wait until that date, or update the
  approval, and run again."
- authorization expired during the run (some mailboxes were signed in as before
  `expires` was reached in the current session): "Mail forwarding checked for <N> of
  <M> active mailboxes: the approval ended on <expires> during the run, so scheck
  stopped signing in as mailboxes. Check the other <M−N> by hand or renew the approval
  and run again."
- the surface refused (`needs_service_account`, the permission not granted, every mailbox
  refused by administrator policy, the Gmail API not enabled, the breaker): one sentence of what happened, a next
  step, and that nothing is wrong with the mail settings and nothing else in the run was
  affected. Policy refusals are worded as API controls or per-unit policy, never as a
  missing scope. The breaker note says scheck stopped after N mailboxes; one `refusal`
  decides the coverage gap and the note alike;
- whenever scheck asked Google to act as a mailbox, a `workspace_credential_warning`:
  "No message was opened or read.", "scheck asked Google to sign it in as each of N
  mailboxes" (N counts mailboxes asked, by the reads' `ActedAsMailbox`, not reads that
  were sent or reused), that the permission could read every message and Google's logs
  may show the service account acting as each person, that it stays until an
  administrator removes it, and where. When an entry for the asset is on the
  collector's context, the warning adds that this was under the approval recorded by
  "<by>" on <date>, and that scheck did not verify that approval;
- the limits note: read whole for N of M active mailboxes (lower bound on an incomplete
  list), the unread ones with a reason (permission denied, limit, redacted, unreadable,
  status unknown, Google did not sign in as or serve the mailbox; super administrators
  marked) and to check them by hand, those not attempted (suspended, archived, without a
  mailbox), the list's own incompleteness, and what was not checked: any message
  forwarded, what each filter matches, the Admin console's forwarding setting, routing
  and compliance rules, mail delegates, POP/IMAP, send-as addresses, where mail goes
  next, and suspended or archived mailboxes;
- a note per saved-but-off address;
- one note listing subdomain destinations not judged.

## Reporting and coverage

The collector owns `workspace.Context`, people attribution and operation-specific
notes. Step 3 extends that view with declared person kinds, `left` and `used_by`,
addresses, an explicit expected-admin-list presence flag and its values, and one
assessment instant and timezone. Engagement fills these declarations; it does not
sequence role reads or interpret Directory fields. One `workspace.Collect` call
sequences binding and inventory and returns evidence, notes, an `InventoryComplete`
summary and shared judgments. Step 2 returns no posture judgments. Engagement
owns report rendering, ranking, context and acceptances.
Step 3 returns nine identity/admin rule outcomes. Its `AdministrationComplete`
summary keeps coverage partial when roles or per-user assignments are unavailable
or their administrative interpretation is unknown, even if observed false user
flags settled individual rules. Collector-owned `InterpretationGaps` notes identify
unknown roles, privileges, conditions or expiry. Step 4 adds `Context.MFA` and
`Context.MFASource`, two 2-step rule outcomes and the 2-step readout notes. Step 5
adds `OAuthEvidence`, the OAuth rule outcomes and readout notes. Step 6 adds
`MailEvidence`, the forwarding rule outcomes and readout notes. The collector words the asset's outcome: `Evidence.Outcome()` says
whether collection completed, with the status sentence (naming OAuth when selected),
and the engagement records it as `collected` or `incomplete` with the outcome's
reason, `failed` when it names none. Any `limit_reached` read, an OAuth grants or Gmail read or an optional exchange's rate
limit included, makes the Workspace asset incomplete, exit 2; a refused optional
permission, `needs_service_account`, a disabled Gmail API and a tripped breaker are
coverage gaps only; a mailbox exchange refused before it left this machine for a limit is
`limit_reached`. A mixed
GitHub/Workspace identity row cannot claim complete assessment from GitHub judgments
alone. Inventory notes show lower bounds,
permission failures, credential uncertainty and fresh delegated verification.
Primary-address attribution is usable on observed records; alias-only attribution
requires a complete population. Each declared address is matched independently, so
one person may own multiple current accounts. Competing people for one current
account leave its attribution unknown. Display names never establish identity.
Unexpected-admin judgments cite both `access.admins` and the matched person's
Workspace-address declaration when their identity supplies the conclusion.

Identity and access coverage contains decided administrative sub-items, the
"Workspace 2-step verification (Google's enforcement and enrollment flags)" sub-item
over both 2-step ids, the "Workspace OAuth grants (third-party app access)" sub-item
over `workspace.oauth_broad_scope`, and a "Workspace domain-wide delegation" sub-item
that is always *not assessed* with `no_rule`, its detail saying nothing was read
because Google offers no Directory read for it, the Admin console path below, and that
with a service-account credential scheck's own delegation is listed there. The
forwarding sub-item is in email coverage (below). The collector words these sub-items as one
identity-area coverage plan, `Evidence.Coverage()`: each group's name and rule ids,
limits, empty, gap, not-on-plan and collapse wording, the delegation sub-item and the
row's closing words. The engagement report marks the plan by the rules in
[report.md](report.md), "Coverage", and composes the row's reason. Incomplete
administrative evidence is the assignments group's `unavailable:workspace_evidence`
gap. Every collector rule id belongs to exactly one sub-item, which a collector test
enforces.

The 2-step sub-item always carries a `no_rule` detail stating its limits
(organizational-unit policy, grace periods, another identity provider, methods and
phishing resistance not checked), whatever its mark. With `sign_in: another_provider` the
limit adds that the declared provider was not read, so for those people Google's flags show
only that Google does not require its own 2-step verification. With no 2-step outcome it is
*not assessed* with `unavailable:workspace_evidence`, never `not_applicable`: unlike
the general `not_applicable` rule in [report.md](report.md), "Coverage", every read account is judged for 2-step verification, so no outcome
means none was recorded. An abstained judgment's reason
detail is its subject and first "Not checked" line. E9 owns global coverage; no new
global area is introduced.

The OAuth sub-item is flagged the same way: on the plan it always carries a `no_rule`
limits detail, the same sentence as the OAuth readout note, and with neither an OAuth
outcome nor a not-on-plan entry (a failed binding, for instance) it is *not assessed*
with `unavailable:workspace_evidence`, "No OAuth grant outcome was recorded for this
tenant". When a bound tenant's profile does not select OAuth, the plan marks the
group not on plan, and the sub-item is *not assessed* with only
`not_on_plan:profile=<profile>` and the collector's detail ("The default Workspace
profile, directory, does not read third-party app access; it needs
SCHECK_WORKSPACE_PROFILE=directory_oauth and the admin.directory.user.security
permission"; another profile is named as "The selected
Workspace profile, <p>,"). `unavailable:oauth_unclassified` abstentions collapse to one
detail line, "N apps hold scopes scheck does not classify and none it classifies as
broad; listed in the JSON report and the readout"; the JSON keeps one abstention per app. The row's `no_rule`
reason names the groups nothing decided: "Workspace OAuth grants and domain-wide
delegation remain unassessed" or "Workspace domain-wide delegation remains
unassessed", then the 2-step limits; a group not on the plan is not called unassessed.

**Email coverage.** `Evidence.Coverage()` returns a second plan, for the email area,
with one group, "Workspace mail forwarding", over `workspace.external_forwarding`, always
carrying the limits detail of the limits note as a `no_rule` reason. With the profile not
selecting the surface the group is not on the plan:
`not_on_plan:profile=<profile>`, with the detail "The default Workspace profile,
directory, does not read mail forwarding; it needs SCHECK_WORKSPACE_PROFILE=<profile
offered> and a service account whose domain-wide delegation includes gmail.readonly,
which can read every message" (another profile is named "The selected Workspace profile,
<p>,"). When selected, the plan's closing words are "the Admin console's forwarding
setting, mail delegates and POP/IMAP were not assessed". The surface's refusal is the
group's gap, decided once for the gap and the readout note: `needs_service_account` and
`insufficient_permission:gmail.readonly` name what is missing, and a tripped breaker is
`unavailable:credential_exchange`. The group is *partial* when some mailboxes abstained.
With neither an outcome nor a gap it is *not assessed* with
`unavailable:workspace_evidence`, "No mail forwarding outcome was recorded for this
tenant". How the report marks the row, and what a Workspace-only engagement's email row
says beside it, is in [report.md](report.md), "Coverage".

Readouts include supported roles and scope limits, alias-matched recon candidates,
declared expected admins not observed, shared-account leaver rotation, and break-glass
recovery/sign-in notes under the existing engagement contract. Remediations identify
unknown admins, narrow roles, review offboarding sessions and grants, remove residual
assignments, and remove or justify broad OAuth grants. Retained suspended roles are
not described as currently usable access.

Domain-wide delegation inventory is not assessed: Directory provides no inventory
read. The report points to **Security → Access and data control → API controls →
Manage Domain Wide Delegation** in the Admin console. One successful delegated read
proves only that operation. Organizational-unit 2-step policy, grace periods and
authentication strength remain unassessed. Missing optional OAuth/Gmail evidence names the selection or permission
gap, never a clean result. Gmail coverage never covers the Admin console's automatic
forwarding setting, mail delegation, POP/IMAP, send-as addresses, routing and compliance
rules, or the Cloud Identity Policy API read of those settings (a 0.0.3 priority). OAuth grants never cover domain-wide delegation, Marketplace
installs for the whole domain, app access control settings, app passwords, token age
or last use, service-account keys, or what an app did with its access.

### Client-facing wording

A unit heading groups affected accounts; it does not identify a unit policy failure.
Each fired enforcement instance leads with plain evidence, the count and the unit,
before flag names, gives the enrollment breakdown, names the accounts, then says: "For
these accounts, Google reports that 2-step verification is not currently enforced.
Enrollment, counted above, is a separate flag: a user who enrolled can still turn it
off while Google does not require it. scheck did not assess organizational-unit
policy, grace periods or protection provided by another sign-in service. Review these
accounts and the current Admin console settings yourself, or with whoever administers
your Workspace."

A suspended assignment says: "Ask your administrator whether this assignment is still
needed, and remove it if not." It does not imply that suspension left normal sign-in
usable. Optional OAuth wording explains that baseline Directory checks work without
the security permission, what that permission also allows, and that an administrator
can approve a dedicated credential if the organization wants the app check ("OAuth
grants", readout notes). Optional forwarding wording
(the finding, its remediation and the notes in "Forwarding interpretation") says what
scheck read, that it read settings and filter forwarding destinations and never a
message, that nothing is wrong with the settings when the check could not run, and, for
a fired instance, the owner-facing next step: ask the person in person or by phone,
accept an address that is set up on purpose, contain a mailbox nobody set up forwarding
for before removing it. A refused or unavailable check asks for approved access, never
more.

Execution diagnostics use plain words: the selected credential file could not be
read, the Workspace customer could not be verified, or authentication expired. They
do not present internal terms such as ADC, binding, bootstrap or gate as operator
actions. Where a session must be replaced, the wording directs the operator to
restart or resume with the intended profile and account. This wording is prepared
for Workspace runs. A successful read is not itself an account-security assessment.
Whole-slice client report review remains step 7 work.

The credential warning says observed grants permit operations beyond reads, scheck
sent only declared reads, effective access was not tested, and an administrator should
review a dedicated assessment credential. Unknown capability is explicit. Counts
say "at least N observed" when incomplete, and no-findings wording never describes
unassessed surfaces as secure.

The OAuth finding's title is "A third-party app holds broad access to Workspace data".
Its impact: "Whoever controls this app (its maker, or anyone who breaches the maker)
can use the access listed as the accounts that granted it, without their password or
second factor, until the grant is removed." A fired excerpt names the app, says what
it "can read" and "can change" in shortened scope names, and lists the active
grantors, marking a super administrator or declared break-glass account, "at least"
on a partial population; an `admin.directory.*` scope adds "Its admin.directory access
depends on the granting account's administrative rights." The remediation asks someone
to confirm the app was chosen and is still needed, names where an administrator blocks
it (Security → Access and data control → API controls → Manage Third-Party App Access)
and where each person removes it (`myaccount.google.com/permissions`), and explains
the console settings: "Trusted widens what the app may reach; it does not limit it,
and this finding stays open either way." It prefers a version that asks for less and
says to accept the app by its client id. The raise wording never implies Admin console
power beyond the granted scopes. The optional-token warning says: "The separate token
scheck used for the app check holds admin.directory.user.security, which also lets it
revoke app access and app passwords, read or create backup codes, sign people out and
turn off 2-step verification. scheck sent only the declared reads; effective access was
not tested. If you will not run the app check again, remove that permission from the
credential's domain-wide delegation entry or consent."

## Verification and evaluation

Fake Google API servers test firing, disproved and abstained outcomes for every rule;
false versus missing booleans; partial populations; aliases and future leavers;
timezone 90/30-day boundaries; fresh detail; service/break-glass exemptions; indirect
roles and unknown privileges; empty pages with next tokens; scope tables; and disabled
or filter-only forwarding. Gate tests prove foreign-customer and excluded-user/unit
requests never send, token exchange is confined to the literal endpoint, unknown or
changed principals reuse nothing, and secret/assertion/token/code/content bytes never
reach report, audit or persisted state. Seeded secrets are asserted absent and their
redaction markers present.

No SEED or RANK work runs in an implementation session or its subagents. E3's rest-lab
seal deadline before the first E5/E6 commit was missed. A new independent authorized
E6 evaluation sealed before code cannot retroactively satisfy or waive that deadline.
Implementers do not read its labels. Clean/context/missing-credential and full-scope
audit runs name the independent reviewer before any metrics claim. No software test
claims release acceptance or rewrites a historical evaluation record.

See [ROADMAP.md](../ROADMAP.md#e6--google-workspace-collector), steps 0–7. Each build
step receives the consultant, client, spec and adversarial reviews required by
`AGENTS.md`; optional surfaces do not block baseline Directory collection. Targeted
DEFINE authentication review for step 1 froze the file, assertion, exchange and
private-bootstrap details above. The targeted step-3 identity parser DEFINE contract
is recorded in [e6-identity-definition-2026-10-10.md](../eval/e6-identity-definition-2026-10-10.md).
Step 3 is complete offline; checks, review corrections and a fresh follow-up review
are recorded in [e6-identity-verification-2026-10-10.md](../eval/e6-identity-verification-2026-10-10.md).
The step-4 2-step DEFINE contract is recorded in
[e6-two-step-definition-2026-10-11.md](../eval/e6-two-step-definition-2026-10-11.md),
and its implementation and reviews in
[e6-two-step-verification-2026-10-11.md](../eval/e6-two-step-verification-2026-10-11.md).
Its tests cover unit grouping and listed order, partial and unknown evidence,
abstentions, inactive accounts, admin outcomes, the declaration comparison, notes,
fresh-detail flag evidence through a fake server, and one run through the gate to the
report with pinned `workspace-two-step` goldens.
The step-5 OAuth DEFINE contract is recorded in
[e6-oauth-definition-2026-10-11.md](../eval/e6-oauth-definition-2026-10-11.md), and its
implementation and reviews in
[e6-oauth-verification-2026-10-11.md](../eval/e6-oauth-verification-2026-10-11.md). Its
tests cover every app outcome, the raise and its exclusions, set-aside by elimination,
asset-level outcomes, malformed and foreign grants, read order and stopping on
`Repeats`; through a fake server, the optional token's one scope, expiry, remembered
failure, profile and principal gates, per-account denial and the registry's pinned
shape; one run through the gate to the report with pinned `workspace-oauth` goldens;
and `policy.CutLabel`. Collector tests hold every rule id in exactly one coverage
group, the plan's gap, collapse and limits wording, and what `Evidence.Outcome()`
names when collection was cut.
The step-6 forwarding DEFINE contract is recorded in
[e6-forwarding-definition-2026-10-11.md](../eval/e6-forwarding-definition-2026-10-11.md),
and its implementation and reviews in
[e6-forwarding-verification-2026-10-11.md](../eval/e6-forwarding-verification-2026-10-11.md).
Its tests cover every destination class and outcome, the read set, merge of automatic
forwarding and filters, the parse, `hides_mail`, the raise and its exclusions, asset-level
outcomes and the notes; through a fake server, the mailbox surface's admission (profile,
service account, principal, inventory, exclusions, verified domain, inactive account),
its token cache and expiry, the breaker, the 1,000 cap, each failure's scope, the pinned
registrations and the widening test (no other path under `/gmail/`), projection before
redaction and that no address, assertion or body reaches the audit log; and the
coverage plan. Pinned goldens: `workspace-mail`, `workspace-mail-refused`,
`workspace-mail-service-account`, `workspace-mail-breaker` and `workspace-mail-with-domain`
(a mixed engagement with a domain root, whose email row reads both).
Attributed live measurements of one authorized tenant, and the statement that
they are not acceptance, are in
[e6-closing-review-2026-10-12.md](../eval/e6-closing-review-2026-10-12.md).
The assumptions that record leaves unmeasured stay unmeasured. No independent
acceptance is claimed.

## Provider references

Primary sources checked by the DEFINE review on 2026-10-10:

- [Directory users](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users) and [manage users](https://developers.google.com/workspace/admin/directory/v1/guides/manage-users)
- [Directory authorization](https://developers.google.com/workspace/admin/directory/v1/guides/authorizing)
- [Customers](https://developers.google.com/workspace/admin/directory/reference/rest/v1/customers/get), [domains](https://developers.google.com/workspace/admin/directory/reference/rest/v1/domains/list) and [domain aliases](https://developers.google.com/workspace/admin/directory/reference/rest/v1/domainAliases/list)
- [Role assignments](https://developers.google.com/workspace/admin/directory/reference/rest/v1/roleAssignments/list) and [manage roles](https://developers.google.com/workspace/admin/directory/v1/guides/manage-roles)
- [OAuth tokens metadata](https://developers.google.com/workspace/admin/directory/reference/rest/v1/tokens/list)
- [Auto-forwarding](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.settings/getAutoForwarding) and [filters](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.settings.filters/list)
- [Service-account authorization](https://developers.google.com/identity/protocols/oauth2/service-account) and [ADC](https://docs.cloud.google.com/docs/authentication/application-default-credentials)
- [2-step verification deployment](https://support.google.com/a/answer/9176657)
