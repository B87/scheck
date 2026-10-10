# scheck — Google Workspace collector specification

Google Workspace assessment planned for 0.0.2 E6. The security-consultant DEFINE
review froze this design on 2026-10-10. Steps 1 and 2 implement credentials, tenant
binding and inventory through engagement Recon and report integration. Step 3
implements identity and administrator rules, with offline checks and reviews
completed on 2026-10-10. Step 4 implements observed 2-step verification offline on
2026-10-11. Optional OAuth/Gmail reads remain planned. No live measurement or release
gate is claimed here.

The gate owns admission, sending, credentials, redaction and persistence
([scope.md](scope.md#the-scope-gate)). Engagement supplies people declarations, admin
thresholds and severity adjustments ([engagement.md](engagement.md), "People",
"Admins", "Severity in context"). Engagement remains the only report author;
[report.md](report.md) and [runs.md](runs.md) govern report and resume behavior.

## Boundary

Every target operation is a compiled `GET` through the gate. The only `POST` is the
separately declared, budgeted credential exchange at the literal endpoint
`https://oauth2.googleapis.com/token`. Its secret body and response never enter
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
provider or impersonation ADC is supported. No target writes, mailbox or message
reads, backup verification code reads, or automatic delegation setup are admitted.
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
requires a fresh ordered bootstrap before a later tenant read.

`SCHECK_WORKSPACE_PROFILE` selects one compiled read profile:

| Profile | Reads selected |
|---|---|
| `directory` (default) | Baseline Directory inventory and identity |
| `directory_oauth` | Directory plus per-user OAuth grant metadata |
| `directory_mail` | Directory plus per-user Gmail forwarding settings |
| `directory_oauth_mail` | All three selected surfaces |

The nonsecret profile is recorded for coverage and invalidation. A profile narrows
the operation catalog; it never widens tenant scope or permits a write. Missing
permissions remain a gap. No automatic broader-scope request or fallback to a
write-capable Gmail scope fills one.

Every profile authenticates the tenant-binding bootstrap with only the baseline
Directory scopes below. Selecting optional checks does not add security or Gmail
scopes to this initial assertion and does not make baseline checks depend on those
grants. Steps 5 and 6 add separate token attempts for the exact selected optional
surface after user admission; their denial remains an optional coverage gap. An
`authorized_user` refresh uses the existing grant, never silently adds scopes.

All baseline scope names below have the prefix
`https://www.googleapis.com/auth/`:

- `admin.directory.customer.readonly`
- `admin.directory.domain.readonly`
- `admin.directory.orgunit.readonly`
- `admin.directory.user.readonly`
- `admin.directory.rolemanagement.readonly`

Optional group context uses `admin.directory.group.readonly`. OAuth metadata needs
`admin.directory.user.security`, which has no read-only variant; the optional
profile requires an existing approved credential and reports broader observed grants.
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
the successfully bound customer id, declared root, selected profile and usable
returned scope evidence leave the private bootstrap.

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
to issuer, subject, customer or profile require fresh evidence. Future Gmail per-user
token caches are keyed by bound customer and admitted user id. Current primary
address, customer and exclusions must be checked before impersonation, never inferred
from an arbitrary target-returned address.

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
| Optional group context | `/admin/directory/v1/groups`, fixed `customer={customer}` | Group id, email, aliases and label only |
| User detail | `/admin/directory/v1/users/{user}` | Same relevant fields; fresh login evidence and delegated-subject verification |
| Roles | `/admin/directory/v1/customer/{customer}/roles` | `kind`, `roleId`, `roleName`, `rolePrivileges.serviceId`, `rolePrivileges.privilegeName` and `isSuperAdminRole` |
| Privilege tree | `/admin/directory/v1/customer/{customer}/roles/ALL/privileges` | `kind`, `serviceId`, `privilegeName`, recursive `childPrivileges` and `isOuScopable` |
| Per-user role assignments | `/admin/directory/v1/customer/{customer}/roleassignments`, fixed `userKey={user}` and `includeIndirectRoleAssignments=true` | Assignment/assignee/role ids, assignee type, CUSTOMER/OU scope, condition presence and `expirationDetails.expireTime` |
| OAuth grants | `/admin/directory/v1/users/{user}/tokens` | Client id, scopes, grantor id and display label; no token value |
| Auto-forwarding | `/gmail/v1/users/{user}/settings/autoForwarding` | Enabled state and destination |
| Forwarding filters | `/gmail/v1/users/{user}/settings/filters` | Filter id and `action.forward` only |

Directory operations use `admin.googleapis.com`; Gmail operations use the reviewed
planned source host `gmail.googleapis.com`. Credential exchange uses
`oauth2.googleapis.com`. API bodies are never retained wholesale. User recovery data,
custom schemas, notes, home addresses, passwords, SSH keys and photos are omitted.
Filter criteria, queries, subjects, labels and unrelated actions are discarded before
generic redaction and persistence. Secrets in retained fields are redacted before
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
per-user assignment returned by Directory. Fresh user details prioritize passed leavers, administrators
and contractors before other accounts when a budget prevents reading everyone.

A fresh `users.get` is required for every inactivity verdict: Google's list
`lastLoginTime` can be inaccurate. Recognized 2-step flags in the current list suffice
for the 2-step rules; fresh detail only fills a flag the list lacks. Conflicting
list/detail identity or security values cause abstention and a diagnostic note.
Flag-specific conflicts are in "Observed 2-step verification".

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
| OAuth grants | 1,000 per user | Single array |
| Gmail filters | 1,000 per user | Single array |

The privilege-tree depth counts node levels. A level-32 node with an empty child
array is within the bound; a further child is not.

Additional data or a next token beyond a cap marks incomplete execution, exit 2,
without discarding positive findings. Reaching exactly a cap with no further data is
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
remain coverage gaps. No group-member
read fills them.

Only current supported assignments establish retained administrative privilege.
An absent condition or explicit empty string is unconditional; a nonempty, null
or wrongly typed condition is unsupported. Absent `expirationDetails` means no
recorded expiry. When present, a valid RFC3339 `expireTime` is interpreted even if
unknown sibling fields are discarded. Null, empty, unknown-only or malformed
expiration structures remain unknown. Projection
must preserve that distinction rather than turning an unreadable shape into absence.
Unknown expiration metadata cannot establish current privilege or absence. A
recognized expiry at or before the assessment instant is expired and is ignored;
a future expiry preserves
the supported assignment. Unknown roles or privileges block absence verdicts, but a
known supported privilege can still prove presence when an unknown sibling is also
returned. `isAdmin:true` independently proves super-admin status even when role
reads are unavailable. The exact service/name table above remains version
`2026-10-10`.

## Rules

Every rule returns shared `finding.Judgment` evidence with a declared subject and
`fired`, `disproved` or `abstained`. Account subjects are current primary addresses;
unit subjects are canonical paths including `/`; OAuth app subjects are exact client
ids. Subject-specific acceptances name that exact instance. Missing, null, unfamiliar,
denied, redacted or truncated evidence is unknown.

Shared identity definitions use provider-neutral prose. Workspace-specific definitions
are registered from the collector beside `Judge` through `finding.Register`;
`finding.Lookup` remains the report and explain read path. Step 3 evaluates the first
nine rules below and step 4 the two 2-step-verification rules; the OAuth and
forwarding rules remain planned.

| Rule | Base severity / subject | Fires | Disproves | Abstains |
|---|---|---|---|---|
| `identity.unexpected_admin` | medium / account | Attributed super admin absent from the tenant's declared expected list | Expected super admin or known not-super-admin | Missing expected list, unknown identity or admin status; passed leaver suppresses this duplicate |
| `identity.unattributed_admin` | high / account | Observed super admin or supported privileged delegate, complete alias attribution finds no person, and tenant people context exists | Unambiguous attribution or known not-privileged | No people context, partial aliases or unknown roles |
| `identity.external_admin` | medium / account | Declared contractor is a super admin | Known not-contractor or not-super-admin | Unknown kind, attribution or admin status |
| `identity.shared_admin` | medium / account | Declared shared account is a super admin | Individual account or known not-super-admin | Unknown kind or admin status |
| `identity.former_person_has_access` | high / account, `+1 attribute:admin` | Passed `left` date, exact primary match and active account | Positively suspended/archived, or recognized complete current-address absence with removed-rename caveat | Future date, unknown status, active alias-only match, missing identifier or partial population |
| `workspace.too_many_super_admins` | medium / none | Count above 3, or at least 3 and above a third of active humans | Complete populations below the threshold | Unknown exemptions or incomplete absence; partial population can fire only on the absolute lower bound above 3 |
| `workspace.stale_account` | medium / account | Eligible active account; fresh detail has a valid actual sign-in more than 90 calendar days ago | Suspended, archived, exempt or recent actual sign-in | Unknown/future/inconsistent dates or status, list-only evidence |
| `workspace.never_signed_in` | low / account | Eligible active account; fresh detail has exact epoch never marker and creation more than 30 calendar days ago | Actual sign-in, creation at most 30 days ago, suspended, archived or exempt | Unknown creation/login or list-only evidence |
| `workspace.suspended_admin_assignment` | medium / account | Suspended account retains super flag or supported privileged direct/indirect assignment | Complete admin metadata proves no assignment | Unknown suspension or partial/uninterpreted roles |
| `workspace.two_step_not_enforced` | high / org_unit | A known-active account in the unit explicitly has `isEnforcedIn2Sv:false`; fire wins inside a unit, "at least" with unknowns or a partial population | Complete users population, unit found exactly once in the unit tree, every account's activity known, every active account explicitly `true`, no conflicts | Otherwise; units with only inactive accounts or none produce no judgment; no active account at all gives one asset-level abstention |
| `workspace.admin_without_two_step` | high / account | Known-active super admin or supported privileged delegate explicitly has `isEnrolledIn2Sv:false`, enforced or not | Explicit enrollment `true`, known inactive, or admin status known false | Unknown admin status, enrollment, activity, or a conflict |
| `workspace.oauth_broad_scope` | medium / oauth_app, `+1` super-admin or declared break-glass grantor | An exact supported broad scope is observed | Complete app-grant population contains only recognized narrow scopes | Unknown fields/scopes or partial/unread absence |
| `workspace.external_forwarding` | medium / account | Active mailbox has enabled auto-forwarding or filter forwarding outside complete verified tenant domains | Both settings reads are known complete with no external destination | Missing delegation/scope/read/domain/destination evidence or malformed data |

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
policy, grace periods, configuration groups, IdP/SSO controls, methods or phishing
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
exempt. Details are `affected`, `not_enrolled`, `enrolled`, `enrollment_unknown`,
`active_observed`, `state_unknown` (unknown flags or activity) and
`population_complete`. `affected` lists every affected account, not enrolled first,
then enrolled, then unknown, alphabetical within each. The excerpt names them, capped
at 20 with a pointer to the JSON report, because the text renderer does not print
`affected`; it explains an "at least" count by the unknown accounts or the partial
population.

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
| `everyone` | every fired unit |
| `admins` | a fired unit whose affected accounts include a known `isAdmin:true` account; delegates do not count |
| `some` | every fired unit, only when a complete population has every active account explicitly off |
| `none`, `unknown`, undeclared | never |

A raised instance carries `contradiction`, cites the declaration, has a one-sentence
"Why here" naming the contradicting fact, and carries the federation caveat under
"Not checked": people who sign in through another identity provider that requires a
second factor may make the raise inapplicable, and scheck read neither that service
nor Google's single sign-on settings. Workspace enrollment alone never establishes an
enforcement contradiction, even when the admin-without-two-step finding fires.

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
  with no unknowns, each adding "Required is not the same as enrolled".

Counts in notes say "at least" on a partial population. Remediation reviews current
flags and console policy/grace settings, and enrolls admins using hardware keys where
appropriate.

### OAuth scope interpretation

The exact table version is `2026-10-10`. Supported broad scopes have prefix
`https://www.googleapis.com/auth/`, except the full mail URI:

`drive`, `drive.readonly`, `gmail.readonly`, `gmail.modify`, `admin.directory.user`,
`admin.directory.user.security`, `admin.directory.rolemanagement`, `cloud-platform`,
and `https://mail.google.com/`.

Broad read sensitivity and write capability are distinguished. The only recognized
narrow scopes are `openid`, `email`, `profile`,
`https://www.googleapis.com/auth/userinfo.email` and
`https://www.googleapis.com/auth/userinfo.profile`. A broad scope plus unknown scopes
can fire on the known broad scope; unknown-only abstains. Unknown is never narrow.
Grants aggregate once per client id across the tenant, with scope union and grantor
ids; partial populations retain lower bounds. Display names prove neither publisher
identity, declared-tool matching nor approval.

The assessment client is exempt from a ranked grant finding only when its exact
`authorized_user` client id is proven by successful client-authenticated refresh
pairing. An arbitrary service-account JSON client id is not trusted for exemption;
its JWT exchange proves the issuer assertion, not that local field. Unknown clients
remain target OAuth applications rather than guessed assessment identities.

### Forwarding interpretation

A saved but disabled auto-forwarding address does not fire. Filter configuration
shows a forwarding rule, not that any message was forwarded. Absence needs both
complete settings reads. Destinations use exact domain comparison against complete
verified tenant domains; suffix matching, trusted subdomains or arbitrary engagement
domain roots cannot establish an internal destination. Remove unintended forwarding;
do not claim message disclosure was observed.

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
`Context.MFASource`, two 2-step rule outcomes and the 2-step readout notes. OAuth
grants and forwarding remain unassessed. A mixed GitHub/Workspace identity row
cannot claim complete assessment from GitHub judgments alone. Inventory notes show lower bounds,
permission failures, credential uncertainty and fresh delegated verification.
Primary-address attribution is usable on observed records; alias-only attribution
requires a complete population. Each declared address is matched independently, so
one person may own multiple current accounts. Competing people for one current
account leave its attribution unknown. Display names never establish identity.
Unexpected-admin judgments cite both `access.admins` and the matched person's
Workspace-address declaration when their identity supplies the conclusion.

Identity and access coverage contains decided administrative sub-items, the
"Workspace 2-step verification (Google's enforcement and enrollment flags)" sub-item
over both 2-step ids, and a "Workspace OAuth grants and domain-wide delegation"
sub-item that stays *not assessed* with `no_rule`; forwarding remains unassessed in
email coverage. Every collector rule id belongs to exactly one sub-item, which a test
enforces. The 2-step sub-item always carries a `no_rule` detail stating its limits
(organizational-unit policy, grace periods, another identity provider, methods and
phishing resistance not checked), whatever its mark. With no 2-step outcome it is
*not assessed* with `unavailable:workspace_evidence`, never `not_applicable`: unlike
the general `not_applicable` rule in [report.md](report.md), "Coverage", every read account is judged for 2-step verification, so no outcome
means none was recorded. An abstained judgment's reason
detail is its subject and first "Not checked" line. E9 owns global coverage; no new
global area is introduced.

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
gap, never a clean result.

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
the security permission; if the organization wants those additional checks, an
administrator can approve a dedicated credential. Optional forwarding wording says
no approved Gmail credential was selected for those accounts and, if wanted, asks the
operator to arrange approved access. These checks inspect settings and filter
forwarding destinations, never messages.

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
No live measurement or independent acceptance is claimed.

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
