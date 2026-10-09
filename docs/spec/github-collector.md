# scheck — GitHub collector specification

GitHub organization and repository assessment for 0.0.2 E5. Steps 1–2 build the
gate foundation and principal/organization inventory. The remaining operations and
all security rules are design, defined with the `security-consultant` on 2026-10-09.
The inventory surface was frozen on 2026-10-10.
Descriptive rule names are not finding ids; inventory does not assess a control.

The gate owns admission, sending, redaction and persistence
([scope.md](scope.md#the-scope-gate)); the engagement owns people attribution, admin
thresholds and severity adjustments ([engagement.md](engagement.md), "People",
"Admins", "Severity in context"). The report contract is [report.md](report.md),
and run state and resume are [runs.md](runs.md). Those decisions are not redefined
here.

## Boundary

All remote reads are compiled `GET` operations through the gate. Credentials come
from `GITHUB_TOKEN` or `GH_TOKEN`, never the engagement file. No git transport,
`gh` execution, GraphQL, arbitrary target-returned URLs or writes. A collector
constructs only typed parameters for declared operations. API version, projection,
pagination and permission requirements are frozen with each operation before it is
built. The reviewed evidence plan uses GitHub's `2026-03-10` API version.

The token's limited view is not the organization's complete posture. Missing,
`null`, unrecognized, denied, redacted or truncated evidence is unknown. A 404 from
an admin endpoint is permission uncertainty, never proof a control is absent.
Selected-repositories credentials cannot prove that no other private repositories
exist. Every rule fires, disproves or abstains; an incomplete population proves
presence, never absence ([scope.md](scope.md#responses)). No known-subject exception
permits a partial member or MFA list to disprove a rule. A complete direct object
read may settle its predicate, but cannot bypass its rule's owning-population
completeness gate or the acceptance completeness gate.

## Reads

Cheapest metadata comes first. Each operation projects only the fields its rules or
coverage read. The inventory surface below is compiled; later paths remain proposed
until registered and reviewed. The permission table distinguishes classic scopes,
fine-grained permissions, organization approval and owner-only visibility.

| Read | Path (inventory built; later reads proposed) | Evidence and limits |
|---|---|---|
| Principal | `/user` | Stable user identity for PAT/App user tokens; public identity needs no extra permission. Missing private MFA field says nothing. Installation-token principal is unsupported and stays unknown. |
| Organization | `/orgs/{org}` | Organization id/settings; owner visibility is required for complete settings. Absent or null `two_factor_requirement_enabled` is unknown. |
| Own organization membership | `/user/memberships/orgs/{org}` | Recognized active membership and owner role establish authority for owner-only fields and filters; login alone does not. |
| Members and owners | `/orgs/{org}/members`, with compiled `role=all` or `role=admin`, `filter=all` | Member and owner inventory. Owner-only `2fa_disabled` filters are not built; later rules trust them only after verified owner authority. |
| Outside collaborators | `/orgs/{org}/outside_collaborators` | Population of account identities; repository-effective permissions require separate evidence. |
| Invitations | `/orgs/{org}/invitations` | Invitation id, role and identity fields needed for matching; a null login retains its invitation identity. |
| Repositories | `/orgs/{org}/repos` (built), `/repos/{owner}/{repo}` (proposed) | Provider id, owner/name, visibility, archived state and default branch. Visibility may be incomplete under the token. |
| Branch and active rules | `/repos/{owner}/{repo}/branches/{branch}`, `/repos/{owner}/{repo}/rules/branches/{branch}` | Default-branch metadata and active rules, including organization rules; evaluate/disabled rules are not active protection. Active-rule reads need Metadata read. `protected:true` alone does not prove PR-review requirements. |
| Workflow defaults | `/orgs/{org}/actions/permissions/workflow`, `/repos/{owner}/{repo}/actions/permissions/workflow` | Organization and repository defaults separately, plus PR-approval setting; fine-grained Administration read at the relevant level. |
| Workflow files | Compiled contents-directory/file operations under `.github/workflows` at the assessed default-branch commit | Gate decodes base64 before secret redaction, so encoded secrets never persist. Never follow `download_url` or `git_url`. Supported syntax is frozen before rules. |
| Deploy keys | `/repos/{owner}/{repo}/keys` | Id, title and `read_only`; full public keys need not be retained. |
| Secret metadata | Organization/repository Actions secret list and selected-repository operations | Names, timestamps, organization visibility and selected repositories; never values. Names are inventory, not evidence of a leak. |
| Dependabot alerts | Per-repository alert operations | Identity, state, affected manifest and severity needed by the rule. An organization-filtered view does not prove repository completeness. |
| Secret-scanning alerts | Per-repository alert and location operations | Id, state, type, validity and location. The provider's `secret` member is dropped before persistence even when no local detector recognizes its format; arbitrary raw metadata is not retained. |

### Built inventory surface

All eight operations use `GET`, `https://api.github.com`, API version `2026-03-10`
and the gate's credential binding. Object and list bodies have a 1 MiB cap; lists
request `per_page=100` and stop at 100 pages. The gate reconstructs each next request
from its compiled template and the preceding request id, never a returned URL.
Repository list items have the subject template `repo:github:{key}`, where `key`
is `full_name`; exclusions are applied before persistence.

| Operation | Retained fields |
|---|---|
| `github.principal` | `id`, `login`, `type`, `two_factor_authentication` |
| `github.organization` | `id`, `login`, `type`, `two_factor_requirement_enabled`, `default_repository_permission` |
| `github.membership` | `state`, `role`, organization `id`, `login`, optional `type`; user `id`, `login`, `type` |
| `github.members`, `github.owners`, `github.outside_collaborators` | `id`, `login`, `type` |
| `github.invitations` | `id`, nullable `login`, `role`, `invitation_source` |
| `github.repositories` | `id`, `name`, `full_name`, owner `id`, `login`, `type`, `visibility`, `private`, `archived`, `default_branch` |

An active own membership establishes member authority only when its user matches
the freshly read principal, its organization matches the declared organization's
id and login, and the evidence is unredacted. The nested organization's `type` may
be absent; when present it must be `Organization`. `role: admin` additionally
establishes owner authority. A successful member response alone can be only a
public-member view; it does not establish active membership.

Members and owners retain `member_visibility_unknown` without verified member
authority. Outside collaborators and invitations retain `owner_visibility_unknown`
without owner authority. `Population.Complete` describes recognized pagination,
independent of the separate `VisibilityComplete` flag. Repository visibility always
remains unknown: these endpoints do not establish the token's repository selection
grants, even after every returned page is read.

Classic private-organization inventory generally requires `read:org`; fine-grained
tokens need organization Members read for own membership, private members, outside
collaborators and invitations, with the endpoint's membership and owner requirements
still applying. `GET /orgs/{org}` needs no extra fine-grained permission; complete
organization details require owner visibility, and classic tokens need `admin:org`
for those details. Public metadata availability is not proof of a complete private
view. Denials, SAML authorization and organization approval remain coverage gaps.
The built step does not fetch owner-only MFA filters or judge the retained settings.
These requirements follow the official [organization read](https://docs.github.com/en/rest/orgs/orgs#get-an-organization)
and [organization membership](https://docs.github.com/en/rest/orgs/members) references.

App installation permissions and repository selection, and repository runners and
applicable runner groups, are carried candidate reads. Their exact scope and
operations remain to be frozen. An organization runner's presence alone does not
prove access to a public repository.

The read plan follows the official GitHub REST references for
[users](https://docs.github.com/en/rest/users/users),
[organizations and members](https://docs.github.com/en/rest/orgs),
[branch rules](https://docs.github.com/en/rest/repos/rules),
[workflow permissions](https://docs.github.com/en/rest/actions/permissions),
[contents](https://docs.github.com/en/rest/repos/contents),
[deploy keys](https://docs.github.com/en/rest/deploy-keys/deploy-keys),
[secret metadata](https://docs.github.com/en/rest/actions/secrets),
[Dependabot alerts](https://docs.github.com/en/rest/dependabot/alerts) and
[secret-scanning alerts](https://docs.github.com/en/rest/secret-scanning/secret-scanning).

## Context and subjects

People match only explicitly declared GitHub logins, as the engagement's "People"
section defines. Expected owners, unattributed admins, admin-count thresholds,
contractor/shared admins, leaving dates and declared MFA use the engagement's
existing conditions; this collector does not invent attribution from names, email,
SAML or SCIM. Linked identities may suggest people entries, never attribute one.

`public: true` on a repository asset is the carried declaration for deliberately
public repositories; it still needs schema and implementation work. URL intent
cannot hold it. Deliberately public never excuses a leaked credential.
Production deployment declarations grade the applicable branch, workflow,
collaborator and deploy-key findings. Production secret stores supply context and
coverage links, not proof that values exist. Mirror checkout paths select history
reads. No question asks last-sign-in dates GitHub cannot supply or trusted action
authors to suppress mutable references.

Findings are per `{id, asset, subject}` ([report.md](report.md#findings)). E5's existing
subject decisions are `account`, `invitation`, `repository`, `branch`, `workflow`,
`deploy_key`, `webhook`, `secret_location`, `principal` and `oauth_app` for their
respective instances. Organization MFA, owner count and organization workflow
defaults have no subject. Exact keys, accepted-subject handling and finding ids are
frozen before each rule step, using the report and engagement validation contracts.

## Rules: proposed evidence outcomes

Every population-based disproof below requires the applicable population complete.
Partial evidence may fire on affirmative presence; it never proves absence. Direct
object evidence does not bypass the owning-population gate. Existing E5a identity
rules retain their definitions and context conditions.

| Descriptive rule | Fires | Disproves | Abstains |
|---|---|---|---|
| Organization MFA not required | Verified owner-visible explicit false | Verified owner-visible explicit true | Non-owner, missing, null or unrecognized field |
| Member or owner without 2FA | Verified owner-only filter returns the account | Complete trusted filter excludes the known account | Unknown authority, failed read or partial population |
| Unexpected owner | Known owner outside declared expected handles | Owner matches expectation | Tenant absent from `access.admins`, unknown match or role |
| Unattributed admin | Recognized admin with no declared person match, under the engagement's attribution conditions | Login matches a declared person | No relevant people identifiers or unknown privilege |
| Contractor or shared admin | Recognized admin attributed to either kind | Known other kind or nonadmin | Role or attribution unavailable |
| Former person retains access | Passed declared leaving date and membership, collaboration or invitation remains | Complete applicable populations establish absence | Future departure, no login or partial population |
| Too many owners | Engagement threshold reached; partial counts may establish only an absolute lower bound | Complete population below threshold | Partial unresolved population; no incomplete ratio |
| Undeclared public repository | Explicit public visibility without `public:true` | Private/internal or declared public | Unknown visibility |
| Broad default member permission | Explicit write/admin | Explicit none/read | Missing or unrecognized setting |
| Outside collaborator administers production | Outside identity, effective admin and production all observed/declared | Known lower privilege or nonproduction | Any join missing |
| Writable workflow default | Explicit write | Explicit read | Unavailable or unrecognized setting |
| Unprotected default branch | Existing branch, no classic protection and successful complete empty active rules | Affirmative active protection | Empty repository, race, denied read or partial rules |
| Mutable third-party action | External action/reusable workflow tag or branch instead of full SHA; container without digest | Complete supported references immutable | Expression, unsupported syntax, redaction or truncation |
| Dangerous PR-target execution | Recognized `pull_request_target` job executes untrusted PR code with proved privilege | Complete supported workflow lacks the combination | Effective permissions, ref or execution flow unknown |
| Public self-hosted runner | Public repository and supported self-hosted job with applicable access | Supported hosted-only workflow | Dynamic labels, groups or access unknown |
| Write deploy key | Explicit `read_only:false` | Explicit `read_only:true` | Missing or unrecognized field |
| App can write all repositories | Explicit all-repository selection and relevant write permission | Selected scope or entirely read-only permissions | Permission or selection unavailable |
| Open dependency alert | Recognized open alert with supported severity | Fixed/dismissed alert or complete supported empty population | Denied read, unknown state/severity or partial population |
| Provider secret alert | Recognized open alert with identifiable location; validity never overstated | Recognized fixed/revoked resolution for that alert | Unknown state/location; false-positive dismissal does not prove rotation |
| Content or history credential | Compiled detector match; marker and location retained | Complete bounded readable scan without a match | Missing/stale/partial mirror, unsupported format or cap |
| Credential in mirror remote | Recognized credential in matching remote configuration | Supported credential-free remote | Missing/mismatched/unreadable configuration |

**Proposed bases, corrected by consultant review.** Existing anchors in
[engagement.md](engagement.md), "Severity in context", remain authoritative.
Organization MFA non-enforcement, owner/admin MFA gaps, unattributed admins and
former people with remaining access are high; former-admin access gains the existing
`attribute:admin` step. A nonadmin member's MFA gap is proposed medium. Unexpected
named owners, contractor/shared owners and excessive owner counts are medium.
Actions not pinned alone are low. Write-all workflow defaults alone are medium;
write-all defaults joined with unpinned actions are high. The join must have both
observations and does not raise an action finding without the writable-token fact.

The remaining DEFINE proposals are high for outside-production admins and public
self-hosted runners; medium for broad member permissions, branch protection, write
deploy keys, all-repository App writes and a credential in a mirror remote. Exact
alert-severity mapping and relevant write-permission lists remain to be reviewed and
frozen with the finding definitions. These are proposed bases, not built rules.

A credential leak is high for private repositories and critical for public
repositories under the existing anchors. Critical PR-target grading requires public
PR submission, proved untrusted checkout/execution and a write token together; not
every PR-target workflow is critical. Secret authenticity or usability is never
tested. A secret name alone proves neither a production credential nor exfiltration.

## History

The mirror reader and its safety boundary are owned by
[scope.md](scope.md#repositories). It reads the operator's mirror in-process,
confines paths after realpath, checks the remote against the declared locator and
compares heads with API evidence. It executes nothing and has no git transport.
Detection is redaction; retain detector marker, commit, path and line, never a value
or value hash. Exact supported object/pack formats and caps remain to be frozen.
Missing/stale mirrors, missing pull refs, caps, unsupported formats and unreadable
objects prevent a complete-history claim. Commits served by SHA outside mirror refs
remain not assessed.

## Principal and resume

Resolve principal with a fresh `/user` request before authenticated reuse. A
recognized positive user id and login establish `github:user:<id>`; its fingerprint
is that stable identity and sorted observed scopes, never a token value. A changed
identity or observed scope set prevents reuse of earlier authenticated successes.
A changed known stable identity (`github:user:<id>`) is printed in the report
header using the former and fresh labels. A login rename, scope change or
unknown-to-known transition produces no identity-change notice. Fresh read
attempts can still fail; the header does not claim they succeeded. Unknown principal
reuses none.
Installation tokens are unsupported until a separately reviewed GET-only principal
source exists; `ghs_` credentials leave the principal unknown and do not call `/user`.
Organization inventory can continue, but authenticated successes are not reused.
Never infer installation identity from `account.login`.
Fine-grained grant changes may be unobservable. Retained evidence keeps its original
observation date and does not claim current access validation
([scope.md](scope.md#resume), [runs.md](runs.md)).

**Assessment token decision pending.** Scope currently requires a broader-grant
finding. The carried consultant recommendation is a run note, unranked and outside
the exit count: the token also permits writes, scheck sent only reads, prefer an
organization-approved fine-grained token and revoke it when finished. The owner must
choose and update the single decision owner before implementation. Unknown
fine-grained/App capability says "write capability not determined", never
"read-only". This draft changes neither the current contract nor the pending choice.

## Reporting and coverage

The built inventory reports observed or “at least” counts, missing reads and
permission/visibility gaps as asset notes. It produces no security findings and
marks the applicable risk areas `not_assessed` with `no_rule`; a successful API read
is not an assessed control. Inventory evidence keeps each read's status, observation
time and reuse decision; asset principals and request traces identify the account
and execution decisions without a credential value. A changed known identity is
carried in optional
`engagement.principal_changes` and printed in the header. The normal header also
names the GitHub account and warns that inventory visibility depends on its
credential. A resumed run says evidence was kept only where reuse was allowed.

Shortfalls direct the reader to inventory notes for what was retained and what
remains unknown; they never claim nothing was read when earlier reads succeeded.
A response truncation or page cap stops collection as `incomplete` with
`limit_reached` and exit 2, as the scope outcome contract requires. Coverage asset
read counts require a successful, recognized, nontruncated organization inventory
read; principal resolution alone, or an incomplete status after failed requests,
never counts as a read asset. Permission or recognition gaps after some successful
reads remain gaps; unknown installation principals do not by themselves make
otherwise readable inventory incomplete.

Population gaps are explained in words. Each reused read's note gives its original
observation time and says current access was not validated. A missing organization
Members permission asks the operator to obtain the organization's owner's
authorization and resume; it does not recommend broad write-capable access.

Coverage sub-items come from the practitioner's list, independent of built rules;
unbuilt items are `no_rule`, not an assessed area (E9 owns that coverage refinement).
Identity, repository access, CI, provider alerts and history retain separate gaps:

- selected repositories, visibility, missing permissions, organization approval or
  SAML authorization; unavailable owner-only MFA evidence;
- no member sign-in dates: an undeclared former member cannot be distinguished from
  a current one; SAML enforcement alone does not cover SSH or tokens;
- Actions secret metadata reads names, not values: no value is requested or received.
  Secret-scanning alert responses can contain a raw secret, which the gate discards
  or redacts before any persistence or output; provider alerts are not a complete scan;
- missing, stale, capped, unsupported or unreadable mirrors and missing pull refs;
- workflow evidence from its assessed ref and supported syntax only; dynamic and
  reusable execution is not fully traced;
- no token-usability test, exploit, workflow dispatch or target modification.

Remediation starts with containment where appropriate: remove departed access and
invitations; reduce owners while retaining recovery; replace write deploy keys; pin
action commits; stop privileged execution of PR-head code; rotate leaked credentials
before removing history; upgrade affected dependencies. Enable organization MFA
after checking automation. Final wording requires consultant REVIEW and client
REPORT review.
