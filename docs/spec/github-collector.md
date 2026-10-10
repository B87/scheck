# scheck — GitHub collector specification

GitHub organization and repository assessment for 0.0.2 E5. Steps 1–5 build the
gate foundation, principal/organization inventory, identity and repository-access
rules, CI configuration, secret metadata and provider-alert rules. Steps 4 and 5
were defined with the `security-consultant` on 2026-10-10. Step 6's history
contract was frozen on 2026-10-10; the reader and `checkout` setting are not built.
Step 5 passes offline checks and consultant/client/adversarial reviews; live
acceptance remains pending. The step 3 evidence and rule surface
was frozen on 2026-10-10.

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
coverage read. The inventory, access, CI, secret metadata and alert surfaces below
are compiled. The permission table distinguishes classic scopes,
fine-grained permissions, organization approval and owner-only visibility.

| Read | Path (built reads) | Evidence and limits |
|---|---|---|
| Principal | `/user` | Stable user identity for PAT/App user tokens; public identity needs no extra permission. Missing private MFA field says nothing. Installation-token principal is unsupported and stays unknown. |
| Organization | `/orgs/{org}` | Organization id/settings; owner visibility is required for complete settings. Absent or null `two_factor_requirement_enabled` is unknown. |
| Own organization membership | `/user/memberships/orgs/{org}` | Recognized active membership and owner role establish authority for owner-only fields and filters; login alone does not. |
| Members and owners | `/orgs/{org}/members`, with compiled `role=all` or `role=admin`, `filter=all` | Member and owner inventory. The compiled `2fa_disabled` filters are sent only after verified owner authority. |
| Outside collaborators | `/orgs/{org}/outside_collaborators` | Population of account identities; repository-effective permissions require separate evidence. |
| Invitations | `/orgs/{org}/invitations` | Invitation id, role and identity fields needed for matching; a null login retains its invitation identity. |
| Repositories | `/orgs/{org}/repos`, `/repos/{owner}/{repo}` | Provider id, owner/name, visibility, archived state and default branch. Visibility may be incomplete under the token. |
| Repository collaborators | `/repos/{owner}/{repo}/collaborators`, compiled `affiliation=all` | Effective permissions and role name for recognized accounts; admin is established by an explicit permission, never guessed from an unfamiliar custom role. |
| Branch and active rules | `/repos/{owner}/{repo}/branches/{branch}`, `/repos/{owner}/{repo}/rules/branches/{branch}` | Default-branch metadata and active rules, including organization rules; evaluate/disabled rules are not active protection. Active-rule reads need Metadata read. `protected:true` alone does not prove PR-review requirements. |
| Workflow defaults | `/orgs/{org}/actions/permissions/workflow`, `/repos/{owner}/{repo}/actions/permissions/workflow` | Organization and repository defaults separately, plus PR-approval setting; fine-grained Administration read at the relevant level. |
| Workflow files | Compiled contents-directory/file operations under `.github/workflows` at the assessed default-branch commit | Gate decodes base64 before secret redaction, so encoded secrets never persist. Never follow `download_url` or `git_url`. Bounded supported syntax is defined under "Supported workflow syntax". |
| Deploy keys | `/repos/{owner}/{repo}/keys` | Id and `read_only`; neither title nor public-key value is retained. |
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
Owner-only MFA filters and retained organization settings are judged in step 3.
These requirements follow the official [organization read](https://docs.github.com/en/rest/orgs/orgs#get-an-organization)
and [organization membership](https://docs.github.com/en/rest/orgs/members) references.

### Built access surface

Step 3 adds five operations with the same version, body cap, list page size and
page cap as inventory. The collector sends owner-only MFA filters only after the
unredacted active own membership establishes owner authority. A missing authority
produces an explicit gap without sending either request. These disabled-MFA
filters establish enrollment only for accounts with provider `type: User`. The
per-member MFA rule abstains for Bot, App or other non-user identities even when
the user filter is complete; absence from a user list proves nothing about them.
Those identities remain available for access inventory and explicit people
attribution, without an inferred `people.kind`.

| Operation | Path and retained fields |
|---|---|
| `github.members_without_mfa` | `/orgs/{org}/members`, compiled `role=all&filter=2fa_disabled`; account `id`, `login`, `type` |
| `github.owners_without_mfa` | `/orgs/{org}/members`, compiled `role=admin&filter=2fa_disabled`; account `id`, `login`, `type` |
| `github.repository` | `/repos/{owner}/{repo}`; the repository inventory projection |
| `github.collaborators` | `/repos/{owner}/{repo}/collaborators`, compiled `affiliation=all`; `id`, `login`, `type`, `role_name`, `permissions.admin`, `permissions.pull`, `permissions.push`, `permissions.maintain`, `permissions.triage` |
| `github.deploy_keys` | `/repos/{owner}/{repo}/keys`; `id`, `read_only`, never the public-key value |

Repository reads use exact declared or in-scope discovered locators. The direct
object must match the requested owner and repository before either child list is
sent; a transfer or returned URL never authorizes following a different locator.
Every permission boolean and `read_only` preserves absent or null as unknown.
Deploy-key pagination can establish that named repository's key-list completeness.
Collaborator pagination never establishes complete visibility: `affiliation=all`
means all collaborators visible to the credential. Its `VisibilityComplete` remains
false and the read keeps `repository_collaborator_visibility_unknown`. Affirmative
access may fire, but absence cannot disprove access, offboarding or privilege rules.
Organization-wide repository visibility remains unknown separately.

App installation permissions and repository selection, and repository runners and
applicable runner groups, are carried candidate reads. Their exact scope and
operations remain deferred for a later DEFINE; step 4 adds neither. An organization
runner's presence alone does not prove access to a public repository.

Fine-grained repository access reads require Metadata read for collaborator lists
and Administration read for deploy-key lists. Classic collaborator reads require
`read:org` and `repo`, the authenticated user's write, maintain or admin access,
and organization membership for organization-owned repositories. A denial is a
coverage gap, never a recommendation to broaden target write access. These
requirements follow the official [collaborator](https://docs.github.com/en/rest/collaborators/collaborators?apiVersion=2026-03-10)
and [deploy-key](https://docs.github.com/en/rest/deploy-keys/deploy-keys?apiVersion=2026-03-10) references.

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

`public: true` on a repository asset declares deliberately public visibility. The
optional boolean is valid only on repository assets; absence or `false` is not a
public declaration. URL intent cannot hold it. Deliberately public never excuses a leaked credential.
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

## Rule evidence

The following step 3 ids and bases are frozen. `none` means the finding is
organization-wide and has no subject. Account keys are lowercase GitHub logins,
invitation keys are `invitation:<id>`, repository keys are lowercase `owner/name`,
and deploy-key keys are `deploy-key:<id>`. Each instance keeps its numeric provider
id. An acceptance for a subject-specific finding must name that subject.

| Finding id | Base | Subject |
|---|---|---|
| `github.mfa_not_required` | high | none |
| `github.owner_without_mfa` | high | account |
| `github.member_without_mfa` | medium | account |
| `identity.unexpected_admin` | medium | account |
| `identity.unattributed_admin` | high | account |
| `identity.external_admin` | medium | account |
| `identity.shared_admin` | medium | account |
| `identity.former_person_has_access` | high | account |
| `identity.former_person_invited` | high | invitation |
| `github.too_many_owners` | medium | none |
| `github.undeclared_public_repository` | high | repository |
| `github.broad_default_member_permission` | medium | none |
| `github.outside_admin_on_production` | high | account |
| `github.writable_deploy_key` | medium | deploy_key |

The identity conditions and grading in the engagement's "People", "Admins" and
"2-step verification" sections govern these rules. Unexpected-owner comparison
requires declared expected handles and a person match. Departed owners are handled
by the former-person rule, and unattributed owners by the unattributed-admin rule,
without a duplicate unexpected-owner finding. Contractor/shared-admin findings
apply to owners only. Production repository admins count for unattributed-admin
and former-person admin grading, but not as organization owners.

Effective repository admin is established by `permissions.admin:true`, including
a custom role. Recognized standard roles are `pull`/`read`, `triage`, `push`/`write`,
`maintain` and `admin`. Conflicting recognized role and permission fields are
unknown. A negative standard-role judgment requires its full permission combination
to be recognized; an unfamiliar custom role with `admin:false` remains
insufficient for a privilege-based disproof. Organization delegated-role chains are
not assessed in this step. An outside-production-admin finding joins the outside
account and repository collaborator by numeric user id, requires a declared
production deployment and explicit effective admin, and stays high without a
second production raise. A writable deploy key is medium, raised one step for
production. Undeclared public visibility is high for unintended confidentiality
exposure; it does not claim a secret was found.

Former-person access is filed once per observed asset and account: organization
access and each observed repository access remain separate instances. Only observed
organization ownership raises its organization instance as admin; only recognized
effective admin on a declared production repository raises that repository instance.
Unknown privilege never erases affirmative access. An aggregate absence judgment
still requires every applicable trusted population complete.

Former-person access compares every declared GitHub login. The declared departure
date must be strictly before the current date in the engagement timezone. Retired
service accounts are included. A null invitation login cannot match a person and prevents an offboarding absence
claim, even after full pagination. An invitation grants possible future access, not
a current admin role. An observed owner establishes current access even when the
member list failed. `access.mfa: some` does not contradict an individual account
without MFA; explicit organization non-enforcement still contradicts that belief.

## Rules: evidence outcomes

Every population-based disproof below requires the applicable population both
`Complete` and `VisibilityComplete`.
Partial evidence may fire on affirmative presence; it never proves absence. Direct
object evidence does not bypass the owning-population gate. E5a supplied the
identity schema and conditions; these identity finding definitions and rules are
built in E5 step 3.

| Descriptive rule | Fires | Disproves | Abstains |
|---|---|---|---|
| Organization MFA not required | Verified owner-visible explicit false | Verified owner-visible explicit true | Non-owner, missing, null or unrecognized field |
| Member or owner without 2FA | Verified owner-only filter returns the account | Complete trusted filter excludes the known account | Unknown authority, failed read or partial population |
| Unexpected owner | Known owner outside declared expected handles | Owner matches expectation | Tenant absent from `access.admins`, unknown match or role |
| Unattributed admin | Recognized admin with no declared person match, under the engagement's attribution conditions | Login matches a declared person | No relevant people identifiers or unknown privilege |
| Contractor or shared admin | Recognized admin attributed to either kind | Known other kind or nonadmin | Role or attribution unavailable |
| Former person retains access | Passed declared leaving date and membership or collaboration remains | Complete applicable populations establish absence | Future departure, no login or partial population |
| Former person invited | Passed declared leaving date and matching pending invitation remains | Complete trusted invitation population establishes absence | Future departure, no login, null invitation login or partial population |
| Too many owners | Engagement threshold reached; partial counts may establish only an absolute lower bound | Complete population below threshold | Partial unresolved population; no incomplete ratio |
| Undeclared public repository | Explicit public visibility without `public:true` | Private/internal or declared public | Unknown visibility |
| Broad default member permission | Verified owner-visible explicit write/admin | Verified owner-visible explicit none/read | Non-owner, missing or unrecognized setting |
| Outside collaborator administers production | Outside identity, effective admin and production all observed/declared | Known lower privilege or nonproduction | Any join missing |
| Step 4 CI rules | Frozen in "CI controls: step 4 definition" below | Frozen there | Frozen there |
| Write deploy key | Explicit `read_only:false` | Explicit `read_only:true` | Missing or unrecognized field |
| App can write all repositories | Explicit all-repository selection and relevant write permission | Selected scope or entirely read-only permissions | Permission or selection unavailable |
| Open dependency alert | Recognized open alert with supported severity | Fixed/dismissed alert or complete supported empty population | Denied read, unknown state/severity or partial population |
| Provider secret alert | Recognized open alert with identifiable location; validity never overstated | Recognized fixed/revoked resolution for that alert | Unknown state/location; false-positive dismissal does not prove rotation |
| Content or history credential | Compiled detector match; marker and location retained | Complete bounded readable scan without a match | Missing/stale/partial mirror, unsupported format or cap |
| Credential in mirror remote | Recognized credential in matching remote configuration | Supported credential-free remote | Missing/mismatched/unreadable configuration |

**Bases and later proposals.** The frozen step 3 table above uses the anchors in
[engagement.md](engagement.md), "Severity in context", which remain authoritative.
Organization MFA non-enforcement, owner/admin MFA gaps, unattributed admins and
former people with remaining access are high; former-admin access gains the existing
`attribute:admin` step. A nonadmin member's MFA gap is medium. Unexpected
named owners, contractor/shared owners and excessive owner counts are medium.
The six step 4 bases and their narrowly supported predicates are frozen below.
All-repository App writes and a credential in a mirror remote remain proposed
medium bases. Exact alert-severity mapping and App write-permission lists remain
for their later DEFINE reviews. Runner-access findings are deferred.

A credential leak is high for private repositories and critical for public
repositories under the existing anchors. Secret authenticity or usability is never
tested. A secret name alone proves neither a production credential nor exfiltration.

## CI controls: step 4 definition

This definition was frozen on 2026-10-10 and is implemented and verified offline.
Consultant REVIEW, client REPORT, `make check`, `make build` and fresh adversarial
review pass. E5's later steps and live acceptance remain pending. It adds no interview question and uses existing production deployment
context. Every finding has area `cicd` and `Exposure: false`.

### Findings and outcomes

| Finding id | Base | Subject | Fires | Disproves | Abstains |
|---|---|---|---|---|---|
| `github.organization_workflow_default_write` | medium | none | Explicit organization default `write` | Explicit `read` | Missing or unrecognized setting |
| `github.repository_workflow_default_write` | medium | repository | Explicit repository default `write` | Explicit `read` | Missing or unrecognized setting |
| `github.default_branch_unprotected` | medium | branch | Exact existing default branch has `protected:false` and complete empty active rules | `protected:true` or a recognized active control | Unknown flag or rules, denied read, branch race or partial rules |
| `github.mutable_action_reference` | low | workflow | A supported remote action, reusable workflow or Docker reference is mutable | Complete supported references are immutable, or contain no external dependency | Unresolved references, unsupported or partial evidence |
| `github.mutable_action_with_write_token` | high | workflow | Mutable step action or Docker dependency and mutation permission in the same direct job, with at least one eligible literal trigger | Complete supported jobs have no mutable dependency, or every direct job containing one has no mutation permission | Permission/event uncertainty, opaque reusable jobs or incomplete job evidence |
| `github.pr_target_unsafe_checkout` | medium | workflow | Literal `pull_request_target`, supported PR-controlled checkout, later recognized local execution and syntactic mutation permission in the same direct job | Complete supported evidence excludes at least one component | Unknown ref, permission, condition or execution flow |

Repository default, branch and PR-target findings gain the existing production
adjustment once. Organization defaults, mutable references and the high joined
finding do not. When the joined finding fires, suppress the duplicate open mutable
reference finding, but retain both assessments. The join requires both observations;
an organization default does not establish an unknown repository default.

Repository subject keys are lowercase `owner/name`. Branch keys retain the exact
case-sensitive branch name; workflow keys are exact `.github/workflows/<name>`
paths. The assessed commit SHA is evidence, not part of the subject key. Acceptances
for these instances must name their subject.

Branch disproof establishes only the presence of protection. It does not prove
required reviews, review strength, bypass resistance or protection of other branches.
Evaluate and disabled rules do not count as active controls.

The PR-target finding says **“Workflow requests PR-controlled code execution with
write permission.”** It establishes requested execution in configuration, never a
successful run or exploitability. It is not critical in step 4. The general critical
anchor is unchanged: a future rule would need evidence of public triggering,
applicable enforcement or bypass and actual execution, beyond this predicate.

### Compiled read plan

Six new GET operations use the existing GitHub origin, credential binding and API
version `2026-03-10`. The registered operation ids, six templates and permission requirements are
frozen here.

| Operation | Compiled path | Fine-grained permission |
|---|---|---|
| `github.organization_workflow_default` | `/orgs/{org}/actions/permissions/workflow` | Organization Administration read |
| `github.repository_workflow_default` | `/repos/{owner}/{repo}/actions/permissions/workflow` | Repository Administration read |
| `github.default_branch` | `/repos/{owner}/{repo}/branches/{branch}` | Contents read |
| `github.active_branch_rules` | `/repos/{owner}/{repo}/rules/branches/{branch}` | Metadata read |
| `github.workflow_directory` | `/repos/{owner}/{repo}/contents/.github/workflows?ref={sha}` | Contents read |
| `github.workflow_file` | Exact validated immediate regular `.yml` or `.yaml` child of that directory, with compiled `ref={sha}` | Contents read |

Classic private reads require `repo`; organization workflow defaults require
`admin:org`. A denied read is a coverage gap, not advice to grant target write
permission. Defaults retain typed permission and PR-approval booleans; the approval
setting is an explanatory note only. Branch evidence retains name, commit SHA and
`protected`; rules retain recognized types; directory/file evidence retains identity.

Read the exact default branch first, then pin every directory and file read to its
SHA. Changed default branches, inconsistent identity or commit evidence produce a
gap. Never follow `download_url`, `git_url`, returned redirects to other locators or
external action URLs. No referenced action, reusable workflow or container is fetched.
A missing-directory 404 is unknown. Symlinks, submodules and nested entries are gaps.

`branch`, `sha` and `file` are typed resources inside the same compiled repository
subject, not URLs or arbitrary API paths. Branch names use 1–255 ASCII letters,
digits, `_`, `.`, `/` or `-`, starting with a letter, digit or `_`; traversal, double
slashes, trailing slashes and components ending in `.` or `.lock` are rejected.
Workflow file names are immediate ASCII children starting with a letter, digit or
`_`, followed by letters, digits, `_`, `.` or `-`, ending in `.yml` or `.yaml`,
with no `..` and at most 200 bytes. Unsupported names remain gaps without follow-up.

The existing 1 MiB response cap, 100-item request size and 100-page ceiling remain.
At most 100 workflow files, 512 KiB decoded per file and 8 MiB decoded per repository
are read. YAML has at most 20,000 nodes and depth 40. Hitting a cap is `limit_reached`,
incomplete and exit 2, and prevents a population absence claim. Hitting GitHub's
own directory listing limit also prevents absence.

### Supported workflow syntax

Version `github-workflow-syntax:2026-10-10` describes the supported grammar. The
gate decodes base64, redacts the decoded bytes, then uses the existing `yaml.v3`
parser to produce a bounded neutral sanitized structure. The collector interprets
that structure; no dependency exception is added and no pre-redaction content is
persisted. Encoded API bodies are discarded on unsuccessful reads. A separate
redaction-marker field preserves markers even when sanitization makes YAML
unparseable; rejected source text is not retained. Parse errors retain only generic
reasons, never raw error text, locations or snippets. A failed parse supplies no file facts.

Support one mapping-root YAML document with string keys, block and flow mappings
and sequences, plain/quoted/block strings, expected booleans and null event
configurations. `on` accepts a literal string, list or mapping. Supported fields are
`permissions`, `jobs`, direct `steps`, `uses`, `run`, `with`, literal `runs-on`, `if`,
`shell`, `defaults.run` and literal working directories. A reusable job's `uses`
is inspected for pinning only; its execution and privilege remain opaque.

Event mapping configurations are null or mappings of supported fields, except
`schedule`, which requires a nonempty list of mappings with nonempty literal
`cron` strings. Cron semantics are not evaluated. Branch and path include/ignore
filters for `push`, `pull_request` and `pull_request_target`,
and tag include/ignore filters for `push`, require nonempty lists of literal
strings. Each include filter is mutually exclusive with its ignore filter.
PR `types` require a nonempty literal list from this frozen activity set:
`assigned`, `unassigned`, `labeled`, `unlabeled`, `opened`, `edited`, `closed`,
`reopened`, `synchronize`, `converted_to_draft`, `locked`, `unlocked`, `enqueued`,
`dequeued`, `milestoned`, `demilestoned`, `ready_for_review`, `review_requested`,
`review_request_removed`, `auto_merge_enabled`, `auto_merge_disabled`.
Nonempty `workflow_dispatch` configurations and other event fields are unsupported;
invalid event types cannot establish a privileged-trigger or PR-target finding.

A direct job requires literal `runs-on`: a nonempty string, nonempty label list,
or a mapping containing only literal `group` and/or literal string/list `labels`.
It also requires nonempty `steps`, each with exactly one string `uses` or `run`.
`uses` steps cannot contain `shell` or `working-directory`; `run` steps cannot
contain `with`. A present `with` must be a mapping. Reusable job references must
name an immediate `.yml` or `.yaml` child of `.github/workflows`, locally or in a
supported remote reference; reusable/direct job fields cannot be mixed. Unsupported
job or step structure blocks findings from that job and prevents negative claims.
Missing or unsupported runner selection leaves the entire direct job structurally
unassessed, including reference pinning. Independent supported sibling jobs may
still supply affirmative evidence.

Reject duplicate keys, anchors, aliases, merge keys, nonstandard tags, multiple
documents and invalid types. There is no general expression, shell, matrix,
reusable-workflow or composite-action interpreter. An unsupported or redacted field
makes predicates needing it unknown; it does not erase an independent affirmative
observation. Opaque execution cannot prove workflow-wide absence.

Remote actions and reusable workflows are immutable only at an exact 40-hex commit
SHA. Docker references require `@sha256:` followed by 64 hex digits. Tags, branches,
short SHAs and bare images are mutable, including GitHub-owned and same-organization
references. `./` references are local, not external; their internals remain unassessed.

### Permission interpretation

Interpret permissions as a vector. A job map replaces the workflow map, which
replaces the repository default; omitted map entries are `none`, not inherited.
Support `read-all`, `write-all`, `{}` and explicit maps with names and allowed values
from the GitHub syntax reference reviewed on 2026-10-10. The mutation keys below
accept `read`, `write` or `none`. `id-token` accepts `write` or `none`;
`vulnerability-alerts` accepts `read` or `none`. Unknown names or values cannot
supply a negative judgment.

Mutation permissions are explicit `write` on `actions`, `artifact-metadata`,
`attestations`, `checks`, `code-quality`, `contents`, `deployments`, `discussions`,
`issues`, `packages`, `pages`, `pull-requests`, `security-events` or `statuses`.
`id-token: write` alone is not token mutation; OIDC trust remains unassessed.
Reusable caller permissions are only an upper bound on opaque callee execution.

For the mutable/write join, eligible literal triggers are `push`,
`workflow_dispatch`, `schedule` and `pull_request_target`. At least one eligible
trigger is enough for an affirmative configuration judgment; additional unsupported
or fork-related triggers do not erase it. A workflow triggered only in ordinary
PR or Dependabot contexts abstains when syntactic permissions include mutation,
because effective fork permissions are unverified. Other event types are
unsupported for privilege inference and cannot supply a negative. PR-target
permission interpretation does not apply the ordinary fork downgrade.

### PR-controlled execution recognition

Relevant `if` conditions must be absent or literal true. Literal false excludes
that path; expressions are unknown. Recognize `actions/checkout` only with one of
these exact refs, allowing whitespace inside `${{ ... }}`:

- `${{ github.event.pull_request.head.sha }}`;
- `${{ github.event.pull_request.head.ref }}`;
- `refs/pull/${{ github.event.pull_request.number }}/merge`.

An optional `repository` must be exactly
`${{ github.event.pull_request.head.repo.full_name }}`, with the same internal
whitespace allowance. Variables, compound expressions, other refs or concatenation
are unknown. Checkout must use the default workspace or literal `.`. Later
recognized execution must use that workspace. Custom paths, dynamic working
directories, intervening checkouts and ambiguous or opaque flow are unknown.
Checkout alone is not execution.

Execution recognition requires an absent shell or literal `bash` or `sh` at every
applicable workflow, job and step level. Other shells, including `python`, custom
shell templates and expressions, are unknown; command text is not interpreted
under them.

Version `github-workflow-execution:2026-10-10` recognizes at most 16 KiB, 100 lines
and 4 KiB per line of each `run`. A cap is an explicit limit gap and precludes an
execution-based disproof. Commands use simple whitespace-separated tokens containing
only letters, digits and `_./:@=+-`. Recognized execution is:

- `make`, or `make <literal-target>`;
- `npm ci`, `npm install`, `npm test`, `npm run <literal-script>`;
- `pnpm` and `yarn` install, test, build and run forms;
- `./<literal-local-script>`;
- `sh`, `bash`, `python` or `python3` followed by `./<literal-local-file>`;
- a later `uses: ./<literal-local-action>` step.

Reject local path traversal. Environment assignments, command prefixes, quoting,
substitutions, expressions, pipes, redirects, shell control operators, continuations
and control flow are unsupported. Preceding lines and relevant checkout/control flow
must also be supported; unfamiliar lines cannot be skipped to construct a firing
chain. Missing a recognized command is not a negative while unsupported commands
or opaque steps remain.

### Runtime policy and runner limits

GitHub documentation reviewed on 2026-10-10 describes public repositories without
an already applicable PR-target event policy as using an `evaluate` default, with
enforcement scheduled for affected repositories on 2026-11-02. It also describes
checkout protection with an `allow-unsafe-pr-checkout` opt-out. These are time-specific policy
facts, not permanent assumptions. Retain an explicit true opt-out as evidence;
absence is not proof of protection. The Actions policies GET requires Administration
write and is not added; scheck never recommends that write grant. Applicable runtime
policy, checkout protection, approvals and actual execution always remain gaps.

Runner access and App findings are deferred entirely. Literal self-hosted labels
or groups may be reported only as requested runner configuration; dynamic requests
are unknown. A hosted-only syntax observation does not establish safety. A later
runner DEFINE must freeze exact repository/group access, public-repository permission,
selected workflows and enterprise constraints; organization runner presence alone
proves none of those. No runner or App operation is added in step 4.

### Coverage and tests

Report defaults, branch-protection presence, reference pinning, privileged mutable
combinations and PR-controlled execution requests separately. Preserve gaps for
review strength, bypass, runtime policies, reusable/composite execution, runner
access, OIDC trust, transitive dependencies and unsupported syntax. Job container
and service images are outside `uses` reference coverage and remain unassessed.
Partial evidence may fire but cannot prove absence. Provenance includes the exact repository,
workflow path, assessed SHA, supporting reads and original observation times.

Each of the six ids has firing, disproved and abstained fixtures. Regressions cover
permission replacement, `id-token` alone, unknown repository defaults, evaluate or
disabled rules, `protected:true`, short SHAs, reusable privilege uncertainty,
duplicates, aliases, caps, redaction, conditions, required runners, exclusive
step forms, typed event filters, checkout without execution,
unavailable policies, denied contents, branch races and partial populations.
A seeded base64 secret is absent from report, audit and persisted run; its marker
is present. Request traces prove GET-only SHA-pinned reads and no returned-URL use.
Consultant REVIEW and Brightcart/Dani client REPORT passed; final fresh adversarial
review found no confirmed findings after the reported defects were fixed. This
is offline implementation verification, not the live acceptance gate.

The frozen interpretation follows GitHub's official
[workflow permissions](https://docs.github.com/en/rest/actions/permissions),
[branches](https://docs.github.com/en/rest/branches/branches),
[active rules](https://docs.github.com/en/rest/repos/rules),
[contents](https://docs.github.com/en/rest/repos/contents),
[workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax),
[PR-target events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request_target),
[reusable workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations)
and [secure use](https://docs.github.com/en/actions/reference/security/secure-use)
references. The dated runtime-policy limits follow
[PR-target security](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
and [Actions policies](https://docs.github.com/en/rest/actions/policies).
Deferred runner evidence is described by
[runner access](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/manage-access)
and [runner REST operations](https://docs.github.com/en/rest/actions/self-hosted-runners).

## Secret metadata and provider alerts: step 5 definition

The `security-consultant` DEFINE on 2026-10-10 freezes this step's read surface,
subjects, severity and three outcomes. The step is built with offline fixtures for
all three rule outcomes. Full checks, build and consultant/client/adversarial
reviews pass. All reported review defects were fixed; none is carried. This is not
a live acceptance result.
History, App grants, runner access and the assessment-token reporting decision
remain outside this step.

### Metadata reads and persistence

Six compiled `GET` operations use `https://api.github.com`, API version
`2026-03-10`, the existing credential binding and a 1 MiB body cap. Lists request
`per_page=100` and stop at 100 pages. Actions and secret-scanning lists use `page`;
Dependabot uses the cursor `after`. No alert state, severity, package, type or
validity filter narrows the population. The secret-alert query compiles
`hide_secret=true`. Pagination remains gate-owned and never follows returned URLs.

| Operation | Path | Retained fields |
|---|---|---|
| `github.organization_secrets` | `/orgs/{org}/actions/secrets` | Secret `name`, `created_at`, `updated_at`, `visibility` |
| `github.secret_selected_repositories` | `/orgs/{org}/actions/secrets/{secret_name}/repositories` | Repository `id`, `name`, `full_name`, owner `id`, `login`, `type`, `visibility` |
| `github.repository_secrets` | `/repos/{owner}/{repo}/actions/secrets` | Secret `name`, `created_at`, `updated_at` |
| `github.dependabot_alerts` | `/repos/{owner}/{repo}/dependabot/alerts` | Number, state, manifest, dependency scope, package name/ecosystem, advisory GHSA/severity, vulnerability severity, dismissal reason |
| `github.secret_scanning_alerts` | `/repos/{owner}/{repo}/secret-scanning/alerts` | Number, state, type, validity, resolution, safe redaction marker |
| `github.secret_scanning_locations` | `/repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations` | Location type; commit SHA, path and line/column ranges |

Repository child reads require an existing direct object whose identity matched
its requested locator. A repository-only root does not authorize organization
secret reads. Selected-secret repository items pass root and exclusion filtering
before persistence; they authorize no child reads. At most 100 selected-secret
repository follow-ups run per organization and 100 alert-location follow-ups per
repository. Reaching a body, structure, page or follow-up cap is `limit_reached`,
incomplete, exit 2; positive observations remain usable and negative population
claims do not.

Names and timestamps are metadata, not leaked values or proof of rotation.
Organization `visibility:all` establishes sharing policy, not production use.
Selected visibility preserves only the admitted selected repository inventory.
Missing permission or feature availability, SAML authorization and token repository
selection remain explicit gaps.

These six operations have a compiled metadata response mode. The gate redacts
success JSON before exact allowlist projection and discards every error,
malformed, duplicate-member, unexpected or truncated body. Generic diagnostics
never contain raw snippets. JSON structure is bounded at 40 levels and 50,000
nodes. Provider `secret`, arbitrary `metadata`, comments, descriptions, snippets
and URLs are structurally omitted even for unknown secret formats or values such
as `true` and `1` that the generic redactor leaves literal. Only a safe redactor
marker may be retained separately; a discarded secret's marker does not invalidate
independently recognized alert metadata. Unknown nested location details never
persist. Nothing prints, audits or persists the raw secret or its hash.

Fine-grained organization secret operations require organization Secrets read;
repository secrets require repository Secrets read. Classic organization access
requires `admin:org`, plus `repo` for private repositories; repository secret access
requires `repo`. Dependabot requires repository Dependabot alerts read; classic
access uses `security_events`, or `public_repo` for public-only use. Secret alert
and location operations require repository Secret scanning alerts read, with the
provider's repository/organization administrator requirements; classic access uses
`repo` or `security_events`, or `public_repo` for public-only use. Permission
shortfalls ask for the corresponding authorized read grant and resume, never a
broader target write grant. These requirements follow the official
[Actions secrets](https://docs.github.com/en/rest/actions/secrets?apiVersion=2026-03-10),
[Dependabot alerts](https://docs.github.com/en/rest/dependabot/alerts?apiVersion=2026-03-10)
and [secret scanning](https://docs.github.com/en/rest/secret-scanning/secret-scanning?apiVersion=2026-03-10)
references reviewed on 2026-10-10.

### Finding instances and outcomes

Version `github-alerts:2026-10-10` fixes these five rule ids. Every definition sets
`Exposure:false`; public-on-purpose never lowers them. An acceptance must identify
one subject, never all future alert locations.

| Finding | Base and area | Subject kind and key |
|---|---|---|
| `github.org_secret_all_repositories` | medium, Secrets | `secret_location`, `actions:<lowercase-name>` on the organization |
| `github.dependabot_high` | high, CI/CD | `dependency_alert`, `dependabot:<number>:<encoded-manifest-path>` on the repository |
| `github.dependabot_medium` | medium, CI/CD | Same dependency alert instance |
| `github.dependabot_low` | low, CI/CD | Same dependency alert instance |
| `github.secret_scanning_open` | high, Secrets | `secret_location`, `secret-scanning:<number>:commit:<sha>:<encoded-path>:<start-line>:<start-column>` on the repository |

Paths preserve case and must be unambiguous normalized relative paths without
traversal. Path delimiters are encoded with `url.PathEscape`; commit SHAs are full
40-hex values normalized to lowercase. Commit ranges require positive coordinates,
ordered lines and ordered columns within the same line. Different supported
locations yield separate findings. Unsupported location types supply an explicit
gap and no content read; they do not erase an independent supported location.

| Rule | Fires | Disproves | Abstains |
|---|---|---|---|
| Organization all-repository sharing | Explicit `visibility:all` | Recognized `private` or `selected`, or complete empty applicable population | Unknown visibility, denied or marked required fields; incomplete population for a negative |
| Dependabot high/medium/low | Open alert with identifiable manifest and matching recognized vulnerability severity; provider critical maps to high | Recognized fixed, dismissed or auto-dismissed state, another recognized severity, or complete empty applicable population | Unknown state, severity or manifest; missing reads; incomplete population for a negative |
| Provider secret | Open alert with nonempty recognized type and supported location; validity active, unknown or unavailable | Provider-reported resolved/revoked state with complete applicable evidence, or complete empty applicable population | Inactive validity, unknown state, missing/unsupported location, non-revocation resolution, denied evidence or incomplete population for a negative |

All negative judgments require recognized complete owning populations and adequate
visibility. Partial populations can establish affirmative presence. An incomplete
owning population also retains an abstained family judgment, so positive findings
cannot make that family's coverage appear complete. A dependency dismissal disproves an open alert, not that the vulnerability was fixed. Provider
critical severity alone does not prove scheck's critical anchor. Dependency rules
receive no automatic production or public adjustment and make no runtime
exploitability, deployed-version or development-dependency safety claim.

For provider secrets, recognized observed public repository visibility raises high
to critical; private/internal stays high and unknown visibility cannot raise it.
The observed-public adjustment cites the direct repository request separately in
`repository_read`, alongside the supporting alert and location requests.
Existing `data_matters_most` grading applies to Secrets findings. Provider validity
is reported, never tested. Inactive means the provider marked it inactive; rotation
was not verified. Resolutions `false_positive`, `used_in_tests`, `wont_fix`,
`pattern_edited` and `pattern_deleted` do not establish revocation. A resolved
`wont_fix` alert still marked active gets a `github_alert_followup` note before the
summary ranking and again in asset notes. It says GitHub closed the alert because
someone chose not to fix it but still reports the credential active, and revocation
was not verified. This requires owner follow-up even when scheck could not reach a
finding. The note is unranked, creates no finding and does not change the exit
count.

### Coverage, wording and verification

Actions metadata, Dependabot alerts and provider secret alerts have separate
coverage. Dependency findings say high or critical when either provider severity
maps to scheck high; their unassessed details describe dependency limits separately
from secret-scan limits. Provider patterns and alerts are not a complete repository
secret scan.
Unsupported locations, unlisted/private repositories, feature availability and
unread history remain explicit gaps. A 404 is permission/feature uncertainty,
never an empty population. No new interview question is added; existing secret
store and important-data declarations are context, not proof of values or use.

Sharing remediation limits the secret to repositories that need it and asks for
workflow review before changing access. Dependency remediation asks to review the
manifest, upgrade where a patch exists, confirm the deployed dependency and test;
it does not claim exploitability was established. Provider-secret remediation
starts with revocation or rotation at the provider, then reviewing use and removing
reported locations. Closing an alert or deleting a commit does not revoke a
credential. Reports say what GitHub reported and what was not verified.

Tests must prove all five rule ids fire, disprove and abstain. Regressions cover
fixed/dismissed wording, missing/unknown/inactive validity, non-revocation
resolutions, multiple and unsupported locations, partial populations, excluded
selected repositories, cursor/page limits and unknown-format secret removal.
Seeded values must be absent from report, audit, persisted requests, Recon and
error diagnostics; safe markers remain present. GET traces must show only the six
compiled operations and no returned-URL or content follow-up.

## History

**Step 6 definition, frozen with the security-consultant on 2026-10-10; not built.**
The planned mirror reader and its safety boundary are owned by
[scope.md](scope.md#repositories). `checkout` remains unavailable until step 6
lands. The following defines that implementation, not coverage already delivered.

### Mirror admission and confinement

The input is an ordinary SHA-1 bare mirror made by the operator. One read-only
boundary uses `os.Root` for all local opens and rejects filesystem symlinks and
nonregular files. Hard links are rejected where reliable standard platform metadata
can identify them; platforms without that check are unsupported. No pathname check
followed by an unconstrained open is permitted. Nothing executes Git, fetches,
checks out files, loads hooks or writes the mirror.

Parse conventional Git config sections, quoted values and comments. Require
`core.bare=true`, repository format 0 or 1 using SHA-1, one unambiguous matching
`remote "origin"`, `mirror=true` and `fetch=+refs/*:refs/*`. Reject includes,
alternates, promisor repositories, replacement refs, grafts, reftable, worktrees,
URL rewrites and extensions that change object or reference interpretation. Inert
settings are ignored. Ambiguous or duplicate admission settings are unsupported.

Origin must name the exact declared GitHub repository in HTTPS, SSH or scp form.
Compare after removing userinfo; reject ports, queries, fragments and ambiguous
origins. The conventional SSH username `git` is not a credential. Removing
userinfo for comparison does not authorize using it: no remote URL is sent,
printed or persisted.

### Supported objects and traversal

Support loose SHA-1 commit, tree, blob and tag objects, PACK v2 and index v2,
including OFS_DELTA and REF_DELTA with bases in another pack or loose storage.
Validate checksums and object identities transiently; retain no blob identity or
value hash. Support loose and packed refs, peeled tags and symbolic HEAD. SHA-256,
PACK v3, index v1, reftable, corrupt objects and missing delta bases leave coverage
partial; none permits an external read.

Traverse all local refs, all commit parents and their trees. Scan normal-file and
symlink blob bytes, including binary content, without extension or directory
filters. A symlink stored in a Git tree is scanned as bytes, never followed on disk.
Submodules, LFS payloads, reflogs and unreachable objects are not assessed. Hidden,
deleted or API-unadvertised refs, and commits GitHub serves only by SHA outside the
mirror's refs, remain gaps.

### Fixed budgets

Budgets are compiled limits, never settings that widen collection. Each repository
also obeys the engagement deadline. Stream packs rather than loading all pack
bytes into memory. The decoded-object cache is at most 64 MiB; eviction is not a
coverage gap. Aggregate resident reader buffers are at most 128 MiB; exceeding
that processing budget stops incomplete with `limit_reached`.

| Resource | Maximum |
|---|---|
| Config | 64 KiB |
| One ref file / all ref bytes | 4 KiB / 8 MiB |
| Refs / directory entries | 10,000 / 250,000 |
| Packs | 64 |
| One pack / all pack bytes | 256 MiB / 512 MiB |
| One index | 16 MiB |
| Objects / commits | 200,000 / 20,000 |
| One expanded object / total expanded bytes | 8 MiB / 512 MiB |
| Delta depth / symbolic-ref or tag depth | 64 / 16 |
| Tree depth / tree visits | 128 / 250,000 |
| Finding locations | 10,000 |
| Time | 60 seconds |

A cap yields incomplete coverage and exit 2. Retain observed positive matches;
never turn a bounded partial traversal into an absence claim.

### Fresh reference comparison and resume

For each repository with `checkout`, send two fresh compiled GETs through the gate:
`/repos/{owner}/{repo}/git/matching-refs/heads/` and
`/repos/{owner}/{repo}/git/matching-refs/pull/`. The fine-grained permission is
repository Contents read. Keep only `ref`, `object.type` and `object.sha`. These
are bounded one-shot arrays: no invented pagination or returned-URL follow-up.
The prefix is compiled and typed, never taken from an origin or a ref. No pull
request is fetched.

Compare every advertised branch and pull ref with local refs. Missing or changed
refs make coverage partial; extra local refs are still scanned. Say "refs differ
from the observed GitHub refs", never "behind origin": equality or ancestry has
not been established. An empty advertised pull-ref array does not prove there
were no past pull requests. API denial allows the confined local scan but prevents
a negative history verdict.

Snapshot config and refs before and after traversal. A change makes coverage
partial; this is a mutation check, not an atomic snapshot claim. Resume rescans the
mirror and reads fresh refs; it never reuses a local history result.

### Rules and subjects

Both planned definitions set `Subject: "secret_location"`, Secrets area and
non-exposure findings. Acceptances must name the exact location.

| Finding | Base | Fires | Disproves | Abstains |
|---|---|---|---|---|
| `github.history_credential` | high | A compiled existing secret-redactor pattern or exact nonempty run credential matches a read blob, even in a partial scan | Complete supported traversal with fresh matching refs finds no recognized pattern | Missing or mismatched mirror, unsupported/corrupt data, mutation, API gap, cap or other incomplete evidence |
| `github.remote_credential` | medium | Structurally credential-bearing origin userinfo, or a compiled credential pattern in origin | Completely parsed supported matching origin contains no recognized credential | Missing, ambiguous, mismatched or unsupported origin |

History's key is
`history:<commit>:<encoded-case-sensitive-path>:<line>:<detector>`; origin's key is
`remote:origin`. Use a full commit identity, a redacted path and one-based line.
No entropy heuristic or `redact_extra` match creates a finding. Extra redactions
hide client-selected text and are counted only. If path redaction prevents a stable
subject key, record a coverage gap rather than retain unsafe text or invent a key.

Explicit public visibility from the direct repository read raises the history
finding from high to critical and cites that read. Production context does not
raise it; public visibility does not raise the remote finding. Existing
important-data adjustments apply. No rule tests credential usability.

### Output, coverage and verification

Retain only safe detector markers, commit, redacted path and line; never raw blob
snippets, config, remote URLs, blob identities or value hashes. Each local attempt
has one audit line naming the asset, execution status/reason, time and numeric
counts, with no target-derived free text. A negative verdict says "No recognized
credential pattern found in the supported mirror history read", never "no secrets".
Detector coverage and credential usability remain gaps beside the traversal gaps.

Remediation revokes or rotates the credential first, reviews its use, then removes
it from history. For origin userinfo, remove it, rotate the credential and use a
credential helper. Removing history does not revoke a credential.

Tests must prove fires, disproves and abstains for both rules; loose, packed and
cross-storage delta reads; corruption, caps and cycles; confinement under symlink
and mutation races; duplicate/opaque config; literal run credentials;
`redact_extra` without a finding; changed mirrors and fresh refs on resume.
Seeded values must be absent from every persisted output with safe markers present.
Fixtures are constructed without invoking Git. No live acceptance is claimed by
this definition.

Format and API references: [Git pack format](https://git-scm.com/docs/gitformat-pack),
[GitHub Git references](https://docs.github.com/en/rest/git/refs),
[Git clone mirror behavior](https://git-scm.com/docs/git-clone) and
[GitHub pull-request refs](https://docs.github.com/en/enterprise-cloud%40latest/pull-requests/how-tos/review-pull-requests/checking-out-pull-requests-locally).

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

Inventory reports observed or “at least” counts, missing reads and
permission/visibility gaps as asset notes. Steps 3–5 report findings and each
rule's fired, disproved or abstained assessments. Declaration references are
printed as declarations, never quoted as collected API observations. Identity and repository-access
coverage is partial where relevant evidence or later controls are missing.
Repository-specific judgments and their request provenance are placed on the
repository asset, which reports its assessed controls rather than an inventory-only
label. Repository-specific identity judgments contribute to the identity area; no rule
family is fabricated for an asset that supplied no applicable judgments. The
CI/CD area includes public-repository, deploy-key and the six CI judgments. Token
defaults, default-branch protection presence, dependency pinning, privileged mutable
dependencies and PR-controlled execution requests have separate coverage sub-items.
Secret metadata sharing, Dependabot alerts and provider-secret alerts have
separate coverage sub-items. History remains `no_rule`; runner access, App grants
and runtime enforcement are not inferred from configuration. `github_alerts` notes
retain metadata inventories, provider validity/resolution caveats and location
gaps. CI summary wording and actionable evidence are governed by [report.md](report.md), "GitHub CI
summary". A successful
API read is not an assessed control.
Inventory evidence keeps each read's status, observation
time and reuse decision; asset principals and request traces identify the account
and execution decisions without a credential value. A changed known identity is
carried in optional
`engagement.principal_changes` and printed in the header. The normal header also
names the GitHub account and warns that visibility depends on its
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

Recon records exact login attribution and provider ids, then `--stop-after recon`
prints candidates with empty `kind`, one account at a time in root and role order.
Production-admin candidate roles use the same recognized effective-permission
predicate as rules; conflicting or marked role fields never establish admin.
Invitation-only candidates carry `invitation_id`, never an account `provider_id`;
only an independently observed account supplies that account id. Unidentified
invitations print comments rather than account declarations. The
operator must set each kind; no name, email or linked identity guesses a person.
Bot logins ending in `[bot]` are supported identifiers, without automatic
classification. The report lists matched service and break-glass accounts, pending
owner invitations outside the owner count, production administrators and grant-source
limits. More than two break-glass owners count toward the threshold. Shared
`used_by` departures produce rotation notes, not claims rotation was observed. MFA
beliefs produce readout notes only from successful recognizable reads. Disabled-MFA
counts use that filter's own completeness and visibility to choose “observed” or
“at least”; a failed filter says enrollment is unavailable, never zero. A stronger
organization policy is noted only from recognized organization evidence. Factor strength,
recovery, session compromise, SSH keys and tokens remain unchecked. GitHub account
2FA is independent of identity-provider MFA; an enforced SAML login alone does not
settle these GitHub enrollment or organization-requirement rules.

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
