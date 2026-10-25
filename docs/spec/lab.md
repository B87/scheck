# scheck — lab specification

The lab is the environment scheck is measured against before a release: a GCP project, a
GitHub organization, two domains with their mail records and sites, and Linux hosts,
seeded with known faults, decoys and clean controls from a secret seed, built with
OpenTofu, and scored against an answer key sealed before any scheck run. Google Workspace
has no lab: it is exercised read-only on the user's production tenant and never measured
("Google Workspace: no lab, observed on the production tenant"). This file defines what
the lab holds, how a seed becomes infrastructure, what the answer key looks like, how it
is sealed and revealed, and how a run is scored. Status: design. Defined by the
`security-consultant` (define mode, AI agent, Claude Opus 5.5, `claude-opus-5-5`) on
2026-10-25 and revised the same day with the user's decisions ("Decisions and open
questions"). No lab code exists. It becomes contract when the lab's first part is built
([ROADMAP.md](../ROADMAP.md), E3 and G7). Until then it describes the target, not the
build.

**What the author read.** [VISION.md](../VISION.md); [ROADMAP.md](../ROADMAP.md): the
rules for every release, E3, the 0.0.2 release gates, G1, G6, G7 and the 0.0.3 and 0.0.4
gates; [eval/README.md](../eval/README.md), [eval/lab-0.0.2-domain.md](../eval/lab-0.0.2-domain.md)
and the first part of [eval/e6-definition-2026-10-10.md](../eval/e6-definition-2026-10-10.md);
and the parts of [scope.md](scope.md) and [report.md](report.md) that define roots,
exclusions, canonical ids, coverage marks and reasons, risk areas and finding records. The
author read no collector, rule, catalog or fixture code (`internal/`, `testdata/`,
`test/`). The coverage table in [report.md](report.md) ("Coverage") lists what each version
judges, so this catalog is not blind to the roadmap. That is why the public catalog is not
the whole answer key: blindness comes from the sealed seed, the varied parameters and the
seeder's private extras ("Private extras").

What a finding record, a coverage row and a canonical asset id look like is
[report.md](report.md) ("Findings", "Coverage"). What scheck may send to each asset is
[scope.md](scope.md). Where results are recorded is [eval/README.md](../eval/README.md).

## What the lab measures

The lab is a measurement, not a fixture. It exists to back five claims in a release record
with evidence that the people who wrote the checks did not write. The user decided on
2026-10-25 that the lab is a release gate for **v1.0.0**. The measures are the ones the
roadmap's gates already name; the right-hand column says where:

| Claim | Gate it feeds (as the roadmap names it) |
|---|---|
| scheck finds the faults a competent consultant would find in the first days with read access | recall (0.0.2 gate 2) |
| scheck does not report look-alikes that are not faults | false positives (0.0.2 gate 3) |
| context moves severity in both directions, and only where it should | context (0.0.2 gate 4) |
| the coverage table never calls an area checked when it was not | coverage (0.0.2 gate 6; 0.0.3 "coverage table correct for every area") |
| scheck writes nothing, and contacts nothing outside scope or excluded | scope (0.0.2 gate 7; 0.0.3 "no write call possible", "every GCP call on the declared list") |

Two more gates use the lab without being scored by this file. Prioritization (0.0.2 gate
5) needs a blind ranker, whose top five is sealed with the labels ("Sealing"). Comparing
runs (G6; 0.0.3 "the comparison of two runs correct against a seeded change list") uses
the change-set pairs ("Change sets").

Every claim covers GCP, GitHub, the domains and the hosts. None covers Google Workspace:
every record of a measured run says **"Workspace: exercised read-only on a real tenant,
not measured."**

Seals made before v1.0.0, starting with the GCP part before G1's first commit, are
development measurements. Each is scored once like a gate seal, recorded, then revealed,
and from then on its seed is a development seed that implementers and `make live` may use
("`make live` and release gates").

## Rules that never change

These rules hold for every part of the lab and every seed. A lab that breaks one is not
run, whatever it would measure.

1. **Nothing seeded is exploitable by anyone outside the team while the lab exists**
   ([ROADMAP.md](../ROADMAP.md), E3). A fault that would be exploitable from the internet
   is seeded only where it cannot be reached (the local host, a source-restricted
   firewall, a private repository), or in a form that observes the same way and does not
   work (X-02).
2. **No seeded secret works.** Every "secret" a fault plants, in a repository, a page,
   metadata or a file on a host, is a canary token, a provider-format string with no
   account behind it, a documented example value, or a password that is not the
   password of the service it names. The only working credentials in the lab are the
   seeders' own and the database passwords of X-03, which live in state only ("Data and
   secrets").
3. **Fake data only.** Customer exports, payroll files and database rows are generated.
   No real person's data is in any lab asset, and no persona is a real person's
   identity.
4. **Third parties are not touched.** DNS records exist only in domains the team owns.
   A dangling or takeover record points only at a name the team holds outside the lab's
   roots or at a provider that verifies the team's ownership. No seeding step sends mail
   to anyone outside the team: the notifications seeding causes (a GitHub invitation) go
   only to mailboxes the team owns.
5. **Isolated accounts.** The lab runs in its own GCP project and billing account, its own
   GitHub organization and its own domains. None holds anything of the team's real work,
   no lab credential works outside the lab, and no production identity is a member of a
   lab asset.
6. **Credentials and state stay out of the repository.** Provider credentials come from
   the environment or the provider's own login. OpenTofu state lives in a private bucket
   outside every lab root, encrypted. Neither is ever in git.
7. **Every seed is torn down.** The parts that can be destroyed are destroyed after each
   gate run. The parts that cannot (the GitHub organization, the domains) are reset to
   their clean baseline ("Lifetime and teardown").
8. **The production Workspace tenant is not a lab.** Nothing is seeded in it, nothing is
   changed in it, and nothing read from it enters the repository except aggregates
   ("Production-tenant safety").

## Pieces

Each piece is one OpenTofu module with a clean baseline and fault slots. Most state is
code. Some state cannot be set through any API, and the table says so plainly.

| Piece | Provider (pinned) | As code | Scripted | Manual | Destroyed after a gate run |
|---|---|---|---|---|---|
| GCP project | `hashicorp/google` `~> 8.8` (8.8.1, 2026-10-23) | project, IAM, service accounts and keys, firewall, VM, Cloud SQL, buckets, audit config, log exclusions, workload identity, budget | the verify step | the dedicated billing account | yes |
| GitHub organization | `integrations/github` `~> 6.13` (6.13.0, 2026-07-08) | repositories, files and history, branch protection and rulesets on public repositories, org and repository Actions permissions, secrets, deploy keys, collaborators, invitations, webhooks, Dependabot settings, Pages | history rewriting for a deleted secret; waiting for provider alerts | organization creation; requiring two-factor authentication; verifying the lab domain for Pages; persona accounts and their 2FA; GitHub App installs | repositories yes; the organization no, reset |
| Domain, email and web | `cloudflare/cloudflare` `~> 5.28` (5.28.1, 2026-10-20); `hashicorp/tls` for certificates | DNS records, SPF, DKIM, DMARC, dangling and takeover records, the sites' server configuration on the lab host or VM | none | buying the two domains; delegating them to Cloudflare | records yes; domains no |
| Hosts | `kreuzwerker/docker` `~> 4.6` (4.6.0, 2026-09-01) for the local host; `hashicorp/google` for the cloud host | the host image and its cloud-init or entrypoint, rendered from the seed | the verify step | none | yes |

Google Workspace has no piece. The `hashicorp/googleworkspace` provider would not have
carried one anyway: its last release, 0.7.0, is from 2022-06-10, its repository was
archived on 2025-06-30, and it never covered 2-step verification enforcement, OAuth
grants or mail settings.

Versions are the latest each registry listed on 2026-10-25 (`api.opentofu.org`, checked
that day). The lock file pins exact versions and hashes; a version change is a lab change
and bumps `LAB_VERSION` ("Layout"). OpenTofu itself is pinned to one minor, at least 1.7
for client-side state encryption.

### GCP project

A project with **no organization** (decided 2026-10-25), on a dedicated billing account
with a budget of about 50 dollars and alerts at 50, 90 and 100% to two named people.

Without an organization there are no organization policies. Organizations created on or
after 2024-05-03 enforce `iam.managed.disableServiceAccountKeyCreation`,
`iam.allowedPolicyMemberDomains` and `storage.uniformBucketLevelAccess` by default (Google
Cloud, "Secure by default organizations", checked 2026-10-25). A project with no
organization has none of them, so user-managed keys and `allUsers` bindings need no
override. The decision has costs, recorded so no result implies otherwise:

- There is no company identity. Every human member of the project is a consumer Google
  account, held by a consenting person, so F-GCP-11 (a personal account among company
  accounts) has nothing to stand out from, and is not seedable.
- There is no organization policy to override, so F-GCP-20 is not seedable.
- There is no folder or organization root, so S-05 (an excluded project under a wider
  root) is not seedable, and G1's `gcp:organizations/<id>` root is never exercised by the
  lab.
- The project itself is a fault a practitioner would report in a real company: a cloud
  project owned by individuals' personal accounts, outside any company-controlled
  identity. It is on in every seed (F-GCP-22).

Seeded as code: IAM bindings, service accounts, keys (F-GCP-03, D-GCP-02, X-02), firewall
rules, one e2-small VM (the cloud host), one Cloud SQL instance in its smallest tier, three
to five buckets, audit configuration, a log exclusion, a workload identity pool, the
budget and its alerts. Manual: the billing account.

### GitHub organization

A dedicated organization on the **free plan** (decided 2026-10-25; Team later). Most
configuration is in `integrations/github`: repository contents and history through
`github_repository_file` and scripted commits, `github_branch_protection` and rulesets,
`github_actions_organization_workflow_permissions` (the default token permission),
`github_actions_organization_secret` with its visibility, `github_repository_deploy_key`,
`github_repository_collaborator`, `github_repository_webhook`,
`github_repository_vulnerability_alerts`, `github_organization_settings` (base
permission), and `github_repository_pages`.

The free plan decides where faults live:

- **Branch protection and rulesets** are not available on private repositories of a free
  organization, so every protection slot (F-GH-07, F-GH-08, F-GH-26, D-GH-04, and their
  clean controls) is on a public repository. Public repositories hold canaries and
  documented examples only (rule 2).
- **Provider alerts** are seeded on public repositories. A Dependabot alert appears after a
  lockfile naming a vulnerable version is pushed to a repository with alerts on, minutes
  to hours later, so the verify step waits for it ("Verify before sealing").
- **Secret-scanning alerts are not measured** (decided 2026-10-25). F-GH-15 is unseeded
  and unmeasured until the organization moves to a plan where the user decides to seed
  it.
- **`pull_request_target`** (F-GH-09) stays in a private repository, which free plans
  allow with Actions; only the workflow file is needed.
- Whether a free organization's default runner group exposes the "allow public
  repositories" setting (F-GH-21) is **unverified**; if not, F-GH-21 is not seeded.

Not settable through the provider or the API, and therefore manual:

- **Requiring two-factor authentication** for the organization. `github_organization_settings`
  has no such argument, and the API reports the requirement but does not set it. Turning it
  on removes every member without 2FA, so the clean baseline turns it on only after
  personas are settled.
- **Persona accounts.** A departed person, a contractor and an outside collaborator need
  GitHub accounts. GitHub's terms allow one free personal account and one machine account
  per person, and a machine account only for automated tasks. Personas are therefore held
  by consenting team members or volunteers, one each, and the engagement file declares
  their roles (a real account declared `left` is exactly the fault).
- **A member without 2FA** (F-GH-02). GitHub has required 2FA of accounts that contribute
  code since 2023. Whether a new account that never contributes can stay without 2FA is
  **unverified**; if it cannot, F-GH-02 is recorded as not seedable.
- **Verifying the lab domain** for GitHub Pages (needed by F-DNS-09), and installing a
  GitHub App (F-GH-23).

### Domain, email and web

Two domains the team owns, both under TLDs that browsers do not preload as HTTPS-only,
with DNS on Cloudflare (decided 2026-10-25): the lab domain, holding the roots under test,
and a second domain outside every root, holding the targets of dangling records. DNS is
managed as code. The sites are server configuration on the cloud host (or the local host
for offline runs), rendered from the seed. Certificates come from a public CA for names
that should be valid, and from `hashicorp/tls` for the expired or mismatched cases.

Non-preloaded TLDs make missing HSTS and plain HTTP seedable (F-WEB-01, F-WEB-02). The
preloaded-TLD decoy (D-WEB-03) is seeded only when a seed also declares a root under the
team's existing `.page` domain.

The 0.0.2 domain part is already sealed (`eval/lab-0.0.2-domain.md`) and not blind; it
stays as it is. This piece replaces it from the next seal on.

### Hosts

Two realizations of the same host module, from the same seed:

- **The local host:** a container started through `kreuzwerker/docker` from a pinned base
  image (Ubuntu LTS and Debian stable, chosen by the seed), with sshd, nginx, an app and a
  database as host processes, reached over SSH on localhost. It costs nothing, runs
  offline, and is the only place the dangerous host faults are seeded (F-HOST-03).
- **The cloud host:** the GCP project's VM, configured by cloud-init from the same
  rendered files. It exists so that a host fault and a cloud firewall rule can meet (X-03),
  which a container cannot show.

Package faults (an outdated build, a held security update, an end-of-life PHP or Node
line) are installed through the distribution's package manager from a dated archive
snapshot, so the version is reproducible. Whether the snapshot services
(`snapshot.ubuntu.com`, `snapshot.debian.org`) carry every build a seed may pick is
**unverified**; a build that cannot be installed is recorded as not seeded.

The images under `test/containers` are not the lab. They were written by the implementers
to test the runner's no-write guarantee and to record fixtures, and their contents are
known to every implementing session. The lab host shares no file with them.

## Google Workspace: no lab, observed on the production tenant

Decided by the user on 2026-10-25: there is no dedicated Workspace tenant and no Workspace
lab. The only Workspace runs are read-only runs against the user's production tenant, a
limited number of times.

### What follows

- **Nothing is seeded, so nothing is measured.** Every F-GWS and D-GWS entry below is
  *unseeded and unmeasured*, and so is every case that depends on Workspace: X-01's
  Workspace leg, X-06, K-08, K-09 and S-02. The entries stay in the catalog as the
  practitioner's reference, so that the gap is named and so that a lab tenant, if one ever
  exists, starts from them.
- **No Workspace claim.** No recall, false-positive, severity, context or prioritization
  claim about Workspace may be made from any run. The blind ranking excludes Workspace.
  Every release gate record and every result record says, in these words: "Workspace:
  exercised read-only on a real tenant, not measured."
- **Coverage honesty still applies.** It needs no ground truth: the report must not call a
  Workspace sub-item checked when its rule did not decide. An optional surface left off
  reads *not checked* with its reason; a population cut by a cap or the timeout reads
  *checked in part*; S-07 (the credential withheld) is run against the production root
  and sends nothing to the tenant.

### What a production run can legitimately verify

| Verified | How | Recorded as |
|---|---|---|
| scheck only reads | the tenant's admin audit log (Reports API, admin activity) holds no event by scheck's principal over the run's window; a write event stops all further production runs until explained | the count of events, which must be zero |
| scheck only makes its declared reads | every request in the run's `audit.jsonl` is an operation on the Workspace collector's declared list ([workspace-collector.md](workspace-collector.md)); the token audit log shows only the read scopes that list needs | counts per operation and per scope |
| coverage is honest | each Workspace sub-item's mark against what its rule decided, read from the report on the user's machine | marks and reasons, no names |
| the same tenant gives the same answer | two runs over an unchanged tenant give the same findings | counts per finding id and severity |
| findings make sense to the person who runs the tenant | the user inspects each Workspace finding in the Admin console and marks it `confirmed`, `refuted` or `could not tell`, with the reason; and notes issues they know of that scheck did not report (`known, not reported`) | an **observation**, aggregated: counts per finding id and per mark |

An observation is not ground truth. The user built the product, inspection misses what
the console does not show, and nobody sealed anything before the run. Observations never
enter a recall, false-positive or severity figure. A refuted finding is a defect candidate
and a `known, not reported` issue is a miss candidate; each is handled as an ordinary
defect, and fixing one makes no measured claim.

### Production-tenant safety

1. **A read-only credential only.** Whatever credential the Workspace collector requires
   ([workspace-collector.md](workspace-collector.md)), granted only the read scopes on its
   declared list and nothing broader; created for the run window and revoked after it
   (delegation removed, key deleted) where the credential's kind allows.
2. **Per-user mail surfaces stay off.** The Gmail forwarding reads and the mailbox tokens
   they need are off, unless the user authorizes specific mailboxes in
   `authorization.mailboxes` and each affected person has agreed beforehand. The optional
   per-user OAuth grant reads are on only by the user's decision for that run.
3. **Nothing from production enters the repository.** No production report, audit log,
   run directory, evidence file, fixture or golden is committed to this repository, to
   `docs/eval/` or to the lab's private repository: they hold real names, addresses and
   admin roles. What is recorded is aggregate counts or pseudonymized labels (`user-1`,
   `admin-2`), in `docs/eval/workspace-production-<YYYY-MM-DD>.md`, headed "observation,
   not measurement". The run directory stays on the user's machine and is deleted once
   that record is written.
4. **Announced.** The other super admins are told beforehand when the run happens, which
   principal it uses and that it only reads, so its activity is not mistaken for an
   intrusion.
5. **Checked after.** After every run, the admin audit log check above. Its result is part
   of the record.
6. **Few runs.** Each run has a stated purpose, written in the record before it starts,
   and the record counts the production runs made in the release.

### The reference catalog

Unseeded and unmeasured, kept for the reasons above. Severity is a practitioner's in a
company of 5 to 100 people.

| Id | Would be seeded | Severity | Evidence |
|---|---|---|---|
| F-GWS-01 | 2-step verification not enforced for the tenant, or not for the unit holding the admins | high (lower when sign-in is federated and the provider enforces it) | enforcement per unit |
| F-GWS-02 | a super admin not enrolled in 2-step verification | critical | `isEnrolledIn2Sv: false`, `isAdmin: true` |
| F-GWS-03 | super admins `k` of `n` users | medium to high | role assignments |
| F-GWS-04 | a departed person's account active, its `left` date past | high (critical when an admin) | user status and the engagement file |
| F-GWS-05 | a super admin not under `access.admins` and tied to no person | high | role assignments and the engagement file |
| F-GWS-06 | a suspended departed person still holding an admin role | low to medium | user status, role assignments |
| F-GWS-07 | a member (not an admin) not enrolled in 2-step verification | medium | enrollment |
| F-GWS-08 | an OAuth grant with full Drive or Gmail scope to a third-party app | high (critical when granted by a super admin) | user tokens and scopes |
| F-GWS-09 | automatic forwarding of a mailbox to an outside address | high | Gmail auto-forwarding settings |
| F-GWS-10 | a filter that forwards and skips the inbox or trashes | critical: the business-email-compromise pattern | Gmail filters |
| F-GWS-11 | a shared account (`it@`) holding an admin role | medium to high | the account, the engagement file |
| F-GWS-12 | a contractor holding a delegated admin role | medium | role assignments |
| F-GWS-13 | an account never signed in, created more than 30 days earlier | low to medium | `creationTime`, `lastLoginTime` |
| F-GWS-14 | domain-wide delegation to a service account with full Gmail or Drive scopes | critical | Admin console API controls |
| F-GWS-15 | a file shared with anyone who has the link | high | Drive sharing |
| F-GWS-16 | an app password in use | medium | per-user app passwords |
| F-GWS-17 | an admin's recovery email set to a personal address | medium | user recovery fields |

| Decoy | Would be seeded | Expected |
|---|---|---|
| D-GWS-01 | a break-glass super admin, declared, enrolled with a security key, rarely signs in | none |
| D-GWS-02 | a suspended departed person with no roles | none or info |
| D-GWS-03 | an OAuth grant with `openid email profile` only | none |
| D-GWS-04 | forwarding to an address on one of the tenant's own domains | none |
| D-GWS-05 | `info@` and `billing@` as Google Groups, not users | not counted as accounts |
| D-GWS-06 | a person with a `left` date after the run, still active | none |

## Fault catalog

### How to read it

Each entry is a **slot**: a subject the lab always creates, configured as the fault when
the seed turns the slot on and as a clean control when it is off. A bucket slot is always a
bucket; it is public or private. So every fault switched off becomes a negative control on
the same kind of subject, and false positives are measured where they would occur.

- **Id.** `F-<piece>-<nn>` for a fault, `D-…` for a decoy, `X-<nn>` for a cross-asset
  fault, `K-<nn>` for a context case, `S-<nn>` for a scope case. An id is never renumbered
  or reused; a retired id stays listed as retired, with why.
- **Severity** is what a practitioner assigns in a company of 5 to 100 people, on
  scheck's five levels, as a range in the answer key. The parenthesis says what context
  moves it and which way.
- **Evidence** is what proves the fault is present, as a read-only observer sees it. It is
  what the verify step confirms before sealing, not what scheck must read.
- **Class.** *Must*: a competent consultant finds it in the first days with read access;
  a miss counts against recall. *Should*: a good consultant finds it; recall is reported,
  not gated. *Hard*: it needs a read scheck does not make, a probe, runtime evidence or
  judgement across systems; the expected outcome is usually honest coverage (the area not
  marked checked, the item in the row's not-judged list), and these entries form the list
  the roadmap requires of issues no planned check finds. *Unmeasured*: not seeded, by
  decision or because the lab cannot hold it; never scored.
- **From** is the first release whose collectors read that asset kind, from the roadmap's
  release themes. Before it, the expected outcome is the area *not checked* with
  `collector_not_built`, and a miss is not a recall miss.
- **Decoys** are look-alikes that are not faults. Their severity range is usually *none*
  or *info*; a finding above the range is a false positive.

### GCP project

| Id | Seeded | Severity | Evidence | Class | From |
|---|---|---|---|---|---|
| F-GCP-01 | `roles/owner` bound directly to a persona's Google account (the contractor or ops persona) | high (critical when the person has left, X-01; medium when a declared admin on a project holding nothing declared to matter) | project IAM policy: `roles/owner` → `user:<persona account>` | must | 0.0.3 |
| F-GCP-02 | `roles/editor` on the default compute service account, granted explicitly | high (critical when a VM runs as it with an external address and the `cloud-platform` scope, F-GCP-13) | binding `roles/editor` → `serviceAccount:<number>-compute@developer.gserviceaccount.com` | must | 0.0.3 |
| F-GCP-03 | a user-managed key on a service account holding a broad role (param: Editor, Storage Admin, Cloud SQL Admin) | high (medium on a narrowly scoped account; D-GCP-02 is the look-alike) | key list: `USER_MANAGED`; the account's bindings | must | 0.0.3 |
| F-GCP-04 | a bucket readable by `allUsers` holding a generated customer export (CSV), not declared public | critical (high when the objects hold nothing declared to matter; info when declared public, K-01) | bucket IAM `allUsers: roles/storage.objectViewer`; object names | must | 0.0.3 |
| F-GCP-05 | a bucket readable by `allAuthenticatedUsers` | high (people read it as "our users"; it means any Google account) | bucket IAM `allAuthenticatedUsers` | must | 0.0.3 |
| F-GCP-06 | firewall rule from `0.0.0.0/0` to tcp 22 (param: and/or 3389) on every instance of the network | medium (high when a host behind it accepts passwords, X-03b) | ingress rule, `sourceRanges: 0.0.0.0/0`, no target tags | must | 0.0.3 |
| F-GCP-07 | firewall rule from `0.0.0.0/0` to a database or cache port (param: 5432, 3306, 6379, 9200, 27017, or a non-default port) aimed at the VM's tag | high (critical when a listener answers there, X-03) | ingress rule and the VM's tags | must | 0.0.3 |
| F-GCP-08 | Cloud SQL with a public IPv4 and authorized network `0.0.0.0/0` | high (critical when TLS is not required, F-GCP-09, or the instance is named in `data.matters_most`) | `ipConfiguration.ipv4Enabled`, `authorizedNetworks` | must | 0.0.3 |
| F-GCP-09 | Cloud SQL `sslMode: ALLOW_UNENCRYPTED_AND_ENCRYPTED` | medium with a public IP (low on private IP only) | `ipConfiguration.sslMode` | should | 0.0.3 |
| F-GCP-10 | Cloud SQL automated backups off | medium (high when the instance is named in `data.matters_most` and no other backup is declared) | `backupConfiguration.enabled: false` | must | 0.0.3 |
| F-GCP-11 | a personal Google account bound to a project role among company accounts | high (critical with Owner or Editor) | binding member under `gmail.com` | unmeasured: a project with no organization has no company accounts to contrast | 0.0.3 |
| F-GCP-12 | a persona granted `roles/iam.serviceAccountTokenCreator` or `serviceAccountUser` on a service account holding Owner or Editor | high: an escalation path nobody lists as "admin" | the account's own IAM policy and the project bindings | should | 0.0.3 |
| F-GCP-13 | the VM has an external address and runs as a service account with the `cloud-platform` scope | medium (high when that account is privileged, F-GCP-02) | instance `serviceAccounts[].scopes`, `accessConfigs` | should | 0.0.3 |
| F-GCP-14 | a canary API token in the VM's `startup-script` metadata | high | instance metadata, which the reader must redact | should | 0.0.3 |
| F-GCP-15 | a log exclusion on the `_Default` sink dropping a class of audit logs (param: Cloud Storage, Cloud SQL data access), or a member exempted in the audit config | medium (high for an exempted member: someone switched off logging of themselves) | sink exclusions; `auditConfigs[].exemptedMembers` | should | 0.0.3 |
| F-GCP-16 | the bucket declared to hold backups has no versioning and no retention, and the app's service account may delete objects | medium (high when declared the only backup) | bucket versioning, retention policy, IAM | should | 0.0.3 |
| F-GCP-17 | a Cloud Run service invokable by `allUsers`, declared internal | high, a contradiction of declared intent (info when declared public) | service IAM `allUsers: roles/run.invoker` | should | 0.0.3 |
| F-GCP-18 | a workload identity provider trusting GitHub Actions with no attribute condition on repository or owner | critical: any GitHub repository can obtain the account's access | provider `attributeCondition` empty, issuer `token.actions.githubusercontent.com` | hard | 0.0.3 |
| F-GCP-19 | a project-wide SSH key in metadata belonging to the departed persona, OS Login off | high | project metadata `ssh-keys`, `enable-oslogin` | hard | 0.0.3 |
| F-GCP-20 | project-level overrides of the secure-by-default organization constraints | medium (low when declared as a deliberate exception) | effective org policy on the project | unmeasured: no organization | 0.0.3 |
| F-GCP-21 | a disk image shared with `allAuthenticatedUsers` | high | image IAM policy | hard | 0.0.3 |
| F-GCP-22 | the project belongs to no organization: owned and administered by individuals' personal Google accounts. On in every seed | medium to high: the company does not control the identities that run its cloud, and offboarding depends on the owner's goodwill | project `parent` absent; the owners' bindings | should; constant, so it measures recall but never a false positive | 0.0.3 |

| Decoy | Seeded | Expected | Trap it sets |
|---|---|---|---|
| D-GCP-01 | a website bucket readable by `allUsers`, HTML and CSS only, declared under `intent.exposed_on_purpose` | none or info | "public bucket" without reading intent |
| D-GCP-02 | a user-managed key created at seed time on an account holding `roles/storage.objectViewer` on one bucket, declared | none to low | every key rated high, whatever it reaches |
| D-GCP-03 | firewall rule from `0.0.0.0/0` to tcp 80 and 443 on the VM tagged `web`, declared internet-facing | none | any `0.0.0.0/0` rule rated high |
| D-GCP-04 | Cloud SQL with a public IPv4, no authorized networks and `ENCRYPTED_ONLY` (connections only through the Cloud SQL Auth Proxy) | none to low | "public IP" read as "reachable" |
| D-GCP-05 | firewall rule from `35.235.240.0/20` (Identity-Aware Proxy) to tcp 22 | none | a wide range read as the internet |
| D-GCP-06 | Owner held by a Google Group of two declared admins, both enrolled in 2-step verification | none to low | every Owner binding rated high |
| D-GCP-07 | Google-managed service agents holding the roles they get by default | none | a Google-owned account counted as the company's |

Cost forces sharing: the lab has one Cloud SQL instance, so F-GCP-08, F-GCP-09, F-GCP-10
and D-GCP-04 are settings of one slot, and the seed picks a consistent combination.

### GitHub organization

| Id | Seeded | Severity | Evidence | Class | From |
|---|---|---|---|---|---|
| F-GH-01 | the organization does not require two-factor authentication (manual) | high (critical when an owner has no 2FA) | organization `two_factor_requirement_enabled: false` | must | 0.0.2 |
| F-GH-02 | a member persona without 2FA (manual; may not be seedable, "Pieces") | high (critical when an owner) | members filtered by `2fa_disabled` (owner-only read) | must | 0.0.2 |
| F-GH-03 | an owner not declared under `access.admins` and tied to no `people` entry | high | membership role `admin`; the engagement file | must | 0.0.2 |
| F-GH-04 | more owners than the work needs (param: 3 to 4 of 5 to 7 members) | medium | membership roles | should | 0.0.2 |
| F-GH-05 | base member permission `write` (param: or `admin`) | medium (high when any repository deploys to production) | organization `default_repository_permission` | must | 0.0.2 |
| F-GH-06 | default workflow token permission `write` at the organization | medium (high when a `pull_request_target` or comment-triggered workflow exists) | organization workflow permissions | must | 0.0.2 |
| F-GH-07 | default branch unprotected on a public repository declared `deploys_to: production` | high (low on a sandbox repository, D-GH-04; K-04) | no protection or ruleset on the default branch | must | 0.0.2 |
| F-GH-08 | protection that does not protect, on a public repository (param: no required review, admins exempt, force pushes allowed) | medium | protection fields | should | 0.0.2 |
| F-GH-09 | a `pull_request_target` workflow that checks out the pull request's head and runs its scripts, in a private repository only | high (critical in a public repository, which the lab never seeds) | the workflow file at the default branch | must | 0.0.2 |
| F-GH-10 | a third-party action at a mutable reference (param: tag, branch) in a workflow that reads secrets | medium (high in the deploy workflow) | `uses:` lines | must | 0.0.2 |
| F-GH-11 | a workflow with `permissions: write-all` (param: or `contents: write` with `id-token: write`) on an untrusted trigger | medium | the workflow file | should | 0.0.2 |
| F-GH-12 | an organization secret visible to all repositories, holding a deploy credential (canary) | high when any repository is public (medium otherwise) | organization secret `visibility: all` | must | 0.0.2 |
| F-GH-13 | a secret committed and deleted in the next commit (param detector: AWS key canary, Slack webhook, Stripe-format `sk_live_` string, GitHub token format) | high (critical when the repository is public and the secret live, which the lab never seeds) | commit, path and line in history | must | 0.0.2 |
| F-GH-14 | a secret at the head of the default branch in a config file | high | path at the head commit | must | 0.0.2 |
| F-GH-15 | an open provider secret-scanning alert | high | the alert | unmeasured: not seeded on the free plan (decided 2026-10-25) | 0.0.2 |
| F-GH-16 | an open Dependabot alert on a public repository, from a committed lockfile with a vulnerable version (param: package and version, chosen from advisories with a fixed version) | medium to high per advisory (high on a production repository with a critical advisory) | the alert | must | 0.0.2 |
| F-GH-17 | a deploy key with write access on a production repository | high | deploy key `read_only: false` | must | 0.0.2 |
| F-GH-18 | an outside collaborator with admin on a production repository | high | collaborators, affiliation `outside`, permission `admin` | must | 0.0.2 |
| F-GH-19 | a pending invitation to the departed persona, or to an address the team owns that is tied to no person | medium | organization invitations | should | 0.0.2 |
| F-GH-20 | a public repository holding infrastructure code, declared private in the engagement file | high, a contradiction of declared intent | repository visibility against the declaration | should | 0.0.2 |
| F-GH-21 | a runner group open to public repositories (a self-hosted runner registered and offline) | high | runner group `allows_public_repositories` | hard (unverified on the free plan) | 0.0.2 |
| F-GH-22 | a webhook to an endpoint outside the company, over http or without a secret | medium | repository webhooks | hard | 0.0.2 |
| F-GH-23 | a third-party GitHub App installed on all repositories with contents write (manual) | medium to high | installations and their permissions | hard | 0.0.2 |
| F-GH-24 | workflows from fork pull requests run without approval on a public repository | medium | repository Actions fork settings | hard | 0.0.2 |
| F-GH-25 | a canary secret printed in an Actions run log | high | run logs | hard | 0.0.2 |
| F-GH-26 | a ruleset bypass list on a public repository that includes the contractor persona | medium | ruleset bypass actors | hard | 0.0.2 |

| Decoy | Seeded | Expected | Trap it sets |
|---|---|---|---|
| D-GH-01 | a documented example credential in a test file (`AKIAIOSFODNN7EXAMPLE` and its documented secret) | none or info | a detector that cannot tell a documented example |
| D-GH-02 | a third-party action pinned to a full commit SHA with a version comment | none | the comment read as the reference |
| D-GH-03 | a `pull_request_target` workflow that only labels, never checks out, with `permissions: pull-requests: write` | none to low | every `pull_request_target` rated high |
| D-GH-04 | an unprotected default branch on an archived repository and on a sandbox with no `deploys_to` | none to low | protection demanded everywhere |
| D-GH-05 | an organization secret shared with selected repositories | none | every organization secret flagged |
| D-GH-06 | a declared break-glass owner with 2FA, under `access.admins` | none | owner count rules that ignore declarations |
| D-GH-07 | a Dependabot alert dismissed as "vulnerable code not used" | listed as dismissed, never open | dismissed read as open, or as fixed |
| D-GH-08 | commits by `dependabot[bot]` and `github-actions[bot]` | not counted as people | bots counted as unattributed members |
| D-GH-09 | a Stripe publishable key (`pk_test_…`) and a Firebase web config in a frontend repository | none or info | public-by-design keys reported as leaked |

### Domain, email and web

| Id | Seeded | Severity | Evidence | Class | From |
|---|---|---|---|---|---|
| F-DNS-01 | DMARC `p=none` on a domain that sends mail | medium | TXT `_dmarc.<d>` | must | 0.0.2 |
| F-DNS-02 | no DMARC record on a domain that sends mail (shares a slot with F-DNS-01) | medium | no TXT at `_dmarc.<d>` | must | 0.0.2 |
| F-DNS-03 | SPF ending `+all` (param: or `?all`) | high for `+all`, medium for `?all` | TXT at the apex | must | 0.0.2 |
| F-DNS-04 | SPF over ten DNS-querying terms | medium (the record fails, so receivers ignore it) | the SPF tree | should | 0.0.2 |
| F-DNS-05 | a declared sender missing from SPF | low to medium | SPF against `mail.senders` | should | 0.0.2 |
| F-DNS-06 | a domain that sends no mail without `v=spf1 -all`, DMARC `reject` or a null MX | medium: a favourite of spoofers precisely because nobody watches it | apex TXT, `_dmarc`, MX | must | 0.0.2 |
| F-DNS-07 | a declared DKIM selector with a 1024-bit key (param: or no record) | low for 1024-bit, medium for missing | TXT `<sel>._domainkey.<d>` | should | 0.0.2 |
| F-DNS-08 | a CNAME to a name that does not exist under the team's second domain (dangling) | medium | CNAME chain ending in NXDOMAIN | must | 0.0.2 |
| F-DNS-09 | a CNAME to `<org>.github.io` on a domain the lab organization verified, with no Pages site for that name (takeover candidate nobody else can claim) | high | CNAME and the provider's "no site" answer | must | 0.0.2 |
| F-DNS-10 | an A record to a static IP the team holds and attaches to nothing | low | A record; nothing answers | hard | 0.0.2 |
| F-DNS-11 | a private address in public DNS (`db-internal.<root>` → `10.x`) | low | A record | should | 0.0.2 |
| F-DNS-12 | a served name with a certificate for another name (param: or a self-signed expired certificate) | medium to high | the TLS handshake | must | 0.0.2 |
| F-DNS-13 | TLS 1.0 or 1.1 accepted | low | the handshake | should | 0.0.2 |
| F-DNS-14 | an MX pointing at a name that does not exist (a decommissioned mail provider) | medium | MX and its target's NXDOMAIN | should | 0.0.2 |
| F-WEB-01 | missing `Strict-Transport-Security` on a site under a TLD that is not preloaded | low; must rank below every medium and above | response headers | must | 0.0.2 |
| F-WEB-02 | a login form served over plain HTTP with no redirect | medium | the http response | should | 0.0.2 |
| F-WEB-03 | a session cookie without `Secure` or `HttpOnly` | low | `set-cookie` | should | 0.0.2 |
| F-WEB-04 | version disclosure in `Server` or `X-Powered-By`, not declared public | low (info when declared, D-WEB-01) | response headers | should | 0.0.2 |
| F-WEB-05 | a canary secret in a public page or JavaScript bundle | high | the response body, redacted | must | 0.0.2 |
| F-WEB-06 | `/.git/` served | high (critical when its history holds a secret) | `GET /.git/HEAD` | must when probes are authorized; *not checked* otherwise | 0.0.3 |
| F-WEB-07 | `/.env` served, holding canaries | critical | `GET /.env` | must when probes are authorized; *not checked* otherwise | 0.0.3 |
| F-WEB-08 | `/admin` declared under `intent.not_exposed`, reachable from the internet | high, a contradiction of declared intent (abstains with `--vantage vpn`, K-03) | the response from an internet vantage | must | 0.0.2 |
| F-WEB-09 | a directory listing holding a generated `backup.sql.gz` | high | the listing | hard (probe or scan) | 0.0.3 |
| F-WEB-10 | no `security.txt` | info, counted and not gated | `/.well-known/security.txt` | should | 0.0.2 |
| F-WEB-11 | a framework debug page on a staging name | high | the response | hard (probe) | 0.0.3 |
| F-WEB-12 | an API reflecting any `Origin` with credentials allowed | medium | CORS headers to a crafted origin | hard (not read) | none planned |

| Decoy | Seeded | Expected | Trap it sets |
|---|---|---|---|
| D-WEB-01 | a version-revealing `/status` page declared public on purpose | info at most (E3's context case) | intent ignored |
| D-WEB-02 | `/admin` declared exposed on purpose, behind an SSO login | none or info | every admin path rated high |
| D-WEB-03 | missing HSTS on a site under `.page`, only when a seed declares a `.page` root | none | preloaded TLDs ignored |
| D-WEB-04 | a publishable key in a page (`pk_live_…`) | none or info | public-by-design keys reported |
| D-DNS-01 | a domain that sends no mail, locked down (null MX, `-all`, DMARC `reject`) | none | "no MX" read as broken |
| D-DNS-02 | DMARC `p=quarantine`, `pct=100`, with `rua` | none to low | anything short of `reject` rated medium |
| D-DNS-03 | a CNAME to a SaaS that serves the name (claimed) | none | every third-party CNAME read as a takeover |
| D-DNS-04 | a wildcard record to a live site | no takeover finding per name | wildcard names judged one by one |
| D-DNS-05 | SPF `~all` with DMARC `reject` | none | `~all` rated alone |

### Hosts

| Id | Seeded | Severity | Evidence | Class | From |
|---|---|---|---|---|---|
| F-HOST-01 | `PasswordAuthentication yes` (param: in the main file, in an `sshd_config.d` drop-in, or left to a distribution default that allows it) | medium (high when the host is declared or found internet-facing, K-05, X-03b) | the effective sshd configuration | must | 0.0.2 |
| F-HOST-02 | `PermitRootLogin yes` | medium (high when internet-facing) | the effective sshd configuration | must | 0.0.2 |
| F-HOST-03 | an account with an empty password and a login shell, with `PermitEmptyPasswords yes`; local host only | critical | shadow entry, shell, sshd setting | must | 0.0.2 |
| F-HOST-04 | a database or cache listening on all interfaces with no host firewall rule (param: postgres, mysql, redis, mongodb; port default or not) | high (critical for redis or mongodb without authentication) | listeners and firewall rules | must | 0.0.2 |
| F-HOST-05 | the host firewall inactive while services other than the web server listen | medium | firewall status and listeners | must | 0.0.2 |
| F-HOST-06 | the Docker socket mode `0666` (param: or a non-admin user in the `docker` group, should) | high: root on the host for whoever can reach it | socket mode, group membership | must | 0.0.3 |
| F-HOST-07 | the Docker API on tcp 2375 without TLS on all interfaces | critical (high when a cloud firewall in front blocks the port, which the cloud host shows) | listener | must | 0.0.3 |
| F-HOST-08 | a world-readable `.env` in the app's directory, holding a database URL with a password (not the database's real one) and canary keys | high | file mode, path, redacted content | must | 0.0.3 |
| F-HOST-09 | cloud CLI credentials readable beyond their owner (param: `~/.config/gcloud/application_default_credentials.json`, `~/.aws/credentials`) | high | file mode and path | should | 0.0.3 |
| F-HOST-10 | `~/.git-credentials` with a token, or a `.pgpass` readable by others | high | file mode and path | should | 0.0.3 |
| F-HOST-11 | a private SSH key with mode `0644` | medium | file mode | should | 0.0.3 |
| F-HOST-12 | `NOPASSWD: ALL` for the deploy or app user | medium (high when that user's credentials sit where the web app can read them) | sudoers | should | 0.0.3 |
| F-HOST-13 | security updates pending, with a package held back (param: openssl, openssh-server, nginx) | medium (high for the package of an internet-facing service) | package manager's pending list | must | 0.0.2 |
| F-HOST-14 | an end-of-life PHP or Node.js line serving the app (param: PHP 7.4 or 8.0, Node 16 or 18) | high when internet-facing (medium internal) | installed packages | must | 0.0.3 |
| F-HOST-15 | a supported PHP or Node.js line missing a dated security fix | medium to high | installed package version against the distribution's fixed version | should | 0.0.3 |
| F-HOST-16 | root's `authorized_keys` holding the departed persona's key (its comment names the persona) | high | `authorized_keys` | hard | none planned |
| F-HOST-17 | a SUID copy of `find` or an interpreter | high | file mode | hard | none planned |
| F-HOST-18 | a root cron job running a world-writable script | high | crontab, file mode | hard | none planned |
| F-HOST-19 | a database port published by Docker, which bypasses the host firewall | high | container port bindings | hard | none planned |
| F-HOST-20 | reboot required: the running kernel older than the installed one | low | kernel version, installed packages | should | 0.0.2 |
| F-HOST-21 | no audit daemon and no log forwarding | low | service status | should | 0.0.2 |
| F-HOST-22 | automatic security updates switched off | low | unattended-upgrades or dnf-automatic configuration | should | 0.0.2 |

| Decoy | Seeded | Expected | Trap it sets |
|---|---|---|---|
| D-HOST-01 | a distribution security build under an old upstream version (an Ubuntu `…ubuntu0.N` OpenSSH or PHP build with the fix backported) | none | upstream version numbers compared without the distribution's fix data |
| D-HOST-02 | a world-readable configuration file holding no secret (ports, log level) | none | every world-readable file flagged |
| D-HOST-03 | a `.env` with mode `0600` under a `0700` home, holding placeholder values | none or info | every `.env` flagged |
| D-HOST-04 | a database on all interfaces with a host firewall rule allowing only an internal range | none | listeners judged without the firewall |
| D-HOST-05 | nginx on `0.0.0.0:443`, declared internet-facing | none | every public listener flagged |
| D-HOST-06 | `PasswordAuthentication yes` only inside a `Match Address 10.0.0.0/8` block, `no` globally | no finding on the global setting (abstaining is acceptable) | Match blocks read as global |
| D-HOST-07 | system accounts with a locked password (`!` or `*`) and a `nologin` shell | none | locked read as empty |
| D-HOST-08 | `NOPASSWD` for one fixed command (`systemctl restart app`) | none to low | every `NOPASSWD` rated as `ALL` |
| D-HOST-09 | public keys (`id_ed25519.pub`) with mode `0644` | none | public keys read as private |

### Cross-asset

Every surviving case stands on GitHub, GCP, the domains and the hosts. A case's Workspace
leg, where it had one, is unmeasured.

| Id | Seeded | Severity | Evidence | Class | From |
|---|---|---|---|---|---|
| X-01 | one departed persona (a past `left` date) still a GitHub member with admin on a production repository, and still holding a GCP project role; the hard leg, their key in project metadata (F-GCP-19) or root's `authorized_keys` (F-HOST-16). The Workspace leg is unmeasured | critical | F-GH-18 or membership with admin, and F-GCP-01, on one `people` handle | must per asset; should as one person item; the GCP link should | 0.0.2 GitHub; 0.0.3 GCP and link |
| X-02 | a service account key JSON committed in a private repository's history whose `private_key_id` and `client_email` name an active user-managed key of a privileged service account. The `private_key` in the file is a different, random key, so the file does not work | critical, as a practitioner rates a committed key that IAM still lists | the committed file's key id equals a key id in the key list | must as a secret; should as the link | 0.0.2 secret; 0.0.3 link |
| X-03 | the cloud host's database listens on all interfaces, the host firewall has no rule for it, and a GCP firewall rule allows `0.0.0.0/0` to that port on the VM. The database takes a long random password, SCRAM only, and generated data | critical | F-HOST-04 and F-GCP-07 on the same host and port | must per asset; should as the link | 0.0.2 host; 0.0.3 cloud and link |
| X-03b | password SSH on the cloud host with a `0.0.0.0/0` rule on tcp 22. Never combined with F-HOST-03 | high | F-HOST-01 and F-GCP-06 | should | 0.0.3 |
| X-04 | a deploy workflow authenticating to GCP with a long-lived key stored as an organization secret visible to all repositories | high | F-GH-12, the workflow, F-GCP-03 | should | 0.0.3 |
| X-05 | F-GCP-18 with a workflow in the organization that uses that provider | critical | the provider and the workflow's `google-github-actions/auth` step | hard | 0.0.3 |
| X-06 | retired 2026-10-25: a Workspace super admin without 2SV who is also project Owner. Workspace-dependent; replaced by X-09 | — | — | unmeasured | — |
| X-07 | the website bucket (D-GCP-01) also holds a `backups/` prefix of generated exports | high: a declared-public bucket holding what nobody meant to publish | bucket IAM and object names | should | 0.0.3 |
| X-08 | a host credential file holds a GitHub token for a production repository (provider format, never valid) | high | F-HOST-10 and the repository | hard | none planned |
| X-09 | one `people` entry whose GitHub login is an organization owner and whose Google account holds project Owner (F-GCP-01), while `access.admins` names them as an admin of neither | critical: one person nobody listed as an admin holds both the code and the cloud | membership role and the project binding, joined through the `people` entry | should | 0.0.3 |
| X-10 | the cloud host's site discloses its runtime (F-WEB-04) and that runtime is an end-of-life PHP or Node line on the host (F-HOST-14) | high: the outdated runtime is announced to anyone who asks | the header and the installed package on one host | should | 0.0.3 |

### Context cases

The same infrastructure is run with two engagement files that differ in one declaration.
Each case states the expected finding in both runs; the context gate is the difference.

| Id | Declaration varied | With it | Without it |
|---|---|---|---|
| K-01 | the website bucket under `intent.exposed_on_purpose` | none or info | high |
| K-02 | `/status` declared public on purpose; a canary secret on the same site | `/status` info; the secret keeps its severity | `/status` low; the secret unchanged |
| K-03 | `/admin` under `intent.not_exposed`; run with `--vantage internet`, then `--vantage vpn` | internet: high, a contradiction; vpn: abstains | no contradiction claimed |
| K-04 | a repository declared `deploys_to: production` | unprotected default branch high | medium or low |
| K-05 | the host declared internet-facing against `lan` | password SSH high | medium |
| K-06 | the Cloud SQL instance named in `data.matters_most` | backups off high; the readout names it | medium |
| K-07 | the departed persona's `left` date in the past against a date after the run, for their GitHub membership | a finding | no finding |
| K-08 | unmeasured (Workspace): sign-in declared federated through another identity provider | — | — |
| K-09 | unmeasured (Workspace): the operator declares 2-step verification enforced, which it is not | — | — |
| K-10 | a GitHub owner omitted from `access.admins` | the unattributed-owner finding | the owners counted without attribution |

### Scope cases

| Id | Seeded | Expected |
|---|---|---|
| S-01 | an excluded repository holding a canary secret | no request names it in scheck's audit log; no finding cites it; the report lists it as excluded |
| S-02 | unmeasured (Workspace): an excluded organizational unit | — |
| S-03 | an excluded subdomain served by a lab web server whose access log is watched | zero requests from scheck in that log |
| S-04 | a second VM in the project, neither declared nor under a root | zero connections in its sshd and web logs |
| S-05 | unmeasured: an excluded project under a folder or organization root; the lab project has no organization | — |
| S-06 | a CNAME under a root pointing to a name under a domain outside every root, with a server the team watches | no HTTP request to that server by the outside name |
| S-07 | the production Workspace root declared with the credential withheld; nothing is sent to the tenant | Identity and access marked from what was read, with `no_credentials`; never *checked*; the exit code as [report.md](report.md) defines for a declared root unassessed. A coverage-honesty check, not a Workspace measurement |
| S-08 | the GCP credential withheld on the lab project | Cloud configuration *not checked* with `no_credentials`; nothing sent to the project (its Data Access logs show no read by any scheck principal) |

### Change sets

A change-set pair is two seeds of one lab, A and B, where B is A with a sealed change list
applied. Both runs use the same engagement file, unless the change is a context change.
Every pair holds at least:

| Change | Minimum | Expected comparison |
|---|---|---|
| fixed: a fault on in A, off in B on the same subject | 2 | fixed |
| new: off in A, on in B | 2 | new |
| still open | 2 | still open |
| moved between assets: the same secret file moved from one repository to another, or the same listener from the local host to the cloud host | 1 | moved, never fixed plus new (G6) |
| asset re-addressed: the cloud host recreated at a new IP with the same host identity | 1 | the same asset, moved |
| severity changed by context only (an engagement-file edit) | 1 | changed severity, never fixed plus new |
| decoy unchanged | 1 | nothing |

No change-set case uses Workspace. The change list is part of the sealed key of B, with
each record's expected comparison class.

### Private extras

The seeder adds faults that are not in this catalog, from their own experience of small
companies, implemented in the private lab repository ("Layout") and sealed with the key:
at least three, or 15% of the present faults, whichever is more, and at least one per piece
where the piece allows it. At least half should be ones the seeder expects no planned
check to find. Extras are scored as their own population, so the record can show whether
scheck generalizes beyond the published catalog. After scoring they are revealed with the
key and join the catalog as new ids, which is how the catalog grows. No extra is a
Workspace fault.

### Not seedable

Recorded here so no record implies they were measured:

- Every Workspace fault, decoy and case: there is no Workspace lab.
- A personal account among company accounts (F-GCP-11), organization-policy overrides
  (F-GCP-20) and an excluded project under a wider root (S-05): the lab project has no
  organization.
- Secret-scanning alerts (F-GH-15): not on the free plan.
- A service account key older than 90 days in a project that lives for a gate run. Only a
  persistent project can age a key (open).
- A real takeover of a third-party name, and a working leaked credential. Both are
  forbidden by "Rules that never change"; X-02 and F-DNS-09 observe the same way and
  cannot be abused.
- Malware, infostealers or stolen sessions on a host: outside scheck ([report.md](report.md),
  "Coverage").
- The registrar and DNS-hosting accounts' sign-in and 2FA: nothing reads them.
- Spoofed mail actually delivered: the lab sends no mail.

## Seeding

### Seed to variables

A seed is 32 bytes from a cryptographic random source, generated by the seeder and kept
only in the sealed bundle. The generator is public, deterministic code in `lab/seed`: the
same `CATALOG_VERSION`, `GENERATOR_VERSION` and seed always give the same variables, so
anyone can re-derive the lab from the revealed seed and check the key.

From the seed the generator derives, in this order:

1. **Which slots are on.** Each slot is on with the probability of its class: must 0.75,
   should 0.6, hard 0.5; decoys 0.8. Must-find slots are randomized too, so a must-find
   switched off is a negative control on its own subject. Constant entries (F-GCP-22) are
   always on; unmeasured entries are never on.
2. **Parameters.** Each catalog entry declares closed parameter domains: names (personas,
   repositories, buckets, subdomains) drawn from word lists, ports, engines, counts, the
   form of a fault (`PasswordAuthentication` in the main file or a drop-in; `+all` or
   `?all`), the detector type of a canary, the distribution of the local host. Global
   names (the project id, bucket names) carry a seed-derived suffix.
3. **Realization variants.** Where a fault can be written several ways a real admin would
   write it, the generator picks one, so a check matched to one literal form misses the
   others.
4. **Engagement files.** The seeded engagement file and, for each context case drawn, its
   counterpart differing in one declaration. No lab engagement file names the production
   Workspace tenant.

The generator writes `faults.auto.tfvars.json` (switches and parameters per module), the
manual checklist for this seed, the engagement files, and the key skeleton.

### Constraints

The generator enforces constraints, and refuses a seed it cannot satisfy rather than
dropping one silently:

- **Safety exclusions.** F-HOST-03 only on the local host. F-GH-09 only in a private
  repository. No `0.0.0.0/0` rule on tcp 22 to a host with an empty-password account. No
  public repository holds anything but canaries and documented examples.
- **Dependencies.** X-03 needs F-HOST-04 and F-GCP-07 on the same host and port. X-10
  needs F-WEB-04 and F-HOST-14 on the cloud host. F-GH-02 needs F-GH-01 (requiring 2FA
  removes members without it). X-01 and X-09 need the persona in GitHub and in the GCP
  project.
- **Plan.** Every protection slot and every alert slot is on a public repository.
- **Shared slots.** One Cloud SQL instance (F-GCP-08 to F-GCP-10, D-GCP-04); one DMARC
  record per domain (F-DNS-01, F-DNS-02, D-DNS-02).
- **Mix.** Every piece in the lab has at least two must-find faults on, at least one off,
  at least two decoys, and at least one clean control. Across a change-set pair every
  must-find slot is on in at least one of A and B.
- **Sticky slots.** A slot whose flip is manual and slow (GitHub's 2FA requirement, a
  GitHub App install) is drawn once per release cycle and kept for both seeds of a pair.
  Its value is still sealed.

### The clean variant

The clean variant has every fault slot off and every decoy on. It is the baseline the
false-positive target is fixed against ([ROADMAP.md](../ROADMAP.md), E3). Destroyable
pieces get their own clean instance (a second project on the same billing account, a
second set of repositories, a second domain root). The GitHub organization's own settings
cannot be seeded and clean at once, so their clean variant is the same organization reset
and run at a different time.

### Verify before sealing

Before the key is sealed, a verify step reads every slot back through the providers with
the seeder's own admin credentials, never scheck's, and records for each record whether
its evidence is present (`verified_present`) or absent (`verified_absent`), and when. It
waits for asynchronous state (Dependabot alerts, DNS propagation, certificate issuance) up
to a fixed limit. A slot that could not be seeded, or whose state did not appear, is
marked `not_seeded` with the cause, in the key, before sealing. It is never dropped
silently and never scored. Manual steps are confirmed the same way: the checklist is not
evidence, the read-back is.

## Ground truth

### The answer key

The key is one JSON document per seed (`labels.json`), canonical: UTF-8, keys sorted, no
insignificant whitespace, one trailing newline. It holds one record per slot (on or off),
per decoy, per cross-asset, context and scope case, and per private extra. Unmeasured
entries are listed with `"kind": "unmeasured"` so the key shows the gap.

```json
{
  "key_version": 1,
  "lab_version": "…", "catalog_version": "…", "generator_version": "…",
  "seed": "<64 hex; present only in the sealed and revealed copy>",
  "part": "gcp", "variant": "seeded", "pair": {"name": "…", "run": "A"},
  "sealed_by": {"kind": "agent", "model": "…", "session": "…"},
  "engagement_files": [{"name": "engagement.yaml", "sha256": "…"}],
  "assets": [{"id": "cloud:gcp:lab-k3x9q", "piece": "gcp", "in_scope": true, "excluded": false}],
  "workspace": "exercised read-only on a real tenant, not measured",
  "records": [{
    "record": "F-GCP-04#1",
    "entry": "F-GCP-04",
    "kind": "fault",
    "present": true,
    "class": "must",
    "from": "0.0.3",
    "asset": "cloud:gcp:lab-k3x9q",
    "subject": {"key": "acme-exports-7f2c", "also": ["gs://acme-exports-7f2c"]},
    "area": "cloud",
    "areas_also": ["data"],
    "severity": {"min": "high", "max": "critical"},
    "context": [{"engagement": "engagement-k01.yaml", "severity": {"min": "none", "max": "info"}}],
    "evidence": "bucket IAM: allUsers holds roles/storage.objectViewer",
    "params": {"objects": 3},
    "comparison": null,
    "seeded_by": "tofu",
    "verify": {"state": "verified_present", "at": "2026-11-02T10:14:03Z"}
  }],
  "ranking": {"by": "…", "top5": ["X-01#1", "…"]},
  "fp_target": {"…": "…"},
  "thresholds": {"…": "…"}
}
```

- `kind` is `fault`, `decoy`, `control` (a fault slot off), `cross`, `context`, `scope`,
  `extra` or `unmeasured`.
- `asset` is the canonical id the report uses ([report.md](report.md), "Findings"). GCP's
  form is fixed by G1; until then the key builder writes `cloud:gcp:<project>` as
  [scope.md](scope.md) declares the root, and the scorer accepts the bound id beside it.
- `subject.key` is what the lab named: an address, a repository, a bucket, `port/proto`, a
  DNS name, a URL, a path. The key does not name scheck's finding ids or subject kinds;
  the author of the key does not know them, and must not need to.
- `area` is one of the report's ten area keys ([report.md](report.md), "Coverage");
  `areas_also` lists areas a practitioner would also accept.
- `severity` uses `none`, `info`, `low`, `medium`, `high`, `critical`. A decoy's range
  usually starts at `none`.
- `comparison` is set in seed B of a pair: `fixed`, `new`, `still_open`, `moved` (with
  `moved_from`), `changed_severity`, or `unchanged`.

### Producing it

The key is produced from the generator's output and OpenTofu, never typed by hand:

1. The generator writes the key skeleton: every record with its entry, class, area,
   severity range, subject name and parameters.
2. `tofu apply` builds the lab; each slot's module exports its resolved identifiers
   (project id, external addresses, repository full names, key ids) as outputs.
   `tofu output -json` is joined into the skeleton to fill `asset` and `subject`.
3. The manual checklist is worked; the verify step fills `verify` on every record.
4. The seeder adds the private extras, the ranker's top five (below) and the frozen
   false-positive target and thresholds.

The key is built from outputs and read-backs, not from state, so the key never carries a
password, a private key or a token that state holds.

### Sealing

1. **Seal.** The sealed bundle is the key, the seed, the private extras' code, the
   generated engagement files and the blind ranking, as one archive. Its SHA-256 is taken
   over the canonical key and over the archive. The archive is encrypted with `age` to two
   recipients: the user's key, kept in the user's password manager, and a second holder's
   (decided 2026-10-25). It is stored in a private repository (decided 2026-10-25). The
   repository may be readable by the credentials implementing sessions use; the bundle is
   encrypted, and no implementing session holds either `age` key. Nothing readable from it
   is committed to this repository.
2. **Record.** A record `docs/eval/lab-<part>-<YYYY-MM-DD>.md` is committed and pushed
   before any scheck run against the seed. It holds: both hashes; where the bundle is; the
   encryption recipients; `LAB_VERSION`, `CATALOG_VERSION`, `GENERATOR_VERSION`, the lock
   file's hash and the lab code's commit; the seeder (person, or agent and model id) and
   the ranker likewise; the time of sealing; the counts of records by kind and class
   (counts reveal no slot); the number of private extras and how many the seeder expects
   no planned check to find; the frozen false-positive target and thresholds; the line
   "Workspace: exercised read-only on a real tenant, not measured"; and the first slice or
   run it is sealed before. The record cites
   [eval/lab-0.0.2-domain.md](../eval/lab-0.0.2-domain.md) as the pattern.
3. **Run.** Only the first scheck run against a sealed seed is scored for recall. Every
   run against it is listed in the result record, debugging runs included.
4. **Fix the report before opening the key.** The run's `report.json` and `audit.jsonl`
   are hashed and their hashes committed before the bundle is decrypted. Lab reports hold
   only lab personas and fake data, so they may be committed; production reports never are.
5. **Reveal.** The bundle is decrypted, the key committed in clear beside the result
   record, and its hash checked against the sealed one. A seal proves nothing until its
   preimage is shown; a revealed seed is burned for gating and becomes a development seed.

**The blind ranking.** For the prioritization gate the ranker reads the key and the
engagement file (not the collector code), has seen no scheck output for this lab, and
writes a top five, which is sealed in the same bundle.

### Late and not blind

A seal is labelled in its record, as the 0.0.2 domain record already does:

- **Not blind** when the seeder read collector, rule or fixture code, wrote checks for the
  release, or is the implementing session or its subagent. Recall then shows that scheck
  finds what it was built to find, not a measurement.
- **Late** when sealed after the first commit of the slice it measures (ROADMAP, "The lab
  comes before the checks it measures"). The record names the slice and the commit it
  should have preceded. A later seal cannot repair a missed one; it dates the measurement,
  nothing more.
- **Contaminated** when anyone who implements checks read the key, the seed, the bundle,
  the lab's state, or looked at the seeded lab's assets by hand before the reveal. The
  record says who and when, and the gate is recorded as not run.

Today: the domain part is not blind (`eval/lab-0.0.2-domain.md`); the rest-lab seal for
E5 and E6 was missed (`eval/e6-definition-2026-10-10.md`), and E6's will never exist now
that there is no Workspace lab; the host-depth slices G5 and G8 have landed on
`release/v0.0.3` with no seal, so host-depth faults sealed now are late for them. The GCP
part is to be sealed before G1's first commit (decided 2026-10-25).

### Who may produce it

Decided 2026-10-25:

- The **seeder** is an AI agent in a fresh session that has never read `internal/`,
  `testdata/`, `test/`, the rule lists in `AGENTS.md`, or any earlier unrevealed key, and
  that writes no check; its model is named in the seal record. It may read
  [VISION.md](../VISION.md), [ROADMAP.md](../ROADMAP.md), [engagement.md](engagement.md),
  [scope.md](scope.md), this file, and the public `lab/` code. It is never a subagent of
  an implementing session (AGENTS.md, `security-consultant`, seed mode).
- The **ranker** is the user, if the user wrote none of the checks being ranked;
  otherwise the prioritization gate is recorded as *not run*. The ranker has seen no
  scheck output for the lab.
- The **adjudicator** of unlabelled findings ("Matching") is the user.
- The **implementing sessions** may read this file and the public `lab/` code, and run
  scheck against the clean variant and revealed development seeds. They get no credential
  to the seeded lab beyond scheck's own run principal, and do not run against a sealed
  seed before its scored run.
- The **scorer** is code.

## Scoring

### Matching

The scorer reads the run's `report.json`, the revealed key and the audit evidence. It
matches findings to records:

1. A finding **matches** a record when its `area` is the record's `area` or in
   `areas_also`, its `key.asset` (or `bound_id`) equals the record's `asset`, and its
   subject's `key`, `label` or `provider_id` equals `subject.key` or one of
   `subject.also`, compared case-insensitively. A record without a subject matches an
   asset-wide finding in its area.
2. A record with `present: true` is **found** when at least one open or accepted finding
   matches it. Its severity is **in range** when the highest matching finding's severity
   (after context) lies within the record's range for that run's engagement file.
3. A record that is a decoy, a control, or a fault with `present: false` is a **false
   positive** when a matching finding is above its range's maximum (for a control, above
   `none`). Info findings are counted apart.
4. A finding that matches no record is **unlabelled**. The adjudicator classifies it as a
   true issue nobody seeded (a defect of the lab's clean baseline, which the lab then
   fixes) or a false positive. The classification and who made it go in the record.
5. A record with `verify.state` other than `verified_present` or `verified_absent`, or of
   kind `unmeasured`, is not scored.

### Measures

| Measure | Computed as |
|---|---|
| must-find recall | found ÷ present must-find records whose `from` the release reaches, per area and overall |
| should-find recall | the same over should-find records; reported, not gated |
| private-extra recall | the same over extras; reported apart |
| hard-case honesty | of present hard records, the share whose area is not marked *checked* or whose row's not-judged list names the item; the item match is adjudicated, since the key does not know scheck's item ids |
| false positives | count at low and above, per area, over decoys, controls and the clean variant; info apart |
| severity in range | in-range ÷ found |
| coverage overclaim | an area marked *checked* that holds a present, missed must-find or should-find record; an excluded asset not listed as excluded; an asset kind with no collector not marked `collector_not_built`; on a production Workspace run, a Workspace sub-item marked checked when its rule did not decide |
| context | for each measured K case, both runs as the table states |
| writes | `tofu plan -refresh-only -detailed-exitcode` on every destroyable piece after the run exits 0 (no drift), having exited 0 before it; GCP Admin Activity audit log entries with scheck's principal as caller: zero (Admin Activity logs record only writes); GitHub organization audit log entries with scheck's credential as actor: zero; the local host's file tree and package database unchanged outside the documented allowlist ([host-collector.md](host-collector.md) §1); on a production Workspace run, the tenant's admin audit log events by scheck's principal: zero |
| scope | measured S cases as the table states; every request in scheck's audit log has a target under a root and not excluded |
| comparison | each pair's records classified as their `comparison` field says |
| prioritization | how many of the ranker's top five are in scheck's top five |

`tofu plan` sees only attributes the modules manage, so it is the cheap first check, and
the provider audit logs are the ones that count. GitHub does not log reads of private
repositories outside Enterprise plans, so S-01 rests on scheck's own audit log and the
report.

### Gate thresholds

Decided 2026-10-25, frozen in the first seal record and carried to every later seal as
the baseline. Changing one needs a decision recorded before the seal it applies to.

| Gate | Threshold |
|---|---|
| recall | at least 90% of present must-find records, **per area**, in areas the release reads; every miss recorded as a miss before any check is added to fix it |
| false positives | at most one finding at low or above **per area** on decoys, controls and the clean variant |
| coverage | zero overclaims |
| writes and scope | zero, without exception |
| context | every measured K case as stated |
| prioritization | at least four of five (ROADMAP, 0.0.2 gate 5), or *not run* when the user wrote checks |
| comparison | every pair record classified as stated |
| Workspace | no threshold: "exercised read-only on a real tenant, not measured" |

With fewer than ten present must-find records in an area, 90% means none may be missed;
the record says so beside the area's figure. The generator's mix rule keeps at least two
present per piece, which is not enough to tell 90% from 100%; the threshold is a floor,
not a precision claim.

### The result record

One record per scored run, appended to `docs/eval/` as `lab-<part>-results-<YYYY-MM-DD>.md`
with a JSON twin. It holds: the seal record it scores and both hashes, checked against the
revealed key committed beside it; scheck's version and commit; the hashes of `report.json`
and `audit.jsonl` committed before the reveal; the engagement files and vantage of each
run; every run made against the seed; the measures above, per area, with each miss and
false positive listed by record id, asset and subject; the unlabelled findings and their
adjudication; the write and scope evidence (commands run, filters, counts); the
comparison result for a pair; the ranking agreement or *not run*; the seal's labels (blind
or not, late or not, contaminated or not) repeated beside every number; whether the run is
a development measurement or the v1.0.0 gate; the line "Workspace: exercised read-only on
a real tenant, not measured", with a link to any production observation record of the same
release; and who ran, scored and adjudicated, with model ids for agents. A gate that could
not be run is recorded as *not run* with the reason, never as passed.

## Safety, cost and lifecycle

### Isolation

- A dedicated GCP project with no organization, on a dedicated billing account with a
  budget of about 50 dollars (`google_billing_budget`, alerts at 50, 90 and 100% to two
  named people), every resource labelled `scheck-lab=true`, `lab-seed=<first 8 hex of the
  key hash>`, `expires=<date>`.
- A dedicated GitHub organization and dedicated domains. Persona accounts belong to the
  lab only. No production identity, Workspace or other, is a member of any lab asset.
- scheck's read principal for each piece is created for the lab and has no rights outside
  it.
- The OpenTofu state bucket is in a separate admin project, outside every lab root and
  unreadable by scheck's principals: state holds the seeded keys and passwords, and its
  object names would reveal the seed to a run that could list them. State is also
  encrypted client-side with OpenTofu's state encryption, its key held by the seeder's
  operator, not by implementing sessions.

### Data and secrets

Every "secret" is one of: a canary token (Thinkst canarytokens or the team's own
equivalent) that alerts when used and grants nothing; a provider-format string with no
account behind it; or a documented example value. The only real credentials in the lab
are the providers' own seeding credentials (environment only) and the database passwords
of X-03 (long, random, in state only). The X-02 key file, the host's credential files
(F-HOST-08 to F-HOST-10, X-08) and every committed secret are built not to work. Customer
exports, payroll files and table rows are generated, with addresses under `example.com` or
`.test`.

### Third parties

- Public buckets and public repositories hold fake data and canaries only.
- No seeding step sends mail to anyone outside the team. DMARC `rua` addresses point at a
  mailbox the team owns, or are omitted.
- DNS records exist only in domains the team owns; dangling targets only under the
  team's second domain; takeover candidates only on a provider that verified the team's
  ownership (E3).
- Canary alerts fired by bots that scrape public repositories are expected noise, not an
  incident; the canary's alert address is a mailbox the team owns.

### Lifetime and teardown

- Destroyable pieces (the GCP project's resources, repositories, DNS records, hosts) are
  applied for a run and destroyed after it; the target lifetime is under 48 hours.
- Persistent pieces (the GitHub organization's own settings and personas, the domains)
  are reset to the clean baseline: invitations cancelled, extra roles removed, apps
  uninstalled.
- **After an aborted run**, the operator runs the lab's `down` entry point: `tofu destroy`
  per piece in reverse dependency order, retried with `-refresh=false` when a provider
  call fails, then the reset script for the persistent pieces, then a sweep that lists
  every resource labelled `scheck-lab=true` on the billing account and every lab DNS
  record, and prints what is left. Cloud SQL is created with `deletion_protection =
  false` so destroy can remove it. The last resort is deleting the project, which stops
  billing and is reversible for 30 days.
- A production Workspace run leaves only a local run directory, deleted once its
  aggregate record is written, and a credential revoked after the run.

### Cost

Order of magnitude per month if left running; list prices not verified at writing time.

| Piece | Cost | Note |
|---|---|---|
| GCP | tens of dollars running; under a dollar per run; capped by the 50-dollar budget | **the expensive piece**: Cloud SQL in its smallest tier is most of it, then the VM and its external address. Destroying after each run keeps it near zero |
| GitHub | zero on the free plan | Team (about 4 dollars per seat) later, by decision |
| Domain, email and web | about 2 dollars (two domains at 10 to 15 dollars a year; DNS free on Cloudflare) | |
| Hosts | zero locally; the VM is counted under GCP | |

## Layout

The lab's public code lives in `lab/` in this repository. The private parts (the private
extras' modules and the sealed bundles) live in a private repository, and the bundles are
encrypted.

```text
lab/
  README.md              how to bring a seed up and down; points here
  VERSION                LAB_VERSION
  catalog/               the catalog of this file as data, with CATALOG_VERSION:
                         per entry the id, piece, class, from, area, severity range,
                         parameter domains, constraints, realization variants
  seed/                  the generator (GENERATOR_VERSION): seed in, variables,
                         manual checklist, engagement files and key skeleton out
  modules/               one OpenTofu module per piece: gcp, github, dns, web, host;
                         each a clean baseline plus one slot per catalog entry,
                         switched by var.slots["F-GCP-04"]
  envs/seeded/           root module composing the pieces for a seeded run
  envs/clean/            the same modules with every fault off; also make live's target
  scripts/               the GitHub steps no provider covers; verify; reset; down
  key/                   key schema (JSON Schema) and the key builder
  score/                 the scorer and the result schema
  seal/                  canonicalize, hash, encrypt, record template, reveal check
  .terraform.lock.hcl    exact provider versions and hashes
```

There is no Workspace module and no Workspace script: nothing is seeded in a tenant.
Generated variables, unrevealed keys, checklists and state never land in either
repository. `lab/` is created with the lab's first part, not before (AGENTS.md, "Do not
scaffold empty abstractions ahead of their slice").

Public modules are readable by implementers on purpose. They must be: a lab that can
harm third parties needs its code reviewed. Blindness does not come from hiding how a
fault is built; it comes from the sealed seed, the parameter and realization variants,
and the private extras.

### `make live` and release gates

The same modules serve all three uses (decided 2026-10-25: the GCP, GitHub, domain and
host seals also serve development and `make live`):

- **`make live`**, which today holds the model path's live tests, gains collector tests
  that run against `envs/clean`, or against a revealed development seed. They check that
  each collector's reads work against a real provider (G1: "an opt-in live test reads a
  test project"). They make no recall claim and never target an unrevealed seed.
- **A development measurement** (the GCP seal before G1, and any seal before v1.0.0)
  brings up `envs/seeded` from a sealed seed, runs scheck once, scores it, records it as a
  development measurement, reveals the key and tears the lab down. The revealed seed then
  joins the development seeds.
- **The v1.0.0 gate** does the same with fresh seals of every part, made for it, and its
  record is the one the release cites.

A sealed seed cannot serve development before its scored run: an implementer who reads
or runs against it before then has contaminated it ("Late and not blind").

Neither runs in CI by default: both need provider credentials, and a measurement needs a
sealed seed.

## Where this differs from the roadmap

- **No Workspace lab.** E3 delivers "a Google Workspace test tenant on a domain the team
  owns", and the 0.0.2 gates measure recall, false positives, context and prioritization
  over it. That tenant will not exist (user, 2026-10-25). Every Workspace share of those
  gates, and of the 0.0.3 gates that re-run them, is a known gap, recorded as
  "Workspace: exercised read-only on a real tenant, not measured".
- **The lab is a v1.0.0 gate.** The roadmap names lab measurements in the 0.0.2, 0.0.3
  and 0.0.4 gates and defines no v1.0.0. Here, seals before v1.0.0 are development
  measurements. The roadmap defers its lab-measured 0.0.2 and 0.0.3 gates to v1.0.0
  ("Release gates and the lab"); what else v1.0.0 contains is not defined.
- **No GCP organization.** G1 supports organization roots and lists organization
  policies among what is not judged; the lab exercises a project root only.
- E3 describes the lab host as a docker-compose file. Here the host is one module with a
  local realization (a container) and a cloud realization (the GCP VM), so that host and
  cloud firewall faults can meet (X-03). The local realization keeps E3's case.
- E3 lets the seeder read "this roadmap's example tables". Here the catalog is public and
  readable by implementers, so recall on it is a measure against a practitioner's
  expectations, and blindness rests on the seed, the variants and the private extras.
- E3 and the roadmap's rules hand back only a hash. Here the key is revealed and committed
  at scoring, since a hash proves nothing until its preimage is shown.
- The roadmap sets no recall threshold, and its false-positive target exists only for the
  domain part. Here both are decided and frozen in the first seal.

## Decisions and open questions

1. **GCP placement** — decided 2026-10-25: a project with no organization. Consequences
   in "GCP project". Open: whether a persistent project exists to age a service account
   key past 90 days.
2. **Billing** — decided 2026-10-25: a dedicated billing account, a budget of about 50
   dollars, alerts at 50, 90 and 100% to two people. Open: who the two people are.
3. **GitHub plan** — decided 2026-10-25: free; public repositories for alert and
   protection cases; no paid secret scanning, so F-GH-15 is unmeasured; Team later.
4. **Personas** — open: which team members or volunteers hold the departed, contractor
   and outside-collaborator GitHub accounts, within GitHub's one-account rule, and which
   consumer Google accounts they use as GCP members.
5. **Workspace** — decided 2026-10-25: no lab tenant; read-only runs on the production
   tenant, a limited number of times, under "Production-tenant safety". Open: who holds
   scheck's read credential for those runs, whether any run turns on the OAuth grant
   reads, and whether any mailbox is ever authorized.
6. **Domains** — decided 2026-10-25: two domains under TLDs that are not HSTS-preloaded,
   DNS on Cloudflare. Open: which domains.
7. **Who seeds, ranks and adjudicates** — decided 2026-10-25: the seeder is an AI agent in
   a fresh session that never reads `internal/`, its model named in the seal record; the
   ranker is the user if the user wrote no checks, otherwise the gate is *not run*; the
   adjudicator is the user.
8. **Thresholds** — decided 2026-10-25: at least 90% must-find recall per area and at most
   one false positive at low or above per area, frozen in the first seal and kept as the
   baseline.
9. **The sealed bundle** — decided 2026-10-25: in a private repository, encrypted with
   `age` to the user's key (in the user's password manager) and a second holder's. Open:
   who the second holder is.
10. **The GCP part's timing** — decided 2026-10-25: sealed before G1's first commit.
11. **The lab as a gate** — decided 2026-10-25: a gate for v1.0.0; the GCP, GitHub,
    domain and host seals also serve development and `make live`. The roadmap reconciles
    the 0.0.2 and 0.0.3 release gates that name the lab ("Release gates and the lab").
    Open: defining v1.0.0 in the roadmap.
