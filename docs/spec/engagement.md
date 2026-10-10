# scheck — engagement specification

How a run works, stage by stage. The *why* is in [VISION.md](../VISION.md); what each
stage may do to a target is in [scope.md](scope.md). Status: design. A section becomes
contract when the release that implements it lands ([ROADMAP.md](../ROADMAP.md)); until
then it describes the target, not the build.

## Stages

Each stage reads the previous stage's output and writes its own. Every output is a
file the operator can read and edit. `--stop-after <stage>` ends a run there, and a
run can resume from a saved output.

| Stage | What happens | Output |
|---|---|---|
| **1. Intake** | Ask what a consultant would ask (below). | Engagement file |
| **2. Scope** | Expand the declared roots into assets with passive discovery and cloud inventory, drop what is excluded, record which assets have evidence of being first-party, and apply defaults. The resolved list is printed before anything beyond passive runs; only first-party confirmations wait for the operator. | Scope |
| **3. Recon** | Every declared read per asset: cloud and SaaS configuration, host facts, DNS, TLS, response headers, technology fingerprint. DNS beyond what Scope used to discover names (SPF, DMARC and declared DKIM selectors as TXT, MX, NS) is read here, per domain root and declared mail domain ([web-collector.md](web-collector.md#reads)). Fills gaps in the context and flags where it is wrong. Anything outside the roots is recorded, not contacted. | Asset map |
| **4. Plan** | A checklist per asset type: the rules that apply, narrowed and ordered by context. With a model (0.0.4), hypotheses as well. | Plan |
| **5. Check** | Run the follow-up reads that rules named and, from 0.0.3, the probes and scans the asset's modes allow, through collectors that enforce scope. | Evidence |
| **6. Analyze** | Each rule ends as *fires*, *disproved* or *insufficient evidence*, the three outcomes every rule already has; a rule may name follow-up reads that would settle it, which go back to Plan. | Findings and follow-ups |
| **7. Report** | Coverage per risk area, then findings for the people who will fix them: what, why it matters here, evidence, remediation. | Report |

In 0.0.2, which only reads, Recon runs every declared read for every asset and Check
runs only follow-ups; from 0.0.3 Check is also where probes run. Keeping the split there
means a collector never decides which stage its requests belong to.

The Plan → Check → Analyze loop ends when no follow-up is open, the run's timeout
passes, its model cost limit is reached, or, for probes and scans, the authorization
window closes ([scope.md](scope.md#throttle-timeout-and-cost)). A limit stop is
reported as incomplete, never as a clean result.

An example from the database on the web host. Recon reads that postgres is bound to all
interfaces and that the host firewall does not restrict 5432. In 0.0.2 that fires
`db.listens_unfiltered`, whose text says the cloud firewall was not assessed. From
0.0.3 a second rule, `db.internet_reachable`, also reads the VPC firewall rules or the
instance's authorized networks and fires only when they let outside traffic in. A bind
address alone is not exposure, and neither rule fires on it. Ports that Docker
publishes bypass ufw and firewalld (they go through Docker's own chains), and `ss` may
show `docker-proxy` or nothing for them. For a port Docker publishes,
`db.listens_unfiltered` abstains, because the host firewall's rules do not apply to it.
Knowing which ports are published needs a fact the catalog does not have yet (the nat
table's `DOCKER` chain, read elevated); until it exists, a listener owned by
`docker-proxy` abstains.

## Intake: the engagement file

The engagement file (`engagement.yaml`) is the source of truth for a run. It is
reproducible, diffable and reviewable, and it is what a run resumes from.

```
$ scheck init                 # interviews the operator, writes engagement.yaml
$ scheck run engagement.yaml  # scope → recon → plan → check → analyze → report
$ scheck run --host deploy@203.0.113.5   # one host, no file: an engagement built in memory
```

`scheck run` is the only command that assesses anything; a one-host check is an
engagement with one root ("One command, one file" below).

`scheck init` asks the questions; editing the file by hand is equally valid. The
interview covers what a consultant draws out, not only the architecture. **Every
question has a consumer**: a rule that reads the answer, a coverage reason that cites
it, or a report field that prints it. "Printed in the report" counts only for what a
reader needs to interpret the findings: the trigger, authorization, scope and accepted
risks. A question nothing consumes is removed from the interview, not kept for a later
release; an operator who answers questions that change nothing stops answering
carefully. The mapping from question to consumer is code: each question declares its
consumers by id, with the slice that owns each. Consumers arrive with their slices
(the host collector's context in E1b, rules in E5 to E9, coverage reasons in E2), so a test proves at every commit that each
declaration is well formed and that every consumer owned by a slice already merged
exists, and the release gate proves they all do. A consumer is never stubbed to pass.

| Topic | Question | Consumed by |
|---|---|---|
| Engagement | What triggered this assessment: a customer questionnaire, an audit, a funding round, an incident, or routine? | Printed in the header. `incident` opens the report with "this is not incident response; evidence read from a possibly compromised system cannot be trusted", worded in [report.md](report.md#the-report) |
| Roots | Which domains do you own, including parked and non-sending ones? Which tenants, organizations, cloud projects and hosts? | Roots ([scope.md](scope.md)) |
| Mail | Which services send mail as each domain, with which DKIM selectors? | DKIM is read per declared selector, since DNS cannot list them; with no selector DKIM is *insufficient evidence*, not missing. SPF includes are compared with the senders. A domain listed under `mail.no_mail` must publish `v=spf1 -all` and DMARC `p=reject`. A domain root with neither a sender nor a `no_mail` entry is judged from the mail use it shows: a non-null MX record, or SPF that authorizes a sender, makes DMARC and SPF judged as for a sending domain; recognized complete MX and SPF evidence showing neither makes it judged as a domain that sends no mail; missing or invalid evidence leaves mail use unknown. The report says the operator did not say which. Comparing SPF with the senders, and DKIM, stay *insufficient evidence* for it. The severity of DMARC `p=none` depends on whether the domain sends |
| Tools | Which SaaS tools and providers do you use, by category? Which areas do not apply to you at all (no hosts, no cloud)? | A tool is covered when a collector reads it (`github-actions` by the GitHub collector, `google-workspace` by Workspace). Each tool no collector reads becomes an "Other declared SaaS" row naming it. `not_used` marks an area *not applicable* in coverage |
| People | Who are the admins and contractors, and the shared, service and break-glass accounts, with every Workspace address and GitHub login each uses? Everyone else is named from the stanza `--stop-after recon` prints, one account at a time ("People" below). | Every people rule matches by these identifiers ("People" below); the kind selects which rules apply; a contractor holding an admin role is a finding whether listed or not; a shared account names who uses it, so a leaver among them says to rotate it |
| People | Who has left recently, and when? | An account of that person still active, or still holding an admin role or group-granted access, is a finding. A suspended account is correct offboarding |
| Access | Who is expected to be a super admin (Workspace) or an owner (GitHub) in each tenant? | A super admin or owner not listed is a finding; a listed person who is not one is a note for the readout, not a finding; one who cannot be tied to a named person is a finding. Too many of them is a finding whatever is listed ("Admins") |
| Access | Which repositories deploy to production, and from which CI? | `deploys_to: production` raises branch protection, workflow token, deploy key and `pull_request_target` findings on those repositories; from 0.0.3 G4 links them to the cloud project |
| Access | In each tenant, who must use 2-step verification: every account (service and break-glass accounts included), only admins, some, none, or you do not know? | Compared with the enforcement the tenant reports ("2-step verification"); a declared enforcement the API disproves raises the finding for it as a contradiction; `unknown` raises nothing and prints what scheck read |
| Secrets | Where do production secrets live? | The Secrets coverage row cites each declared store and whether scheck read it |
| Data | What data matters most, and on which asset? | Severity adjustment on that asset ("Severity in context" below), attributed |
| Data | Where are the backups, in which account? | The data stores and backups coverage row prints the location as *declared, not verified* and stays *not assessed* until the cloud collector can compare it with inventory (0.0.3) |
| Intent | What is exposed on purpose, and to whom? | Exposure findings on that exact URL or service drop to *info*, attributed ("Severity in context") |
| Intent | What must not be reachable, except from where? | A contradiction finding when it is reachable from a vantage outside the declared audience |
| Hosts | For each host: its role, exposure, environment and expected services, and how to reach it | The host collector's context (`host-collector.md §5.3`) and its connection |
| Authorization | Before any probe or scan: who authorized it, for which windows, from which source addresses? | Asked only when a probe or scan mode other than `off` is chosen (0.0.3 on). The windows bound probes and scans and sources are printed ([scope.md](scope.md#authorization)); the block is printed in the report |

Not asked, and why:

- **Accepted risks.** Nobody can name a finding id before seeing a report. The report
  prints a ready-to-paste `accepted_risks` entry under each finding; risks are accepted
  at the readout, as in practice, and the next run reads them.
- **Framework.** Comparing a declared framework with the observed one is not a risk.
  The question returns with probes (0.0.3 G3), where it selects which ones apply.
- **Hosting.** The roots and tools already say it.
- **Compliance goal.** It would select references printed with each finding, and no
  reviewed finding-to-control table exists. It returns with one.

Later, scheck may read existing docs, compose files or infrastructure code to
*suggest* additions. A suggestion enters the file only when the operator confirms it;
nothing inferred joins scope on its own.

### The file

One complete file, as `scheck init` writes it for the company in the examples, plus the
entries written later (a Scope confirmation, an accepted risk). Every top-level key is
shown; every key maps to a row of the interview table above or to a section of
[scope.md](scope.md). The file may change freely until 0.0.2 is published.

```yaml
# engagement.yaml — written by `scheck init`; editing by hand is equally valid.
schema: 1
engagement:
  name: example-ltd-2026-q4           # names the run directory: ^[a-z0-9][a-z0-9-]{0,62}$
  operator: platform-team
  timezone: Europe/Madrid             # IANA, required; every date in this file lasts until 24:00 here
  trigger: questionnaire              # questionnaire | audit | funding | incident | routine

roots:                                # scope.md "What is in scope"
  - domain: example.com
  - domain: example.net               # parked: owned, sends no mail
  - saas: google-workspace:example.com
  - saas: github:example-org
  - cloud: gcp:example-prod           # no collector until 0.0.3: coverage says "collector not built", and the run exits 2
  - host: deploy@203.0.113.5
exclude:
  - domain: legacy-billing.example.com
  - url: https://shop.example.com/checkout/
  - repo: github:example-org/client-nda   # an API asset: dropped before anything is stored
# scope: full                        # scope.md "Full scope"; 0.0.2 rejects it: "not available in this build"

defaults:                             # every asset, declared or discovered
  probe: off                          # 0.0.2 accepts only off
  scan: off
  throttle: {rate: 5/s, concurrency: 2}
  profile: baseline                   # host catalog tier, baseline | hardened (host-collector.md §3)
limits:
  timeout: 1h                         # `none` turns it off; 0 is rejected
  # max_cost: USD of model spend. Rejected in 0.0.2: "not available in this build"

redact_extra:                         # client strings to hide, RE2; added to the built-in rules
  - "project-tangerine"               # the report counts matches and never prints a pattern

people:                               # handles; every other key names people by handle
  alice:      {kind: employee, workspace: [alice@example.com], github: [alice-ex]}
  bob:        {kind: contractor, org: "Acme Dev", github: [bob-acme]}
  carol:      {kind: employee, workspace: [carol@example.com], github: [carol-codes, carol-work], left: 2026-09-15}
  ops-admin:  {kind: shared, workspace: [ops@example.com], used_by: [alice, carol]}
  deploy-bot: {kind: service, github: [example-deploy-bot]}
  breakglass: {kind: break_glass, workspace: [breakglass@example.com]}

access:
  admins:                             # per tenant: the super admins (Workspace) and owners (GitHub) you expect
    google-workspace:example.com: [alice, breakglass]
    github:example-org: [alice]
  mfa:                                # who must use 2-step verification: everyone | admins | some | none | unknown
    - {where: google-workspace:example.com, enforced: everyone}
    - {where: github:example-org, enforced: everyone}

tools:                                # a tool without a collector is a coverage row naming it
  - {category: identity, name: google-workspace}
  - {category: code, name: github}
  - {category: ci, name: github-actions}
  - {category: payments, name: stripe}
  - {category: chat, name: slack}
not_used: []                          # coverage areas that do not apply, e.g. [hosts]: printed as *not applicable*

mail:
  senders:                            # DKIM is read per selector listed here
    - {domain: example.com, service: google-workspace, dkim_selectors: [google]}
    - {domain: example.com, service: sendgrid, dkim_selectors: [s1, s2]}
  no_mail: [example.net]              # must refuse all mail: SPF -all, DMARC reject

secrets:
  production:                         # where production secrets live
    - {store: github-actions-secrets, asset: github:example-org}
    - {store: env-file, asset: deploy}

data:
  matters_most:
    - {what: "customer orders and invoices", asset: deploy}
  backups:
    - {where: "bucket example-backups", account: gcp:example-backups}

intent:
  exposed_on_purpose:
    - {url: https://shop.example.com/status, audience: internet, reason: "the uptime vendor reads it"}
  not_exposed:
    - {url: https://shop.example.com/admin, audience: vpn}
  accepted_risks:                     # pasted from a report, at the readout
    - id: sshd.password_auth_enabled
      asset: deploy                   # subject: the instance key (a login, a DNS name, port/proto), required
                                      # when the finding declares one; a host finding has none in 0.0.2
      reason: "break-glass path; MFA at the bastion"
      accepted_by: alice
      expires: 2026-12-31

authorization:                        # optional while every probe and scan mode is off
  by: "CTO, Example Ltd"
  date: 2026-10-06
  windows:
    - {from: 2026-10-07T09:00:00+02:00, to: 2026-10-07T18:00:00+02:00}
  source: [203.0.113.10/32]
  note: "Annual self-assessment; contact on-call before any scan."

assets:                               # per-asset settings; the key is the name the report uses
  deploy:
    host: deploy@203.0.113.5          # id host:203.0.113.5:22, bound to its host.id on first contact
    jump: ops@198.51.100.7            # a connection hop, not an asset: nothing runs on it
    identity: ~/.ssh/deploy           # a path, never a key; without it, ssh-agent
    known_hosts: ~/acme/known_hosts   # the fingerprints the client gave; default ~/.ssh/known_hosts
    timeout: 10m                      # the host collector's run timeout, not limits.timeout
    elevate: sudo                     # `sudo -n --` as a prefix, never a password (host-collector.md §7.1)
    profile: hardened                 # overrides defaults.profile for this host
    disable_checks: [fs.suid]         # the client's rules of engagement: only narrow
    deny_paths: [/srv/backups]        # literal absolute prefixes, checked after realpath
    context:                          # host-collector.md §5.2: only these four fields
      role: "web and database host"
      exposure: internet
      environment: prod
      expected_services:
        - {port: 443, proto: tcp, purpose: "nginx public TLS", audience: internet}
        - {port: 5432, proto: tcp, purpose: "postgres", audience: localhost}
  shop:
    url: https://shop.example.com/
    first_party: {confirmed_by: alice, date: 2026-10-07, target: shops.myshopify.com}   # by hand in 0.0.2; the Scope stage asks from 0.0.3
  shop-repo:
    repo: github:example-org/shop
    deploys_to: production
    ci: github-actions
    public: false                    # true declares deliberate public visibility
```

A repository asset's optional `public` boolean records intentional public visibility.
Only `public: true` declares it public on purpose; omission and `false` do not. The
field does not grant scope or excuse secrets. E5's public-repository rule compares
this declaration with recognized API visibility; URL `intent` cannot declare a
repository's public visibility.

### Identity, references and validation

**Assets.** Every asset's id is a canonical locator for its kind; a name under
`assets` is an alias for it, and a discovered asset is named by its locator.

| Kind | Root or entry | Id |
|---|---|---|
| domain | `domain: example.com` | `domain:example.com` (lowercase, no trailing dot) |
| url | `url: https://shop.example.com/` | `url:https://shop.example.com/` (lowercase host, default port dropped, path kept with dot segments removed and percent-encoding normalized) |
| host | `host: deploy@203.0.113.5` or `host: local` | `host:203.0.113.5:22`, bound to the collector's `host.id` after first contact; the SSH user is a connection setting, not part of the id |
| network | `network: 203.0.113.0/28` | `network:203.0.113.0/28`; an address found in it is a `host` |
| saas | `saas: github:example-org`, `saas: google-workspace:example.com` | `saas:github:example-org`; a Workspace tenant is bound to its customer id after first contact |
| repo | `repo: github:example-org/shop` | `repo:github:example-org/shop`; a GitHub organization root contains its repositories |
| cloud | `cloud: gcp:example-prod` | `cloud:gcp:example-prod` |

A host locator is `[user@]address[:port]`, with IPv6 in brackets; `host: local` is the
machine running scheck. The port is part of the locator; there is no separate `port`
key, and the locator never carries a password. A single-label name (`web1`) is a name,
resolved the way ssh resolves it; a name whose last label is all digits
(`203.0.113.05`) is refused, since a resolver reads it as an address. A `jump` is a
host locator other than `local`. A `network` is written with its host bits zero. A
`url` is a prefix: no query, fragment or credentials. A `repo` is `github:owner/name`; a local
checkout is not a locator (`repo: ./` exits 3) but a repository's `checkout` setting,
an absolute path to the operator's `git clone --mirror` ([scope.md](scope.md#repositories)).
`checkout` is accepted only on repository assets; its mirror is checked when read.

**Names.** `engagement.name`, `assets` names and `people` handles all match
`^[a-z0-9][a-z0-9-]{0,62}$`. A throttle rate is `N/s` or `N/m`.

**An asset's settings follow its kind.** `jump`, `identity`, `elevate`, `profile`,
`disable_checks`, `deny_paths` and `context` are host settings; `first_party` is
taken by a domain, url or host; `deploys_to` (`production | staging | development`)
`ci` (a tool named under `tools`) and `checkout` (an absolute mirror path) by a
repository. A setting on the wrong kind
exits 3, and so do two `assets` entries for the same id and an entry for an asset an
`exclude` covers, whose settings could never apply.

In the file, an asset reference (`secrets[].asset`, `data.matters_most[].asset`,
`accepted_risks[].asset`, the keys of `access.admins`, `access.mfa[].where`) is an
`assets` name or a root's value exactly as written under `roots`. A reference that
resolves to neither exits 3. `accepted_risks[].asset` may also be a canonical id that
falls under a declared root and no `exclude`, checked as an intent URL is, since a
finding on an asset found by discovery (a repository under an organization root) is
named by its canonical id and must be acceptable as the report prints it. `data.backups[].account` is a declaration, not a
reference: it may name an account outside scope, and the coverage row then says
"declared, outside scope, not verified".

**Asset scope.** The relationship of asset entries to roots and exclusions is defined
in [scope.md](scope.md#what-is-in-scope). A site's
entry points are its `url` root or entry and every `intent.*.url` on it; there is no
other list of URLs. Intent URLs are entry points but never first-party evidence.

**People.** `people` is a map from a handle to an account holder's kind and identifiers.
Every other key that names a person uses the handle, except `authorization.by`, which is
free text because the person authorizing may not be in `people`. Built in E5a: the
schema and its validation. GitHub identity rules are built in E5 step 3; Workspace
rules arrive with E6.

| Kind | Who | Exempt from | Counted for the admin threshold |
|---|---|---|---|
| `employee` | a person on the payroll | nothing | yes |
| `contractor` | a person working for another company, named in `org` | nothing; holding super admin or owner is a finding (`identity.external_admin`, medium) whether or not `access.admins` lists them | yes |
| `shared` | one account several people sign in to (`ops@`); `used_by` names them, `org` the company behind it if any | nothing | yes, as one |
| `service` | an account automation signs in as | the stale and never-signed-in rules only | no |
| `break_glass` | an emergency admin account nobody uses day to day | the stale and never-signed-in rules only | no, for at most two per tenant; any beyond two count as admins, with a readout note |

GitHub identifiers also accept provider Bot logins ending in `[bot]`; this does
not infer that the operator should classify the account as `service`. GitHub
user-only disabled-MFA filters do not establish Bot or App enrollment; the
per-member MFA rule abstains for those identities.

`workspace` and `github` are lists: a person may hold a work and a personal login in
the organization, or addresses in more than one tenant, and every rule matches over all
of them. `left` is the date after which no access is expected; on a `service` account
it means retired, and a retired account still active is a finding like a person's. No
kind is exempt from the 2-step verification, admin or OAuth rules: a break-glass super
admin without 2-step verification is reported like any admin (hardware keys are the
answer to "it must survive a lost phone"), and the operator may accept it by subject.
A shared account holding an admin role is a finding (`identity.shared_admin`, medium):
nobody's actions on it can be told apart. When a handle in its `used_by` has a `left`
date that has passed, the readout says to rotate its password and second factor,
naming who left; rotation is not observable, so that is a note, not a finding.

Rules match:

- in Workspace, by `primaryEmail`. A declared address that matches no primary address
  but is an alias of exactly one user is that user's, with `matched_by: alias`, printed
  in coverage ("alice → alice.smith@example.com, by alias") and a readout note to write
  the primary address; without it, a typo-level declaration would file a false
  "admin tied to no person". For a person whose `left` date has passed, the same match
  on an *active* user makes the Workspace side of the left-person rule *insufficient
  evidence*, never disproved, with a note ("carol@ now delivers to archive-carol@, an
  active account: if that is carol's account renamed, she still has access; if it is
  someone else's, mail and password resets meant for carol reach them"). An alias of a
  suspended user is correct offboarding. A declared address that is a group's is a
  note to list its members instead;
- in GitHub, by login only. GitHub returns a member's email only on Enterprise Cloud to
  an owner's token, so there is no email path, and a Workspace account is never merged
  with a GitHub login by guess. A person with no `github` login gives *insufficient
  evidence* on the GitHub side, never "not found, so fine";
- in GitHub, over members, outside collaborators and pending invitations, not members
  alone.

Each matched account's provider id is recorded beside its key, in the run's
`recon.json` (`{tenant, key, provider_id, handle, matched_by}`) and in each finding's
`subject.provider_id`, so a rename between two runs is followed by id when runs are
compared (0.0.3 G6). It is never written into the engagement file. An account renamed
with its old address removed cannot be found by address, which the left-person rule
lists under what it did not check.

An admin or owner nobody can tie to a person is a finding; unattributed plain members
are a count in coverage. Nothing is filed because something was not declared: the
unexpected-admin rule runs for a tenant only when `access.admins` names it, and the
unattributed-admin rule only when `people` holds at least one identifier for that
tenant. Otherwise both are *insufficient evidence*. The report lists the service and
break-glass accounts. A declared break-glass account that is not a super admin, or
that signed in within the last 90 days, gets a readout note ("a break-glass account
that cannot administer the tenant cannot recover it"; "confirm the sign-in was an
exercise").

Three traps the people rules must not fall into, each tested in the rule's fixtures: a
`left` date that has not yet passed in `engagement.timezone` (a person serving notice)
makes the left-person rule abstain until it has; a suspended account is correct
offboarding, never "still active"; and an account created recently that has never
signed in is a new hire, not a stale account, so the never-signed-in rule reads the
creation date.

**Admins.** `access.admins` lists, per tenant, the **super admins** (Workspace users
with `isAdmin`) and **owners** (GitHub organization members with role `admin`) the
operator expects. Those are what it is compared with and what the threshold counts.
Holders of delegated roles that can reset passwords, change users' sign-in or recovery
details, change security settings, move users between organizational units, manage
domains, control app access or administer groups (Workspace's User Management, Help
Desk and Groups roles and custom roles with those privileges), and GitHub organization
roles granting admin over every repository or settings, or repository admin on a
`deploys_to: production` repository, are listed by name in the readout, not compared
with `access.admins`. They count as admins for the unattributed-admin rule and for
`attribute:admin` on a person who left, since an unknown person who can reset passwords
is as dangerous as an unknown super admin. The exact privilege and role names are
frozen at the start of E5 and E6 against what the APIs return. When a person's `left`
date has passed, their admin role is reported by the left-person rule with
`attribute:admin`, and the unexpected-admin rule does not file it again.

Too many admins is a finding whatever `access.admins` lists
(`workspace.too_many_super_admins`, `github.too_many_owners`, medium, no subject: the
admins are its `affected` list). The count is the admins less `service` accounts and
less up to two `break_glass` accounts; shared and unattributed accounts count. It fires
when the count is above 3, or when it is at least 3 and above a third of the tenant's
active humans (Workspace: active users not declared `service` or `break_glass`;
GitHub: members, not outside collaborators, not declared `service`). Pending invitations
with the owner role are shown beside the count, not in it. Two is never too many: it is the
providers' own advice, so a tenant is never told to go below it. It is disproved on
complete admin and user populations; on a partial one it may fire on the first clause,
as "at least N", and never computes the ratio.

**2-step verification.** `access.mfa[].enforced` says who the operator believes must
use a second factor in that tenant. It is the operator's belief, so `unknown` is an
answer, and true or false is refused as ambiguous.

| Value | Claims | Raises as `contradiction` |
|---|---|---|
| `everyone` | every active account must, service and break-glass included | every instance of the not-enforced finding; on GitHub, the organization's requirement switched off even when every member has 2FA, since the claim was enforcement |
| `admins` | every super admin or owner must | not-enforced on an organizational unit holding an unenforced super admin, and every admin without 2-step verification; GitHub cannot require it of owners only, so there it raises only an owner without 2FA, with a readout note |
| `some` | part of the tenant must | everything, when nothing is enforced; a note when everything is |
| `none` | nothing is enforced | nothing; a note when the tenant does better |
| `unknown` | the operator does not know | nothing; a readout note says what scheck read ("N of M accounts not required") |

Observed better than declared is never a finding. A Workspace user with enforcement on,
not enrolled and created within the enrolment period is a new hire, a note and not a
contradiction; a super admin in that state is still an admin without 2-step
verification. GitHub's organization requirement is read only by an owner's token and
is three-valued: absent or null is *insufficient evidence*, never "not required".

**The recon stanza.** `--stop-after recon` prints the accounts no handle names, for the
operator to paste under `people` (in JSON, `people_candidates[]` with the same fields):

```yaml
# Accounts no handle under people names, read 2026-10-09 14:02 (Europe/Madrid).
# Set kind for each and paste under people: in /home/alice/acme/engagement.yaml.
# One entry per account: the same person may appear once per provider; merge them by
# hand. An admin or owner nobody can name is a finding.
# kind: employee | contractor | shared | service | break_glass    (add left: YYYY-MM-DD if they left)
people:
  # google-workspace:example.com  super admin  last sign-in 2026-10-01  created 2024-03-12
  dave:
    kind: ""
    workspace: [dave@example.com]
  # google-workspace:example.com  member  last sign-in never  created 2026-10-02 (7 days ago)
  erin:
    kind: ""
    workspace: [erin@example.com]
  # github:example-org  owner  GitHub reports no sign-ins
  dkim-dave:
    kind: ""
    github: [dkim-dave]
  # github:example-org  pending invitation, role member, sent 2026-09-30 (no account to declare yet)
# Not listed: 7 suspended accounts that hold no admin role or group-granted access.
```

A GitHub candidate seen only in a pending invitation carries `invitation_id`, not
an account `provider_id`; invitation identity is never presented as account identity.

Entries run in roots order; within a tenant, admins and owners first, then delegated
role holders, members, outside collaborators and invitations, then by key. A handle is
the local part or login made to fit the handle pattern, `-2` added on a collision. A
Workspace last sign-in of 1970 prints as `never`. On a partial population the header
says "At least these accounts". `kind: ""` is printed on purpose and validation rejects
it until someone who knows writes the kind: pasting the stanza wholesale as `employee`
would attribute every former employee nobody listed and defeat the unattributed-admin
rule, which is why bulk confirmation is refused for first-party evidence too
([scope.md](scope.md)). A key hidden by `redact_extra` is printed as a comment asking
for the address, never as a value that could validate. The stanza never writes the
engagement file, never prefills a kind or suggests `left` from staleness, never merges a
Workspace account with a GitHub login, sends no request of its own, prints no field a
rule or label does not read, omits attributed and excluded accounts, never counts as a
finding or changes the exit code, and prints nothing from a credential. Run again after
a paste, it lists only what is still unnamed.

**Accepted risks** follow `host-collector.md §5.2` for `id` (a catalog finding id or
`custom:`) and add `asset`, `subject`, `accepted_by` and `expires`. `subject` is the
finding's instance key (a login, an OAuth app's client id, a DNS name). When the
finding's definition declares a subject kind, `subject` is required: an acceptance of
the whole id would also accept every instance the asset gains later, next month's
Drive-scoped OAuth app among them, so validation exits 3 naming the kind ("reported per
OAuth app, … name the OAuth app, and add one entry per OAuth app to accept"). A
definition without a subject kind is accepted by id. Either it is about the asset as a
whole (too many owners of an organization), or its instances are not keyed yet: every
host finding in 0.0.2, `accounts.empty_password` among them, whose acceptance covers
every account on the host, including accounts added later. A host acceptance that names
a subject is listed as not applied (the Recon paragraph under "Runs, state and
configuration"); a `subject` on any other id without a subject kind exits 3 ("… is about
the organization as a whole; remove subject"), since nothing could ever match it.
`custom:` ids are never subject-checked. Past `expires`,
the adjustment stops and the report says so; `expires` is a date in
`engagement.timezone`, compared with the collection time of the asset it names, never
the time the report is rendered. The report prints a ready-to-paste entry under each
open finding ([report.md](report.md#findings)).

**Time.** A timestamp is RFC 3339 with seconds and an explicit offset. A date lasts
until the end of that day (24:00) in `engagement.timezone`, which is required. Both are
decoded as strings and parsed explicitly (`time.RFC3339`; `2006-01-02` in that zone),
never through YAML's own time type, which reads a date as UTC start of day and silently
returns a zero time for some forms. `authorization.windows` is a list; `source` is a list
of CIDRs.

**Exposure vocabulary.** One enum, `internet | vpn | lan | localhost | airgapped`. A
host's `exposure` takes four of them (`internet | vpn | lan | airgapped`,
`host-collector.md §5.2`). A service's `audience` and an intent entry's `audience` take
any of the five, and the engagement passes a service's `audience` to the host collector
as that collector's free-text field. Free-text values the standalone host collector
accepts, such as `vpc-only`, exit 3 in an engagement.

**Host context.** The host collector's context is `assets.<name>.context` and nothing
else: `role`, `exposure`, `environment` and `expected_services`. Accepted risks live
only under `intent.accepted_risks`, and a compliance goal is not read. The host
collector's other sources (`--context`, `./.scheck/context/**`, `target:`, and the
`context:` block of 0.0.1's `scheck.yaml`) are not read by `scheck run`: prose context
has no consumer without a model, and a host must not describe itself
(`host-collector.md §5.4`). The report records what was passed.

**Host settings.** A host's reach settings are `identity`, `known_hosts` (the file its
key is verified against; default `~/.ssh/known_hosts`), `jump` and `timeout` (the host
collector's run timeout, `host-collector.md §4.4`; not `limits.timeout`), so a run that
needed any of them can be repeated from its file. Beside its reach settings and context, a host asset takes `profile`
(overriding `defaults.profile`, which only host assets read) and the narrowing lists
`disable_checks` and `deny_paths`, with the semantics of `host-collector.md §8`: a
check id that is not in the catalog exits 3, and so does a `deny_paths` entry that is
relative or `/`.

**Jump hosts (0.0.2 E1c).** `jump: user@address[:port]` on a host asset, or `--jump`
with `--host`, reaches the host through one SSH hop, as `ssh -J` does: scheck
authenticates to the hop, opens one `direct-tcpip` channel to the host's address and
port, and runs the host's SSH handshake inside it. The hop is a connection setting, not
an asset: no session, command or canary runs on it, it is never in scope by being
named, and it has no coverage row or findings. The hop's host key is verified strictly
against the same `known_hosts` file as the host's, with the same identity or agent, and
there is no bypass. The hop needs its own SSH user, refused by Scope before any contact
when it is missing; it may not be `local` or the host itself, and a hop an `exclude`
covers exits 3, since scheck authenticates there and exclude always wins. The address the hop
connects to is the host's locator as written, resolved by the hop, so a name only the
hop can resolve works. Every audit line of a host reached through a hop carries `via:
user@address:port`, and so do the report's asset (`assets[].via`) and its coverage line
("through ops@198.51.100.7:22"). One hop only; a chain of hops is not offered. What a
hop leaves behind is what sshd writes for any authenticated connection (an ssh login's own
noise, `host-collector.md §1`: the PAM session's motd cache); the integration test holds
it to that list, with none of the target's documented artefacts.

**Validation**, before any target contact:

- Unknown keys exit 3.
- Probe and scan modes other than `off`, `scope: full` and `max_cost` exit 3 with "not
  available in this build" until their release.
- `0` is never "no limit"; `none` is.
- A value shaped like a credential is a usage error. Detection is by shape: known
  prefixes such as `ghp_` and `AKIA`, PEM headers, and high-entropy strings, not
  keywords.
- Every error names `file:line:key` and, for a credential, the detector that matched;
  it never prints the value.
- A `redact_extra` pattern that is not valid RE2 exits 3. A pattern shaped like a
  credential is refused like any other value: the place to keep a secret out of the
  report is the built-in redactor, not a copy of the secret in the file.
- A name-based `exclude` (domain, url, repo, organizational unit) that falls under no
  root exits 3. A `network` exclude is always accepted, since it only narrows and an
  address's root is known only once resolved; so is a `host` exclude written as an
  address, while one written as a name must fall under a root. A `cloud` project
  exclude is accepted when an organization root exists. A `url` exclude falls under a
  root when it does over either scheme, with or without its trailing slash, as it
  excludes ([scope.md](scope.md#admission)). Whether any exclude matched something is
  known only after Scope, which reports it.
- A root an `exclude` covers exits 3: exclude always wins, so it would never be read.
  An intent URL an `exclude` covers exits 3 for the same reason. An address is
  compared in every form, as the scope gate compares it ([scope.md](scope.md#admission),
  "Address excludes"): `host: 203.0.113.5` covers `host: deploy@[64:ff9b::cb00:7105]`.
- An IPv4-mapped address or network (`::ffff:198.51.100.7`) exits 3: it is written as
  its IPv4 form, so every address has one spelling, as the scope gate requires.
- Two roots written alike (`domain: example.com` and `host: example.com`) exit 3,
  since a reference names a root by its value as written.
- References name what they must: the keys of `access.admins` and `access.mfa[].where`
  a SaaS tenant; `accepted_by`, `confirmed_by` and the lists under `access.admins` a
  handle under `people`. An address or login held by two handles, or listed twice
  under one, exits 3, since no rule could tell them apart; one account several people
  sign in to is one handle of kind `shared` with `used_by`. `workspace`, `github` and
  `used_by` are lists, never a single value, and never empty. `org` is taken by a
  contractor or a shared account; `used_by` is required on a shared account, refused on
  any other, and names people, never a shared or service account or itself. An
  admin listed for a tenant must have an identifier for it (a Workspace address for a
  Workspace tenant, a login for a GitHub organization), or the comparison could never
  find them. `kind: ""`, which the recon stanza prints, exits 3 asking for the kind.
  A marker scheck printed in place of a hidden value is never accepted as a value.
- `access.mfa[].enforced` is one of `everyone`, `admins`, `some`, `none` or `unknown`;
  `true` and `false` exit 3 as ambiguous; a tenant appears at most once.
- A mail domain (`mail.senders[].domain`, `mail.no_mail`) falls under a `domain` root,
  and a domain listed both as sending and under `no_mail` exits 3. An intent URL falls
  under a root, and one URL listed under both `intent.exposed_on_purpose` and
  `intent.not_exposed` exits 3.
- An accepted risk needs `id`, `asset`, `reason` and `accepted_by`; an empty `reason`
  counts as missing. It needs `subject` when the finding's definition declares a
  subject kind, and may not have one on a non-host id whose definition declares none
  ("Accepted risks" above).
- The operator-facing wording of the people and MFA errors is fixed here, since the
  recon stanza sends operators straight to them: `kind: ""` says "is empty. Say whose
  account this is: employee, contractor, shared, service or break_glass. If you cannot
  tell, find out: an admin nobody can name is reported as a finding"; `enforced: true`
  says "true is ambiguous. Write everyone if every account must use 2-step
  verification, admins if only administrators must, some, none, or unknown"; a login
  under two handles says "One login belongs to one handle; if several people sign in to
  it, declare it once with kind: shared and used_by".
- The file is one YAML document, written out: a second document, anchors, aliases,
  merge keys, explicit tags (`!!binary`) and a key repeated in a mapping exit 3, so
  nothing in the file is dropped or decoded from text the credential check did not
  read as written.
- The file is checked in two passes, and each reports every error it finds, in line
  order. Structure and credentials come first; a file that fails them is not read
  further, so a credential is never echoed by a later message. A message quotes a
  value only after the credential check has passed it, and a locator with a password
  before `@` is refused without being quoted.

`scheck run engagement.yaml --stop-after intake` validates the file and prints it
resolved (YAML, or JSON with `--format json`): every locator as its canonical id,
every root as an asset (named by its `assets` entry, or by its id), the defaults
applied, and `redact_extra` as a count of patterns.

## Severity in context

Context moves severity in code, attributed as `host-collector.md §5.3` and §6.2
describe, never by a model. A severity nobody can explain starts with an adjustment
nobody listed, so the engagement's adjustments are a closed table:

| Rule | Source | Moves | Step |
|---|---|---|---|
| `exposed_on_purpose` | the declaration, `intent.exposed_on_purpose[i]` | exposure findings on that exact URL or service | to `info` |
| `data_matters_most` | the declaration, `data.matters_most[i]` | findings on that asset in the identity and access, secrets, data stores and external surface areas | +1 |
| `deploys_to:production` | the declaration, `assets.<repo>.deploys_to` | branch protection, workflow token, deploy key and `pull_request_target` findings on that repository | +1 |
| `contradiction` | the declaration the observation disproves (`access.mfa[i]`, an intent audience) | the finding for the weakness declared absent | +1 |
| `attribute:<name>` | a fact, cited by observation and excerpt | the finding whose definition declares that attribute of its subject or of who it affects (`attribute:admin` on a left person's account, `attribute:admin_grantor` on an OAuth app a super admin or break-glass account granted) | +1 |

- **Exposed on purpose** applies only to exposure findings: those whose whole claim is
  that a URL answers or names its software (reachable, version or technology
  disclosed), on that exact URL. A finding about what the response contains (a secret,
  a file, a debug page) is not one, and neither is a contradiction of a declared
  restriction (`web.restricted_reachable`), though its claim is that a URL answers. Every finding definition declares whether it is
  one (`exposure_finding`). Secrets, TLS and configuration findings on the same asset
  never move: an exposed `.env` on a public-on-purpose site is still high. Listeners on
  a host are governed by its `expected_services`, not by intent.
- **Data that matters most** leaves findings in other areas (headers, email, host
  hardening) where they are. A finding's area is a required field of its definition.
  Whether a host's remote-access and account findings move on the host that holds the
  data is decided in E9, with the lab.
- **A contradiction** raises because someone believes they are protected, which makes
  the weakness worse than the same one never declared.
- **An attribute raise or a separate id.** When the fix is the same and only the stakes
  differ (a person who left and is an admin), the definition declares an attribute
  raise; when the fix differs (an admin without 2-step verification is enrolled, the
  organization's enforcement is switched on), the findings are separate ids.
- **Accepted risks** keep the finding in the report with `status: accepted`, the
  reason and who accepted it, and out of the exit code.

**Stacking.** A collector's own table applies first and is the collector's (`by:
collector`; the host's in `host-collector.md §5.3`). The engagement's rules follow in
the table's order (`by: engagement`), each at most once per finding instance and one
step each. Severity never rises past critical, and a step that cannot move it is
recorded in the chain but not as an adjustment. The engagement's table only raises,
except `exposed_on_purpose`, which only lowers, and only an exposure finding, and only
to `info`.

**Base severity anchors.** With rules only, the ranking is the base-severity table plus
context, so bases must agree across collectors or "Fix these first" fails whatever the
renderer does. Each anchor is a base before context, with the context step that moves
it beside it. The `security-consultant` reviewed and froze them on 2026-10-09, before
E7, the first network collector, assigned its bases; every later base is placed
against them:

| Base | Means | Anchors |
|---|---|---|
| critical | Anyone on the internet can use it now, with no further step, and gets credentials, code execution or the tenant. | a usable empty password: an account with an empty password that sshd accepts empty passwords for (a multi-fact rule, E9); a credential in a public repository or its history; a credential of a kind never meant for a browser (a private key, `sk_live_`, a GitHub or npm token, a Google refresh token or client secret) served in a public web response; a `pull_request_target` workflow that checks out the pull request's head with a write token, on a public repository, where anyone can open one |
| high | One common attacker step away (a phished or stuffed password, an account at a provider, read access already given to someone) from accounts, data or the domain's name. | an empty password on an account with a login shell (usable locally under the distribution's default PAM; remote use not shown); 2-step verification not enforced at the identity provider; an admin without 2-step verification; a person who left still active (+1 `attribute:admin`); a super admin or owner nobody can name; a credential in a private repository or its history (scheck cannot tell whether it is live, and must not try); the GCP Owner role (`roles/owner`) on a service account; a bucket readable by anyone, not declared public; a write-all default workflow token with actions not pinned to a commit; a subdomain pointing at a provider that says nothing is set up there, where anyone can claim the name; SPF that authorizes any sender (`+all`, a bare `all`); a DKIM key short enough to factor (RSA under 1024 bits) |
| medium | Weakens a control or widens what a compromise reaches; needs a further condition. | a write deploy key (+1 `deploys_to:production`); password SSH (+1 `exposure:internet` by the host collector); DMARC not enforced on a domain that sends or shows mail use; an OAuth app with a broad scope (+1 `attribute:admin_grantor`); a named person who is a super admin or owner but not listed under `access.admins`; a contractor or shared account that is one; more super admins or owners than the tenant needs; a human with the GCP Owner or Editor role not declared an admin; a write-all default workflow token, alone; a name pointing at an outside name that does not exist, at a provider with no takeover entry; a page declared reachable only from a VPN or LAN that answered from the internet (+1 `contradiction`) |
| low | Hardening that matters mostly alongside another weakness. | missing HSTS; pending updates of unknown class; a certificate that fails verification; a version number disclosed (to `info` when exposed on purpose); a non-sending domain not locked down; a session cookie without `Secure` or `HttpOnly`; plain HTTP not redirected (+1 `attribute:password_form`); actions not pinned, alone |
| info | Context or cleanup, not a weakness; listed apart, never ranked. | anything lowered by `exposed_on_purpose`; security-header hygiene beyond HSTS; a missing or expired `security.txt`; a 1024-bit DKIM key; a public name resolving to a private address; a stale record inside your own roots; a certificate expiring within 14 days |

A declared admin who holds Owner is a note for the readout, not a finding. Of the
example seeded issues in ROADMAP E3, every one but missing HSTS anchors at medium or
above, and HSTS is the only low.

## Reachability and vantage

Reachability and the operator-declared vantage are defined in
[web-collector.md](web-collector.md#reachability-and-vantage).

## One command, one file

`scheck run` is the only command that assesses anything (0.0.2 E2). Its input is an
engagement file or, for one host, a locator; a run directory resumes that run ("Stop
and resume"):

```
$ scheck run engagement.yaml
$ scheck run --host deploy@203.0.113.5 --identity ~/.ssh/deploy --sudo --profile hardened
$ scheck run --host local
$ scheck run --host deploy@203.0.113.5 --write-engagement engagement.yaml
$ scheck run ~/.local/state/scheck/engagements/acme/2026-10-08T09:00:00Z
```

**`--host`** builds an engagement in memory: one `host:` root, one asset with the reach
settings given as flags (`--identity`, `--jump`, `--known-hosts`, `--sudo` or
`--elevate none|sudo`, `--profile`, `--timeout`), `defaults` and `limits` as
`scheck init` writes them, `engagement.name` derived from the locator with a
non-default port kept (`host-203-0-113-5`, `host-203-0-113-5-2222`, `host-local`),
`engagement.timezone` from the machine running scheck, and nothing else: no people,
intent or context. It goes through the same validation, stages, run directory and
report as a file, and the run directory keeps it as `engagement.yaml` like any other.
Its coverage table says what a one-host check is without burying the host: the areas
it did not ask for fold into one line ("one-host check: identity, secrets, cloud, …
not requested", reason `not_declared`), and the Hosts row expands into the host
collector's domains, naming the checks that did not run and why (elevation, profile,
narrowing), which is what the 0.0.1 text report showed. `--timeout` keeps its 0.0.1
meaning, the host collector's run timeout (`host-collector.md §4.4`); `limits.timeout`
bounds the whole engagement. Context,
accepted risks and narrowing are not flags: a host that needs them is written into a
file, and `--write-engagement FILE` writes the in-memory engagement as a starting point,
contacts nothing and never overwrites a file.
So every setting a run used exists as a file the operator can read, diff and resume
from. The reach flags are accepted only with `--host`.

Configuration-file refusal and the migration of 0.0.1 keys are defined in
[host-collector.md §8](host-collector.md#8-configuration).

**Narrowing travels with the engagement.** What a client says must not be read or
revealed is part of the rules of engagement, so it lives in the engagement file: a
host asset's `disable_checks` and `deny_paths`, and the engagement's `redact_extra`.
They are scope decisions, like `exclude`: each only subtracts a check, adds a denied
path prefix or adds a redaction, and nothing in the file can add a check, allow a path
the compiled policy denies, or reveal a redacted value. `redact_extra` applies to every
output of every collector, through the runner for hosts and through the scope gate for
API and web evidence. A disabled check's rules are *not assessed*, and coverage names
each entry that removed something under `excluded_by_operator`, so a narrowed run never
reads as a clean one. The report says how many operator redaction rules matched and
never prints a pattern, since a pattern is often the very string it hides. Redaction
applies to what collectors read; names and locators are written into the stage
documents and the report as declared, so validation warns when a root, an asset's name
or its locator matches a pattern, naming their positions and the pattern's index, never
either string.

The deprecated aliases and their flag mapping are defined in
[host-collector.md §8](host-collector.md#8-configuration).

Exit codes and their precedence are defined in [scope.md](scope.md#outcomes).

The embedded host envelope and JSON consumers are defined in
[report.md](report.md#text-and-json).

## Runs, state and configuration

Run directories, state, locking and resume are defined in [runs.md](runs.md).

## The report

Report order, wording, coverage, ranking, findings and JSON are defined in
[report.md](report.md).

## Rules and the model

Every stage works without a model. The model is an upgrade, and it has to earn its
place by measurement.

| Stage | Rules alone | With a model |
|---|---|---|
| Intake | Fixed interview questions | Follow-up questions based on earlier answers; suggestions from docs |
| Plan | A checklist per asset type, narrowed and ordered by the structured fields. Not hypotheses: a checklist that runs to completion in an hour is the same checklist whatever its order, and the report calls it a checklist | Hypotheses drawn from prose context and from recon, as structured output over the declared checks |
| Check | Follow-up reads named by rules; from 0.0.3, probes and scans per the asset's modes: `off`, `confirm` or `all` | `auto`: an experimental gate on probes and scans ([scope.md](scope.md)) |
| Analyze | Deterministic rules, single-fact and multi-fact, each ending as fires, disproved or insufficient evidence; each rule can name the follow-up reads that would settle it | Conclusions across assets the rules do not encode; choosing follow-ups |
| Report | Templated text per finding | Explanations written for the operator's setup |

**Multi-fact rules.** A rule may combine facts from several checks or assets: "bound
to all interfaces" **and** "host firewall allows the port" is `db.listens_unfiltered`;
adding "VPC firewall rule or authorized network open to the internet" is
`db.internet_reachable`; the bind alone is neither. This lifts the single-fact limit of
the host collector's posture rules (`host-collector.md §6.5`) for the engagement; each
rule still declares exactly which facts it reads, and abstains when any of them is
unknown. **An incomplete population proves presence, never absence**
([scope.md](scope.md#responses)): over a list cut by a cap, a page limit or an
exclusion drop, a rule may fire on an instance it saw but is never disproved, and a
count it prints is a lower bound ("at least 4 super admins"). Rules that name follow-ups are what let the loop iterate without a model.

Fixed in both modes:

- The model chooses among declared checks; it never writes a command or a request.
- It cannot widen scope, raise an asset's impact level or change an active mode.
- Severity comes from code (base severity plus context adjustments), not from the model.
- A finding must cite evidence that a check produced.

The rules-only path is both the fallback (no API key needed) and the baseline the model
path is measured against. The model path becomes the default only when it beats that
baseline on labeled cases written by someone other than the authors of the checks. The
evaluation harness in `internal/eval` and the criteria in `docs/eval/` are the starting
point for that measurement.
