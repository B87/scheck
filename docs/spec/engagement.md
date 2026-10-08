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
| **3. Recon** | Every declared read per asset: cloud and SaaS configuration, host facts, DNS, TLS, response headers, technology fingerprint. DNS beyond what Scope used to discover names (mail records, NS, SOA, CAA) is read here, per domain root and declared mail domain. Fills gaps in the context and flags where it is wrong. Anything outside the roots is recorded, not contacted. | Asset map |
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
| Engagement | What triggered this assessment: a customer questionnaire, an audit, a funding round, an incident, or routine? | Printed in the header. `incident` opens the report with "this is not incident response; evidence read from a possibly compromised system cannot be trusted", worded in "The report" |
| Roots | Which domains do you own, including parked and non-sending ones? Which tenants, organizations, cloud projects and hosts? | Roots ([scope.md](scope.md)) |
| Mail | Which services send mail as each domain, with which DKIM selectors? | DKIM is read per declared selector, since DNS cannot list them; with no selector DKIM is *insufficient evidence*, not missing. SPF includes are compared with the senders. A domain listed under `mail.no_mail` must publish `v=spf1 -all` and DMARC `p=reject`. A domain root with neither a sender nor a `no_mail` entry is *insufficient evidence* for the sending rules, never treated as non-sending. The severity of DMARC `p=none` depends on whether the domain sends |
| Tools | Which SaaS tools and providers do you use, by category? Which areas do not apply to you at all (no hosts, no cloud)? | A tool is covered when a collector reads it (`github-actions` by the GitHub collector, `google-workspace` by Workspace). Each tool no collector reads becomes an "Other declared SaaS" row naming it. `not_used` marks an area *not applicable* in coverage |
| People | Who are the admins, contractors and agencies, and the service and break-glass accounts, with their Workspace address and GitHub login? Everyone else can be filled in from the stanza `--stop-after recon` prints. | Every people rule matches by these identifiers ("People" below); the kind selects which rules apply |
| People | Who has left recently, and when? | An account of that person still active, or still holding an admin role or group-granted access, is a finding. A suspended account is correct offboarding |
| Access | Who is expected to be an admin or owner in each tenant? | An admin or owner not listed is a finding; a listed person who is not one is a note for the readout, not a finding; an admin or owner who cannot be tied to a named person is a finding |
| Access | Which repositories deploy to production, and from which CI? | `deploys_to: production` raises branch protection, workflow token, deploy key and `pull_request_target` findings on those repositories; from 0.0.3 G4 links them to the cloud project |
| Access | Is MFA enforced, and where? | Compared with the enforcement the tenants report; a declared enforcement the API disproves is a contradiction finding |
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
  alice:      {kind: employee, workspace: alice@example.com, github: alice-ex}
  bob:        {kind: contractor, org: "Acme Dev", github: bob-acme}
  carol:      {kind: employee, workspace: carol@example.com, github: carol-codes, left: 2026-09-15}
  deploy-bot: {kind: service, github: example-deploy-bot}
  breakglass: {kind: break_glass, workspace: breakglass@example.com}

access:
  admins:                             # per tenant root: who is expected to be an admin or owner
    google-workspace:example.com: [alice, breakglass]
    github:example-org: [alice]
  mfa:
    - {where: google-workspace:example.com, enforced: true}
    - {where: github:example-org, enforced: true}

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
      asset: deploy                   # subject: the instance key (a login, a repository, port/proto);
                                      # omitted, every instance of the id on the asset is accepted
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
```

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

**Names.** `engagement.name`, `assets` names and `people` handles all match
`^[a-z0-9][a-z0-9-]{0,62}$`. A throttle rate is `N/s` or `N/m`.

**An asset's settings follow its kind.** `jump`, `identity`, `elevate`, `profile`,
`disable_checks`, `deny_paths` and `context` are host settings; `first_party` is
taken by a domain, url or host; `deploys_to` (`production | staging | development`)
`ci` (a tool named under `tools`) and `checkout` by a repository. A setting on the wrong kind
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

**An `assets` entry never adds scope.** Its locator must equal a root or fall under one,
or validation exits 3. Scope has one source, `roots`, narrowed by `exclude`. A site's
entry points are its `url` root or entry and every `intent.*.url` on it; there is no
other list of URLs. Intent URLs are entry points but never first-party evidence.

**People.** `people` is a map from a handle to a person's identifiers and kind
(`employee`, `contractor`, `agency`, `service`, `break_glass`); `org` names a
contractor's or agency's company. Every other key that names a person uses the handle,
except `authorization.by`, which is free text because the person authorizing may not be
in `people`. Rules match:

- in Workspace, by `primaryEmail` only. An address that resolves as an alias of another
  user is reported separately ("mail to carol@ reaches bob"), never as the person being
  active;
- in GitHub, by login only. GitHub returns a member's email only on Enterprise Cloud to
  an owner's token, so there is no email path. A person with no `github` login gives
  *insufficient evidence* on the GitHub side, never "not found, so fine";
- in GitHub, over members, outside collaborators and pending invitations, not members
  alone.

An admin or owner nobody can tie to a person is a finding; unattributed plain members
are a count in coverage. Nothing is filed because something was not declared: the admin
rule runs for a tenant only when `access.admins` names it, and the unattributed-admin
rule only when `people` holds at least one identifier for that tenant. Otherwise both
are *insufficient evidence*. `--stop-after recon` prints the unattributed owners, admins and
members as a `people` stanza to fill in. `service` and `break_glass` accounts are
exempt from the stale and never-logged-in rules and counted apart from human admins;
the report lists them.

Three traps the people rules must not fall into, each tested in the rule's fixtures: a
`left` date that has not yet passed in `engagement.timezone` (a person serving notice)
makes the left-person rule abstain until it has; a suspended account is correct
offboarding, never "still active"; and an account created recently that has never
signed in is a new hire, not a stale account, so the never-signed-in rule reads the
creation date.

**Accepted risks** follow `host-collector.md §5.2` for `id` (a catalog finding id or
`custom:`) and add `asset`, `subject`, `accepted_by` and `expires`. `subject` is the
finding's instance key (a login, a repository, `port/proto`); without it the acceptance
covers every instance of that id on that asset, and the report says so. Past `expires`,
the adjustment stops and the report says so; `expires` is a date in
`engagement.timezone`, compared with the collection time of the asset it names, never
the time the report is rendered. The report prints a ready-to-paste entry under each
open finding ("The report", "Findings").

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
  handle under `people`. Two handles with the same Workspace address or GitHub login
  exit 3, since no rule could tell them apart. `org` is taken by a contractor or an
  agency.
- A mail domain (`mail.senders[].domain`, `mail.no_mail`) falls under a `domain` root,
  and a domain listed both as sending and under `no_mail` exits 3. An intent URL falls
  under a root.
- An accepted risk needs `id`, `asset`, `reason` and `accepted_by`; an empty `reason`
  counts as missing.
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
  a file, a debug page) is not one. Every finding definition declares whether it is
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
it beside it. The `security-consultant` reviews and freezes them before E5 assigns the
first network collector's bases, and every later base is placed against them:

| Base | Anchors |
|---|---|
| critical | a usable empty password; a credential in a public repository or its history; a `pull_request_target` workflow that checks out the pull request's head with a write token, on a public repository, where anyone can open one |
| high | 2-step verification not enforced at the identity provider; a person who left still active (+1 `attribute:admin`); Owner on a human or service account; a public bucket; an admin without 2-step verification; a credential in a private repository or its history (scheck cannot tell whether it is live, and must not try); a write-all default workflow token with actions not pinned to a commit |
| medium | a write deploy key (+1 `deploys_to:production`); password SSH (+1 `exposure:internet` by the host collector); DMARC `p=none` on a domain that sends (a domain under `mail.no_mail` falls under the non-sending rules instead); an OAuth app with a broad scope (+1 `attribute:admin_grantor`) |
| low | missing HSTS; pending updates of unknown class |

## Reachability and vantage

Whether something is reachable depends on where the request came from. `scheck run
--vantage internet|vpn|lan` records the run's vantage in the run, not in the file. A
`not_exposed` rule fires only when the run's vantage is `internet` and the declared
audience is not `internet`; every other combination, and an unknown vantage, abstains.
`/admin` declared VPN-only and reached from the VPN is not a contradiction. The vantage
is the operator's word, printed in the report header and recorded on each piece of
evidence like the principal; a resume with a different vantage reads those entry
points again.

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

**No configuration file.** scheck reads no configuration file. Each key of 0.0.1's
`scheck.yaml` (`host-collector.md §8`) has one home:

| 0.0.1 `scheck.yaml` | From 0.0.2 |
|---|---|
| `context:` `role`, `exposure`, `environment`, `expected_services` | `assets.<name>.context` |
| `context:` `accepted_risks` | `intent.accepted_risks` |
| `context:` `data_classification` | `data.matters_most`, which ties it to an asset and moves severity |
| `context:` `compliance`, `owner`, other keys | not read: no consumer without a model ("Not asked") |
| `targets:` | `assets.<name>` (`host`, `identity`, `jump`) |
| `profile`, `elevate` | `defaults.profile`, `assets.<name>.profile`, `assets.<name>.elevate`; with `--host`, `--profile` and `--sudo` |
| `disable_checks`, `deny_paths` | `assets.<name>.disable_checks`, `assets.<name>.deny_paths` |
| `redact_extra` | `redact_extra` |
| `state_dir` | `--state-dir`; the default of `host-collector.md §6.4` |
| `provider`, `model`, `base_url`, `effort`, `max_context` | flags on the hidden `scheck eval` |

`scheck run` exits 3 when it finds `./scheck.yaml` or the user configuration file of
`host-collector.md §8`, naming each key the file sets and its new home, and saying what
to do: move the keys, then delete or rename the file. The two paths that contact
nothing, `--write-engagement` and `--stop-after intake`, print the same list as a
warning and go on, since they are how those keys move into a file. A narrowing a v0.0.1 user relied
on is never dropped silently, whichever release they upgrade to; the check costs two
file lookups and stays.

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

**The aliases, for 0.0.2 only.** `scheck local` is `scheck run --host local` and
`scheck ssh user@host` is `scheck run --host user@host`; each prints a deprecation line
on stderr, and both are removed in 0.0.3. Their 0.0.1 flags map as follows, and any
other exits 3 naming its replacement:

| 0.0.1 flag | Under `scheck run --host` |
|---|---|
| `user@host`, `--port`, `--identity`, `--known-hosts` | the user and port in the locator (`--port` wins over a port in the argument, as in 0.0.1); `--identity`, `--known-hosts`. `scheck ssh local` exits 3: `local` is this machine, `scheck run --host local` |
| `--sudo`, `--elevate`, `--profile` | the same, except that `--sudo` with `--elevate none` exits 3, where 0.0.1 let `--elevate` win |
| `--timeout` | the same: the host collector's run timeout, not `limits.timeout` |
| `--format`, `--out`, `-v`, `-vv`, `--state-dir`, `--no-persist` | the same; `--format json` prints the engagement report |
| `--include-evidence` | the same: with `--format json`, the hosts' redacted captures inside each embedded envelope, on stdout only |
| `--record-fixtures` (hidden) | the same: every exec of the host written to a fixture directory, post-redaction |
| `--stop-after context` | `--stop-after intake` |
| `--stop-after plan` | exits 3 naming `scheck catalog --platform P --profile P`, which lists the checks without contacting the host |
| `--stop-after facts` | no flag: it is the run |
| `--context`, `--ignore-context` | exit 3: context is `assets.<name>.context` in a file (`--write-engagement`) |
| `--audit-log` | exits 3 naming the run directory's `audit.jsonl` |
| the model flags, `--only`, `--local-only`, `--format sarif` | exit 3, as in 0.0.1 |

`scheck catalog`, `scheck explain` and `scheck sudoers` stay; `scheck config` goes with
the file it read. A 0.0.1 `./.scheck/context/` directory, which `local` and `ssh` read
implicitly, is refused like the configuration file, so its accepted risks never vanish
without a word.

**Exit codes.** The four codes keep their meanings (`host-collector.md §7`), and an
engagement fixes how they are reached:

- `1` when an open finding is at or above its asset's threshold: a host asset's profile
  sets it as in 0.0.1 (`baseline`: medium, `hardened`: low); every other asset uses
  medium. Accepted risks and `info` never count.
- `2` when the run is incomplete: a declared root had no successful read (coverage,
  below), or any asset's collection was cut by a transport failure, a run timeout or a
  limit (reasons `failed` and `limit_reached`). A check that is merely unavailable
  (elevation, permission, profile, narrowing) makes coverage *partial* and does not
  change the exit code, as in 0.0.1.
- `3` for usage, validation, policy and canary errors. Precedence is `3`, `2`, `1`,
  `0`.

For a host, exit 3 is a positive list. A host asset or its jump host with no SSH user is
refused by Scope before any target is contacted, so nothing is read and no run directory
is created. An unknown or changed host key, an unreadable identity or known_hosts file,
failed authentication and a canary mismatch are found on contact, and so are an unknown
or changed key on a jump host and failed authentication to it, before the host itself
is contacted: that host is recorded
as `refused`, the other assets are still collected and every stage is written before
the run exits 3, so nothing already read from a client's host is discarded. A canary
that never answers is not a mismatch: nothing was shown to be altered, so it is a
transport failure. Every other failure to reach a host (a name that
does not resolve, TCP refused or timed out, a handshake reset, cut off or past its
deadline, a jump host that cannot reach the host) is a transport failure: the asset is `failed` and the run exits 2. A session
lost after it worked stops that host's plan where it was lost, keeps what was read, and
is `incomplete` with reason `failed`: never a complete run of unavailable checks. A
session lost while the canary itself ran is a transport failure too, not a canary
mismatch: nothing was shown to be altered. As aliases of `scheck run --host`, `scheck
ssh` and `scheck local` follow these rules too: a host that never answered now exits 2
where 0.0.1 exited 3, the one change a CI job gating on `scheck ssh` sees. The canary's
echo is printed only after redaction, and cut short, in the JSON only.

For an API, a credential that is present but rejected (a 401, an invalid grant) is
the same positive list: that asset is `refused` with kind `access`, the other assets
are still collected, and the run exits 3. A declared SaaS root with no credential in
the environment is `no_credentials` and exits 2, as a declared root with no successful
read; Scope warns about it before any target is contacted, so the operator can stop
and set it. A provider's rate limit that the gate cannot wait out is `limit_reached`,
exit 2 ([scope.md](scope.md#outcomes)).

So a one-host run exits as the 0.0.1 command did for the same findings and the same
failures, except a host that never answered (2, a transport failure, where 0.0.1 said
3), and a CI job gating on `scheck ssh` keeps its meaning.

**JSON consumers.** The engagement report's JSON carries each host asset's collector
envelope (`host-collector.md §6.4`) whole, under that asset, with its own
`schema_version`; `run.assessment`, `assessments` and `facts` keep their shape one
level down. The report on stdout is complete without the run directory, so
`--no-persist` loses nothing, and `--include-evidence` adds captures to the embedded
envelope of each host this session collected ("Stop and resume"). The engagement's own findings are authoritative where their severity differs
from the envelope's ("The report", "Findings"). The aliases' deprecation line names the new path of `run.assessment`.

## Runs, state and configuration

**Nothing else configures a run.** The engagement file, the flags of "One command, one
file" and the environment's credentials are a run's whole input. A host's `elevate` is
the file's only key that widens what a host check may read, within the catalog; nothing
widens what the catalog may run or reveal.

**One directory per run.** A run lives under the state dir
(`host-collector.md §6.4`; `--state-dir` and `--no-persist` apply), created `0700`
and locked while a run holds it:

```
<state-dir>/engagements/<engagement.name>/<started>/
  run.json             the run's manifest: its start, the file's path and hash, each
                       session, the hash of every file a stage wrote ("Stop and resume")
  engagement.yaml      the file as read, its redact_extra masked (below);
                       for `--host`, the engagement built in memory
  scope.json           stage 2: resolved assets, evidence, exclusions
  recon.json           stage 3: the asset map
  plan.json            stage 4: the checklist per asset, and each host's planned and
                       disabled checks (with a model, hypotheses too)
  evidence/            stages 3 and 5: one file per result, redacted and truncated;
                       per host <asset>.json and <asset>.collection.json, and
                       requests/, the gate's successes a resume may reuse
  findings.json        stage 6: rule outcomes and follow-ups opened and settled
  report.json          stage 7, with report.txt
  audit.jsonl          every request, command and API call, in order
```

Everything in the directory is post-redaction. The engagement file is copied as read,
since validation guarantees it holds no credential, except for its `redact_extra`
patterns, which are often the very strings they hide: each is replaced by
`[REDACTED:redact_extra:<n bytes>]`, any other match of a pattern in the copy is
redacted, and the copy still validates. A file without `redact_extra` is copied
byte for byte; the original is named by path and hash in every stage document. Evidence keeps only the fields rules read: a full directory record carries
recovery phone numbers and addresses that no rule needs. Every piece of evidence
carries its collection time and the principal it was read as. A host asset's own run
JSON lands under `evidence/`, not under the host collector's `runs/<host.id>/`, so an
engagement never mixes with standalone host runs.

**In 0.0.2 (E1b, E2).** `<started>` is the start time in UTC, RFC 3339 to the second. The
lock is an `flock` on `.lock` in the directory, released when the run ends or its
process dies; a second run on a locked directory exits 3, and so does a new run whose
directory already exists, naming `scheck run <directory>` to resume it. `--stop-after
intake` validates and prints the file and creates no directory; without `--stop-after` a
run goes through Report, which writes `report.json` and `report.txt` ("The report"). Scope writes the declared
roots and assets entries, each domain, url and host asset with its first-party evidence
from the file (a `url` or `host` root, a `network` root holding its address, or
`operator`'s confirmation, printed as such) and every exclude, and refuses, before any
target is contacted, a host or jump host without an SSH user. From E4 it also expands
each `domain` root by passive discovery, through the gate and contacting no server of
the company's ([scope.md](scope.md#discovery)). Every asset of kind `host`, a root or an `assets` entry,
is collected; an asset of any other kind is `not_collected` with reason
`collector_not_built`, which makes the run exit 2 when the asset is a root. Plan writes an
empty checklist and Check opens no follow-up. `evidence/<asset>.json`, written by Recon,
is the host collector's envelope; its `context_sources` names `<file> assets.<name>` with
kind `config`, and the accepted risks it grades are those in `intent.accepted_risks` that
name the asset by catalog id without a `subject`, each attributed to its own entry
(`<file> intent.accepted_risks[i]`), a later entry for the same id winning. The host
grader accepts a whole id, so a `subject` acceptance is not widened into one: it is
listed under `acceptances_not_applied` in `findings.json`, printed as a warning and in
the report as not applied, and becomes applicable when host findings carry instance
keys. Accepted risks are graded at the start of the session that collected the host, in
`engagement.timezone`.
Recon writes every asset's commands to `audit.jsonl` and keeps each asset's entries for
the report's trace, so the trace survives `--no-persist`. A canary mismatch's echo is
kept apart from its detail (`echo` in `recon.json` and the report's JSON). Scope's refusals (a
host or jump host without an SSH user) happen before the run directory is created, so a
refused run leaves nothing behind. Stdout is the report, as text or with `--format json`
as `report.json` (`--include-evidence` adds the hosts' captures to stdout only); a run
stopped earlier prints that stage's document with `--format json` (`--stop-after check`
prints one that no file holds, since Check writes none until E9), and a summary per
asset as text.

**Stop and resume.** `--stop-after <stage>` ends the run after that stage's file is
written. `scheck run <directory>` resumes:

- **Per request, not per stage.** Each stage records the status of every request it
  made. A resume keeps what succeeded and sends again what failed, was rate-limited or
  was refused, each admitted by the gate from its first check, so a request refused
  before is refused again under the same file; a resume never replays a decision
  ([scope.md](scope.md#resume)). A paginated list is read again whole.
- **A host is resumed as a unit.** A host whose collection completed under the same
  inputs is kept; any other is collected again on a new session, canary first. A host
  costs seconds, and an envelope merged from two sessions would break what its command
  trace means (`host-collector.md §9`).
- **Only success is reused.** "No check re-runs with the same inputs" applies to
  successful results, and the inputs include the principal and its granted scopes, so
  a better token on resume reads again what the weaker one could not.
- **A changed engagement file.** The resume reads the file again at its recorded path,
  and each stage compares what it reads from it. If anything Scope reads changed, Scope
  runs again. A host is kept only while nothing its collection reads changed, the
  accepted risks that name it and `engagement.timezone` included: nothing regrades a kept envelope, so a changed
  accepted risk on a host collects that host again rather than re-running only Analyze
  and Report, which adds only contact the file already authorizes. A change to people,
  access, data, secrets or anything no host or Scope reads contacts no target. Reading
  again only the DNS names and entry points a changed `mail` or `intent` URL names is
  not built (0.0.2 E7): Scope runs again whole.
- **Hand edits.** A file the resume uses is used as written, and the report names each
  one edited since scheck wrote it; a host's envelope is never used as written (below).
  An edit cannot widen scope: the gate checks every request against the engagement
  file's roots and exclude, not against `scope.json`. `run.json` is trusted as written:
  whoever can write the run directory can change which engagement file it names and the
  hashes it holds, so the report's list catches an accidental edit, not a deliberate one
  that rewrites `run.json` too. The safeguard is that every resume prints on stderr which
  engagement file it read and its sha256.
- **Principal and time.** The principal per collector is recorded; a different principal
  on resume is printed in the report (E5, the first collector that reads a principal).
  The report prints the collection span from the run's first start, and time-based
  rules (stale accounts, expiries) are computed against collection time: scope and
  first-party confirmations are read at the start of the session that reads them, and a
  host's accepted risks at the start of the session that collected it.

**In 0.0.2 (E4).** `scheck run <directory>` resolves a path that reaches the directory
through a link, locks the directory and exits 3 when it is locked; when it holds no
`run.json` (not a run directory, or an earlier build wrote it); when it holds a link
anywhere inside it, anything but directories and regular files, a file or directory
another user owns, a regular file with another hard link, or a file or directory
writable by group or others, none of which scheck writes (another user who may write
`run.json` could point the resume at an engagement file of their own); when the directory it sits in
(`engagements/<name>`) is owned by another user or writable by group or others; and
with `--host`, `--write-engagement`, `--no-persist` or `--state-dir`. `audit.jsonl` and
`.lock` are opened without following a link, and `audit.jsonl` is checked again once
open: this user's, with one link. It reads the engagement file again from `run.json`'s
`file`, only when that is an absolute path to a regular file (a device or a pipe is
refused), and parses it under the name the first session gave it (`source.path`),
which its errors and the report's source path then name, so a run started from a
relative path keeps its hosts; for a run `run.json` marks `host`, it reads the directory's own
`engagement.yaml` (which `--host` writes unmasked). It exits 3 when that file is
missing or not valid, names another engagement ("start a new run"), or, for `--host`,
changed since scheck wrote it ("start a new run with `scheck run --host`"). Every
resume prints on stderr `resuming <directory> with <path> (sha256 <hash>)`, the path
being `run.json`'s absolute `file`, with `the engagement --host built` for the path of
a `--host` run; a file that does not load is named the same way, without its hash,
before the error. The report's command to run it again names the file by that absolute
path too, and a path that starts with `-` as `./<path>`, never as a flag. It then runs Intake through Report, or to
`--stop-after`, in the same directory, appending to `audit.jsonl`. The run's start stays
the first session's: the directory's name, the stage documents' headers, the report's
`run.started` and the start of the collection span.

`run.json` holds the run's start, the source `{path, sha256}`, `file` (the engagement
file's absolute path, written by the first session and never by a resume, so a relative
path is resolved against the first session's working directory; empty for `--host`),
`host` (true for a run `--host` built; a file named `--host` is a file run), `sessions` (each `{started, version, egress, ended}`), `files` (each file a stage wrote,
relative to the directory, with the sha256 of the bytes written) and `scope_inputs`. It
is written when a session starts, after each file a stage writes, and after each stage
with what the session has sent so far as its `egress`; `ended` is set when the session
ends.

- **Scope** is kept, its `scope.json` used as written and nothing sent, when
  `scope_inputs` is unchanged (a hash of the build version, the resolved roots,
  exclude, defaults, assets, `redact_extra`, `mail`, `intent` and `authorization`, and
  each asset's first-party evidence evaluated at the session's start, so a confirmation
  that expired or became current since runs Scope again) and the earlier Scope found no
  gap: every domain root's certificate transparency answer read, and no name
  `insufficient_evidence` or `not_checked`. Otherwise Scope runs again.
- **A host** is kept, never contacted, from one record alone:
  `evidence/<asset>.collection.json`, which Recon writes after the envelope
  `evidence/<asset>.json` for each host it collected, completely or not, as `{inputs,
  graded, envelope_sha256, recon, planned, trace}` (`recon` the asset's whole Recon
  entry, `graded` the start of the session that collected it). The host is kept when the
  record's inputs match, its `recon` status is `collected` with the same name and id,
  and the sha256 of `evidence/<asset>.json` as it is on disk equals both the record's
  `envelope_sha256` and `run.json`'s hash for that file. The record, its trace included,
  is used as written; the envelope never is: one edited, or written by a session cut
  before it recorded it, collects the host again, so no kept host mixes two sessions.
  `recon.json` is not read. The inputs are a hash of the build version and everything the collection
  reads (reach, user, identity, known_hosts, jump, elevate, profile, `disable_checks`,
  `deny_paths`, `redact_extra`, timeout, its context with the accepted risks that name
  it and `engagement.timezone`, in which their expiry is graded, the context's source,
  and the engagement's `exclude`, which its SSH dial is checked against).
- A build whose version names no commit (`dev`) or carries uncommitted changes
  (`-dirty`) keeps neither Scope nor any host.
- **The gate's successes** are written after each stage to
  `evidence/requests/<identity>.json` and listed in `run.json`'s `files`; the next
  session's gate is handed only those `run.json` lists, so a file placed there by hand is
  ignored ([scope.md](scope.md#resume)). A success this session sends again and keeps
  replaces the stored one, so a record that could not be reused is rewritten. No op in this build yields a reusable success,
  so the directory stays empty.
- **The report.** `run.resumed` is true, and the text header's `Resumed` line says the
  run was stopped and resumed, that what an earlier session read completely was kept and
  that everything else was read again. A file the resume used (`scope.json` when kept;
  `evidence/<asset>.collection.json` for a kept host; a success the gate reused) whose bytes differ from its hash in `run.json` is listed in
  `engagement.edited_by_hand` and on the header's `Edited by hand` line: `<files>:
  changed since scheck wrote it, and used as written.` ("them" for more than one). An
  acceptance's outcome and its "expires in N days" are decided at the time the host it
  names was graded, the start of the session that collected it. A kept host's asset
  carries `kept: true`; its captures were never stored, so `--include-evidence` adds no
  `evidence` to its envelope rather than empty captures that would read as a command
  that printed nothing.
- **What left this machine** covers this session and every earlier one, merged: sources
  by name and host, so DNS once per resolver (a session on another network asked
  another one) and DNS first, with their subjects and credentials unioned and counts
  summed; sites' requests summed; SSH names unioned. Each session records in `run.json`
  the hosts it reached (`sessions[].egress.Contacts`), each counted once Recon finished
  it, with the checks it ran there that may make a host contact its package
  repositories. The hosts row counts every session's: a kept host's contact and SSH
  names are the session's that collected it, not this one's, and a host reached in one
  session and collected again in the next counts in both; `host_side_effects` is the
  union of every session's, so a check disabled since still shows. A session that ends
  on an error is `ended`, its contacts recorded. An earlier session not marked `ended`
  (killed, or the machine stopped) recorded only what it had sent by its last finished
  stage: its start is listed in `egress.unrecorded_sessions`, and
  the block opens with `At least what follows: the session started <time> ended before
  it recorded all it sent. audit.jsonl in the run directory lists every request this
  run made.` (for more than one, `the sessions started <times> ended before they
  recorded all they sent`).

**Scope confirmations persist.** A first-party confirmation is an `assets` entry with
`first_party: {confirmed_by, date, target}` ([scope.md](scope.md#first-party-evidence)).
In 0.0.2 the operator writes it by hand: Scope asks nothing and prints no stanza to
paste, and lists each discovered name with what it points at, which is its `target`.
From 0.0.3, when a confirmation unlocks probes, the Scope stage asks, writes the entry
into the engagement file (the only key it writes after `scheck init`) and records the
new hash; `confirmed_by` is `engagement.operator`, which must then be a handle under
`people`.

## The report

The report is what the engagement delivers, and its first page decides what a small
team fixes this week. It has two jobs: put the few things to fix first in front of the
reader, and stop a short list from being read as cover where there is none. It is
written for the operator, not for their customers; a version to hand out is a later
audience option. Defined with the `security-consultant` (define and review modes) and
read by the `client` (report mode) for 0.0.2 E2; `report.txt` and `report.json` are
stage 7 of the run directory, and stdout carries the same report under
`--no-persist`.

**Words, not tokens.** The text report is read by someone who has not read this spec,
on a busy day. It prints plain words for marks and reasons ("Reason wording" below);
the tokens (`partial`, `no_rule`, `insufficient_permission:<scope>`) are the JSON's
and `-v`'s, where a consumer or a person searching for them reads them. In text a mark
is *checked*, *checked in part*, *not checked*, *not applicable* or *outside scheck*.
Templates never use a gendered pronoun: a person is named by handle or address, or
"the person".

### Order

| # | Section | Present |
|---|---|---|
| 1 | Header: name, operator, collection span, version, trigger, method, authorization, handling notice | always |
| 2 | Run status: what was refused, then what is incomplete, or which systems were read | always |
| 3 | Summary: what was checked and what was not, "Fix these first", the not-a-clean-bill statement | always |
| 4 | Coverage: the full table, the Hosts row expanded, the fold line, *Other declared SaaS* and *outside scheck* rows | always |
| 5 | Findings: ranked open findings, then informational, then accepted | always; "0 open findings" is written out |
| 6 | Not checked, grouped by what would close the gap | when anything was not checked |
| 7 | Excluded, narrowed and not run | always; probes and scans are one line in 0.0.2 |
| 8 | What left this machine | always |
| 9 | Notes for the readout | when any note exists |
| 10 | Close: the exit code and why, for automation; where the files are | always |

Coverage is read before any finding: the summary says, in two to five lines of plain
words, what was checked and what was not, above "Fix these first", and the full table
follows the summary so the top five stay on the first screen once the Hosts row
expands. Run status sits above the summary, so an incomplete or refused run is the
first thing read; with trigger `incident`, the incident block stays above it.

**Header.** The engagement name and `engagement.operator`; the collection span in
`engagement.timezone`, the zone named; the scheck version; the trigger (`not declared
(one-host check)` for `--host`); on a resume, the `Resumed` line, the files edited by
hand and, from E5, a principal that changed ("Stop and resume"). Fixed lines:

- Method, in 0.0.2: `rules only: a fixed checklist per asset type, no model, no
  hypotheses. Reading only: nothing was probed, scanned, exploited or changed. Not a
  penetration test.` A questionnaire asks for the date of the last penetration test,
  and this report's date must not be written there.
- Authorization absent: `none recorded. This run only read, with access you already
  hold; scheck requires a record only for probes and scans.` Holding access is not
  authorization, and the line must not teach that it is. Present: `by`, `date`, each
  window, `source` and `note`, and the levels used (`levels used: passive, observe.
  probe off, scan off.`). The block is the operator's declaration, never presented as
  verified ([scope.md](scope.md#authorization)).
- Handling notice: `Handle with care: this report names people, accounts, internal
  hosts and services, and says where weaknesses are. Keep it as private as a
  list of passwords. It is written for you, not for your customers.`
- Trigger `incident` adds, under the trigger: `This is not incident response. scheck
  does not look for signs of intrusion, and evidence read from a possibly compromised
  system cannot be trusted. This report lists weaknesses in what scheck could read; it
  cannot tell you whether you are safe now or how the incident happened. For that you
  need an incident responder; what this report can do is list weaknesses to close.`

**Run status.** One block per condition, refused before incomplete, each row `{asset,
reason, detail}` in words ("Incompleteness and refusals" below). When findings are
open and the exit code is 2 or 3: `Findings are also open: N at or above their asset's
threshold; see Findings below.` With nothing refused or cut, the block names what
was read and how much of it was judged, never "complete", "OK", "passed" or a sentence
that reassures before anything is read: `Read: deploy, google-workspace (checked only in
part: deploy, 4 of 13 host areas judged). See Coverage for what was not checked.` Only
collected assets are named as read: an asset no collector reads that is not a root (so
the run is not incomplete) is named apart, `Not read: shop (this version of scheck does
not read it)`. With nothing open at medium or above, the summary names per host how many
checks gave no answer, so "nothing open" is never read as a clean host.

**Summary.** Two to five lines, `Checked` and `Not checked`, naming areas and systems
in plain words; then "Fix these first" ("Ranking" below); then the not-a-clean-bill
statement with this run's numbers:

```
A short list is not a clean bill of health. scheck reports only what its rules could
decide. Checked in part: hosts. On deploy, 4 of 13 host areas were judged, each only on
the settings named under Coverage; 6 have no rule in this version and 3 had no usable
evidence. Not checked: identity and access, secrets, cloud configuration, … Anything not
checked is unknown, not fine.
```

Risk areas are named, never given as a fraction, which reads as a score; a host's areas
are counted, because "Hosts: checked in part" hides that most of a host was never
judged (the summary line reads `Hosts (deploy, 4 of 13 areas judged)`). Areas declared
under `not_used` are named as not applicable. On a `--host` run the not-checked list is
`Nothing but this host was looked at.` With nothing
open at medium or above the lead is `Nothing open ranks at medium or above among what
was checked.`, never "no findings", "all clear" or "nothing to fix". The summary has no
score, grade, percentage or compliance claim.

**Not checked, and what would close the gap.** Grouped by the action that closes it,
as the host report groups by remedy (`host-collector.md §6.6`): re-run with elevation;
for missing access, the permission needed, read-only where the provider offers it, and
where to look by hand for the one setting it hides ("GitHub > Settings >
Authentication security"), never "give scheck an owner's token" as the default; or
"this version of scheck does not read it; assess it by other means until it does". No
manual checklist is printed for a root without a collector: it would be a second,
unreviewed catalog.

**Excluded, narrowed and not run.** Every `exclude` entry and whether it matched
anything: an entry discovery covers prints how many discovered names it dropped, and
any other "not matched: nothing in this version discovers what it covers"; every
narrowing entry, as "narrowed in the engagement file", and what it removed; redaction
counts, built-in rules by rule and `redact_extra` as rules and matches, never a
pattern; for `deny_paths`, the reads each entry denied, each counted once under the
longest entry its requested path falls under, and any none accounts for (a symlink
into a denied prefix) under `deny_paths` as a whole; probes and scans (in 0.0.2: `none exist in this version; nothing beyond
reading was attempted.`, and from 0.0.3 the probes that would have applied, as *not
run*); acceptances not applied, with why.

**What left this machine.** One fixed block, defined with the gate (0.0.2 E4). A
client's data protection officer asks this question, and so does the CTO, often to
answer a customer's questionnaire, so it is written in plain words. Four groups, always
in this order, and a group with nothing in it prints `none`:

- *Third-party services* ([scope.md](scope.md#third-party-sources)): each source, who
  runs it when it is a public service, what it was sent, and the request count. The
  DNS line counts the control queries, and names `systemd-resolved` rather than
  `127.0.0.53`.
- *Your own systems*: per kind, the count of requests, SSH sessions or local runs, for
  assets with first-party evidence, and the servers a connection was attempted to that
  never answered, which are not sessions, and the jump hosts connected to or not
  reached, each server once whoever logs in to it. What SSH did is what its transport recorded, the host apart from
  its jump host (a name resolved, a connection attempted, one opened), never what the
  file declares: a host refused before any of it adds nothing, and a jump host reached
  is not a session with the host behind it. When such
  a check ran, a line saying which
  host check may make the host download its package list from its own update servers,
  with the check's id in brackets.
- *Names under your domains not shown to be yours*: the names, at most ten and then a
  count, and the requests to them, said as what a browser sends when it opens the
  page.
- *AI models*: `Nothing was sent to an AI model provider.`

On a resumed run the groups cover every session of the run, and the block opens with an
"At least what follows" line when an earlier session ended before it recorded all it
sent ("Stop and resume").

Then fixed lines: that nothing was sent to the makers of scheck, pinned by
`scripts/depcheck.sh`: no module outside a fixed list is in the build for any shipped
platform, and only the gate, the SSH transport, the model adapters (built only by the
hidden `eval` command) and the local target (which runs catalog entries) import an API
that reaches the network or a process; the User-Agent the gate set, when a web request was sent; and
where what
scheck read is stored and how to delete it, naming the people data read from a tenant
when one was read. Under `--no-persist`: `What scheck read is stored nowhere; the
report is on stdout.`

```
WHAT LEFT THIS MACHINE
  Third-party services:
    Your DNS resolver at 192.168.1.1, and whatever it forwards to, as for any web browsing on this network: names under your domains, the names they point to, and the services above; 214 lookups, including 2 random test names under your domains and one under invalid.
    crt.sh, a public certificate log run by Sectigo: asked which certificates exist for example.com and example.net; 2 requests. crt.sh sees this machine's internet address and those names, and may keep logs.
    api.github.com: example-org, using the credential in GITHUB_TOKEN (the variable's name; its value appears nowhere); 96 requests.
  Your own systems:
    websites shown to be yours: 3 sites, 9 requests.
    servers: 1 SSH session.
    One server check may make the server download its package list from its own update servers (pkg.dnf_check_update).
  Names under your domains not shown to be yours:
    www.example.com, blog.example.com and 10 more: 36 requests, what a browser sends when it opens the page (the certificate, and the home page over https and http). These servers may be a provider's or someone else's.
  AI models:
    Nothing was sent to an AI model provider.
  Nothing was sent to the makers of scheck: no telemetry, no update check.
  Every web request identified itself as "scheck/0.0.2 (security self-assessment)".
  What scheck read, including people's names and email addresses from google-workspace:example.com, is stored only on this machine, in ~/.local/state/scheck/engagements/acme/2026-10-07T09:00:00Z; deleting that directory removes it.
```

A source names the environment variable a credential came from, never its value. A
host named by an address puts nothing under third-party services. The names SSH
resolved with this machine's own lookup, a host's and a jump host's written as names,
are on a line of their own, since SSH asked the system's resolver for them, not the
gate; the hosts a jump host resolved are named on another, as resolved by the jump
host, not by this machine. A request counts once a connection was made. A source's
line words what it was sent; GitHub's and Google's are worded with their collectors
(E5, E6). The sentence about macOS resolvers from
[scope.md](scope.md#third-party-sources) follows the DNS line when it applies. Who
runs a public source is data held beside its op, so it cannot drift from the code.
JSON carries the block as `egress: {sources: [{source, operator, host, sent, requests,
credentials, control_lookups, control_invalid, scoped_resolvers_ignored}], assets:
[{kind, requests | sessions | unreached | jump_hosts | jump_unreached | runs, sites}], unconfirmed: {names,
requests}, host_side_effects: [check ids], model: "none", telemetry: "none",
user_agent, stored, tenants_read, ssh_resolved, ssh_resolved_by_jump,
unrecorded_sessions}` (the last only on a resume that has one): every fact the text
states, so a reader of the JSON gets the same answer.

**Notes for the readout.** Not findings, and not counted: `first_party` entries that
expired or whose target moved, so someone removes them; what each acceptance came to
when it was not applied ("Acceptances" below), acceptances that expire within 30 days
or have no `expires`; a listed admin who is not one; a declared person or system
scheck found no trace of; declarations scheck could not verify; the count of
unattributed members; the service and break-glass accounts, listed ("People").

**Close.** For automation, and for whoever wires scheck into a pipeline: the exit code
and why, then where `report.txt`, `report.json`, `audit.jsonl` and the evidence are.

| Exit | Line |
|---|---|
| 0 | `Exit 0: no open finding at or above threshold among the N rules that could decide. That is not a clean result: M rules had no usable evidence, and K areas were not checked.` |
| 1 | `Exit 1: N open findings at or above their asset's threshold (<asset>: <severity>, profile <p>; every other asset: medium). Exit 0 would not have meant a clean result either.` |
| 2 | `Exit 2: incomplete.` and why; with open findings, `Exit 2 takes precedence over exit 1, so a pipeline that gates on exit 1 will not see the N open findings.`; then the exit-0 sentence |
| 3 | `Exit 3: <asset> was not assessed: <reason in words>.`, then `The other assets were read and are reported above.` only when there are other assets, and the precedence sentence with `Exit 3` when findings are open |

`--no-persist` is for host runs only: a run with any other root or asset is refused
before any contact, since the gate's audit log is the record of what was sent
([scope.md](scope.md#audit)). Under it the close says that no run directory or audit
log was written and that the command trace is in the JSON report.

### Coverage

The marks are mechanical, computed beside the rules and tested, never inferred by a
renderer:

| Mark | Text | Means |
|---|---|---|
| `assessed` | checked | every sub-item of the area decided with recognized evidence on every in-scope asset it applies to |
| `partial` | checked in part | some did; the row names what decided and what did not |
| `not_assessed` | not checked | none did; the row gives the reason |
| `not_applicable` | not applicable | the operator declared under `not_used` that the area does not apply (`not_used: [hosts, cloud]`); printed as their declaration |
| `outside_scheck` | outside scheck | scheck does not cover this area in any mode |

**A sub-item is a rule, never a check.** A rule that is not applicable on a platform
is no answer about the host: it leaves the count, and a family whose only applicable
member could not decide is *not assessed*. For a network collector it is a rule (or a
family of rules sharing a finding id) applied to an asset. For a host it is a finding
id on that host: a host domain is *assessed* when every selected rule in it decided
(matched, not matched, or not applicable on recognized evidence), *partial* when some
did, *not assessed* when none did. A domain whose checks ran but that no rule judges is
*not assessed* with reason `no_rule`, and its detail names what was read ("2 listening
sockets read; whether they should be reachable is not judged"): rules alone judge no
Linux listener and no host firewall (`host-collector.md §6.5`), and "check ran" must
never read as "risk judged". Rules that share a finding id on one host are a family:
when one decided on complete evidence (`updates.pending` through apt), the others
failing with `command_missing` (dnf, zypper) do not lower the domain's mark and are
listed only under `-v`. Host domains that carry no rule (host identity, operating
system, session and shell, text utilities) are not coverage at all: they are absent
from the table and its JSON, and their facts stay in the host's envelope.

**A mark counts its population.** Each row and sub-item carries `population: {kind,
in_scope, read}`: the assets (or repositories, users, entry points) of the kind it
reads that are in scope, and how many were read. A row is *assessed* only when every
in-scope one was; CI/CD read on two repositories of an organization with 120 in scope
is *partial*, with "2 of 120 repositories". A cap carries its `selection` ("the 40
most recently pushed"), since a sample nobody can name cannot be compared between
runs.

A reason is one of `no_credentials`, `insufficient_permission:<scope>`,
`not_on_plan:<feature>`, `collector_not_built`, `refused` (an asset refused the access
scheck was given, on the positive list of "Exit codes"), `not_declared` (no root of the kind this area reads was
declared), `excluded_by_operator`, `limit_reached`, `failed`, `sampled`,
`unavailable:<reason_code>` (a collector's own per-read reason, kept verbatim after the
colon) or `no_rule` (read, but no rule in this version judges it), with a detail line.
A row that is not *assessed* always carries its reasons: a *partial* row usually has
several (a permission, an excluded unit, a sample), so a row holds a list, never one
"main" reason. `sampled` makes a row at most *partial*. Only `failed` and
`limit_reached` on a cut collection, and a declared root with no successful read,
change the exit code ("Exit codes"); an `unavailable` read makes coverage *partial* and
does not. A host's `reason_code`s (`host-collector.md §6.4`) map as follows:

| Host `reason_code` or cause | Coverage reason |
|---|---|
| `requires_elevation`, `sudo_refused` | `insufficient_permission:sudo` |
| `run_timeout`, `canceled` | `limit_reached` |
| `path_denied` by the asset's `deny_paths`; a check in `disable_checks` | `excluded_by_operator` |
| a check above the asset's profile | `not_on_plan:profile=<profile>` |
| `path_denied` by compiled policy | `unavailable:path_denied` |
| `command_missing`, `check_timeout`, `exec_error`, `exit_error`, `parse_error`, `extract_error`, `metadata_unavailable` | `unavailable:<reason_code>` |
| `unknown_check`, `invalid_params` | `unavailable:<reason_code>`; a defect, never expected in a report |
| the check ran, but its rule could not read what it returned (`unrecognized-value`, `partial-output`, …, `host-collector.md §6.5`) | `unavailable:<reason>`, hyphens as underscores |
| a fact read that no rule judges | `no_rule` |
| the session lost after it worked | `failed`; the checks after the loss are `not_run`, never `unavailable` |

**Reason wording.** The text prints each reason as a fixed phrase, with the detail.
Each phrase says what is unknown and what would change it; none reads as a verdict on
the target:

| Reason | Text |
|---|---|
| `no_credentials` | no access was given for it |
| `insufficient_permission:<scope>` | the access scheck was given cannot read this; it needs `<scope>`, read-only where the provider offers it |
| `not_on_plan:<feature>` | your plan with the provider does not include `<feature>`; for a host profile, not in the checks you chose (profile `<p>`) |
| `collector_not_built` | this version of scheck does not read `<kind>` |
| `refused` | an asset refused the access scheck was given; its line names the cause by kind ("its host key changed, so it was not contacted", "GitHub did not accept the token") |
| `not_declared` | not part of this engagement; to include it, list it under `roots` in `<file>` |
| `excluded_by_operator` | left out by the engagement file (`<entry>`) |
| `limit_reached` | stopped by a time, size or rate limit (`<limit>`) |
| `failed` | not run: scheck's connection to the host dropped before this check; for a host never reached, "could not connect from this machine" |
| `sampled` | only part was read: `<n> of <m> <unit>` (`<selection>`); the rest is unknown |
| `unavailable:command_missing` | the tool that would tell is not installed on the host, so scheck could not tell (this is not a finding) |
| `unavailable:exclusion_unknown` | scheck could not tell which items your exclusions cover, so it kept none |
| `unavailable:redirect_out_of_scope` | the site sent scheck somewhere outside your roots, which it did not follow (`<location host>`) |
| `unavailable:redirect_not_entry_point` | the site redirected to another of its pages, which scheck read only as the redirect (`<path>`) |
| `unavailable:address_not_public` | the name points at a private or reserved address, which scheck does not contact from outside a declared network |
| `unavailable:<other>` | the command or request that reads it did not give a usable answer (`<code>`) |
| `no_rule` | not judged: this version of scheck has no rule for it; the detail says what was read and what was not |

A token is never wrapped across lines; the detail wraps.

Each row also carries the assets covered and those excluded by name; the principal the
data was read as (once per asset in text, per row and per piece of evidence in JSON),
with where its permissions came from (`provider`, `declared` or `unknown`; text prints
"permissions not readable" for `unknown`, never "read-only"); the collection span (per
row in text only when it differs from the header's); caps and sampling, with the
selection; narrowing that removed something; and declared facts scheck did not verify
("backups declared in gcp:example-backups, not verified"), the line most often misread
as verified. An excluded organizational unit is named and makes the row at most
*partial* ([scope.md](scope.md)). Per-sub-item marks print in text only when they are
not *assessed*; JSON carries them all, and every `not_applicable` assessment.

`not_used` takes the area keys `identity`, `secrets`, `cloud`, `data`, `cicd`,
`external`, `web`, `hosts`, `email` and `logging`, in the order of the table below.

| Risk area | Sub-items |
|---|---|
| Identity and access | MFA and 2-step verification enforcement and enrolment, admins against `access.admins`, people attribution (with the count of unattributed members), stale, suspended and external accounts, OAuth grants |
| Secrets | secrets in repositories and their history, CI secret names, credential files on hosts. At most *partial* in 0.0.2: CI logs, chat and shared documents are not read |
| Cloud configuration | public storage and snapshots, broad IAM, service account keys, VPC firewall rules |
| Data stores and backups | public access to databases, backup existence and location. A declaration alone is *not assessed* |
| CI/CD and supply chain | branch protection, workflow token permissions, deploy keys, action pinning, dependency alerts |
| External surface | domains, subdomain takeover, exposed services, TLS |
| Web application | headers and cookies at entry points; exposed files and debug routes from 0.0.3 |
| Hosts | the host collector's catalog (`host-collector.md`), expanded below |
| Email and domain | SPF, DKIM per declared selector, DMARC, non-sending domains |
| Logging and incident readiness | audit logging enabled, alerting on administrative changes |
| Malware and stolen sessions | *outside scheck*: scheck reads the settings of the hosts you list; it does not look for malware, infostealers or signs of compromise on any of them, and laptops you did not list were not looked at. Without the row a report on a laptop reads as covering what happens on it |
| Application logic | *outside scheck*: authenticated testing of access control and business rules |
| Processes | *outside scheck*: whether offboarding, incident response and vendor reviews are done as written. The accounts themselves are checked under Identity and access; without the row, "Identity: checked" reads as "offboarding is handled" |
| Lookalike and typo domains | *outside scheck*: registrations of names you do not own are outside every root ([scope.md](scope.md)), and they are the most common small-company email fraud |
| Other declared SaaS | one row per tool in `tools` without a collector, by name |

**The Hosts row** is one block per host asset, under a mark that aggregates them (all
*assessed*: *assessed*; none: *not assessed*; otherwise *partial*). Each block has an
identity line (name, canonical id, operating system, principal and elevation,
collection span), a counts line (`checks N: R ran, U unknown, X not run. rules M: D
decided, I had no usable evidence.`, the same counts the run status uses), one sub-row
per host domain that carries a rule, in the order of the host report's domains. A
sub-row never prints a bare mark that reads as a pass: a checked domain names what its
rules judged and what they found (`checked (password login, direct root login):
nothing found by these rules`, or `: 1 open finding (see Findings)`), then what was
read there that no rule judges (`also read, not judged: 9 SUID files`); a domain no
rule judges reads `not judged: …` with what was read; the rest give their reasons. The
JSON carries the same as `judged` and `read_not_judged` per sub-item. The Hosts mark
adds `N of M hosts read` when a host was not read; `Narrowed in the engagement file:` when narrowing removed
anything, a check with no rule included; and `Declared, not verified:` for host context
no rule consumes in this version (`expected_services` before E9). With more than three
hosts, each block collapses to its identity and counts lines and the domains that are
not *assessed*.

**The fold line.** Rows whose reason is `not_declared` fold into one line, labeled `Not
requested`, only when no declaration in the file points at the area. An area the file
half-declares (a `tools` entry with no root, backups under `data.backups`, a
`secrets.production` store on an undeclared asset, mail senders with no domain root)
keeps its own row with the declaration printed, since folding it would hide the gap
the operator half-knows about. On a `--host` run the line reads `Not requested: a
one-host check reads this host only. Your accounts, code, cloud, domains and email were
not looked at.` JSON never folds. The *outside scheck* rows print on every run,
`--host` included, and never fold.

### Ranking

"Fix these first" ranks **items** and is labeled `Fix these first: a ranking of what
was checked, not of all your risks`. The findings list opens with `Ranked by severity
in your context, among what scheck checked. Areas not checked may hold worse problems
than anything here.`

- Only open findings rank. Accepted findings are listed apart; `info` is listed apart.
- An item is of kind `finding_id`, every open instance of one id across subjects and
  assets, at the highest severity among them, naming the assets or the count; or, from
  E9, of kind `person`, the findings tied to one `people` handle across tenants ("carol,
  who left on 2026-09-15, is still active in Workspace and GitHub"), since one action
  fixes them. The findings list groups the instances of one id on one asset into one
  block that lists the subjects; JSON never groups.
- Order: severity after context, critical first; then risk area in the coverage
  table's order; then an asset named in `data.matters_most` first; then more affected
  instances; then canonical asset id and finding id. Thresholds do not enter the
  ranking: they set the exit code, and the close names them.
- Up to five items, open, at medium or above, never padded with low or info. With
  fewer: `Nothing else open ranks at medium or above. Below: N low, M informational, K
  accepted.` With more, the summary never says "nothing else": `N more open at medium or
  above; see Findings.`, and the JSON counts them (`summary.more`).
- Each item carries its basis (`rank_basis` in JSON: `["severity:high",
  "area:identity", "data_matters_most:deploy"]`); the text prints one phrase of it only
  when context moved severity ("base medium, raised: you declared deploy
  internet-facing").

With rules only, the ranking is the base-severity table plus context, so base
severities are calibrated across collectors ("Base severity anchors" in "Severity in
context").

### Findings

**One record per instance**, keyed `{id, asset, subject}`. `asset` is the canonical id
(`host:203.0.113.5:22`, `saas:google-workspace:example.com`,
`repo:github:example-org/shop`), declared or found under a declared root; the bound id
(`host.id`, a Workspace customer id) is a field beside it, always present and null
when the asset binds to nothing, so a finding whose asset changed address but not
identity is reported as the same asset moved. `subject` is the instance key, or null for
the asset itself; severity, acceptance and a later comparison of runs are all per
instance, so an `instances[]` array would be reshaped the first time two instances of
one id graded differently.

| Field | Holds |
|---|---|
| `key` | `{id, asset, subject}`: the join key for acceptance, grouping and comparing runs |
| `asset_name`, `bound_id` | the `assets` name, or the id; the bound id or null |
| `subject` | `{kind, key, label, provider_id?, person?}`. `kind` is declared per finding definition (`account`, `org_unit`, `group`, `deploy_key`, `token`, `principal`, `oauth_app`, `service`, `repository`, `workflow`, `branch`, `webhook`, `invitation`, `secret_location`, `dns_name`, `url`, `declaration`). `key` is short and typable, what `accepted_risks[].subject` takes; `label` is what a human needs to recognise it, built only from fields rules read; `provider_id` survives a rename; `person` is the `people` handle when attributed |
| `id`, `title` | `id` is the join key into `scheck explain` |
| `area` | one of the ten area keys; required on every finding definition |
| `category` | the collector's own grouping |
| `exposure_finding` | required on every finding definition: whether "exposed on purpose" may move it ("Severity in context") |
| `severity`, `severity_base`, `adjustments[]` | each adjustment `{rule, by, delta, source}`: `rule` from the closed table of "Severity in context" or the collector's own, `by` `collector` or `engagement`, `source` either `{file, key}` for a declaration or `{observation, excerpt}` for a fact; no non-base severity without its chain |
| `status`, `acceptance` | `acceptance`, present exactly when the status is `accepted`, is `{entry, reason, accepted_by, expires, expired, covers_every_instance}` |
| `rule` | `{kind: single_fact \| multi_fact, reads[]}`: the check, request and declaration ids the rule reads, in the vocabulary of `assessments[]` |
| `evidence[]` | at least one observed item. Observed: `{asset, check \| request, observation, collected_at, principal, excerpt}`; declared: `{source: "engagement.yaml <key path>", excerpt}`. A declaration supports a finding and never makes one alone |
| `derived[]` | computed values (`days_since_left`, `age_days`), always against collection time; each states what a field shows, never who acted |
| `affected` | secondary subjects (the users who granted an OAuth app, the repositories a token reaches): `{count, listed[], cap, of_note[]}`, the cap printed |
| `impact` | from the definition |
| `why_here[]` | templated lines from attributed context only, never free prose; empty prints "No context was declared for this asset; this is the catalog's generic assessment." |
| `not_checked[]` | what the rule could not see that would change the conclusion ("whether a cloud firewall in front of deploy restricts port 22") |
| `remediation` | `{summary, steps[], commands[], caveat, where}`; `where` is a console path for a SaaS finding, which has no command. Steps are in the order a responder takes them: contain first (suspend, revoke sessions and tokens), then remove access, then review what happened, then clean up |
| `accept_template` | present exactly when the status is `open`: the ready-to-paste entry, structured; text renders it as YAML |

In text a finding prints its evidence as `Observed` (an observation) and `You
declared` (a declaration), a multi-fact finding as `Concluded from` and the facts it
combined by reference (`people.carol.left`, `workspace.users#1`), then derived values
in words ("last sign-in 2026-09-28, 13 days after the declared leaving date; scheck
cannot tell who signed in"), `Severity` with its chain, `Why here`, `Not checked`,
`Fix`, and the paste. A contradiction prints both sides on two lines, the declaration
and the observation.

**Subjects.** Host findings carry no subject in E2: no rules-only host finding names a
listener, and the host grader accepts a whole id. A listener's subject, `{kind:
service, key: "<port>/<proto>"}`, arrives in one slice with the listener rule and with
host acceptance by subject. A person's account is keyed by the address rules match
people by, with the provider's id beside it. A token is keyed by its credential id and
labeled with its owner, name, scopes and expiry, never any part of its value; scheck's
own principal is keyed by the name of the environment variable it came from. An OAuth
grant is one finding per app, keyed by client id, with the users who granted it under
`affected` and an admin or break-glass grantor under `of_note`: the fix is one action
on the app. A secret found in a repository is keyed `<detector>:<path>@<commit, 12
hex>` and labeled with the detector type and first commit, never a hash of the value,
which a low-entropy secret does not survive and which would sit in every comparison of
runs; two secrets in one file stay two findings. A subject whose key matches
`redact_extra` renders as its marker; its paste uses `provider_id` when there is one,
and otherwise has `by_subject: false` and says the finding cannot be accepted by
subject while the pattern hides its name.

**The paste.** Once, after the findings, under `IF YOU DECIDE NOT TO FIX A FINDING`, headed
`Only for a risk you decide not to fix, and decided by whoever owns it: paste the entry
under intent.accepted_risks in <path of the engagement file> and write the reason.`,
one entry per open finding labeled with its title (the findings list points to it
once). Printed under every finding it made a report with seven findings twice as long
and read as a to-do. Each entry:

- `id`; `asset` as the `assets` name, or else the canonical id, which validation
  accepts for an asset under a declared root ("Identity, references and validation");
  `subject` when the finding has one, with a comment that omitting it accepts every
  instance on the asset.
- `reason: ""`, which validation rejects until it is written.
- `accepted_by: ""`, with the candidate handles in a comment (`# a handle under
  people: alice (admin of google-workspace)`): a risk is accepted by its owner, and a
  prefilled name lets an edit attribute an acceptance to someone who never saw it.
  Validation rejects it empty.
- `expires`, the collection date plus 90 days for critical and high and 180 days
  otherwise, in `engagement.timezone`, with the comment `# after this date the finding
  counts again until someone re-reviews it`.

An engagement without `people`, as every `--host` engagement is, is headed instead to
write the engagement to a file (`--write-engagement FILE`), add yourself under people,
paste, and run `scheck run FILE` from then on; its `asset` is the name
`--write-engagement` gives the asset, which a test pins.

**Accepted and adjusted findings show.** An adjusted finding prints its chain
(`high: base medium, +1 exposure internet (assets.deploy.context.exposure)`); an
unadjusted one prints its severity alone, and its why-here line says scheck was not told
how the machine is used, so this is the standard rating. One
lowered to `info` by intent is listed under informational with the operator's own
reason, never dropped. An accepted finding is listed under accepted with the severity
it would have had, `accepted by <handle> until <date>` (and "expires in N days" at 30
or fewer) or `accepted by <handle>, no expiry`, the quoted reason, its entry, and
"covers every instance of this id on this asset" when the acceptance has no `subject`.
Past `expires` the finding is open and ranked, with `the acceptance by <handle> expired
on <date> (<entry>); the finding is open again`, and the acceptance's outcome is
`expired`. Notes and the not-applied list name an acceptance by the finding's title, the
asset and who accepted it, its entry last. The host collector's own
`risk.acceptance_expired` (`host-collector.md §5.3`) stays in its envelope; the
engagement's findings leave it out, since it rests on the file alone and a finding
needs observed evidence.

**Acceptances.** Each `intent.accepted_risks` entry ends as one of `applied`,
`expired`, `not_applied` (with why: a host acceptance by subject, before host findings
carry one), `not_matched` (its rule decided on complete evidence and found no
instance: "likely fixed. Confirm, then remove the entry"), `rule_not_decided` (its rule
could not decide, or found nothing in only part of what is there: the acceptance still
stands and scheck cannot say whether the problem is gone) or `subject_not_found` (the
rule found instances, none with that subject). Only `not_matched` may say "fixed".

**One severity.** The engagement's `findings[]` is authoritative. A host asset's
embedded collector envelope stays whole as that collector's evidence and grading; an
engagement finding's chain starts from the envelope's chain (`by: collector`) and
appends the engagement's own adjustments (`by: engagement`), and the schema says so on
the envelope.

### Incompleteness and refusals

`findings.json` and the report carry each as `{asset, asset_name, reason, detail,
effect}`: `asset` the canonical id, `reason` from the closed list, `detail` escaped,
post-redaction text, for a refusal its `kind` (`host_key_unknown`, `host_key_changed`,
`jump_host_key_unknown`, `jump_host_key_changed`, `excluded`, `jump_excluded`, `access`, `canary`), which picks the sentence below and prints the raw error only at
`-v`, and `effect` what was lost (`{checks_run, checks_unknown,
checks_not_run, kept}` for a host, `{requests_not_sent}` for an API). They print in run
status, refused before incomplete, each in the order of `roots`:

| Case | Text | Exit |
|---|---|---|
| Unknown host key | `REFUSED: deploy was not contacted: its host key is not in your known_hosts file. Confirm the fingerprint with whoever runs the host, then add it.` | 3 |
| Unknown key on the jump host | `REFUSED: deploy was not contacted: the host key of its jump host ops@198.51.100.7:22 is not in your known_hosts file. Confirm the fingerprint with whoever runs the jump host, then add it.` | 3 |
| Changed key on the jump host | `REFUSED: deploy was not contacted: the host key of its jump host ops@198.51.100.7:22 changed. A changed key can mean a reinstalled server or an interception; confirm the fingerprint with whoever runs the jump host before you accept it.` | 3 |
| Host address excluded | `REFUSED: deploy was not contacted: its name resolves to an address your engagement file excludes. Remove the exclude if the host is in scope, or the host if it is not.` (for a jump host: `its jump host ops@198.51.100.7:22 resolves to an address your engagement file excludes, and scheck never connects to an excluded address.`) | 3 |
| Changed host key | `REFUSED: deploy was not contacted: the host key for 203.0.113.5 changed. A changed key can mean a reinstalled server or an interception; confirm the fingerprint with whoever runs the host before you accept it.` | 3 |
| No SSH user, unreadable identity or known_hosts, failed authentication | `REFUSED: deploy: scheck could not use the access it was given (authentication failed for deploy@203.0.113.5 with ~/.ssh/deploy). Nothing was read from it.` | 3 |
| Canary mismatch | `REFUSED: deploy: scheck stopped before running any check, because the host's login shell changed what it sent back (often a login banner or a profile script that prints text). This does not by itself mean the host is compromised: ask whoever runs it to look at its login scripts. The raw reply is in report.json.` | 3 |
| Session lost | `INCOMPLETE: deploy: the connection was lost after 18 of 33 checks; 15 were not run. What was read before is kept and assessed. scheck only reads; an interrupted run leaves nothing half-changed.` | 2 |
| Host run timeout | `INCOMPLETE: deploy: the host collector's timeout (10m, assets.deploy.timeout) stopped it after 25 of 33 checks.` | 2 |
| `limits.timeout` | `INCOMPLETE: limits.timeout (1h) ended the engagement: <assets> were not read.` | 2 |
| Unreachable before contact | `INCOMPLETE: deploy: could not connect from this machine (connection timed out). This does not tell you whether it is up for anyone else. Nothing was read.` | 2 |
| Root with no collector | `INCOMPLETE: example-org (GitHub organization): this version of scheck does not read it. Nothing was read from it.` | 2 |
| Credential rejected | `REFUSED: example-org (GitHub organization): GitHub did not accept the token in GITHUB_TOKEN (expired, revoked or mistyped). Nothing was read from it.` (or `37 requests were read from it.` when it was rejected mid-run) `Set GITHUB_TOKEN to a current, read-only token.` | 3 |
| No credential | `INCOMPLETE: example-org (GitHub organization): neither GITHUB_TOKEN nor GH_TOKEN is set, so nothing was read from it. Set one to a read-only token.` | 2 |
| Provider rate limit | `INCOMPLETE: example-org (GitHub organization): scheck stopped after 140 requests to leave a fifth of this token's GitHub rate limit for its other uses; the limit resets at 15:02 (Europe/Madrid). What was read is kept and assessed.` | 2 |

Counts agree everywhere they appear: "18 of 33" in run status is the checks attempted
before the loss, and the Hosts block's counts line splits the same 33 into ran,
unknown and not run. User text names no slice ("0.0.2 E5" is project jargon); JSON may
carry `planned_in`. The canary echo is never printed in text: it is
attacker-influenced output from a host that just failed its trust check, and it lives
redacted and cut in `report.json`'s `echo` only.

### What never appears

In no output (report, run directory, stdout, stderr):

- pre-redaction bytes; a `redact_extra` pattern; a redaction count a target could forge:
  the runner's count per capture is the total, markers in the capture name its rules only
  when they account for exactly that total, and the rest is counted as `unattributed`;
- a credential, including the values of the environment variables a collector
  authenticated with (their names, and the principal's identity and scopes, are
  printed); any part of a secret or token value, even one a provider returns (GitHub's
  `token_last_eight`), which collectors do not store; a hash of a secret value as an
  identifier;
- directory fields no rule reads (display names, recovery phone numbers and emails,
  addresses, employee ids, photos), which the schema has no place for;
- captures, except with `--include-evidence`, and then only in JSON (`report.txt` is
  always rendered at default verbosity);
- a word that states a posture verdict ("secure", "pass", "clean", "compliant", "no
  issues", "OK" beside an area, a tick, a score, a grade, a percentage);
- a claim that misuse, intrusion or compromise happened: a derived value states what a
  field shows (a sign-in date), never who acted;
- anything implying the report was reviewed or signed by a person: the operator's name
  is the engagement's owner, not a signatory;
- a severity without its chain; a finding without observed evidence; a finding filed
  from the absence of a declaration;
- unescaped text, whether derived from a target or written by the operator
  (`authorization.note`, `reason`, `role`, `purpose`), escaped as `host-collector.md
  §6.6` describes.

The JSON carries the handling notice as `notice: {personal_data: true,
internal_topology: true, audience: "operator"}`, so a consumer knows not to forward
it; no pseudonymised or shareable version is claimed.

### Text and JSON

JSON (`docs/engagement-report-schema.json`, `schema_version` `MAJOR.MINOR`, free to
change until 0.0.2 is published) carries what a consumer agent or a comparison of runs
(0.0.3 G6) needs and the text leaves out:

- `run: {started, directory, resumed}`, the scheck version and `rules_version`, so a
  finding that disappears because a rule changed between versions is never read as
  fixed; the engagement source `{path, sha256}`, where for `--host` the hash is of the
  engagement exactly as `--write-engagement` would write it;
- `exit: {code, reasons: [{code, why, asset}], thresholds}`, each threshold with its
  basis (`profile:baseline`, `default`);
- `incomplete[]` and `refused[]`;
- every coverage row unfolded with its reasons, population, sub-items, principals,
  spans, caps with their selection, and narrowing;
- `findings[]` flat, one record per instance, in the order the report ranks them (open
  by severity after context, risk area, data that matters most, asset and id; then
  informational; then accepted), so a consumer reading in order reads the most serious
  first;
- `assessments[]`, one record per rule and asset: its status, its `instances` count,
  whether it was `complete` (it decided on unmarked evidence **and** read its whole
  population: no cap, sample, excluded unit or page limit; for a host, not a check that
  reads a bounded sample by design such as a depth-capped `find`, not a truncated
  capture, and not a command whose non-zero exit was tolerated), its reason, and every input
  it read, declarations included (`declared:people.carol.left`), so a later run reads an
  instance as *fixed* only when its rule decided on complete evidence with the same
  declared inputs, and otherwise as *no longer observed, not assessed*;
- `summary` with its items (`kind`, `ids[]`, `person`, member keys, severity,
  `rank_basis`) and disjoint area counts (`assessed`, `partial`, `not_assessed`,
  `not_applicable`, `total`);
- `acceptances[]`, every `intent.accepted_risks` entry with its outcome and the
  findings it touched;
- `redaction` counts;
- `assets[]` with name, canonical and bound ids, kind, root, status, reason, detail,
  collector, principal, evidence path, and for a host its plan's counts (`checks`:
  planned, ran, unknown, not run) and its collector envelope whole ("JSON consumers");
- `notes[]` as `{kind, source, detail}`; `notice`;
- **the command trace**, per asset, always: each check or request id, its bound
  parameters (post-redaction), when it ran, its decision and its output hash, so a run
  under `--no-persist` still says what touched every asset and when.

Enums a later collector will extend (subject kinds, note kinds, adjustment rules, asset
kinds, reasons' parameters) are open by design: adding a value is a MINOR change, and
the schema's description tells consumers to tolerate one.

Text only: the plain wording of marks and reasons, the summary sentences, the fold
line, the grouping in "Fix these first", remedy phrasing, the YAML of the paste, the
closing sentences, and colour on a tty (decided in `cmd/scheck`, `host-collector.md
§6.6`). A host's fact sheet prints under `-v`, not by default, and `-vv` adds its
redacted captures, as in 0.0.1.

The text and JSON reports are pinned by golden files under the rules of the host
report's (`host-collector.md §9`).

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
