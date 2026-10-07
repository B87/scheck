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
| **2. Scope** | Expand the declared roots into assets with passive discovery and cloud inventory, drop what is excluded, record which assets have evidence of being first-party, and apply defaults. The operator sees the resolved list before anything beyond passive runs. | Scope |
| **3. Recon** | Every declared read per asset: cloud and SaaS configuration, host facts, DNS, TLS, response headers, technology fingerprint. Fills gaps in the context and flags where it is wrong. Anything outside the roots is recorded, not contacted. | Asset map |
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
| Engagement | What triggered this assessment: a customer questionnaire, an audit, a funding round, an incident, or routine? | Printed in the header. `incident` opens the report with "this is not incident response; evidence read from a possibly compromised system cannot be trusted" |
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
    first_party: {confirmed_by: alice, date: 2026-10-07}   # written by the Scope stage
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
`url` is a prefix: no query, fragment or credentials. A `repo` is `github:owner/name`; a local checkout (`repo: ./`) is not
accepted until the gate decides how history is read (0.0.2 E4).

**Names.** `engagement.name`, `assets` names and `people` handles all match
`^[a-z0-9][a-z0-9-]{0,62}$`. A throttle rate is `N/s` or `N/m`.

**An asset's settings follow its kind.** `jump`, `identity`, `elevate`, `profile`,
`disable_checks`, `deny_paths` and `context` are host settings; `first_party` is
taken by a domain, url or host; `deploys_to` (`production | staging | development`)
and `ci` (a tool named under `tools`) by a repository. A setting on the wrong kind
exits 3, and so do two `assets` entries for the same id and an entry for an asset an
`exclude` covers, whose settings could never apply.

In the file, an asset reference (`secrets[].asset`, `data.matters_most[].asset`,
`accepted_risks[].asset`, the keys of `access.admins`, `access.mfa[].where`) is an
`assets` name or a root's value exactly as written under `roots`. A reference that
resolves to neither exits 3. `data.backups[].account` is a declaration, not a
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

**Accepted risks** follow `host-collector.md §5.2` for `id` (a catalog finding id or
`custom:`) and add `asset`, `subject`, `accepted_by` and `expires`. `subject` is the
finding's instance key (a login, a repository, `port/proto`); without it the acceptance
covers every instance of that id on that asset, and the report says so. Past `expires`,
the adjustment stops and the report says so.

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
  exclude is accepted when an organization root exists. Whether any exclude matched
  something is known only after Scope, which reports it.
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
- An accepted risk needs `id`, `asset`, `reason` and `accepted_by`.
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

Context moves severity in code, attributed as `host-collector.md §5.4` describes, never
by a model.

- **Exposed on purpose** applies only to exposure findings: those whose whole claim is
  that a URL answers or names its software (reachable, version or technology
  disclosed), on that exact URL. A finding about what the response contains (a secret,
  a file, a debug page) is not one. Every finding definition declares whether it is
  one. Secrets, TLS and configuration findings on the same asset never move: an exposed
  `.env` on a public-on-purpose site is still high. Listeners on a host are governed by
  its `expected_services`, not by intent.
- **Data that matters most** raises findings on that asset by one step in the identity
  and access, secrets, data stores and external surface areas. Findings in other areas
  (headers, email, host hardening) do not move.
- **Accepted risks** keep the finding in the report with `status: accepted`, the
  reason and who accepted it, and out of the exit code.

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
engagement file or, for one host, a locator:

```
$ scheck run engagement.yaml
$ scheck run --host deploy@203.0.113.5 --identity ~/.ssh/deploy --sudo --profile hardened
$ scheck run --host local
$ scheck run --host deploy@203.0.113.5 --write-engagement engagement.yaml
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
never prints a pattern, since a pattern is often the very string it hides.

**The aliases, for 0.0.2 only.** `scheck local` is `scheck run --host local` and
`scheck ssh user@host` is `scheck run --host user@host`; each prints a deprecation line
on stderr, and both are removed in 0.0.3. Their 0.0.1 flags map as follows, and any
other exits 3 naming its replacement:

| 0.0.1 flag | Under `scheck run --host` |
|---|---|
| `--user`, `--port`, `--identity`, `--known-hosts` | the user and port in the locator; `--identity`, `--known-hosts` |
| `--sudo`, `--elevate`, `--profile` | the same |
| `--timeout` | the same: the host collector's run timeout, not `limits.timeout` |
| `--format`, `--out`, `-v`, `-vv`, `--state-dir`, `--no-persist` | the same; `--format json` prints the engagement report |
| `--include-evidence`, `--record-fixtures` | the same, on the host asset's evidence file |
| `--stop-after context` | `--stop-after intake` |
| `--stop-after plan` | exits 3 naming `scheck catalog --platform P --profile P`, which lists the checks without contacting the host |
| `--stop-after facts` | no flag: it is the run |
| `--context`, `--ignore-context` | exit 3: context is `assets.<name>.context` in a file (`--write-engagement`) |
| `--audit-log` | exits 3 naming the run directory's `audit.jsonl` |
| the model flags, `--only`, `--local-only`, `--format sarif` | exit 3, as in 0.0.1 |

`scheck catalog`, `scheck explain` and `scheck sudoers` stay; `scheck config` goes with
the file it read.

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

For a host, exit 3 is a positive list: no SSH user in the locator, an unknown or
changed host key, an unreadable identity or known_hosts file, failed authentication,
and a canary mismatch. That host is recorded as `refused`; the other assets are still
collected and every stage is written before the run exits 3, so nothing already read
from a client's host is discarded. Every other failure to reach a host (a name that
does not resolve, TCP refused or timed out, a handshake reset, cut off or past its
deadline) is a transport failure: the asset is `failed` and the run exits 2. A session
lost after it worked stops that host's plan where it was lost, keeps what was read, and
is `incomplete` with reason `failed`: never a complete run of unavailable checks. Until
E2 makes them aliases, `scheck ssh` keeps exiting 3 on any connection failure, and
shares the lost-session rule (`host-collector.md §7`). The canary's echo is printed
only after redaction, and cut short.

So a one-host run exits as the 0.0.1 command did for the same findings and the same
failures, and a CI job gating on `scheck ssh` keeps its meaning.

**JSON consumers.** The engagement report's JSON carries each host asset's collector
envelope (`host-collector.md §6.4`) whole, under that asset, with its own
`schema_version`; `run.assessment`, `assessments` and `facts` keep their shape one
level down. The report on stdout is complete without the run directory, so
`--no-persist` loses nothing, and `--include-evidence` adds captures to the embedded
envelope. The aliases' deprecation line names the new path of `run.assessment`.

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
  engagement.yaml      the file as read, its redact_extra masked (below);
                       for `--host`, the engagement built in memory
  scope.json           stage 2: resolved assets, evidence, exclusions
  recon.json           stage 3: the asset map
  plan.json            stage 4: the checklist per asset (with a model, hypotheses too)
  evidence/            stages 3 and 5: one file per result, redacted and truncated
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

**In 0.0.2 E1b.** `<started>` is the start time in UTC, RFC 3339 to the second. The
lock is an `flock` on `.lock` in the directory, released when the run ends or its
process dies; a second run on a locked directory exits 3, and so does a directory that
already holds a finished run until resume exists (E4). `--stop-after intake` validates
and prints the file and creates no directory; without `--stop-after` a run goes through
the last stage built, Analyze, until the report arrives (E2). Scope writes the declared
roots as written and refuses, before any target is contacted, a host asset with a
`jump` or without an SSH user. Every asset of kind `host`, a root or an `assets` entry,
is collected; an asset of any other kind is `not_collected` with reason
`collector_not_built`, which makes the run exit 2 when the asset is a root. Plan writes an
empty checklist and Check opens no follow-up. `evidence/<asset>.json` is the host
collector's envelope; its `context_sources` names `<file> assets.<name>` with kind
`config`, and the accepted risks it grades are those in `intent.accepted_risks` that
name the asset by catalog id without a `subject`, each attributed to its own entry
(`<file> intent.accepted_risks[i]`), a later entry for the same id winning. The host
grader accepts a whole id, so a `subject` acceptance is not widened into one: it is
listed under `acceptances_not_applied` in `findings.json` and printed as a warning,
and becomes applicable when host findings carry instance keys. Scope's refusals (a
`jump`, a host without an SSH user) happen before the run directory is created, so a
refused run leaves nothing behind. With `--format json` stdout is the last stage's
document (`--stop-after check` prints one that no file holds, since Check writes none
until E9); text is a summary per asset until the report.

**Stop and resume.** `--stop-after <stage>` ends the run after that stage's file is
written. `scheck run <directory>` resumes:

- **Per request, not per stage.** Each stage records the status of every request it
  made. A resume retries what failed, was rate-limited or was denied, and keeps what
  succeeded.
- **Only success is reused.** "No check re-runs with the same inputs" applies to
  successful results, and the inputs include the principal and its granted scopes, so
  a better token on resume reads again what the weaker one could not.
- **A changed engagement file.** The resume reads the file at its recorded path and
  compares hashes. If roots, exclude, assets or defaults changed, it restarts from
  Scope. If `mail` or an `intent` URL changed, it reads only the DNS names and entry
  points that changed. If only people, access, data, secrets or accepted risks changed,
  it re-runs Analyze and Report without contacting a target.
- **Hand edits.** A stage output the operator edited is used as written, and the report
  says which stage was edited. An edit cannot widen scope: the gate checks every
  request against the engagement file's roots and exclude, not against `scope.json`.
- **Principal and time.** The principal per collector is recorded; a different principal
  on resume is printed in the report. The report prints the collection span, and
  time-based rules (stale accounts, expiries) are computed against collection time.

**Scope confirmations persist.** When the operator confirms in the Scope stage that a
discovered asset is first-party, scheck writes an `assets` entry with
`first_party: {confirmed_by, date}` into the engagement file, the only key it writes
after `scheck init`, and records the new hash. A run with no terminal prints the stanza
instead and leaves the asset without first-party evidence.

## The report's coverage

The report opens with a coverage table, before any finding, so a short list of
findings cannot be read as a clean result. The marks are mechanical, so a test can
check them:

| Mark | Means |
|---|---|
| *assessed* | every sub-item of the area ran with recognized evidence on every in-scope asset it applies to |
| *partial* | some did; the row names what ran and what did not |
| *not assessed* | none did; the row gives the reason |
| *not applicable* | the operator declared under `not_used` that the area does not apply (`not_used: [hosts, cloud]`); printed as their declaration |
| *outside scheck* | scheck does not cover this area in any mode |

A reason is one of `no_credentials`, `insufficient_permission:<scope>`,
`not_on_plan:<feature>`, `collector_not_built`, `refused` (a host refused us on the
positive list of "Exit codes"), `not_declared` (no root of the kind
this area reads was declared), `excluded_by_operator`, `limit_reached`, `failed` or
`sampled`, with a detail line. `sampled` makes a row at most *partial*. Each row also prints the
assets covered and those excluded by name, the principal the data was read as, the
collection span, caps and sampling ("history of 40 of 120 repositories; blobs over
5 MB skipped"), and declared facts scheck did not verify ("backups declared in
gcp:example-backups, not verified").

`not_used` takes the area keys `identity`, `secrets`, `cloud`, `data`, `cicd`,
`external`, `web`, `hosts`, `email` and `logging`, in the order of the table below.

| Risk area | Sub-items |
|---|---|
| Identity and access | MFA and 2-step verification enforcement and enrolment, admins against `access.admins`, people attribution, stale, suspended and external accounts, OAuth grants |
| Secrets | secrets in repositories and their history, CI secret names, credential files on hosts. At most *partial* in 0.0.2: CI logs, chat and shared documents are not read |
| Cloud configuration | public storage and snapshots, broad IAM, service account keys, VPC firewall rules |
| Data stores and backups | public access to databases, backup existence and location. A declaration alone is *not assessed* |
| CI/CD and supply chain | branch protection, workflow token permissions, deploy keys, action pinning, dependency alerts |
| External surface | domains, subdomain takeover, exposed services, TLS |
| Web application | headers and cookies at entry points; exposed files and debug routes from 0.0.3 |
| Hosts | the host collector's catalog (`host-collector.md`) |
| Email and domain | SPF, DKIM per declared selector, DMARC, non-sending domains |
| Logging and incident readiness | audit logging enabled, alerting on administrative changes |
| Endpoints and workstations | *outside scheck*: laptops are where infostealers start, and leaving the row out would imply coverage |
| Application logic | *outside scheck*: authenticated testing of access control and business rules |
| Other declared SaaS | one row per tool in `tools` without a collector, by name |

The ranking of findings is labeled as a ranking of what was assessed. A run in which a
declared root had no successful read (no credentials, collector not built, every read
denied or failed) exits 2, even when findings fired, so a pipeline never reads exit 0
or 1 as "covered". A root read in part is *partial* in coverage and does not exit 2 by
itself; a collection cut by a failure or a limit does ("Exit codes" above).

The report header states the method ("rules only; the plan is a checklist" in
0.0.2), and that the report contains personal data and internal topology. It is written
for the operator, not for their customers; a version to hand out is a later audience
option.

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
unknown. Rules that name follow-ups are what let the loop iterate without a model.

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
