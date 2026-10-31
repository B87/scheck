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
| **3. Recon** | The inventory read per asset: SaaS tenant inventory, host facts, DNS, TLS, response headers, technology fingerprint. DNS beyond what Scope used to discover names (SPF, DMARC and declared DKIM selectors as TXT, MX, NS) is read here, per domain root and declared mail domain ([web-collector.md](web-collector.md#reads)). Lists what the context does not name: the accounts no handle names (the `recon` stanza) and the domains a Workspace tenant holds that are not roots. Reads inventory only (users, roles and admin assignments; members, owners, outside collaborators, invitations; the repository list with `pushed_at`; DNS; host and web reads, which have no selection), persists evidence and gives no verdict. Anything outside the roots is recorded, not contacted. | Asset map |
| **4. Plan** | A checklist per asset type: the rules that apply, narrowed and ordered by context. Under a cap, which repositories and users are read first, and the declaration that chose them ("Plan selection and follow-ups"). Names the rules that will abstain for lack of a declaration. `--stop-after plan` prints it. With a model (0.0.4), hypotheses as well. | Plan |
| **5. Check** | Run every read only rules consume, in Plan's order (GitHub's per-repository reads by kind, then the mirror, 6a; per-user OAuth grants and Gmail forwarding, 6b), then the follow-up reads that rules named (F1, built in E9 step 7; "Plan selection and follow-ups") and, from 0.0.3, the probes and scans the asset's modes allow, through collectors that enforce scope. | Evidence |
| **6. Analyze** | Every verdict is given here: each collector's rules over the evidence Recon and Check persisted, the host's posture rules, the multi-fact rules, then the context adjustments ("Severity in context"). Each rule ends as *fires*, *disproved* or *insufficient evidence*, the three outcomes every rule already has; a rule may name follow-up reads that would settle it, which go back to Plan. Notes where the evidence contradicts a declaration ("Context notes"). | Findings and follow-ups |
| **7. Report** | Coverage per risk area, then findings for the people who will fix them: what, why it matters here, evidence, remediation. | Report |

In 0.0.2, which only reads, Recon runs the inventory and host, DNS and web reads for
every asset and Check runs the selected per-item reads and the follow-ups (E9 steps 6 and 7); from 0.0.3 G3 Check is also where probes run (Plan previews them, `plan.json` `probes` and `probes_unevidenced`; Check asks per site in `confirm` mode and writes `check.json` `assets[].probes`, which hold no body; Analyze judges them; [scope.md](scope.md#probes)). Keeping the split there
means a collector never decides which stage its requests belong to. A collector's
choice among its own reads while it collects (the takeover enrichment of a web name, the
location follow-ups of a secret alert) is read selection: it stays in Recon and emits no
verdict. No network collector judges in Recon (built, E9 step 1b): Analyze judges
web, GitHub and Workspace assets from the evidence Recon holds, and a resume judges
again. The host is judged in Analyze too (built, E9 step 1c): Recon
writes its evidence with no verdict, and Analyze evaluates its posture rules and grades
them through its context, for a kept host as for a collected one.

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
`docker-proxy` on a database's usual port abstains.

## Intake: the engagement file

The engagement file (`engagement.yaml`) is the source of truth for a run. It is
reproducible, diffable and reviewable, and it is what a run resumes from.

```
$ scheck init                 # interviews the operator, writes engagement.yaml; contacts nothing
$ scheck init engagement.yaml # asks only what that file does not answer
$ scheck run engagement.yaml  # scope → recon → plan → check → analyze → report
$ scheck run --host deploy@203.0.113.5   # one host, no file: an engagement built in memory
```

`scheck run` is the only command that assesses anything; a one-host check is an
engagement with one root ("One command, one file" below).

`scheck init` asks the questions below and nothing else. With no path it writes
`engagement.yaml`. `scheck init FILE` asks only the questions that file does not
already answer, and a file from `scheck run --host … --write-engagement` is a valid
start. It reads no flags. No code path in `init` contacts a target. An answer shaped
like a credential is refused by the same detector as validation. Editing the file by
hand is equally valid.

The interview covers what a consultant draws out, not only the architecture. **Every
question has a consumer**: a rule that reads the answer, a coverage reason that cites
it, or a report field that prints it. "Printed in the report" counts only for what a
reader needs to interpret the findings: the trigger, authorization, scope and accepted
risks. A question nothing consumes is removed from the interview, not kept for a later
release; an operator who answers questions that change nothing stops answering
carefully. A question whose consumers belong only to a slice that has not merged is
cut the same way. E9 is merged into the interview at its step 9, so a question kept
for Plan, Analyze or a multi-fact rule is asked. The mapping from question to consumer is code
(`internal/engagement/interview.go`): each question declares its consumers by id,
with the slice that owns each. A test proves at every commit that each declaration
is well formed and that every consumer owned by a slice already merged exists. The
release gate that they all exist is not claimed by this slice. A consumer is never
stubbed to pass.

| Topic | Question | Consumed by |
|---|---|---|
| Engagement | What triggered this assessment: a customer questionnaire, an audit, a funding round, an incident, or routine? | Printed in the header. `incident` opens the report with "this is not incident response; evidence read from a possibly compromised system cannot be trusted", worded in [report.md](report.md#the-report) |
| Engagement | A short name for this assessment; who to print as the operator; the IANA time zone dates in the file are read in. | `engagement.name` names the run directory; `operator` is printed in the header; `timezone` is required ("Time") |
| Roots | Which domains do you own, including parked and non-sending ones? Which tenants, organizations, cloud projects and hosts? | Roots ([scope.md](scope.md)) |
| Roots | What is explicitly off limits, as a domain, url, repo or host? | `exclude` ([scope.md](scope.md)). A blank answer leaves it unset |
| Mail | Which services send mail as each domain, with which DKIM selectors? | DKIM is read per declared selector, since DNS cannot list them; with no selector DKIM is *insufficient evidence*, not missing. SPF includes are compared with the senders. A domain listed under `mail.no_mail` must publish `v=spf1 -all` and DMARC `p=reject`. A domain root with neither a sender nor a `no_mail` entry is judged from the mail use it shows: a non-null MX record, or SPF that authorizes a sender, makes DMARC and SPF judged as for a sending domain; recognized complete MX and SPF evidence showing neither makes it judged as a domain that sends no mail; missing or invalid evidence leaves mail use unknown. The report says the operator did not say which. Comparing SPF with the senders, and DKIM, stay *insufficient evidence* for it. The severity of DMARC `p=none` depends on whether the domain sends |
| People | Who are the admins and contractors, and the shared, service and break-glass accounts, with every Workspace address and GitHub login each uses? Everyone else is named from the stanza `--stop-after recon` prints, one account at a time ("People" below). | Every people rule matches by these identifiers ("People" below); the kind selects which rules apply; a contractor holding an admin role is a finding whether listed or not; a shared account names who uses it, so a leaver among them says to rotate it |
| People | Who has left recently, and when? | An account of that person still active, or still holding an admin role or group-granted access, is a finding. A suspended account is correct offboarding |
| Access | Who is expected to be a super admin (Workspace) or an owner (GitHub) in each tenant? | A super admin or owner not listed is a finding; a listed person who is not one is a note for the readout, not a finding; one who cannot be tied to a named person is a finding. Too many of them is a finding whatever is listed ("Admins") |
| Access | Which repositories deploy the live production environment, as opposed to a demo or a staging copy? | `deploys_to` is `production`, `staging` or `development`. `production` raises branch protection, workflow token, deploy key and `pull_request_target` findings on those repositories; from 0.0.3 G4 links them to the cloud project. The question does not ask which CI |
| Access | In each tenant, who must use 2-step verification: every account (service and break-glass accounts included), only admins, some, none, or you do not know? For Google Workspace, a second factor that another sign-in service such as Okta or Microsoft Entra asks for counts; the next question asks about it. | Compared with the enforcement the tenant reports ("2-step verification"); a declared enforcement the API disproves raises the finding for it as a contradiction; `unknown` raises nothing and prints what scheck read |
| Access | For a Google Workspace tenant declared `everyone` or `some`: does Google send people to another sign-in service, such as Okta or Microsoft Entra, instead of asking for their Google password? | `access.mfa[].sign_in`: `google`, `another_provider` or `unknown` ("2-step verification"). Asked only for a tenant with such an entry and no `sign_in`; yes and no are refused. The prompt says how to tell: open mail.google.com in a private window and type the work address; Google asking for the password is `google`, a jump to the company login page is `another_provider`. With `another_provider` a not-enforced unit ranks higher for contradicting `everyone` only when a super admin is among its accounts. Consumer `workspace.two_step_sign_in` (E6) |
| Intent | What is exposed on purpose, and to whom? | Exposure findings on that exact URL or service drop to *info*, attributed ("Severity in context") |
| Intent | What must not be reachable, except from where? | A contradiction finding when it is reachable from a vantage outside the declared audience |
| Intent | "Which of these hold the data that would hurt the company most if it leaked or was lost, such as customer records, payment details, source code or contracts? Give the number of each, and a few words on what the data is, one per line (for example `2: customer orders and invoices`). If you are not sure, leave this blank." Offers hosts, Workspace tenants, GitHub organizations and repositories, url sites and cloud roots, not domain roots. Help: "Problems found on what you pick rank higher. Account and access problems, exposed secrets and open databases there move up one step. This answer alone never makes anything critical. Other findings, such as web headers or email settings, do not move. Leaving it blank changes no finding." | `data.matters_most[]`: the raise ("Severity in context"), Plan's repository tier 4 ("Plan selection and follow-ups") and the ranking tie-break. The words go to `what`, through the credential detector. Asked after `context` and before `not_used`; rules below the table |
| Hosts | For each host: how to reach it, and its exposure, environment and expected services. | The connection, and the host collector's context (`host-collector.md §5.3`). Of those fields, only `internet`, `airgapped` and `dev` move a host finding's severity. `prod` does not raise one. `expected_services` is read by `db.listens_unfiltered` (E9 step 3a), `svc.listens_beyond_declared` (E9 step 5a) and `svc.sensitive_listens_unfiltered` (0.0.3 G5, for the audience it raises on); the service line is worded under the table. The answer `internet` is refused when `not_used` already lists `external`: "you said you run nothing internet-facing (not_used: external); a server the internet can reach is internet-facing" |
| Hosts | Is an application installed on a server you named, as files on its disk? If it runs only in containers or Kubernetes, or you do not know, leave this blank. Otherwise one block per server, one `path:` line per folder (`name: shop`, `path: /srv/shop`); folders under `/srv`, `/var/www`, `/opt`, `/app` or `/data` (others are refused); a folder under `/home`, `/root` or `/Users` is accepted, but a `.env` there is listed and not judged. | `assets.<host>.app_paths`: the folders `creds.app_env_N` lists `.env` files in (`creds.env_file_exposed`, G5). Asked after `context`; skipped when no host is declared or any host already has `app_paths`. A name that is not a declared host, a block with no `path:` line, and any path "Host settings" refuses, refuse the whole answer. With the answer blank, the report says `.env` files were not looked for (`unavailable:no_app_paths`) |
| Coverage | Which of hosts, cloud, data, cicd, email, web and external do you not operate at all? | `not_used` marks that area *not applicable*. What is refused is under "Validation"; `external` is refused beside a host already answered `internet`, by the same refusal as intake |
| Authorization | Before any probe or scan: who authorized it, for which windows, from which source addresses? | Asked only when a probe or scan mode other than `off` is chosen (0.0.3 on). The windows bound probes and scans and sources are printed ([scope.md](scope.md#authorization)); the block is printed in the report. Not built in G3: the interview asks for no probe mode and no authorization block, and the operator writes both by hand |

**The service line of the `context` question** (built in E9 step 9). The line is
`service: <port> <tcp|udp> [localhost|lan|vpn|internet] <purpose>`. A third token that
is one of the four words is the audience; otherwise the audience is unset and the rest
is the purpose. Several `service:` lines per host block are accepted. `airgapped` is refused with the intake text ("Exposure vocabulary"). An
`internet` service on a `lan` or `vpn` host is not refused. The prompt's examples are:

```
service: 443 tcp internet the public HTTPS listener
service: 5432 tcp localhost the shop's Postgres, used only by the app on this server
```

and its closing text: "A service is a port that should be open, with tcp or udp, then
who should reach it: localhost (only this server), lan (the office network), vpn, or
internet, then a few words on what it is. A database only this server uses is localhost:
it should be open, to this server. scheck reports a service that listens more widely than
you said. If you do not know who should reach it, leave that word out. If you do not know
the port, leave service out. Do not name a port you hope is closed." With no audience the
line is accepted and `init` prints: "No audience given for 5432/tcp: scheck will check
that it is listening, but not whether it listens more widely than it should."

**The `data.matters_most` question** (built in E9 step 9). It is asked after `context`
and before `not_used`. It offers every declared, non-excluded thing in a fixed group
order: hosts, Workspace tenants, GitHub organizations, repositories (repo roots and
`assets` entries with `repo`), url sites (url roots and url assets), cloud roots. Within
a group the order is the file's; `assets` entries are in name order, since `assets` is a
map. Domain roots, networks and excluded assets are never offered. Each line is
numbered from 1 and labelled with the asset name first, and its locator in parentheses,
when an `assets` name exists, else the root as written:

```
1. shop (host: deploy@203.0.113.5)
2. saas: google-workspace:example.com
3. saas: github:example-org (GitHub organization: its members and admins)
4. shop-repo (repo: github:example-org/shop)
```

Under the list: "Picking an organization covers its members and admins. To cover a
repository's code, pick the repository." An organization and its repositories may both
be picked; the organization pick raises the organization's own findings, not its
repositories'. Cloud roots stay offered: the readout says nothing reads them in 0.0.2
([report.md](report.md), "The report").

An answer line is `N: a few words`. A line `repo: github:org/name: a few words` is also
accepted for a repository under a declared GitHub organization root; `init` writes an
`assets` entry named from the repository's last path segment, as the deploys question
does, and refuses when the segment is not a valid name or collides with an existing one:
"name this repository in the deploys question or in the file's assets; `<seg>` cannot be
used as a name here." `asset` is written as the `assets` name when one exists, else the
root value as written. `what` is required, goes through the credential detector, and is
at most 120 characters. Refusals, whole-answer (any bad line refuses all):

| Line | Refusal |
|---|---|
| malformed | "Write each line as a number, a colon and a few words, for example `2: customer orders and invoices`." |
| no words | "Say in a few words what data number N holds, for example `N: customer orders and invoices`." |
| a `repo:` line with no words | "Say in a few words what data <repo> holds, for example `repo: <repo>: customer orders and invoices`." |
| out of range | "There is no number N here; pick from 1 to M." |
| a domain typed in | "A domain is not offered: pick the site (url) or server that holds the data." |
| a number repeated | "N is listed twice; give one line per number and put both descriptions on it." |
| a `repo:` line, malformed | "Write a repository as repo: github:org/name: a few words." |
| a `repo:` line, excluded | "<repo> is excluded (<exclude id>), so scheck reads nothing in it; it cannot be picked." |
| a repository twice | "<repo> is listed twice; give one line per repository and put both descriptions on it." |
| a repository already offered | "<repo> is already listed as number N; pick that number." |
| not under a declared organization | "<repo> is not under a GitHub organization you listed under roots." |
| a description over 120 characters | "Keep the description of number N to 120 characters or fewer." |

The question is skipped, with no prompt printed, when the file already has
`data.matters_most` or nothing is offerable. A blank answer writes nothing. Its consumers
are `severity.data_matters_most` (E9 step 1a), `plan.github_tier4` (E9 step 6a),
`report.rank_tiebreak` (E2) and `report.matters_most_readout` (E9 step 9).

Not asked, and why. The keys below stay valid. The interview does not ask them.

- **Accepted risks.** Nobody can name a finding id before seeing a report. The report
  prints a ready-to-paste `accepted_risks` entry under each finding; risks are accepted
  at the readout, as in practice, and the next run reads them. `date` and `expires`
  are required when an entry is written ("Validation"). The paste block writes `date`
  as the collection day.
- **SaaS tools.** `tools` stays valid. A tool a collector reads is covered by that
  collector; a tool none reads is an "Other declared SaaS" row when the key is written
  by hand. The interview does not ask for the list: the roots already name Workspace
  and GitHub, and the rest changes no rule in this build.
- **Which CI.** `assets.<repo>.ci` stays valid, and still has to name a tool under
  `tools`. The interview asks which repositories deploy to production and does not ask
  which CI. `deploys_to` stays the string `production`, `staging` or `development`.
- **Production secrets.** `secrets.production` stays valid, and `store` stays free
  text. The interview does not ask where production secrets live: a free-text store
  cannot say whether scheck read it. Plan reads `secrets.production[].asset` when the
  file has it ("Plan selection and follow-ups").
- **Backups.** `data.backups` stays valid. The interview does not ask where backups
  are. A declaration still prints as *declared, not verified*, and the row stays *not
  assessed* until a cloud collector can compare it with inventory (0.0.3).
- **Host role.** `assets.<name>.context.role` stays valid. The interview does not ask
  it. Exposure, environment, expected services and how to reach the host are asked.
- **Federation.** The interview asks `mfa_sign_in` right after `mfa`, only for a
  `google-workspace:` tenant whose `access.mfa` entry is `everyone` or `some` and has no
  `sign_in` ("2-step verification"). It offers those tenants, writes `google`,
  `another_provider` or `unknown`, normalizes a named service (Okta, Entra) to
  `another_provider`, and refuses `sso`, yes and no. A blank or partly answered reply
  prints "No sign_in given for `<where>`" and leaves the field absent; for `some` the
  line says that if the list of users is complete and Google reports every active
  account as not required to use 2-step verification, every unit with an active
  account will rank higher for contradicting the answer. A Cloud Identity
  SSO read stays a 0.0.3 candidate. GitHub Enterprise Managed Users is a known limit,
  not built: `sign_in` on a GitHub tenant is refused.
- **Which apps, and forwarding on purpose.** Neither is a question. When the file
  names a Workspace tenant, `scheck init` explains two optional checks and writes
  nothing from either. `directory_oauth`: set `SCHECK_WORKSPACE_PROFILE=directory_oauth`
  in the environment, not in the file; the credential stays out of the file;
  `admin.directory.user.security` has no read-only form and can also revoke app
  access, sign people out, and turn off 2-step verification. `directory_mail`: a
  service account whose domain-wide delegation is `gmail.readonly` and nothing else,
  and who must approve access to staff mailboxes.
- **Mailbox authorization.** `scheck init` does not ask for, write, renew or extend
  `authorization.mailboxes`. The human operator who approves signing in as staff
  mailboxes writes the entry by hand; the not-selected readout note explains what to
  add and who must approve it.
- **Framework.** Comparing a declared framework with the observed one is not a risk.
  The interview asks `framework` (built, 0.0.3 G3) because it selects which
  framework-specific probes apply, and only when the file names a `domain` or `url`
  root. It is asked after `restricted` and before `reach`, and writes
  `defaults.framework`. Its consumer is `web.probe_selection`. The answer is one or more
  of `laravel`, `django`, `rails`, `spring`, `wordpress`, `node`, `php`, or `none` or
  `unknown` alone. It turns nothing on: the probes run only when the operator sets a
  probe mode and an authorization window by hand.
- **Hosting.** The roots already say it.
- **Compliance goal.** It would select references printed with each finding, and no
  reviewed finding-to-control table exists. It returns with one.

Later, scheck may read existing docs, compose files or infrastructure code to
*suggest* additions. A suggestion enters the file only when the operator confirms it;
nothing inferred joins scope on its own.

### The file

Every file `scheck init` writes starts with these lines, then the keys the answers
filled:

    # This file names people, people who have left, and accepted weaknesses.
    # Keep it out of public repositories.
    # Written by `scheck init`. Editing by hand is equally valid.

The block below is every key, including keys the interview does not ask ("Not
asked") and entries written later (a Scope confirmation, an accepted risk). It is
the schema, not a copy of a file `scheck init` emits. The file may change freely
until 0.0.2 is published. The files under [../examples/](../examples/README.md) are
the ones to copy and run, one surface each and one that names the four roots 0.0.2
reads. They use placeholders, and a credential never appears in them.

```yaml
# engagement.yaml — every key. `scheck init` writes its own header, then the keys it asked.
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
  probe: off                          # off | confirm | all, on domain and url assets; auto exits 3; a mode other than off needs authorization.windows
  # framework: [laravel, php]         # laravel | django | rails | spring | wordpress | node | php, or none | unknown alone; only selects probes; an assets entry replaces it
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
    - {where: google-workspace:example.com, enforced: everyone, sign_in: google}   # sign_in: google | another_provider | unknown; Workspace only
    - {where: github:example-org, enforced: everyone}

tools:                                # valid, not asked; a name no collector reads is a coverage row
  - {category: identity, name: google-workspace}
  - {category: code, name: github}
  - {category: ci, name: github-actions}
  - {category: payments, name: stripe}   # a tool category; there is no payments coverage area
  - {category: chat, name: slack}
not_used: []                          # hosts, cloud, data, cicd, email, web, external; only when no root or host/repository asset covers it

mail:
  senders:                            # DKIM is read per selector listed here
    - {domain: example.com, service: google-workspace, dkim_selectors: [google]}
    - {domain: example.com, service: sendgrid, dkim_selectors: [s1, s2]}
  no_mail: [example.net]              # must refuse all mail: SPF -all, DMARC reject

secrets:
  production:                         # valid, not asked; store stays free text
    - {store: github-actions-secrets, asset: github:example-org}
    - {store: env-file, asset: deploy}

data:
  matters_most:                       # asked by the interview
    - {what: "customer orders and invoices", asset: deploy}
  backups:                            # valid, not asked
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
      date: 2026-10-06              # the day it was written; expires is at most 365 days later
      expires: 2026-12-31

authorization:                        # optional when no probe runs and no mailbox surface is selected; a probe mode needs at least one window
  by: "CTO, Example Ltd"             # required when the block also has windows, source, note, by or date
  date: 2026-10-06                   # required when the block also has windows, source, note, by or date
  windows:
    - {from: 2026-10-07T09:00:00+02:00, to: 2026-10-07T18:00:00+02:00}
  source: [203.0.113.10/32]
  note: "Annual self-assessment; contact on-call before any scan."
  mailboxes:                          # one entry per Workspace asset; both this entry and SCHECK_WORKSPACE_PROFILE gate the surface
    - asset: google-workspace:example.com  # assets name or root value resolving to saas:google-workspace:*
      by: "CEO, Example Ltd"         # free text; not a people handle; redacted in the audit log
      date: 2026-10-06
      expires: 2027-01-04            # at most 90 days after date; current from start of date through 24:00 on expires

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
    app_paths: [/srv/shop]            # where the application lives: .env files are listed here (G5)
    context:                          # host-collector.md §5.2: only these four fields
      role: "web and database host"    # valid, not asked
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
    deploys_to: production            # production | staging | development
    ci: github-actions                # valid, not asked; must name a tool under tools
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
`disable_checks`, `deny_paths`, `app_paths` and `context` are host settings; `first_party` is
taken by a domain, url or host; `deploys_to` (`production | staging | development`),
`ci` (a tool named under `tools`) and `checkout` (an absolute mirror path) by a
repository. The interview asks `deploys_to` and does not ask `ci`. `ci` stays valid.
A setting on the wrong kind
exits 3, and so do two `assets` entries for the same id and an entry for an asset an
`exclude` covers, whose settings could never apply.

In the file, an asset reference (`secrets[].asset`, `data.matters_most[].asset`,
`accepted_risks[].asset`, `authorization.mailboxes[].asset`, the keys of `access.admins`,
`access.mfa[].where`) is an `assets` name or a root's value exactly as written under
`roots`. A reference that resolves to neither exits 3. `authorization.mailboxes[].asset`
must additionally resolve to `saas:google-workspace:*` and must not be excluded. `accepted_risks[].asset` may also be a canonical id that
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
| `admins` | every super admin or owner must | Workspace not-enforced findings whose affected accounts include a super admin, based on an explicit enforcement-off flag; GitHub raises an owner-without-2FA finding, since owner-only enforcement is unavailable, with a readout note |
| `some` | part of the tenant must | everything, when a complete active population has known enforcement off for every account; a partial population cannot prove this; a note when everything is |
| `none` | nothing is enforced | nothing; a note when the tenant does better |
| `unknown` | the operator does not know | nothing; a readout note says what scheck read ("N of M accounts not required") |

`access.mfa[].sign_in` says whether Google sends people to another identity provider to
sign in. It is read only for a Google Workspace tenant and is optional; absent is
decided as `unknown`. It is allowed with every `enforced` value. There is no `mixed`
value: Google's single sign-on profiles are per unit or group and not readable, and
whether all or some people are sent changes no decision. It never changes a verdict or a
base severity; it changes only which fired units are raised as `contradiction`.

| `sign_in` | Effect on the `contradiction` raise |
|---|---|
| `google`, `unknown`, absent | none; the raise is as the table above says, and the caveat words which of the four answers it follows |
| `another_provider` with `everyone` | only a fired unit whose affected accounts include a known super admin (`isAdmin:true`, no security conflict) is raised; super admins can still sign in to Google with a Google password. Unknown administrator status and delegated admins do not keep the raise |
| `another_provider` with `some` | never raised: every active account off is what a federated tenant looks like |
| `another_provider` with `admins`, `none`, `unknown` | none |

A unit the comparison would have raised and `sign_in` stopped is still reported, at its
base severity, with a "Not checked" line saying so. Raised and stopped instances cite
`access.mfa[i]` as declared evidence, and `access.mfa[i].sign_in` too when it is present
and `enforced` is `everyone` or `some`. When
the Cloud Identity SSO profile read lands (0.0.3), it takes precedence over the
declaration: a unit observed with no SSO profile re-raises whatever `sign_in` says, so
the answer never becomes a permanent suppression. Plan words the effect before Check
("Plan selection and follow-ups"). On GitHub, single sign-on does not replace the
two-factor requirement scheck reads, so `sign_in` there exits 3.

Observed better than declared is never a finding. Workspace's Directory flags describe
current per-account enforcement and enrollment, not organizational-unit policy or a
readable enrollment grace window. Not-enforced findings group affected accounts by
unit without claiming that the unit's policy is disabled. An explicit enforcement-off
flag contradicts `everyone`, or `admins` when the affected account is a super admin,
without establishing whether policy, configuration groups or grace caused it. An
enforced but unenrolled non-admin may be in a grace period; the readout calls that
possibility unknown, never an observed window. An unenrolled super admin is still an
admin without 2-step verification. Workspace enrollment alone never establishes an
enforcement contradiction, even when the admin-without-two-step finding fires. GitHub's
organization requirement is read only by
an owner's token and is three-valued: absent or null is *insufficient evidence*, never
"not required".

**The recon stanza.** `--stop-after recon` prints the accounts no handle names, for the
operator to paste under `people` (in JSON, `people_candidates[]` with the same fields).
A GitHub account seen only as a collaborator on a repository Check read is a candidate
too. Check recomputes the people fields (GitHub, then Workspace) and `check.json` carries
them, so `--stop-after check` prints the stanza with those accounts and `--stop-after
recon` does not; the report does not print it:

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
`custom:`) and add `asset`, `subject`, `accepted_by`, `date` and `expires`. `subject` is the
finding's instance key (a login, an OAuth app's client id, a DNS name). When the
finding's definition declares a subject kind, `subject` is required: an acceptance of
the whole id would also accept every instance the asset gains later, next month's
Drive-scoped OAuth app among them, so validation exits 3 naming the kind ("reported per
OAuth app, … name the OAuth app, and add one entry per OAuth app to accept"). A
definition without a subject kind is accepted by id. Either it is about the asset as a
whole (too many owners of an organization), or its instances are not keyed yet: every
host posture finding in 0.0.2, `accounts.empty_password` among them, whose acceptance
covers every account on the host, including accounts added later. The two engagement
rules over a host's listeners, `db.listens_unfiltered` and
`svc.listens_beyond_declared`, are the first host-side findings to declare a subject
kind, `service` (`<port>/<proto>`; E9), so an acceptance of either names it, and so does
one of `svc.sensitive_listens_unfiltered` (R6, 0.0.3 G5). A host
posture acceptance that names a subject is listed as not applied (the Recon paragraph under "Runs, state and
configuration"); a `subject` on any other id without a subject kind exits 3 ("… is about
the organization as a whole; remove subject"), since nothing could ever match it.
`custom:` ids are never subject-checked. Past `expires`,
the adjustment stops and the report says so; `expires` is a date in
`engagement.timezone`, compared with the latest collection time among the reads the
matched finding cites (a host finding: the host's collection), never the run's first
start, the time the report is rendered or a resuming session started ("Time" under
"Severity in context"). An acceptance whose finding did not fire has no verdict
consequence from `expires`. An acceptance whose only matching instance is reported as
another, worse finding in its place (`superseded_by`) is `rule_not_decided` and names
that finding to accept instead: the problem is there, so it is never called fixed nor
the entry removable. The report prints a ready-to-paste entry under each
open finding ([report.md](report.md#findings)).

**Time.** A timestamp is RFC 3339 with seconds and an explicit offset. A date lasts
until the end of that day (24:00) in `engagement.timezone`, which is required. Both are
decoded as strings and parsed explicitly (`time.RFC3339`; `2006-01-02` in that zone),
never through YAML's own time type, which reads a date as UTC start of day and silently
returns a zero time for some forms. `authorization.windows` is a list; `source` is a list
of CIDRs. For `authorization.mailboxes[]`, the approval is current from the start of
`date` through 24:00 on `expires`, both in `engagement.timezone`: `date` may be in the
future and is accepted at intake, but is not yet current until that day. A `date` in the
past with an `expires` that has not yet elapsed is current.

**Exposure vocabulary.** One enum, `internet | vpn | lan | localhost | airgapped`. A
host's `exposure` takes four of them (`internet | vpn | lan | airgapped`,
`host-collector.md §5.2`). An intent entry's `audience` takes any of the five. A
service's `audience` takes `localhost`, `lan`, `vpn` or `internet` (E9 step 5a):
`airgapped` on a service exits 3 ("a service's audience is localhost, lan, vpn or
internet; airgapped describes a host"). The engagement passes a service's `audience` to
the host collector as that collector's free-text field. Free-text values the standalone
host collector accepts, such as `vpc-only`, exit 3 in an engagement.

**Host context.** The host collector's context is `assets.<name>.context` and nothing
else: `role`, `exposure`, `environment` and `expected_services`. `scheck init` asks
exposure, environment, expected services and how to reach the host. It does not ask
`role`. `role` stays a field. Only `internet`, `airgapped` and `dev` move a host
finding's severity (`host-collector.md §5.3`). `prod` does not raise one. Accepted risks live
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
relative or `/`. A `deny_paths` entry that is, or lies under or over, `/home`, `/root`,
`/Users` or `/var/root` (or whose canonical form is) disables `creds.home_files` for that host at run time, since its
fixed walk cannot honour the denial (`host-collector.md §3`).

`app_paths` (0.0.3 G5) lists the folders of the application the host runs, so
`creds.app_env_1` to `creds.app_env_5` can list `.env` files in them, names and modes
only (`host-collector.md §3`, §6.5). It is a host setting and part of the host's resume
fingerprint, so a changed list collects the host again. Each entry is an absolute, clean
path strictly under `/srv`, `/var/www`, `/opt`, `/app`, `/data`, `/home`, `/root` or
`/Users`, in the charset `[A-Za-z0-9._/-]`, listed once; at most 5 entries; on any
other kind of asset the key exits 3. A relative path, `/` itself, a path outside
those trees, a character outside the charset, a duplicate or a sixth entry exits 3 at
intake naming the entry; so does an unclean one (`/srv//shop`, `/srv/shop/../x`), which
neither intake nor the interview rewrites. The file picks a subtree the path policy
already lets scheck list (`host-collector.md §4.1`); it never widens the policy, and
`deny_paths` still applies: an entry that is equal to, inside or containing a
`deny_paths` entry exits 3, since scheck walks a declared folder whole. Intake sees only
the literal overlap; a folder whose resolved root contains a `deny_paths` entry (a symlinked
parent) is refused by the runner at run time, `path.deny_inside`, and reads as excluded by
the operator (`host-collector.md §3`, §4.1). A `.env` file
under `/home`, `/root`, `/Users` or `/var/root` is listed but not judged
(`host-collector.md §6.5`); the interview says so when it asks, offers `/srv`, `/var/www`, `/opt`,
`/app` and `/data`, and does not suggest a laptop folder. Without `app_paths`, no `.env` file is looked for.

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
- Scan modes other than `off`, the probe mode `auto`, `scope: full` and `max_cost` exit 3
  with "not available in this build" until their release.
- A probe mode other than `off` (`defaults.probe` or an `assets` entry) needs at least one
  entry in `authorization.windows`; the error names `authorization.windows` and the key
  that turned probes on. `probe` and `framework` are accepted on `domain` and `url`
  assets only. `framework` takes the closed list of the file schema, and `none` or
  `unknown` stand alone.
- `0` is never "no limit"; `none` is.
- A value shaped like a credential is a usage error. Detection is by shape: known
  prefixes such as `ghp_` and `AKIA`, PEM headers, and high-entropy strings, not
  keywords. `scheck init` refuses an answer with the same detector and does not
  write it. The error names the detector, never the value.
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
- `access.mfa[].sign_in` is one of `google`, `another_provider` or `unknown`; `yes`, `no`,
  `true` and `false` exit 3 as ambiguous; a tenant that is not a Google Workspace
  tenant exits 3.
- `not_used` entries are area keys, each at most once. `identity`, `secrets` and
  `logging` exit 3: they cannot be marked not applicable. An area a declared root
  already covers exits 3: `email` beside a domain root; `web` beside a domain or url
  root; `external` beside a domain, url or network root; `cicd` beside a GitHub root
  or a repository root; `hosts` beside a host root; `cloud` or `data` beside a cloud
  root. A repository asset covers `cicd` the same way, and a host asset covers
  `hosts`. `hosts`, `cloud`, `data`, `cicd`, `email`, `web` and `external` are
  accepted when no such root or asset exists. Evidence that contradicts a
  `not_used` area is a note, not an error ("Context notes"), with one exception (E9 step
  5a): `external` beside a host asset with `exposure: internet` exits 3, since that host
  is declared internet-facing. There is no `payments` area. A
  `tools[].category` of `payments` is not one.
- A mail domain (`mail.senders[].domain`, `mail.no_mail`) falls under a `domain` root,
  and a domain listed both as sending and under `no_mail` exits 3. An intent URL falls
  under a root, and one URL listed under both `intent.exposed_on_purpose` and
  `intent.not_exposed` exits 3.
- An accepted risk needs `id`, `asset`, `reason`, `accepted_by`, `date` and `expires`;
  an empty `reason` counts as missing. `date` and `expires` are YYYY-MM-DD in
  `engagement.timezone`. `expires` is on or after `date` and at most 365 days after
  it. A date already in the past is still valid: the report leaves the finding open
  when the acceptance has lapsed, and intake does not fail. `scheck init` does not
  ask for accepted risks. The paste block writes `date` as the collection day.
  It needs `subject` when the finding's definition declares a
  subject kind, and may not have one on a non-host id whose definition declares none
  ("Accepted risks" above).
- `authorization.mailboxes`, when present, is a list. Each entry requires `asset`,
  `by` and `date` and `expires`; `note` is optional; any other key exits 3. `asset`
  must resolve to a Workspace root that is not excluded, and at most one entry per asset
  is allowed. `by` must be non-empty free text; it is not a people handle. `date` is
  YYYY-MM-DD. `expires` is YYYY-MM-DD, on or after `date` and at most 90 days after it.
  A missing required field, a bad date, an `expires` before `date` or more than 90 days
  after it, an asset that resolves to nothing or to a non-Workspace root, an excluded
  asset, a duplicate asset, or an unknown key exits 3 at intake, before any contact.
  The block is valid with only `mailboxes` and no `windows`, `source`, `note`, `by` or
  `date`; in that case `by` and `date` at the top level of `authorization` are not
  required. When `windows`, `source`, `note`, or top-level `by` or `date` are present,
  the existing rules for top-level `by`, `date`, `windows` and `source` still apply.
  `note` on a mailbox entry is optional free text; it does not narrow which mailboxes
  are signed in as, and there is no skip list. `authorization.mailboxes`
  holds no credential key, no path to a credential, and no staff address. `scheck init`
  and `--write-engagement` never emit this key; only the human operator writes, renews
  or extends it.
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

| Rule | Source | Moves | Step | Past high |
|---|---|---|---|---|
| `exposed_on_purpose` | the declaration, `intent.exposed_on_purpose[i]` | exposure findings on that exact URL or service | to `info` | n/a |
| `data_matters_most` | the indexed declaration, `data.matters_most[i]`; the readout prints that entry's `what` | findings on that asset in the identity and access, secrets, data stores and external surface areas; on a Workspace tenant, its identity findings; on a host, the host access findings whose definitions carry the flag below, and the findings in the secrets area | +1 | no: stops at high |
| `deploys_to:production` | the declaration, `assets.<repo>.deploys_to` | branch protection, workflow token, deploy key and `pull_request_target` findings on that repository | +1 | no: stops at high |
| `exposure:internet` | the host's context, `assets.<host>.context.exposure: internet` | `db.listens_unfiltered`, `svc.listens_beyond_declared` (E9 step 5a), `svc.sensitive_listens_unfiltered` (0.0.3 G5) and `php.fix_missing` (0.0.3 G8) only | +1 | no: stops at high |
| `contradiction` | the declaration the observation disproves (`access.mfa[i]`, an intent audience, `expected_services`) | the finding for the weakness declared absent | +1 | yes |
| `attribute:admin` | a fact, cited by observation and excerpt; on a GitHub repository, `repository_admin` counts only where the repository is declared production | `identity.former_person_has_access` on a left person's account; `workspace.external_forwarding` from a known-active super admin's mailbox | +1 | on a left person's account only |
| `attribute:admin_grantor` | a fact, cited by observation and excerpt | `workspace.oauth_broad_scope`, when a known-active super admin or declared break-glass account gave a broad scope in its own grant; a delegated admin's grant never raises it | +1 | no: stops at high |
| `attribute:public_repository` | the direct repository read, observed public visibility | `github.secret_scanning_open` and `github.history_credential` | +1 | yes |
| `attribute:production_write` | people `left` passed, and effective write (push, maintain or admin) on a `deploys_to: production` repository, from the collaborators read (R4 below) | `identity.former_person_has_access` on GitHub | +1 | yes |
| `attribute:serves_web` | the listener and firewall reads of R7: a web server from `rules.WebServersVersion` listens beyond loopback and the firewall leaves the port open | `php.fix_missing` (R7, 0.0.3 G8) | +1 | no: stops at high |
| `attribute:<other>` | a fact, cited by observation and excerpt | the finding whose definition declares that attribute (`attribute:password_form`, web-collector.md) | +1 | no: stops at high |

The three probe findings (`web.vcs_metadata_exposed`, `web.config_file_exposed`,
`web.debug_interface_exposed`, [web-collector.md](web-collector.md#probes)) are not exposure
findings: `exposed_on_purpose` never moves them. No attribute raises them past high yet; one
needs a row in this table first.

The table is data in Analyze (`internal/engagement/severity`, built in E9 step 1a): one
entry per rule, with its source, the definitions or attribute it moves, its step and
whether it may pass high. `Grade` gives each fired judgment its chain, replacing any a
collector set; the report renders the chain and decides nothing. A collector's own
steps are declared on its finding definitions (`Attributes`, for example
`attribute:password_form` +1, a Slack webhook -1 on `web.secret_in_response`) and apply
first. `deploys_to:production` is decided here from `assets.<repo>.deploys_to` on the
repository that owns the finding; a collector emits no production attribute. An entry
not named here does not exist.

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
  On a host asset, only definitions flagged `HostAccess` or in the secrets area move,
  whatever their other area: `sshd.password_auth_enabled`, `sshd.root_login_enabled`,
  `accounts.empty_password`, `accounts.empty_password_remote`, `db.listens_unfiltered`,
  `svc.sensitive_listens_unfiltered`, `php.fix_missing` (0.0.3 G8) and `docker.socket_exposed` (flagged), and `creds.env_file_exposed`,
  `creds.ssh_key_exposed` and `creds.cloud_credentials_exposed` (secrets; 0.0.3 G5): a
  credential kept on the host that holds the data is the way to that data. Every other
  asset kind matches by area. The three credential findings are medium at base, so the
  raise makes them high at most. Time sync, auditd and pending updates never move. The step is applied
  by the engagement (`by: engagement`) after the host collector's own table
  (`host-collector.md §5.3`, unchanged): the embedded host envelope keeps the
  collector's severity, and the engagement finding carries the step (built, E9 step 9).
  `svc.listens_beyond_declared` does not raise on a `data.matters_most` host and its
  chain has no `data_matters_most` step: it is not a host access finding. A host access
  finding the host table left at high records the step as stopped, "capped at high by
  data_matters_most".
  It does not raise along a link from a repository to a host: `deploys_to` stays the
  string `production`, `staging` or `development`, and a link between assets is 0.0.3
  G4. The raise stacks with any other adjustment on the same finding ("Stacking").
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
step each, and a rule that applies is never skipped because an earlier one did.
Severity never rises past critical, and a step that cannot move it is
recorded in the chain but not as an adjustment.

**Exposed on purpose is terminal** (E9 step 1a). Once `exposed_on_purpose` lowers a
finding to `info`, no later step of the table applies. Each skipped step is recorded in
the chain: "not applied: declared exposed on purpose (`intent.exposed_on_purpose[i]`)".

**Time.** A date condition is judged at the moment scheck saw the thing it is about,
and the excerpt names that moment in `engagement.timezone`. It is never the session
start or the time the report is rendered, and where the moment is unclear the rule
abstains. This list is complete; a rule that reads a date and is not here is a defect:

| Rule | Judged at the collection time of |
|---|---|
| The left-person rule (a `left` date has passed when that time is after 24:00 of the date in `engagement.timezone`) | The read that observed the account. Firing on presence: the read(s) that observed it; where the page that held an item is not recorded, the earliest read of the population that held it. Disproving on absence: the earliest read of the population |
| Stale and never-signed-in accounts | The per-account detail read that returned the compared sign-in and creation times, not the users read |
| A Workspace role assignment's `expireTime` | The assignments read that carried it |
| A certificate's expiry and its 14-day window | The TLS read |
| `node.line_unsupported` (R9, 0.0.3 G8): a Node.js line the table holds a fix for (22, 24, 26) is supported until its table date (2027-04-30, 2028-04-30, 2029-04-30), the date compared as the left-person rule compares a `left` date (`finding.LeftAt`, in UTC). A line the table does not hold (18, 20, 21, 23, 25) is end of life with no clock | The host's collection: the start and the end of the session that read its packages (the kept envelope's `run.started` and `duration_ms`). Date not passed at the last read: disproved. Passed at the first read: fires. Within the read: abstains `unavailable:eol_within_collection`. No recorded time: abstains `unavailable:collection_time` |
| `security.txt` `Expires` | The `security.txt` read |
| `identity.unexpected_admin` for a person with a `left` date | The reads the left-person rule uses for that account (the owners reads on GitHub, the users reads on Workspace): handed to offboarding once the date has passed; while it falls within collection or a read has no recorded time, the rule abstains with the left-person rule's reason rather than judge the account as a current person's |
| An acceptance's expiry | One time per acceptance, for its outcome and every instance it covers alike: the latest collection time among the reads its matched findings cite; for a host finding, the host's collection, the start of the session that collected it. Never the run's first start. When any matched finding's reads carry no recorded time, the acceptance is undecided (`rule_not_decided`) and every instance it covers stays open |

An acceptance whose finding did not fire has no verdict consequence from `expires`;
the report prints the date only.

A population-based condition has two clocks. When the left date has passed at the
latest of the reads but not at the earliest (it falls within collection), the rule
abstains (reason `left_date_within_collection`): "left date *d* falls within or after
collection; re-run after *d*". When no read of the population returned a response,
nothing was seen at any time: the rule keeps its own reason for missing evidence, and
no absence is judged for a declared leaver. When
the left date has not passed at the observing read, there is no verdict (reason
`leaving_date_not_passed`), and the readout may note "leaves on *d*; observed with
access on *read date*".

A read with no recorded collection time makes the time-dependent rule abstain, reason
"collection time not recorded" (`unavailable:collection_time`); the session start is never the fallback. A sign-in or
creation timestamp later than its own read's collection time plus a fixed 5-minute
skew allowance is malformed, and the rule abstains. A readout note about a departed
person still observed uses the rule's clock and gating, is dated by the read that
observed them, and is never emitted unless the left date had passed at that read.

The excerpt states the comparison in dated words, each against its own read:

| Rule | Excerpt |
|---|---|
| Left person | "left 2026-09-01; account observed in the members read of 2026-09-30, 29 days after" |
| Left person, absence | "no access observed as of 2026-09-28 (earliest of the population's reads)" |
| Stale account | "last sign-in 2026-06-01, 121 days before the account read of 2026-09-30" |
| Never signed in | "created 2026-08-20, no sign-in as of the account read of 2026-09-30 (41 days)" |
| Certificate | "certificate expires 2026-10-20, 6 days after the TLS read of 2026-10-14" |

A resume re-judges persisted evidence, so this holds from step 1d; a resume keeps
nothing older than 7 days ([runs.md](runs.md), "Stop and resume"; built, step 8).

**Ceilings.** Critical is the anchor's definition: anyone on the internet can use it now, with no further step, and gets credentials, code execution or the tenant; or a high that someone with no right to it can use now, or that the company believes is handled. A step may take a finding past high only where the table's last column says yes: `contradiction`, `attribute:admin` on a left person's account, `attribute:production_write` and `attribute:public_repository`. No other step passes high: not the other rows of the table, not a collector's own steps declared on a definition (`Attributes`; none may pass high in 0.0.2), and not the host collector's own table (`host-collector.md §5.3`, which caps a finding left above high at high after the table). A declaration of stakes alone (`deploys_to:production`, `data_matters_most`, a host's `exposure: internet`) says neither that someone with no right to it can use the weakness now nor that the company believes it is handled. A finding definition may
also carry a severity ceiling that no engagement rule passes: `db.listens_unfiltered`,
`svc.listens_beyond_declared` and `svc.sensitive_listens_unfiltered` stop at high, since the cloud firewall and the
database's own authentication were not read; `php.fix_missing`, `node.fix_missing` and `node.line_unsupported` stop at high too, since the cloud firewall and whether the web server passes requests to PHP were not read. A step stopped by a ceiling is recorded in
the chain with the cap. For a table entry that stops at high: "capped at high by `<rule>`:
critical means that anyone, or someone with no right to it, can use this now, or that you
believe it is handled; `<rule>` says neither." For a definition's ceiling (R1, R3, R6):
"capped at high: the cloud firewall and the service's own sign-in were not read, so
scheck cannot say anyone can use this now." A definition's ceiling binds every step, including the host collector's own
`exposure:internet` step; the capped step is recorded with the definition-ceiling
wording. A ceiling is part of the definition, like its base, and is never a setting. The engagement's table only raises,
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
| critical | Anyone on the internet can use it now, with no further step, and gets credentials, code execution or the tenant; or a high that someone with no right to it can use now, or that the company believes is handled (reached only by the raises the table marks, "Severity in context"). | a usable empty password: an account with an empty password that sshd accepts empty passwords for (`accounts.empty_password_remote`, a multi-fact rule, E9); a credential in a public repository or its history; a credential of a kind never meant for a browser (a private key, `sk_live_`, a GitHub or npm token, a Google refresh token or client secret) served in a public web response; a `pull_request_target` workflow that checks out the pull request's head with a write token, on a public repository, where anyone can open one |
| high | One common attacker step away (a phished or stuffed password, an account at a provider, read access already given to someone) from accounts, data or the domain's name. | an empty password on an account with a login shell (usable locally under the distribution's default PAM; remote use not shown); 2-step verification not enforced at the identity provider; an admin without 2-step verification; a person who left still active (+1 `attribute:admin`, and +1 `attribute:production_write` when they can still push to a production repository); a super admin or owner nobody can name; a credential in a private repository or its history (scheck cannot tell whether it is live, and must not try); the GCP Owner role (`roles/owner`) on a service account; a bucket readable by anyone, not declared public; a write-all default workflow token with actions not pinned to a commit; a subdomain pointing at a provider that says nothing is set up there, where anyone can claim the name; SPF that authorizes any sender (`+all`, a bare `all`); a DKIM key short enough to factor (RSA under 1024 bits) |
| medium | Weakens a control or widens what a compromise reaches; needs a further condition. | a write deploy key (+1 `deploys_to:production`); password SSH (+1 `exposure:internet` by the host collector); DMARC not enforced on a domain that sends or shows mail use; an OAuth app with a broad scope (+1 `attribute:admin_grantor`); a named person who is a super admin or owner but not listed under `access.admins`; a contractor or shared account that is one; more super admins or owners than the tenant needs; a human with the GCP Owner or Editor role not declared an admin; a write-all default workflow token, alone; a name pointing at an outside name that does not exist, at a provider with no takeover entry; a page declared reachable only from a VPN or LAN that answered from the internet (+1 `contradiction`); a database listening on a non-loopback address that the host firewall does not restrict (`db.listens_unfiltered`; +1 `exposure:internet`, +1 `contradiction`; ceiling high); a remote-administration service in R6's table listening the same way (`svc.sensitive_listens_unfiltered`, 0.0.3 G5; +1 `unauthenticated_default` for Docker's API without TLS and etcd, +1 `exposure:internet`, +1 `contradiction`; ceiling high); a PHP web package below its source's fix for the October 2026 flaws (`php.fix_missing`, 0.0.3 G8; +1 `attribute:serves_web`, +1 `exposure:internet`; ceiling high) and the Node.js equivalents (`node.fix_missing`, `node.line_unsupported`; no raises) |
| low | Hardening that matters mostly alongside another weakness. | missing HSTS; pending updates of unknown class; a certificate that fails verification; a version number disclosed (to `info` when exposed on purpose); a non-sending domain not locked down; a session cookie without `Secure` or `HttpOnly`; plain HTTP not redirected (+1 `attribute:password_form`); actions not pinned, alone; a declared service listening beyond its declared audience (`svc.listens_beyond_declared`, E9 step 5a; fires only against a declaration, so always +1 `contradiction`: medium, high on an internet host; ceiling high) |
| info | Context or cleanup, not a weakness; listed apart, never ranked. | anything lowered by `exposed_on_purpose`; security-header hygiene beyond HSTS; a missing or expired `security.txt`; a 1024-bit DKIM key; a public name resolving to a private address; a stale record inside your own roots; a certificate expiring within 14 days |

A declared admin who holds Owner is a note for the readout, not a finding. Of the
example seeded issues in ROADMAP E3, every one but missing HSTS anchors at medium or
above, and HSTS is the only low.

## Plan selection and follow-ups

Design; becomes contract when E9 lands (steps 6 and 7, `ROADMAP.md`). Step 7, the
follow-up table with F1 and its loop, is built. Step 6 is built in
two parts: 6a, GitHub (the tiers, the budget, the selection, the Plan document and
`--stop-after plan`), built, and 6b, Workspace (the per-user order, OAuth grants and
forwarding in Check), built. The tier tables are versioned data
(`TiersVersion` in `internal/collector/github/selection.go`, `UserTiersVersion` in
`internal/collector/workspace/selection.go`); changing a tier or the kind order changes
the version, and `plan.json` carries it as `tiers_version`. With rules only, the one decision context
makes in Plan is which part of a large population is read first when a budget, a cap, a
rate limit or the run's deadline stops the reads short. The order is a table, not a
judgement, and every tier names the declaration or observation that put an item there.
The capped reads run in Check, after Plan, in this order; `--stop-after plan` shows what
will be read before any of it is. Workspace's Check reads run before GitHub's, because
the Workspace session's token lives about an hour from Recon's bootstrap.

**Repositories**, in tier order; within a tier, most recently pushed first (`pushed_at`,
a retained field of `github.repositories` and `github.repository`), a repository with no
`pushed_at` last, then `full_name`:

| Tier | Repositories | Basis and source named in `selection` |
|---|---|---|
| 1 | `deploys_to: production` | "deploys_to production", `assets.*.deploys_to` |
| 2 | named by a `secrets.production[].asset` | "declared secret store", `secrets.production` |
| 3 | observed visibility public | "public", observed |
| 4 | named by a `data.matters_most[].asset` | "data that matters most", `data.matters_most` |
| 5 | `deploys_to: staging` | "deploys_to staging", `assets.*.deploys_to` |
| 6 | declared as a repository asset (`assets.<r>`) and in no tier above | "declared repository asset", `assets` |
| 7 | the rest, not archived | "most recently pushed", no source |
| 8 | archived | "archived", no source |

The lowest tier wins. A repository that is public and archived is in tier 3; an archived
`deploys_to: production` repository is in tier 1. A `secrets.production[].asset` that
names an organization puts in tier 2 the repositories the inventory shows selected for an
organization secret (visibility `selected`), with source "secrets.production
(organization secrets, selected repositories)" in the selection; each item in `plan.json`
names the exact key as its source, for example "secrets.production[0] (organization
secrets, selected repositories)". When the secret's visibility is `all` or
`private`, or the selected-repositories read failed, it orders nothing, and Plan says
"`secrets.production[i]` names the organization; every repository can read its secrets,
so it orders none." This is ordering only: selected visibility is still not production
use for any finding.

**Declared repositories are never cut by the budget.** A repository declared as an
`assets` entry is read in every kind, at its tier's place, and its requests count toward
what is spent. Tier 2 repositories selected for an organization secret and tier 3 public
repositories are ordered first but can be cut. A declared repository missing from the organization list is still read and counts in
`in_scope`. A repository root with no declared organization has no budget and is read in
full.

**Users**, for the per-user Workspace reads (6b): 1 a person who left, still
active; 2 admin holders no `people` handle names; 3 super admins and holders of delegated
roles a handle names; 4 declared `contractor` and `shared` accounts; 5 `break_glass` and
`service` accounts; 6 the rest. An admin holder, for ordering, is an account with
`isAdmin`, `isDelegatedAdmin` or an observed role assignment; the findings' own rule for
an admin is unchanged. Within every tier: active first, then most recent
sign-in, then `primaryEmail`, then the account id. One order serves the per-user
reads Plan's order reaches: Recon's per-user assignment and detail reads, which can use
only what the user list already says (Google's admin flags, since no assignment is read
yet), and Check's OAuth grants. Gmail forwarding keeps its own order, leavers still
active first, then admin holders, then the rest, active first within each tier and then
`primaryEmail`. There is no Workspace request budget in 0.0.2:
the selection attaches only when a cap, the timeout or the rate limit cuts a per-user
population, and each keeps its reason (`limit_reached`, exit 2) and gains the selection.
A read stopped because the session's token expired (`unavailable:bootstrap_required`) is
such a limit: the tenant is `incomplete` with `limit_reached`, exit 2, and a cut per-user
population gains its selection; resume reads the rest. Expiry never preserves an
authorization. A `Repeats` stop that is not a limit is a failure and has no selection.
Only OAuth grants and forwarding carry a Workspace selection; Recon's per-user assignment
cap (10,000 observations) carries none, only its own reason.

**Breadth first by kind.** The budget is a compiled request count, 4,000 per organization
per run, for the per-repository reads Check sends. `limits.timeout` and GitHub's rate
limit still stop the run as `limit_reached`, and the existing per-repository caps (100
workflow files, 100 alert locations) stay. GitHub reads go by kind: five passes in this
order, each over every selected repository in tier order before the next pass starts, and
within a pass one repository's reads run together.

| Pass | Kind | Reads |
|---|---|---|
| 1 | access and protection | the `github.repository` object, the default-branch read, branch rules, the workflow default, collaborators (all pages), deploy keys (all pages) |
| 2 | CI | the workflow directory listing, the repository's Actions secret names, then the workflow files |
| 3a | alerts | secret-scanning alerts |
| 3b | alerts | Dependabot alerts |
| 3c | alerts | secret alert locations |

A repository object that is not found ends that repository's reads. The local mirror (two
ref listings, then the local read) runs after every counted pass, only for repositories
with a declared mirror, and is not counted.

**What counts.** Every page is one request; a retry of the same request counts once. A
request counts when the gate wrote a send line for it or a retry of it, whatever came back
(a 5xx, a timeout or a reset after sending is spent), or when the ledger answers it; a
refusal or a limit stop before sending does not count. The
`github.repository` object counts. Inventory, the mirror and the follow-ups (F1
has its own cap of 20) do not. On resume, a request the ledger answers counts as when
it was first sent, so a resumed run reaches exactly the selection one session would.

**A kind is all or nothing per repository.** It starts on a repository only while the
requests spent are below the budget; once started it finishes on that repository. The
spend can therefore pass the budget by one repository's kind under the caps, and Plan and
the report print "sent N of a 4,000 budget"; no cost is estimated. A kind cut inside a
repository by the timeout, the rate limit or a page cap is partial with that read's own
reason, never the budget's. A cap therefore leaves every selected repository with the
cheapest evidence and cuts the dearest kind first.

**A budget cut is `sampled`, not `limit_reached`, and does not change the exit code**,
whether it stops one kind early or leaves repositories with no per-repository read. The
reason sits on the row or sub-item whose kind was cut; its population counts the
repositories that got that kind (the least-reached kind among the kinds a row's rules
rest on), and the evidence of a kind the budget did not reach is marked `sampled` in
`check.json`, so a rule judges nothing from it (a secret alert locations cut abstains with
reason `sampled`); its detail names "the 4,000-request budget for
<org>". A kind's population counts a repository as read only when the kind read it: the
access kind when its object was recognized (a 404 repository was asked, not read); a later
kind when a request was sent or answered from the ledger. When the gate reports that every
later request would be answered the same (`Repeats`: a provider's rate limit, the
deadline), Check starts no further repository; the one in progress finishes its kind (the
gate refuses without sending), and the stop is `limit_reached`, never the budget's.
A declared repository left unstarted is recorded as an access entry
`unavailable:not_started` with reason `limit_reached` and the stop's detail, so it is listed
incomplete and never `failed`; an undeclared one is counted unread and adds no entry, note
or not-assessed line. A kind that needs no request on a repository (secret alert locations
where no alert exists) counts it as read.
`github.undeclared_public_repository` fires from the organization repository list for any
public repository whose object Check did not read: the budget, the deadline or a failed
read. Repositories with no per-repository read keep their inventory judgments.
`limits.timeout` and GitHub's rate limit stay `limit_reached`, exit 2, and their
population carries the selection too.

**What the report says.** A population's `selection` names what chose the items, in words
and in JSON ([report.md](report.md), "Coverage"):

```
40 of 120 repositories: deploys_to production (3, assets.*.deploys_to), declared secret
store (1, secrets.production), public (2, observed), then most recently pushed (34)
```

GitHub repository populations print the selection line every run; a Workspace population
only when a cap, the timeout or the rate limit cut it (`limit_reached`, never a failure
every later account would repeat); the JSON carries `selection` on every population Plan
ordered, with `kind` (`access`, `ci`, `secret_alerts`, `dependabot_alerts`,
`secret_locations`, and for Workspace `oauth_grants` or `mail_forwarding`) naming the read
it counts. "No declaration named
any repository; most recently pushed (N)" prints only when tiers 1, 2, 4, 5 and 6 are all
empty, and the observed-public count still prints before it; archived repositories read
follow as "archived (N)". Below the budget: "all N repositories read; the request budget
cut nothing." Every GitHub line ends "; sent N of a 4,000 budget." When a row's kinds
reached different populations the text prints one line per distinct selection, "Repositories
read for <kind words>: <selection>" (access and branch protection, workflows, secret-scanning
alerts, Dependabot alerts, secret alert locations); otherwise one "Repositories: <selection>".
A repository-root engagement has no budget and no selection line; its population reads
"1 of 1".

A Workspace selection has `unit` `users`, `kind` `oauth_grants` or `mail_forwarding`, and
the fallback "active, last sign-in desc, primaryEmail" (forwarding's JSON fallback is
"active, primaryEmail"). Its tiers are those of the accounts read, printed in tier order,
each with its basis and source from "Users" above. It
prints "Users: <selection>", or "Users read for third-party app grants: <selection>" and
"... for mail forwarding: ..." when a row's kinds reached differently. The sentence
follows the GitHub one with the unit and the fallback words taken from the unit and kind:
repositories "most recently pushed", users "the rest, active and most recently signed in
first", forwarding "the rest, active first". It reads "no declaration named any user; the
rest, ... (N)" when no tier above the last was read, "then the rest, ... (N)" after
declared tiers, "no declaration named any user" alone when nothing was read in the
fallback, and "all N users read" with no budget
clause, since Workspace has none. The sub-item that carries a cut selection counts that
population (`users`, read of in scope) and is at most *partial*.

A population's `selection.in_scope_at_least` (JSON) is set when the organization
repository list was not complete: the text reads "N of at least M repositories: ..." or
"all N repositories listed read; the list was not complete, so more may be in scope".

**`--stop-after plan`**, per GitHub organization: a header with the in-scope count, "budget
4,000 requests; inventory, the local mirror and follow-ups not counted" and the kind order
in words; then the ordered list, one line per repository with its position, `full_name`,
tier, basis and source, `pushed_at` date and the flags declared, public, archived and
mirror. The text lists every repository in tiers 1 to 6, then fills to 20 lines in all
and ends "and N more, most recently pushed first (`plan.json` lists all)". The JSON lists
all. The text never predicts the cut: "Check sends nothing until you resume this run; the
budget may not reach the later kinds on every repository." When some person with a `left`
value declares a GitHub login and the root has a `deploys_to: production` repository (no
date is checked), the selection's `notes` in `plan.json`, printed with them, gain: "After
these reads, Check may ask GitHub for a departed person's permission on each production
repository (at most 20 requests, not counted in the budget)." A Workspace tenant prints
"<asset>  N accounts in scope; OAuth grants are read in this order" (N "at least N" when
the users list was not complete) and the tier counts "(plan.json lists the accounts)"; the
JSON lists the ordered accounts. The not-judged list follows,
headed "Not judged for lack of a declaration:". `plan.json` holds it as `not_judged`, each
GitHub root's order as `github[]` (`asset`, `tiers_version`, `budget`, `in_scope`, `order[]`,
`notes[]`), and each host's checks as `hosts[]`. A Workspace tenant's order is
`workspace[]` (`asset`, `tiers_version`, `in_scope`, `in_scope_at_least`, `order[]`, each
account with `id`, `primary_email`, `tier`, `basis`, `handle` and `active`).

**The not-judged list.** Plan prints these lines, a closed list, each only when its
condition holds on what Recon read. Rules the engagement can read but that will not decide:

- Engagement-wide, when no `people` entry has a `left` date: "`identity.former_person_has_access` will not be judged on any account: no `people` entry has a `left` date, so scheck cannot tell a former employee's account from a current one." For GitHub, `identity.former_person_invited` is named in the same way.
- Per asset and person, when a leaver has no identifier for that asset: "`identity.former_person_has_access` on `<asset>` will not be judged for `<handle>`: their `people` entry gives no <GitHub login|Workspace address>."
- "`identity.unexpected_admin` on `<asset>` will not be judged: `access.admins` lists nobody for this <Workspace tenant|GitHub organization>, so scheck cannot tell an expected admin from an unexpected one."
- "`identity.unattributed_admin` on `<asset>` will not be judged: no `people` entry gives a <Workspace address|GitHub login>, so scheck cannot say whose the admin accounts are."
- "`github.outside_admin_on_production` on `<asset>` will not be judged: no repository in this organization declares `deploys_to: production`."
- Per sending mail domain: "`email.dkim_missing` on `<domain>` will not be judged: no DKIM selector is declared for it under `mail.senders`, and DNS cannot list selectors."
- "`email.spf_undeclared_sender` on `<domain>` will not be judged: `mail.senders` names no service that sends as this domain."
- When `intent.not_exposed` has URLs and the vantage is not `internet`: "`web.restricted_reachable` will not be judged for <n> URLs under `intent.not_exposed`: this run's vantage is <not given|vpn|lan>; run with `--vantage internet` from a network outside your VPN and office."
- "`svc.listens_beyond_declared` on `<host>` will not be judged: no service on this host is declared for localhost, lan or vpn (`expected_services`)." It is also named when entries exist but none has a narrow audience.
- "`workspace.external_forwarding` on `<asset>` will not be judged: `authorization.mailboxes` authorizes no mailbox, so no forwarding settings are read."

Declarations that are absent and change what is raised or ranked:

- "No repository declares `deploys_to: production`: no finding is raised for reaching production, a departed person's push to production cannot be raised, and no repository is read first for it."
- "`data.matters_most` is empty: you named nothing as holding the data that would hurt most, so no finding is raised for it and nothing is read or ranked first for it."
- Per tenant or organization with `access.mfa` absent or unknown: "`access.mfa` does not say who must use 2-step verification in `<asset>`: scheck reports what it reads, but cannot raise a gap as a contradiction of what you believe."
- Per Google Workspace tenant with `access.mfa` `everyone` or `some`, from `sign_in`: with `another_provider` and `everyone`, "a unit where Google does not require 2-step verification is still reported, but ranks higher for contradicting `access.mfa` only when a super administrator is among its accounts"; with `another_provider` and `some`, "never ranks higher"; with `sign_in` absent or `unknown`, that such a unit "ranks higher ... even if another service requires a second factor for those accounts". Nothing for `google`, nor for `admins`, `none` or `unknown`.
- When there are web roots and `intent.not_exposed` is empty: "`intent.not_exposed` lists no URL: nothing is checked for answering from the internet when it should not."

`identity.external_admin`, `identity.shared_admin`, `exposed_on_purpose`, `public: true`,
R1, R2 and R6 are left off the list on purpose.

The Plan document, `plan.json`, lists each host's planned and disabled checks, each GitHub
root's repository order and each Workspace tenant's account order above, and the
not-judged list. Its `checklist` stays empty: a rule family's order is the rules' own, and
context narrows none of them in 0.0.2.

**Follow-up reads** (built, E9 step 7). A follow-up is a row of a static table
(`internal/engagement/followup.go`, data): a trigger (a rule's verdict), a declared gate
operation, parameters typed from the judgment's subject, a cap and a depth. No model
picks a read. The table has one row.

| # | Trigger | Read | Parameters and cap | Depth |
|---|---|---|---|---|
| F1 | `identity.former_person_has_access` on GitHub fired, or abstained for lack of repository visibility ("F1 triggers") | `github.collaborator_permission`, `GET /repos/{o}/{r}/collaborators/{login}/permission` | the left person's declared login and one `deploys_to: production` repository; at most 20 requests per run | 1 |

F1b is answered by Check's access pass; no follow-up row reads it. The access pass reads
the branch and rules of every declared repository, and no rule reads branch protection
for R4: protection does not remove a writer's path to production. F2 is answered by
Workspace tier 1: a left person's account that is still active is first in the per-user
order ("Users"), so its OAuth grants and Gmail forwarding are read before any other
account's. Where those reads did not happen, the Workspace finding says so
([workspace-collector.md](workspace-collector.md), "Rules"). The depth allowance of 2 is
unused in 0.0.2.

An invariants test checks that every follow-up read is a declared gate operation, that
its parameters are typed from the subject, and that the table is acyclic with depth at
most 2. The gate's ledger answers a repeated success without sending; a follow-up that
failed or was denied is not reopened in the same session, and a resume may ask again.

*F1 triggers.* A (login, repository) pair is open only when the person has a `left` date
that had passed at the observing reads, a declared GitHub login, and the repository is
`deploys_to: production` in that organization (from `Declarations.Production`, never
decided by the collector) and its object was recognized in this run. A declared login
that is not a user login (for example one ending in `[bot]`) opens no pair. Then one of:

- *Fired.* The organization-level or a repository-level
  `identity.former_person_has_access` fired for the login, the login is not an observed
  owner, no production repository is `write_held` for it, and on this repository the R4
  fact is `write_unsettled` with the cause "login not listed", "permissions unknown" or
  "collaborators read ... failed" (a 5xx, a timeout or a truncated read). A collaborators
  read that was denied does not open the pair, since F1 needs the same permission, and an
  archived repository where the listed person is not admin does not either.
- *Abstained.* The judgment for a login seen nowhere (`details.membership` `none`)
  abstained with `insufficient_evidence` ("lack of repository visibility") and a leaving
  date that had passed at the reads of the population: members, owners, outside
  collaborators, invitations and each repository's collaborators. The pair opens on every production repository whose collaborators
  read was not denied. These reasons open none: `leaving_date_not_passed`,
  `left_during_collection`, `no_collection_time` and `no_declared_github_login`. A
  disproved judgment never triggers.

For each login the pairs stop at the first write established. The cap is 20 requests per
run across all organizations; a request sent or answered from the ledger counts, a retry
once, and on resume a ledger answer counts as when it was first sent. The requests are
outside the 4,000-request budget. The round is the primary key of the order: round *r*
asks every open login its *r*-th open production repository, repositories in Plan's tier-1
order (`pushed_at` desc, `full_name`). Within a round, fired triggers come before
abstained ones, then people by `left` most recent first, then handle, then login.

*The loop.* Inside Check, after the planned reads and the mirror, under the same
`limits.timeout`. Check calls the GitHub `Judge` in memory over Recon's, Check's and the
follow-up evidence to find the triggers; the verdicts are not persisted. A pair is open
when triggered and not attempted this session, and it is judged again after each round.
The loop ends when none is open, the cap is reached or a limit stops it. A 401 on a
permission read, which the gate records as refused, kind `access`, also stops it: nothing
more is sent with that token, and the remaining pairs are `not_sent` with reason
`limit_reached` and the refusal's detail. Its requests
carry audit stage `check`, like every Check read. `check.json` carries `follow_ups[]`,
one object per pair opened or cut:

| Field | Value |
|---|---|
| `row` | `F1` |
| `trigger` | `{id, asset, subject, person, verdict}`; `verdict` is `fired` or `abstained` and says why the read was sent, never a posture verdict |
| `op` | `github.collaborator_permission` |
| `asset` | `repo:github:<owner>/<repo>` |
| `params` | `{owner, repo, username}` |
| `outcome` | `read`, `not_found`, `denied`, `failed` or `not_sent` (below) |
| `reason` | the read's reason as the collector recorded it: the gate's reason, or `follow_up_cap` or `limit_reached` for a pair cut; omitted when empty |
| `request` | the request id; omitted for a pair not sent |

The outcome is `not_sent` for a pair the loop cut (the cap, a stop, an earlier 401) and
for a pair the gate stopped for a limit with no send line and no response
(`refused:rate_limit` or `refused:deadline`; reason `limit_reached`). A request the gate
sent, meaning it wrote a send line for it or for a retry (a request the run's timeout ended
in flight, a retry halted after a 502), is never `not_sent`: it is `failed`, worded "could
not be read: ...", whatever came back. The R4 cause "was not asked: the run stopped first
(...)" is for `not_sent` only. Otherwise `denied` is for
`insufficient_permission*`, `refused`, 401 and 403; `not_found` for 404 with no reason;
`read` for 200 with no reason and a read that was not truncated; `failed` otherwise.
The coverage line's "asked *N* of *M*" counts the pairs that are not `not_sent`
([report.md](report.md), "Coverage").

The permission evidence is persisted beside the repository access evidence, keyed by
(repository, login). The `findings.json` judgments that use it cite the permission read
in `Reads` and in the attribute `Refs`. A limit stop, including the stop after a 401,
makes a GitHub root that Check left `collected` `incomplete`, reason `limit_reached`, detail "the follow-up reads stopped: *detail*", exit 2 ("Stages"); a cap
reached changes no status and no exit code; a read that is denied, not found or failed
changes no root status or exit code and shows in the coverage line ([report.md](report.md),
"Coverage"); the one gate refusal that exits 3 on the follow-up is a 401 the gate records as refused,
kind `access` (the root it was sent for is refused; another GitHub root Check left
`collected` is `incomplete` as above). Any other gate refusal of the permission read is a defect
the tests catch, not an outcome.

## Context notes

Built (E9 step 5b). A context note says that the evidence
and a declaration disagree, or that a declaration reached nothing. It is not a finding.
Its shape is `{kind, source, detail}`: no id, no severity, never a change to the exit
code. It prints in the readout and under `notes` in JSON ([report.md](report.md),
"Findings"); a C3 note is also on its area's row as `context_notes`. `kind` is `context_workspace_domain`, `context_deploys_to` or
`context_not_used`; `source` names the declaration or asset it is about. A note is never
made from a population scheck did not read, and never contradicts a finding: it does not
restate one, move a severity or turn a row *assessed*.

- **C1 `context_workspace_domain`**, `source` the Workspace asset's id. A verified domain
  or domain alias the Workspace tenant's domains read returned (one reading merges both)
  that is not equal to any domain root. An unverified one is skipped; an incomplete list
  gives notes for what was seen; when the read failed there is none. No note for a domain
  whose mail records the web collector attempted to read (the roots, and declared mail
  senders and `no_mail` names under a root); a failed read shows in the web coverage, not
  as a C1 note. Under no root:
  "`example.co.uk` is a verified domain of your Workspace tenant and is under none of your domain roots, so its SPF, DKIM and DMARC were not
  read. Add it under `roots` to have them read." Under a root: "`eu.example.com` is a
  verified domain of your Workspace tenant under the root `example.com`; scheck reads
  mail records only at each root and the mail domains you declare, so its SPF and DMARC
  were not read. Add it under `roots` to have them read." The note names the most
  specific root that holds the domain.
- **C2 `context_deploys_to`**, any `deploys_to` value, `source` `assets.<name>.deploys_to`.
  A repository the GitHub credential does not see, one that is archived, or one that was
  not read. An archived repository is noted even when judgments exist on it, since they
  are on a repository nothing deploys from; not found and not read are noted only when no
  judgment exists on that repository asset. The text names the `deploys_to` value (here
  `production`). Not found: "`shop-repo`
  (`github:example-org/shop`) is declared to deploy production, but the GitHub credential
  sees no repository `shop` in `example-org`, so nothing on it was judged and no
  production raise applied. Check the name, whether it was renamed or moved, and whether
  the credential can see it." "And no production raise applied" is said only when the value is
  `production`; otherwise the sentence ends "nothing on it was judged." Archived: "`shop-repo` (`github:example-org/shop`) is
  declared to deploy production, but GitHub shows it archived. If production now deploys
  from another repository, declare that one." Not read: "`shop-repo`
  (`github:example-org/shop`) is declared to deploy production, but it was not read in
  this run (*reason phrase*), so nothing on it was judged." The phrase is omitted when no
  direct read was attempted; `insufficient_permission` reads "the credential was not
  allowed to read it", any other reason is its code with underscores as spaces.
- **C3 `context_not_used`**, `source` `not_used[i]`. A `not_used` area the evidence
  contradicts: one note per area, with up to three evidence clauses in the table's order (every workflow clause, across all GitHub assets, before any secret clause)
  and then "and *N* more". "You said you run no *area phrase* (`not_used`), but *e1*;
  *e2*; and *e3*. If these are yours, remove `<area>` from `not_used`." The area phrases are
  `cloud` "cloud accounts", `hosts` "servers", `data` "data stores", `email` "email" and
  `external` "internet-facing services". A name or a secret's name suggests: the note
  never says "leaks", "credential" or "key exposed", and a secret is cited by name only.
  The table is versioned data (`ContextTableVersion`); a change to it changes the version.
  A `not_used` area that has a fired finding, open or accepted, is not *not applicable*
  ([report.md](report.md), "Coverage"), and this note is attached to the row.

A workflow clause names the action's purpose after it: `google-github-actions/auth`
"which signs in to Google Cloud", `setup-gcloud` "which sets up the Google Cloud CLI",
`deploy-cloudrun` "which deploys to Google Cloud Run", `aws-actions/configure-aws-credentials`
"which signs in to AWS", `amazon-ecr-login` "which signs in to AWS's container registry",
`azure/login` "which signs in to Azure"; `appleboy/ssh-action` "which connects to a server
over SSH", `appleboy/scp-action` "which copies files to a server over SSH",
`easingthemes/ssh-deploy` "which deploys to a server over SSH", `webfactory/ssh-agent`
"which loads an SSH key to connect to a server", `shimataro/ssh-key-action` "which
installs an SSH key to connect to a server". An organization secret reads "`example-org`
has an organization Actions secret named `X`". A CNAME name an exclusion dropped is skipped.
`external` has no contradicting evidence in 0.0.2.

| Area | Contradicted by | Clause |
|---|---|---|
| `cloud` | a CNAME under a root to `*.run.app`, `*.appspot.com`, `*.cloudfunctions.net` (Google Cloud), `*.amazonaws.com` or `*.cloudfront.net` (AWS) | "`api.example.com` is a CNAME to `x.cloudfront.net` (AWS)" |
| `cloud` | a workflow `uses:` (any ref) of `google-github-actions/auth`, `google-github-actions/setup-gcloud`, `google-github-actions/deploy-cloudrun`, `aws-actions/configure-aws-credentials`, `aws-actions/amazon-ecr-login` or `azure/login` | "a workflow in `example-org/shop` (`deploy.yml`) uses `google-github-actions/auth`, which signs in to Google Cloud" |
| `cloud` | an Actions secret whose name starts `AWS_`, `GCP_`, `GOOGLE_CLOUD_` or `AZURE_`, or is exactly `GOOGLE_APPLICATION_CREDENTIALS` or `GOOGLE_CREDENTIALS` | "`example-org/shop` has an Actions secret named `AWS_ACCESS_KEY_ID`" |
| `hosts` | a workflow `uses:` of `appleboy/ssh-action`, `appleboy/scp-action`, `easingthemes/ssh-deploy`, `webfactory/ssh-agent` or `shimataro/ssh-key-action` | "a workflow in `example-org/shop` uses `appleboy/ssh-action`, which connects to a server over SSH" |
| `hosts` | an Actions secret named exactly `SSH_PRIVATE_KEY`, `SSH_KEY`, `SSH_HOST`, `DEPLOY_HOST`, `DEPLOY_SSH_KEY` or `SERVER_SSH_KEY` | as for `cloud`: "`example-org/shop` has an Actions secret named `SSH_PRIVATE_KEY`" |
| `data` | `net.listeners` on a declared host showing a process of R1's database table on any address, loopback included | "`postgres` listens on 127.0.0.1:5432 on `deploy`"; for `java` on 9200 or 9300, ", read as a data store from its port" follows |
| `email` | the Workspace users read: accounts neither suspended nor archived whose mailbox is set up | "*N* accounts in `google-workspace:example.com` have a Gmail mailbox" ("1 account ... has"; "at least *N*" when the users read was not whole, counting only accounts known neither suspended nor archived) |

No `run:` script is matched, and `ghs.googlehosted.com` is not a cloud name.

## Reachability and vantage

Reachability and the operator-declared vantage are defined in
[web-collector.md](web-collector.md#reachability-and-vantage).

## One command, one file

`scheck run` is the only command that assesses anything (0.0.2 E2). Its input is an
engagement file or, for one host, a locator; a run directory resumes that run ("Stop
and resume"). `scheck local` and `scheck ssh`, the 0.0.1 commands, were aliases of
`scheck run --host` in 0.0.2 and are removed in 0.0.3: unknown commands, exit 3.

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
contacts nothing and never overwrites a file. `--write-engagement` does not emit
`authorization.mailboxes`; only the human operator writes it.
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

The 0.0.2 aliases `scheck local` and `scheck ssh`, removed in 0.0.3, and the 0.0.1 flag
mapping they had are recorded in
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
| Check | Follow-up reads named by rules; from 0.0.3, probes (built, G3) and scans per the asset's modes: `off`, `confirm` or `all` | `auto`: an experimental gate on probes and scans ([scope.md](scope.md)) |
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

*The framework* (built, E9 step 3a: `internal/engagement/rules`). A rule declares its
reads, each a host check by catalog id or a declaration of the host's context, and
judges through a view that hands it only those; an undeclared read is recorded and
fails the invariants test, as does a declared read no judgment uses. Analyze judges
every collected host, kept ones included, from what a persisted envelope keeps (status,
reason, observation, parsed): exit codes and stderr are not kept, so a rule reads parsed
output and reason codes only. A fact known to be partial (a truncated or redacted
capture, a cap) never supports a disproval: the framework withdraws it with the reason
`unavailable:incomplete_read`, and the host's coverage is marked partial. A host of a
platform the rule does not judge gets no verdict, and its coverage plan names the
sub-item unread. Each judgment cites the facts it read by check, observation and
excerpt, and is graded by the severity table like a network collector's. A multi-fact
definition is marked `MultiFact` (report rule kind `multi_fact`); the model's finding
store refuses it, and an acceptance of its id is applied to the judgment by subject,
never by the host grader. An invariants test requires that every rule fires, is
disproved and abstains on a fixture, and that an all-partial read never disproves.

### The multi-fact rules of 0.0.2

R1 (E9 step 3a), R2 (step 3b), R4 and R5 (step 4), R3 (step 5a), R6 (0.0.3 G5 step 3) and R7 to R9 (0.0.3 G8 step 2) are contract; the rest
is design that becomes contract when its step lands (`ROADMAP.md`). Already built
and only audited in E9, each with its three fixtures: `identity.unexpected_admin`,
`identity.unattributed_admin`, `identity.former_person_has_access`,
`identity.former_person_invited`, `identity.external_admin` and `identity.shared_admin`
for Workspace and GitHub; the `deploys_to:production` raise; `web.restricted_reachable`;
the 2-step `contradiction`. E9 adds the rules below. An absence over repository populations (`identity.former_person_has_access`, and the
organization-level absence of `identity.unattributed_admin`) is disproved only when Check
read the object of every selected repository; when a budget, the deadline or a failed
object left one unread, the rule abstains (`Evidence.RepositoriesUnread`).
Each declares what it reads, ends as
*fires*, *disproved* or *insufficient evidence*, never fires on a population it knows to
be incomplete and never disproves on one, and has a firing, a disproved and an
insufficient-evidence fixture; an invariants test, like `ValidateRules`, rejects a rule
that reads nothing it declares.

**R1 `db.listens_unfiltered`** (built, E9 step 3a). Area data stores, base medium,
ceiling high, subject kind `service` (`port/proto`: an acceptance names it; the label is
the process name). It is an engagement rule over a host's facts, not a host posture rule,
and no `exposed_on_purpose` or `expected_services` entry lowers it. It judges Linux hosts;
a host of another platform gets no verdict, and its coverage names the sub-item
"Databases listening beyond localhost" as unread: "this version of scheck has no rule for
databases on this platform". It reads `net.listeners` (with process names, so elevated:
host-collector.md §7.1), `fw.ufw`, `fw.nft`, `fw.firewalld`, `fw.iptables_backend`, `os.release` and
the host's `expected_services`. The host's `exposure` is the severity table's input, not the
rule's.

*The database table* (`DatabasesVersion` 2026-10-31) names the processes by the kernel's
command name (15 characters, as `ss` prints it) and the ports they use:

| Process | Ports |
|---|---|
| `postgres` | 5432 |
| `mysqld`, `mariadbd` | 3306, 33060 |
| `redis-server`, `valkey-server` | 6379 |
| `mongod` | 27017 |
| `memcached` | 11211 |
| `clickhouse-serv`, `clickhouse` | 8123, 9000 |
| `influxd` | 8086 |
| `couchdb` | 5984 |
| `beam.smp` | 5984 only |
| `java` | 9200, 9300 only, tcp only (Elasticsearch, OpenSearch) |

A database process counts on any port except `beam.smp` (the Erlang VM of many programs)
and `java` (the JVM Elasticsearch and OpenSearch bundle, shared with any Java program),
which count only on their ports. A `java` judgment says it reads the program from its
port and did not confirm it, and never says whether the store's security is on. A table
port held by a known other process is no subject. An unnamed owner on a table port is insufficient evidence
(`unavailable:listener_owner`). `docker-proxy` and `conmon` on a table port are
insufficient evidence (`unavailable:container_port`): "Docker/Podman publishes this port;
its rules bypass ufw and firewalld, and scheck does not read them in this version";
`rootlessport`, `pasta`, `pasta.avx2` and `slirp4netns` on a table port abstain the same
way, since the service behind them is not known.

*Listeners.* A record counts for `tcp` `LISTEN` and `udp` `UNCONN`. Loopback is
`127.0.0.0/8`, `::1`, a v4-mapped loopback and any address with zone `lo`; `*`,
`0.0.0.0`, `::` and any specific or link-local address are beyond loopback. `::` takes
IPv4 too unless a `0.0.0.0` listener holds the same port. A subject is one port/proto
with its v4 and v6 listeners merged; it fires if any family of a database listener is
open.

*The firewall* is read from parsed output and reason codes only (exit codes and stderr
are not persisted). `ufw status verbose` must parse as ufw's `get_status` prints it:
`Status` active or inactive (any other word is unrecognized); `Default` incoming `deny`
or `reject` filters and `allow` does not; rule lines `To  ACTION DIR  From
[(attribute)] [# comment]`, `IN` only, where the attribute is `(log)`, `(log-all)` or
`(out)` and `(v6)` after To or From names the family. To is `Anywhere`[`/proto`], a port
spec (a port, a range `a:b`, a list, with `/tcp` or `/udp`), an address with a port spec,
or an address alone or with `/proto`; an application rule prints its ports followed by
the profile in brackets (`22/tcp (OpenSSH)`), and the printed ports are what is read.
From is `Anywhere`[`/proto`], an address or network (with ports or `/proto`), which
restricts the source, or ports alone, which do not: the source is still every address and
a sender chooses its own source port; with To `Anywhere`, a protocol ufw prints in From
only (`53/udp`) is the rule's. An address or network is `/proto`-suffixed as ufw
prints it (`192.168.1.0/24/tcp`); an application profile's name may hold spaces and
" on "; an IPv6 source address makes the rule an IPv6 rule. A line in no other shape
makes the whole read unrecognized, since it may be the first match.
For each family the first rule that covers the port decides: a rule bound to an
interface is unknown; a source-restricted rule is passed over; a `DENY` or `REJECT` to
one destination address, or any rule to a loopback destination, is passed over (traffic
to the host's other addresses does not match it); an `ALLOW` to one non-loopback
destination address is unknown (scheck does not compare it with the address the database
listens on); `ALLOW` or `LIMIT` from Anywhere is open; `ALLOW` or `LIMIT` from source ports alone is
open too, and the excerpt says "ufw allows this port from any address whose source port is
*P*; a sender chooses its own source port, so the rule does not restrict who can
connect"; `DENY` or `REJECT` from source ports alone is passed over; `DENY` or `REJECT`
from Anywhere is filtered; with no rule, the default decides. A disproval that rests on
an `ALLOW` from a source range adds the Not checked line "ufw allows this port from
*src*; whether those addresses are only the ones that need it was not judged". Every verdict reached
through ufw, fired or disproved, carries the not-checked sentence "Only ufw's own rule
listing was read: rules added outside ufw (by scripts, Docker, kube-proxy or a network
plugin, in iptables or other nftables tables) and custom lines in /etc/ufw/before.rules
were not, and they can open or close this port whatever ufw shows". The remediation's
caveat says to delete a source-port rule (`ufw status numbered`, then `ufw delete N`):
connection tracking already lets in replies to the host's own DNS queries. IPv6 is judged only when ufw lists at least
one `(v6)` rule: with `IPV6=no` ufw still prints its default but does not manage
ip6tables, so with no `(v6)` rule the IPv6 family is unknown. A `ufw` read known to be
partial never lets the default decide. The module is shared with R3.

*No host firewall* means: `ufw` inactive or not installed; `firewalld` not installed or
"not running"; `nft list ruleset` exit 0 with only blank or `#` lines (an empty ruleset,
no tables); and the `iptables` backend `xtables-nft-multi`, or no `/usr/sbin/iptables`
(`fw.iptables_backend` empty, except on `ID=alpine` in `os.release`, which keeps
`iptables` in `/sbin`: there the backend is unrecognized and the rule abstains). A known
limit: an empty backend read cannot tell "no `/usr/sbin/iptables`" from a `realpath`
without `-e` (busybox), and a host without merged `/usr` that keeps legacy `iptables`
only in `/sbin` (Ubuntu 18.04, Debian 9) is read as having none; with an empty `nft`
ruleset R1 then fires though legacy rules may filter the port. `firewalld` running, a non-empty `nft` ruleset with `ufw` inactive, `nft`
not installed or unreadable, the legacy backend (`xtables-legacy-multi`,
`xtables-multi`) and any other target abstain, with the reasons
`unavailable:firewall_ufw`, `firewall_firewalld`, `firewall_nft` and `firewall_backend`.

| Outcome | When |
|---|---|
| fires | a database listener on a non-loopback address, its owner named and not a container proxy, and the host firewall recognized as not filtering the port in that family: (a) `ufw` active with default incoming allow, or an `ALLOW` or `LIMIT` from Anywhere that covers the port; or (b) no host firewall, as above |
| disproved | for a subject, `ufw` active and every listening family filtered (default deny or reject with no open rule, or only source-restricted ones). For the host, a complete read (listeners usable and not partial, every non-loopback listener named) with no database listening beyond localhost |
| insufficient evidence | listeners unavailable (`unavailable:listeners`, which includes no `--sudo`: `net.listeners` is elevated); a non-loopback listener whose owner is not shown (a host-level abstention, `unavailable:listener_owner`, which also keeps the host from being disproved); a firewall read that did not run or parse; the cases above that abstain; a macOS host |

A fact known to be partial never disproves: the framework withdraws a disproval that
rests on it, with the reason `unavailable:incomplete_read` ("what it read was incomplete,
so it could show a problem but not rule one out"). The `Match`-block condition that bears
on sshd is not read, and R2 states it as a limit.

Raises: +1 `exposure:internet` when the host's `exposure` is `internet` (the severity
table, below, not the host collector), +1 `contradiction` citing
`assets.<h>.context.expected_services[i]` when that port and protocol is declared for an
audience of `localhost`, `lan` or `vpn`. A declared audience of `internet` leaves it at
base, with the `why_here` "You declared it internet-facing; a database open to every
address is still reported. Restrict it to the addresses that need it." Text: "*process*
on *host* listens on *address:port* and the host firewall does not restrict that port."
Not checked: "Whether a cloud firewall or security group blocks it was not assessed; who
can sign in to the database (its users, passwords and access rules, such as pg_hba.conf)
was not read", and, on the `ufw` branch, "Only ufw's own rule listing was read: …", or,
on the no-firewall branch, "Filters outside nftables (eBPF programs such as Cilium's)
were not read", and last, when a `java` process is among the listeners, "A java process on
*port/proto* is read as Elasticsearch or OpenSearch from its port; which program it is
was not confirmed". Remediation: "If only this host uses the database, bind it to localhost
(postgres `listen_addresses = 'localhost'`, MySQL `bind-address = 127.0.0.1`, Redis `bind
127.0.0.1`, Elasticsearch and OpenSearch `network.host: 127.0.0.1`) and restart it. If other machines need it, allow the port only from their
addresses (`ufw default deny incoming`, `ufw allow from 10.0.0.5 to any port 5432 proto
tcp`). Check your cloud firewall rules too: scheck did not read them." A bind address
alone is neither exposure nor this finding.

Deferred, with owners in `ROADMAP.md`: the base-chain refinement of an `nft` ruleset and
a parameterized `sshd -T -C user=` read (0.0.3 G5); the note for Docker's userland proxy
turned off; R1's contradiction evidence line naming the audience (carried from step
3b, no slice owns it yet).

**R2 `accounts.empty_password_remote`** (built, E9 step 3b). Area hosts, base critical,
no subject: one finding per host, the accounts listed under `affected`. Title "An account
with no password can log in over SSH", category `remote-access`, a host access finding.
It judges Linux hosts only. It reads `accounts.passwd_status`, `accounts.passwd`,
`sshd.config` (`sshd -T`, elevated) and `net.listeners`. The empty-password join is the
posture rule's own decision per account (`finding.StatusWithLoginShell.Decide`,
`finding.DecideJoin`; the posture rule's verdict is unchanged), so R2 and
`accounts.empty_password` never disagree on which accounts have an empty password.

| Outcome | When |
|---|---|
| fires | for an account U: `accounts.empty_password` fired for U; and `permitemptypasswords yes`; and a password method: `passwordauthentication yes`, or keyboard-interactive `yes` with `usepam yes` (`kbdinteractiveauthentication`, or `challengeresponseauthentication` when that is absent, OpenSSH before 8.7); and `authenticationmethods any`; and none of `allowusers`, `denyusers`, `allowgroups`, `denygroups` set; and, for an account with uid 0 (sshd applies `permitrootlogin` by uid, not name), `permitrootlogin yes`; and sshd listening beyond loopback |
| disproved | `permitemptypasswords no`; or `accounts.empty_password` disproved; or both password methods off; or every `authenticationmethods` list includes `publickey`; or the only accounts have uid 0 and `permitrootlogin` is `no`, `prohibit-password`, `without-password` or `forced-commands-only`; or sshd listens on no address beyond localhost on a complete listener read |
| insufficient evidence | password states unread; no account established; `sshd -T` unread, partial or unrecognized; a user or group list set; `authenticationmethods` it does not judge; `permitrootlogin` unrecognized for a uid-0 account; an account whose password state is not recognized and none fired (it is undecided, never left out); listeners unknown, an owner not shown, or a `systemd`, `inetd` or `xinetd` socket on a port sshd does not name (an `ssh.socket` `ListenStream` override moves sshd without `sshd -T` showing it) |

`sshd -T` prints the four user and group lists only when they are set, so their absence
counts only when the output is recognized: `permitemptypasswords` and `port` present and
the read not partial. "Listening beyond loopback" means a tcp listener owned by `sshd` on
any port, or, when the owner is `systemd` (socket activation) or not shown, on a port
that sshd's `port` or `listenaddress` names; a socket activator on another port keeps
the read from disproving. When R2 fires but some accounts were not decided (a password state
or a shell scheck does not recognize, a partial password-state read), the list is a lower
bound: the judgment marks the read incomplete and its Not checked names them ("Other
accounts were not decided: …"). The reasons are `unavailable:accounts`,
`unavailable:sshd_config` and `unavailable:sshd_listener`, each with report wording.

*`Match` blocks.* `sshd -T` without `-C` prints the settings outside `Match` blocks, and
nothing scheck reads shows that a `Match` block exists, so R2 cannot tell and does not
condition on one. Every R2 judgment's Not checked says: "Settings inside Match blocks of
sshd_config were not read, and whether PAM accepts an empty password (pam_unix nullok, on
by default on Debian, Ubuntu and Fedora) was not read". The fixed Hosts item
`hosts.ssh_match` carries the same limit ([report.md](report.md), "Coverage"). The
parameterized read `sshd -T -C user=<u>` is 0.0.3 G5.

No host context step moves it, and its `why_here` says: "This is the standard rating,
whatever the host is used for: anyone who can reach sshd can sign in as these accounts."
(A multi-fact finding that no step moved otherwise reads "This is the standard rating for
what this host's settings show.") It is critical on `dev` and `airgapped` hosts too.
`accounts.empty_password` keeps firing beside it; "Fix these first" leaves it out on a
host where an open R2 fired and names every account it does ([report.md](report.md), "Ranking"), and it stays under
Findings. Remediation: "Lock or set a password for these accounts (`passwd -l <user>`),
and set `PermitEmptyPasswords no` in sshd_config, then reload sshd."

**R3 `svc.listens_beyond_declared`** (built, E9 step 5a). Area
external surface, base low, ceiling high, category network, never lowered by
`exposed_on_purpose`, subject kind `service` (`port/proto`; the label is the process name
when shown, else the entry's `purpose`, else `port/proto`). It is an engagement rule over
a host's facts and judges Linux hosts; it reads what R1 reads, and R1's listener, ufw and
`*No host firewall*` readings are shared, not restated here. The host's `exposure` is the
severity table's input, and for `lan` and `vpn` also the rule's.

*Subjects.* Each `assets.<h>.context.expected_services[i]` with audience `localhost`,
`lan` or `vpn`, keyed `port/proto`. A service declared `internet` is no subject and has
no verdict: it is declared reachable. An entry with no audience is no subject either: it
declares nothing narrower. A service's audience is never `airgapped` ("Exposure
vocabulary"); an audience the rule does not recognize that reaches it abstains,
`unavailable:audience` ("a service's audience is localhost, lan, vpn or internet"), with the
Not checked line "*audience* is not an audience a service can have". A port/proto on which R1 emitted any outcome (a database
process, an unnamed owner on a table port, a container proxy on a table port) is R1's and
never R3's; a table port held by a known process that is not a database is R3's unless R6
finds a remote-administration service on it (R6, below). Nothing
listening on the declared port gives no verdict and no note: a declared service that is
not there is `svc.expected_missing`'s ([host-collector.md](host-collector.md)). A declared
port not seen on a `net.listeners` read known to be partial gives no verdict either. A
declared port not seen while a listener record's port could not be read abstains,
`unavailable:listeners` ("a listening socket's port could not be read, so whether this
service listens could not be established"), and the host-level disproval below is given
only on a listener read whose ports all parsed.

*Owner.* Not needed: an unnamed owner on a port that is not a table port is judged. A `docker-proxy` owner (Docker) or a `conmon` owner (Podman) abstains, reason
`unavailable:container_port`, saying "Docker publishes *port/proto* on *address*, though
you declared it for *audience* only; Docker's rules bypass ufw and firewalld, and scheck
does not read them in this version. If only this host needs it, publish it on 127.0.0.1
(`-p 127.0.0.1:8080:8080`)." (for Podman, "Podman" for "Docker"). `rootlessport`, `pasta`,
`pasta.avx2` and `slirp4netns` abstain with R1's text. A `systemd` socket-activated
owner is judged.

*Firewall first.* The predicate is R1's, unchanged: a source-restricted rule is passed
over and the default or a later open rule decides. R1 and R3 read the firewall once per
host through the same reader, lazily. A firewall that filters the port disproves it
whatever the bind, as R1 does; an unknown firewall abstains with R1's reason. `ufw` default deny incoming
with an `ALLOW` from a source range counts as filtering, and its Not checked adds "ufw
allows this port from *src*; whether those addresses are only your *audience* was not
judged"; R1 has the same line, worded "whether those addresses are only the ones that
need it was not judged".

*Bind.* A listener bound to loopback only is disproved first, whatever the firewall, but only
on a listener read whose ports all parsed: with an unreadable port, a declared port seen
only on loopback abstains `unavailable:listeners`, as one not seen does. A
filtering firewall then disproves and an unrecognized one abstains, before any row below.
The rows below are read only for the listeners in a family the firewall left open: the
open answer and the address are the same family's, and the address `bind_network` names
is one of them.

| Audience | Host `exposure` | Bind | Outcome |
|---|---|---|---|
| `localhost` | any | loopback only | disproved: "listens only on loopback (127.0.0.1:8080)" |
| `localhost` | any | any non-loopback address (wildcard, public, RFC 1918, CGNAT, ULA, link-local, bridge) | fires |
| `lan` or `vpn` | `internet` | loopback only | disproved |
| `lan` or `vpn` | `internet` | wildcard, or a specific global-unicast address | fires |
| `lan` or `vpn` | `internet` | a specific private, CGNAT (`100.64.0.0/10`), ULA (`fc00::/7`) or link-local address | insufficient evidence, `unavailable:bind_network`: "bound to *addr*, a private address; on a cloud VM a public address can forward to it, and scheck did not read the cloud firewall" |
| `lan` or `vpn` | not `internet`, or unset | any non-loopback | insufficient evidence, `unavailable:audience_network`: "you declared it for your *lan* (or *vpn*); on a host not declared internet-facing, scheck cannot tell which networks its addresses face" |

Every other insufficient-evidence case is R1's: listeners unavailable, an unrecognized or
unread firewall, a macOS host. A family known to be partial never disproves
("`unavailable:incomplete_read`", above).

*Raises.* The `contradiction` step always applies, since the rule fires only against a
declaration, and cites `assets.<h>.context.expected_services[i]`; `exposure:internet` +1
on a host declared `internet` ("Severity in context"). No `data_matters_most` and no
host step moves it. The result is low, +1 `contradiction` to medium, and on an internet
host +1 more to high; the ceiling holds it there, with the definition-ceiling wording.

*Text.* Title "A service listens beyond the audience you declared". "*label* on *host*
listens on *address:port*, though you declared it for *audience* only
(`expected_services[i]`), and the host firewall does not restrict that port." It never
says "reachable". Not checked, always: "Whether a cloud firewall or security group blocks
it was not assessed; whether the service asks for a password or key was not read", then
R1's ufw sentence or its no-firewall sentence. `why_here`, by case:

| Case | `why_here` |
|---|---|
| `localhost`, internet host | "You declared it for this host only, and the host is internet-facing: unless a cloud firewall blocks it, anyone can connect to it." |
| `localhost`, other host | "You declared it for this host only; machines on the networks this host is on can connect to it." |
| `lan` or `vpn`, internet host, every address | "You declared it for your *audience* only, but it listens on every address of an internet-facing host and the host firewall lets any address in." |
| `lan` or `vpn`, internet host, a public address | "You declared it for your *audience* only, but it listens on a public address of an internet-facing host and the host firewall lets any address in." |

Remediation, one fixed text for every audience: "If only this host uses it, bind it to
127.0.0.1 and restart it; if it serves your LAN or VPN, bind it to that interface's
address instead of all addresses. Or allow the port only from the addresses that need it
(`ufw default deny incoming`, `ufw allow from 10.0.0.0/24 to any port 8080 proto tcp`).
If Docker publishes it, publish it on 127.0.0.1 or the private address: Docker's rules
bypass ufw. Check your cloud firewall rules too: scheck did not read them. If the wider
audience is intended, correct `expected_services`."

*Coverage.* The host's coverage plan names the group "Declared services listening beyond
their audience" under the External surface row ([report.md](report.md), "Coverage"); on a
host that is not Linux it is unread: "this version of scheck has no rule for declared
services on this platform". A host with no `localhost`, `lan` or `vpn` entry is *not
assessed* for it: a host-level abstention, reason `unavailable:no_declaration`, "no
service on this host is declared for localhost, lan or vpn (`expected_services`); scheck
judges a service's reach only against what you declared". A host that has such entries
but none that yields a subject (every declared port is one R1 judges or one on which R6 finds a
service, or nothing listens there) gets one host-level disproval, "no service declared for
localhost, lan or vpn listens here, other than on database and remote-administration ports
R1 and R6 judge",
which the framework withdraws on a partial listener read. The fixed item `external.beyond_declared` is gone from the
not-judged list. The Hosts row's Firewall line reads "whether declared services listen
beyond their audience only; see External surface" beside R1's.

The interview's `expected_services` answers have three consumers: `db.listens_unfiltered`,
`svc.listens_beyond_declared` and `svc.sensitive_listens_unfiltered`. The interview's
`context` question asks for them ("Intake", the service line).

**R6 `svc.sensitive_listens_unfiltered`** (built, 0.0.3 G5 step 3). Area external surface,
category network, base medium, ceiling high, `HostAccess`, never lowered by
`exposed_on_purpose`, subject kind `service` (`port/proto`; the label is the process name
when shown, else `port/proto`). It is R1's rule over a table of remote-administration
services instead of databases, and it needs no declaration: a service in the table that
listens beyond loopback with nothing in front of it is reported whatever
`expected_services` says. It judges Linux hosts and reads what R1 reads (`net.listeners`,
the four firewall readings, `os.release`, the host's `expected_services`); a macOS host
gets no verdict. Its table is versioned data (`SensitiveServicesVersion`, `2026-10-24.2`;
a change to it changes the version). A listener matches on the process name the kernel
shows (cut at 15 characters) and, where the row lists ports, on the port:

| Class | Process | Port | `unauthenticated_default` +1 |
|---|---|---|---|
| Docker Engine API without TLS | `dockerd`; `systemd` on 2375 only | 2375/tcp | yes |
| Docker Engine API with TLS | `dockerd`; `systemd` on 2376 only | 2376/tcp | no |
| etcd client | `etcd` | 2379/tcp | yes |
| kubelet | `kubelet`, `k3s-server`, `kubelite` | 10250/tcp | no |
| kubelet read-only port (no sign-in at all) | `kubelet`, `k3s-server`, `kubelite` | 10255/tcp | yes |
| Telnet | `in.telnetd`, `telnetd` on any port; `systemd`, `inetd`, `xinetd` on 23 only | tcp | no |
| FTP | `vsftpd`, `proftpd`, `pure-ftpd` on any port; the same activators on 21 only | tcp | no |
| SMB | `smbd` | 445, 139/tcp | no |
| RDP | `xrdp`, `gnome-remote-de` | 3389/tcp | no |
| VNC | `Xvnc`, `Xtigervnc`, `x11vnc`, `wayvnc`, `vncserver-x11-c` | 5900 to 5909/tcp | no |
| Jupyter | `jupyter-lab`, `jupyter-noteboo`, `jupyter-server` | any port, tcp | no |
| SNMP | `snmpd` | 161/udp | no |
| RabbitMQ management | `beam.smp` | 15672/tcp | no |

*Outcomes.* The mechanics are R1's: the shared listener grouping, the firewall reader
(ufw, firewalld, nft and the iptables backend, read once per host) and the bind and
firewall order.

| Outcome | When |
|---|---|
| fires | a table service listens on a non-loopback address and the host firewall is recognized as leaving that port open to every source in that family |
| disproved | a loopback-only bind; a firewall that filters the port in every family that listens; or, for the host, a complete listener read (usable, not partial, every non-loopback listener named) with no table service beyond localhost |
| insufficient evidence | listeners unavailable (`unavailable:listeners`, which includes no `--sudo`); a non-loopback listener whose owner is not shown on a port of the table (`unavailable:listener_owner`; elsewhere it keeps the host from being disproved); a named program that is not one of the row's processes on a table port (`unavailable:listener_owner` as well, never a host-level disproval); `docker-proxy`, `conmon` or a rootless proxy owning a table port (`unavailable:container_port`); a firewall read that did not run or parse, including `firewalld` running and a non-empty `nft` ruleset with `ufw` inactive (R1's reasons); a macOS host |

A fact known to be partial never disproves (`unavailable:incomplete_read`, as R1). A
port/proto on which every listener beyond loopback is a table service is R6's and never R3's.
Where R6 only doubts the owner (an unnamed owner, a container proxy), or another program
listens on the port beside a table service (the other address family, a second binding),
R6 abstains (`unavailable:listener_owner` or `unavailable:container_port`: it never
disproves a port it did not read whole) and the declared service stays R3's, so R3 still
fires there with its own words (R3, above).

*Raises.* `unauthenticated_default` +1 on the classes marked above (Docker's API without TLS, etcd and
the kubelet's read-only port), declared on the definition (`Attributes`). The severity chain
cites the listener read that showed the service. `exposure:internet` +1 when the host's `exposure` is
`internet`. `contradiction` +1, citing `assets.<h>.context.expected_services[i]`, when
that port and protocol is declared for `localhost`, `lan` or `vpn`; a service declared
`internet` is no contradiction and stays at base, with the `why_here` "You declared it
internet-facing; a remote-administration service open to every address is still
reported. Restrict it to the addresses that need it." A host on `data.matters_most`
raises it by +1 (`HostAccess`). `exposed_on_purpose` never lowers it. The ceiling is high:
a capped step is recorded with the definition-ceiling wording, and nothing makes it
critical.

*Text.* Title "A remote-administration service listens beyond localhost and the host
firewall does not restrict it". Otherwise the `why_here` is the class and its fix, for
example "Docker Engine API without TLS. Never expose 2375; reach the engine through an
ssh:// Docker context." When the service is declared for `localhost`, `lan` or `vpn`, the `why_here` ends with
"You declared it for <audience> only, but it listens beyond that and the host firewall lets any address in."
Not checked, always: "Whether a cloud firewall or security group
blocks it was not assessed; whether the service asks for a password, a key or a
certificate was not read", then R1's ufw sentence or its no-firewall sentence.
Remediation: "If you do not use it, stop and disable it. If only this host uses it, bind
it to 127.0.0.1. Otherwise allow its port only from the addresses that need it, or reach
it through SSH or a VPN. Check your cloud firewall rules too: scheck did not read them."
Caveat: "If Docker publishes the port, its rules bypass ufw: publish it on 127.0.0.1
instead."

*What it never claims.* That the service is reachable from the internet (the cloud
firewall is not read), that it accepts a connection without a credential (three classes
have none by default; that is a default, not a reading), or that anything was sent to it.
It never connects: it reads the listeners and firewall rules the host collector already
collected.

*Cloud metadata is not judged* (decided 2026-10-24). Whether a cloud VM's metadata
service (`169.254.169.254`) is reachable from its processes is no finding before the
cloud collectors. It cannot be judged without sending a request, which the host collector
never does ([host-collector.md](host-collector.md) §11); on a cloud VM the service is
reachable by every local process by design, and the absence of a firewall rule that
restricts it by owner adds nothing; what matters is what the attached service account
can do, which the GCP collector (0.0.3 G1) and the host-to-cloud link (G4) own. The fact
sheet names the cloud platform from DMI only as a label (host-collector.md §3).

*Coverage.* The host's coverage plan names the group "Remote-administration services
listening beyond localhost" under the External surface row ([report.md](report.md),
"Coverage"); on a host that is not Linux it is unread: "this version of scheck has no rule
for remote-administration services on this platform". A read in which some listener's
owner is not shown is *not assessed* with `unavailable:listener_owner`: "some listeners'
owners are not shown to a read without sudo, so a remote-administration service on another
port could not be ruled out". The Hosts row's Firewall line reads "whether
remote-administration ports are filtered only; see External surface" beside R1's and R3's.
The fixed item `hosts.firewall_linux` reads "the firewall on Linux hosts, apart from
database ports, remote-administration ports and the services you declared".

**R7 `php.fix_missing`, R8 `node.fix_missing` and R9 `node.line_unsupported`** (built, 0.0.3
G8 step 2). Area hosts, category updates, base medium, ceiling high, subject kind `package`
(`key` and `label` the package name), never lowered by `exposed_on_purpose`. They judge the
PHP and Node.js packages of a Linux host against the dated table of the disclosures of
2026-10-21 (`advisory.TableVersion`, `2026-10-24`; the bar for an entry, and why `php` and
`node` are never run, are in [host-collector.md](host-collector.md) §1 and §11). A rule here
compares no version itself: the table's classifier compares a package only with the fix of
its own source, by dpkg or rpm ordering, never by upstream version number. They read
`pkg.dpkg_runtimes`, `pkg.rpm_runtimes` and `os.release` (the table row is chosen by its
`ID`, never `ID_LIKE`); R7 also reads `net.listeners` and the firewall readings R1 reads. A
macOS host gets no verdict, and its coverage plan names the groups unread: "this version of
scheck reads PHP and Node.js packages on Linux only".

| Id | Judges | Raises | `HostAccess` |
|---|---|---|---|
| `php.fix_missing` (R7) | a PHP web package (`php<L>-fpm`, `php<L>-cgi`, `libapache2-mod-php<L>`; rpm `php`, `php-fpm` and Remi's software-collection `phpNN-php`, `phpNN-php-fpm`; the collection's `phpNN-php` is judged as a PHP package, not as `mod_php`; an rpm `php-cli` or `phpNN-php-cli` is not judged, see `unavailable:php_cli`) below the fix of its source for CVE-2026-109618 and CVE-2026-109619 | `attribute:serves_web` +1, `exposure:internet` +1 | yes |
| `node.fix_missing` (R8) | `nodejs` (rpm also `nodejs18`, `nodejs20`, `nodejs22`, `nodejs24`, `nodejs26`) below the fix of its source for the ten flaws of the Node.js release of 2026-10-21; for a distribution package, its Brotli library below the distribution's fix for CVE-2026-111497 | none | no |
| `node.line_unsupported` (R9) | `nodejs` from a source that tracks the Node.js project, on a line the project no longer fixes | none | no |

*Outcomes,* per package (the subject):

| Outcome | When |
|---|---|
| fires | the installed version is below the fix of its own source: a distribution package below that release's fixed package; an upstream-tracking source (deb.sury.org for PHP 8.2 to 8.5, Remi, NodeSource) below the upstream fix; for R8, a distribution Node.js whose system Brotli library is below the distribution's fix (updating `nodejs` does not fix it). R9 fires for an upstream-tracking source on a line the table does not hold, or on one whose table date had passed at the first read of the host ("Severity in context", "Time") |
| disproved | the version is at or above the fix of the same source, the read complete and the source recognized. Ubuntu 24.04's `8.3.6-0ubuntu0.24.04.13` is fixed, though its upstream number is far below 8.3.36 (the false-positive trap). R9 is disproved for a package on a line whose table date had not passed at the last read. A disproof needs a whole read: with any partial runtime read, every would-be disproof is an abstention (`unavailable:packages_partial`) |
| insufficient evidence | `unavailable:packages` (neither package database could be read); `unavailable:os_release` (the distribution is unread or unknown); `unavailable:backport_unknown` (the table's fixed-package field for this distribution is empty, as for the Red Hat family, Fedora and Debian 11); `unavailable:source_unrecognized` (control-panel PHP, FrankenPHP, a local rebuild, any source the table does not know); `unavailable:unnumbered_backport` (PHP 7.4, 8.0 and 8.1 from deb.sury.org, fixed without a new version number); `unavailable:brotli_unread` (a distribution Node.js whose Brotli library was not found); `unavailable:distro_node_unfixed` (a distribution Node.js whose Brotli is already fixed: the distribution has published nothing for the other nine flaws); `unavailable:line_unsupported` (R8 on an end-of-life line, which R9 owns); `unavailable:distro_package` (R9 on a distribution package, whose support is the distribution's to give); `unavailable:php_cli` (R7: an rpm `php-cli` or `phpNN-php-cli`, whose `/usr/bin/php-cgi` may serve requests; the CGI program was not read, and while one is installed the host-level "no PHP web package" disproof is not said); `unavailable:php_without_package` (R7: a `php-fpm`, `php-cgi` or `frankenphp` listener on a host whose package databases show no PHP); `unavailable:packages_partial` (a would-be disproof, with a partial runtime read: see below); `unavailable:distribution` (no package of the product, on a distribution whose package names the reads do not cover); `unavailable:eol_within_collection` and `unavailable:collection_time` (R9, from the dates above) |

A Debian or Ubuntu host with only `php<L>-cli` has no PHP subject (dpkg's `php<L>-cli` is not read). The host-level outcome, when no package
of the product is installed, is a disproof only of "no PHP web package (or no Node.js
package) is installed according to the package database", never of "no vulnerable PHP on
this host". It is allowed only when `os.release` `id` is a distribution whose package names
the reads cover, by release (`advisory.Covers`): `debian` 9 or later and `ubuntu` 16.04 or
later for dpkg; `fedora` and the Red Hat family (`rhel`, `centos`, `rocky`, `almalinux`,
`ol`) 8 or later for rpm. On SUSE, Alpine, Arch, CentOS or Red Hat 7, Amazon Linux, Debian 8
and older, a derivative (`raspbian`, `linuxmint`), or with `os.release` unread, the rule
abstains `unavailable:distribution` and says which distribution it saw. It also says, in
"Not checked", that a PHP running outside the package databases is looked for only among
listening sockets, and only when they are read with sudo. One usable package database
is enough: a host has dpkg or rpm, and the other being unavailable is expected.

*Partial reads.* The three rules set `Rule.OwnPartial`: the framework neither withdraws
their disproofs because some fact they touched was partial nor marks the host's population
incomplete for it, and the rules settle it themselves. A runtime read is partial when its
output was cut, a dpkg package is half-installed, the rpm sentinel is missing, or lines were
not recognized. A partial read counts unless the distribution is one the other manager covers (a partial rpm
read is ignored only where dpkg covers the distribution, and the reverse): an rpm database that
does not exist on a Debian host does not cancel the disproofs the dpkg read supports. On a
distribution the reads do not know (Mint, Raspbian, Amazon Linux, CentOS 7, Debian 8) or with
`os.release` unread, every partial read withdraws the disproofs. The host-level disproof cites
the read whose manager covers the distribution. With any partial runtime read, every would-be disproof (a package at or
above its fix, a line still supported, no package of the product) becomes an abstention
`unavailable:packages_partial` whose "Not checked" names the read. A fired verdict stands:
a partial read can show a package behind, never ahead. Every per-package verdict cites
`os.release` (`ID=… VERSION_ID=…`), and a Node.js judged through the Brotli library also
cites the library's record.

*Standing gap.* Each rule declares the gap `unavailable:runtime_installs` ("PHP and Node.js
installed outside the package database (containers, Homebrew, source builds, version
managers, control panels) are not read"; `Rule.Gap`, carried as `CoverageGroup.Gap`). A group
that decided is therefore at most *partial*, and the gap's reason prints with the mark
([report.md](report.md), "The Hosts row"). The groups are "PHP security fix (October
2026)", "Node.js security fixes (October 2026)" and "Node.js release line support", under
the Hosts row's "Runtimes (PHP, Node.js)" sub-row.

*Raises.* `attribute:serves_web` is declared on the definition (`Attributes`) and set only
on a fired R7, only on Linux, when a program from the versioned list
`rules.WebServersVersion` (`2026-10-24`) listens on a non-loopback address and R1's firewall
reader leaves that port open to every source: `nginx`, `apache2`, `httpd`, `caddy`,
`lighttpd`, `litespeed`, `lshttpd`, `openlitespeed`, `frankenphp`, `unitd`, `angie`, and
`php-fpm*` or `php-cgi*` listening themselves. A reverse proxy that may front another
machine (`haproxy`, `traefik`, `envoy`, `varnishd`) and PHP's built-in server are not
counted. The chain cites the listener read. When the listeners or the firewall cannot be
read, or no such web server is shown reachable, the finding stands at its base and its
`why_here` says it is "rated at its base" and why; the raise has no "not applied" step. When
no web server is seen and a container proxy (`docker-proxy` and the like) owns a port beyond
localhost, the reason names the port and the container: "`docker-proxy` publishes
`0.0.0.0:443/tcp`, a container: what it serves, and any PHP or Node.js inside it, was not
read". Listener addresses are written as people write them, an IPv6 address in
brackets (`[::]:80/tcp`).
`exposure:internet` +1 when the host's `exposure` is `internet`; a host on
`data.matters_most` raises R7 by +1 (`HostAccess`). R8 and R9 raise on neither, and Node.js
has no listener join: `process.title` and process managers rename the program the kernel
shows. The ceiling is high, and the chain's stop says (`finding.Def.CeilingWhy`, for
`php.fix_missing`): "capped at high: whether the cloud firewall lets anyone reach this web
server, and whether it passes requests to this PHP, were not read, so scheck cannot say
anyone can reach this PHP now." The `serves_web` raise's own sentence is the shorter "A web
server on this host listens beyond localhost and the host firewall lets any address in,
which ranks one step higher."

*Text.* A fired PHP judgment reads "*package version* on *host* is below *fixed*, the first
*distribution release* package that fixes CVE-2026-109618 and CVE-2026-109619 (the PHP
security release of 21 October 2026). These flaws let anyone who can send a request to PHP
run code as the web server's account, before your application runs." On the Apache module
it adds "Apache with mod_php is the setup the PHP project demonstrated a full exploit
against." Ubuntu 18.04 and 20.04 add that the fix is published only through Ubuntu Pro.
The remediation is to update from the source installed from and then restart every PHP
process, because an installed update does not protect workers started before it; until
then `session.upload_progress.enabled=0` and `post_max_size=8M` (32M if the site takes
uploads) in `php.ini` or the FPM pool, not `.user.ini`, which reduce the risk and do not
remove it. R8 for a Node.js project build names the fixed versions (22.23.4, 24.22.1,
26.12.1); for a distribution package it names the Brotli library and says that updating
`nodejs` alone does not fix it; its remediation also says that copies built into Docker
images, single executable apps and snapshots must be rebuilt. R9's impact and remediation are line-generic, since it fires for a line after its table date
as well as for lines the table never held: the line reached end of life, the project's
release of 21 October 2026 fixes 22, 24 and 26 only, and later flaws will not be fixed on it. The
words *vulnerable* and *exploited* are never used: a version does not show a host
vulnerable, and that an exploit has been demonstrated is not that one was used.

Not checked, always: "Read: PHP and Node.js packages from dpkg and rpm. Not read:
containers and their images; Homebrew and installs from source; nvm, volta, asdf and fnm
installs in home directories; control-panel PHP (cPanel, Plesk, CloudLinux); Node.js inside
applications; other programs that bundle Brotli; whether running processes were restarted
after an update. Advisories published after 2026-10-24, the date of this build's table, are
not known to it." A distribution Node.js judgment adds "Debian had not published fixes for
the other nine flaws of this release as of 2026-10-24" only when the source is Debian.

*What it never claims.* That a host is vulnerable or exploited, that PHP is reachable (the
web server may not pass requests to it, and the cloud firewall is not read), or anything
about a runtime it did not read. It never runs `php`, `php-fpm`, `node` or `brew`.

**R4 `attribute:production_write`** (built, E9 step 4). A raise on the GitHub
`identity.former_person_has_access` finding. The GitHub collector states facts and the
severity table decides production, from `Declarations.Production[owner]`
(`assets.<repo>.deploys_to`); the collector never reads `deploys_to`
([github-collector.md](github-collector.md), "Rules: evidence outcomes"). The facts, on
a *fired* repository-level judgment: `repository_admin` (effective admin known true) and
`write` (`EffectiveWrite` below; not set on an archived repository unless the person is
admin), the latter citing the collaborators read and an excerpt of `role_name` and the
permission booleans. The organization-level judgment never carries `write`. The raise is
+1 and may reach critical.

| Case | Chain |
|---|---|
| admin on a production repository | `attribute:admin` (matching `admin`, or `repository_admin` on a production repository) high to critical, then `attribute:production_write` recorded as a step that cannot move (the scale's end) |
| push or maintain, no admin | `attribute:production_write` high to critical |

The chain sentence is: "This person left and can still push to *owner/repo*, which you
declared deploys to production, so this ranks one step higher." It never disproves
anything and creates no finding. When no repository is declared `deploys_to: production`
and a leaver judgment fired or abstained, the coverage row says the push to production was
not judged ([report.md](report.md), "Coverage"; built, E9 step 8).

*Not applied.* "Not applied" is a chain move said but not taken (`from` equals `to`, not
an adjustment), as `exposed_on_purpose`'s is. For each login the collector puts two
attributes on one *carrier* judgment, the organization-level judgment when it fired, else
the fired repository-level judgment with the lowest canonical asset id, and on none for
an observed owner (admin everywhere, already critical through `attribute:admin`):
`write_held` for each repository read where the login's write is established, and
`write_unsettled` for each where it is not, each with `Asset` (the repository) and, for
`write_unsettled`, the cause as the reference's excerpt. A repository is unsettled when
its collaborators read is missing, denied or failed, the login is not listed, the listed
permissions are unknown, F1 was asked and did not settle it, or it is archived and the
person is not admin. A repository
where write is known false is neither. The table keeps the production repositories among
them and says the move on the carrier only when no production repository is
`write_held` and at least one is `write_unsettled`. Nothing is emitted when no repository
is declared production, when every production repository settles false, or when the
finding did not fire. The sentence is: "not applied: write access to production
repositories was not established (*cause*)." with *cause* the first unsettled production
repository in canonical order:

| Cause | Wording |
|---|---|
| collaborators read missing, denied or failed | "the collaborators of *owner/repo* could not be read: *reason phrase*" |
| login not listed | "*login* is not listed among the collaborators of *owner/repo*, and that list may not show everyone with access" |
| permissions unknown | "the permissions returned for *login* on *owner/repo* were missing or contradictory" |
| archived | "*owner/repo* is archived" |
| permission read denied (F1) | "the credential was not allowed to read *login*'s permission on *owner/repo*" |
| permission read 404 (F1) | "GitHub has no account named *login* now (it may have been renamed or deleted), so its access to *owner/repo* could not be read" |
| permission read failed (F1), including one sent and stopped by a limit | "*login*'s permission on *owner/repo* could not be read: *reason phrase*" |
| account id differs (F1) | "the account now named *login* is not the one this run saw in *org*" |
| cut by the F1 cap | "*login*'s permission on *owner/repo* was not asked: scheck sends GitHub at most 20 permission requests per run" |
| cut by a limit before it was sent, or left unsent after a 401 | "*login*'s permission on *owner/repo* was not asked: the run stopped first (*reason phrase*)" |

The F1 causes take precedence, in the order of the table; "login not listed" survives only
where F1 was not sent and none of them applies. A permission answer that is unknown or
contradictory uses the "permissions unknown" wording.

When more than one repository is unsettled, the cause ends "; and 1 more production
repository" or "; and *N* more production repositories". In the chain the move has rule
`attribute:production_write`, `from` equal to `to`, `stopped` `not_established` and `why`
the sentence. The report JSON carries no chain; the text report prints the sentence under
"Why here", and `findings.json` judgments carry the move.

*The permission read (F1, built, E9 step 7).* For a production repository the
collaborators list did not settle, `productionWriteFacts` reads F1's answer; the list wins
when it settles. Write established gives `write_held` with a reference to the permission
read and an excerpt such as "permission: write; role_name: maintain; admin: false;
maintain: true; push: true; pull: true". Known not write settles that repository false.
F1 may make an abstained leaver judgment fire, and never disproves one: the answer for a
reclaimed or hidden login is `none` or 404, which is not an absence. A fired judgment
is on the production repository, its subject the account from the answer (id, login,
type), with `details.membership` `collaborator`, the attribute `write` and, where
established, `repository_admin`, with references to the permission read. It becomes a
carrier candidate under the lowest-canonical-asset rule, and once it fires the
organization-level `none` abstention is no longer emitted. The leaving date is judged at
the permission read's collection time. Its excerpt reads: "*login*: GitHub reports
*permission* (role *role_name*) on *owner/repo*, through a direct, team, base or
enterprise grant (GitHub does not say which); declared leaving date *d*; observed in a
permission read of *date*." When the judgment stays abstained and every production
repository answered `none`, its Not checked gains: "GitHub reports no access for *login*
to the *N* production repositories asked; other repositories were not asked." What the
collector reads from the answer is in [github-collector.md](github-collector.md),
"Selection under a budget and the permission follow-up (E9)".

*Effective write.* The collector's predicate `EffectiveWrite` returns write, not write or
unknown, from one collaborator entry:

- `role_name` redacted or truncated: unknown.
- Effective admin known true: write.
- `permissions` absent: unknown; a `role_name` alone never establishes write.
- `push` or `maintain` true is write only when `pull` is not false, `maintain` true does
  not come with `push` false, and `role_name` is absent, or `write`, `push`, `maintain`
  or `admin`, or a custom role (anything outside `read`, `pull` and `triage`). A
  `read`, `pull` or `triage` role with `push` or `maintain` true is a contradiction:
  unknown.
- `admin`, `push` and `maintain` all present and false: known not write, unless
  `role_name` is `write`, `push`, `maintain` or `admin`, a contradiction: unknown.
- Anything else: unknown.

Known not write on a listed collaborator settles that repository: per-collaborator
permissions are effective across direct, team and base access. The visibility caveat
applies only to a login the list does not show.

**R5 the person rollup.** A *person* is a `people` handle with a `left` value. R5
creates no finding, moves no severity and is not a finding id. It is a readout of two
kinds: the *People who left* lines and the `person` ranking item ([report.md](report.md),
"People who left" and "Ranking"). Both read findings and judgments already made.

- *Lines.* Every person with `left` gets lines on every tenant where they have a
  declared account or the tenant is in scope; the states, the wording and the JSON are
  in report.md, "People who left". Only a person with an open tied finding ranks. Each
  line reads an attributed judgment, so every collector judges every left person:
  Workspace gives one for each declared address (or `declared:<handle>`), abstaining
  with `leaving_date_not_passed` or the users rule's own reason when the leaving date had
  not passed or the users were not read; GitHub's carry `details.membership` (`owner`,
  `member`, `outside_collaborator`, `collaborator`, `none`), and a person with no
  declared login gets one abstention on the subject `declared:<handle>`, reason
  `no_declared_github_login`.
- *Tied findings.* `identity.former_person_has_access`, `identity.former_person_invited`,
  and any other open identity-area finding whose `subject.person` is the handle on an
  account where that person's `identity.former_person_has_access` fired on the same
  tenant. Findings outside the identity area (`workspace.external_forwarding`) stay
  separate. Without a fired `identity.former_person_has_access` on that tenant, nothing
  ties.
- *Item.* A `person` item exists when the person's open tied findings span two or more
  tenants or two or more finding ids. A single instance stays in its `finding_id` item.
  The ranking rules are in report.md, "Ranking".

Cut, with the owner: `db.internet_reachable` needs cloud firewall rules (0.0.3 G4); the
read of `pg_hba.conf` after R1 (0.0.3 G5); `net.unexpected_listener` as a rule, since
absence of an explanation proves nothing, at most a readout line; `fw.no_firewall_active`
alone, which stays unfired (the firewall row says "judged only for database and
declared-service listeners"); a finding for a contractor who can push, or naming the push
holders on a production repository's `github.default_branch_unprotected` (0.0.3 G4, with
"at least" framing); `data.matters_most` along a link from a repository
to a host (G4).

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
