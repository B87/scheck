# scheck — roadmap

What gets built next, and in which release. The direction is [VISION.md](VISION.md);
the contracts are in [spec/](spec/). v0.0.1, the host collector, was published on
2026-09-22 and is specified in [spec/host-collector.md](spec/host-collector.md).

| Release | Theme | In one line |
|---|---|---|
| **0.0.2** | The first engagement | Google Workspace, GitHub, the domain's email and web surface, and a host, through all seven stages, rules only, nothing beyond reading |
| **0.0.3** | Cloud, probes and follow-up | GCP, first-party evidence from its inventory, the first probes, deeper host checks, and comparing two runs, still rules only |
| **0.0.4** | Judgement and depth | A model in Plan and Analyze, scans, full scope and the `auto` gate, each measured |

The order follows one argument: cover the places a small company actually gets
breached, identity, leaked secrets and cloud configuration, before adding a model to
reason about them, and prove every model feature against the rules-only baseline before
it becomes a default (VISION principle 5). An independent consultant's review of an
earlier draft, which opened with a host, a website and probes, is the reason the first
engagement starts from identity and code instead: those are where the findings that
matter come from, they need no authorization window, and they are read through APIs
that a fake server can stand in for in tests.

What scheck is, release by release, said plainly: through 0.0.3 it is the collection
and first-pass judgement of an engagement, with a coverage table honest about the rest.
Hypotheses drawn from the operator's own words, the part of the job that earns the word
"consultant", arrive in 0.0.4 and only if they beat the rules on labeled cases.

## Rules for every release

- **One enforcement point per collector kind.** Host commands go through
  `runner.Runner.Run`; every HTTP request and API call goes through one scope gate with
  the same duties: scope and exclusion, first-party evidence, level and mode,
  authorization window, throttle, timeout, redaction, audit. Nothing reaches a target
  any other way.
- **A declared surface.** Host checks are a compiled catalog, probes a reviewed list,
  API collectors a declared list of read operations. Nothing builds a command or request
  from a model, a config value or target output beyond typed parameters.
- **Redact before output; unknown is not safe.** A seeded secret is asserted absent from
  every report, audit log and persisted run, and its marker present. A check that could
  not run, was denied or was not approved is reported, and coverage says so.
- **Every interview question has a consumer.** A question in `scheck init` exists
  because a rule reads its answer, a coverage reason cites it, or the report prints it
  (`spec/engagement.md`, "Intake"). A question nothing reads is removed, not kept for
  later.
- **The lab comes before the checks it measures.** Each release's lab is seeded by
  someone who does not write that release's checks, and its labels are sealed before
  the first collector slice starts. One author cannot be blind to their own seeding.
  The seeder may be a second person or an **AI agent in its own session**, under these
  conditions: the seeding session reads the vision, the specs and this roadmap's
  example tables but never the collector code, the rules or their fixtures; it writes
  the seeded issues and the clean variant, seals the labels (encrypted in the tree or
  outside it, hash in `docs/eval/`) and hands back only the hash; the implementing
  sessions never read the labels until the recall run; and the acceptance record names
  the seeder (person, or agent and model) and says which. An agent seeder is weaker
  than a stranger, since it draws on the same documents as the implementer, so the
  record must also list the issues the lab contains that no planned check finds, as a
  check that the seeding was not shaped to the roadmap. Without any seeder of either
  kind, the recall and false-positive gates are recorded as *not run*, never as passed.
- **Evidence for every release gate.** Gates are recorded in
  `docs/eval/acceptance-<version>.md` and published through
  [RELEASING.md](RELEASING.md). A gate that could not be run is recorded as such.
- **One commit per slice**, `make check` green at each. When implementation deviates
  from a spec, the spec changes in the same commit.
- **The host collector does not regress.** Its golden command traces and reports change
  only with an explained reason (`spec/host-collector.md §9`). Adding a check is such a
  reason; a trace that changes for any other reason is a defect.

---

## 0.0.2 — the first engagement

An operator runs `scheck init`, answers an interview, and gets an engagement file.
`scheck run engagement.yaml` resolves scope, reads the Google Workspace tenant, the
GitHub organization, the domain's DNS, email records and TLS, and the host, combines
facts with rules, and writes a report that opens with coverage per risk area and ranks
what it found. Nothing in 0.0.2 sends a request beyond reading: no probes, no scans, no
authorization window needed. The point is to prove the engagement works end to end,
including the claim that context and links between assets change the result, on the
assets where a small company's risk actually sits.

### Decisions

| Question | Decision |
|---|---|
| Which assets first? | Google Workspace and GitHub (identity, secrets, CI/CD), the domain (email spoofability, takeover, TLS) and one host. Websites are read only at their declared entry points. |
| Why not probes? | A probe needs first-party evidence, and in 0.0.2 the only evidence for a discovered site would be the operator's word. Probes arrive in 0.0.3 after the cloud inventory can vouch for an address. |
| Why GCP and Google Workspace rather than AWS and Microsoft 365? | A market decision, stated as one: the authors' own environment is Google, so the live tests and the lab can exist. AWS has the larger share of small companies and is the next collector on the same shape, before Azure and Microsoft 365. |
| Third-party tools? | None. DNS, TLS, headers, fingerprinting and both APIs need only the Go standard library. |
| The host side? | The host collector, unchanged in 0.0.2. `scheck local` and `scheck ssh` keep working as in 0.0.1; the deeper checks a small company needs from it are 0.0.3 G5. |
| A model? | No. Every stage runs on rules, single-fact and multi-fact. Plan is a checklist per asset type, narrowed and ordered by context, and the report says so. |
| Reports? | The host report keeps its schema and versioning (`spec/host-collector.md §6.4`). The engagement report is a new document with its own schema, starting at 1.0. The engagement file and report may change freely until 0.0.2 is published. |

### E1 — engagement file and `scheck init`

**Delivers:** the `engagement.yaml` schema as `spec/engagement.md` shows it: roots,
exclude, defaults, limits, `people` keyed by handle, assets with canonical ids and the
host reach settings, the four host context fields of `spec/host-collector.md §5.2`
allowed in an engagement, the intake answers with their declared consumers, and the
optional authorization block; validation before any target contact (`spec/engagement.md`,
"Identity, references and validation"); `scheck init`, an interview that writes the
file; `scheck run engagement.yaml --stop-after intake`.

**Done when:** unknown keys, malformed roots, an `assets` entry outside every root and
an `exclude` under no root exit 3 naming `file:line:key`; a credential-shaped value is a
usage error that names the detector and never prints the value; a probe or scan mode
other than `off`, `scope: full` and `max_cost` exit 3 with "not available in this
build"; a timestamp without seconds or an offset, and a limit of `0`, are rejected;
`engagement.name` outside `^[a-z0-9][a-z0-9-]{0,62}$` is rejected; every interview
question maps in code to a consumer a test proves exists; no code path in this slice
contacts a target.

### E2 — the lab, sealed

**Delivers:** a GitHub test organization the team owns, a Google Workspace test tenant
on a domain the team owns, and one Linux host over SSH (nginx in front of a Next.js app,
postgres on the same host) in a docker-compose file; a seeded issue list written by a
seeder who is not the implementer (a person, or an agent in its own session, under the
rule above) and sealed before E5 starts; two context cases and a clean variant; the
false-positive target for the clean variant, fixed now.

| Example seeded issue | Found through |
|---|---|
| A secret committed in a repository's history | repository scan (E5) |
| Organization does not require two-factor authentication | GitHub API (E5) |
| A workflow token with write access to every repository | GitHub API (E5) |
| A third-party action unpinned in a `pull_request_target` workflow | GitHub API (E5) |
| 2-step verification not enforced for the tenant | Admin SDK (E6) |
| Four super admins among six users | Admin SDK (E6) |
| An account of a person whose `left` date has passed, still active | Admin SDK and the intake answer (E6, E9) |
| A GitHub organization owner nobody declared, tied to no person | GitHub API and `people` (E5, E9) |
| A third-party OAuth app with full Drive scope | Admin SDK (E6) |
| DMARC published at `p=none` | DNS (E7) |
| A CNAME to a hosting service that no longer serves the name | DNS (E7) |
| `PasswordAuthentication yes` on the host | host collector (E8) |
| postgres bound to all interfaces with no host firewall rule in front | multi-fact rule (E9) |
| Missing `Strict-Transport-Security` header | response headers (E7); low, must rank below every item above |

Context cases: a version-revealing `/status` page declared public on purpose must not be
reported above *info*, while a secret exposed on the same site keeps its severity;
`/admin` declared VPN-only and reachable from a run with `--vantage internet` must be
reported as a contradiction of the declared intent, and the same run with
`--vantage vpn` must abstain.

The lab is a docker-compose file, and ports Docker publishes bypass the host firewall.
The seeded issue in the table runs postgres as a host process, so the rule can fire. A
Docker-published listener is a different issue, which the seeder may add, and on which
the 0.0.2 rule correctly abstains (`spec/engagement.md`, "Stages").

**Done when:** the labels are committed encrypted or stored outside the tree, with
their hash in `docs/eval/`, before the first commit of E5; the seeder is named in the
acceptance record, with the model when it is an agent. E1, E3 and E4 need no lab and
may proceed while it is being built.

### E3 — scope stage and the scope gate

**Delivers:** expansion of roots by passive discovery (DNS, certificate transparency);
`exclude`, including repositories, organizational units and projects under a root, with
excluded items dropped from API responses before anything is stored; first-party
evidence per asset, and the operator's confirmations written back to the engagement
file as `first_party`; the resolved list with `--stop-after scope`, printed without
waiting when there is no terminal; the scope gate with its audit log, throttle (the
provider's rate-limit headers for APIs), timeout, re-resolution of names at request
time, and the authorization windows, which nothing in 0.0.2 needs but every later level
checks; third-party data sources (certificate transparency, DNS resolvers, provider API
endpoints) as a declared list of their own; the run directory, `0700` and locked;
per-request status for resume. Decided in this slice: how repository history is fetched
for E5 (`spec/scope.md`, "Repositories").

**Done when:** gate tests prove a request to an asset outside every root or to an
excluded asset is refused and audited as refused; an excluded repository returned by a
list call never reaches evidence and the drop is audited; a name re-pointed into an
excluded range between Scope and the request is refused; a dangling-record fixture is
reported and never contacted; an observe request to a discovered site reads only its
front page and certificate; a run past its timeout stops as incomplete; a resume after a
denied request retries it and keeps what succeeded.

### E4 — the engagement report

**Delivers:** the coverage table by risk area (`spec/engagement.md`), with the five
marks defined there and reasons from its closed list, and per row the assets covered
and excluded, the principal, the collection span, caps and sampling, and declared facts
not verified; the *outside scheck* rows; ranked findings labeled as a ranking of what
was assessed; a header with the trigger, the method ("rules only; the plan is a
checklist"), the authorization block when present, and a notice that the report holds
personal data and internal topology; a ready-to-paste `accepted_risks` entry under each
finding; excluded, out-of-scope, refused and not-run items; exit 2 when a declared root
went unassessed, findings or not; text and JSON with
`docs/engagement-report-schema.json`; golden files under the same rules as the host
report's. Built before any collector so every later slice renders into the real report.

**Done when:** golden text and JSON reports are committed for an engagement with no
collectors (every area *not assessed* with the reason `collector_not_built`, the
*outside scheck* rows present), the JSON validates against the schema as committed,
the run exits 2, and target-derived text is control-character escaped.

### E5 — GitHub organization and repository secrets

**Delivers:** a GitHub collector with a read-only token from the environment and a
declared list of read API calls: two-factor requirement, owners and outside
collaborators, default workflow token permissions, branch protection on default
branches, third-party actions pinned to a commit and their use in `pull_request_target`
workflows, the names (never the values) of organization and repository secrets, deploy
keys with write access, pending invitations, and Dependabot and secret-scanning alerts
where the token can read them. A secret scan of repository history, through the
transport decided in E3, redacted in every output. A token with more than read access
is itself reported. People are matched by login only (`spec/engagement.md`, "People").

What a token cannot see is *insufficient evidence*, never a pass: the organization's
two-factor requirement is visible only to an owner's token, and whether a fine-grained
token or an App has more than read access cannot always be read.

**Done when:** tests against a fake GitHub API server cover every rule's three outcomes,
including a non-owner token on the two-factor rule; a seeded secret never appears in any
output and its marker does; no non-`GET` request is ever made.

### E6 — Google Workspace collector

**Delivers:** read-only Admin SDK calls with scopes from the environment or the
provider's login. Rules for: 2-step verification enforcement and enrolment, kept
apart, since enforcement is per organizational unit with grace periods; super admins
against `access.admins`; stale and never-logged-in accounts, not counting new hires
(read the creation date) or `service` and `break_glass` accounts; suspended accounts
only when they keep an admin role or group-granted access, since suspension is correct
offboarding; third-party OAuth apps with broad scopes; external mail forwarding, which
needs per-user Gmail settings through domain-wide delegation and is *not assessed*
without it. The tenant is identified by its customer id; secondary domains and domain
aliases belong to it; people match by `primaryEmail` only, and an alias is reported
apart (`spec/engagement.md`, "People"). The exact list is frozen at the start of the
slice against what the read scopes return.

**Done when:** as E5, against a fake Admin SDK server; an opt-in live test (`make live`)
reads the lab tenant; broader-than-read scopes are reported as a finding.

### E7 — domain, email and web observe

**Delivers:** DNS records and subdomain takeover detection by provider-specific
fingerprints, wildcard-aware, never by trying to claim the name; SPF, DKIM and DMARC
with the DMARC policy and alignment read, not just presence; DKIM read per selector
declared under `mail.senders`, *insufficient evidence* without one; domains declared
under `mail.no_mail` expected to publish `v=spf1 -all` and DMARC `p=reject`, and DMARC `p=none` graded by
whether the domain sends; TLS and certificate, response headers and cookies, technology
fingerprint, `robots.txt` and `/.well-known/` entries, from entry points only
(`spec/scope.md`, "Web applications and sites"). Single-fact rules for each.

**Done when:** tests against recorded HTTP and DNS fixtures (`httptest`, no network)
fire, disprove and abstain for every rule; the audit log shows no request outside an
asset's entry points.

### E8 — the host as an engagement asset

**Delivers:** a `host:` root runs the host collector through the runner; its facts and
posture findings join the asset map. The asset's reach settings (`identity`, `jump`,
`elevate`; the port is part of the locator) come from the engagement file, and an explicit `elevate: none` in
`scheck.yaml` vetoes elevation; `jump` is new (ProxyJump), a connection hop on which
nothing runs. The host collector receives only the asset's four context fields; its
implicit context sources and `target:` sources are not read.

**Done when:** the golden command traces in `internal/baseline` are unchanged and the
0.0.1 reports for `scheck local` and `scheck ssh` are byte-identical; an integration
test reaches the lab host through a jump host, and the canary is still the first
command on the session.

### E9 — Plan, Analyze and multi-fact rules

**Delivers:** a rules-only plan per asset type, narrowed and ordered by structured
context; multi-fact rules that declare exactly which facts they read and abstain when
any is unknown, including the rules that consume intake answers: declared admins
against each tenant's admins and owners, people who have `left` against active
accounts, unattributed owners and admins, `deploys_to: production` repositories,
declared exposure against observed reachability from the recorded vantage; rules that
name follow-up reads, so the loop iterates; termination when no follow-up is open or a
limit is reached; no successful check re-run with the same inputs and principal;
context adjustments as `spec/engagement.md` "Severity in context" fixes them, each
attributed.

**Done when:** every multi-fact rule has firing, disproved and insufficient-evidence
fixtures; `db.listens_unfiltered` fires only when listener and host firewall facts both
agree and says the cloud firewall was not assessed; the left-person rule fires on the
lab and abstains when the tenant was not read or the person has no identifier for it;
"exposed on purpose" moves an exposure finding and leaves a secret finding on the same
asset unchanged; a loop fixture terminates.

### Release gates

1. `scheck init` produces an engagement file for the lab, and `scheck run` takes it
   through all seven stages, each inspectable with `--stop-after` and resumable.
2. **Recall:** the run is recorded against the sealed labels; every miss is recorded as
   a miss before any check is added to fix it.
3. **False positives:** the clean variant's findings are counted against the target
   fixed in E2.
4. **Context:** both context cases behave as stated, beside a run without context.
5. **Prioritization:** a named reviewer who wrote none of the checks ranks the lab's
   issues before seeing any scheck output; at least four of the reviewer's top five are
   in scheck's top five. Without such a reviewer the gate is recorded as *not run*.
6. **Coverage:** every risk area's mark matches what ran by the definitions in
   `spec/engagement.md`, for the lab and for an engagement with a collector missing or
   credentials withheld; the reason is printed, and the run with a declared root
   unassessed exits 2.
7. **Scope:** only the observe level reaches any asset, no request leaves the declared
   entry points, and the audit log shows every request and API call. The lab host's
   integration diff stays the exact allowlist of `spec/host-collector.md §1`.
8. `make check` is green, and the host collector's reports and command traces are
   unchanged.

**Sequence:** E1 → E2 → E3 → E4 → {E5, E6, E7, E8} → E9. The lab and the report come
before any collector so that recall is measured, not confirmed, and so each collector
has somewhere to render.

---

## 0.0.3 — cloud, probes and follow-up

0.0.3 adds the collector that reaches cloud configuration for a company on Google,
**GCP**, and uses its inventory as the first-party evidence that lets the first
**probes** run. It deepens the host collector where small companies bleed, and adds
the feature a company pays for a second time: comparing two runs. Still rules only.

### Decisions

| Question | Decision |
|---|---|
| Which cloud first? | GCP, with a project or organization root (`cloud: gcp:<project>` or `gcp:organizations/<id>`); see the 0.0.2 decision on why. |
| Credentials? | Application Default Credentials or a service account from the environment, never the engagement file. Recommended roles: Security Reviewer and Cloud Asset Viewer. Broader grants are reported as a finding; scheck still calls only its declared read list. |
| Data stores? | Judged from the control plane (public IP, authorized networks, SSL requirement, backups), not by connecting to them. |
| Probes? | *probe* with `off`, `confirm` and `all`, only on assets with first-party evidence from inventory, a `host` or `url` root, a `network` root, or a `first_party` confirmation in the engagement file, which the report names as the evidence. |
| A model? | No. New cross-asset links are multi-fact rules. |

### G1 — GCP collector

**Delivers:** a declared list of read API calls over Cloud Asset Inventory and the
services it points at. Rules for: IAM bindings to `allUsers`/`allAuthenticatedUsers`;
primitive roles (Owner, Editor) held by users and service accounts; user-managed
service account keys and their age; firewall rules open to `0.0.0.0/0` on
administrative and database ports; Cloud SQL with a public IP and broad authorized
networks, without SSL, or without automated backups; public buckets and buckets without
versioning or retention; audit log configuration; which project holds the backups, for
the intake question that asks.

**Done when:** tests against a fake API server cover every rule's three outcomes; the
collector makes only calls on its declared list; an opt-in live test (`make live`)
reads a test project.

### G2 — first-party evidence from inventory

**Delivers:** external addresses, load balancers, Cloud Run and App Engine URLs from the
inventory become first-party evidence for assets discovered under domain roots; Cloud
DNS zones suggest domain roots in the Scope stage, confirmed by the operator.

**Done when:** a discovered address present in the inventory becomes first-party with
that evidence named in the report; one absent from it stays observe-only.

### G3 — probes

**Delivers:** the reviewed probe list (`/.git/HEAD`, `/.env`, framework debug routes,
common admin panels), each a single `GET`; the `off`, `confirm` and `all` modes; the
preview of every planned request; the authorization block and a window required for
any probe; the interview's framework question returns, since it now
selects which probes apply; the lab's web tier gains a served `.git` directory and an exposed admin panel,
seeded under the same rule as 0.0.2.

**Done when:** no probe runs without an authorization window, first-party evidence and
the asset's mode allowing it; `confirm` with no terminal reports probes as *not run*;
each probe's request count matches its declaration; a probe on an asset whose only
evidence is the operator's confirmation names that in the report.

### G4 — cross-asset rules and intake

**Delivers:** multi-fact rules across collectors, for example a Cloud SQL instance with a
public IP **and** an authorized network of `0.0.0.0/0` **and** no SSL requirement; a
long-lived service account key **and** a GitHub workflow that deploys to the same
project without workload identity federation; `deploys_to: production` repositories
linked to the project they deploy to; declared admins and `people` against the
project's IAM, with `group:` members expanded through Cloud Identity and
`user:…@gmail.com` bindings a finding class of their own. `scheck init` asks about GCP
and checks the credentials' scopes before the first run.

**Done when:** every rule has its three fixtures, and intake reports missing or
over-broad credentials before any target contact.

### G5 — host depth: credentials and exposure on disk

**Delivers:** catalog checks and rules for what an attacker on a small company's server
or laptop looks for first: mode and ownership of `.env` files under the application
paths a host asset declares (`app_paths`, asked by the interview from this slice, when
it gains its consumer), `~/.ssh`, `~/.aws`, `~/.config/gcloud` and the docker socket; cloud
metadata reachability; a listener-exposure multi-fact rule (listener, host firewall,
and for a cloud host the firewall rule from G1). Each is a catalog entry under the host
collector's rules (`spec/host-collector.md`), with the golden trace change explained.

**Done when:** every new rule has its three fixtures; the integration diff is still the
exact allowlist; the world-readable `.env` seeded on the lab host is found.

### G6 — comparing two engagements

**Delivers:** comparison of two runs of the same engagement file, for remediation
follow-up: fixed, still open, new, and assets that changed. Deterministic, on the JSON
report, keyed by canonical asset ids and finding instance keys
(`spec/engagement.md`, "Identity, references and validation").

**Done when:** a golden comparison of two lab runs is committed and a finding that moved
between assets is reported as such, not as fixed plus new.

### G7 — coverage and the lab

**Delivers:** the cloud configuration, data stores and backups, logging and web
application areas of the coverage table move from *not assessed* to *assessed* or
*partial* with reasons. The lab gains a GCP test project with seeded issues, under the
same sealed-label rule.

### Release gates

The 0.0.2 gates, re-run on the larger lab, plus: every GCP call on the declared list
and nothing else (audit log); no write call possible from the code (a test over the
declared list); credentials never in any output; probes run only after confirmation
and only on assets with named first-party evidence; the coverage table correct for every
area; the comparison of two runs correct against a seeded change list.

---

## 0.0.4 — judgement and depth

With the main risk areas covered, 0.0.4 adds what a consultant brings beyond a
checklist: hypotheses from what the operator said, conclusions across assets, and
deeper testing where it is authorized. Every model feature is measured against the
rules-only path on a freshly seeded lab, with criteria frozen before the run. A feature
that does not beat the baseline does not ship as a default; if none does, 0.0.4 ships
without the model, as 0.0.1 did.

The 0.0.1 evaluation (`docs/eval/phase2-results.md`) is read narrowly here: one
tool-calling loop, two models from one vendor, never called a tool. It does not show
that a model cannot choose among declared checks; it shows that this loop does not. So
J1 and J2 do not re-run that loop. They use single-pass calls with forced structured
output (the model fills a schema; it never decides whether to answer), across at least
two providers, and the measurement names the mechanism it tested.

### J1 — model-driven Plan

**Delivers:** hypotheses drawn from prose context and recon, each naming the declared
checks that would settle it, produced as structured output against a schema that lists
the declared checks. Reuses the provider contract of [spec/model.md](spec/model.md): the
model chooses among declared checks, never writes a command or a request, cannot widen
scope or change a mode.

### J2 — model-driven Analyze

**Delivers:** conclusions across assets that the rules do not encode, as judgement
findings; severity from code; every cited excerpt validated against the observation it
names, as `finding.Store` does today.

### J3 — the scan level

**Delivers:** the *scan* level of `spec/scope.md`, with nuclei restricted to safe
templates as the first wrapped tool (pinned version, declared argument list, JSON
output parsed), and path discovery on first-party sites. `off`, `confirm` and `all`
modes, authorization window required.

### J4 — full scope

**Delivers:** `--full-scope` as `spec/scope.md` defines it: probes and scans on every
first-party, non-excluded asset, with the throttle, timeout and cost limit still in
force.

### J5 — the `auto` gate

**Delivers:** `auto` for probes and scans as `spec/scope.md` defines it, built on the
bounded pattern of [spec/bounded.md](spec/bounded.md): code decides relevance where it
can; Jev answers only an inconclusive fingerprint or whether the operator's prose asks
to avoid an asset; code decides and fails closed. Its value is an unattended run with
scans on, which is why it follows J3 and J4; with `confirm` the operator already sees
every request. Thresholds and questions are frozen before the live evaluation.

### Release gates

Criteria for J1, J2 and J5 are frozen in `docs/eval/` before any live run, in the form
of `docs/eval/phase2-criteria.md`: recall, false positives, prioritization against the
named reviewer, cost and latency, and adversarial pairs for hostile context and target
output. J3 and J4 pass the 0.0.3 scope gates with scans enabled.

---

## Later, not scheduled

- AWS, then Azure and Microsoft 365 collectors, on the GCP and Workspace shape.
- Other SaaS tenants (Slack, the payment provider's dashboard settings where an API
  allows it), and secrets shared in Drive, Slack or Notion.
- A workstation profile for the host collector (disk encryption, screen lock, endpoint
  protection present, admin accounts), for the laptops where small-company breaches
  often start. Several `host:` roots in one engagement already cover a handful; a fleet
  stays out of scope (VISION).
- Dependency vulnerabilities beyond Dependabot alerts: reading lockfiles and advisories.
- Reading docs, compose files and infrastructure code to suggest intake answers.
- SARIF and other machine formats for the engagement report.
- A report audience for handing out: pseudonymized people and topology, for the
  operator's customers. The 0.0.2 report is for the operator only.
- A compliance goal in the interview, once a reviewed table maps findings to controls;
  without one it would have no consumer.
- Local-only model inference.

Outside scheck for good: exploitation, authenticated testing of application logic,
remediation, continuous monitoring (VISION, "Not in scope").
