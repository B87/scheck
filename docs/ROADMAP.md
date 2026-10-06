# scheck — roadmap

What gets built next, and in which release. The direction is [VISION.md](VISION.md);
the contracts are in [spec/](spec/). v0.0.1, the host collector, was published on
2026-09-22 and is specified in [spec/host-collector.md](spec/host-collector.md).

| Release | Theme | In one line |
|---|---|---|
| **0.0.2** | The first engagement | A host, its website and a GitHub organization, through all seven stages, rules only |
| **0.0.3** | Cloud and identity | GCP and Google Workspace, where most small-company risk lives, still rules only |
| **0.0.4** | Judgement and depth | A model in Plan and Analyze, scans, full scope and the `auto` gate, each measured |

The order follows one argument: cover the places a small company actually gets
breached before adding a model to reason about them, and prove every model feature
against the rules-only baseline before it becomes a default (VISION principle 5).

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
- **Evidence for every release gate.** Gates are recorded in
  `docs/eval/acceptance-<version>.md` and published through
  [RELEASING.md](RELEASING.md). Quality is measured on labeled cases seeded by someone
  who did not write the checks, against labels the check authors do not see until the
  run is recorded.
- **One commit per slice**, `make check` green at each. When implementation deviates
  from a spec, the spec changes in the same commit.
- **The host collector does not regress.** Its golden command traces and reports change
  only with an explained reason (`spec/host-collector.md §9`).

---

## 0.0.2 — the first engagement

An operator runs `scheck init`, answers an interview, and gets an engagement file.
`scheck run engagement.yaml` resolves scope, reads the host, the site and the GitHub
organization, runs the probes the operator approves, combines facts with rules, and
writes a report that opens with coverage per risk area and ranks what it found. The
point is to prove the engagement works end to end, including the claim that context
and links between assets change the result, not to cover many checks.

### Decisions

| Question | Decision |
|---|---|
| Third-party tools? | None. TLS, headers, DNS, fingerprinting, the probe list and the GitHub API need only the Go standard library. |
| The host side? | The host collector, unchanged. `scheck local` and `scheck ssh` keep working as in 0.0.1. |
| A non-host asset? | A GitHub organization, read with a read-only token, so the release exercises identity, secrets and CI/CD. |
| A model? | No. Every stage runs on rules, single-fact and multi-fact. |
| Which active levels? | *probe* with `off`, `confirm` and `all`. *scan*, `auto` and full scope are 0.0.4. |
| Reports? | The host report keeps its schema and versioning (`spec/host-collector.md §6.4`). The engagement report is a new document with its own schema, starting at 1.0. The engagement file and report may change freely until 0.0.2 is published. |

### E1 — engagement file and `scheck init`

**Delivers:** the `engagement.yaml` schema (authorization, roots, exclude, defaults,
assets, limits, and the context fields of `spec/host-collector.md §5.2`); validation
before any target contact; `scheck init`, an interview that writes the file;
`scheck run engagement.yaml --stop-after intake`.

**Done when:** unknown keys, malformed roots and an `exclude` that excludes nothing exit
3 with the offending line; a credential-shaped value in the file is a usage error; no
code path in this slice contacts a target.

### E2 — scope stage and the scope gate

**Delivers:** expansion of roots by passive discovery (DNS, certificate transparency);
`exclude`; first-party evidence per asset; the resolved list with `--stop-after scope`;
the scope gate with its audit log, throttle, timeout and authorization window.

**Done when:** gate tests prove a request to an asset outside every root, an excluded
asset, or a probe on an asset without first-party evidence is refused and audited as
refused; a dangling-record fixture is reported and never contacted; a run past its
window stops as incomplete.

### E3 — the host as an engagement asset

**Delivers:** a `host:` root runs the host collector through the runner; its facts and
posture findings join the asset map.

**Done when:** the golden command traces in `internal/baseline` are unchanged and the
0.0.1 reports for `scheck local` and `scheck ssh` are byte-identical.

### E4 — web and email collector (passive and observe)

**Delivers:** TLS and certificate, response headers and cookies, technology
fingerprint, `robots.txt` and `/.well-known/` entries, from known entry points only;
SPF, DKIM and DMARC; subdomain takeover detection from DNS. Single-fact rules for each.

**Done when:** tests against recorded HTTP and DNS fixtures (`httptest`, no network)
fire, disprove and abstain for every rule; the audit log shows no request outside an
asset's entry points.

### E5 — probes

**Delivers:** the reviewed probe list (`/.git/HEAD`, `/.env`, framework debug routes,
common admin panels), each a single `GET`; the `off`, `confirm` and `all` modes; the
preview of every planned request; the authorization block required for any probe.

**Done when:** no probe runs without an authorization window, first-party evidence and
the asset's mode allowing it; `confirm` with no terminal reports probes as *not run*;
each probe's request count matches its declaration.

### E6 — GitHub organization and repository secrets

**Delivers:** a GitHub collector with a read-only token from the environment and a
declared list of read API calls: two-factor requirement, owners and outside
collaborators, default workflow token permissions, branch protection on default
branches. A secret scan of repository history, redacted in every output. A token with
more than read access is itself reported.

**Done when:** tests against a fake GitHub API server cover every rule's three outcomes;
a seeded secret never appears in any output and its marker does; no non-`GET` request
is ever made.

### E7 — Plan, Analyze and multi-fact rules

**Delivers:** a rules-only plan per asset type, narrowed and ordered by structured
context; multi-fact rules that declare exactly which facts they read and abstain when
any is unknown; rules that name follow-up checks, so the loop iterates; termination
when no hypothesis is open or a limit is reached; no check re-run with the same
inputs; intent declared in intake lowers or raises severity with an attributed reason.

**Done when:** every multi-fact rule has firing, disproved and insufficient-evidence
fixtures; the database example in `spec/engagement.md` fires only when listener, host
firewall and exposure facts all agree; a loop fixture terminates.

### E8 — the engagement report

**Delivers:** the coverage table by risk area (`spec/engagement.md`), with reasons;
ranked findings labeled as a ranking of what was assessed; the authorization block;
excluded, out-of-scope, refused and not-run items; text and JSON with
`docs/engagement-report-schema.json`; golden files under the same rules as the host
report's.

**Done when:** golden text and JSON reports are committed, the JSON validates against
the schema as committed, and target-derived text is control-character escaped.

### E9 — the lab

**Delivers:** a docker-compose lab (one Linux host over SSH, nginx in front of a Next.js
app, postgres on the same host), a GitHub test organization the team owns, a seeded
issue list kept blind from the check authors, two context cases and a clean variant.

| Example seeded issue | Found through |
|---|---|
| A secret committed in a repository's history | repository scan (E6) |
| Organization does not require two-factor authentication | GitHub API (E6) |
| A workflow token with write access to every repository | GitHub API (E6) |
| `.git` directory served by nginx | probe (E5) |
| World-readable `.env` with credentials on the host | host file permissions (E3) |
| postgres bound to all interfaces with no host firewall rule in front | multi-fact rule (E7) |
| Next.js running in development mode | fingerprint and host process list (E4, E3) |
| Missing `Strict-Transport-Security` header | response headers (E4); low, must rank below every item above |

Context cases: a version-revealing `/status` page declared public on purpose must not be
reported above *info*; `/admin` declared VPN-only but reachable from the assessment's
source address must be reported as a contradiction of the declared intent.

### Release gates

1. `scheck init` produces an engagement file for the lab, including an authorization
   block, and `scheck run` takes it through all seven stages.
2. **Recall:** the run is recorded against the blind labels; every miss is recorded as
   a miss before any check is added to fix it.
3. **False positives:** the clean variant's findings are counted against a target fixed
   before the run.
4. **Context:** both context cases behave as stated, beside a run without context.
5. **Prioritization:** at least four of the top five findings match an independent
   consultant's top five, and no low finding outranks a high one.
6. **Coverage:** every risk area is marked correctly; cloud configuration, for example,
   is *not assessed* with the reason.
7. **Scope:** only allowed levels reach each asset, probes run only after confirmation,
   the authorization block is printed, and the audit log shows every request and API
   call. The lab host's integration diff stays the exact allowlist of
   `spec/host-collector.md §1`.
8. Each stage's output can be inspected with `--stop-after` and resumed from.
9. `make check` is green, and the host collector's reports and command traces are
   unchanged.

**Sequence:** E1 → E2 → {E3, E4, E6} → E5 → E7 → E8 → E9.

---

## 0.0.3 — cloud and identity

The consultant's review of the 0.0.2 design found that most small-company breaches
start in identity, leaked secrets and cloud configuration, not on a server. 0.0.3 adds
the two collectors that reach those for a company on Google: **GCP** and **Google
Workspace**. Still rules only.

### Decisions

| Question | Decision |
|---|---|
| Which cloud first? | GCP, with a project or organization root (`cloud: gcp:<project>` or `gcp:organizations/<id>`). AWS, Azure and Microsoft 365 follow the same collector shape later. |
| Credentials? | Application Default Credentials or a service account from the environment, never the engagement file. Recommended roles: Security Reviewer and Cloud Asset Viewer; Workspace through read-only Admin SDK scopes. Broader grants are reported as a finding; scheck still calls only its declared read list. |
| Data stores? | Judged from the control plane (public IP, authorized networks, SSL requirement, backups), not by connecting to them. |
| A model? | No. New cross-asset links are multi-fact rules. |

### G1 — GCP collector

**Delivers:** a declared list of read API calls over Cloud Asset Inventory and the
services it points at. Rules for: IAM bindings to `allUsers`/`allAuthenticatedUsers`;
primitive roles (Owner, Editor) held by users and service accounts; user-managed
service account keys and their age; firewall rules open to `0.0.0.0/0` on
administrative and database ports; Cloud SQL with a public IP and broad authorized
networks, without SSL, or without automated backups; public buckets and buckets without
versioning or retention; audit log configuration.

**Done when:** tests against a fake API server cover every rule's three outcomes; the
collector makes only calls on its declared list; an opt-in live test (`make live`)
reads a test project.

### G2 — first-party evidence from inventory

**Delivers:** external addresses, load balancers, Cloud Run and App Engine URLs from the
inventory become first-party evidence for assets discovered under domain roots; Cloud
DNS zones suggest domain roots in the Scope stage, confirmed by the operator.

**Done when:** a discovered address present in the inventory becomes first-party with
that evidence named in the report; one absent from it stays observe-only.

### G3 — Google Workspace collector

**Delivers:** read-only Admin SDK calls. Rules for: 2-step verification enforcement and
enrolment; super admin count; suspended, stale and never-logged-in accounts; third-party
OAuth apps with broad scopes; external mail forwarding where the API exposes it. The
exact list is frozen at the start of the slice against what the read scopes return.

**Done when:** as G1, against a fake Admin SDK server and an opt-in live test tenant.

### G4 — cross-asset rules and intake

**Delivers:** multi-fact rules across collectors, for example a Cloud SQL instance with a
public IP **and** an authorized network of `0.0.0.0/0` **and** no SSL requirement; a
long-lived service account key **and** a GitHub workflow that deploys to the same
project without workload identity federation. `scheck init` asks about GCP and
Workspace and checks the credentials' scopes before the first run.

**Done when:** every rule has its three fixtures, and intake reports missing or
over-broad credentials before any target contact.

### G5 — coverage and the lab

**Delivers:** the identity, cloud configuration, data stores and backups, and logging
areas of the coverage table move from *not assessed* to *assessed* or *partial* with
reasons. The lab gains a GCP test project and a Workspace test tenant with seeded
issues, under the same blind-seeding rule.

### Release gates

The 0.0.2 gates, re-run on the larger lab, plus: every GCP and Workspace call on the
declared list and nothing else (audit log); no write call possible from the code (a
test over the declared list); credentials never in any output; the coverage table
correct for every area.

---

## 0.0.4 — judgement and depth

With the main risk areas covered, 0.0.4 adds what a consultant brings beyond a
checklist: hypotheses from what the operator said, conclusions across assets, and
deeper testing where it is authorized. Every model feature is measured against the
rules-only path on a freshly seeded lab, with criteria frozen before the run. A feature
that does not beat the baseline does not ship as a default; if none does, 0.0.4 ships
without the model, as 0.0.1 did.

### J1 — model-driven Plan

**Delivers:** hypotheses drawn from prose context and recon, each naming the declared
checks that would settle it. Reuses the provider contract and tool discipline of
[spec/model.md](spec/model.md): the model chooses among declared checks, never writes a
command or a request, cannot widen scope or change a mode.

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
to avoid an asset; code decides and fails closed. Thresholds and questions are frozen
before the live evaluation.

### J6 — comparing two engagements

**Delivers:** comparison of two runs of the same engagement file, for remediation
follow-up: fixed, still open, new, and assets that changed.

### Release gates

Criteria for J1, J2 and J5 are frozen in `docs/eval/` before any live run, in the form
of `docs/eval/phase2-criteria.md`: recall, false positives, prioritization against an
independent consultant, cost and latency, and adversarial pairs for hostile context and
target output. J3 and J4 pass the 0.0.2 scope gates with scans enabled.

---

## Later, not scheduled

- AWS, Azure and Microsoft 365 collectors, on the GCP and Workspace shape.
- Other SaaS tenants (Slack, the payment provider's dashboard settings where an API
  allows it).
- Reading docs, compose files and infrastructure code to suggest intake answers.
- SARIF and other machine formats for the engagement report.
- Local-only model inference.

Outside scheck for good: exploitation, authenticated testing of application logic,
remediation, continuous monitoring (VISION, "Not in scope").
