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
| **1. Intake** | Ask what a consultant would ask (below), including who authorized the assessment. | Engagement file |
| **2. Scope** | Expand the declared roots into assets with passive discovery and cloud inventory, drop what is excluded, record which assets have evidence of being first-party, and apply defaults. The operator sees the resolved list before anything beyond passive runs. | Scope |
| **3. Recon** | Low-impact discovery per asset: cloud and SaaS configuration, host facts, DNS, TLS, response headers, technology fingerprint. Fills gaps in the context and flags where it is wrong. Anything outside the roots is recorded, not contacted. | Asset map |
| **4. Plan** | Combine context and recon into prioritized hypotheses, each with the checks that would settle it. | Plan |
| **5. Check** | Run the planned checks through collectors that enforce scope. | Evidence |
| **6. Analyze** | Mark each hypothesis confirmed, ruled out or unknown, and open new ones from what was found. New hypotheses go back to Plan. | Findings and follow-ups |
| **7. Report** | Coverage per risk area, then findings for the people who will fix them: what, why it matters here, evidence, remediation. | Report |

The Plan → Check → Analyze loop ends when no hypothesis is open, the run's timeout
passes, its model cost limit is reached, or the authorization window closes
([scope.md](scope.md#throttle-timeout-and-cost)). A limit stop is reported as
incomplete, never as a clean result.

An example hypothesis from Plan: *"postgres runs on the web host and is bound to all
interfaces. It is exposed only if the host firewall and the cloud security group both
let outside traffic reach it: read both. Separately, check whether the database
password is readable on disk and whether the app runs in development mode."* A bind
address alone is not exposure, and is reported as such.

## Intake: the engagement file

The engagement file (`engagement.yaml`) is the source of truth for a run. It is
reproducible, diffable and reviewable, and it is what a run resumes from.

```
$ scheck init                 # interviews the operator, writes engagement.yaml
$ scheck run engagement.yaml  # scope → recon → plan → check → analyze → report
```

`scheck init` asks the questions; editing the file by hand is equally valid. The
interview covers what a consultant draws out, not only the architecture:

| Topic | Example questions |
|---|---|
| Authorization | Who authorized this assessment? For which window? From which source address? |
| What you run | What is the product? Public URLs? Where is it hosted? Framework? |
| Accounts | Which cloud accounts and SaaS tools (identity provider, code hosting, payments, email)? |
| Data | What data matters most, and where does it live? Where are the backups, and in which account? |
| Access | Who has production access? How is someone offboarded? Is MFA enforced, and where? |
| Intent | What is exposed on purpose? What is accepted as a known risk, until when? |
| Drivers | Is there a compliance goal (SOC 2, ISO 27001, a customer questionnaire)? |

Later, scheck may read existing docs, compose files or infrastructure code to
*suggest* additions. A suggestion enters the file only when the operator confirms it;
nothing inferred joins scope on its own.

The structured context schema in `host-collector.md §5.2` (role, exposure, expected services,
accepted risks) is the starting point for this file's per-asset fields.

## The report's coverage

The report opens with a coverage table, before any finding, so a short list of
findings cannot be read as a clean result:

| Risk area | Typical evidence |
|---|---|
| Identity and access | SSO and MFA enforcement, admin count, stale and external accounts, OAuth grants |
| Secrets | secrets in repositories and their history, CI variables, readable files on hosts |
| Cloud configuration | public storage and snapshots, broad permissions, root account protection, network rules |
| Data stores and backups | public access to databases, backup existence, backups in a separate account |
| CI/CD and supply chain | branch protection, pipeline token permissions, deploy keys |
| External surface | domains, subdomain takeover, exposed services, TLS |
| Web application | headers, exposed files and debug routes, framework mode |
| Hosts | the host collector's catalog (`host-collector.md`) |
| Email and domain | SPF, DKIM, DMARC |
| Logging and incident readiness | audit logging enabled, alerting on administrative changes |

Each area is marked *assessed*, *partial* or *not assessed*, with the reason
(no credentials given, collector not built yet, excluded, limit reached). The ranking
of findings is labeled as a ranking of what was assessed.

## Rules and the model

Every stage works without a model. The model is an upgrade, and it has to earn its
place by measurement.

| Stage | Rules alone | With a model |
|---|---|---|
| Intake | Fixed interview questions | Follow-up questions based on earlier answers; suggestions from docs |
| Plan | A checklist per asset type, narrowed and ordered by the structured fields | Hypotheses drawn from prose context and from recon |
| Check | Probes and scans run per the asset's modes: `off`, `confirm` or `all` | `auto`: an experimental gate on probes and scans ([scope.md](scope.md)) |
| Analyze | Deterministic rules, single-fact and multi-fact; each rule can name the follow-up checks that would settle it | Conclusions across assets the rules do not encode; choosing follow-ups |
| Report | Templated text per finding | Explanations written for the operator's setup |

**Multi-fact rules.** A rule may combine facts from several checks or assets: "bound
to all interfaces" **and** "host firewall allows the port" **and** "security group
open to the internet" is a finding; the bind alone is not. This lifts the single-fact
limit of the host collector's posture rules (`host-collector.md §6.5`) for the engagement; each
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
