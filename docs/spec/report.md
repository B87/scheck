# scheck — engagement report specification

The report contract for the engagement in [engagement.md](engagement.md).
Built in 0.0.2 E2, with instance findings in E5a and web assessment in E7.

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
hand and, from E5, a principal that changed ([runs.md](runs.md), "Stop and resume").
GitHub principal changes carry the asset, former identity label and fresh identity
label in `engagement.principal_changes` only when both known stable user identities
differ. Login renames and unknown-to-known transitions produce no change notice; no
token value or credential hash is retained. GitHub collection also names the account
and warns that visibility depends on the credential in the normal header. Resume
wording qualifies retained evidence by whether reuse was allowed; inventory notes
identify reused observations by their original time and say current access was not
validated. GitHub shortfalls refer to those notes instead of claiming nothing was
read. GitHub steps 3–6 group identity, repository-access, CI configuration, secret sharing
and provider-alert judgments into coverage sub-items. Delegated roles, runtime
enforcement and runner access remain visibly unassessed. Supported mirror history
and mirror-origin credential detection have separate Secrets coverage sub-items.
Missing or partial mirrors abstain, with read counts and actionable gaps in asset
notes. Local mirror observations have their own actor and time, separate from the
GitHub principal. History findings retain only detector markers and commit/path/line
locations, never blob snippets or origin URLs. Repository identity
judgments count in Identity and access.
Declaration references are labeled separately from observed evidence.

**GitHub CI summary.** When CI assessments are selected, the summary names how many
rule assessments decided out of how many selected and says runtime execution was
not verified. With zero CI decisions it says no CI configuration rule could decide
and directs the reader to missing reads and next steps. When no security rule
could decide and nothing ranks, the empty ranking says no security verdict was
possible from the collected CI evidence. Successful requests or zero findings
never substitute for decided rules.

CI findings cite recognizable configuration: observed default permissions or
branch-protection evidence, and the workflow's requested permission, mutable
reference or recognized execution chain. Workflow evidence names its exact path
and assessed commit; derived configuration details remain separate from raw API
observations. `github_ci` readout notes preserve configuration and runtime gaps.
Permission shortfalls name the required read permission, such as Contents or
Metadata read, and authorization/resume next steps without recommending a target
write grant. CI-only reports do not fabricate identity evidence or notes.

**GitHub metadata and alerts.** `github_alerts` asset notes distinguish Actions
secret names/visibility from provider Dependabot and secret-scanning reports.
Counts say observed or “at least” when populations are incomplete. Owning-population
gaps retain abstained family judgments beside affirmative findings, keeping that
family's coverage partial. Names and timestamps establish neither leaked values, production use nor rotation. Provider
alerts are not a complete repository scan; deployed dependencies, exploitability
and credential usability were not tested. Denied reads and unsupported locations
remain coverage gaps. Safe provider metadata retains its provenance while secret
values, snippets, comments and arbitrary metadata are omitted before persistence.

Dependency findings use `dependency_alert` subjects containing the alert number
and case-preserving encoded manifest path. Secret findings use `secret_location`:
organization secret names or exact alert/commit/path/start-coordinate instances.
An acceptance names the instance; it does not accept future locations. Dependabot
critical maps to high and receives no automatic production/public adjustment;
the finding title preserves “high or critical” as the provider severity range.
Dependency caveats describe deployed versions, exploitability and alert coverage,
without unrelated secret-scan caveats.
Recognized observed public repository visibility raises a provider-secret finding
from high to critical; `repository_read` cites the direct repository request
separately from alert metadata. Public-on-purpose does not lower either secret rule.

Closed dependency alerts say fixed or dismissed as the provider reports; dismissal
is not proof of a fix. Inactive provider secrets say rotation was not verified.
Non-revocation resolutions do not prove a credential was revoked. A resolved
`wont_fix` alert reported active receives a `github_alert_followup` note before the
summary ranking and again in asset notes. Plain wording says someone chose not to
fix the closed alert but GitHub still reports the credential active; revocation
was not verified and the credential owner needs to follow up. This unranked note
is not a finding and does not affect the exit count. Secret remediation starts
with revocation or rotation at the provider, before removing reported locations; closing an alert or deleting a commit does not revoke it.

Fixed lines:

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
sent ([runs.md](runs.md), "Stop and resume").

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
    Your DNS resolver at 192.168.1.1, and whatever it forwards to, as for any web browsing on this network: names under your domains, the names they point to (including third-party mail and DNS providers), and the services above; 214 lookups, including 2 random test names under your domains and 2 queries for random names under invalid.
    crt.sh, a public certificate log run by Sectigo: asked which certificates exist for example.com and example.net; 2 requests. crt.sh sees this machine's internet address and those names, and may keep logs.
    api.github.com: example-org, using the credential in GITHUB_TOKEN (the variable's name; its value appears nowhere); 96 requests.
  Your own systems:
    websites shown to be yours: 3 sites, 9 requests.
    servers: 1 SSH session.
    One server check may make the server download its package list from its own update servers (pkg.dnf_check_update).
  Names under your domains not shown to be yours:
    www.example.com, blog.example.com and 10 more: 24 requests, what a browser sends when it opens the page (the certificate, and the home page over https and http). These servers may be a provider's or someone else's.
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
credentials, control_lookups, control_invalid, invalid_queries, scoped_resolvers_ignored}], assets:
[{kind, requests | sessions | unreached | jump_hosts | jump_unreached | runs, sites}], unconfirmed: {names,
requests}, host_side_effects: [check ids], model: "none", telemetry: "none",
user_agent, stored, tenants_read, ssh_resolved, ssh_resolved_by_jump,
unrecorded_sessions}` (the last only on a resume that has one): every fact the text
states, so a reader of the JSON gets the same answer.

**Notes for the readout.** Not findings, and not counted: `first_party` entries that
expired or whose target moved, so someone removes them; what each acceptance came to
when it was not applied ("Acceptances" below), acceptances that expire within 30 days
or have no `expires`; a listed admin who is not one, and a listed admin who holds
Owner; a domain under `mail.no_mail` that shows mail use
([web-collector.md](web-collector.md#email)); a declared person or system
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
member could not decide is *not assessed*. For a network collector it is a rule or a
family of rules (rules sharing a finding id, or one rule split by where its target
lies, as `dns.dangling_external` and `dns.dangling_internal` are, count as one)
applied to an asset. For a host it is a finding
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
scheck was given, on the positive list of [scope.md](scope.md#outcomes)), `not_declared` (no root of the kind this area reads was
declared), `excluded_by_operator`, `limit_reached`, `failed`, `sampled`,
`unavailable:<reason_code>` (a collector's own per-read reason, kept verbatim after the
colon) or `no_rule` (read, but no rule in this version judges it), with a detail line.
A row that is not *assessed* always carries its reasons: a *partial* row usually has
several (a permission, an excluded unit, a sample), so a row holds a list, never one
"main" reason. `sampled` makes a row at most *partial*. Only `failed` and
`limit_reached` on a cut collection, and a declared root with no successful read,
change the exit code ([scope.md](scope.md#outcomes)); an `unavailable` read makes coverage *partial* and
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
| the session lost after it worked | `failed`; the checks after the loss are counted under the host's `not_run` (a count of checks, not a coverage reason), never as `unavailable` |

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
| `unavailable:blocked` | a firewall or bot protection in front of the site (`<vendor>`) answered instead of the site, so this page was not judged; to have it checked, let scheck through for the run (it identifies itself as "`<user agent>`"), or run from another network |
| `unavailable:address_not_public` | the name points at a private or reserved address, which scheck does not contact from outside a declared network |
| `unavailable:<other>` | the command or request that reads it did not give a usable answer (`<code>`) |
| `no_rule` | not judged: this version of scheck has no rule for it; the detail says what was read and what was not |

A token is never wrapped across lines; the detail wraps.

**A missing intake answer.** A rule that reads an intake answer the file does not give
says so in the report, in these words (0.0.2 E7; [web-collector.md](web-collector.md)):

| Rules | Read | When the answer is missing |
|---|---|---|
| `email.dmarc_*`, `email.spf_missing`, `email.spf_invalid`, `email.spf_permits_anyone`, `email.no_mail_spoofable` | `mail.senders[].domain`, `mail.no_mail`; for an undeclared domain, the MX and SPF observed ("Intake", Mail) | "You did not say whether *d* sends mail. It shows signs of mail use (MX), so DMARC was judged as for a sending domain." or "…it shows none, so it was judged as a domain that sends no mail." |
| `email.dkim_*` | `mail.senders[].dkim_selectors` | "DKIM for *service* on *d* was not checked: no selector was given, and DNS cannot list them. Find it as `s=` in the DKIM-Signature header of a message *service* sent." |
| `email.spf_undeclared_sender` | `mail.senders` for that domain | "SPF was not compared with your senders: none were listed for *d*." |
| `web.version_disclosed` | `intent.exposed_on_purpose[].url`, exactly | its `why_here`: "No page was declared public on purpose; this is the standard rating." |
| `web.restricted_reachable` | `intent.not_exposed[]` and `--vantage` | with no vantage: "Pages you said are restricted were not checked for reachability: the run's vantage was not given (`--vantage internet`)."; with `vpn` or `lan`: "…you declared this run came from inside your network."; with no `not_exposed` entry, no line |
| headers, cookies, `security.txt`, plain HTTP | `url` roots and entries, `first_party` | "*N* names under *root* were read but not judged for headers: none is declared as your site. Add a `url` entry for the ones you run." |
| ranking | `data.matters_most[].asset` | no line |

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
| External surface | domains, subdomain takeover, exposed services, TLS. The row names what was not checked ([web-collector.md](web-collector.md#not-assessed)), the registrar account among it: who can sign in to it, its 2-step verification, auto-renew and the domain's expiry |
| Web application | headers and cookies at the entry points of declared and first-party sites, with a count of names read but not judged; exposed files and debug routes from 0.0.3. On every run with a domain or url root the row says: `Only whole domain endings (such as .page, .dev, .app) were looked up in browsers' built-in HTTPS-only list; whether your own domain is on it was not checked.` |
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

**The external, email and web rows, in this build.** A domain root the web
collector read feeds these rows; a URL root feeds external, web and secrets coverage.
In the external row each such root has *dangling records*
(`dns.dangling_external` and `dns.dangling_internal`), *subdomain takeover*
(`dns.takeover_candidate` and `dns.unclaimed_at_provider`) and *private addresses*
(`dns.private_address`), each marked from its rules' verdicts on that root and the
names under it (*assessed* when none abstained, *partial* when some decided, *not
assessed* when none did) with each abstention's reason and subject, or
`not_applicable` when its rules had nothing to judge on complete evidence. A wildcard
finding that shares its subject with a discovery gap retains the gap's reason and
leaves coverage partial ([web-collector.md](web-collector.md#dns-and-takeover)).
*Services your names point at* lists names without a verified takeover fingerprint,
with the count not checked and `no_rule`; an unknown-provider wildcard is listed once
as `*.<root>`, even with no certificate-log members, and grouped names are omitted.
*TLS and certificates* is marked from the certificate and negotiation verdicts;
unknown handshake, inspection and takeover reasons remain gaps. A row whose
sub-items are each *assessed* or `not_applicable` is *assessed*. The email row has four
families per root: *DMARC policy* (including no-mail policy), *SPF policy*, *SPF
senders* and *DKIM selectors*. The same verdict-based marks apply. No mail evidence
is `unavailable:mail_evidence`; missing senders, selectors, inherited policy, marked
records and incomplete trees remain explicit reasons, never a pass. Default text
coverage retains the affected domain or service when no DKIM selector was given. `mail_context`
notes print under "Mail context" in text and in `notes` in JSON: declared or inferred
mail use, observed alignment tags and report-destination presence, unclassified SPF
terms, missing declarations and the limits of a DNS-only review. Current receiver
DMARC tree walking and actual message authentication or delivery are not assessed
([web-collector.md](web-collector.md#email)). A declared `domain` asset
read with its root counts as read in both rows; its names are judged under its root's
sub-items, and it has none of its own. A declared URL asset read with its root likewise
counts as read in external, web and secrets coverage, using the root's judged
sub-items rather than `collector_not_built`. A root that was not read gives its own
reason in the rows it feeds.

Network redaction totals use trusted gate hits retained on pages, counted once per
request id even when a front-page read is reused as an entry. Built-in and operator
rule counts never come from marker-shaped text a target supplied.

Web coverage uses header, plain-HTTP, cookie, security-contact and version families;
secrets coverage includes response-secret judgments. Missing web evidence is
`unavailable:web_evidence`, never a pass. Cookie coverage retains the unread login
flow even when the observed cookies have good flags. `web_context` notes describe
technology and CDN fingerprints with their sources, robot counts, block pages and
entry-point limits. Assessment `outcomes` carry subject-specific derived details,
including the preloaded-TLD reason, TLD and list version. Shared-origin reads retain
one finding per `{id, asset, subject}` and one assessment per `{id, asset}`; merged
evidence and read references are united, retaining the strongest observed severity
and status. TLS versions beyond the
observed negotiation, ciphers and revocation, and scripts and pages beyond the entries
remain explicit unassessed sub-items. Findings and acceptances
use the owner and subject rules in [web-collector.md](web-collector.md#subjects).
`attribute:password_form` raises a plaintext HTTP finding one level from an active
password input; its evidence cites the page containing that input, and no form was
submitted. The browser finding under a preloaded TLD is disproved and gets no raise. `web.version_disclosed` moves to info only on an exact URL declared public on
purpose. A Slack webhook has high base severity; other accepted secret detectors
retain critical, regardless of public-on-purpose intent.

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
| `asset_name`, `bound_id` | the `assets` name; for a name found under a domain root and not declared, the name; else the id. The bound id or null |
| `subject` | `{kind, key, label, provider_id?, person?}`. `kind` is declared per finding definition (`account`, `org_unit`, `group`, `deploy_key`, `token`, `principal`, `oauth_app`, `service`, `repository`, `workflow`, `branch`, `webhook`, `invitation`, `secret_location`, `dependency_alert`, `dns_name`, `dns_record`, `url`, `origin`, `mail_domain`, `dkim_selector`, `spf_mechanism`, `declaration`). `key` is short and typable, what `accepted_risks[].subject` takes; `label` is what a human needs to recognise it, built only from fields rules read; `provider_id` survives a rename; `person` is the `people` handle when attributed |
| `id`, `title` | `id` is the join key into `scheck explain` |
| `area` | one of the ten area keys; required on every finding definition |
| `category` | the collector's own grouping |
| `exposure_finding` | required on every finding definition: whether "exposed on purpose" may move it ([engagement.md](engagement.md), "Severity in context") |
| `severity`, `severity_base`, `adjustments[]` | each adjustment `{rule, by, delta, source}`: `rule` from the closed table of [engagement.md](engagement.md), "Severity in context" or the collector's own, `by` `collector` or `engagement`, `source` either `{file, key}` for a declaration or `{observation, excerpt}` for a fact; no non-base severity without its chain |
| `status`, `acceptance` | `acceptance`, present exactly when the status is `accepted`, is `{entry, reason, accepted_by, expires, expired, covers_every_instance}` |
| `rule` | `{kind: single_fact \| multi_fact, reads[]}`: the check, request and declaration ids the rule reads, in the vocabulary of `assessments[]`. `single_fact` is one fact per subject, which includes a host rule that joins a second check of the same host per account (`host-collector.md §6.5`, both checks in `reads`); `multi_fact` combines facts across checks or assets ([engagement.md](engagement.md), "Multi-fact rules") |
| `evidence[]` | at least one observed item. Observed: `{asset, check \| request, observation, collected_at, principal, vantage, excerpt}`; declared: `{source: "engagement.yaml <key path>", excerpt}`. A declaration supports a finding and never makes one alone |
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
and the observation. `Observed` includes the date when the collection span crosses
a day, so retained evidence is not presented as newly collected.

**Subjects.** Host findings carry no subject in 0.0.2: no rules-only host finding names a
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
runs; two secrets in one file stay two findings. A secret in a web page is keyed
`<detector>:<url>`, one per detector per page. The domain, email and web collector's
subjects, and how their keys are written, are in
[web-collector.md](web-collector.md#subjects).
A subject whose key matches
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
  accepts for an asset under a declared root ([engagement.md](engagement.md), "Identity, references and validation");
  `subject` when the finding has one, which validation then requires; a finding
  without a subject kind is accepted by id, with a comment that the entry covers that
  finding on the whole asset.
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
stands and scheck cannot say whether the problem is gone) or `subject_not_found` (no
instance with that subject was read on this run: the rule judged no such subject,
whatever it found elsewhere). Only `not_matched` may say "fixed".
Domain, email and web acceptance ownership and missing-subject outcomes are in
[web-collector.md](web-collector.md#subjects).

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
status, refused before incomplete, each in the order of `roots`. Exit decisions are
owned by [scope.md](scope.md#outcomes):

| Case | Text |
|---|---|
| Unknown host key | `REFUSED: deploy was not contacted: its host key is not in your known_hosts file. Confirm the fingerprint with whoever runs the host, then add it.` |
| Unknown key on the jump host | `REFUSED: deploy was not contacted: the host key of its jump host ops@198.51.100.7:22 is not in your known_hosts file. Confirm the fingerprint with whoever runs the jump host, then add it.` |
| Changed key on the jump host | `REFUSED: deploy was not contacted: the host key of its jump host ops@198.51.100.7:22 changed. A changed key can mean a reinstalled server or an interception; confirm the fingerprint with whoever runs the jump host before you accept it.` |
| Host address excluded | `REFUSED: deploy was not contacted: its name resolves to an address your engagement file excludes. Remove the exclude if the host is in scope, or the host if it is not.` (for a jump host: `its jump host ops@198.51.100.7:22 resolves to an address your engagement file excludes, and scheck never connects to an excluded address.`) |
| Changed host key | `REFUSED: deploy was not contacted: the host key for 203.0.113.5 changed. A changed key can mean a reinstalled server or an interception; confirm the fingerprint with whoever runs the host before you accept it.` |
| No SSH user, unreadable identity or known_hosts, failed authentication | `REFUSED: deploy: scheck could not use the access it was given (authentication failed for deploy@203.0.113.5 with ~/.ssh/deploy). Nothing was read from it.` |
| Canary mismatch | `REFUSED: deploy: scheck stopped before running any check, because the host's login shell changed what it sent back (often a login banner or a profile script that prints text). This does not by itself mean the host is compromised: ask whoever runs it to look at its login scripts. The raw reply is in report.json.` |
| Session lost | `INCOMPLETE: deploy: the connection was lost after 18 of 33 checks; 15 were not run. What was read before is kept and assessed. scheck only reads; an interrupted run leaves nothing half-changed.` |
| Host run timeout | `INCOMPLETE: deploy: the host collector's timeout (10m, assets.deploy.timeout) stopped it after 25 of 33 checks.` |
| `limits.timeout` | `INCOMPLETE: limits.timeout (1h) ended the engagement: <assets> were not read.` |
| `limits.timeout` while a domain root is read | `INCOMPLETE: example.com: limits.timeout ended the engagement while it was read.` |
| Unreachable before contact | `INCOMPLETE: deploy: could not connect from this machine (connection timed out). This does not tell you whether it is up for anyone else. Nothing was read.` |
| Root with no collector | `INCOMPLETE: example-org (GitHub organization): this version of scheck does not read it. Nothing was read from it.` |
| Credential rejected | `REFUSED: example-org (GitHub organization): GitHub did not accept the token in GITHUB_TOKEN (expired, revoked or mistyped). Nothing was read from it.` (or `37 requests were read from it.` when it was rejected mid-run) `Set GITHUB_TOKEN to a current, read-only token.` |
| No credential | `INCOMPLETE: example-org (GitHub organization): neither GITHUB_TOKEN nor GH_TOKEN is set, so nothing was read from it. Set one to a read-only token.` |
| Provider rate limit | `INCOMPLETE: example-org (GitHub organization): scheck stopped after 140 requests to leave a fifth of this token's GitHub rate limit for its other uses; the limit resets at 15:02 (Europe/Madrid). What was read is kept and assessed.` |

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

**JSON consumers.** The engagement report's JSON carries each host asset's collector
envelope (`host-collector.md §6.4`) whole, under that asset, with its own
`schema_version`; `run.assessment`, `assessments` and `facts` keep their shape one
level down. The report on stdout is complete without the run directory, so
`--no-persist` loses nothing, and `--include-evidence` adds captures to the embedded
envelope of each host this session collected ([runs.md](runs.md), "Stop and resume"). The engagement's own findings are authoritative where their severity differs
from the envelope's ("The report", "Findings"). The aliases' deprecation line names the new path of `run.assessment`.


JSON (`docs/engagement-report-schema.json`, `schema_version` `MAJOR.MINOR`, free to
change until 0.0.2 is published) carries what a consumer agent or a comparison of runs
(0.0.3 G6) needs and the text leaves out:

- `run: {started, directory, resumed}`, the scheck version and `rules_version`, so a
  finding that disappears because a rule changed between versions is never read as
  fixed. For network reports, `rules_version` combines the binary version with the
  pinned web, preload, takeover and sender-data versions. `scheck_version` remains
  the binary version, and host-only `rules_version` retains its existing value;
  the engagement source `{path, sha256}`, where for `--host` the hash is of the
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
  declared inputs, and otherwise as *no longer observed, not assessed*. An assessment
  may have an empty `reads` list when no read was collected or a static preload rule
  decided without a request; it never invents a request id. A finding still requires
  nonempty rule inputs and observed evidence;
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

