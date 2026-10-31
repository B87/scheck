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
| 6 | People who left: one block per person with a declared `left` | when any `left` is declared |
| 7 | Not checked, grouped by what would close the gap | when anything was not checked |
| 8 | Excluded, narrowed and not run | always; probes and scans are one line in 0.0.2 |
| 9 | What left this machine | always |
| 10 | Notes for the readout | when any note exists |
| 11 | Close: the exit code and why, for automation; where the files are | always |

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
and warns that visibility depends on the credential in the normal header.
Assessment-credential notes also precede the summary: `github_credential_warning`
names recognized beyond-read OAuth grants; `github_credential` describes exact
supported read scopes or unknown write capability. These are unranked run notes,
not findings, and affect no severity, acceptance, coverage or exit count. Effective
permissions remain untested; missing grant evidence is never called read-only
([github-collector.md](github-collector.md#principal-and-resume)). Resume
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
  hold; scheck requires a record for probes, scans and signing in as staff mailboxes.`
  Holding access is not authorization, and the line must not teach that it is. Present:
  `by`, `date`, each window, `source` and `note`, and the levels used (`levels used:
  passive, observe. probe off, scan off.`). The block is the operator's declaration,
  never presented as verified ([scope.md](scope.md#authorization)).
- Mailbox authorization, per Workspace asset, in the header after the authorization
  block. Entry used and at least one mailbox signed in as: `Mailbox settings: approved by "<by>" on <date>, until <expires>
  (<zone>), for <asset>. scheck signed in as <N> mailboxes to read forwarding settings
  and filters only (`1 mailbox` when N is 1). This is your declaration; scheck did not verify it.`
  Entry used and none signed in as (the profile selected mail, the entry is current, N is 0): the same sentence through `for <asset>`, then
  `No mailbox was signed in as.` Entry unused, when the profile is known and did not select mail:
  `Mailbox settings: approved by "<by>" on <date>, until <expires>; not used: the Workspace profile did not select mail
  forwarding.` Entry ended, and none signed in as: `Mailbox settings: the approval by "<by>" ended on <expires>, for <asset>. No mailbox was signed in as.`
  Entry not yet current: `Mailbox settings: the approval by "<by>" starts on <date>, for <asset>. No mailbox was signed in as.`
  Entry current and the Workspace profile was not observed (binding did not finish): `Mailbox settings: approved by "<by>" on <date>, until <expires> (<zone>), for <asset>. Workspace was not read, so scheck did not sign in as mailboxes.` That line is not the ended line.
  Each of those lines ends with `This is your declaration; scheck did not verify it.`
  No mailbox entry at all: no mailbox line is printed (the authorization-absent line
  covers a block that does not exist). An entry that exists is never printed as
  `none recorded`. `by` is the operator's free text; it is never verified. Whether the
  entry is current, ended or not yet current is taken from the clock when the report
  is built, in `engagement.timezone`.
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
decide. No area is fully checked in this version; each area row under Coverage lists what
this version does not judge. Checked in part: hosts. On deploy, 4 of 13 host areas were judged, each only on
the settings named under Coverage; 6 have no rule in this version and 3 had no usable
evidence. Not checked: identity and access, secrets, cloud configuration, … Anything not
checked is unknown, not fine.
```

Risk areas are named, never given as a fraction, which reads as a score; a host's areas
are counted, because "Hosts: checked in part" hides that most of a host was never
judged (the summary line reads `Hosts (deploy, 4 of 13 areas judged)`). Areas declared
under `not_used` are named as not applicable. On a `--host` run the not-checked list is
`Nothing but this host was looked at.` With no selected rules, the empty ranking
says `No security rules ran; this report contains inventory only.` With selected
rules but no decided verdict, it says `No security verdict was possible from the
collected evidence.` Otherwise, with nothing open at medium or above the lead is
`Nothing open ranks at medium or above among what was checked.`, never "no findings",
"all clear" or "nothing to fix". A differing-mirror-ref follow-up gives the authorized
mirror update and resume action before the ranking. History credential remediation
asks the operator to identify the credential owner, without claiming authenticity
or usability was tested; origin cleanup is assigned to the mirror maintainer after
revocation or rotation. The summary has no
score, grade, percentage or compliance claim.

**Data that matters most** (E9 step 9). When `data.matters_most` has entries, the
summary carries a readout block, one line per entry, in file order:

Let M be the rules this answer raises on the asset (`finding.Def.MattersMostRaises`:
the `HostAccess` definitions and the secrets area on a host, the identity, secrets, data
and external areas elsewhere), D those of them that decided and U = M - D the rest. A check decided when
it fired (`matched`) or was disproved over everything it had to read (`not_matched`
and complete); a disproval over part of a read is undecided, with its own reason (a
budget cut's `sampled`), or `unavailable:incomplete_read` when it has none. A rule that cannot apply on the asset
(`not_applicable`, another platform's) is not one of the M. The outcomes:

On a host, the credential-on-disk rules (`creds.env_file_exposed`,
`creds.ssh_key_exposed`, `creds.cloud_credentials_exposed`) and `docker.socket_exposed`
are among the M (0.0.3 G5). They read a depth-capped sample, and a listing that shows no
file is undecided (`unavailable:no_file_listed`), so on a clean host with no application
folder declared four of the nine host checks are undecided (the `.env` rule reads
`unavailable:no_app_paths`; a `.env` under a home is `unavailable:home_ancestors_not_read`):
a host's readout is `partial` rather than `read` until a later change lets a sample
decide. The line says so; it never reads `read` over a check that did not decide.

- `raised`: "*asset* (*what*): N findings on it that this answer raises." N counts
  every open or accepted finding on the asset that this answer raises, those already at
  the top included, not only the ones it moved ("1 finding"). When U > 0 the line adds
  "; U of the M checks this answer raises could not decide (*reason*)."
- `read` (D = M > 0, nothing raised): "*asset* (*what*): read; every check this answer
  raises decided, and none found anything it raises."
- `partial` (0 < D < M): "*asset* (*what*): read; U of the M checks this answer raises
  could not decide (*reason*); the other D found nothing it raises."
- `not_judged` (read, D = 0): "*asset* (*what*): read, but none of the M checks this
  answer raises could decide (*reason*); nothing on it was raised." With M = 1: "the one
  check this answer raises could not decide". With M = 0: "*asset* (*what*): read, but
  this version of scheck has no check this answer raises for it; nothing on it was
  raised."
- `not_read`: "*asset* (*what*): not read in this run (*reason*); nothing on it was
  checked or raised." For a cloud root in 0.0.2 the reason is "this version of scheck
  does not read cloud projects".

The reason is the not-assessed reason covering most of the undecided checks (ties in
assessment order), worded as coverage words it; with more than one reason the line
adds ", and other reasons; see Not checked". Only `read` means every check this answer
raises decided.

The JSON is `summary.matters_most[]`, always present (an empty array when the file has
no entry), each item `{key, asset, name, what, outcome, raised, checks, undecided,
reasons}`: `key` is `data.matters_most[i]`, `asset` the canonical asset id, `name` its
name, `outcome` one of `raised`, `read`, `partial`, `not_judged` or `not_read`, `raised`
the count, `checks` M, `undecided` U, and `reasons` an array of reason tokens, always
present: the undecided checks' reasons, most common first, or for `not_read` the asset's
reason or status (`failed`, `collector_not_built`).

**Not checked, and what would close the gap.** Grouped by the action that closes it,
as the host report groups by remedy (`host-collector.md §6.6`): re-run with elevation;
for missing access, the permission needed, read-only where the provider offers it, and
where to look by hand for the one setting it hides ("GitHub > Settings >
Authentication security"), never "give scheck an owner's token" as the default; or
"this version of scheck does not read it; assess it by other means until it does". No
manual checklist is printed for a root without a collector: it would be a second,
unreviewed catalog. Items on an asset named in `data.matters_most` are listed first.

**Excluded, narrowed and not run.** Every `exclude` entry and whether it matched
anything: an entry discovery covers prints how many discovered names it dropped, and
any other "not matched: nothing in this version discovers what it covers"; every
narrowing entry, as "narrowed in the engagement file", and what it removed; redaction
counts, built-in rules by rule and `redact_extra` as rules and matches, never a
pattern; for `deny_paths`, the reads each entry denied, each counted once under the
longest entry its requested path falls under, and any none accounts for (a symlink
into a denied prefix) under `deny_paths` as a whole. A walk the runner refused because a denied entry lies inside its root
(`path.deny_inside`) is counted the same way, under `deny_paths` as a whole, with no per-entry attribution; probes and scans (in 0.0.2: `none exist in this version; nothing beyond
reading was attempted.`, and from 0.0.3 the probes that would have applied, as *not
run*); acceptances not applied, with why.

**What left this machine.** One fixed block, defined with the gate (0.0.2 E4). A
client's data protection officer asks this question, and so does the CTO, often to
answer a customer's questionnaire, so it is written in plain words. Four groups, always
in this order, and a group with nothing in it prints `none`:

- *Third-party services* ([scope.md](scope.md#third-party-sources)): each source, who
  runs it when it is a public service, what it was sent, and the request count. A
  source has a separate row per literal host: Google token exchange and Directory
  requests keep their own hosts and counts. The
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

A source names the credential selection, such as its environment variable or the
local ADC file label, never its value or file contents. A
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
unattributed members; the service and break-glass accounts, listed ("People"); context notes, where a declaration and the evidence disagree ("Findings").

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
| `not_applicable` | not applicable | the operator declared under `not_used` that the area does not apply (`not_used: [hosts, cloud]`); printed as their declaration. Never when a finding, open or accepted, fired in the area (below) |
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

A host's coverage gains two domains in 0.0.3 G5, "Credentials on disk" (`creds.home_files`
and the `.env` slots) and "Container engine" (`docker.sockets`, Linux). A `.env` slot
past the folders the file declares is not planned. When a declared slot answered, the
others are excused like a family's other members; when none was declared, each reads
*not assessed* with `unavailable:no_app_paths`. A declared slot a timeout or a lost
connection skipped reads `limit_reached` or `failed`. A listing that shows no file never
disproves, on any platform: it reads `unavailable:no_file_listed`. When `deny_paths`
touches the home trees `creds.home_files` reads as excluded by `disable_checks`
(`host-collector.md §3`). Every read is depth-capped (`host-collector.md §6.5`).

**A mark counts its population.** Each row and sub-item carries `population: {kind,
in_scope, read}`: the assets (or repositories, users, entry points) of the kind it
reads that are in scope, and how many were read. A row is *assessed* only when every
in-scope one was; CI/CD read on two repositories of an organization with 120 in scope
is *partial*, with "2 of 120 repositories". A cap carries its `selection` ("the 40
most recently pushed"), since a sample nobody can name cannot be compared between
runs.

**A selection names what chose it** (GitHub built in E9 step 6a, Workspace in 6b;
contract when E9 lands; [engagement.md](engagement.md), "Plan selection and follow-ups").
In text:
`40 of 120 repositories: deploys_to production (3, assets.*.deploys_to), declared secret
store (1, secrets.production), public (2, observed), then most recently pushed (34)`.
With no declaration naming any item: `no declaration named any repository; most recently
pushed.`, printed only when no repository is in the declared tiers (1, 2, 4, 5 and 6);
the observed-public count still prints before it. Below the budget: `all N repositories
read; the request budget cut nothing.` A GitHub repository population prints the line on
every run, a Workspace population only when a cap, the timeout or the rate limit cut it,
and a repository-root engagement, which has no budget, none: its population reads `1 of
1`. In JSON every population Plan ordered carries `selection: {tiers: [{basis, source,
count}], fallback: "pushed_at desc", read, in_scope}`, with `kind`, `unit`, `spent` and `budget` added
for a budgeted GitHub population, which the text words "; sent N of a 4,000 budget." at the
end of its line. `selection.in_scope_at_least` is set when the organization repository list was not
complete; the text then reads "N of at least M repositories: ..." or "all N repositories
listed read; the list was not complete, so more may be in scope". A row whose kinds
reached different populations prints one line per
selection, "Repositories read for <kind>: ...", `kind` being `access`, `ci`, `secret_alerts`,
`dependabot_alerts` or `secret_locations`.

A Workspace selection has `unit` `users`, `kind` `oauth_grants` or `mail_forwarding` and
the fallback "active, last sign-in desc, primaryEmail" ("active, primaryEmail" for
forwarding). Tiers print in tier order. Its sentence reads "no declaration named any user;
<fallback words> (N)" and "then <fallback words> (N)" (users "the rest, active and most
recently signed in first", forwarding "the rest, active first"), "no declaration named any
user" alone when nothing was read in the fallback, and, with no budget, "all N users read"; the line is "Users: ..." or "Users read for third-party app
grants: ...". It exists only when a cap, the timeout, the rate limit or the Workspace
session's token expiring (`limit_reached`, exit 2; detail "The Workspace session's token
expired before every Workspace read was made; resume to read the rest.") cut the
population, and the sub-item carrying it is at most *partial*. Recon's per-user assignment
cap carries no selection.

A request-budget cut is `sampled` and does not change the exit code. Its reason sits on
the row or sub-item whose kind was cut, the population counts the repositories that got
that kind, and the detail names "the 4,000-request budget for <org>". A cut by
`limits.timeout` or GitHub's rate limit stays `limit_reached`, exit 2, and its population
carries the selection too.

A reason is one of `no_credentials`, `insufficient_permission:<scope>`,
`not_on_plan:<feature>`, `collector_not_built`, `refused` (an asset refused the access
scheck was given, on the positive list of [scope.md](scope.md#outcomes)), `not_declared` (no root of the kind this area reads was
declared), `excluded_by_operator`, `limit_reached`, `failed`, `sampled`,
`unavailable:<reason_code>` (a collector's own per-read reason, kept verbatim after the
colon) or `no_rule` (read, but no rule in this version judges it), with a detail line.
A `no_rule` reason on an assessed sub-item states the limits of what was checked, not
that the sub-item was unassessed.
A row that is not *assessed* always carries its reasons or a non-empty `not_judged` (the
fixed list below). A JSON row that is *partial* with only `no_rule` reasons, or none, is
partial only by this version's limits, not by anything the run left open. A *partial* row
usually has several (a permission, an excluded unit, a sample), so a row holds a list, never one
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
| `path_unresolved` (a walk whose root `fs.realpath` could not resolve) | `unavailable:path_unresolved` |
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
| `not_on_plan:<feature>` | your plan with the provider does not include `<feature>`; for a host or Workspace profile (`not_on_plan:profile=<p>`), not in the checks you chose (profile `<p>`) |
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
| `unavailable:oauth_unclassified` | some apps hold scopes this version of scheck does not classify, and none it classifies as broad |
| `unavailable:workspace_evidence` | the Workspace evidence it needs was missing or not recognized |
| `unavailable:needs_service_account` | it needs a service account with domain-wide delegation, and the credential used holds one person's sign-in |
| `unavailable:credential_exchange` | Google did not issue the token this read needs |
| `unavailable:mailbox_credential` | Google did not sign scheck in as some mailboxes |
| `unavailable:mailbox_unavailable` | Google did not serve some mailboxes' settings |
| `unavailable:api_disabled` | Google has not enabled the API this read needs in the credential's project |
| `unavailable:mailbox_inactive` | the account list did not report the account active with a mailbox |
| `unavailable:mailbox_authorization_missing` | the engagement file records no approval for signing in as mailboxes for this asset; to check forwarding, have whoever approves access to staff mailboxes approve it, add `authorization.mailboxes`, and run again |
| `unavailable:mailbox_authorization_expired` | the approval to sign in as mailboxes has ended or has not yet started; renew the approval and update `expires`, or wait until `date`, and run again |
| `unavailable:forwarding_subdomain` | forwarding to a subdomain that is not itself a domain of this Workspace was not judged |
| `unavailable:no_declaration` | no service on this host is declared for localhost, lan or vpn (`expected_services`); scheck judges a service's reach only against what you declared |
| `unavailable:audience` | a service's audience is localhost, lan, vpn or internet |
| `unavailable:audience_network` | on a host not declared internet-facing, scheck cannot tell which networks its addresses face |
| `unavailable:bind_network` | the service is bound to a private address; on a cloud VM a public address can forward to it, and scheck did not read the cloud firewall |
| `unavailable:no_app_paths` | no application folder was declared for this host (`app_paths`), so `.env` files were not looked for |
| `unavailable:listing_not_trusted` | on macOS any local user can forge a line of the listing, so it can show a file is exposed but never that it is not |
| `unavailable:no_file_listed` | no file by these names was listed; a read that stops 4 folders deep, and does not follow links or enter other filesystems, cannot tell none from not looked at |
| `unavailable:home_ancestors_not_read` | the `.env` file sits in a home directory, and the folders above a declared folder are not read, so a private home cannot be told from an open one |
| `unavailable:symlink_not_followed` | the only match was a symbolic link, and scheck does not follow links |
| `unavailable:packages` | neither the dpkg nor the rpm package database could be read |
| `unavailable:backport_unknown` | the package comes from a distribution whose fixed package is not in scheck's table, so its version cannot be judged |
| `unavailable:source_unrecognized` | the package came from a source scheck does not recognize |
| `unavailable:unnumbered_backport` | the fix for this PHP line was published without a new version number, so the version cannot say whether it is in |
| `unavailable:brotli_unread` | the Brotli library this Node.js links was not found |
| `unavailable:distro_node_unfixed` | the distribution has published no fix for the other flaws of the Node.js release |
| `unavailable:os_release` | the operating system was not identified, so the package's source is not known |
| `unavailable:line_unsupported` | the Node.js project publishes no fix for this line |
| `unavailable:distro_package` | a distribution package: its fixes come from the distribution |
| `unavailable:php_without_package` | PHP is running here, but no package of it was found, so its version was not read |
| `unavailable:packages_partial` | the package read was cut short or held a half-installed package, so it cannot show a package absent or fixed |
| `unavailable:php_cli` | an rpm `php-cli` may serve requests through its CGI program, which was not read, so it is not judged against the fix |
| `unavailable:distribution` | this distribution (or this release of it) was not identified or names PHP and Node.js packages otherwise, so finding none proves nothing |
| `unavailable:eol_within_collection` | the release line's support ended while the host was being read |
| `unavailable:collection_time` | the time the packages were read was not recorded, and the judgment depends on a date |
| `unavailable:runtime_installs` | PHP and Node.js installed some way the package databases do not show are not read (the JSON `detail` names them: containers, Homebrew, source builds, version managers, control panels) |
| `unavailable:<other>` | the command or request that reads it did not give a usable answer (`<code>`) |
| `leaving_date_not_passed` | the declared leaving date had not passed when it was read |
| `left_date_within_collection` | the declared leaving date falls within or after collection; run again after that date |
| `no_declared_github_login` | no GitHub login is declared for this person |
| `no_rule` | not judged: this version of scheck has no rule for it; the detail says what was read and what was not. On a risk-area row the limits print inside "Also not judged on the assets read" (below), not as this phrase; it remains on host domain sub-rows |

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
row in text only when it differs from the header's) and, per asset, the oldest
collection time of any successful observation the report rests on (built, E9 step 8; a
successful observation is decided per request, not per audit line: a ledger answer
(`reused`) counts; for a request that was sent, only its result decides, a response of
200 to 499 other than 401, 403, 407 and 429 that the gate did not end as unavailable (a
200 cut for its size or not recognized does not count); the DNS lookup of a request's
host shares its id and is no reading of it; for a DNS read, its answer counts (NXDOMAIN
counts; a timeout, SERVFAIL or refusal does not); a send line alone, a request the
gate refused at any step (one stopped after the lookup of its host included), a failed
read, a Workspace token exchange and the local mirror's line never date an asset; a
resume keeps nothing older than 7 days, [runs.md](runs.md), "Stop and resume"). The JSON
`assets[].oldest_collected_at` is a UTC date-time or null, never omitted: a host's
envelope collection start; for a network asset, the earliest successful read (sent or
reused) in its final trace, after the partition to repositories, a reused one at its
original time; a `domain` or `url` asset also Scope's `collected_at`; null when nothing
was read. `run.session_started` (required) is when this session started. The text prints
it only on a resumed run, in the `Resumed` field of the header: "Readings older than 7
days were read again, never kept." and the line "Oldest reading kept, per asset:
*name* *date time* (*N* days before this session, or "under a day"); …", listing only
assets whose oldest reading is before this session's start, with whole days floored and
the date in `engagement.timezone`; caps and sampling, with the
selection; narrowing that removed something; and declared facts scheck did not verify
("backups declared in gcp:example-backups, not verified"), the line most often misread
as verified. An excluded organizational unit is named and makes the row at most
*partial* ([scope.md](scope.md)). Per-sub-item marks print in text only when they are
not *assessed*; JSON carries them all, and every `not_applicable` assessment.

The coverage table's area keys are `identity`, `secrets`, `cloud`, `data`, `cicd`,
`external`, `web`, `hosts`, `email` and `logging`, in the order of the table below.
`not_used` may name `hosts`, `cloud`, `data`, `cicd`, `email`, `web` and `external`
only when no declared root covers that area. A repository asset covers `cicd`,
and a host asset covers `hosts`. `identity`, `secrets` and `logging` cannot be marked not
applicable. There is no `payments` area
([engagement.md](engagement.md), "Validation").

**A declaration never hides a finding** (built, E9 steps 5a and 5b). A `not_used` area with a
finding in it, open or accepted, is not *not applicable*: its row is built as if
`not_used` were absent, and the `context_not_used` note ([engagement.md](engagement.md),
"Context notes", C3; step 5b) is attached to it.

| Risk area | Judged in this version | Not judged in this version |
|---|---|---|
| Identity and access | tenant 2-step enforcement; admins without 2-step verification; members without it; admins against `access.admins`; too many admins; unattributed admins; contractor and shared admins; people who left, still active or invited; stale and never-signed-in accounts; suspended accounts holding roles; OAuth grants with broad scopes (optional profile); outside collaborators with admin on production; the base member permission | sign-in through another identity provider (SSO), and that provider's 2-step verification; which kind of 2-step verification people use (security key, app or text message); app passwords and other sign-ins that skip 2-step verification; service accounts allowed to act as any Workspace user (domain-wide delegation); which third-party apps staff may connect to Workspace (app access control); administrators' recovery email and phone; GitHub Apps installed on the organization and what they can reach; GitHub's rules for personal access tokens; GitHub members' SSH keys; access to repositories not declared `deploys_to: production` by a departed person not listed among their collaborators; deploy keys, GitHub App authorizations and self-hosted runners a departed person added; what a departed person did after leaving (audit log not read) |
| Secrets | provider secret-scanning alerts; secrets in mirrored history; organization secrets shared with every repository; secrets in public web responses. `secrets.production` is printed as declared, not verified | whether GitHub blocks secrets before they are pushed (push protection); secrets printed in CI logs; secrets inside container images; secrets pasted in chat and shared documents |
| Cloud configuration | none: no cloud collector (`collector_not_built`) | storage buckets and disk snapshots anyone can read; administrator roles (such as Owner or Editor) held by people; administrator roles held by service accounts, including the default ones; long-lived keys for service accounts and users, and their age; databases with a public address or authorized networks open to anyone; network firewall rules open to the whole internet; organization-wide guardrails (organization policies) |
| Data stores and backups | databases on Linux hosts listening beyond localhost with no host firewall rule in front (`db.listens_unfiltered`; a host's coverage plan, sub-item "Databases listening beyond localhost") | who can sign in to each database (pg_hba.conf, database users and their passwords); databases on hosts that filter with firewalld or their own nftables rules (scheck does not read those rules yet); databases published by Docker or Podman, whose port rules bypass the host firewall; data stores not in scheck's database list (MinIO, Cassandra, Kafka, RabbitMQ and others), and Elasticsearch or OpenSearch on ports other than 9200 and 9300 or not shown as java; Google Drive sharing defaults, and files shared with anyone who has the link; whether backups exist, where they are kept, and who can delete them (declared, not verified) |
| CI/CD and supply chain | default-branch protection; the workflow token default; action pinning; `pull_request_target`; write deploy keys; dependency alerts | who can push to repositories that deploy to production, contractors included; review rules on the production deployment environment; approval before workflows run on pull requests from forks; self-hosted runners that public repositories can use; which third-party actions the organization allows; trust from workflows to cloud accounts (OIDC); webhooks and where they send data |
| External surface | dangling records; subdomain takeover; private addresses; TLS and certificates; on Linux hosts, remote-administration services (Docker's API, etcd, kubelet, Telnet, FTP, SMB, RDP, VNC, Jupyter, SNMP, RabbitMQ management) listening beyond localhost with no host firewall rule in front (`svc.sensitive_listens_unfiltered`; a host's coverage plan, group "Remote-administration services listening beyond localhost"). The row names what was not checked ([web-collector.md](web-collector.md#not-assessed)) | whether a cloud firewall lets those services in; services on hosts reachable beyond the audience you declared for them; which ports and services answer from the internet (scheck reads; it does not scan); the registrar account: who can sign in, its 2-step verification, auto-renew and when the domain expires; the DNS hosting account and who can change records |
| Web application | HSTS; plain HTTP; security headers; cookies; version disclosure; `security.txt`; restricted pages reachable. On every run with a domain or url root the row says: `Only whole domain endings (such as .page, .dev, .app) were looked up in browsers' built-in HTTPS-only list; whether your own domain is on it was not checked.` | exposed files, debug pages and admin panels (such as /.git, /.env or /admin); third-party scripts the site loads; which other sites may read the site's responses (CORS) |
| Hosts | the host collector's catalog (`host-collector.md`), expanded below, including `log.auditd_inactive` and `accounts.empty_password_remote` (an empty password that SSH accepts); on Linux hosts, PHP and Node.js packages against the fixes of the 2026-10-21 disclosures (`php.fix_missing`, `node.fix_missing`, `node.line_unsupported`; 0.0.3 G8; always *partial*, see "The Hosts row") | PHP and Node.js in containers, from Homebrew or source, under version managers or control panels, and whether processes were restarted after an update; the firewall on Linux hosts, apart from database ports, remote-administration ports and the services you declared; listening services you did not declare (on Linux hosts, apart from remote-administration ports); who can become root or administrator, and sudo rules that need no password; SSH keys allowed to log in (authorized_keys); SSH settings inside Match blocks, and whether PAM accepts an empty password; disk encryption on Linux hosts; programs that run with root rights (SUID files); programs started at boot or on a schedule; credential files (.env files, ~/.aws, ~/.ssh, cloud CLI logins) |
| Email and domain | SPF; DKIM per declared selector; DMARC; non-sending domains; forwarding to an outside address (optional) | whether Workspace lets staff forward mail outside the company (the tenant setting); Workspace protection against spoofed and lookalike senders; encryption of mail in transit (MTA-STS and TLS reporting) |
| Logging and incident readiness | none in 0.0.2: the row prints "not checked" | alerts on administrator changes and suspicious sign-ins in Workspace; GitHub audit log retention and streaming; cloud audit logs; whether host logs are kept anywhere off the host |
| Malware and stolen sessions | *outside scheck*: scheck reads the settings of the hosts you list; it does not look for malware, infostealers or signs of compromise on any of them, and laptops you did not list were not looked at. Without the row a report on a laptop reads as covering what happens on it |
| Application logic | *outside scheck*: authenticated testing of access control and business rules |
| Processes | *outside scheck*: whether offboarding, incident response, backup restore tests and vendor reviews are done as written. The accounts themselves are checked under Identity and access; without the row, "Identity: checked" reads as "offboarding is handled" |
| Lookalike and typo domains | *outside scheck*: registrations of names you do not own are outside every root ([scope.md](scope.md)), and they are the most common small-company email fraud |
| Other declared SaaS | one row per tool in `tools` without a collector, by name |

Services listening beyond the declared audience moved left in step 5a (`svc.listens_beyond_declared`;
the External surface row's sub-item "Declared services listening beyond their
audience", read from a host's coverage plan like the Data row's). Databases listening beyond localhost moved left in step 3a: the Data row reads a
host's coverage plan, and its remaining right-hand items are `data.db_signin`,
`data.db_firewall_rules`, `data.db_containers` and `data.other_stores`. An empty password
that SSH accepts moved left in step 3b (`accounts.empty_password_remote`); the Hosts row
keeps `hosts.ssh_match` for the two things that rule does not read. Release markers for the other items live in
`ROADMAP.md`, not here.

**The lists are fixed, whatever rules are built** (contract from E9 step 2). Each row's
sub-items come from the practitioner's list for the area, not from the rules that exist,
so a reader can tell *checked* from *checked thinly*. The right-hand column is the
list, in this order, and `internal/engagement/report/fixed.go` holds it as data.
Each item has a stable id (`identity.sso`, `hosts.ssh_keys`, `data.db_signin`)
that is not renamed when its words change.

- *JSON.* `coverage[].not_judged` is `[{id, text}]`. The ten risk-area rows require it,
  including `not_applicable` and folded ("Not requested") rows; *Other declared SaaS*
  and *outside scheck* rows carry none.
- *Mark.* A row whose list is non-empty is never *assessed*: an *assessed* row becomes
  *partial*. The list never lifts *not assessed*, and never changes `not_applicable`, the
  exit code or the run status. In this version every area has a non-empty list, so no
  area row is *assessed*.
- *Text.* Each area row printed on its own (not folded, not `not_applicable`, not an
  *outside scheck* or *Other declared SaaS* row) ends with `Not judged in this version:
  <items joined by "; ">.`, followed by ` Also not judged on the assets read: <limits>.`
  when the row has `no_rule` reasons (the limits inside built sub-items). Row-level
  `no_rule` reasons do not print again in the reasons line. It prints with and without
  `-v`, before "Declared, not verified", and is not repeated under "NOT CHECKED, AND WHAT
  WOULD CLOSE THE GAP". In the Hosts row it prints once, right under the Hosts mark and
  before the host blocks, with no "Also" sentence.
- *No duplicates.* An unread sub-item that names a fixed item
  (`finding.CoverageUnread.Fixed`, a fixed id) is not repeated in the row's reasons: the
  Workspace plan's "domain-wide delegation" names `identity.delegation` and stays only in
  the JSON `sub_items`. A judged Workspace tenant adds no logging `no_rule` reason; the
  fixed logging list replaces it. A collector's free-text limit carries no fixed id and may
  still overlap an item (Workspace forwarding, GitHub OIDC); deferred in the roadmap. An
  "inventory only" limit is added only for an inventory that was read.

An item moves left only when a rule for it lands, and a golden pins each row.

**The Hosts row** is one block per host asset, under a mark that aggregates them (all
*assessed*: *assessed*; none: *not assessed*; otherwise *partial*), then lowered to
*partial* by the fixed list like every area row. Each block has an
identity line (name, canonical id, operating system, principal and elevation,
collection span), a counts line (`checks N: R ran, U unknown, X not run. rules M: D
decided, I had no usable evidence.`, the same counts the run status uses), one sub-row
per host domain that carries a rule, in the order of the host report's domains. A
sub-row never prints a bare mark that reads as a pass: a checked domain names what its
rules judged and what they found (`checked (password login, direct root login):
nothing found by these rules`, or `: 1 open finding (see Findings)`), then what was
read there that no rule judges (`also read, not judged: 9 SUID files`); a domain no
rule judges reads `not judged: …` with what was read; the rest give their reasons. A
multi-fact rule ([engagement.md](engagement.md), "The multi-fact rules of 0.0.2")
reports in the host domain its facts belong to, as a rule of that domain does, and the
checks its facts cite no longer print as `also read, not judged` there: the SSH server
line reads `checked (password login, direct root login, accounts with no password that
SSH lets in)`, and the Firewall line reads `checked (whether database ports are filtered
only; see Data stores)`, or `not checked: <reason>` when R1 abstained. The host-area
counts include these groups. From E9 step 5a the Firewall
line also reads "whether declared services listen beyond their audience only; see
External surface" (R3), and "whether remote-administration ports are filtered only; see
External surface" (R6, 0.0.3 G5). `expected_services` is read by R3 and R6 as well as R1,
so the "Declared, not verified" line names all three. A rule group with a standing gap
(`CoverageGroup.Gap`: R7 to R9, `unavailable:runtime_installs`, 0.0.3 G8) counts as
decided when it decided but leaves its sub-row *partial* and prints the gap's reason
beside the mark: what the rule can never read is not hidden by what it read. The
"Runtimes (PHP, Node.js)" sub-row reads `checked in part (PHP web packages against the
October 2026 fix, ...)` with that reason. A partial package read does not mark the host's
population incomplete: these rules turn each would-be disproof into an abstention
(`unavailable:packages_partial`) themselves (`engagement.md`, R7 to R9). The
JSON carries the same as `judged` and `read_not_judged` per sub-item. The Hosts mark
adds `N of M hosts read` when a host was not read; `Narrowed in the engagement file:` when narrowing removed
anything, a check with no rule included; and `Declared, not verified:` for host context
no rule fully consumes in this version (`expected_services`, which `db.listens_unfiltered`, `svc.listens_beyond_declared` and `svc.sensitive_listens_unfiltered` read, and which never lowers a finding). The row's "Not judged in this version" line prints once under the mark. With more than three
hosts, each block collapses to its identity and counts lines and the domains that are
not *assessed*.

**A collector's coverage plan.** A network collector may word an asset's coverage as
one plan per area (`finding.CoveragePlan`): its rule groups in order, each with a name
and rule ids, and the sub-items nothing reads. The collector words every sub-item and
detail; the report marks them and composes the row's reason, the same way for every
plan. A judgment decided when it fired or was disproved with no reason left open
(`Judgment.Decided`). A group the selected profile does not read is *not assessed* with
only its `not_on_plan` reason, rendered "<group>: not in the checks you chose (profile
<p>)". An asset feeds an area when its collector gave a plan for it; when every group
of that plan is off plan, the row takes those not-on-plan reasons and the asset is not
counted as read for the area. Otherwise a group is *assessed* when some judgment
decided, none is undecided and the asset's population is complete; *partial* when some
decided otherwise; `not_applicable` when nothing was judged on a complete population;
and *not assessed* when none decided. A group judged for every read subject is never
`not_applicable`: with no judgment it is *not assessed* with the collector's reason.
Each undecided judgment adds its reason with its subject and first "Not checked" line,
except those the plan collapses into one line. A gap in required evidence makes a group
with decisions *partial* and one without *not assessed*. What left a group undecided
reaches the row named by the group: the group's gap and each abstention's reason are
lifted to the row with the group name as detail, and a group is `no_rule` *unassessed*
only when it has neither an outcome nor a gap, so a refused read is never reported as
"no rule". The detail of a collector-plan reason prints without `-v`. A limits detail is a `no_rule`
reason whatever the mark, and an incomplete population adds the plan's wording to every
group. A sub-item nothing reads is *not assessed* with `no_rule`. The row's `no_rule`
reason names the groups and unread sub-items nothing decided ("Workspace OAuth grants
and domain-wide delegation remain unassessed"), then the plan's closing words.
Workspace is the one collector with a plan in this build, in the identity area and, for
its optional mail forwarding, in the email area; GitHub and web families are marked in
the report. A row read only through a plan, with no declared `domain` asset, keeps a
`not_declared` reason whose detail names what a domain would add (for email, "Domain
email settings (SPF, DKIM and DMARC)"), beside the plan's reasons.

**Departed people's access to production repositories.** When Check opened at least one
F1 pair ([engagement.md](engagement.md), "Plan selection and follow-ups"), the Identity
row's departed-people item carries the detail line: "Departed people's access to production
repositories: asked GitHub for *N* of *M* (login, repository) pairs", then "; the cap of
20 per run stopped the rest" when the cap cut pairs, or "; the run stopped before the rest
(*phrase*)" when a limit did, then a full stop. With no pair open there is no line. The line is the
optional `detail` string of the sub-item in the JSON; the text prints it on the area row
after the selection lines. A denied, not found or failed read adds no status and no exit
code.

When the organization declares no `deploys_to: production` repository, some
`identity.former_person_has_access` judgment on GitHub fired or abstained, and the line
above is not there, the sub-item's `detail` is: "Push to production by people who left:
not judged. No repository in this organization is declared `deploys_to: production`, so a
departed person's write access is reported but not raised as access to production, and no
repository's permissions were asked for it. Declare the repositories that deploy to
production to judge it." (built, E9 step 8). It is the after-the-fact counterpart of
Plan's not-judged sentence, and it changes no mark and no exit code.

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
  E9, of kind `person` ("A person item" below), the findings tied to one `people`
  handle, since one action fixes them. The item is not a finding id and moves no
  severity. The findings list groups the instances of one id on one asset into one
  block that lists the subjects; JSON never groups.
**A person item** (E9 step 4, R5 in [engagement.md](engagement.md)). A person gets a
`person` item when their open tied findings span two or more tenants or two or more
finding ids; a single instance stays in its `finding_id` item. The tied findings are
`identity.former_person_has_access`, `identity.former_person_invited` and the other open
identity-area findings engagement.md names; accepted and `info` findings are not open.

- *Title.* "*handle*, who left on *YYYY-MM-DD*, *phrases*", the phrases in tenant order:
  "is still active in *Tenant*" (Workspace, `identity.former_person_has_access`), "still
  has access to *Tenant*" (GitHub, the same id), "has a pending invitation to *Tenant*"
  (`identity.former_person_invited`). Phrases with the same verb merge ("still has access
  to GitHub and GitHub acme-labs"); groups join with ", " and the last with ", and ":
  "carol, who left on 2026-09-15, is still active in Workspace, and still has access to
  GitHub". *Tenant* is "Workspace" or "GitHub" when the engagement has one asset of that
  provider, else "Workspace *asset name*" or "GitHub *org*".
- *Under the title*, the severity phrase below, then that person's lines from "People
  who left", and only those.
- *Severity* is the highest among the item's open instances after context. When the
  `attribute:production_write` raise set it, the text phrase is "raised: can still push
  to *owner/repo*, declared production". `rank_basis` carries `person:<handle>` and the
  raises of that instance.
- *Cap and dedup.* At most two `person` items among the five; further qualifying people
  stay in `finding_id` items. Instances in a `person` item leave the `finding_id` items
  for ranking; those items still rank on their remaining instances and say "and other
  people" in their naming: JSON sets `other_people: true` on the item, and the text
  prints ", and other people" inside the parenthesis that names the assets. For the departed-people ids, "more affected instances" counts
  distinct people, not repository-level instances. The findings list is unchanged and
  JSON never groups.

- Order: severity after context, critical first; then risk area in the coverage
  table's order; then an asset named in `data.matters_most` first; then more affected
  instances; then canonical asset id and finding id. Thresholds do not enter the
  ranking: they set the exit code, and the close names them.
- On a host where an open `accounts.empty_password_remote` fired and lists every
  account `accounts.empty_password` cites, "Fix these first" leaves out
  `accounts.empty_password`: the remote finding's first remediation step is that
  finding's fix. It stays open under Findings. When the remote finding lists fewer
  accounts (root with key-only logins, say), both are ranked.
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

**Context notes** (built, E9 step 5b). A note that a declaration
reached nothing or that the evidence contradicts one ([engagement.md](engagement.md),
"Context notes") prints under "Notes for the readout" as "*source*: *detail*" and in `notes` in JSON
as `{kind, source, detail}`, `kind` one of `context_workspace_domain`, `context_deploys_to`
and `context_not_used`. It has no id, no severity and no effect on the exit code. A
`context_not_used` note also goes onto its area's row as `context_notes` in JSON and
prints under it as "  Note: *detail*"; a row with one is never folded into "Not
requested". Whether the row is *not applicable* is decided by findings alone ("Coverage").

Network collectors return the shared `finding.Judgment` and `finding.Subject`
types; the report aliases these types and remains the author of the final report.
Judgments identify the rule, asset, subject, verdict, reason and gate request ids,
with declaration references kept separately from observations. An empty subject is
an asset-wide judgment and is omitted from `findings.json`'s `judged` list. The
`Sources` field retains the JSON key `source`. The names a wildcard match stands for come from the collector's `Suspensions`,
read selection before `Enrich`, never a judgment field or report output. Finding
definitions stay in `internal/finding`; collectors do not return report fragments.

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
| `asset_name`, `bound_id` | the `assets` name; for a name found under a domain root and not declared, the name; else the id. The bound id or null. The asset beside it carries `bound_id_source`: `machine_id` (a host's machine identifier), `provider_id` (a tenant's own id) or `hostname` (the fallback for a host whose identifier was unreadable, truncated or hidden by a redaction rule); only the first two name an identity across runs |
| `subject` | `{kind, key, label, provider_id?, person?}`. `kind` is declared per finding definition (`account`, `org_unit`, `group`, `deploy_key`, `token`, `principal`, `oauth_app`, `service`, `repository`, `workflow`, `branch`, `webhook`, `invitation`, `secret_location`, `dependency_alert`, `dns_name`, `dns_record`, `url`, `origin`, `mail_domain`, `dkim_selector`, `spf_mechanism`, `mail_forward`, `package`, `declaration`). `key` is short and typable, what `accepted_risks[].subject` takes; `label` is what a human needs to recognise it, built only from fields rules read; `provider_id` survives a rename; `person` is the `people` handle when attributed |
| `id`, `title` | `id` is the join key into `scheck explain` |
| `area` | one of the ten area keys; required on every finding definition |
| `category` | the collector's own grouping |
| `exposure_finding` | required on every finding definition: whether "exposed on purpose" may move it ([engagement.md](engagement.md), "Severity in context") |
| `severity`, `severity_base`, `adjustments[]` | each adjustment `{rule, by, delta, source}`: `rule` from the closed table of [engagement.md](engagement.md), "Severity in context" or the collector's own, `by` `collector` or `engagement`, `source` either `{file, key}` for a declaration or `{observation, excerpt}` for a fact; no non-base severity without its chain |
| `status`, `acceptance` | `acceptance`, present exactly when the status is `accepted`, is `{entry, reason, accepted_by, expires, expired, covers_every_instance, judged_at}`; `judged_at` is the collection time the expiry was read at (`engagement.md`, "Severity in context", "Time"), a date-time or null |
| `rule` | `{kind: single_fact \| multi_fact, reads[]}`: the check, request and declaration ids the rule reads, in the vocabulary of `assessments[]`. `single_fact` is one fact per subject, which includes a host rule that joins a second check of the same host per account (`host-collector.md §6.5`, both checks in `reads`); `multi_fact` combines facts across checks or assets ([engagement.md](engagement.md), "Multi-fact rules") |
| `evidence[]` | at least one observed item. Observed: `{asset, check \| request, observation, collected_at, principal, vantage, excerpt}`; declared: `{source: "engagement.yaml <key path>", excerpt}`. A declaration supports a finding and never makes one alone |
| `derived[]` | computed values (`days_since_left`, `age_days`), each against the collection time of the read it is about, named in the excerpt (`engagement.md`, "Severity in context", "Time"); each states what a field shows, never who acted |
| `affected` | secondary subjects (the users who granted an OAuth app, the repositories a token reaches): `{count, listed[], cap, of_note[]}`, the cap printed |
| `impact` | from the definition |
| `why_here[]` | templated lines from attributed context only, never free prose: the reasons of the steps that moved the severity first, then a step said but not taken (`not applied: write access to production repositories was not established (cause)`, E9 step 4), then the collector's sentence, then a cap that still holds. A finding no step moved prints the standard-rating line for its collector; one a step moved never prints a cap or the standard-rating line as its first reason |
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

**Subjects.** Host posture findings carry no subject in 0.0.2, and the host grader
accepts a whole id. The first host-side subject is a listener's, `{kind: service, key:
"<port>/<proto>"}`, declared by the engagement rules `db.listens_unfiltered` (built, E9 step 3a),
`svc.listens_beyond_declared` (E9 step 5a) and `svc.sensitive_listens_unfiltered` (0.0.3
G5; [engagement.md](engagement.md), "The multi-fact rules of 0.0.2"); an acceptance of any
of them names it. `php.fix_missing`, `node.fix_missing` and `node.line_unsupported` (0.0.3
G8) have the subject `{kind: package, key: "<package name>"}`. An acceptance is applied to the judgment
like a network collector's, never by the host grader. Host posture acceptance by subject stays
unbuilt. A person's account is keyed by the address rules match
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
- `date`, the collection day in `engagement.timezone`, the day the acceptance is written.
- `expires`, that day plus 90 days for critical and high and 180 days otherwise,
  so it stays inside the one-year cap, with the comment `# after this date the finding
  counts again` and a following line `# until someone re-reviews it`.

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
it would have had, `accepted by <handle> until <date>` (and, at 30 days or fewer, `(<N> days after collection on <date>)` after the date) or `accepted by <handle>, no expiry`, the quoted reason, its entry, and
"covers every instance of this id on this asset" when the acceptance has no `subject`.
Past `expires` at the collection time ("expired <date>, before collection on <date>") the finding is open and ranked, with `the acceptance by <handle> expired
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

### People who left

A block in the text report at default verbosity, after Findings and before what was not
checked, printed whenever any `left` is declared (E9 step 4, R5 in
[engagement.md](engagement.md)). It is not part of the Identity coverage row and it
decides nothing: it restates verdicts already made. It holds the personal data the
handling notice covers (`notice.personal_data`, "What never appears").

Every person with a `left` value gets a header "*handle* (left *YYYY-MM-DD*)" and one line per tenant in
coverage-table asset order: every tenant where the person has a declared account or
the tenant is in scope. A tenant neither in scope nor named in the declaration is left
out. *Tenant* is named as in "Ranking". Several declared accounts in one tenant: their
states joined with "; ".

| Workspace state | Line |
|---|---|
| fired | "Workspace: *address* still active (finding)." |
| fired, administrator | "Workspace: *address* still active, with administrator rights (finding)." |
| accepted | "Workspace: *address* still active (accepted until *expires*)." |
| disproved | "Workspace: *address* no access observed as of *date*." |
| `leaving_date_not_passed` | "Workspace: *address* leaving date had not passed at the read of *date*, not judged." |
| `left_date_within_collection` | "Workspace: *address* leaving date falls within collection, not judged; re-run after *left*." |
| `unavailable:collection_time` | "Workspace: *address* collection time not recorded, not judged." |
| users not read or denied | "Workspace: users could not be read (*reason phrase*), not checked." (the asset's recorded reason when there is one, else the judgment's) |
| absence over an incomplete users list | "Workspace: *address* not seen as of *date*; the users list was incomplete, so no access is not proven." (state `not_proven`) |
| an abstention with no account read for it (no provider id) and no other row | "Workspace: *address* could not be checked (*reason phrase*)." |
| account read, status or access evidence not recognized | "Workspace: *address* account observed, but its status or access evidence was not recognized, not checked." (*address* is the account's primary address; applies only to an account that was read) |
| the tenant was collected and nothing was judged for the person | "Workspace: nothing was judged for this person, not checked." |
| identity missing or ambiguous | "Workspace: *address* account identity missing or ambiguous, not checked." |
| no address declared | "Workspace: no address declared, not checked." (whatever the time reason; checked before the leaving-date rows) |
| address declared, tenant not in scope | "Workspace: not in this engagement's scope, not checked." |

Workspace has no invitation finding, so no Workspace invited line.

GitHub covers `identity.former_person_has_access` and `identity.former_person_invited`.
The parts for one login join with "; ":

| GitHub state | Line or part |
|---|---|
| organization-level fired | "GitHub: *login* still has access as *owner*, *member* or *outside collaborator* (finding)" |
| repository-level fired, R4 not involved | "*login* is a collaborator on *N* repositories (finding)" |
| R4 applied | "*login* can still push to *owner/repo*, declared production[ and *N* more] (finding)" |
| R4 not applied | "write access to production repositories was not established" |
| invitation fired | "pending invitation for *login* (finding)" |
| accepted | "(accepted until *expires*)" in place of "(finding)" |
| disproved over a complete population | "GitHub: *login* no access observed as of *date*." |
| absence over an incomplete population | "GitHub: *login* not seen as of *date*; access to repositories cannot be fully listed, so no access is not proven." |
| time reasons | as Workspace, with *login* |
| no login declared | "GitHub: no login declared, not checked." |
| login declared, no organization in scope | "GitHub: not in this engagement's scope, not checked." |
| the organization was not read | "GitHub: the organization could not be read (*reason phrase*), not checked." |
| the organization was collected and nothing was judged for the person | "GitHub: nothing was judged for this person, not checked." |
| a login abstained for another reason | "*login* could not be checked (*reason phrase*)" |

JSON carries `people_left[]`: `{handle, left, tenants: [{asset, provider, state, reason?,
line, accounts: [{key, state, finding_keys[], production_write?: {applied, repositories[]}}]}]}`.
`line` is the sentence printed; `asset` is null for a provider the person declares an
account at when no tenant of it is in scope.
`state` is one of `finding`, `accepted`, `no_access_observed`, `not_proven`,
`not_judged`, `not_checked`, `not_in_scope`, `no_login_declared`. `reason` is the
coverage reason where there is one. `finding_keys` are the `{id, asset, subject}` keys of
the findings the line cites.

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
level down. A host asset's `bound_id_source` is the envelope's `host.id_source`. The report on stdout is complete without the run directory, so
`--no-persist` loses nothing, and `--include-evidence` adds captures to the embedded
envelope of each host this session collected ([runs.md](runs.md), "Stop and resume"). The engagement's own findings are authoritative where their severity differs
from the envelope's ("The report", "Findings"). The aliases' deprecation line names the new path of `run.assessment`.


JSON (`docs/engagement-report-schema.json`, `schema_version` `MAJOR.MINOR`, free to
change until 0.0.2 is published) carries what a consumer agent or a comparison of runs
(0.0.3 G6) needs and the text leaves out:

- `run: {started, session_started, directory, resumed}`, the scheck version and `rules_version`, so a
  finding that disappears because a rule changed between versions is never read as
  fixed. For network reports, `rules_version` combines the binary version with the
  pinned web, preload, takeover and sender-data versions and the C3 table's
  (`:context:<version>`, `ContextTableVersion`), on every report that has a network
  collector's rules version or any context note, whichever collector read the evidence. `scheck_version` remains
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
  it read. The assessment's `reads` do not carry declared inputs in 0.0.3; a finding's
  `rule.reads` do (`declared:people.carol.left`). A rule that reads the engagement file
  without such a read (the mail senders, selectors and `no_mail` a domain declares, a
  host's `app_paths`) says so in its definition (`ReadsDeclarations`). `scheck diff`
  therefore reads an instance as *fixed* only when its rule decided on complete evidence
  and, when the engagement file hash differs, `finding.ReadsDeclarations(id)` is false:
  the earlier finding's `rule.reads` hold no `declared:` entry, its definition does not
  set `ReadsDeclarations`, it is not in the identity area and not one of
  `svc.expected_missing`, `github.too_many_owners`,
  `github.undeclared_public_repository`, `dns.dangling_external`,
  `dns.dangling_internal`, `dns.takeover_candidate`, `dns.unclaimed_at_provider`,
  `web.secret_in_response`, `web.version_disclosed`, `web.security_headers`,
  `web.hsts_missing`, `web.plaintext_http`, `web.plaintext_http_clients`,
  `web.security_txt`, `tls.certificate_invalid`, `tls.certificate_expiring`,
  `tls.legacy_only` and `dns.private_address` (eighteen named ids), and the id is one
  this build knows. Otherwise it
  is *not confirmed*, and an appearing one *first reported*, cause `declaration_changed`
  (`runs.md`, "Comparing two runs"). That is
  conservative: any rule that reads a declaration is unconfirmed across a file edit.
  Per-assessment declared-input digests, which would say whether the declaration it read
  changed, are carried. An assessment
  may have an empty `reads` list when no read was collected or a static preload rule
  decided without a request; it never invents a request id. A finding still requires
  nonempty rule inputs and observed evidence;
- `summary` with its items (`kind`, `ids[]`, `person`, member keys, severity,
  `rank_basis`), `matters_most[]` ("Summary") and disjoint area counts (`assessed`, `partial`, `not_assessed`,
  `not_applicable`, `total`);
- `people_left[]`, one record per person with a declared `left` ("People who left");
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
redacted captures, as in 0.0.1. The sheet's `finding:` flags show the severity the
engagement report gives the finding, not the host collector's.

The text and JSON reports are pinned by golden files under the rules of the host
report's (`host-collector.md §9`).

