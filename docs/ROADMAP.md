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
  later. Each question declares its consumers and the slice that owns each; a slice is
  not done until the consumers it owns exist, and a consumer is never stubbed to pass
  that test.
- **The lab comes before the checks it measures.** Each release's lab is seeded by
  someone who does not write that release's checks, and each part of it is sealed
  before the first slice whose checks it measures starts. One author cannot be blind to their own seeding.
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
- **The host collector does not regress.** Its golden command traces, and its facts and
  findings for the same inputs, change only with an explained reason
  (`spec/host-collector.md §9`). Adding a check is such a reason; a trace that changes
  for any other reason is a defect. Moving the host into `scheck run` (0.0.2 E1b, E2)
  changes which command and which report a person sees, not what reaches the target.

## Release gates and the lab

Decided by the maintainer:

- **2026-10-24:** `release/v0.0.2` was merged into `main` (PR #21). The 0.0.2 gates 1 to
  11 were not run, `docs/eval/acceptance-0.0.2.md` does not exist and no tag or release
  was cut for 0.0.2. Nothing below records any of them as passed
  ([eval/deferred-gates-0.0.2-2026-10-25.md](eval/deferred-gates-0.0.2-2026-10-25.md)).
- **2026-10-25:** the lab (E3's rest of the lab, G7's GCP project, and every acceptance
  pass that needs one) is deferred as a gate for **v1.0.0**. There is no Google Workspace
  lab: Workspace is exercised read-only on the maintainer's production tenant and is not
  measured ([spec/lab.md](spec/lab.md), "Google Workspace: no lab, observed on the
  production tenant"). Every record of a measured run says "Workspace: exercised
  read-only on a real tenant, not measured."
- 0.0.3 slices are pull requests into `release/v0.0.3`, as 0.0.2's were into
  `release/v0.0.2`.

Which gates the lab decision defers, and which still apply:

| Gate | Status |
|---|---|
| 0.0.2 gates 1 to 5 (the lab through all stages; recall; false positives; context; prioritization) | Deferred to v1.0.0: each is measured on the lab |
| 0.0.2 gate 6 (coverage) and gate 7 (scope: the audit log of the lab run) | Deferred to v1.0.0 as lab measurements. Gate 6's second half, an engagement with a collector missing or credentials withheld, and the host integration diff of gate 7 need no lab: see the open placements below |
| 0.0.2 gates 8 and 9 (`make check`, host traces and facts unchanged; interview consumers exist) | Not lab-bound. They still apply, and were not run for 0.0.2 |
| 0.0.2 gate 11 (mailbox authorization) | Done offline 2026-10-11, as recorded there; not an acceptance |
| 0.0.3 "the 0.0.2 gates, re-run on the larger lab" | Deferred to v1.0.0 with the lab; Workspace is not measured |
| 0.0.3 "every GCP call on the declared list and nothing else (audit log)"; "coverage table correct for every area"; "the comparison of two runs correct against a seeded change list" | Deferred to v1.0.0 with the lab ([spec/lab.md](spec/lab.md), "What the lab measures") |
| 0.0.3 "no write call possible from the code (a test over the declared list)"; "credentials never in any output" | Their tests run in `make check` and are required; the lab does not replace them |
| 0.0.3 "probes run only after confirmation and only on assets with named first-party evidence" | Not lab-bound. It still applies |
| 0.0.4 gates | Unchanged by this decision; they name a freshly seeded lab, which is not reconciled here |

A deferred gate is recorded as *not run*, never as passed, in the release's record
(Rules for every release, "Evidence for every release gate"). What v1.0.0 contains is not
defined: the lab gate is the only part decided.

Open placements, undecided: whether 0.0.2 gate 10 (`scheck run --host` against the
`scheck ssh` alias on the lab host) is lab-bound, and, with the aliases removed in this
branch, whether it can be run at all (only against a 0.0.2 build; its unit and integration
evidence went with the aliases, and the maintainer decides whether it is given up); whether gate 6's second half and gate
7's integration diff now count as their own gates; which gates a 0.0.2 or 0.0.3 tag
would need, if one is ever cut.

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

0.0.2 also makes `scheck run` the only way to run an assessment. A one-host check is an
engagement with one root: `scheck run --host deploy@203.0.113.5` builds that engagement
in memory, with no file and no interview, and goes through the same validation, run
directory and report as a full one. `scheck local` and `scheck ssh` are aliases of it
for this release and are removed in 0.0.3. `scheck.yaml` is no longer read: everything
it held belongs to an asset, to the engagement or to a flag (`spec/engagement.md`, "One
command, one file").

### Decisions

| Question | Decision |
|---|---|
| Which assets first? | Google Workspace and GitHub (identity, secrets, CI/CD), the domain (email spoofability, takeover, TLS) and one host. Websites are read only at their declared entry points. |
| Why not probes? | A probe needs first-party evidence, and in 0.0.2 the only evidence for a discovered site would be the operator's word. Probes arrive in 0.0.3 after the cloud inventory can vouch for an address. |
| Why GCP and Google Workspace rather than AWS and Microsoft 365? | A market decision, stated as one: the authors' own environment is Google, so the live tests and the lab can exist. AWS has the larger share of small companies and is the next collector on the same shape, before Azure and Microsoft 365. |
| Third-party tools? | None. DNS, TLS, headers, fingerprinting and both APIs need only the Go standard library. |
| The host side? | The host collector's catalog, runner, policy and guarantees are unchanged in 0.0.2. It becomes the collector for `host:` assets in E1b and gains no check there; the deeper checks a small company needs from it are 0.0.3 G5. One exception, decided 2026-10-13 (owner): E9 adds `fw.iptables_backend` (`realpath -e /usr/sbin/iptables`) so that `db.listens_unfiltered` can tell an empty `nft` ruleset from no firewall. A second, decided 2026-10-15 (D3b): `net.listeners` on Linux is elevated. |
| One command? | Yes. From E2, `scheck run` is the only assessment command. `scheck local` and `scheck ssh` were aliases of `scheck run --host` in 0.0.2, with a deprecation line on stderr, and are removed in 0.0.3 (done: they are unknown commands, exit 3). Two pipelines would mean two reports, two run histories and two places to declare a host, and only one of them would say what it did not assess. |
| `scheck.yaml`? | Not read by `scheck run` (E1b), removed with the aliases (E2). Profile, elevation, host context and the narrowing lists move into the engagement file, per asset where they describe a host; the state directory and the evaluation harness's model settings are flags. A restriction a client asked for is part of the rules of engagement and has to travel with the engagement file: kept in a per-machine file, it silently disappears when a colleague or a CI job runs the same engagement elsewhere. A config file where 0.0.1 read one makes `scheck run` exit 3, naming where each of its keys moved and saying to delete or rename the file, so a v0.0.1 `deny_paths` is never dropped silently, whichever release a user upgrades to; the check stays. |
| A model? | No. Every stage runs on rules, single-fact and multi-fact. Plan is a checklist per asset type, narrowed and ordered by context, and the report says so. |
| Reports? | The engagement report is the one report a person or an agent reads, with its own schema starting at 1.0. The engagement file and report may change freely until 0.0.2 is published. The host collector's JSON envelope keeps its schema and versioning (`spec/host-collector.md §6.4`) as the host asset's evidence file in the run directory; the host text report (§6.6) is no longer printed once E2 lands. |
| Why does the host come first? | Order of building is not order of importance. The host collector is the only collector that already exists, so wiring it in first proves the engagement file, the run directory, the stages and the report on real evidence before any network collector, and the report's goldens show a real asset rather than an empty engagement. E1b adds no host check, and 0.0.2 does not ship until Workspace, GitHub and the domain are read. `scheck init` comes beside the collectors, so each question is written when the rule that reads its answer is. |

### E1a — the engagement file

**Delivers:** the `engagement.yaml` schema as `spec/engagement.md` shows it: roots,
exclude, defaults (including the host `profile`), limits, `redact_extra`, `people` keyed
by handle, assets with canonical ids, the intake answers and the optional authorization
block. A host asset carries its reach settings (`identity`, `jump`, `elevate`; the port
is part of the locator), the four context fields of `spec/host-collector.md §5.2`, its
`profile` and its narrowing lists (`disable_checks`, `deny_paths`). Validation runs
before any target contact (`spec/engagement.md`, "Identity, references and
validation"), including the credential detector; `scheck run engagement.yaml
--stop-after intake` validates the file and prints it resolved. `jump` is accepted and
validated here; E1c makes it reachable.

**Done when:** unknown keys, malformed roots, an `assets` entry outside every root and
an `exclude` under no root exit 3 naming `file:line:key`; so do an unknown check id
under `disable_checks`, a relative or `/` entry under `deny_paths` and an invalid
`redact_extra` pattern. A credential-shaped value is a usage error that names the
detector and never prints the value. A probe or scan mode other than `off`, `scope:
full` and `max_cost` exit 3 with "not available in this build". A timestamp without
seconds or an offset, a limit of `0`, and an `engagement.name` outside
`^[a-z0-9][a-z0-9-]{0,62}$` are rejected. No code path in this slice contacts a target.

### E1b — `scheck run` on a host

**Delivers:** `scheck run engagement.yaml` and `scheck run --host LOCATOR`, with the
flags of `spec/engagement.md` ("One command, one file": `--identity`, `--known-hosts`,
`--sudo` or `--elevate`, `--profile`, `--timeout`, `--write-engagement FILE`); the exit
codes defined there; the run directory, `0700` and locked, holding the stage outputs
built so far; `--stop-after` with the engagement's stage names. Until E4, Scope resolves
the declared roots as written, without discovery. A `host:` root runs the host
collector through the runner in Recon, its facts join the asset map
(`internal/engagement/hostasset`), and its posture rules run in Analyze, which holds
only the host collector's rules (one check, or two joined per account, E5a) until E9; Plan selects and Check reads the per-repository GitHub evidence from E9 step 6a (Workspace follows in 6b). A root
of a kind with no collector yet (`github:`, `domain:` and the rest, until their slice)
is validated, recorded as not collected with the reason `collector_not_built`, and
makes the run exit 2, as coverage will report it from E2. The host collector receives
the asset's context fields, profile, elevation and narrowing lists, and the runner's
redactor gains the engagement's `redact_extra`; nothing else reaches it: `--context`,
`.scheck/context/`, `target:` sources and `scheck.yaml` are not read, and a config file
where 0.0.1 read one exits 3, naming each key's new home. Until E2, `findings.json`
(`--stop-after analyze`) is the last output of `scheck run`, and `scheck local` and
`scheck ssh` keep their 0.0.1 behaviour.

**Done when:** the golden command traces in `internal/baseline` are unchanged; the host
asset's facts and posture findings for each fixture equal the 0.0.1 golden JSON
report's for the same profile, elevation and context; a seeded secret on a fixture
host is absent from every file in the run directory and its marker present, and so is
a fixture string matching the engagement's `redact_extra`; a run cut by a transport
failure exits 2 as in 0.0.1; an engagement with a host root and a `github:` root exits
2 with the host's findings written; a second run on a locked run directory exits 3;
the integration diff stays the exact allowlist of `spec/host-collector.md §1`.
The engagement's packages carry the host envelope, so `internal/report` stops importing
`internal/llm` here rather than in E2 (AGENTS.md, "Layout").

### E1c — jump hosts

**Delivers:** `jump` on a host asset and `--jump` with `--host`: an SSH ProxyJump hop,
with strict host-key verification on the hop as on the target. The hop is a connection
setting, not an asset: nothing runs on it, it is never in scope by being named, and the
audit log records it. Quoting, the canary and the catalog are unchanged; the canary is
still the first command on the target's session.

**Done when:** an integration test reaches a container host through a jump container
with the canary first; the jump container's filesystem is unchanged by the run; an
unknown host key on the hop exits 3 before the target is contacted; the integration
diff on the target stays the exact allowlist of `spec/host-collector.md §1`.

### E2 — the engagement report, and one command

**Delivers:** the coverage table by risk area (`spec/report.md`), with the five
marks defined there and reasons from its closed list, and per row the assets covered
and excluded, the principal, the collection span, caps and sampling, declared facts
not verified, and what the engagement's narrowing removed; the *outside scheck* rows;
ranked findings labeled as a ranking of what was assessed; a header with the trigger,
the method ("rules only; the plan is a checklist"), the authorization block when
present, and a notice that the report holds personal data and internal topology; a
ready-to-paste `accepted_risks` entry under each finding; excluded, out-of-scope,
refused and not-run items; exit 2 when a declared root went unassessed, findings or
not; text and JSON with `docs/engagement-report-schema.json`; golden files under the
same rules as the host report's. Then one command: `scheck local` and `scheck ssh`
become aliases of `scheck run --host local` and `scheck run --host user@host`, print a
deprecation line on stderr, and map each 0.0.1 flag to its `run` equivalent or exit 3
naming the replacement (`spec/engagement.md`, "One command, one file"). The host text
report and `runs/<host.id>/` persistence stop; `internal/config`, `scheck config`,
`docs/CONFIGURATION.md` and `scheck.example.yaml` are removed; the README and the
`scheck` skill move to `scheck run` and the engagement report's JSON, which embeds each
host asset's collector envelope whole. Built before any network collector so every
later slice renders into the real report. Because the only real asset at this point is
a host, the schema is reviewed by the `security-consultant` and the `client` (report
mode) against at least one non-host finding shape, a person, a token or an OAuth grant,
before it is frozen. The content and wording were defined with the `security-consultant`
and read by the `client` on 2026-10-07 (`spec/report.md`, "The report"; `spec/engagement.md`, "Severity in
context"): one finding record per instance keyed `{id, asset, subject}`, with `area` and
`exposure_finding` required on every finding definition and observed evidence on every
finding; host coverage marked from the rules that decided, never from the checks that
ran, with the reasons `unavailable:<code>` and `no_rule` and a population per row;
plain words for marks and reasons in text, tokens in JSON; a summary of what was checked
and the top five before the full table; a closed table of context adjustments; and the
command trace always in the JSON.

**Done when:** golden text and JSON reports are committed for a one-host engagement
from a fixture (the hosts area marked from what ran, every other area *not assessed*
folded into one line with the reason `not_declared`, the Hosts row expanded into the collector's domains, the *outside scheck* rows present) and for an engagement
whose only root has no collector (`collector_not_built`, exit 2); the JSON validates
against the schema as committed; target-derived text is control-character escaped;
`scheck ssh user@host` and `scheck run --host user@host` produce the same report and
the same command trace; a one-host run exits as the 0.0.1 command did for the same
findings and failures, except a host that never answered (2, not 3, `spec/scope.md`, "Outcomes"); `--format json --no-persist --include-evidence` still prints the
host's facts with their captures; no code path reads a config file. Goldens also pin a
lost session (exit 2, the checks after the loss *not run*), a refused host (exit 3), a
Linux host whose Firewall and Network exposure rows are `no_rule`, and the apt, dnf and
zypper family leaving Software updates *checked*; `ValidateRules` fails on a finding
definition without `area` or `exposure_finding`; the `--host` paste's `asset` validates
against what `--write-engagement` writes; and no reason or mark token appears in the
text report outside `-v`.

**Carried from the E1b review** (security-consultant and code review, 2026-10-07),
decided here so E2 does not unpick E1b: `findings.json` and the report's JSON carry the
run's incompleteness and refusals as `{asset, reason, detail}`, and an exit-2 line that
also hides open findings says both; the text output shows per host asset its checks
(ok, unavailable by reason) and rules (insufficient evidence), leads with
incompleteness, and closes with "exit 0 is not a clean result"; `plan.json` lists each
host asset's planned and disabled checks so it reconciles with `audit.jsonl`; one of
`recon.json` and `evidence/<asset>.json` is named the record of a host's facts; a run
under `--no-persist` still leaves its command trace somewhere (the report's JSON, or an
audit path); accepted risks carry `accepted_by` to the report, and an acceptance's
`expires` is read in `engagement.timezone` (`operator.Risk.Expired` reads UTC); validation
warns when a declared locator or asset name matches a `redact_extra` pattern, since
stage documents carry them as written; the coverage reason `refused` is rendered; and
`session` in `cmd/scheck` calls `hostasset` instead of its own copy of the baseline run
when `local` and `ssh` become aliases.

**Carried from the E2 review** (security-consultant, client and code review,
2026-10-08), each to the slice that owns it: `--write-engagement` writes `trigger:
routine` only so the file validates, and should say so in a comment and show a
`people:` example (E8); the host fact sheet's status word "skipped" covers commands that
ran and failed, which it should call "failed" (0.0.3 host depth); and
`accounts.empty_password` is anchored critical as "a usable empty password" but fires on
any `NP` status without checking for a login shell, so the rule or its anchor changes
(E9, or 0.0.3 host depth). The text report still names engagement-file keys by path
(`assets.macos.disable_checks[0]`, `intent.accepted_risks[2]`, "roots"), which an
operator who did not write the file cannot read; E8, which adds the interview and its
words, replaces them with plain descriptions in text and keeps the paths in JSON.

### E3 — the lab, sealed

**Delivers:** a GitHub test organization the team owns, a Google Workspace test tenant
on a domain the team owns, a second domain the team owns, separate from the tenant's,
with its DNS, mail records and a small website, and one Linux host over SSH (nginx in
front of a Next.js app, postgres on the same host) in a docker-compose file; a seeded
issue list written by a seeder who is not the implementer (a person, or an agent in its
own session, under the rule above) and sealed in two parts (below); two context cases
and a clean variant; the false-positive target for the clean variant, fixed now.

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
| A CNAME to a hosting service that no longer serves the name, built so that nobody outside the team can claim it while the lab is up (a provider-verified domain, or a target under a domain the team holds outside the lab's roots) | DNS and the front-page read (E7); high when the provider's fingerprint matches, medium when the target name does not exist |
| `PasswordAuthentication yes` on the host | host collector (E1b) |
| postgres bound to all interfaces with no host firewall rule in front | multi-fact rule over listeners (elevated) and firewall reads (E9 step 3a) |
| Missing `Strict-Transport-Security` header, on a site under a TLD that is not preloaded (a declared `url` root or `first_party`) | response headers (E7); low; must rank below every item above |

No seeded issue may be exploitable by anyone outside the team while the lab exists. A
takeover is seeded only where the provider's verification or the team's own
registration stops anyone else from claiming the name.

Sites under a preloaded TLD (`.page`) exercise the preloaded branch of the HSTS and
plain-HTTP rules (`spec/web-collector.md`, "Preloaded TLDs") and count in the clean
variant's false positives. If the team owns no domain under a TLD that is not
preloaded, the acceptance record says that HSTS and plain-HTTP recall was measured on
fixtures only. A lab root that is a subdomain (`lab.<x>.page`) publishes its DMARC
explicitly at `_dmarc.<lab root>`, or `<x>.page` is declared a root too; otherwise the
DMARC rules abstain, its organizational domain not being a root.
For the dangling CNAME, either point a name at GitHub Pages on a domain the lab's GitHub
organization has verified, with no Pages site for that name and the verification record
kept published while the lab exists (a takeover candidate, high), or point it at a name
that does not exist under a second domain the team owns outside the lab's roots (a
dangling record, medium). Never point it at an S3, Azure or Elastic Beanstalk name
nobody holds, and never reserve the bucket or app under the matching name, which leaves
nothing to find.

The host collector's checks predate the lab, and E1b adds none, so wiring the host in
before the labels are sealed shapes nothing; the recall gate measures its checks like
every other.

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
their hash in `docs/eval/`, in two parts, each seeded blind and sealed before the
commit the table names:

| Part | What it holds | Sealed before |
|---|---|---|
| Domain | the second domain, its DNS and mail records, and the small website, with E7's seeded issues, the context cases, the domain's clean variant and its share of the false-positive target | the first commit of E7 |
| The rest | the GitHub organization, the Workspace tenant and the SSH host, with their seeded issues, clean variant and share of the false-positive target | the first commit of E5 or E6, whichever comes first |

The seeder of each part is named in the acceptance record, with the model when it is an
agent. E1a to E2 and E4 need no lab and may proceed while it is being built.

**The lab as code** (defined 2026-10-25, design): the OpenTofu pieces, the fault catalog
with decoys, clean controls, cross-asset, context, scope and change-set cases, seeding
from a sealed random seed, the answer key's format, sealing and reveal, and scoring are
[spec/lab.md](spec/lab.md). Its "Where this differs from the roadmap" section lists what
it changes here.

**Known gap: no Workspace lab** (user's decision, 2026-10-25). The Google Workspace test
tenant this section delivers will not exist. Workspace is run read-only against the
user's production tenant a limited number of times, under the safety rules of
[spec/lab.md](spec/lab.md) ("Google Workspace: no lab, observed on the production
tenant"). The Workspace share of the recall, false-positive, context and prioritization
gates below is recorded as "Workspace: exercised read-only on a real tenant, not
measured", never as passed; the coverage gate still applies to it. The same decision makes
the lab a gate for v1.0.0, and the rest of E3 (the GitHub organization, the second
domain, the SSH host and their sealed labels) is deferred with it. Which 0.0.2 and 0.0.3
gates this defers is in "Release gates and the lab". E3's sealing duties stay as written
for the v1.0.0 seals; E5 to E7 shipped without the seals they were to follow, which the
slices record.

### E4 — scope stage and the scope gate

**Delivers:** the scope gate, `internal/engagement/gate`, the one place an HTTP request,
API call or DNS query is sent, with rules defined by the `security-consultant` and
specified in `spec/scope.md`, "The scope gate":

- requests as registered operations, never URLs, with an invariants test;
- admission in a fixed order: scope, exclusion, level, entry points, first-party
  evidence and windows, decided from the engagement file and live resolution, never
  from `scope.json`;
- names re-resolved at send time, every address checked, special-purpose and metadata
  addresses refused;
- no automatic redirects, verified TLS with no bypass, no proxy, an honest User-Agent;
- `GET` and `HEAD` only, plus one declared token exchange;
- credentials from the environment, attached by the gate and redacted by value;
- a response pipeline that redacts the raw bytes before parsing, drops excluded items
  failing closed, projects to declared fields and caps size;
- per-provider throttle ceilings with rate-limit headers, per-request timeouts under
  `limits.timeout`, and bounded retries;
- an audit line written before each request is sent;
- authorization windows, which nothing in 0.0.2 needs but every later level checks.

Around it:

- expansion of roots by passive discovery (DNS, certificate transparency), with
  dangling records recorded and never contacted;
- `exclude`, including repositories, organizational units and projects under a root;
- first-party evidence per asset, with the operator's confirmations as `first_party:
  {confirmed_by, date, target}`, written by hand in 0.0.2, bound to the target they
  confirmed and valid for a year (the Scope prompt arrives with probes in 0.0.3, after
  the observe reads, redesigned with the `client`: who runs the server, fixed
  answers, grouped, "decide later");
- the resolved list with `--stop-after scope`, printed without waiting when there is
  no terminal;
- third-party sources as a declared list, printed in the report as "What left this
  machine", with "nothing was sent to the makers of scheck" pinned by a test;
- the gate's own DNS client, for discovery and for every request it sends: rcodes and
  CNAME chains, the resolver it names is the one it asked;
- per-request status for resume, each retry admitted again, with a host resumed as a
  unit;
- the compiled redaction rules' JSON key/value rule and Google, Stripe, npm and Slack
  webhook shapes, which change host redaction too; no host golden changed.

Decided in this slice: repository history is read in-process from the operator's
`git clone --mirror` checkout (`spec/scope.md`, "Repositories"), with no git transport.

Built in four steps, reviewed as E2 was:

1. The gate core and the registry, tested with a fake op.
2. The response pipeline and the redaction rules.
3. Scope and passive discovery.
4. Resume and windows, in two reviewed halves:
   - 4a, the gate: authorization windows and the resume ledger (a request's identity,
     earlier successes answered without sending), proving 20 and 21 at the gate;
   - 4b, `scheck run <directory>`: the lock and a directory refused when it holds a
     link, a special file, a file another user owns or another hard link reaches, or a
     file or directory others may write, the directory it sits in included, `run.json` with the
     recorded file and the hash of every file a stage wrote, the file a resume read and
     its hash printed on stderr every time, Scope kept while what it read is unchanged, a
     host kept as a unit from its one collection record and an envelope whose hash
     matches it, the gate's
     successes listed in `run.json` handed to the next session's gate, the report's
     `resumed` and `edited_by_hand` pinned by the `resumed` goldens, and "What left this
     machine" covering every session, "at least" when one ended before recording what
     it sent (`spec/runs.md`, "Stop and resume"). Decided 2026-10-08: a changed
     accepted risk on a host collects that host again, since nothing regrades a kept
     envelope, which adds only contact the file already authorizes. The report's changed
     principal goes to E5, the first collector that reads a principal, and reading again
     only what a changed `mail` or `intent` URL affects goes to E7.

**Done when** gate tests against `httptest` servers and an injected resolver and dialer
prove:

1. **Unknown op:** an unregistered op is `refused:unknown_op` with zero dials, audited,
   and the asset's coverage reason is `unavailable:refused_by_gate`.
2. **Out of root:** a request for another organization's repository is
   `refused:out_of_scope`, and the fake server sees nothing.
3. **Excluded asset:** a per-user op on a user in `/Board` or `/Board/Sub` is refused,
   while `/Boardroom` is sent.
4. **List drop:** an excluded repository in a list response is absent from evidence,
   findings, the report and the audit log. The drop is audited by count, and the row is
   at most *partial*.
5. **Excluded-subject set:** items referencing an excluded user are dropped. When the
   users list failed, the op is `unavailable:exclusion_unknown` and nothing is stored.
   An item without its exclusion key is dropped and counted as unattributable.
6. **Rebinding:** a name re-pointed into an excluded range between Scope and the
   request is `refused:address_excluded` with no dial.
7. **Every address checked:**
   - an answer with one public and one excluded address refuses the name;
   - an answer of 169.254.169.254 or `::ffff:127.0.0.1` is refused even under a
     `network` root.
8. **Dangling record:** a CNAME chain ending in NXDOMAIN is reported with zero dials and
   no search-domain query; NODATA is dangling too, and SERVFAIL is insufficient
   evidence. A resolver that rewrites NXDOMAIN, and a root with wildcard DNS, are
   caught by the control queries, with nothing read on the matched names.
9. **Discovered names:** for a discovered name without first-party evidence, the
   server sees exactly `GET /` over https and over http, and one TLS handshake; a
   collector's request for `/robots.txt` on it is `refused:entry_point` and audited.
10. **Entry points:** a `url` root reads only its entry points, `robots.txt` and
    `security.txt`.
11. **Redirects:** a redirect off scope is recorded, not followed. A pagination link to
    another host is rebuilt or refused.
12. **TLS and proxies:** an invalid certificate is a finding and the server's HTTP
    handler is never invoked. No `InsecureSkipVerify` exists outside tests. With
    `HTTPS_PROXY` pointing at a fake proxy, the proxy sees nothing and the note
    prints.
13. **Redaction:** each of these is absent from every output and the run directory, with
    its marker present:
    - a `redact_extra` string in a body, header and error body;
    - `{"access_token":"ya29…"}`;
    - a token echoed in an error.

    Redacted JSON still parses. Under `"password"`, each quoted `yes`, `no`, `true`,
    `false`, `none`, `null`, `on`, `off`, `x`, `*`, `-`, `required`, `optional`,
    `prompt` and `ask` becomes a `json-secret` marker; `true`, `false`, `null`, `0`,
    `1`, `"0"`, `"1"` and `""` are kept byte for byte; `{"secret_scanning":{"status":
    "enabled"}}` is kept; the same body as a 2xx and as a 4xx error body reveals the
    same values; the host goldens are unchanged and `PermitEmptyPasswords no` survives
    `kv-secret`. A `set-cookie` value and an unlisted header are absent
    from the run directory. A gzip bomb, a content-type mismatch and JSON over its cap
    each give their `unavailable` code with nothing stored.
14. **Credential:** the token never appears in the audit log, URLs or error strings, and
    a request to a web asset carries no `Authorization`.
15. **Methods:** the registry invariant rejects a non-`GET` op outside the allowlist,
    an op missing a declared field, and a list op over an excludable kind with no
    exclusion key. A full fake run sends only `GET`, `HEAD` and one `POST` to the token
    endpoint, and neither that body nor its response appears anywhere in the run
    directory.
16. **Rate limit:**
    - a 403 rate limit is `limit_reached`;
    - a `Retry-After` beyond the deadline stops at once with exit 2;
    - the remaining floor stops the run before the limit is exhausted.
17. **Permission traps:** a 404 on a known subject is `insufficient_permission`, and a
    403 with `X-GitHub-SSO` is `insufficient_permission:sso_authorization`.
18. **Deadline:** a run past `limits.timeout` cancels the request in flight, marks the
    rest not sent and exits 2.
19. **Population:** a list cut by a cap is marked incomplete in its evidence, and a
    test rule over it, through the rule evaluator, fires, is never disproved, and
    prints its count as "at least". E4 proves the page's population and the predicate
    (`AnyRecord` over a partial population); the rule evaluator reads no collector
    evidence before a collector lands, and E5's first list rule carries this test
    through it.
20. **Resume:**
    - a rate-limited request is sent again and kept;
    - a refused request is re-admitted and refused again;
    - successes are not resent;
    - a changed principal resends everything.
21. **Window:** a test-only probe op outside every window is `refused:window`, and
    inside one it is cut at the window's end.
22. **Audit:** every request has a line written before it was sent, and the line
    survives a crash mid-request. `--no-persist` with a domain, url, network, SaaS or
    repository root, or a url asset under a host root, exits 3 with no connection and no resolver query; `--host local`
    and `--host user@h` with `--no-persist` still run; `gate.New` without an audit log
    that keeps its lines is an error; a failed audit write is
    `unavailable:audit_failed` and never dialled.
23. **Egress:** the report's "What left this machine" lists `crt.sh` with the roots
    queried, the DNS resolver with its query count, and the model line; a CNAME target
    outside every root is listed and never dialed; an email identity in a
    certificate-transparency answer is absent from every output, with its count
    present. A `--host local` run prints `none` for third-party sources, its one host,
    and the model line. (A certificate-transparency name outside every root cannot be
    tested here: `crt.sh` returns only the identities that matched the query, so
    "other names on your certificates" comes from the handshake in E7.)
24. **Credentials:** the gate's credential step refuses a request with no credential
    as `no_credentials` and a rejected one as kind `access`, proved with a test-only op.
    No root is checked for a credential before a collector would use it: the warning
    before any contact (exit 2) and the rejected credential (exit 3, the other assets
    still collected) are proved end to end in E5 and E6, whose collectors use them.

**Carried from E4 step 4a:** 20's "a changed principal resends everything" is proved at
the gate by the identity (another principal or scope set gives another identity) and by
a success on record under a principal the gate does not know being sent again; E5,
whose principal op tells the gate who a credential is, carries it through a real
principal. A web asset's vantage joins a request's identity in E7 step 5
(`spec/scope.md`, "Resume").

**Deferred from E4's design review** (a modularity pass over the gate, kept here so the
slices that add callers do them first):

- before E5 and E6: the provider table carries what is now hard-coded per provider (a
  display name, page keys, rate-limit recognition), so a collector adds one entry, not
  six edits in two packages; a list declares its item's subject as a template
  (`repo:github:{key}`), as an op's subject already is, so the gate stops writing the
  engagement's id syntax; org-unit matching moves behind `Scope`, beside every other
  exclude match;
- before E7, done in E7 step 1a: `Scope.Site`, paths partitioned by the evidence each
  needs, became one `Scope.Admits(origin, path, lookup)` decision written once in the
  engagement. The gate asks it at steps 7 and 8 and, when the answer needs the lookup,
  again at step 12 (`spec/scope.md`, "Admission"); discovery's listing decides
  first-party evidence after resolution with the same function, and the report counts
  a site as first-party from the gate's answer;
- with E7's first op, E7 being the first network collector, done in E7 step 1a ahead
  of it: a request's `Reason` comes from its decision by one table, and only a sent
  request's from its status; the gate's longest functions (`attempt`, `send`, op
  validation, discovery's per-root loop, `shape`) are split into steps, `attempt`'s in
  the order of `spec/scope.md`, "Admission".

**Deferred from E4's slice-closing review** (2026-10-08), each carried by the slice
named:

- done in G3: the per-asset mode check of `spec/scope.md`, "Admission", step 6 exists
  (`Scope.Allows`) and the gate's `ceiling` is the constant *probe*; the window tests
  run on real probe ops.
- done in E7 step 5: each session's site request counts remain split by
  first-party status across sessions, so later evidence never moves earlier
  unconfirmed requests into "websites shown to be yours".
- E7: `unavailable:blocked`, a firewall that blocks scheck's User-Agent, is the web
  collector's to decide from the page it is served (`spec/scope.md`, "Connections").
- E5, E6, E7: a collector marks coverage by `spec/scope.md`'s "Outcomes" table, its
  row for a request that got no answer (`unavailable:connection_reset`,
  `unavailable:timeout`, `unavailable:unreachable`: exit 2 for what was declared)
  included.

### E5a — people, access and acceptances

**Why now:** the security-consultant's review of `spec/engagement.md` (2026-10-09) found
that the people-and-access model E5, E6, E8 and E9 all build on would have been a
migration across three collectors once they existed, and that the first report a reader
saw was topped by a false critical. Defined by the consultant the same day; the owner
adopted the recommended answers.

**Delivers:**

- A finding definition declares a subject kind (`finding.Def.Subject`, from the closed
  list in `spec/report.md`, "Findings"), checked by the invariants test; an accepted
  risk for such an id must name its subject, or validation exits 3 (`spec/engagement.md`,
  "Accepted risks"). No host finding declares one in 0.0.2: host acceptance by subject
  arrives with the listener slice.
- `access.mfa[].enforced` is `everyone | admins | some | none | unknown`; true and false
  exit 3 as ambiguous; a tenant appears once.
- `people`: `workspace` and `github` are lists; kinds are `employee`, `contractor`,
  `shared` (with `used_by`), `service` and `break_glass` (`agency` is gone: a contractor
  is `contractor` with `org`); an admin listed for a tenant must have an identifier for
  it; `kind: ""`, which the recon stanza prints, exits 3 asking for the kind.
- The spec for what E5 and E6 build on it: the admin definition per provider, the
  too-many-admins rule, the 2-step verification comparison, the alias rule, provider-id
  binding in run state, the narrowed service and break-glass exemptions, and the recon
  stanza and what it must never do (`spec/engagement.md`, "People", "Admins",
  "2-step verification", "The recon stanza").
- `accounts.empty_password` reads `/etc/passwd` beside `passwd -S -a` and fires only on
  an account with a login shell, at high (`spec/host-collector.md §6.5`); libuser's `PS`
  and `LK` are recognized; an empty status listing is insufficient evidence. The
  many-findings golden takes the finding from the rule over edited captures, not from an
  injected `backup NP` its own fixture disproved. The evaluation case `linux-empty-password` gains the
  `/etc/passwd` line its `passwd -S` listing assumed for `deploy` (a login shell); its
  base fixture had none, so the rule rightly abstained. Its label is unchanged. The
  host fact summary counts "with a login shell" by the rule's own shell lists
  (`internal/check/shells.go`), so a report never calls an account a login account in
  one line and not the next: Ubuntu's `sync` and Fedora's `sync`, `shutdown` and `halt`
  no longer count, and an empty shell field does. The assessment names the second check
  (`with`, `with_observation`), the host report schema going to 1.7, and coverage names
  that check when it was missing.

**Done when:** every validation error has a test with its wording; the empty-password
rule passes the consultant's fixtures (fires, disproved, insufficient, including a
denied or disabled `/etc/passwd`); the real Ubuntu and Fedora fixtures, all locked, give
the same verdict as before and the command traces are unchanged.

**Open, for the owner (consultant's recommendation in brackets):** whether to add
`sshd.permit_empty_passwords`, medium, a single-fact rule on the existing `sshd.config`
check [yes, cheap]; `attribute:uid0` raising an empty password on a uid-0 account to
critical [yes, with E9's attribute mechanism]; keeping Workspace's `name.fullName` as a
declared label and stanza field [yes]; an organization Actions secret visible to all
repositories as `secret_location` keyed `actions:<name>` or a new kind (E5).

**Carried:** each subject kind's shape is validated (`org_unit` starts with `/`, a
`service` is `<port>/<proto>`, a workflow is a `.github/workflows/` path) when the
collector that declares the kind lands (E5, E6); empty password raised to critical by
the E9 multi-fact rule `sshd.empty_password_login` (`permitemptypasswords yes` with
password or keyboard-interactive login, and the shell; high for a refusing shell when
TCP forwarding is allowed, since nologin does not stop `ssh -N`); done in E7 step 5:
`--vantage internet` from an office the admin panel allowlists gives a false
contradiction, so the flag help, the warning and the finding define "internet" as
outside every address the page allows (not the office, not the VPN).

### E5 — GitHub organization and repository secrets

**Delivers:** a GitHub collector with a read-only token from the environment and a
declared list of read operations through the gate: two-factor requirement, owners and outside
collaborators, default workflow token permissions, branch protection on default
branches, third-party actions pinned to a commit and their use in `pull_request_target`
workflows, the names (never the values) of organization and repository secrets, deploy
keys with write access, pending invitations, and Dependabot and secret-scanning alerts
where the token can read them. A secret scan of repository history, read in-process from
the operator's mirror checkout (`checkout`, decided in E4), redacted in every output.
Recognized assessment-token scopes beyond reads produce an unranked run warning,
not a finding. People are matched by login only, over every login a handle lists
(`spec/engagement.md`, "People"); owners against `access.admins`, too many owners,
an owner nobody can name and a contractor or shared account that is one, as
`spec/engagement.md` "Admins" defines them; the organization's 2FA requirement against
`access.mfa` ("2-step verification"); the recon stanza of unattributed accounts. Each
finding declares its subject kind (consultant's E5a list: `account` for members and
collaborators, `invitation`, `repository`, `branch`, `workflow`, `deploy_key`,
`webhook`, `secret_location`, `principal`, `oauth_app` for App installations; none for
the organization's 2FA requirement, too many owners and the default workflow token).
Every base E5 assigns is placed against the base severity anchors frozen on 2026-10-09
(`spec/engagement.md`, "Severity in context").

What a token cannot see is *insufficient evidence*, never a pass: the organization's
two-factor requirement is visible only to an owner's token and is three-valued (absent
is insufficient, never "not required"), the `2fa_disabled` member filter is trusted only
for an owner's token, and whether a fine-grained
token or an App has more than read access cannot always be read. The token advice in refusals and
coverage says to get it from an organization owner: a fine-grained token may need the
organization's approval, and owner-only fields need an owner's token.

**Done when:** tests against a fake GitHub API server cover every rule's three outcomes,
including a non-owner token on the two-factor rule; a seeded secret never appears in any
output and its marker does; no non-`GET` request is ever made; a resume under another
principal, told apart by the principal op, sends again every request the first one's
successes would have answered (carried from E4 step 4a) and prints the changed principal
in the report's header (`spec/runs.md`, "Stop and resume", carried from E4 step
4b).

**Build steps** (security-consultant DEFINE, 2026-10-09; steps 1–6 built with
offline checks and consultant/client/adversarial reviews; step 6's history rules
and permissions frozen on 2026-10-10):

0. **Contract preparation.** Split the engagement spec and audit citations; draft the
   operation/permission and rule-outcome tables; review bases before their
   definitions are fixed. Assessment-token reporting is resolved on 2026-10-10
   as described below. The required E3 rest-lab seal before the first E5 commit
   is not established; the implementation session never opens sealed labels.
   This preparation step is documentation only.
1. **Gate foundation (built).** Move provider display, pagination and rate-limit metadata
   into the provider table and list-item subject templates into operations, as E4's
   review requires. Preserve every existing admission and response guarantee.
2. **Principal and organization inventory (built).** GET-only PAT/App-user principal,
   verified own membership, organization metadata, members/owners, outside
   collaborators, invitations and repository inventory; projected evidence,
   permission/population gaps, changed-principal resume and header tests. Unsupported
   installation principals stay unknown and authenticated successes are not reused.
   No later rule id or optional check is introduced in this step. Inventory counts
   are observed or lower bounds, never assessed security controls; applicable risk
   areas remain `not_assessed` with `no_rule`. Repository token visibility remains
   unknown after complete pagination. Response/page caps are `limit_reached` with
   exit 2; coverage counts successful inventory reads rather than execution status.
   Assessment-token reporting is resolved below. The E3 preimplementation rest-lab
   seal is not established; no live acceptance is claimed.
3. **Identity and repository access (built).** E5a people/admin/MFA conditions gain
   their finding definitions and rules; repository `public` intent, default member
   permission, production outside-admin and write deploy-key rules. Five compiled
   reads add owner-gated MFA filters and exact repository objects, collaborators and
   deploy keys. Fourteen finding ids, bases, subject keys, privilege recognition and
   three outcomes are frozen in `spec/github-collector.md`, "Rule evidence".
   Missing authority sends no owner-only MFA filter; partial populations can fire
   but never disprove. Collaborator visibility stays unknown after pagination.
   Recon prints per-account candidates and exact attribution; readout notes consume
   shared-account users, recovery accounts, pending owner invitations and MFA beliefs.
   Delegated organization roles, repository invitations, sign-in
   dates and unobserved private repositories remain unassessed. CI, secrets and
   history remain later steps. The E3 preimplementation rest-lab seal is not
   established; live acceptance remains pending.
   Adversarial-review defects in repository provenance, recon privilege labels, MFA
   readout counts, per-asset offboarding instances and covered-asset inventory were
   fixed with regression tests. None of those review defects is deferred.
4. **CI controls (built; verified offline).** Security-consultant DEFINE on
   2026-10-10 freezes six finding ids, bases and three outcomes in
   `spec/github-collector.md`, "CI controls: step 4 definition": separate
   organization/repository write defaults, default-branch protection presence,
   mutable references, mutable step dependencies with mutation permission, and
   requested PR-controlled execution with write permission. Six GET templates pin
   workflow reads to the exact default-branch SHA. Bounded sanitized YAML,
   permission-vector replacement, supported triggers/refs/execution and caps are
   versioned; unsupported evidence stays unknown. The PR-target rule is medium
   (high for declared production), never an execution or exploitability claim.
   Runtime policy and checkout protection remain gaps. Runner access and App
   findings/operations are deferred; literal runner requests are notes only.
   Offline fixtures prove all three outcomes, permission replacement, supported
   command shells, redaction before persistence and GET-only SHA-pinned requests.
   An end-to-end fake-server run retains secret markers but no seeded secret in
   report, audit or persisted evidence. Consultant REVIEW clarified shell support,
   branch-protection remediation and the unassessed job container/service images.
   Full `make check` and `make build` pass. Consultant REVIEW, Brightcart/Dani
   client REPORT and the final fresh adversarial review pass. Invalid event, job
   and step structures abstain in positive and negative regression fixtures;
   unsupported runner selection leaves the entire direct job unassessed, including
   reference pinning. All reported review defects were fixed; none is deferred.
   The E3 preimplementation rest-lab seal is not established; live acceptance
   remains pending.
   The 2026-10-10 live software test identified rejected numeric workflow fields
   and redaction of runtime token references. Grammar revision
   `github-workflow-syntax:2026-10-10.2` accepts bounded decimal numbers without
   string coercion; workflow-only policy redaction preserves whole exact built-in
   token references while credential and extra detectors remain active. Empty
   permission diagnostics explain unavailable access or feature evidence, and
   Dependabot next steps include repository selection and feature availability.
   These fixes do not establish live security acceptance.
5. **Secret metadata and provider alerts (built; verified offline).**
   Security-consultant DEFINE on 2026-10-10 fixes six compiled metadata GETs and
   five rule ids in `spec/github-collector.md`, "Secret metadata and provider
   alerts: step 5 definition": organization all-repository secret sharing, three
   Dependabot severities and supported commit-location provider-secret findings.
   Secret values, arbitrary metadata and error bodies never persist; selected
   repository items are scope-filtered without authorizing child reads. Page,
   cursor and follow-up limits preserve affirmative findings but prevent absence
   claims. Provider severity/validity remain provider reports, not exploitation or
   credential tests. Public visibility raises provider-secret findings only;
   Dependabot has no automatic production/public adjustment. History, App grants,
   runner access remain deferred. Assessment-token reporting is resolved below.
   Every rule has fired, disproved and abstained offline fixtures; fake API tests
   cover secret removal, unsupported locations and request pagination. Consultant
   and client review fixes preserve partial family coverage for incomplete owning
   populations, direct-request provenance for public severity, provider high/critical
   wording and dependency-specific caveats. Provider-closed alerts still reported
   active as `wont_fix` have an unranked follow-up note before the summary ranking,
   without creating a finding or changing the exit count. Full `make check`
   (vet, fix, zero lint issues, dependency checks and race tests) and `make build`
   pass. Consultant REVIEW, Brightcart/Dani client REPORT re-review and final
   fresh adversarial review pass. All reported review defects were fixed; none is
   carried. The E3 preimplementation rest-lab seal is not established; live acceptance
   remains pending; no live acceptance is claimed.
6. **Confined history reader — built and verified offline.**
   The security-consultant DEFINE on 2026-10-10 freezes the contract in
   `spec/github-collector.md`, "History": ordinary SHA-1 bare mirrors; one
   read-only `os.Root` boundary in the gate; conventional matching mirror config;
   loose objects, PACK/index v2 and cross-storage deltas; all-ref/all-parent tree
   traversal; fixed budgets and fresh branch/pull ref comparison through two GETs.
   Repository assets accept an absolute `checkout`. No Git invocation, transport,
   mirror write or new dependency. The rules are `github.history_credential`
   (high) and `github.remote_credential` (medium), both per `secret_location`.
   Only safe markers and locations survive; compiled existing redactor detectors
   and the exact run credential detect, without entropy heuristics. Resume rescans
   and obtains fresh refs. Missing API evidence, unsupported formats, mutation and
   caps never support an absence verdict. Consultant-approved partial continuation
   ignores unsupported on-disk mechanisms while reading independently validated
   ordinary confined objects; strict config admission still applies. No alternate
   or replacement is followed, no object fetched and no absence claim permitted.
   Packs stream with no decoded-object cache
   and 128 MiB resident-buffer reservations, including retained findings/redactions
   and traversal bookkeeping. Full tree paths are capped at 4,096 bytes before
   join allocation, as approved by the consultant. Local audit records contain execution
   status and numeric counts, with no content hash. Local observations retain their
   own actor/time; partial mirror counts and actionable gaps remain visible.
   Unit and fake-API tests cover all three rule outcomes, packed/loose/delta reads,
   confinement, limits, fresh resume and seeded all-output secrecy. Three history
   report outcomes are pinned by goldens. Consultant REVIEW re-review passes after
   its two wording should-fixes; final client REPORT re-review passes without
   blockers. Full `make check` and `make build` pass. The first adversarial pass
   confirmed three must-fix defects: root acquisition races, index allocation/accounting and silent detector
   candidate exhaustion. Fixes anchor root acquisition and verify directory identity,
   reserve conservative index accounting before allocation, and make raw candidate
   exhaustion incomplete while retaining positives. Detector transient buffers
   reserve 32 MiB inside the existing 128 MiB budget. A second review confirmed
   uncharged directory-list allocation as a fourth must-fix. Lists reserve 1 KiB per entry before `ReadDir`,
   including overflow, bounded by the available resident budget; recursive parent
   and pack lists retain their charge until no longer used. Regression tests cover
   list limits. Pending parent identities copy only their 40-byte SHA, and header
   iteration avoids a split-line array. A subsequent fresh review found a fifth
   must-fix: quoted `core` or `extensions` subsections could be mistaken for ordinary admission settings.
   The fix rejects every such subsection, including empty quotes; full collector
   regressions prove no history or origin disproof for all four forms. All five
   confirmed defects are fixed and re-reviewed. Full checks and build pass after
   the final config-admission and inflation-buffer fixes. The fresh final
   adversarial review passes with no must-fix, should-fix or nit; no reviewed
   defect is deferred. The E3 preimplementation rest-lab seal is not established;
   live acceptance remains pending.
7. **Closing review — built and verified offline.** Whole-slice consultant REVIEW and
   client REPORT pass. Client wording improvements clarify inventory-only and
   zero-decided reports, place the differing-mirror-ref action before the ranking,
   identify the credential owner and assign origin cleanup to the mirror maintainer
   after revocation or rotation. A confirmed closing self-audit defect classified
   an over-cap loose object as corrupt instead of `limit_reached`; the fix checks
   the expansion limit first and separately bounds decoded payload length, with
   one-byte and 1,024-byte over-cap regressions proving no absence verdict.
   Spec sync/audit, full `make check` and build passed before the whole-slice
   adversarial review. That review confirmed one must-fix: the 10,000 advertised
   ref cap did not mark the affected read `limit_reached`, allowing exit 0 or 1
   despite partial history. The fix retains the limit reason, gap and detail;
   collector and fake-API regressions with 10,001 refs prove exit 2, retained
   positive findings and no negative verdict. Targeted tests, final full
   checks and build pass; the fresh review of the fix passes with no must-fix,
   should-fix or nit. No reviewed defect is deferred. Every built rule
   has firing, disproved and abstained fixtures. Live lab measurements are **not
   run**. This review does not claim E5 release acceptance: no E3 preimplementation
   rest-lab seal is recorded. That prerequisite is not established; a later seal
   cannot establish preimplementation blindness.
   See `eval/e5-closing-review-2026-10-10.md`.

**Assessment-credential decision and evaluation plan** (2026-10-10): the owner
adopts the consultant's unranked run warning, defined in
`spec/github-collector.md`, "Principal and resume". This closes the token-reporting
choice without adding network calls or changing findings, coverage or exit counts.
No E3 preimplementation rest-lab seal is recorded; a later seal cannot establish
preimplementation blindness. A separately authorized, team-owned lab needs fresh
independent seeder and ranker sessions, labels inaccessible to implementers until
measurement, frozen clean-variant/false-positive criteria and recorded full,
clean, context and missing-credential runs. This would be a postimplementation
independent evaluation, not satisfaction or waiver of the unmet preimplementation
prerequisite. Release acceptance remains pending owner handling of that prerequisite
and the live measurements. No blind seeding, ranking or live assessment runs in this
implementation session. See `eval/e5-credential-decision-2026-10-10.md`.

**Resolved in step 7 from the inventory client review** (2026-10-10): the empty
ranking says “No security rules ran; this report contains inventory only” when no
rule was selected, and “No security verdict was possible from the collected
evidence” when none decided. Coverage and exit semantics are unchanged.

**Collector cleanup before E6:** web, GitHub and the report share
`finding.Judgment` and `finding.Subject`, retaining persisted field names and
wildcard members. GitHub owns its read explanations and coverage-reason mapping;
web owns mail normalization and rule-input assembly from `ScopeView`. Engagement
keeps scope interpretation and final report authorship. Stage documents and web
collection helpers live in `stage_docs.go` and `collect_web.go` within the same
package. This cleanup changes no rule, report wording or network operation.
Definition registration, collector report fragments and gate restructuring are
left out; no new enforcement path is introduced.

**Resolved in step 7 from the step 6 client review** (2026-10-10): differing-ref
update/resume notes precede the summary ranking; history remediation identifies the
credential owner while retaining the authenticity/usability limitation; the mirror
maintainer revokes or rotates an origin credential before cleanup. Synthetic report
fixtures explain “mirror” and “origin” like production notes. These changes add no
finding and change no coverage or exit count.

**Deferred, owner unassigned:** App grant and installation-principal evidence,
runner access and runner-group/public-repository scope await a reviewed DEFINE.
No later roadmap slice owns these reads yet; their assignment remains an open
decision, and this closing review does not invent it.

**Carried from E4's reviews:** before E5's first op, unless E6 did it first, the provider
table carries what is now hard-coded per provider (a display name, page keys, rate-limit
recognition), so a collector adds one entry, not six edits in two packages, and a list
declares its item's subject as a template (`repo:github:{key}`), as an op's subject
already is. Coverage is marked by `spec/scope.md`'s "Outcomes" table, a request that got
no answer exiting 2.

**Carried from the engagement-spec review** (security-consultant, 2026-10-09):

- *Engagement-spec split completed before E5's spec text:* report order, wording,
  coverage, ranking, findings and JSON are owned by `spec/report.md`; run directories,
  `run.json`, locking and resume by `spec/runs.md`; the `scheck.yaml` and alias tables
  by `spec/host-collector.md §8`; domain acceptance ownership by
  `spec/web-collector.md`, "Subjects". Exit outcomes are owned by `spec/scope.md`,
  "Outcomes", reachability by `spec/web-collector.md`, and whether asset entries add
  scope by `spec/scope.md`, "What is in scope". Citation updates and the
  `spec-steward` audit accompany the split.
- "Which repositories are public on purpose": `public: true` on a repository asset,
  and an undeclared public repository is the finding (`intent` holds URLs only).
- Anchors for self-hosted runners on public repositories (high), GitHub App
  installations with write on all repositories, outside collaborators with admin on
  production repositories, and the organization's default member permission.
- Assessment-token reporting is resolved on 2026-10-10: recognized beyond-read
  OAuth scopes produce an unranked run warning with remediation, never a finding
  or exit input. Exact supported read scopes carry a narrow informational note;
  missing, unsupported or unknown capability is never read-only. The full
  interpretation is in `spec/github-collector.md`, "Principal and resume".
- Under *not assessed*: GitHub shows no sign-in dates, so a former member nobody
  listed cannot be told apart from a current one; and SAML single sign-on, if enforced,
  does not cover git over SSH or tokens, which the 2FA rules list under what they did
  not check.
- SAML or SCIM linked identities may *suggest* `people` entries, never attribute one.
- Each risk area E5 marks lists its sub-items from the practitioner's list, not from
  the rules built, so an unbuilt one is `no_rule` and the row *partial* (owned by E9,
  below).

### E6 — Google Workspace collector

**Status:** DEFINE design frozen on 2026-10-10. Steps 1 and 2 implement credentials,
tenant binding and inventory through engagement Recon and report integration.
Step 3 implements identity/admin rules, verified offline. Step 4 implements observed
2-step verification, verified offline. Step 5 implements optional OAuth grant
metadata, verified offline. Step 6 implements optional Gmail forwarding metadata,
verified offline. Step 7, the whole-slice offline reviews and separately
attributed live measurements on one authorized tenant, is recorded in
[eval/e6-closing-review-2026-10-12.md](eval/e6-closing-review-2026-10-12.md).
That record is not acceptance. Recall, false positives and the missed E3
rest-lab seal were not passed, and the 0.0.2 release gates are not passed.
The design is
[spec/workspace-collector.md](spec/workspace-collector.md). Assessment-credential
grants beyond reads produce an unranked warning, as in E5, not a posture finding.
Unknown grants remain unknown; a successful read does not prove write capability.

**Build steps:**

0. Freeze the evidence, rule outcomes, permission surface, severities and coverage
   with the security-consultant. **Done 2026-10-10:** AI consultant DEFINE/REVIEW,
   client wording review and spec audit are recorded in
   [eval/e6-definition-2026-10-10.md](eval/e6-definition-2026-10-10.md).
   Independent lab preparation and acceptance remain pending; recording the missed
   historical seal does not satisfy or waive it.
1. Gate foundation: supported Google credentials, audited token exchange and minimal
   customer/domain bootstrap that binds the declared root before tenant reads.
   **Done 2026-10-10, library only:** strict restricted ADC loading, in-process RSA assertions,
   private audited token exchange through `Send`, ordered customer/domain/alias
   binding and no ledger reuse while the principal is unknown. Every profile uses
   baseline Directory scopes for bootstrap; optional token attempts belong to
   steps 5 and 6 and never block baseline reads. No live Workspace
   request, stage wiring or inventory is claimed by this step. Exclusion admission
   and delegated-user verification belong to step 2. The targeted authentication
   DEFINE contract is recorded in
   [eval/e6-authentication-definition-2026-10-10.md](eval/e6-authentication-definition-2026-10-10.md),
   including green offline checks and a fresh adversarial review with no findings.
   These are software-verification results, not independent security acceptance.
   **Foundation cleanup:** `Bind` owns ordered bootstrap through `Sender`, with unexported
   bootstrap ids and an explicit failed read for an unusable final summary. The gate
   owns customer selectors and the three exact bootstrap endpoints; ordinary bound
   reads use the standard compiled projection and redaction pipeline. Caller-supplied
   customer ids are refused, and HTTP 401 drops authentication and binding. Ordinary
   op definitions are not repeated in gate validation. Query-based customer selection
   and paging admission land in step 2.
2. Tenant inventory: domains, organizational units and users, exclusions before
   persistence and follow-ups, stable account ids and people attribution.
   **Implemented:** one `workspace.Collect` call owns binding, recognized domain/alias,
   complete unit-tree and customer-bound user reads, people attribution and notes.
   Query selectors and pagination remain gate-owned. Excluded identities never leave
   the gate; partial populations carry lower bounds. Actual cuts and unknown/conflicting
   identities prevent delegated follow-ups; known exclusion drops permit details only
   for current admitted nonexcluded users. Root-parent sentinel compatibility remains
   unmeasured live.
   A service-account delegated subject is verified against current admitted stable ids;
   authorized-user callers stay unknown. Resume repeats admission and reuses no
   authenticated Workspace reads. Report coverage says `no_rule`: inventory alone
   assesses no Workspace security control. **Done 2026-10-10:** consultant/client/module
   reviews and final offline checks passed. A fresh adversarial review found cursor
   completion and stale continuation defects; both were corrected and a fresh
   follow-up review found no confirmed findings. Verification is recorded in
   [eval/e6-inventory-verification-2026-10-10.md](eval/e6-inventory-verification-2026-10-10.md).
   No live request or independent acceptance is claimed.
3. Identity and admin rules: declared admins, super-admin counts, departed and stale
   accounts, and suspended accounts retaining direct or indirect administrative roles.
   **Done offline 2026-10-10:** one collector call owns roles, bounded privileges,
   admitted per-user direct/indirect assignments and fresh details, with nine
   three-outcome rules and explicit interpretation gaps. Consultant, client and
   modularity reviews passed. The adversarial review found malformed expiry and
   privilege projection plus a fresh-login regression; corrected regressions,
   green `make check` and a fresh follow-up review with no confirmed findings are
   recorded in
   [eval/e6-identity-verification-2026-10-10.md](eval/e6-identity-verification-2026-10-10.md).
   The targeted definition remains in
   [eval/e6-identity-definition-2026-10-10.md](eval/e6-identity-definition-2026-10-10.md).
   Optional attribution caching is deferred without security implications. No live
   measurement or independent acceptance is claimed.
4. Observed 2-step verification: per-account enforcement and enrollment, compared
   with the operator's current requirement; no inferred unit policy or grace window.
   **Done offline 2026-10-11:** `workspace.two_step_not_enforced` (high, per direct
   unit) and `workspace.admin_without_two_step` (high, per account), each with firing,
   disproved and abstained fixtures; fresh detail fills only missing list flags, and
   conflicting, malformed or refused detail makes only the 2-step rules abstain. The
   collector decides the `access.mfa` comparison once and owns the readout notes;
   raised instances carry `contradiction` and a caveat about another identity provider
   (worded from `sign_in` since 2026-10-18, see "Carried from step 4"). Coverage adds the
   2-step sub-item with explicit limits, *not assessed* when no 2-step outcome was
   recorded; OAuth grants and domain-wide delegation stay *not assessed*. Consultant,
   client and modularity reviews passed. The adversarial review found no must-fix; its
   should-fix (a 2-step sub-item `not_applicable` with no outcome) and nits were
   corrected, and a fresh follow-up review found no must-fix or should-fix. Green
   `make check` and both reviews are recorded in
   [eval/e6-two-step-verification-2026-10-11.md](eval/e6-two-step-verification-2026-10-11.md).
   The targeted definition remains in
   [eval/e6-two-step-definition-2026-10-11.md](eval/e6-two-step-definition-2026-10-11.md).
   No live tenant was contacted and no independent acceptance is claimed.
5. Optional OAuth grant metadata, using an existing approved credential; no
   automatic request for a broad security grant.
   **Done offline 2026-10-11:** under `directory_oauth` or `directory_oauth_mail`, the
   gate mints a separate token with exactly `admin.directory.user.security` through its
   own audited exchange after baseline admission, remembers a failure for the session
   and clears both with the binding; a refused scope is a coverage gap, never exit 3.
   The collector reads every admitted account's grants in priority order, stopping on
   the gate's `Result.Repeats`; the gate drops items naming another user (`SelfRef`).
   `workspace.oauth_broad_scope` (medium, per client id, `+1 attribute:admin_grantor`
   only on a known-active super admin's or declared break-glass account's own broad
   grant) has firing, disproved and abstained fixtures, asset-level outcomes, scheck's
   own grant set aside only by elimination, and scope table `2026-10-11`. Coverage
   splits the OAuth sub-item (`not_on_plan:profile=<p>` when not selected) from an
   always-unassessed domain-wide delegation sub-item. Consultant, client and modularity
   reviews passed after their must-fixes were applied; green `make check` is recorded in
   [eval/e6-oauth-verification-2026-10-11.md](eval/e6-oauth-verification-2026-10-11.md),
   the definition in
   [eval/e6-oauth-definition-2026-10-11.md](eval/e6-oauth-definition-2026-10-11.md).
   The adversarial review confirmed one must-fix, a Google 403 rate limit on any
   Workspace read classified as a missing permission (now retried and `limit_reached`),
   one test should-fix and two nits, all corrected; a fresh follow-up review found no
   must-fix or should-fix. No live tenant was contacted and no independent acceptance
   is claimed.
6. Optional Gmail forwarding metadata through an existing approved delegated
   credential; no messages, mail content or automatic delegation setup.
   **Done offline 2026-10-11:** under `directory_mail` or `directory_oauth_mail`, a
   service account only, the gate mints one `gmail.readonly` token per admitted
   mailbox, admitted from current inventory (active, with a mailbox, in a verified
   domain) before each exchange, and only when a current `authorization.mailboxes`
   entry for that asset is loaded for the gate session. The environment variable alone
   does not admit the sign-in. Tokens are cached by customer and user id, audited under one
   exchange operation with the user id as its only parameter. A circuit breaker (first
   five exchanges all failing, or 20 in a row) and a 1,000-exchange session cap stop the
   surface; failures are the surface's or one mailbox's, a coverage gap and never exit
   3; an `authorized_user` credential is `unavailable:needs_service_account`. Two
   pinned reads of `users/me/settings` (`autoForwarding`, `filters`) are projected
   before redaction, and the registry refuses every other path under `/gmail/`.
   `workspace.external_forwarding` (medium, subject `mail_forward` per mailbox and
   outside destination, `+1 attribute:admin` on a known-active super admin's mailbox)
   has firing, disproved and abstained fixtures, a read set, exact verified-domain
   comparison, subdomain abstention, asset-level outcomes and `hides_mail`. Coverage
   adds the email-area "Workspace mail forwarding" group; the report's plan marking now
   lifts an undecided group's gap and abstentions to the row and counts an asset whose
   plan is wholly off plan as not read for that area. Consultant, client and
   modularity reviews passed after their must-fixes were applied (an undecided group
   whose read was refused showed "no rule"; a tripped breaker reported as one mailbox's
   failure; the refusal decided four ways, now one `refusal` and one wording); green
   `make check` is recorded in
   [eval/e6-forwarding-verification-2026-10-11.md](eval/e6-forwarding-verification-2026-10-11.md),
   the definition in
   [eval/e6-forwarding-definition-2026-10-11.md](eval/e6-forwarding-definition-2026-10-11.md).
   The adversarial review confirmed one must-fix, a mailbox exchange refused before it
   left the machine (a deadline) reported as Google refusing the mailbox and never
   `limit_reached` (now the surface's, with its own reason, exit 2), and two should-fix
   (the warning now counts the mailboxes scheck asked Google to act as; a disabled Gmail
   API is `unavailable:api_disabled`), with nits, all corrected; a fresh follow-up review
   found no must-fix and three should-fix (an unanswered or 5xx exchange is that
   mailbox's own failure; the breaker's wording is neutral), all fixed with tests and
   not reviewed again. No live tenant was contacted and no independent acceptance is
   claimed.
7. Whole-slice offline tests and consultant/client/adversarial reviews, coverage and
   report review, spec audit, and separately attributed live measurements.
   **Done 2026-10-12, offline plus attributed live measurements, not acceptance:**
   consultant, client, spec audit and a fresh adversarial review, with `make check`
   green, are recorded in
   [eval/e6-closing-review-2026-10-12.md](eval/e6-closing-review-2026-10-12.md).
   One authorized tenant (not a sealed lab) was measured there.
   After the assignee-type fix, administrator evidence was complete, both measured
   mailboxes were disproved, and the run exited 1 from the 2-step findings. Once
   the security scope had propagated, OAuth grants were read, eight broad-scope
   findings fired, and identity stayed partial. Recall, false positives and the
   missed E3 rest-lab seal were not passed. The 0.0.2 release gates are not passed.

**Done when:** every rule has firing, disproved and abstained fixtures against fake
Google API servers; scope, exclusions, pagination, unknown fields, permission failures,
redaction and resume are proved end to end. Opt-in live measurements read only an
authorized lab tenant and record their evidence. A software test is not release
acceptance. The independent recall and false-positive gates remain pending.

**Evaluation prerequisite:** E3's required rest-lab seal before E5 or E6 was not
established before E5. A later seal cannot establish earlier blindness. E6 records the
gap and prepares separately attributed measurements without rewriting past evaluation
records or waiving the release gate.

**Carried from E4's reviews:** the provider table and a list's item subject template
remain the gate's responsibility. Org-unit matching moves behind `Scope`, beside every
other exclusion match. Coverage follows `spec/scope.md`, "Outcomes"; an attempted
request without a usable answer remains distinct from an optional surface not selected.

**Carried from the engagement-spec review** (security-consultant, 2026-10-09):
domain-wide delegation has no Directory API to read it and remains *not assessed*,
with the Admin console review path printed; break-glass super admins are expected but
still need 2-step verification; OAuth app display names never establish a match to
`tools`.

**Deferred report wording polish** (step-2 client REPORT, 2026-10-10): plain
credential/count/read-operation wording, repeated Workspace labels and the generic
"Fix these first" heading remain nonblocking report-wide polish for E9's final report
review. Preserve explicit inventory-only coverage and unknown effective permissions;
wording polish never adds security assurance. The step-2 AI review record is
[eval/e6-inventory-review-2026-10-10.md](eval/e6-inventory-review-2026-10-10.md).

**Deferred report wording polish** (step-3 client REPORT re-review, 2026-10-10):
the client found no remaining wording blocker after explanatory retained-assignment,
password-reset-role and expected-person wording was corrected. Generic `no_rule`
phrasing, duplicated aggregate evidence and remaining “current admitted users”
phrasing belong to E9's final report review. Preserve explicit scope and coverage;
wording polish never expands what the collector observed.

**Carried from step 4** (consultant DEFINE and REVIEW, client REPORT and modularity
assess, 2026-10-11; [eval/e6-two-step-verification-2026-10-11.md](eval/e6-two-step-verification-2026-10-11.md)):

- *Release blocker, done 2026-10-18 (owner's decision, option A, on a `security-consultant`
  DEFINE of the same day):* the optional `access.mfa[i].sign_in` (`google`,
  `another_provider`, `unknown`; Workspace only). Under `another_provider`, `everyone`
  raises `contradiction` only on a fired unit with a known super admin, `some` never
  raises, and a unit it stopped keeps its base severity with a "Not checked" line. The
  caveat has four wordings, Plan names the effect, and the interview asks `mfa_sign_in`
  (E8). Rules and wording: `spec/engagement.md`, "2-step verification" and
  `spec/workspace-collector.md`, "Observed 2-step verification". GitHub Enterprise
  Managed Users is a recorded known limit, not built. A 0.0.2 fix landing after E9, not a
  new slice. Built offline with goldens (`workspace-two-step-sign-in*`); no live tenant
  contacted.
- *0.0.3 contract (SSO read):* a Cloud Identity SSO profile read takes precedence over
  `sign_in`; a unit observed with no SSO profile re-raises whatever `sign_in` says, so
  the declaration never becomes a permanent suppression.
- *Pre-release live check, open (acceptance, not a decision):* whether Google's own
  mandatory 2-step verification for super admins shows in `isEnforcedIn2Sv`. If it does
  not, a super admin raise under `another_provider` could be false. Record the result in
  the acceptance record of the release that carries it (no 0.0.2 record exists). E9's "may a context raise reach critical?" is a
  separate question.
- *E9:* "Fix these first" collapses many unit instances of one finding into one line.
- *Deferred limit:* a fresh detail refused because the account's unit changed leaves
  the account unknown in its list unit only, not in both units as the DEFINE asked.
- *Deferred to E9's report review* (client REPORT): declaration evidence prints
  "Operator declaration at access.mfa[0]" rather than the declared value; raw reason
  codes in coverage text; the acceptance template for a unit that covers every
  account; duplicate per-read `Observed` lines; "(as unknown)" principal wording; `-v`
  adds nothing for Workspace; generic `no_rule` phrasing.
- *Modularity follow-ups:* F2 coverage groups and their limits registered by collectors,
  and F4 a collector-supplied asset status sentence, are done for Workspace on
  2026-10-11; their GitHub and web remainders are listed in "Carried from step 5".
  Not yet assigned to a slice: F1 GitHub MFA readout notes live in engagement rather
  than the GitHub collector; F3 a typed `access.mfa` declaration vocabulary.

**Carried from step 5** (consultant DEFINE and REVIEW, client REPORT and modularity
assess, 2026-10-11; [eval/e6-oauth-verification-2026-10-11.md](eval/e6-oauth-verification-2026-10-11.md)):

- *Owner's decisions, still open:* (S5) add further broad scopes in a later table
  version: `spreadsheets`, `documents`, `presentations`, `calendar`,
  `admin.directory.group`, and for reading `spreadsheets.readonly`,
  `documents.readonly`, `calendar.readonly`, `gmail.metadata`; whether the admin raise
  is skipped for grants to the assessment client that were not set aside (kept today).
- *Decided 2026-10-12 (S7):* a coverage gap, not exit 2, for OAuth and for mail. The
  consultant's exit-2 recommendation was declined. A rate limit remains
  `limit_reached` and can still exit 2
  ([eval/e6-decisions-2026-10-12.md](eval/e6-decisions-2026-10-12.md)).
- *Step 6, pulled forward from the modularity assess:* F2 the OAuth limit sentence is
  duplicated in the collector's note and the report's coverage group, and the
  `oauth_unclassified` collapse and its reason phrase live in the report; F4 the asset
  status sentence and the limit scan in `collect_workspace.go` belong to the collector.
  **Done for Workspace 2026-10-11, offline:** `finding.CoveragePlan` is a collector's
  coverage for one asset in one area, and `Judgment.Decided` (not abstained, no
  reason) is the stricter definition GitHub already used. `workspace.Evidence.Coverage()`
  words every group, limit, gap, not-on-plan entry, collapse and the delegation
  sub-item; the report's generic `planCoverage` holds the marking rules and composes
  the row's reason ([spec/report.md](spec/report.md), "Coverage").
  `AssetInput.Coverage` replaces `JudgmentEvidenceIncomplete` and `NotOnPlan`;
  `PopulationIncomplete` stays the asset's switch. The OAuth limit sentence is one
  constant for the readout note and the coverage detail; the
  `unavailable:oauth_unclassified` phrase stays in the report's reason vocabulary
  ("Reason wording" owns every phrase). `workspace.Evidence.Outcome()` holds the status
  sentence and the limit scan; the engagement maps it and keeps the credential-warning
  log. The modularity design review before code settled that plans carry an area, so
  GitHub can migrate one area at a time, and that the report, not the collector,
  composes the row. `make check` is green; every golden is unchanged but the OAuth
  limits detail in `workspace-oauth.json`, which gained "(they may not appear as a
  person's grant)" from the shared sentence.
- *Modularity remainder, not yet assigned to a slice:* F2 for GitHub, whose families
  per area live in `internal/engagement/report/github.go` (its abstention detail is the
  subject label alone, where `planCoverage` adds the first "Not checked" line, so a
  migration changes wording), and for the web collector's `judgedFamilies`; F4 for
  GitHub, whose status logic lives in `internal/engagement/github.go` (`Outcome` would
  need `refused` and `not_collected`). The Workspace logging-row sentence and the
  collector display names in `internal/engagement/report/areas.go`, and the
  inventory-only fallback in `judgedRow` ("Workspace account controls"), stay in the
  report. F1 and F3 remain unassigned ("Carried from step 4").
- *Unmeasured assumptions, left unmeasured in step 7* ([eval/e6-closing-review-2026-10-12.md](eval/e6-closing-review-2026-10-12.md)): Google downscopes an
  `authorized_user` refresh carrying `scope` and answers `invalid_scope` for an
  ungranted scope; domain-wide delegation does not appear in `tokens.list`;
  `tokens.list` lists the caller's own grant; it echoes `userKey` as the numeric id
  requested (otherwise every grant is dropped and the surface abstains); suspended
  accounts' tokens are blocked and return on restore; a delegated admin gets 403 on
  super admins' tokens; first-party client ids (Drive for desktop, Cloud SDK, ADC);
  the Admin console paths (Manage Third-Party App Access; Limited, Specific Google
  data, Trusted); whether unrelated anonymous apps share a client id.
- *E8, decided 2026-10-12:* no "which apps do you use" question. `scheck init`
  explains `directory_oauth` and what `admin.directory.user.security` also allows.
  See E8.
- *E9:* group app findings in "Fix these first"; decide whether `data.matters_most`
  with `attribute:admin_grantor` may reach critical (with the pending "may a context
  raise reach critical?"); lab-rank Drive for desktop and Apple Mail grants on admins;
  collapse identical per-read `Observed` lines (OAuth is the first rule with high
  fan-in, so its priority rises); plain-word scope descriptions; the OAuth sub-item
  `partial` or `not_assessed` when no app was seen and some accounts were refused.
  From the client REPORT: acceptance template explanations (the handle, the indent,
  "this app for every account that granted it"), where to see an app's grantors in the
  console, blocking against per-person removal, one term for app access, grants,
  scopes and OAuth, a one-line example of setting `SCHECK_WORKSPACE_PROFILE`, `-v`
  adding nothing for Workspace, the "+1 attribute admin grantor" jargon, the Credential
  "unknown" line beside the token warning, and the report-wide "not in the checks you
  chose" phrase for a profile the operator did not choose.
- *0.0.3 candidates:* a first-party client id table, for wording only; legacy feed
  scopes; downscoping the baseline `authorized_user` refresh; app passwords; token
  activity (Reports API); Cloud Identity app-access policy reads.
- *Filled 2026-10-12, a belief and not a verified fact:* Brightcart's profile now says
  Dani is not sure which Google Marketplace apps are installed or who created the
  Google credential. Dani thinks the MSP, who set Google up, added some apps and
  probably created the credential, and may be wrong about both.

**Carried from step 6** (consultant DEFINE and REVIEW, client REPORT and modularity
assess, 2026-10-11; forwarding in
[eval/e6-forwarding-verification-2026-10-11.md](eval/e6-forwarding-verification-2026-10-11.md);
mailbox authorization in
[eval/e6-mailbox-authorization-2026-10-11.md](eval/e6-mailbox-authorization-2026-10-11.md)):

- *Done offline 2026-10-11, not acceptance and not a live measurement (D3):* a current
  `authorization.mailboxes` entry for the Workspace asset gates signing in as
  mailboxes, with the profile. The environment variable alone does not admit a
  mailbox sign-in. The gate checks the copy loaded for the session. Recorded in
  [eval/e6-mailbox-authorization-2026-10-11.md](eval/e6-mailbox-authorization-2026-10-11.md).
- *Candidate, not built:* a later `authorization.mailboxes[].skip` list that would
  narrow which mailboxes are signed in as, because `exclude:` also removes those
  accounts from Directory rules. Not added in this slice.
- *Decided 2026-10-12:* `directory_oauth` does not need an `authorization.mailboxes`
  entry. That profile acts with the administrator credential and does not sign in as
  staff. The entry stays the gate for profiles that select `gmail_forwarding`
  (`directory_mail` and `directory_oauth_mail`), together with
  `SCHECK_WORKSPACE_PROFILE`; neither alone admits a mailbox sign-in
  ([eval/e6-decisions-2026-10-12.md](eval/e6-decisions-2026-10-12.md)).
- *Deferred, client REPORT, not changed beyond the verification sentence:* the header
  "approved by" can be read as approval of the forwarding itself. The warning now also
  says scheck did not verify the approval. A later wording pass can say "permission to
  read mailbox settings, typed into the engagement file" if the owner wants it.
- *Consultant should-fix, not applied:* grade the header's currency from the run's
  collection time rather than the clock when the report is built; if user inventory is
  incomplete, the report may name that gap and not the missing mailbox approval (no
  mailbox is signed in as either way); a non-empty `note` does not say it does not
  limit who is signed in as.
- *Not built:* re-reading the engagement file in the middle of a running process. The
  gate checks the session's loaded entry and the clock on every mailbox read and again
  on the exchange, and reads the file again on the next session.
- *Code review should-fix, not applied:* the header's "signed in as N" counts every
  mailbox the gate asked Google to act as, including an exchange Google then refused;
  recommend saying "asked Google to sign in as" or counting only a usable token. The
  email coverage detail for a profile that does not select mail still names only the
  environment variable; the readout note names the approval, and the gate still
  refuses. A resumed report's header counts this session's sign-ins; an earlier
  session's `mailbox_approvals` stay in `run.json` and are not merged into that line.
- *Decided 2026-10-12 (S7):* a surface selected and then refused with no usable read
  (a refused permission, `needs_service_account`, a tripped breaker) is a coverage
  gap, not exit 2, for OAuth and for mail. This confirms D4. The consultant's exit-2
  recommendation was declined. A rate limit remains `limit_reached` and can still
  exit 2
  ([eval/e6-decisions-2026-10-12.md](eval/e6-decisions-2026-10-12.md)).
- Step 6 relaxes DEFINE's disproof rule once: a mailbox with forwarding off and no
  forwarding filter is disproved even when the alias list was cut, and when no
  settings read was usable only the asset-level judgment is emitted; the consultant's
  review accepted both.
- *E8, decided 2026-10-12:* no "do you forward mail on purpose?" question.
  `scheck init` explains `directory_mail`, the service account it needs and who
  approves reading mailbox settings, and does not write `authorization.mailboxes`.
  See E8.
- *E9:* `data.matters_most` for email-area Workspace findings (none applies in 0.0.2,
  D5); collapse many forwarding instances in "Fix these first"; whether `hides_mail`
  raises or ranks; lab-rank forward-and-hide filters against helpdesk and accounting
  forwards as false-positive traps; `Observed` lines that cite reads that did not
  observe the evidence (report-wide). From the client REPORT: "as unknown" on `Observed`
  lines, duplicated `Observed` lines, the "+1 attribute admin" arithmetic, an
  acceptance how-to (what `accepted_by` takes and where the file is), "not in the checks
  you chose" for a profile the operator never chose and how to set an environment
  variable, a Summary pointer to skipped forwarding, ranking two stacked permission
  warnings, naming skipped mailboxes, and "1 of 1 asset read" beside "no rule".
- *0.0.3 candidates:* the Cloud Identity Policy API read (`gmail.auto_forwarding`,
  `mail_delegation`, POP/IMAP, per-user outbound gateway), a priority (D7);
  `forwardingAddresses`, delegates, send-as and POP/IMAP per mailbox; a table of
  receiving services (wording only); a multi-fact rule joining subdomain destinations
  with the web collector's MX reads; "new forwarding since the last run".
- *Deferred from the adversarial reviews:* a failed binding still shows mail forwarding
  on plan in the email row (the profile is unknown before binding; OAuth's group in
  identity is the same); the refusal wording follows the first failed read when failures
  differ; a deadline or cancel during the token body read is reported
  `unavailable:response_read_failed` (a surface gap) rather than `limit_reached`;
  per-mailbox Gmail 403s other than the API being disabled do not feed the breaker.
- *Modularity remainder, owner to confirm:* S3 profile names live in several places (the
  gate's `profileScopes` and surface table, the collector's `knownProfile` and `offer`
  fallbacks, "directory" literals); recommended: a gate `workspaceProfiles()` and one
  `notOnPlan` helper, before a 0.0.3 surface. Step 7 did not do it. S6 the report maps
  attributes by rule id and named `Details` keys (`admin_mailbox_read`,
  `admin_grant_read`, `repository_read`); recommended: `Judgment.AttributeRead` and a
  report `raises` table, in E9 or when the next raise lands. L7 shared asset-level
  outcome and unread wording between OAuth and mail; when the first 0.0.3 per-mailbox
  read lands.
- *Measured live 2026-10-12, one tenant:* `getAutoForwarding` returned `enabled:false`
  when forwarding was off. An empty filter list arrived as HTTP 204 with no body, not
  `{}`; the filters read accepts that 204 as the empty list.
- *Unmeasured assumptions, left unmeasured in step 7* ([eval/e6-closing-review-2026-10-12.md](eval/e6-closing-review-2026-10-12.md)): (2) the exchange errors for
  suspended, archived, deleted, unlicensed and
  Gmail-disabled subjects (only "user doesn't exist" as `invalid_grant` is sourced);
  (3) reads of a Gmail-disabled mailbox answer 400 `failedPrecondition`; (4) a
  suspended mailbox bounces or stops forwarding; (5) an archived mailbox receives no new
  mail; (6) turning off automatic forwarding stops existing forwards; (7) a filter to a
  later-deleted address still lists; (8) the token endpoint limits at 100 to 1,000
  sequential JWT exchanges; (9) Google's audit logs record per-user impersonation; (10)
  the Admin console paths (Email Log Search, End User Access, Manage Domain Wide
  Delegation); (11) `admin_policy_enforced` varies by organizational unit and whether it
  appears for domain-wide-delegated service accounts at all; (12) Gmail's per-user
  filter limit against scheck's cap of 1,000; and, added by the review, whether Google's
  "internal addresses only" counts subdomains internal (bears on D6) and whether
  `disposition` values match `trash`, `archive` and `markRead`.
- *Filled 2026-10-12, a belief and not a verified fact:* Brightcart's profile now says
  that a Google "service account" is something Dani heard the MSP mention when they
  set mail up, that Dani does not know whether one was created, who holds the key or
  what it can open and would not create one, and that Dani would not alone approve a
  tool signing in as staff mailboxes to read whether mail is forwarded somewhere else,
  would ask Sam and the MSP because the MSP set Google up, is not sure "settings"
  leaves the messages unread, and would say no if it sounded like opening people's
  mail.

**Carried from step 7** (consultant REVIEW, client REPORT, spec audit and
adversarial review, 2026-10-12;
[eval/e6-closing-review-2026-10-12.md](eval/e6-closing-review-2026-10-12.md)):

- *Should-fix, not applied, next edit of Workspace assignment admission (not E8
  or E9):* `strings.ToUpper` stores `assigneeType` `uſer` (U+017F) as `USER`.
  Directory will not send it. The whole-slice review did not treat it as a
  realistic wrong report. Accept the type only when every byte is an ASCII
  letter and the uppercased spelling is `user` or `group`.
- *E9, not applied:* the client heard "none it classifies as broad" as no broad
  app, an escaped app name as a glitch, and "Google Chrome" as the browser, and
  would edit the 2-step declaration to clear a critical finding because a shared
  warehouse PC is believed exempt. The consultant found no judgement defect.
  Keep control-character escaping. An exception written down does not enroll an
  unenrolled super admin. The three fixtures were separate reports; do not
  delete a disproof sentence because another fixture fired.
- *Before a 0.0.3 surface:* S3, profile names in one place, was not done here.
  E8 and E9 items carried from steps 4, 5 and 6 stay carried.

**Never declared:** `verificationCodes.list`, which returns backup sign-in codes.
The gate's registry refuses any op whose decoded path reads `verificationCodes`, and
the bound path is checked again before sending (`spec/scope.md`, "The scope gate").

### E7 — domain, email and web observe

**Delivers:** the reads, rules and data of `spec/web-collector.md`. DNS records and
subdomain takeover detection by provider-specific fingerprints, wildcard-aware, never by
trying to claim the name; SPF, DKIM and DMARC with the DMARC policy and alignment mode
read, not just presence; DKIM read per selector declared under `mail.senders`,
*insufficient evidence* without one; domains declared under `mail.no_mail` expected to
publish `v=spf1 -all` and DMARC `p=reject`, DMARC `p=none` graded by whether the domain
sends, and a domain root nobody declared judged from the mail use it shows
(`spec/engagement.md`, "Intake"); the names the company's own MX, NS and SPF records
point at resolved and recorded, never contacted (`spec/scope.md`, "Third-party
sources"); TLS and certificate, response headers and cookies, technology fingerprint,
`/robots.txt` and `/.well-known/security.txt`, from entry points only, with one
redirect hop on the same host, on a declared or first-party site (`spec/scope.md`, "Web
applications and sites", "Connections"); header, cookie, `security.txt` and plain-HTTP
rules on declared and first-party sites only. Single-fact rules for each, and
`web.restricted_reachable`, which reads one response, the declaration and the vantage.
The gate gains what they need: TXT (a record's strings joined, TCP on truncation), MX
and NS in its DNS client, the labels `_dmarc` and `_domainkey` and dotted selectors in
its DNS name type, a typed certificate verification class beside the error text, and
the TLS alert that ended a handshake (`unavailable:tls_handshake`, or
`unavailable:tls_refused` after the handshake completed). Versioned
data in the tree: the takeover table, `PreloadedTLDs` (from Chromium's preload list,
pinned to a commit), an embedded public-suffix snapshot
(`golang.org/x/net/publicsuffix` stays barred by `scripts/depcheck.sh`), the
TLS-interception list, the session cookie names, the SPF include-to-service table and
the block-page markers. Validation refuses one URL under both `intent` lists.
`scheck run --vantage internet|vpn|lan`, recorded in the run and on each piece of web
and DNS evidence and printed in the report header, with a warning at the start when
`intent.not_exposed` is listed and no vantage is given (`spec/web-collector.md`, "Reachability and vantage"); a web request's identity for resume includes it
(`spec/scope.md`, "Resume"). On a resume, a changed `mail` or `intent` URL reads again
only the DNS names and entry points it affects; Scope discovery is kept when its
inputs are unchanged
(`spec/runs.md`, "Stop and resume"; carried from E4 step 4b). E7 is the first
network collector: the `security-consultant` froze the base severity anchors on
2026-10-09 (`spec/engagement.md`, "Severity in context"), and every base E7 assigns is
placed against them.

Built in steps, reviewed as E4 was:

0. The definition: `spec/web-collector.md`, the frozen severity anchors, `PreloadedTLDs`;
   the lab's domain part sealed (`eval/lab-0.0.2-domain.md`).
1. The gate, in two halves:
   - 1a, done: the refactors carried from E4's reviews (below): a request's `Reason`
     from its decision by one table, the longest functions split into steps, and
     `Scope.Admits`;
   - 1b, done: what E7's reads need of the gate: TXT, MX and NS in its DNS client, and
     a records read (`dns.records`) at a name built from the file, admitted as a
     discovery lookup is (`spec/scope.md`, "Third-party sources"); the underscore
     labels and DKIM selectors in its name types; a CNAME query at the chain's end,
     once per name, when the queries there find nothing (a DNS host may hide an in-zone
     CNAME whose target does not exist), with fixtures of that and of a DNS host's
     compact denial of existence in the gate's fake zone; the typed certificate
     verification class, the TLS alert that ended a handshake before or after it
     completed, with the gate completing every handshake itself, and verification by Go's own verifier on every platform, so
     that no intermediate is fetched outside the gate, with no roots read noted and
     every failure then unclassified (`spec/scope.md`, "Connections").
2. The collector, in two halves, since nothing carried a finding that is not a host's:
   - 2a, done: the gate's follow-ups of the names a records read's answer points at
     (`dns.follow`: by index, as answered, an excluded one refused, at most 10
     `include:` and `redirect=` reads per SPF evaluation, one evaluation per domain;
     `spec/scope.md`, "Third-party sources"), and `internal/collector/web`, whose
     `Collect` reads each domain root in Recon (`spec/web-collector.md`, "Reads"): its
     mail domains' TXT, DMARC, MX and SPF include tree and declared DKIM selectors (each
     mail domain once, under the most specific root holding it), its
     NS, the addresses of its MX and NS targets, and the front page over https and http
     of each name Scope marked to read (`web.front`), the https read's handshake the
     name's one TLS handshake and its certificate read. What it reads is kept in
     `recon.json`, only the fields the rules read; the root is `limit_reached` when
     `limits.timeout` ends the engagement before or while it is read. A `url` root is
     not read yet;
   - 2b, split in two on 2026-10-09:
     - 2b-i, done: the path a finding takes when it is not a host's, proven with
       `dns.dangling_external`, `dns.dangling_internal` and `dns.private_address`: a
       rule interface over a collector's evidence (`Judge`, run in Recon, its verdicts
       in `recon.json`), Scope's lookups with their outcome and request id in
       `scope.json`, the report's input, findings and acceptance by subject, coverage
       rows for the external and email areas, and E7's subject kinds in
       `docs/engagement-report-schema.json` (`spec/web-collector.md`, "DNS and
       takeover"; `spec/report.md`, "Coverage", "Findings"). A read domain root is
       `collected`: its coverage replaces `collector_not_built`, and its findings set
       the exit code. A finding belongs to the most specific asset holding its subject,
       a name found under the root its own; a declared domain asset under a read root is
       recorded with it; nothing unread counts as nothing found, a verdict standing only
       when Scope's resolver and the one this session's Recon checked with its own
       control lookup are known not to invent answers (`spec/scope.md`, "Discovery");
       and the model path's store refuses an id that is not a host finding's;
     - 2b-ii, done: takeover table `2026-10-09.1`, pinned to
       `can-i-take-over-xyz` commit `5bd4e12837911c8475486f1da922c9b9c706e632`
       (`2025-02-08`), reviewed `2026-10-09`; enabled fingerprints for GitHub Pages,
       S3, Elastic Beanstalk, Azure and Vercel, with the remaining planned providers
       explicitly unverified (`spec/web-collector.md`, "Takeover fingerprints").
       `dns.takeover_candidate` and `dns.unclaimed_at_provider` both declare subject
       kind `dns_name`, as the three existing DNS definitions do: an acceptance must
       name the subject. A positive fingerprint replaces duplicate
       `dns.dangling_external`; unknown providers and NODATA remain ordinary dangling
       records. Scope keeps its concrete wildcard control; Recon judges it once on
       `*.<root>` with matching undeclared names grouped, and reads its front-page
       pair only for a resolving body-fingerprint provider through the normal gate.
       Wildcard matching requires recognized equal chains, outcomes and addresses,
       never shared IPs alone or equal markers. The gate redacts the lookup's name,
       refusals included; a marked control is insufficient and never becomes an HTTP
       target. An insufficient or unchecked control leaves Scope incomplete for
       resume to retry; a successful control is kept with complete Scope. A positive
       fingerprint suspends operator confirmations for its exact subject or listed
       wildcard members in live and persisted scope; declared names keep their own
       reads and judgments. Provider caveats reach the report, whose coverage lists
       services with no fingerprint, including a wildcard with no certificate-log
       members once on `*.<root>`. Gaps in discovery stay partial even when the wildcard fires.
       Findings on discovered names get the default medium exit threshold even when
       the name has no asset input. Reviewed with the merged `dns_name` definitions
       from 2b-i; the code review's fixes passed fresh review, including the final
       resume fix, and `make check` is green. No review findings deferred from this
       step.
3. **Done:** the eleven email rules over
   collected DNS: DMARC enforcement, legacy sampling and subdomain policy; no-mail
   policy; SPF presence, syntax, static tree limits, broad authorization and declared
   sender comparison; declared DKIM selectors and RSA key sizes. Each definition
   requires its mail-domain, SPF-mechanism or DKIM-selector subject. Findings stay on
   the owning domain root. Missing declarations, unread or marked records, unknown
   mail use and incomplete trees remain coverage gaps; `mail_context` notes describe
   what DNS shows and cannot show. DMARC uses the embedded public-suffix snapshot and
   already-collected organizational policies across roots, after every root is read;
   current receiver DNS tree walking and actual messages are not assessed. The
   versioned sender table maps four services by exact includes and explicit aliases.
   SPF syntax is checked past `all`, but unreachable mechanisms and an ignored
   redirect are not followed; the gate's request surface and cap are unchanged.
   See `spec/web-collector.md`, "Email", for the reviewed predicates and limitations.
   The code review's fixes are implemented: DMARC and DKIM markers survive tag
   reduction as uncertainty; SPF record selection requires the version at byte zero
   and its ASCII-space or end delimiter; include subjects drop trailing dots and
   deduplicate for findings and acceptances. Uncollected or unknown read decisions
   retain `unavailable:not_read`, so absent mail evidence or a declared selector with
   no read cannot become an absence finding. A further fresh review's fix preserves
   uncertainty in a marked DMARC version with the tag parser's whitespace handling;
   SPF version recognition remains strict, and both redaction and truncation markers
   count before version recognition and tag reduction. `make check` is green;
   consultant and client reviews are complete, and the final fresh code review found
   no remaining issues. No review findings deferred from this step.
4. **Done:** three TLS and eight web rules:
   typed certificate failures, expiry within 14 days (confirm renewal), a failed
   TLS 1.2-or-later negotiation without claiming older versions work; HSTS, plain HTTP
   and preloaded-browser exceptions, session cookie flags, recognized security
   headers, version disclosure, trusted detector hits and security contacts. Subject
   acceptances and verdict-based web/secrets coverage preserve missing evidence;
   cookie coverage never claims the unread login flow passed. Declared URL roots and
   assets, first-party entries, well-known files and one gate-admitted same-host hop
   use `web.entry` after takeover suspensions, beside `web.front`. Intent alone grants
   neither first-party status nor header eligibility. Nondefault-port URL roots make
   no implicit 443 read. Recon retains admission metadata and collection times;
   robots paths are neither retained there nor requested. `web_context` notes report
   technology sources, block pages, robot counts and entry-point limits. Chromium's
   51-TLD snapshot is pinned to `d5e6fd51b430fec89732a3976e666011ecffa0a2`, with
   versioned inspection issuers, session names and block markers. Consultant review
   corrections are implemented. The first code review's six confirmed fixes cover
   trusted reused security-contact 404s, literal HTTP quoted-pairs in HSTS, nested
   template depth, whole HTML attribute tokens, CSP nonce/hash payload grammar and
   wildcard takeover suppression of the control hostname's TLS judgments. A fresh
   review verified those fixes and found a related HTML tag boundary issue: slash
   delimiters now preserve active inputs, inert containers and closing-tag recognition.
   A subsequent review verified earlier fixes and found raw-text closing-tag
   recognition: raw-text/RCDATA now precedes ordinary comment and attribute parsing,
   with script escaped/double-escaped states retained, including inside templates.
   `make check` is green after every boundary fix. Consultant and client reviews are
   complete; the final fresh code review verified the raw-text/RCDATA, script-state
   and earlier fixes and found no remaining issues. No review findings deferred from
   this step. Verified follow-up fixes for URL-only engagements restrict
   resolver-control doubt to DNS/email judgments;
   URL assets contained by an explicit URL root inherit its authority for their exact
   entry paths; unread redirect attempts do not suppress ordinary declared-entry
   reads; and URL assets read with a root count as read in coverage. Scope, exclusions
   and per-capture abstentions remain enforced. `make check` is green; consultant
   review and a fresh code review found no remaining issues. Five offline regression
   tests cover the real-run failure modes. No follow-up review findings deferred.
5. **Done:** `--vantage internet|vpn|lan` is
   declared on each invocation and recorded in sessions, HTTP/DNS evidence, audit
   and the report. `internet` means outside every permitted source, including office
   allowlists and VPN; no egress detection is sent. `web.restricted_reachable` judges
   exact restricted URL entries, with an authentication caveat and outage caveat.
   Changed mail declarations refresh records and dependent follow-ups by domain;
   changed intent role or audience refreshes its exact URL; reasons and web
   acceptances only regrade. Changed vantage refreshes Scope and web/DNS evidence,
   leaving hosts unchanged. Reused evidence keeps its observation time. The
   adversarial review fixes preserve canonical escaped entry and redirect-hop
   paths, reuse successful MX and NS address dependencies,
   recalculate reused DNS chain membership against current roots, mark failed declared
   root NS reads incomplete, and scope missing accepted-subject completeness to its
   owning asset and collector. Follow-up review corrections keep first-party egress
   counts separate within sessions as well as across resumes, sort those rows
   deterministically, and require the original scheme for a same-origin login redirect.
   `make check` and `make build` are green. Consultant and final client report reviews
   are complete; the whole E7 integration review and a fresh review of the final
   boundary fixes found no remaining issues. Offline regressions cover these fixes,
   selective resume and all three restricted-rule outcomes. No review findings are
   deferred from this step. These are software checks, not external live-security
   acceptance or a recorded 0.0.2 release-gate pass.

**Done when:** tests against recorded HTTP and DNS fixtures (`httptest`, no network)
fire, disprove and abstain for every rule; the audit log shows no request outside an
asset's entry points and its one redirect hop, and no `robots.txt` path
requested; a resume with a different vantage reads a web asset's names and entry
points again; a resume after a changed `mail` or `intent` URL reads again only the DNS names
and entry points it affects (carried from E4 step 4b).

**Carried from E4's reviews:**

- done in E7 step 1a: a request's `Reason` derived from its decision by one table, and
  the gate's longest functions (`attempt`, `send`, op validation, discovery's per-root
  loop, `shape`) split into steps. The provider table and a list's item subject as a
  template stay with E5 and E6;
- done in E7 step 1a: `Scope.Site` replaced by one `Scope.Admits(origin, path, lookup)`
  decision written once in the engagement, which the gate calls before and after
  resolving the name, and whose evidence check after resolution discovery's listing
  shares (E4's "Deferred from E4's design review");
- done in step 5: site requests remain split by first-party status across
  sessions; later confirmation never changes earlier unconfirmed request counts;
- the web collector decides `unavailable:blocked` from the page it is served: status
  and a block-page marker (`spec/scope.md`, "Connections");
- coverage is marked by `spec/scope.md`'s "Outcomes" table, a request that got no
  answer exiting 2 only for what was declared.

**Carried from E7 step 2b-i's review** (code review, 2026-10-09), each fixed before E7
closes:

- done in step 5: observed items use actual request collection times and
  preserve them when reused (`spec/report.md`, "Findings");
- done in step 5: network assets have a trace of redacted gate entries,
  including DNS queries (`spec/report.md`, "Text and JSON");
- done in step 5: `method.levels_used` comes from actual DNS queries and
  request sends over the retained run, plus host collection; DNS-only reads never
  invent `observe`
  (`spec/runs.md`, "Runs, state and configuration").

**Carried from E7 step 2b-i** (2026-10-09), done in step 5:

- Resolver controls remain a heuristic: a resolver that handles `invalid.` specially
  can rewrite other missing names. The report explains this limitation; it makes no
  guarantee that every dangling target is found.
- Missing accepted subjects are removable only over a complete applicable population;
  incomplete evidence remains `rule_not_decided`, never evidence of a fix.
- Egress records actual reserved-name query counts in `invalid_queries`, alongside
  the boolean `control_invalid`; wording names Scope and Recon's real total.
- Recon's resolver control outcome is in `recon.json` and report context notes.
- Discovery wording includes passive resolution of third-party CNAME, MX, NS and SPF
  names outside roots; no such lookup authorizes HTTP contact.

**Carried to 0.0.3 from E7's definition** (2026-10-09): an SOA lookup of a dangling
target's registrable domain, which would tell whether anyone can register it
(`spec/web-collector.md`, "Not assessed"); no 0.0.3 slice owns it yet.

### E8 — `scheck init`: the interview

**Delivers:** `scheck init`, an interview that writes the engagement file E1a defined,
asking the questions of `spec/engagement.md` ("Intake") and nothing else; each question
declares its consumers in `internal/engagement/interview.go` by id and owning slice.
`scheck init FILE` asks only what that file does not answer. A file from
`scheck run --host … --write-engagement` is a valid start. No code path contacts a
target. A credential-shaped answer is refused by the same detector as validation.
Plan, Analyze and multi-fact rules are E9, not this slice. No release gate is marked
passed.

**Done when:** every question declares its consumers, and a test checks that each
declaration is well formed and that the consumers owned by merged slices exist; the
file `init` writes for each company profile in `.agents/clients/` validates; an answer
that would put a credential in the file is refused by the same detector as validation;
no code path in `init` contacts a target.

**Decided 2026-10-12** (owner). The engagement-spec review of 2026-10-09 and the E6
items carried into this slice are closed by these decisions. `spec/engagement.md`
("Intake") is the wording.

- Cut from the interview. The keys stay valid and unasked: `data.backups`,
  `secrets.production` (`store` stays free text), `assets.<host>.context.role`,
  `data.matters_most`. `deploys_to` stays the string `production`, `staging` or
  `development`.
- Cut the SaaS tools question and the "from which CI" question. `tools` and
  `assets.<repo>.ci` stay valid and unasked. `ci` still has to name a tool under
  `tools`.
- The interview asks host exposure, environment, expected services, and how to reach
  the host. Only `internet`, `airgapped` and `dev` move a host finding's severity.
  `prod` does not raise one (`spec/host-collector.md §5.3`).
- `not_used` refuses `identity`, `secrets` and `logging` always. It also refuses an
  area a declared root already covers: `email` beside a domain root; `web` beside a
  domain or url root; `external` beside a domain, url or network root; `cicd` beside
  a GitHub root or a repository asset; `hosts` beside a host root; `cloud` or `data`
  beside a cloud root. `hosts`, `cloud`, `data`, `cicd`, `email`, `web` and
  `external` stay allowed when no such root exists. There is no `payments` area.
- `intent.accepted_risks[].date` is required. `expires` is required, on or after
  `date`, and at most 365 days after `date`. A past `expires` still validates; the
  report leaves the finding open. `scheck init` does not ask for accepted risks. The
  paste block writes `date` as the collection day.
- *E6 step 4 release blocker, done 2026-10-18:* the question `mfa_sign_in` follows `mfa`,
  asked only for a `google-workspace:` `access.mfa` entry that is `everyone` or `some`
  and has no `sign_in`. It offers those tenants, normalizes a named service to
  `another_provider`, refuses `sso` and yes/no, and a blank answer prints "No
  `sign_in` given for `<where>`". Consumer `workspace.two_step_sign_in` (E6). A Cloud
  Identity SSO read stays a 0.0.3 candidate (E6, "Carried from step 4").
- No "which apps do you use?" question. No "do you forward mail on purpose?"
  question. When the file names a Workspace tenant, `scheck init` explains
  `directory_oauth` (the environment variable, the credential stays out of the file,
  and `admin.directory.user.security` can also revoke app access, sign people out,
  and turn off 2-step verification) and `directory_mail` (a service account,
  `gmail.readonly`, and who must approve). It does not ask for, write, renew or
  extend `authorization.mailboxes`.
- `scheck init` writes a header comment: the file names people, people who have
  left, and accepted weaknesses, and is kept out of public repositories.

### E9 — Plan, Analyze and multi-fact rules

**Delivers:** the verdicts moved to Analyze; the rules the identity slices left to a
multi-fact rule; a rules-only Plan that decides which items are read first under a cap;
follow-up reads from a static table; the context adjustments as one closed table;
fixed sub-item lists per risk area; and a 7-day maximum age for what a resume keeps.
`spec/engagement.md` ("Stages", "Severity in context", "Plan selection and follow-ups",
"Context notes", "The multi-fact rules of 0.0.2") and `spec/report.md` ("Coverage",
"Ranking") are the wording; each is design until its step lands.

- *Already built, audited here and not re-implemented:* `identity.unexpected_admin`,
  `identity.unattributed_admin`, `identity.former_person_has_access`,
  `identity.former_person_invited`, `identity.external_admin` and
  `identity.shared_admin` (Workspace and GitHub), the `deploys_to:production` raise,
  `web.restricted_reachable` and the 2-step `contradiction`. Each is audited against
  firing, disproved and insufficient-evidence fixtures; a missing fixture is added.
- *New engagement rules:* `db.listens_unfiltered` (R1), `accounts.empty_password_remote`
  (R2), `svc.listens_beyond_declared` (R3), the `attribute:production_write` raise on
  `identity.former_person_has_access` (R4) and the person rollup (R5). Each declares its
  reads and has all three fixtures. R1 and R3 carry a `service` subject and a ceiling of
  high.
- *Recon:* inventory only (users, roles, admin assignments; members, owners, outside
  collaborators, invitations; the repository list with `pushed_at`; DNS; host and web
  reads).
- *Plan:* tiers for repositories and users, a `selection` in text and JSON, and the
  Plan document's list of reads and of rules that will abstain for lack of a declaration.
  `--stop-after plan` shows what will be read before any of it is.
- *Check:* every read only rules consume, in Plan's order (per-repository children,
  workflow files, alerts, the mirror; per-user OAuth grants and Gmail forwarding),
  breadth first under a request budget; then the follow-up table (F1; F1b and F2 are
  answered by the access pass and Workspace tier 1, step 7), depth at most 2, an
  invariants test.
- *Analyze:* every collector's `Judge`, the host's grading, the multi-fact rules and then
  the adjustment table, which is data. The context notes C1 to C3.
- *Report:* fixed sub-item lists with "not judged in this version: …", the oldest
  collection date per asset, the person ranking item.
- *Host collector:* one new catalog check, `fw.iptables_backend` (D3 below).

**Done when:** every multi-fact rule has firing, disproved and insufficient-evidence
fixtures; `db.listens_unfiltered` fires only when listener and host firewall facts both
agree, is not lowered by `exposed_on_purpose` or `expected_services`, and says the cloud
firewall was not assessed; the left-person rules fire on the lab and abstain when the
tenant was not read or the person has no identifier for it; "exposed on purpose" moves an
exposure finding and leaves a secret finding on the same asset unchanged; the adjustment
table has a stacking test per entry, ceilings included, and `data.matters_most` raises
a finding that also carries a context; with 150 repositories under a small cap, the
repositories read are those the tiers name and the selection says so; a loop fixture on
F1 terminates and the invariants test rejects a cyclic or deeper table; an observation
older than 7 days is collected again on resume; every risk area's row prints its
"not judged in this version" line; the command traces change only by the recorded
`fw.iptables_backend` line and the elevated `ss` read (D3, D3b).

**Build steps**, each a commit with `make check` green:

1. Verdicts move to Analyze, in four parts.
   - *1a (done, offline).* The adjustment table is data: `internal/engagement/severity`
     (`Declarations`, `Grade`, `GradeAll`), one entry per rule with source, moved
     findings, step and past-high flag, and a definition's own `Ceiling`, `HostAccess`
     and `Attributes` (the collector's steps, such as `password_form` +1 and
     `slack_webhook` -1). `internal/engagement/adjust.go` builds the declarations from the
     resolved engagement and `reportInput` grades every network-collector judgment after
     `partitionGitHubJudgments`; the report renders the chain. The `data_matters_most`
     raise no longer skips a judgment that has a `why`, `exposed_on_purpose` is terminal
     and applies to any definition marked an exposure finding on the exact URL,
     `attribute:public_repository` (was `observed_public`) enters the table, and
     `data.matters_most[i]` is cited by index. `deploys_to:production` is decided by the
     engagement from `assets.<repo>.deploys_to` on the owner repository; a collector keeps
     the declaration in a judgment's `source` and emits no production attribute. A
     stacking test per entry, ceilings included. The graded path that lowers a finding to
     `info` for a matching `expected_services` entry is not used for R1.
   - *Decided in 1a:* `finding.Judgment` carries `Attributes` as `{name, ref}` (`ref` a
     declaration `key` or an `observation` and `excerpt`), a `why` sentence and `chain`
     (set by Analyze, replaced by `GradeAll`; a collector never sets it), not a separate
     graded wrapper type as the modularity sketch had it: one type reaches the report,
     and a judgment that was not graded has no chain.
   - *1b (done, offline).* The web, GitHub and Workspace `Judge` calls run in Analyze
     (`internal/engagement/judge.go`), on what this session's Recon holds, keyed by asset;
     web judges after every root is read, so inherited mail policy sees them all.
     `githubc.Evidence.Judgments`, `workspace.Evidence.Judgments`, `ReconAsset.Judged` and
     `finding.Judgment.Members` are gone, so `recon.json` and `evidence/` carry no
     verdict. `githubc.Judge` runs every family (`JudgeAccess`, `JudgeCI`, `JudgeAlerts`,
     `JudgeHistory`); `workspace.Evidence.Coverage` takes Judge's verdicts;
     `web.Suspensions` names the fingerprinted names whose confirmation is suspended
     before `Enrich`, as read selection and no verdict. `findings.json` carries every
     verdict after partition and grading as `judged` per asset, output only, never read
     on resume.
   - *1c (done, offline).* A host is graded in Analyze: Recon writes the evidence
     envelope (`report.Evidence`, no assessment, finding or context) and Analyze rebuilds
     the fact sheet from it (`report.SheetFrom`, `check.Decode`) and grades it
     (`report.Assess`, `hostasset.Grade`) through the asset's context and the accepted
     risks that name it. A kept host is graded again, so an edited context, accepted
     risk or `engagement.timezone` re-runs only Analyze and Report and contacts no host;
     the host's collection inputs exclude all three and the context's source. An
     envelope that cannot be read back collects the host again. Acceptances a host
     cannot apply (a subject set) are named from Analyze for every host asset.
     Acceptances on a kept host are still graded at the collecting session's start.
   - *1d (done, offline).* Observation-time clocks for every time-dependent rule, decided
     2026-10-14 (below): each rule's clock is the read that carries the value, and the
     excerpt names it. `internal/finding/clock.go` holds the shared `LeftAt` (passed,
     within collection, not passed, unknown), reason `unavailable:collection_time` and
     the `left_date_within_collection` outcome. The web collector's `Input.Now` is gone:
     certificate expiry and `security.txt` `Expires` use their page's `CollectedAt`. GitHub's
     `Context.Today` became `Context.Zone`; Workspace's `Context.AssessedAt` is gone and
     `Read` carries `CollectedAt`. An acceptance's expiry is judged at the latest
     collection time among the reads its finding cites, a host's at the start of the
     session that collected it, and the JSON carries it as
     `findings[].acceptance.judged_at`. The 7-day maximum and a zero
     collection time counted as expired on resume are step 8.
2. *(done, offline).* The fixed sub-item lists, with "not judged in this version: …" in
   every row; goldens. `internal/engagement/report/fixed.go` holds each area's ordered
   `{id, text}` list; `coverage[].not_judged` is required on the ten area rows, no area
   row is `assessed`, and the list never lifts *not assessed* or changes
   `not_applicable`, the exit code or the run status. The text line prints on each row
   shown on its own, once under the Hosts mark, and replaces the row-level `no_rule`
   reason; the not-a-clean-bill paragraph says no area is fully checked. A collector's
   unread sub-item names its fixed id (`CoverageUnread.Fixed`) so it is not said twice.
   Decided 2026-10-15 (`security-consultant` define, adopted by the owner's standing
   delegation): the lists come from the practitioner's list, not from the rules; new
   items for 2-step kind and app access policy, container-image secrets, push to
   production, the DNS account, host SSH keys, admins with sudo, Linux disk encryption,
   email forwarding policy and off-host logs; credential files under Hosts only, cloud
   keys and databases under Cloud only; the restore test moved to the Processes
   *outside scheck* row; R1, R2 and R3 sit in the right column until steps 3 and 5 build
   them. Deferred: collector limit details keep their own "remain unassessed" and "were
   not assessed" phrasing (ask collectors for noun phrases later), and a free-text limit
   that overlaps a fixed item is printed twice (Workspace forwarding's Admin console
   setting, GitHub CI/CD's OIDC trust; give such limits a fixed id); the population line
   "1 of 1 asset read." on a row where no sub-item reads anything (logging) may mislead.
3. The multi-fact rule framework, R1 and R2, in two commits.
   - *3a (done, offline).* `internal/engagement/rules`: declared reads (a host check or
     a declaration), a view that hands a rule only those, the three outcomes, a disproval
     withdrawn on a partial fact (`unavailable:incomplete_read`), `Validate` and tests
     that every rule fires, is disproved and abstains, reads only what it declares and
     uses every declared read; `finding.Facts` and `FactsOf` give a persisted host's facts
     the posture rules' usable decision, so a kept host is judged the same;
     `finding.Def.MultiFact` and `Judgment.Facts`. Analyze judges every collected host
     (`internal/engagement/judge.go`), graded by `severity.GradeAll`; an acceptance of a
     multi-fact id goes through the report's judged path. The `fw.iptables_backend` check
     (D3) and `net.listeners` elevated (D3b); the golden command traces change by exactly
     those lines. R1 `db.listens_unfiltered` with `DatabasesVersion` 2026-10-15 (2026-10-31
     since G5 added `java` on 9200 and 9300) and
     ufw's verbose rule grammar as its `get_status` prints it (no profile table: verbose
     output prints each application rule's ports), the firewall reading (`rules/firewall.go`, reused
     by R3), the severity row `exposure:internet`, the Data row read from a host's
     coverage plan with its four new fixed items, and the goldens
     `host-database-fired`, `-disproved`, `-abstained`. Fixtures for `fw.iptables_backend`
     were recorded by hand from the test containers. The code review found four ufw
     reading defects, each fixed with a fixture before commit: a logged rule's `(log)`
     attribute made it read as source-restricted, so an open port was disproved; IPv6 was
     judged filtered by ufw's default when ufw lists no `(v6)` rule (with `IPV6=no` it does
     not manage ip6tables), now unknown; a rule to one destination address was treated as
     covering every address; and application rules never matched a profile table that
     verbose output never prints. A partial ufw read no longer lets the default decide. A second review found
     that a From of source ports alone (`Anywhere ALLOW IN 53`) was read as restricting the
     source, so an open port was disproved; on the security-consultant's decision of
     2026-10-15 such an ALLOW or LIMIT fires with a sentence saying a sender chooses its own
     source port (the remediation's caveat says to delete the rule), and a DENY or REJECT
     of that shape is passed over. Every verdict through ufw now says rules added outside
     ufw and `/etc/ufw/before.rules` were not read. Networks printed with a protocol
     (`192.168.1.0/24/tcp`), other protocols, profile names holding " on " and IPv6
     sources are read. A third review found a UDP source-port rule firing a TCP database
     port (ufw prints the protocol in From only when To is `Anywhere`); fixed.
     Recorded as a known limit, not fixed: an empty `fw.iptables_backend` cannot tell no
     `/usr/sbin/iptables` from a busybox `realpath` or a legacy `iptables` kept only in
     `/sbin` on a host without merged `/usr`.
   - *3b (done, offline).* R2 `accounts.empty_password_remote`
     (`internal/engagement/rules/ssh.go`), on the security-consultant's define of
     2026-10-15: the empty-password join is the posture rule's own per-account decision
     (`StatusWithLoginShell.Decide`, `DecideJoin`); the `Match`-block condition was
     dropped because `sshd -T` without `-C` prints nothing that shows a block exists, and
     every judgment says so in Not checked. `accounts.empty_password` keeps firing and
     "Fix these first" leaves it out on a host with an open R2; its impact sentence points
     to R2. The Hosts row: a multi-fact rule reports in its host domain's sub-row (R2 in
     "SSH server", R1 in "Firewall": "checked (whether database ports are filtered only;
     see Data stores)"); `hosts.empty_password_ssh` is gone and `hosts.ssh_match` added;
     goldens `host-ssh-empty-password`. The code review found, each fixed with a test
     before commit: a socket-activated sshd on a port `sshd -T` does not name (an
     `ssh.socket` `ListenStream` override) was disproved, and now keeps the read from
     disproving; `permitrootlogin` was applied to the name `root`, not to uid 0 as sshd
     does, so a second uid-0 account fired; "Fix these first" dropped the local finding even
     when R2 listed only some of its accounts; a fired R2 with undecided accounts read as
     complete, and now names them and marks the list a lower bound; an R2 acceptance with
     a subject passed intake (`HostFinding` now excludes multi-fact ids); the golden's
     posture envelope did not carry the local finding on the same accounts. A second
     review found an account whose password state was not recognized left out of the
     join's accounts, so R2 could be disproved beside it (root with keys only); such an
     account is now undecided in `finding.JoinOutcome`, and the posture verdict is
     unchanged. Step 3 is done.
   - *Deferred from 3a and 3b:* the contradiction's generic "You declared … Operator
     declaration at …" evidence line, with the audience in the excerpt (still open; no
     slice owns it yet, to be assigned); the base-chain refinement of an
     `nft` ruleset and a parameterized `sshd -T -C user=` read (0.0.3 G5); a note for
     Docker's userland proxy turned off.
4. People: R4 and R5. R4: on a fired repository-level
   `identity.former_person_has_access` judgment the GitHub collector states facts
   (`repository_admin`, `write` from `EffectiveWrite` with the collaborators read cited),
   and on one carrier judgment per login `write_held` and `write_unsettled` attributes
   (`finding.Attribute.Asset` names the repository, the cause is the reference's
   excerpt); the collector never reads `deploys_to`. The severity table decides
   production: `attribute:admin` also matches `repository_admin` on a production
   repository, `attribute:production_write` raises on `write` there, and otherwise says
   a not-applied move (`StoppedNotEstablished`) with its cause; the report prints it
   under "Why here". The remediation gains a rotate-and-review sentence. R5: the "People
   who left" block and `people_left[]` (`line` is the printed sentence), the `person`
   ranking item (two at most) with `other_people` on the `finding_id` item that lost
   instances to it (`internal/engagement/report/people.go`). GitHub leaver judgments carry
   `details.membership`; a person with no declared login is judged on
   `declared:<handle>`; Workspace now abstains once per declared address for a leaving
   date not passed or users not read, so every left person has a line. The reasons
   `leaving_date_not_passed`, `left_date_within_collection` and `no_declared_github_login`
   are in the schema and worded. The identity row's fixed not-judged list gains three
   items (`identity.leaver_unlisted_write`, `identity.leaver_additions`,
   `identity.leaver_activity`). `spec/engagement.md` ("The multi-fact rules of 0.0.2",
   R4, R5) and `spec/report.md` ("Ranking", "People who left") are the wording.
   Code review: a first review found an active alias-only or conflicting account printed
   as "users could not be read" and the `declared:<handle>` key printed as an address
   (both fixed, with end-to-end tests through `workspace.Judge` and
   `github.JudgeAccess`; the users-unread line now carries the read's reason); a second
   found an address missing from an incomplete users list printed as "account observed"
   (fixed: the `not_proven` line). Step 4 is done.
   Carried to step 8 and closed there: the R4 coverage sub-item "Push to production by
   people who left: not judged".
5. R3 and the context notes, in two parts (5a done; 5b design).
   - *5a (done).* R3 `svc.listens_beyond_declared` with the `exposure:internet` step
     moving it as well as R1; the validation that exits 3 for `airgapped` on a service's
     `audience` and for `not_used: [external]` beside a host with `exposure: internet`;
     the coverage rule that a `not_used` area with a finding, open or accepted, is not
     *not applicable*. R1 and R3 share the listener grouping and a lazily read firewall
     (`internal/engagement/rules`). Deferred to step 9: the interview's
     `expected_services` consumers (`db.listens_unfiltered`,
     `svc.listens_beyond_declared`), since the interview test accepts only merged
     slices. `spec/engagement.md` ("The multi-fact rules of 0.0.2", R3; "Severity in
     context"; "Validation") and `spec/report.md` ("Coverage") are the wording. Decided
     by the `security-consultant`, adopted under the owner's delegation.
     Review of 5a (`code-reviewer`), all fixed except the last nit. Must-fix: R3 could
     take "open" from one IP family and the bind from the other (the bind is judged only
     in families the firewall left open). Should-fix: R1 judged Docker and Podman proxies
     on any port, double-judging R3's (now table ports only, as `spec/engagement.md`
     says); the interview accepted `not_used: [external]` beside an internet host and
     `init` then exited 3 (`notUsedRefusal` is shared by intake and the interview); R3
     disproved a host on a listener read with an unreadable port. Nits: R1's subject
     order follows the first listener, loopback included; the unrecognized-bind detail
     reads "a listener's bind address"; deferred, a partial fact read for one subject
     withdraws another subject's disproval with `unavailable:incomplete_read` (safe,
     the wording is imprecise).
     A second review found that a declared port seen only on loopback was disproved on a
     listener read with an unreadable port (fixed, with a fixture), and a test nit (R1's
     host verdict is now asserted unaffected by Docker off a database port). Step 5a is
     done.
   - *5b.* The context notes C1 to C3, `{kind, source, detail}`, and the versioned C3
     table (`spec/engagement.md`, "Context notes"; `spec/report.md`, "Findings").
     Built. Review found, and fixed: must-fix, C1 said mail records
     were not read for a declared mail domain that was read, and C3's tail predicted a row
     mark that is false where a finding exists; should-fix, an exact email count on a
     partial users read, `report.md` claiming a noted row is not *not applicable*, and C2
     naming a raise for a `deploys_to` value other than `production`; nits, the clause
     order, naming the most specific root, not counting accounts of unknown archived
     state, a merged doc comment, and the table version recorded in `rules_version`.
     A second review found, and fixed with tests: should-fix, the table version reached
     `rules_version` only with a domain root; should-fix, the C1 test did not exercise the
     mail-domain skip (checked by removing the fix); nit, "read" means attempted (the spec
     is reworded), and the `active()` filter is now tested. Step 5b is done. Step 5 is
     done.
   - *Resolved at the slice close (security-consultant):* `svc.expected_missing` moves
     from medium to info: a declared service that is not listening weakens no control and
     exposes nothing. It is stale context or downtime, which the info anchor covers, and
     as a medium it would push real hardening findings out of "Fix these first".
6. Plan selection: `pushed_at`, the tiers, the per-item reads moved from Recon to Check,
   breadth-first GitHub reads under the 4,000-request budget, the `selection` text and
   JSON, the Plan document's read and abstain lists, `--stop-after plan`. A fake server
   with 150 repositories under a small budget.
   Split in two. **6a, GitHub**, done (offline): `pushed_at` retained on the repository
   projections, the eight tiers, the per-repository reads moved from Recon to Check, the
   breadth-first budget, Select, the Plan document, `--stop-after plan` and the selection
   in the report. **6b, Workspace**, done (offline): the per-user tiers
   (`UserTiersVersion`), Recon's per-user reads in that order, `Select` and `plan.json`
   `workspace[]`, OAuth grants and then Gmail forwarding moved from Recon to Check
   (`CollectUsers`, `check.json` `workspace`), the `users` selection on a cut population,
   and the tier counts in `--stop-after plan`. Step 6 is done.
   - *Decided 2026-10-15* (`security-consultant` define, adopted under the owner's
     standing delegation; `spec/engagement.md`, "Plan selection and follow-ups", carries
     the wording):
     - Five passes in order, each over every selected repository in tier order: access
       and protection, CI, then alerts as three passes (secret-scanning, Dependabot,
       secret alert locations); the mirror runs after every counted pass and is not
       counted.
     - The `github.repository` object is counted; inventory, the mirror and the follow-ups
       are not. Every page is one request, a retry counts once, and a ledger answer on
       resume counts as when first sent; a refused or limit-stopped request is not spent.
     - A budget cut is `sampled`, exit code unchanged; the timeout and the rate limit stay
       `limit_reached`. A kind is all or nothing per repository, so the spend may pass the
       budget by one repository's kind; Plan and the report print "sent N of a 4,000
       budget".
     - Declared repositories (`assets` entries) are never cut, tier 2 selected and tier 3
       public ones can be: tier 6 is new, "declared as a repository
       asset" (`assets.<r>`); the lowest tier wins; a `secrets.production[].asset` naming an
       organization orders the repositories selected for an organization secret, and
       orders none when the visibility is `all` or `private` or the read failed. A
       repository root with no declared organization has no budget.
     - `--stop-after plan` prints the header, the ordered list (20 lines in text, all in
       JSON) and a closed not-judged list (`spec/engagement.md`).
     - The selection line prints every run for GitHub; "all N repositories read; the
       request budget cut nothing."
     - Workspace (6b, built): ordering evidence wider than finding evidence (`isAdmin`,
       `isDelegatedAdmin` or an observed role assignment); the swapped tiers; one order for
       Recon's per-user reads and Check's OAuth grants; no Workspace request budget in
       0.0.2; a selection attaches only to a population a cap, the timeout or the rate
       limit cut.
   - *Code review of 6b* (`code-reviewer`), five should-fix and three nits, all fixed, with
     tests (mail order, forwarding selection, expired token, Recon's notes, Check's
     status); the re-review and a final targeted review are below. Should-fix: Workspace's Check reads run before
     GitHub's (the session token lives about an hour from Recon's bootstrap), and a read
     stopped by the token expiring (`unavailable:bootstrap_required`) is a limit, so the
     tenant is `incomplete` with `limit_reached` (exit 2, was `failed`) and a cut per-user
     population gains its selection, while expiry still never preserves an authorization;
     Recon knows from the profile whether grants and forwarding are read, writes no readout
     for them and notes that Check reads them; the selection words print tiers in tier
     order and take the fallback words from the unit and kind; credential warnings raised
     by Check's reads go to stderr as Recon's do. Nits: the plan text said the profile
     reads no OAuth grants only when it does not; `plan.json` keeps `primary_email` as
     read (sorting is case-insensitive); `PlanDoc.method` names repositories and
     Workspace accounts; the `CheckDoc` comment. Only OAuth grants and forwarding carry
     a Workspace selection; Recon's per-user assignment cap (10,000 observations) carries
     none.
   - *Re-review of 6b* (`code-reviewer`), one should-fix and three nits, all fixed, with
     tests; a final targeted review found it clean. Should-fix: after a Workspace token
     expiry the gate answered only the first read with `unavailable:bootstrap_required` and
     every later read as `refused:tenant_binding` (the drop of authentication unbinds the
     session), so forwarding lost its selection and blamed the binding. The gate now keeps
     a per-session `expired` state that halts every later non-bootstrap read with the
     expiry, repeating `unavailable:bootstrap_required`, until `workspace.bootstrap_customer`
     is attempted; no token or binding is kept. Nits: Recon's note names only the selected
     surfaces; Recon's outcome detail no longer claims grant or forwarding checks were
     collected; test assertions.
   - *Deferred, pre-existing and not 6b, to be assigned:* after a mid-run HTTP 401 on a
     bound Workspace read, later reads halt as `refused:tenant_binding`, so a revoked
     credential's later gaps are worded as a binding failure. Wording only; nothing is
     admitted.
   - *Code review of 6a* (`code-reviewer`), all fixed, with tests. Must-fix: a refusal
     sent in Check was lost where Recon left the root incomplete, and `githubStatus`
     dropped the refusal kind; a kind cut on the access pass did not mark later kinds on
     that repository cut. Should-fix: the meter counted calls the gate did not send; the
     spec and the code disagreed on which tiers are never cut (declared `assets` entries
     are; tier 2 selected repositories and tier 3 public ones can be cut); history
     sub-items were dropped without a mirror (now `mirror_not_declared`); `recon.json`
     said `collected` for repositories not yet read. Nits: an incomplete repository list
     was not a lower bound (`selection.in_scope_at_least`); `github.undeclared_public_repository`
     was omitted from the access kind and not judged past the budget. A re-review is
     ran again (the third and fourth rounds follow).
   - *Second review of 6a*, all fixed, with tests. Must-fix: an absence was disproved over
     unread repositories after a deadline (now `Evidence.RepositoriesUnread`: the
     rules abstain). Should-fix: the meter did not count sent-but-failed requests (the
     gate's `Result.Sent`); any failed object was treated as not found (`NoObject` is a 404
     or another repository's object; a failed read stays unread in `in_scope`); collaborator
     candidates were printed nowhere and Workspace attribution was dropped after Check
     (`check.json` carries the people fields, `--stop-after check` prints the stanza). Nit:
     a mirror audit write failure skipped the refusal re-check (it now follows it and
     replaces a recorded limit or failure for the root with `failed`). *Deferred* (nit, to
     be assigned within E9): the unbudgeted `CollectAccess`, `CollectCI`, `CollectAlerts`
     and `CollectHistory` remain, used only by tests (`github_ci_run_test.go` in the gate
     and the collector tests); move those tests to `CollectRepositories` and remove them.
   - *Third round of review findings of 6a*, both should-fix, fixed with tests. A kind's
     population counts a repository as read only when the kind read it (the access kind
     when its object was recognized; later kinds when a request was sent or answered from
     the ledger; a 404 repository is asked, not read). A gate result that says every later
     request would be answered the same (`Repeats`: rate limit, deadline) stops Check from
     starting another repository; the one in progress finishes its kind and the stop is
     `limit_reached`, never the budget's. `github.undeclared_public_repository` fires from
     the organization list for any public repository whose object Check did not read
     (budget, deadline or failed read); `github-collector.md` and `engagement.md` now agree.
   - *Fourth round of review of 6a*, all fixed, with tests. Must-fix: a declared repository
     a rate-limit or deadline stop left unstarted was reported `failed`; it is now an access
     entry `unavailable:not_started`, reason `limit_reached`, with the stop's detail, for
     declared repositories only, so it reconciles to `limit_reached` and is listed
     incomplete. Should-fix: `secret_locations` counted unread a repository with no alert to
     locate (a kind needing no request counts read). A later should-fix: the not-started
     entries for undeclared repositories produced duplicate readout notes and not-assessed
     entries; they are now declared only, and undeclared ones are unread through `Kinds` and
     `RepositoriesUnread`. Nits: test assertions and a comment. Step 6a is done.
   - *Deferred, pre-existing and not 6a, to be assigned:* a declared repository answering 404
     ends `not_collected`/`failed` with exit 0, and its gate reason `insufficient_permission`
     is not surfaced.
   - *Design, `modularity` agent (code detail, not contract):* the GitHub collector owns
     tiers, kinds and the budget: `Collect` (inventory, Recon), `Select(inventory,
     context) Selection` (Plan) and `CollectRepositories(ctx, sender, selection, input)`
     (Check), with an unexported meter that counts every `Send`, ledger answers included.
     `recon.json` keeps the inventory only; Check's evidence goes to `check.json`
     (`CheckDoc`, assets) and Analyze judges the union. A shared `finding.Selection {area,
     unit, tiers[{basis, source, count}], fallback, read, in_scope}` is what the report
     words; the population JSON gains `selection`, plus `spent` and `budget`. Check's audit
     lines, the mirror's included, carry stage `check`.
   - *Verified:* every finding id named in the not-judged list exists in
     `internal/finding` or its collector.
7. The follow-up table, the loop and its invariants test; F1 with
   `github.collaborator_permission`; F1b and F2 recorded as answered by the access pass
   and Workspace tier 1. Done (offline). Decided by the `security-consultant` (define,
   2026-10-15), adopted by the implementing session. The table has one row, F1: F1b would
   have no consumer (no rule reads branch protection for R4) and F2 duplicates Workspace
   tier 1, so neither is a row; the invariants test still enforces depth at most 2 and
   acyclicity, and the depth-2 allowance is unused in 0.0.2. F1 settles R4's "not listed"
   cause and, in one narrow case, makes an abstained leaver judgment fire, never disprove
   one; its causes, cap of 20, order, loop and `check.json` `follow_ups[]` are in
   `spec/engagement.md` ("Plan selection and follow-ups", R4), the operation's frozen
   fields and interpretation in `spec/github-collector.md`. The Workspace leaver finding
   names the reads that did not happen and gains a remediation sentence
   (`spec/workspace-collector.md`, "Rules"); the Identity row's departed-people item
   carries the coverage line and the fixed not-judged item is reworded
   (`spec/report.md`, "Coverage").
   - *Design, `modularity` agent (code detail, not contract):* the follow-up table is data
     in `internal/engagement/followup.go`; the permission read lives in the GitHub
     collector (`permission.go`); the triggers are judged in memory in Check, over Recon's,
     Check's and the follow-up evidence, and not persisted.
   - *Code review of step 7* (`code-reviewer`), no must-fix. Should-fix, fixed with tests:
     a declared `[bot]` login opened pairs that were refused; the limit and refusal
     outcomes were untested. Nits, fixed: a read sent and stopped by a limit was worded
     "not asked" (it is `failed`, worded as a failed read); the gate did not pin the op id
     and retained fields of the `CollaboratorLogin` read; the spec's order sentence was
     ambiguous (the round is now the primary key).
   - *Re-review of the step 7 fixes*: two should-fixes, fixed: after a 401 the loop kept
     sending with the rejected token; a limit applied before sending was reported as sent
     and failed.
   - *Third review of step 7*: a must-fix, fixed: a request sent but answered by no response
     (the deadline in flight) was worded not asked; reads now keep the gate's `sent`.
     Should-fixes fixed: the coverage count used another rule; the 401 tests did not count
     requests or cover two roots.
   - *Deferred from step 7:* F1 for repositories not declared `deploys_to: production`;
     a departed person's GitHub Apps, personal access tokens, SSH keys and deploy keys;
     a `+1 attribute:left` on `workspace.external_forwarding` for a left person's mailbox
     (the next change to the severity table); lab assertions for the 403 behaviour and
     the 200 `none` answer; a test that a ledger answer on resume counts against the F1
     cap; building F1's request parameters from the row's declared sources (the run test
     asserts them instead).
8. *(done, offline).* The 7-day resume maximum (a zero
   collection time counts as expired, so a kept observation with no recorded time is
   collected again), the oldest collection time per asset in the report, and the critical
   definition with its ceilings in `spec/engagement.md`.
   - *Define:* `security-consultant`, adopted as is by the implementing session. The
     rule is `0 <= session start - collection time < 7 x 24 hours`; a zero time and a
     time after the session's start are expired. The define asked for one stderr line per
     collector for the ledger; the ledger's records carry no collector, so one line is
     printed for all.
   - *D1 applied to the host table (decided, step 8):* the host grader
     (`host-collector.md §5.3`) caps a finding left above high at high once, after the whole
     table, as the engagement's ceilings require, so an internet-facing root login no longer reaches critical. This
     deviates from the v0.0.1 host contract.
   - *Closed, carried from steps 4 and 7:* the R4 coverage sub-item "Push to production by
     people who left: not judged" (`spec/report.md`, "Coverage").
   - *Code review:* no must-fix. Should-fixes fixed: the capped host step left no trace in
     the report (now "Why here"); the per-step cap lowered an internet+dev host finding to
     medium (security-consultant: cap once after the whole table, option b);
     `oldest_collected_at` counted failed reads; two resume tests depended on the date.
     Nits fixed: a future collection time worded as "older than 7 days"; a critical-base
     finding's chain.
     A re-review found a must-fix, fixed: a request's host-name DNS answer, which shares
     its id, dated an asset whose read failed (decided per request now); should-fix fixed:
     a 200 the gate ended as unavailable dated an asset; nit fixed: "they" for one read. A
     third review found a should-fix, fixed: a request the gate stopped after looking up its
     host (no such name, a private address, the deadline) dated an asset by its DNS answer;
     nits fixed: a Workspace token exchange dated a tenant, and the spec did not say the
     local mirror's line never dates an asset.
   - *Deferred:* an asset whose expired reading was read again and failed gets no "an
     earlier reading of <date> was older than 7 days and was not used" detail; a kept
     host's coverage line prints only the time, not the date, when it differs from the
     header's first date; no run test takes a host's cap from the grader through to the
     report's "Why here" (a unit test sets it by hand; nothing round-trips the in-memory
     `CappedBy` through JSON today).
   - *Closed in step 9:* the `HostAccess` flag on the host posture findings
     `sshd.password_auth_enabled`, `sshd.root_login_enabled` and `accounts.empty_password`
     (D8 is built in step 9, below).
9. E9 joins the merged slices in `internal/engagement/interview.go` (`MergedSlices` gains
   E9); `scheck init` asks `data.matters_most` again, run through the `client` interview
   mode on the wording, and gains the `expected_services` consumers
   (`db.listens_unfiltered`, `svc.listens_beyond_declared`; carried from step 5a).
   **Decided 2026-10-16 by the `security-consultant` on the owner's delegation**
   (built, offline). `spec/engagement.md` ("Intake", "Severity in context", "Plan selection
   and follow-ups") and `spec/report.md` ("Summary", "Not checked") carry the wording.
   - The `data.matters_most` question: offered assets, answer lines, refusals, and the
     `repo:` line that writes an `assets` entry. Consumers: `severity.data_matters_most`,
     `plan.github_tier4`, `report.rank_tiebreak`, `report.matters_most_readout`.
   - The `context` question's service line asks the audience
     (`service: <port> <tcp|udp> [localhost|lan|vpn|internet] <purpose>`); `airgapped`
     is refused; no audience is accepted with a printed note.
   - Plan's not-judged sentences for `svc.listens_beyond_declared` and an empty
     `data.matters_most` are reworded.
   - D8 built: on a host asset only `HostAccess` definitions move, whatever their area,
     applied by the engagement after the host collector's table; the host envelope keeps
     the collector's severity. `svc.listens_beyond_declared` does not raise on a
     `data.matters_most` host.
   - The report's summary gains the `summary.matters_most[]` readout, and "Not checked"
     lists items on a named asset first.
   - The readout has five outcomes (`raised`, `read`, `partial`, `not_judged`, `not_read`)
     and says `read` only over checks that decided (decided 2026-10-16,
     `security-consultant`, after review: "nothing found" had been said over checks that
     never decided). The interview refuses an excluded, repeated, already offered,
     undeclared-org or malformed `repo:` line and a description over 120 characters.
     `findings.json` gains `host_chains` per host asset; the `-v` fact sheet shows the
     engagement report's severity.
   - *Review record (2026-10-16).* Client interview (`client`, brightcart's Dani): she
     typed `service: 22 tcp MSP and Leo only, ssh`, a person where the audience goes. It
     is accepted as no audience, with the note, and kept as a test case
     (`TestBrightcartServiceAnswerKeepsWhatDaniTyped`); no wording change on one client's
     misreading. Carried, not fixed, to 0.0.3 G4 (the next slice that
     changes the interview): (1) whether SSH is internet-facing is hard to place as
     internet, vpn or lan; (2) the Postgres example in the `context` question may be
     copied as a pattern; (3) what "a host holds the data" means is unclear. The next
     `client` interview run on the wording decides each. Code review (`code-reviewer`): no must-fix. Should-fix, all
     fixed with tests: the `repo:` line accepted an excluded repository (`init` then
     exited 3); the readout said "nothing found" over checks that never decided, and
     counted only moved findings; no test drove Analyze's host raise
     (`TestDataMattersMostRaisesAHostsAccessFindings`); `findings.json` and the `-v`
     fact sheet carried the collector's severity beside the raised one. Nit fixed: a
     repeated repository line got the naming refusal. The step 8 `HostAccess` item is
     closed. A re-review of the fixes found a must-fix, fixed with a test
     (`TestMattersMostReadoutCountsOnlyWholeDecisions`): a disproval over part of a read
     counted as decided, so the readout could say every check decided where coverage said
     partial; such a check is now undecided, with its own reason or
     `unavailable:incomplete_read`, and a rule not applicable on the platform is not
     counted. A targeted review of that fix was clean; its two nits are fixed. Should-fix fixed: the `repo:` line's
     no-words refusal gave an example that was itself refused. Nits fixed: the
     `host-matters-most` golden's sshd assessments now match its findings; a host chain's
     `base` is documented as the severity after the host table. Spec drift the re-review
     saw was already synced.
   - *Slice close (2026-10-17):* `spec-steward` audit: no drift in code, goldens or
     schema; AGENTS.md's tables, step 9's carried owners and an example comment fixed.
     Whole-slice `code-reviewer`: no must-fix. Should-fix, fixed with a test: the
     `context` answer took the same port twice, which intake then refused after every
     answer was lost; it is now refused in the interview, and a refused `context` answer
     changes nothing. Nit, fixed: the F1 cap's sentence says permission requests, not
     production repositories (`spec/engagement.md` agrees). The re-review of those fixes
     found no must-fix or should-fix; its nits are fixed (`Apply` documents that its
     caller restores on refusal, as `init` does). `svc.expected_missing` moved to info
     (above).
   - *Status:* E9 is done, offline, its slice-closing audit and review run. The
     acceptance record is separate and not run.

R3 may move out of E9 if the slice runs long; a deferral is recorded here with its owner.

**Decided 2026-10-13** (owner), on the `security-consultant`'s define of the same day.
`spec/engagement.md` and `spec/report.md` carry the wording.

- *D1.* A context raise may reach critical. Critical is "anyone on the internet can use
  it now, with no further step, and gets credentials, code execution or the tenant; or a
  high that someone with no right to it can use now, or that the company believes is
  handled". The raises that qualify are `contradiction`, `attribute:admin` and
  `attribute:production_write` on a person who left, and `attribute:public_repository`.
  `deploys_to:production` and `data_matters_most` stop at high, and the chain says so
  in the words of `spec/engagement.md`, "Severity in context", "Ceilings". Past-high is
  as that table lists it: no other raise passes high.
- *D2.* A resume keeps no observation older than 7 days: compiled in, no setting. It
  applies to the Scope document, the host envelopes and the gate ledger's successes,
  from each observation's collection time to the resuming session's start. An expired
  one is collected again, never an error; a failed collection again leaves the asset
  failed or unread, never the old data. The report prints the oldest collection date per
  asset.
- *D3.* The host gains `fw.iptables_backend`: literal argv `realpath -e
  /usr/sbin/iptables`, Linux only, not elevated, `Baseline: true`, `MinProfile:
  baseline`. A target of `xtables-nft-multi` is `nf_tables`, `xtables-legacy-multi` is
  `legacy`, exit 1 (absent) means no `iptables` userspace so an empty `nft` ruleset is
  decisive, and any other target is unrecognized and R1 abstains. `iptables` stays in
  `deniedBinaries`; there is no exemption. An empty `nft` ruleset means no filtering only
  on the `nf_tables` backend. This is an exception to the 0.0.2 decision that the host
  gains no check (Decisions, "The host side?"). The golden command traces change with
  this reason, recorded under release gate 8. It does not count toward the baseline tier
  cap of 40, which counts on-demand entries only.
- *D3b* (decided 2026-10-15, `security-consultant`, adopted under the owner's standing
  delegation). `net.listeners` on Linux is elevated (`sudo -n -- ss -tulpnH`): `ss -p`
  names only the caller's own sockets, and databases run as their own users. Without
  `--sudo` the listeners fact is unavailable (requires elevation) and R1 abstains. The
  `scheck sudoers` fragment gains `ss` at `/usr/bin/ss` and `/usr/sbin/ss`. The golden
  command traces change by exactly the `fw.iptables_backend` line and by `ss` behind
  `sudo -n --` with its `which ss` probe (later `sys.which` observations renumbered),
  recorded with this reason under release gate 8. The eval cases
  `linux-truncated-listeners`, `linux-context-explains` and `linux-password-auth` keep
  their recorded output, with the argv in the elevated form.
- *D4.* A finding definition, and an adjustment entry, may carry a severity ceiling; the
  chain records the cap.
- *D5.* `scheck init` asks `data.matters_most` again, as a pick from hosts, Workspace
  tenants, GitHub organizations and repositories, url sites and cloud roots (not domain
  roots), with a number and a few words per line; the words go to `what` through the
  credential detector. Wording in `spec/engagement.md`, "Intake". This changes E8's cut of the key above, which stays as written there as
  history. `secrets.production[].asset` stays unasked; Plan reads it when present.
- *D6.* GitHub reads under a budget go breadth first by kind, within the tier order.
  The budget is a compiled request count, 4,000 per organization per run, for the
  per-repository reads Check sends (inventory and the local mirror not counted).
  `limits.timeout` and GitHub's rate limit still stop the run as `limit_reached`; the
  per-repository caps (100 workflow files, 100 alert locations) stay.
- *D7.* `db.listens_unfiltered` and `svc.listens_beyond_declared` carry a `service`
  subject (`<port>/<proto>`), so an acceptance names it. They are the first host-side
  subjects in 0.0.2, as engagement rules rather than host posture rules.
- *D8.* On a host listed in `data.matters_most`, the host access findings raise +1 by a
  flag on their definitions, not by area: `sshd.password_auth_enabled`,
  `sshd.root_login_enabled`, `accounts.empty_password`,
  `accounts.empty_password_remote` and `db.listens_unfiltered`. Time sync, auditd and
  updates never move.
- *D9.* `log.auditd_inactive` stays in the hosts area; the logging row prints "not
  checked" in 0.0.2.

**Decided 2026-10-13** by the `security-consultant`, on the owner's delegation, on the
twelve items the first draft left open:

- Per-item reads move to Check, after Plan. Recon reads inventory only; Check runs every
  read only rules consume, in Plan's order.
- The GitHub budget is a compiled 4,000 requests per organization per run (D6).
- The host check is `fw.iptables_backend`, and `iptables` stays denied (D3).
- A table cap and a definition ceiling each have their chain wording
  (`spec/engagement.md`, "Ceilings"). The past-high column stands as written.
- An unbuilt fixed sub-item makes its row *partial*; the "not judged" line also lists
  limits inside built sub-items.
- The `data.matters_most` question's offered assets, prompt and help are as in
  `spec/engagement.md`, "Intake"; its consumers are the raise, Plan's repository tier 4
  and the ranking tie-break.
- Within every Workspace user tier: active first, then most recent sign-in, then
  `primaryEmail`; a suspended leaver dropping is intended.
- Host acceptance by subject stays unbuilt; only R1 and R3 carry a `service` subject.
- R2 is moved by no host context step: critical on `dev` and `airgapped` hosts too.
- Step 1 semantics. `exposed_on_purpose` is terminal: no later table step applies, and
  each skipped step is recorded "not applied: declared exposed on purpose
  (`intent.exposed_on_purpose[i]`)". A definition's ceiling binds every step, the host
  collector's `exposure:internet` step included, with the definition-ceiling wording.
  The `data_matters_most` adjustment cites `data.matters_most[i]` and the readout prints
  that entry's `what`. Time-dependent rules judge against the collection time of the
  observation they read, not the session start (the leaver rule, stale and
  never-signed-in accounts, certificate expiry and its 14-day window, acceptance
  expiry); step 1d applies this because it makes a resume re-judge persisted evidence, and
  step 8 adds only the 7-day cap.
- Step 1d clocks, decided 2026-10-14 (owner, on the `security-consultant`). A date
  condition is judged at the moment scheck saw the thing it is about, named in the
  excerpt in `engagement.timezone`, never the session start or render time; where
  unclear, abstain. Population-based conditions (the leaver rule) fire on the read(s)
  that observed the account and disprove on the earliest read of the population; a date
  that falls within collection abstains. Stale and never-signed-in accounts use the
  per-account detail read. An acceptance's expiry uses the latest read its finding
  cites, and means nothing for a finding that did not fire. A read with no recorded
  collection time makes the rule abstain, and step 8 treats a zero collection time as
  expired on resume (not built). Also time-dependent, each against its own read: a
  Workspace role assignment's `expireTime`, `security.txt` `Expires`, and a timestamp
  later than its read plus 5 minutes (malformed). The list in `spec/engagement.md`,
  "Severity in context", "Time" is complete. Readout notes about a departed person
  share the rule's clock and gating.
- Step 1 design, from the `modularity` agent (network collectors built in 1b, hosts in 1c). Verdicts leave the evidence types
  (`githubc.Evidence.Judgments`, `workspace.Evidence.Judgments`, `ReconAsset.Judged`);
  Analyze judges; `findings.json` carries every verdict with its severity chain as output
  only, never read on resume; a kept host is graded again in Analyze, so editing an
  acceptance or host context no longer collects a kept host again (`spec/runs.md`).

**Cut or deferred by the same decision.** `db.internet_reachable` (0.0.3 G4: needs cloud
firewall rules); the `pg_hba.conf` read after R1 (0.0.3 G5); `net.unexpected_listener`
as a rule (never: it would file the absence of an explanation; at most a readout line);
`fw.no_firewall_active` alone, which stays unfired; a contractor-can-push finding, and the
enrichment of `github.default_branch_unprotected` with push holders, cut from 0.0.2 and
carried to 0.0.3 G4 with "at least" framing; per-account keying of
`accounts.empty_password`, a 0.0.3 G5 candidate; `data.matters_most` along a repository-to-host link (0.0.3 G4).

**Carried from the engagement-spec review** (security-consultant, 2026-10-09), closed
2026-10-13 (owner) unless marked open:

- *Plan has no job with rules only, and the stage table is wrong about where rules
  run.* Closed. Plan gets selection under a budget (tiers above); every rule verdict
  moves to Analyze (step 1).
- *Recon "fills gaps in the context and flags where it is wrong".* Closed. The stage
  table says what Recon does list (accounts no handle names, tenant domains that are
  not roots), and Analyze notes contradictions (C1 to C3).
- *Termination by construction.* Closed. The follow-ups are a static table of depth at
  most 2 under an invariants test; a follow-up that ended without success is not
  reopened in the same session (step 7).
- *"Checked" cannot be told from "checked thinly".* Closed. The sub-item lists are fixed
  per area and every row prints "not judged in this version: …" (step 2). An unbuilt item makes
  its row *partial*, and the line also lists limits inside built sub-items.
- *`data.matters_most` raises along declared links.* Closed. No new shape: `deploys_to`
  stays a string, the raise stays on the named asset, a Workspace tenant's identity
  findings and a host's flagged access findings (D8), and a link from a repository to a
  host is 0.0.3 G4.
- *A declared `not_used` area the evidence contradicts.* Closed. C3 (step 5).
- *Resume maximum age.* Closed. D2, 7 days (step 8). The date on `Observed` across a day
  is E7 step 5's, already implemented.
- *May a context raise reach critical?* Closed. D1.
- *From E6 step 5:* whether `data.matters_most` with `attribute:admin_grantor` may reach
  critical. Closed: no (D1; `attribute:admin_grantor` stops at high). The rest of the
  step 5 items stay open: findings grouped in "Fix these first", lab ranking of Drive for
  desktop and Apple Mail on admins, collapsed per-read `Observed` lines, and the OAuth
  wording and coverage items in E6, "Carried from step 5".
- *Still open, from E6 steps 4 and 6:* "Fix these first" collapsing many unit instances
  of one finding into one line, and the step-4 client REPORT wording items listed in E6,
  "Carried from step 4"; `data.matters_most` for email-area Workspace findings, collapsed
  forwarding instances in "Fix these first", whether `hides_mail` raises or ranks, lab
  ranking of forward-and-hide filters against helpdesk and accounting forwards, the client
  REPORT items listed in E6, "Carried from step 6", and the mailbox-authorization wording
  left open there (header currency, an incomplete user list, and a `note` that does not
  say it limits who is signed in as).

### Release gates

None of these was run. `release/v0.0.2` was merged into `main` on 2026-10-24 without
them, and the lab-measured ones are deferred to v1.0.0 ("Release gates and the lab").

1. `scheck init` produces an engagement file for the lab, and `scheck run` takes it
   through all seven stages, each inspectable with `--stop-after` and resumable.
2. **Recall:** the run is recorded against the sealed labels; every miss is recorded as
   a miss before any check is added to fix it.
3. **False positives:** the clean variant's findings are counted against the target
   fixed in E3.
4. **Context:** both context cases behave as stated, beside a run without context.
5. **Prioritization:** a named reviewer who wrote none of the checks ranks the lab's
   issues before seeing any scheck output; at least four of the reviewer's top five are
   in scheck's top five. Without such a reviewer the gate is recorded as *not run*.
6. **Coverage:** every risk area's mark matches what ran by the definitions in
   `spec/report.md`, for the lab and for an engagement with a collector missing or
   credentials withheld; the reason is printed, and the run with a declared root
   unassessed exits 2.
7. **Scope:** only the observe level reaches any asset, no request leaves the declared
   entry points, and the audit log shows every request and API call. The lab host's
   integration diff stays the exact allowlist of `spec/host-collector.md §1`.
8. `make check` is green; the host collector's command traces and redacted output are
   unchanged, and its facts and findings equal 0.0.1's for the same inputs, except
   where a 0.0.2 slice changed a rule on purpose and records why (E5a: an account
   with no password and no login shell no longer fires, and one with a login shell is
   high, not critical; the accounts summary counts login shells by the rule's lists; E9: the golden command
   traces gain the `fw.iptables_backend` line, the one host check added in 0.0.2, decided
   2026-10-13 by the owner, and the elevated `ss` read of `net.listeners`, with its
   `which ss` probe, decided 2026-10-15, D3b).
9. **Consumers:** every consumer declared by an interview question exists, and the
   test that checks it no longer skips anything.
10. **One command:** `scheck run --host` on the lab host and the `scheck ssh` alias
    give the same report and command trace, and the host's facts match the host asset's
    in the full engagement run, and its findings do for the same context; no run reads a
    config file.
11. **Mailbox authorization** (owner's decision, 2026-10-11): an explicit authorization
    entry in the engagement file, recorded in the audit log, gates signing in as each
    active mailbox for Gmail forwarding reads; the environment variable alone does not
    (E6, "Carried from step 6"). **Done offline 2026-10-11**, not acceptance and not a
    live measurement: fake servers (`httptest`) and unit tests, with `make check`
    green, recorded in
    [eval/e6-mailbox-authorization-2026-10-11.md](eval/e6-mailbox-authorization-2026-10-11.md).
    No independent acceptance is claimed.

**Sequence:** E1a → E1b → E2 → E4 → {E5, E6, E7, E8} → E9, with E1c at any point after
E1b, E5a before E5 and E6 (alongside E7), and E3 built alongside and sealed in parts,
its domain part before E7 and the rest before E5 or E6. E7 is the first network
collector, before E5 and E6, because the operator needs the domain, email and web reads
first. The host path and the report come first because they need no network
and can be proven on evidence that already exists; the lab comes before any network
collector so that recall is measured, not confirmed; the interview comes with the
collectors, whose rules read its answers.

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
| The 0.0.2 aliases? | Removed, as 0.0.2 promised. `scheck local` and `scheck ssh` are unknown commands (exit 3, nothing collected), and `--include-evidence` is a flag of `scheck run --format json` only. The refusal of a 0.0.1 `scheck.yaml`, user configuration file or `./.scheck/context/` directory by `scheck run` stays (`cmd/scheck/legacy.go`; `spec/host-collector.md §8`). |

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

**Carried from E7's definition** (2026-10-09): the definition of an exposure finding
(`spec/engagement.md`, "Severity in context") must cover "a named resource readable by
anyone" (a public bucket), as the high anchor "a bucket readable by anyone, not
declared public" assumes; today it covers only a URL that answers or names its
software.

### G2 — first-party evidence from inventory

**Delivers:** external addresses, load balancers, Cloud Run and App Engine URLs from the
inventory become first-party evidence for assets discovered under domain roots; Cloud
DNS zones suggest domain roots in the Scope stage, confirmed by the operator.

**Done when:** a discovered address present in the inventory becomes first-party with
that evidence named in the report; one absent from it stays observe-only.

### G3 — probes

**Status: built** (2026-10-31).

**Delivers:** the reviewed probe list, each a single `GET`; the `off`, `confirm` and
`all` modes; the preview of every planned request; the authorization block and a window
required for any probe; the interview's framework question, since it now selects which
probes apply (`spec/scope.md`, "Probes"; `spec/web-collector.md`, "Probes").

**Built:**

- Gate: the ceiling is *probe*; scan stays refused. Step 6 calls `Scope.Allows` (mode
  `all`, or `confirm` with the request approved live in this session; approvals are in
  memory); steps 7 and 8 call `Scope.AdmitsProbe` (first-party evidence at the origin;
  new audit rule `first_party`). A probe op declares a signature and a 4 KiB cap; the
  gate tests the redacted prefix and drops the body; no retry, no redirect. Registry
  validation refuses a malformed probe op (`gate.checkProbe`).
- Collector: `web.Probes` (13 entries, `ProbesVersion` 2026-10-31), one op each,
  `web.Judge` verdicts, and the findings `web.vcs_metadata_exposed`,
  `web.config_file_exposed` and `web.debug_interface_exposed`.
- Engagement: `defaults.probe` / `assets.<name>.probe` (`off`, `confirm`, `all`, on
  domain and url assets), `defaults.framework` / `assets.<name>.framework`, a probe mode
  requiring an authorization window. Plan previews (`plan.json` `probes`,
  `probes_unevidenced`), Check asks per site (`cmd/scheck/probes.go`) and writes
  `check.json` `assets[].probes`; Analyze judges.
- Report: the coverage sub-items `exposed files` and `debug and status pages` for an
  asset that had probe judgments, `method.probes` (`ran`, `none_ran`), the Method,
  Authorization and "Probes and scans" lines true to it. All text goldens changed by the
  one "Probes and scans" line.
- Interview: the `framework` question (consumer `web.probe_selection`, slice G3).
- Example: `docs/examples/probes.yaml`.

**Decisions:** the security-consultant's define pass said a login page that exists is an
observation, not a finding, so common admin panels are not on the list. Django has no
probe: its debug page is a `404` and the gate matches only `200`, so it waits for a
signature that can name its status. No framework declared means only
the probes that apply to every site; a framework is never guessed from responses. An
unrecognised answer is never a pass: a `200` that does not match is *disproved* only when
nothing was redacted and, for a text file, the type is `text/plain` or
`application/octet-stream` (an HTML page is disproved as "not the file"; any other type or
none abstains, `unavailable:content_type`). Text-file probes refuse only HTML types
(`ProbesVersion` 2026-11-01).

**Carried from G3** (2026-10-31):

- `security-consultant` review-mode pass on the probe list and signatures. The define
  output was partial (paths and signatures withheld), so the list is the implementer's.
- The interview does not ask for a probe mode or the authorization block; the operator
  writes them by hand. `spec/engagement.md`, "Intake: the engagement file", says authorization is
  asked when a probe mode is chosen.
- The Scope stage's first-party confirmation prompt (`spec/scope.md`, "First-party
  evidence") is not built; the operator writes `first_party` by hand.
- Review (2026-10-31) leftovers: Plan's preview does not filter requests an `exclude`
  covers (the gate refuses them as `excluded`); a probe answered `429`, `5xx` or by a
  reset is sent again on a resumed session, since only a success is reused.
- The first-party evidence a probe rests on, "operator confirmed" included, is named in
  the excerpt of each probe verdict that was sent, as well as in Plan's preview and the
  confirm prompt; the report has no per-site evidence table of its own.
- The lab web tier gains a served `.git` directory with the lab (G7).

**Deferred from G3:**

- Common admin panels: a login page that exists is an observation, not a finding.
- A control request per origin (a path that must not exist), which the consultant
  suggested against catch-all responses. Page-specific strings make a catch-all match
  improbable and text-file probes never match an HTML page, so it is not needed yet.
- An attribute that raises a probe finding to *critical* needs a row in
  `spec/engagement.md`, "Severity in context", ceilings.
- Listing, per probe, the framework-specific probes not selected; Plan counts them
  (`framework_skipped`) and the report counts them in the sub-item's reason
  (`unavailable:probe_framework`) without listing them.

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
and checks the credentials' scopes before the first run. Carried from E9 step 9
(2026-10-16), client interview wording: the SSH audience is hard to place as internet,
vpn or lan; the Postgres example may be copied as a pattern; "a host holds the data" is
unclear. Carried from E9 (2026-10-13): a
finding for a contractor who can push to a production repository, or naming the push
holders and contractors on `github.default_branch_unprotected`, with "at least" framing.

**Done when:** every rule has its three fixtures, and intake reports missing or
over-broad credentials before any target contact.

### G5 — host depth: credentials and exposure on disk

**Delivers:** catalog checks and rules for what an attacker on a small company's server
or laptop looks for first: mode and ownership of `.env` files under the application
paths a host asset declares (`app_paths`, asked by the interview from this slice, when
it gains its consumer), `~/.ssh`, `~/.aws`, `~/.config/gcloud` and the docker socket; a
cloud-vendor label from DMI (metadata reachability is not built, step 2); a
listener-exposure multi-fact rule (listener, host firewall, and for a cloud host the
firewall rule from G1, which waits for G1). Each is a catalog entry under the host
collector's rules (`spec/host-collector.md`), with the golden trace change explained.
Carried from E9 (2026-10-13): host acceptance by subject, with `accounts.empty_password`
keyed per account, as a candidate.

**Build step 1 (built):** `creds.home_files` (Linux elevated, macOS not), `docker.sockets`
and `creds.app_env_1` to `creds.app_env_5` (one per declared `app_paths` folder,
unelevated by decision), the `find_ls` parser, and the findings `creds.env_file_exposed`,
`creds.ssh_key_exposed`, `creds.cloud_credentials_exposed` (secrets, medium) and
`docker.socket_exposed` (hosts, high, `HostAccess`), judged on mode bits and the folders
above (`spec/host-collector.md §3`, §6.5); a listing that shows no file never disproves, a macOS listing never disproves (the `.env` rules are `FireOnly`, enforced by `finding.ValidateRules`), the runner refuses a walking slot when a `deny_paths` entry lies inside its resolved root (`check.Check.Walk`, `path.deny_inside`) and ends it `unavailable:path_unresolved` when `fs.realpath` cannot resolve the root (find never runs), a `find_ls` line whose path holds a redaction marker is unparsed so the set is partial, and
a `.env` under a home is not judged. The path policy gains the metadata-only
entries and application trees of `§4.1`. The host asset gains `app_paths` and the
interview its question, after `context` (`spec/engagement.md`, "Host settings"). A host
named in `data.matters_most` raises on a credential kept on it, so its readout is
`partial` until a sample can decide (`spec/report.md`, "Data that matters most"). The
golden traces changed as `spec/host-collector.md §3` records, the Ubuntu and Fedora
fixtures were re-recorded, and `test/integ/creds_test.go` seeds the cases.

Fixes after step 3 review: `NewPathPolicy` also holds each `deny_paths` entry in its canonical form (adds
denials only), `hostasset` compares that form when it disables `creds.home_files`, a `path.deny_inside` refusal
is counted under `deny_paths` as a whole in the report, and the `app_paths` question no longer mentions a
laptop and says a folder under `/home`, `/root` or `/Users` is accepted but its `.env` is listed and not
judged (`spec/engagement.md`, "Host settings").

**Build step 2 (built):** `sys.dmi` (Linux, unelevated, `ExitOK` 0, 1 and 2) and
`check.CloudVendor` (`CloudVendorsVersion` 2026-10-24): the fact sheet prints `cloud VM:
<provider> (from DMI)` or `cloud platform not identified`. It is plumbing in the host
domain: no coverage row and no finding. The golden Linux trace gains one `sys.dmi` line,
the fixtures were re-recorded and the Ubuntu fixture plans 37 host checks
(`spec/host-collector.md §3`). Decided 2026-10-24: cloud metadata reachability
(169.254.169.254) is not built as a finding. It cannot be judged without sending a request
(non-negotiable 1); on a cloud VM every local process reaches it by design, a missing
firewall owner-match rule proves nothing new, and what the attached service account can
do belongs to the GCP collector (G1) and the G4 link (`spec/host-collector.md §11`).

Fixes after step 2 review (`Rule.OwnPartial`, collection time, coverage of the names):

- The framework no longer withdraws a runtime rule's disproofs for a partial fact nor marks
  the host's population incomplete (`Rule.OwnPartial`). Any partial runtime read (cut
  output, a half-installed dpkg package, the rpm sentinel missing, unrecognized lines)
  turns every would-be disproof into `unavailable:packages_partial`, naming the read;
  fired verdicts stand.
- A host-level "no PHP web package / no Node.js package" disproof needs an `os.release`
  `id` and release the reads cover (`advisory.Covers`: Debian 9+ and Ubuntu 16.04+ for dpkg;
  Fedora and the Red Hat family `rhel`, `centos`, `rocky`, `almalinux`, `ol` 8 or later for
  rpm); SUSE, Alpine, Arch, CentOS/RHEL 7, Amazon Linux, Debian 8 and older, derivatives
  (`raspbian`, `linuxmint`) and an unread `os.release` abstain `unavailable:distribution`.
  The rpm read also asks for Remi's `phpNN-php`, `phpNN-php-fpm` and `phpNN-php-cli` (the
  first judged as a PHP package, not as `mod_php`) and for `nodejs18/20/22/24/26`; its
  `ExitOK` is 0 to the number of names (`check.RpmRuntimeExitOK`).
- A partial read counts for the runtime rules unless the distribution is one the other manager
  covers (rpm partial ignored only where dpkg covers, and the reverse), so an rpm database that
  does not exist on a Debian host no longer cancels dpkg-based disproofs; on a distribution the
  reads do not know, or with `os.release` unread, every partial read withdraws disproofs. The host-level "no PHP package" disproof says in Not
  checked that a PHP running outside the package databases is looked for only among
  listening sockets, and only when read with sudo. `php_without_package` reads "no package of
  it was found"; the `runtime_installs` report text is shorter and the JSON detail keeps the
  examples. `node.line_unsupported`'s impact and remediation are line-generic (it fires for
  22, 24 and 26 after their dates).
- R9 is a dated rule, judged at collection time (`rules.Host.Collected`, `View.Collected()`,
  `finding.LeftAt`, from the kept envelope's `run.started` and `duration_ms`): not passed
  at the last read, disproved; passed at the first, fired; within the read,
  `unavailable:eol_within_collection`; no recorded time, `unavailable:collection_time`.
  The earlier "reads no clock" wording was false and is gone.
- Every per-package verdict cites `os.release`; a Node.js judged through the Brotli library
  cites the library's record. `finding.Def.CeilingWhy` words `php.fix_missing`'s stop at
  high (the cloud firewall and whether the web server passes requests to this PHP were not
  read); the `serves_web` sentence is shorter. A container proxy owning a port beyond
  localhost with no web server seen names the port and the container (`docker-proxy
  publishes 0.0.0.0:443/tcp, a container: what it serves, and any PHP or Node.js inside it,
  was not read`). The Debian "other nine flaws" line appears on Debian sources only;
  IPv6 listeners are written in brackets.
- The report tests' fake host carries lower-case `os.release` keys as the parser gives them
  and a dpkg read with no PHP, so the shared goldens show the Runtimes line as judged and
  partial.

**Build step 3 (built):** the multi-fact rule R6 `svc.sensitive_listens_unfiltered`
(`internal/engagement/rules/svc_sensitive.go`, its definition in
`internal/finding/multifact.go`, table version `SensitiveServicesVersion` 2026-10-24.2).
Linux only; area external surface, base medium, ceiling high, `HostAccess`, subject
`service`. It fires on a remote-administration service in its table (Docker's API,
etcd, kubelet, Telnet, FTP, SMB, RDP, VNC, Jupyter, SNMP, RabbitMQ management) that listens
beyond loopback with nothing in the host firewall in front, with R1's mechanics and
abstentions. The three classes with no sign-in by default (Docker's API without TLS, etcd, the
kubelet's read-only port) rank one step higher; a declared audience of `localhost`, `lan` or `vpn` adds the
`contradiction` step; an `internet` declaration fires at base; `exposed_on_purpose` never
lowers it. It joins the `exposure:internet` row, and R3 leaves a port to R6 where R6 finds a
table service on it, as it leaves a database port to R1; where R6 only doubts the owner, the
declared service stays R3's. A named program outside a row's processes on a table port is an
abstention, never a host-level disproof. Goldens `host-sensitive-docker` and
`host-sensitive-smb` pin a fired R6. The interview's `context` question lists R6 as a consumer,
and the fixed not-judged item `hosts.firewall_linux` reads "apart from database ports,
remote-administration ports and the services you declared" (`spec/engagement.md`, R6).

**Carried, not built in steps 1 to 3** (each needs a decision or a later step):

- `creds.authorized_keys_writable`, joined with sshd's `StrictModes`: deferred
  (`security-consultant`, 2026-10-31). `authorized_keys` is not in `credNames`, so it needs
  an argv change, a golden trace change and fixtures; `findPruned` lists only
  non-traversable folders, so a writable `~/.ssh` is invisible to it; and the `StrictModes`
  join, Debian's user-group modes and `AuthorizedKeysFile` from `sshd -T` make it a design,
  not a small item.
- `group_grants_root`: a named group is a deliberate share and is not judged.
- A rule for membership of the `docker` group: deferred (`security-consultant`,
  2026-10-31). There is no `/etc/group` fact; the deploy user is in `docker` on nearly
  every small server, and G5 decided a named group is a deliberate share, so a rule would
  fire on almost every host. It is better later as an informational "accounts effectively
  root" line that includes `sudoers` membership.
- Host acceptance by subject: `creds.*` per file (candidate subject `secret_location`)
  and `accounts.empty_password` per account (carried from E9, 2026-10-13). Deferred
  (2026-10-31): it is larger than a few hundred lines, an engine and report-contract
  change that needs its own decisions. Acceptance stays by id until then.
- The listener-exposure rule's cloud part, which needs G1's firewall rules.
- A presence readout note for credential files on production or internet hosts (G4).
- Elasticsearch and OpenSearch in R1's database table: built 2026-10-31
  (`security-consultant` decision, `DatabasesVersion` 2026-10-31). Matched as `java` on
  9200 and 9300 only, since the kernel names the bundled JVM; severity unchanged. The
  judgment never claims the program or its security setting: a Not-checked sentence says
  the program was read from its port and not confirmed. Other ports, or a store not shown
  as `java`, stay in the fixed `data.other_stores` not-judged item.
- DMI-driven wording: where the cloud platform is identified, the "Not checked" lines of
  R1, R3 and R6 could name that provider's firewall instead of "a cloud firewall"
  (undecided).

**Done when:** every new rule has its three fixtures; the integration diff is still the
exact allowlist; the world-readable `.env` seeded on the lab host is found.

### G8 — runtime security fixes (PHP, Node.js)

**Named G8 because G6 is taken** ("comparing two engagements") and G7 follows it; the
slice sits after G5 because it extends the host collector's depth. Decided by the
maintainer: it is a slice of its own, G8, not "G5 step 4". The advisory table is refreshed
one pull request per disclosure through the `advisory-refresh` skill
(`.agents/skills/advisory-refresh/SKILL.md`), which answers "who refreshes the table and
on what trigger". "Fix these first" ranks by the base severity table, so a serving
`php.fix_missing` is not ranked above other highs. The Alpine `os.release` defect was
fixed in PR #24. Whether the `pkg.*` checks are write-free with a stale apt cache is
deferred to a later integration test.

**Delivers:** a host that runs a PHP or Node.js package older than the fix of the
2026-10-21 disclosures is named, with the package and the fix of its own source. An
exception to the host collector's "No CVE database" non-goal, bounded by the written bar
in `spec/host-collector.md §1` and §11: a dated constant table of named disclosures
(`advisory.TableVersion` 2026-10-24), not a feed. PHP: CVE-2026-109618 and
CVE-2026-109619, fixed in 8.5.12, 8.4.27, 8.3.36 and 8.2.35; an exploit has been
demonstrated against Apache with mod_php. Node.js: ten CVEs fixed in 22.23.4, 24.22.1
and 26.12.1, among them CVE-2026-111497, the Brotli decoder write. scheck never runs
`php`, `php-fpm`, `node` or `brew`: the version is package metadata (§11).

**Build step 1 (built):** the catalog checks `pkg.dpkg_runtimes` (`dpkg-query -s` over
exact names) and `pkg.rpm_runtimes` (`rpm -q`), both unelevated, in a new domain
`runtimes` (fact sheet label "Runtimes (PHP, Node.js)"); the typed parser `packages` (`check.ParsePackages`: name, version, status,
manager); `php`, `php-cgi`, `phpdbg`, `brew`, `deno` and `bun` added to the denied
binaries, and `rpm` limited to a first token of `-q`; the leaf package `internal/advisory`
(standard library and `internal/check` only), which owns the table and its classifier.
`os.release` chooses the table row by `ID`, never `ID_LIKE`. The table (`TableVersion`
2026-10-24) holds the PHP and Node.js fixes, the dpkg ordering and `Assess`, which the
rules of step 2 call; every end-of-life date in it was read on 2026-10-24 from
php.net/supported-versions (PHP 8.2 2026-12-31, 8.3 2027-12-31, 8.4 2028-12-31, 8.5
2029-12-31) and the Node.js release schedule (20 2026-04-30, 22 2027-04-30, 24 2028-04-30,
25 2026-06-01, 26 2029-04-30). The golden Linux traces
gain the two package reads, the fixtures were re-recorded (every Linux output hash
changed: hostname, kernel, home-folder timestamps) and the Ubuntu fixture plans 39 host
checks, up from 37 (`spec/host-collector.md §3`). Nothing reads the advisory table yet:
no finding, no report line.

Fixes after step 1 review: `pkg.dpkg_runtimes` runs `dpkg-query -s`, not `-l`: one field
per line, which no terminal width cuts (the columns of `-l` are cut by `COLUMNS`); the
parser reads stanzas (`Package`, `Status`, `Version`), and a record's status is the third
word of dpkg's `Status`. A held package (`hold ok installed`) counts as installed;
`config-files` and `not-installed` give no record; the half states (`half-*`, `unpacked`,
`triggers-*`), a marker of redaction or truncation in a field and a stanza without name,
version or status make the read partial. rpm records are always installed
(`check.PackageInstalled` is the constant). The invariants hold `dpkg-query` to the verb
`-s` and `rpm` to `-q`, both names-only: no token after the verb may start with a dash, so
`--pipe`, `--rcfile`, `--dbpath` and `--admindir` cannot be added; the `rpm` denied tokens
stay as a second layer. In the advisory, Ubuntu and Debian provenance is anchored to each
distribution's own revision shape, not a substring; `.gbp` alone no longer means
deb.sury.org; an unread `os.release` gives the reason `os_release`; and the Node.js
end-of-life sentence stops at "says end-of-life versions are always affected. Its Brotli
decoder flaw is CVE-2026-111497."

Fixes after the second step 1 review: `pkg.rpm_runtimes` asks `rpm` first (the argv is in
`spec/host-collector.md` §3). The first name is a sentinel: when the rpm database cannot be
opened rpm prints "package X is not installed" for every name and exits like a host with
none, so the parser counts the read as whole only when a record for `rpm` is present, and
otherwise partial. `ExitOK` is 0 to the number of names (`check.RpmRuntimeExitOK`), not `check.AnyExit`, so a signal or crash is
unavailable. The parser drops the last record or open stanza of truncated output and counts
it unparsed; a purged or removed dpkg stanza (`config-files`, `not-installed`) has no
version and is no longer partial. The denied binaries gain `nodejs`, `npm`, `npx`, `dpkg`,
`dpkg-deb`, `rpmquery`, `rpmverify`, `rpmdb`, `rpmkeys`, `rpmsign` and any versioned `php`,
`php-fpm`, `php-cgi` or `phpdbg` name. `internal/advisory` reads the `os.release` keys as
the key-value parser lowercases them (`id`, `version_id`). Provenance shapes: Ubuntu
revisions `ubuntu`, `build` and `maysync` (a plain Debian-style revision on Ubuntu is not
Ubuntu's); Debian `+bN` binNMU; rpm `[.+]el9`-style module builds. A PHP line older than
7.4 on deb.sury.org or Remi gets the reason `backport_unknown` with its own wording (only
7.4, 8.0 and 8.1 are "unnumbered"). The end-of-life table gains Node.js 26 (2029-04-30).

Fixes after the third review: `pkg.rpm_runtimes` no longer asks for `php-cgi` or
`phpNN-php-cgi`, which are no packages on the Red Hat family or Remi (`/usr/bin/php-cgi` is
inside `php-cli`); it asks `php-cli` and `phpNN-php-cli` (48 names with `nodejs18` to
`nodejs26`). An rpm php-cli is not judged against the fix: it abstains `unavailable:php_cli`,
and while one is installed the host-level "no PHP web package" disproof is not said. dpkg's
`php<L>-cli` is still not read. A partial read counts unless the other manager covers the
distribution. The host-level disproof cites the read whose manager covers the distribution.
The Ubuntu integration test seeds Node.js 24, so it does not depend on the 2027-04-30 end date,
and `node.line_unsupported`'s impact no longer lists lines.

**Build step 2 (built):** three multi-fact rules in `internal/engagement/rules`, subject
kind `package`, risk area hosts, ceiling high, `exposed_on_purpose` never lowering them:

| Id | Base | Moves |
|---|---|---|
| `php.fix_missing` | medium | +1 `attribute:serves_web`, +1 `exposure:internet`, +1 `data_matters_most` (`HostAccess`); stops at high |
| `node.fix_missing` | medium | none; not `HostAccess` |
| `node.line_unsupported` | medium | none; time-dependent, judged at the host's collection time: a line the table holds a fix for (22, 24, 26) is supported until its table date, a line outside the table is end of life with no clock, and a distribution package abstains (`distro_package`); listed in `spec/engagement.md`, "Severity in context", "Time" |

R7 `php.fix_missing`, R8 `node.fix_missing`, R9 `node.line_unsupported`. No version-only
single-fact finding exists. `attribute:serves_web` is declared on the definition and set
only on Linux when a web-server process listens beyond loopback and R1's firewall reader
leaves the port open to every source; when listeners or the firewall cannot be read, the
finding fires at base and its `why_here` says it is rated at its base, with the reason (no
"not applied" chain step exists for this raise, decided 2026-10-24). The versioned list of
web servers is `rules.WebServersVersion` (`2026-10-24`). Node.js has no listener join.
Each rule fires when the installed version is below the fix of its own source, is disproved
per subject at or above it, and abstains when the distribution field is empty (the Red Hat
family and Fedora rows are empty; Alpine is unsupported), when the source is not
recognized, when `os.release` or the package read is missing or unparseable, or when the
read is partial (a would-be disproof only; see the fixes below).
The three coverage groups carry the standing gap `unavailable:runtime_installs`
(`Rule.Gap`, `CoverageGroup.Gap`), so a decided group is at most partial and the Hosts row
prints the reason (`spec/report.md`, "The Hosts row"). The report words each fired and
abstained judgment and the "Not checked" line as decided in the consultant's output of
2026-10-24 (`spec/engagement.md`, R7 to R9). The subject kind `package` joins the closed
list (`finding.SubjectKinds`, `docs/engagement-report-schema.json`), and `php.fix_missing`
joins the `exposure:internet` row of the severity table.

**Build step 3 (built):** `test/integ/runtimes_test.go` (`TestRuntimePackagesOnUbuntu`,
`TestRuntimePackagesOnFedora`). Ubuntu: stub dpkg packages seeded as root with `dpkg-deb`
before the diff snapshot, and a real nginx; PHP below the distribution's fix gives
`php.fix_missing` at medium, because the container cannot run ufw, the firewall is unknown
and the report says the rating is at its base; Ubuntu 24.04's `8.3.6-0ubuntu0.24.04.13`, the
fixed-package trap, is not reported. Fedora: rpm is read whole and shows no PHP or Node.js,
so nothing is reported. The Ubuntu test also asserts the PHP rule decided in the fixed-package
case and that no persisted audit record shows an attempt to run `php`, `node`, `npm` or
`brew`. Both hold the read-only diff to the exact allowlist, unchanged. The
`scheck` skill names the findings. No example is added: the runs are `docs/examples/host.yaml`
with no new key. The Ubuntu test uses `assertReadOnly` with `ubuntu`, and its guard against
a runtime being executed also catches a `sudo`-prefixed one. Known limitation: it runs
`apt-get install nginx` at test time, so it needs the network. The test does not seed a stale apt cache, so whether a `pkg.*` check
rewrites it when scheck connects as root is deferred to a later integration test.

**Carried, not built in this slice** (each needs a decision or a later step):

- Homebrew Cellar reads and `/usr/local` header reads (`php_version.h`, `node_version.h`).
  macOS gets no rule and says so.
- `php.line_unsupported`: not built; unreachable until a source tracking upstream for PHP
  8.1 and older is read, so it is carried with the Homebrew and source reads.
- A `php.ini` check for `session.upload_progress`: not built, by decision
  (`security-consultant`, re-decided 2026-10-31); CVE-2026-115560 (no fix; needs
  application code that sets `session.serialize_handler`) appears in the remediation text
  only, as the `php.fix_missing` caveat. The setting defaults to On, so a rule would fire
  on nearly every PHP host; a disproof from one `php.ini` is unsound across SAPIs,
  `conf.d`, pool settings and `.user.ini`; paths vary by version and the catalog takes
  literal argv; and exploitability depends on application code scheck cannot see.
- R6 table additions: the PHP-FPM FastCGI port beyond loopback as unauthenticated, and the
  Node inspector on 9229/tcp. Outside the version rules.
- Installs under home directories (nvm, volta, asdf, fnm).
- Restart detection: process start against package install time.
- Tables for Alpine, SUSE, Arch, cPanel and Plesk (the rules abstain `unavailable:distribution` on the first three).
- Containers and their images.
- Lockfile dependencies (see "Later").
- The E7 `X-Powered-By` header must never become a vulnerability finding.
- Whether an rpm `php-cli` should be judged as CGI instead of abstaining `unavailable:php_cli`
  (open decision for the security-consultant).
- Whether the `pkg.*` checks are write-free with a stale apt cache: a later integration
  test (decided).

**Done when:** each of the three rules has fired, disproved and abstained fixtures, and
the table-trap host does not fire; scheck runs no `php`, `node` or `brew` (the golden
trace shows package reads only); the integration diff is still the exact allowlist; the
report says the table's date and what it did not read.

### G6 — comparing two engagements

**Delivers:** comparison of two runs of the same engagement file, for remediation
follow-up: fixed, still open, new, and assets that changed. Deterministic, on the JSON
report, keyed by canonical asset ids and finding instance keys
(`spec/engagement.md`, "Identity, references and validation").

**Built:** `scheck diff EARLIER LATER`, `internal/engagement/compare`, `ReadReport` and
the strict `report.ReadJSON`, `docs/engagement-comparison-schema.json`. The rules (what
*fixed* needs, identity, severity, exit) are in `spec/runs.md`, "Comparing two runs".

**Done when:** a golden comparison of two lab runs is committed and a finding that moved
between assets is reported as such, not as fixed plus new. The committed pair
(`internal/engagement/compare/testdata/lab`) is synthetic, built in `golden_test.go`; a
pair of real lab runs replaces it when the lab runs. The 0.0.3 release gate "comparison
correct against a seeded change list" is deferred with the lab to v1.0.0 ("Release gates
and the lab").

**Decided by the implementing session with the security-consultant, to confirm:**
refusing swapped arguments rather than sorting them; matching a release build positively
(only `v?MAJOR.MINOR.PATCH` is "the same rules"; `dev`, a describe string, `-dirty`, empty and
`unknown` never are); exit 2 for a later run that did not read everything outweighing
exit 1.

**Carried from G6:** bound free-form values in `walkAny` (`internal/engagement/report/strict.go`), or lower the report size cap: memory for free-form values is about 30 times the text; make an excluded DNS target an abstention (incomplete) instead of
silence, and record a `declared:` read when a root other than the asset's own decides
`FinalInRoot`, so the `dns.*` ids no longer need the id list in `declarations.go`; bound ids for GitHub organizations and repositories (a report
schema MINOR); a structured principal id (today the identity label, elevation and
scopes); a `superseded_by` category; per-assessment declared-input digests (precise
declaration drift); re-judging the earlier run's persisted evidence with the newer build,
so a version change does not block every confirmation; per-subject completeness;
separating an asset no longer listed under a root read whole from one out of scope; the
"this rule depends on the date" note on new instances of time-dependent rules; the
earlier report's "Fix these first" with each item's later state; a `rekeyed` identity;
`-v` extras (the engagement file's key diff, notes changes, reads and collection time per
fixed instance); choosing the previous run inside `scheck run`; withholding by pattern
rather than by count when `redact_extra` differs, which also omits a fixed instance's
earlier `not_checked` lines; reading a run directory takes the run's flock on `.lock`
(`O_CREATE|O_RDWR`), so a read-only archived run directory cannot be compared and its
`report.json` file is used instead (fix: a read-only lock open); the `O_NONBLOCK` hardening of `ReadReport`'s open (a pipe
swapped in between the `Lstat` and the open can block it; it needs a local race inside an
owned directory, and adding the flag changes `scripts/depcheck.sh`'s `syscall` pin); a fact-level host drift view
(`host-collector.md §6.4`).

### G7 — coverage and the lab

**Delivers:** the cloud configuration, data stores and backups, logging and web
application areas of the coverage table move from *not assessed* to *assessed* or
*partial* with reasons. The lab gains a GCP test project with seeded issues, under the
same sealed-label rule ([spec/lab.md](spec/lab.md): the GCP piece, its faults and
decoys, and the cross-asset cases with GitHub, the domains and the cloud host). Decided
2026-10-25: the GCP part is sealed before G1's first commit, as a development
measurement; the project has no organization, so the lab exercises no organization root
and no organization policy. The host-depth slices G5 and G8 landed with no seal, so
host-depth faults sealed now are late for them. **Known gap:** there is no Workspace lab,
so the 0.0.3 gates' "0.0.2 gates, re-run on the larger lab" hold no Workspace measurement;
Workspace is recorded as "exercised read-only on a real tenant, not measured". The GCP
test project is a lab piece and is deferred with the lab to v1.0.0 as a release gate; its
development seal before G1's first commit is a development measurement
([spec/lab.md](spec/lab.md), "`make live` and release gates").

### Release gates

The 0.0.2 gates, re-run on the larger lab, plus: every GCP call on the declared list
and nothing else (audit log); no write call possible from the code (a test over the
declared list); credentials never in any output; probes run only after confirmation
and only on assets with named first-party evidence; the coverage table correct for every
area; the comparison of two runs correct against a seeded change list.

Since 2026-10-25 the lab-measured gates above are deferred to v1.0.0, and the others still
apply to 0.0.3: the table in "Release gates and the lab" says which is which. A deferred
gate is recorded as *not run*.

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
