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
| The host side? | The host collector's catalog, runner, policy and guarantees are unchanged in 0.0.2. It becomes the collector for `host:` assets in E1b and gains no check there; the deeper checks a small company needs from it are 0.0.3 G5. |
| One command? | Yes. From E2, `scheck run` is the only assessment command. `scheck local` and `scheck ssh` are aliases of `scheck run --host` in 0.0.2, with a deprecation line on stderr, and are removed in 0.0.3. Two pipelines would mean two reports, two run histories and two places to declare a host, and only one of them would say what it did not assess. |
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
only the host collector's rules (one check, or two joined per account, E5a) until E9; Plan and Check pass through empty until then. A root
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
| postgres bound to all interfaces with no host firewall rule in front | multi-fact rule (E9) |
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

- G3: before anything raises the gate's `ceiling` above observe, the per-asset mode
  check of `spec/scope.md`, "Admission", step 6 ("allowed by the asset's mode") exists.
  Today only `ceiling` is checked, and the window tests admit a test-only probe op that
  has no mode at all.
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
the operator's mirror checkout (`checkout`, decided in E4), redacted in every output. A token with more than read access
is itself reported. People are matched by login only, over every login a handle lists
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

**Build steps** (planned, security-consultant DEFINE, 2026-10-09; rules and
permissions in `spec/github-collector.md` are proposals until reviewed and frozen):

0. **Contract preparation.** Split the engagement spec and audit citations; draft the
   operation/permission and rule-outcome tables. Resolve the assessment-token
   reporting choice and review proposed bases before their definitions are fixed.
   Confirm E3's rest-lab seal before the first E5 commit; never open its
   labels in the implementation session. This step is documentation only.
1. **Gate foundation.** Move provider display, pagination and rate-limit metadata
   into the provider table and list-item subject templates into operations, as E4's
   review requires. Preserve every existing admission and response guarantee.
2. **Principal and organization inventory.** GET-only PAT/App-user principal,
   verified own membership, organization metadata, members/owners, outside
   collaborators, invitations and repository inventory; projected evidence,
   permission/population gaps, changed-principal resume and header tests. Unsupported
   installation principals stay unknown and authenticated successes are not reused.
   No later rule id or optional check is introduced in this step.
3. **Identity and repository access.** Existing E5a people/admin/MFA rules; repository
   public intent, default member permission, production outside-admin and write
   deploy-key rules. Freeze privilege maps, bases and subject keys before building.
4. **CI controls.** Organization/repository workflow defaults, default-branch
   protection and active rules, supported workflow parsing, immutable action
   references and dangerous PR-target combinations. Freeze supported syntax and
   runner evidence; carried App/runner breadth remains an explicit decision.
5. **Secret metadata and provider alerts.** Secret names/visibility and projected
   Dependabot/secret-scanning alerts, with per-location findings and honest gaps.
6. **Confined history reader.** In-process mirror remote/head checks, bounded object
   and history reads, detector markers and redaction assertions; freeze supported
   formats and caps before implementation.
7. **Closing review.** Consultant REVIEW, client REPORT, spec sync/audit,
   `make check` and a fresh whole-slice adversarial code review. Every built rule has
   firing, disproved and abstained fixtures. Missing live lab measurements remain
   *not run*, never passed.

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
- scheck's own token with more than read access, which a classic token always has
  for repositories, is a run note with the fix, never ranked and never counted in the
  exit code (owner's decision pending; this is the consultant's recommendation, and
  `spec/scope.md` calls it a finding today).
- Under *not assessed*: GitHub shows no sign-in dates, so a former member nobody
  listed cannot be told apart from a current one; and SAML single sign-on, if enforced,
  does not cover git over SSH or tokens, which the 2FA rules list under what they did
  not check.
- SAML or SCIM linked identities may *suggest* `people` entries, never attribute one.
- Each risk area E5 marks lists its sub-items from the practitioner's list, not from
  the rules built, so an unbuilt one is `no_rule` and the row *partial* (owned by E9,
  below).

### E6 — Google Workspace collector

**Delivers:** read-only Admin SDK calls with scopes from the environment or the
provider's login. Rules for: 2-step verification enforcement and enrolment, kept
apart, since enforcement is per organizational unit with grace periods, and compared
with `access.mfa` as `spec/engagement.md` "2-step verification" says; super admins
against `access.admins`, too many super admins, one nobody can name, and a contractor
or shared account that is one ("Admins"), delegated roles listed for the readout; stale and never-logged-in accounts, not counting new hires
(read the creation date) or `service` and `break_glass` accounts; suspended accounts
only when they keep an admin role or group-granted access, since suspension is correct
offboarding; third-party OAuth apps with broad scopes; external mail forwarding, which
needs per-user Gmail settings through domain-wide delegation and is *not assessed*
without it. The tenant is identified by its customer id; secondary domains and domain
aliases belong to it; people match by `primaryEmail`, a current person's declared alias
by the alias rule and a leaver's never as disproved (`spec/engagement.md`, "People");
each matched account's provider id is recorded in `recon.json`; the recon stanza.
Subject kinds: `org_unit` for 2-step verification not enforced, `account` for the
per-account findings, `oauth_app` keyed by client id, `principal` for scheck's
credential; none for too many super admins. The exact list is frozen at the start of the
slice against what the read scopes return.

**Done when:** as E5, against a fake Admin SDK server; an opt-in live test (`make live`)
reads the lab tenant; broader-than-read scopes are reported as a finding.

**Carried from E4's reviews:** before E6's first op, unless E5 did it first, the provider
table and a list's item subject as a template, as under E5; and org-unit matching moves
behind `Scope`, beside every other exclude match. Coverage is marked by
`spec/scope.md`'s "Outcomes" table, a request that got no answer exiting 2.

**Carried from the engagement-spec review** (security-consultant, 2026-10-09):
domain-wide delegation has no Directory API to read it and is the tenant-takeover path,
so it is *not assessed* with the console path printed; a break-glass super admin is
expected but needs 2-step verification and rare sign-ins; OAuth apps are never matched
to `tools` by display name; and, as under E5, each area's sub-items come from the
practitioner's list.

**Never declared:** `verificationCodes.list`, which answers with users' backup sign-in
codes: no finding needs them and no redaction rule could recognize them. The gate's
registry refuses any op whose path, decoded, reads `verificationCodes`, an API op takes
no path parameter, and a bound path is checked again before it is sent (a test pins
it, from E4).

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
declares its consumers in code by id and owning slice. A file written by
`scheck run --host … --write-engagement` is a valid starting point: `scheck init FILE`
asks only what it does not answer. The `client` agent's interview mode is run on the
wording before it is fixed, and its fixture mode writes the engagement files the
interview tests use.

**Done when:** every question declares its consumers, and a test checks that each
declaration is well formed and that the consumers owned by merged slices exist; the
file `init` writes for each company profile in `.agents/clients/` validates; an answer
that would put a credential in the file is refused by the same detector as validation;
no code path in `init` contacts a target.

**Carried from the engagement-spec review** (security-consultant, 2026-10-09). Each
changes what the interview asks or what the file accepts, so E8 decides it before the
wording is fixed:

- *Questions with no 0.0.2 consumer*, by the spec's own rule that "printed" counts
  only for the trigger, authorization, scope and accepted risks: the backups question
  only unfolds a row that stays *not assessed* (the consultant recommends deferring it
  to G1, where inventory reads it); `secrets.production[].store` is free text, so
  whether scheck read the store cannot be computed (make it a closed list mapped to
  collectors); and a host's `role` is prose for a model that does not run. Each is cut
  from the interview or given a real consumer.
- *`data.matters_most` moves almost nothing*: every finding definition today is in the
  hosts or external area, so the example `{asset: deploy}` raises no finding and the
  answer only breaks ranking ties. With E9, it raises along declared links: remote
  access and account findings on the asset that holds the data, findings on
  repositories that deploy to it, secrets whose declared store is on it. That needs
  `deploys_to: {environment: production, targets: [deploy]}`, a schema change made
  while the file may still change.
- *`not_used` accepts every area*: `identity`, `secrets` and `logging` are refused,
  and so is any area a declared root covers (`email` beside a domain root, `cicd`
  beside a GitHub root).
- `scheck init` writes a header comment: the file names people, departures and
  accepted weaknesses, and is kept out of public repositories.
- `intent.accepted_risks[].expires` becomes required, capped at one year after the
  date it is written: a risk register without review dates is not one.

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

**Carried from the engagement-spec review** (security-consultant, 2026-10-09):

- *Plan has no job with rules only, and the stage table is wrong about where rules
  run.* Recon runs every declared read, Plan is "the same checklist whatever its
  order", and the web collector judges in Recon while the stage table puts rules in
  Analyze. VISION principle 1 ("decides what it examines and in what order") is then
  false for 0.0.2, and gate 1's "all seven stages" is theatre for Plan. E9 gives Plan
  the one decision context makes with rules only, selection under a budget: with
  many repositories or users under a cap or a rate limit, it reads first the
  `deploys_to: production` repositories and those holding a declared secret store,
  and, for per-user reads, people who left, admins and declared contractors. A cap's
  `selection` then names the context that chose it. Every rule verdict moves to
  Analyze, or the stage table says collectors judge in Recon.
- *Recon "fills gaps in the context and flags where it is wrong"* (the stage table):
  nothing does this in 0.0.2. Reword the stage table or build it, beside the item
  above.
- *Termination by construction.* Follow-ups are a static table of depth at most 2,
  checked by an invariants test, rather than proven by one loop fixture; a follow-up
  that ended without success is not reopened in the same session.
- *"Checked" cannot be told from "checked thinly".* Each risk area's sub-items are
  fixed from the practitioner's list, independent of the rules built, so an unbuilt
  one is `no_rule` and the row is *partial*; every row prints "not judged in this
  version: …" even when it is marked *assessed*, as the hosts and external rows already
  do.
- *`data.matters_most` raises along declared links* (see E8).
- *A declared `not_used` area the evidence contradicts* gets a note ("you said no
  cloud; `api.example.com` is a CNAME to `*.run.app`").
- *Already built, carried here:* a resume keeps Scope and host envelopes of any age,
  so a run resumed weeks later reports old discovery as current. Keep nothing older
  than a fixed maximum, compiled in with no setting to widen it (the consultant
  recommends 7 days; owner's decision pending). The date on `Observed`
  whenever a run's collection crosses a day is implemented in E7 step 5; the maximum
  age decision and enforcement remain E9's.
- *Owner's decision pending:* may a context raise reach critical? Today "a person who
  left still active" with `attribute:admin` and "2-step verification not enforced" with
  `contradiction` both reach critical, while critical is defined as usable by anyone on
  the internet with no further step. The consultant recommends yes, with critical's
  definition widened to "or a high that someone with no right to it can use now, or
  that the company believes is handled".

### Release gates

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
   high, not critical; the accounts summary counts login shells by the rule's lists).
9. **Consumers:** every consumer declared by an interview question exists, and the
   test that checks it no longer skips anything.
10. **One command:** `scheck run --host` on the lab host and the `scheck ssh` alias
    give the same report and command trace, and the host's facts match the host asset's
    in the full engagement run, and its findings do for the same context; no run reads a
    config file.

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

**Delivers:** the reviewed probe list (`/.git/HEAD`, `/.env`, framework debug routes,
common admin panels), each a single `GET`; the `off`, `confirm` and `all` modes; the
preview of every planned request; the authorization block and a window required for
any probe; the interview's framework question returns, since it now
selects which probes apply; the lab's web tier gains a served `.git` directory and an exposed admin panel,
seeded under the same rule as 0.0.2.

**Before the gate's `ceiling` rises above observe** (carried from E4's slice-closing
review): the per-asset mode check of `spec/scope.md`, "Admission", step 6, which 0.0.2
does not build; until it exists the window tests admit a test-only probe op with no
mode at all.

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
