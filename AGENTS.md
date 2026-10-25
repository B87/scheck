# Working on scheck as an agent

scheck is becoming a **security consultant in a CLI**: an engagement (intake → scope →
recon → plan → check → analyze → report) across cloud accounts, SaaS tenants,
repositories, hosts and websites, driven by context only the operator knows. Read
`docs/VISION.md` first, then `docs/ROADMAP.md` for what is being built in which release.

What exists today, released as v0.0.1, is the **host collector**: a read-only posture
checker for one macOS or Linux host, local or over SSH. It becomes the collector for
host assets in the engagement and its guarantees do not change. In 0.0.2 `scheck run`
is the one command, with an engagement file or `--host`; `scheck local` and `scheck ssh`
are deprecated aliases of `scheck run --host`, removed in 0.0.3, and no configuration
file is read (`docs/spec/engagement.md`, "One command, one file"). This file is the
operating manual for a coding agent in this repository.

## Documents

| Document | Role |
|---|---|
| `docs/VISION.md` | What scheck is for and its principles. Wins on direction. |
| `docs/ROADMAP.md` | 0.0.2 (first engagement: Workspace, GitHub, domain, host; reading only), 0.0.3 (GCP, probes, host depth, comparing runs), 0.0.4 (model, scans, `auto`): slices and release gates |
| `docs/spec/host-collector.md` | Contract of the built host collector. Wins on any conflict about host collection. |
| `docs/spec/engagement.md`, `docs/spec/scope.md` | Designs for the engagement and its scope rules; each section becomes contract when its release lands |
| `docs/spec/report.md`, `docs/spec/runs.md` | The engagement report contract, run directories, state and resume, and the comparison of two runs (`scheck diff`) |
| `docs/spec/github-collector.md` | E5 gate, inventory, identity/repository-access, CI, secret metadata, provider alerts and confined mirror history |
| `docs/spec/workspace-collector.md` | E6 credential, tenant binding, tenant inventory, identity/admin and observed 2-step verification rules; optional OAuth grant and Gmail forwarding metadata, mailbox tokens and coverage limits |
| `docs/spec/web-collector.md` | Design of the domain, email and web collector (E7): its reads, rules, takeover table and what the report never claims; contract when E7 lands |
| `docs/spec/model.md` | The model path (provider contract, agent loop, tools); kept offline |
| `docs/spec/bounded.md` | The bounded yes/no decision arm (Jev), offline; the pattern behind the `auto` gate |
| `docs/examples/` | Engagement files an operator copies. The spec-steward keeps them true to the specs. |
| `docs/eval/` | Recorded evidence: frozen criteria, evaluation results, acceptance passes. Appended, never rewritten. |
| `docs/RELEASING.md` | Release runbook |

Code comments cite specs as `docs/spec/<file>.md §N` for anything that exists because
of a security decision. When implementation has to deviate from a spec, update that
spec in the same commit; history is git history. Silent drift is a bug.

**No model assesses a host in this build.** The live evaluation failed its frozen
criteria (`docs/spec/host-collector.md §2.1`, `docs/eval/phase2-results.md`), so a
host asset's facts are assessed with posture rules. The
model path — `internal/agent`, its three tools, the `llm` adapters — is kept, tested
offline and reachable only from the hidden `scheck eval`. Do not wire it into a run and
do not delete it: 0.0.4 plans to reuse it for Plan and Analyze, and only a passing record
against frozen criteria puts a model on a default path.

## Non-negotiables

These are the host collector's security boundary, and the model for every new
collector: one enforcement point, a declared surface, redaction before output, nothing
outside scope (`docs/spec/scope.md`). A change that weakens one is wrong even if every
test passes.

1. **The tool never modifies the target.** No check may write, and no code path may
   run anything that is not a catalog entry. Integration tests diff the container before
   and after a full run and fail on any change outside sshd's own login noise and an
   exact list of documented artefacts, both of which they log; keep that assertion true
   and never widen its tolerances. Three writes are known, documented in
   `docs/spec/host-collector.md §1` and enforced as an exact allowlist in
   `test/integ/facts_test.go`: dnf's package-manager cache (`pkg.dnf_check_update`),
   sudo's timestamp directory (`sudo -n --`) and ufw's lock file (`fw.ufw`). Adding a
   fourth needs a decision recorded in the spec, not a wider pattern.
2. **The catalog is the whole command surface.** Every executable command is a
   `check.Check` with literal argv tokens and typed `{name}` placeholders. Never build
   argv by concatenation, never accept a command string from a model or a user, never
   call `target.Exec` from anywhere but `internal/runner`.
3. **`runner.Runner.Run` is the single enforcement point.** Bind → realpath → path
   policy → elevation → budgeted exec → redact → truncate → extract → parse → audit.
   The model path's `run_check` and `read_file` tools go through it. Do not add a second
   path "for a special case". New collectors (GitHub, Workspace, web, GCP) get one
   scope gate of their own with the same duties (`docs/ROADMAP.md`, "Rules for every
   release"); no collector calls the network any other way.
4. **Policy owns sensitivity, redaction and budgets** (`internal/policy`). Config knobs
   only narrow (disable checks, deny paths, add redactions). Never add a knob that
   widens what may run or what may be revealed. The engagement's opt-in levels (probe,
   scan, full scope) are scope decisions recorded in the engagement file and audit log,
   never config knobs that loosen policy.
5. **Redact before truncate; mark everything.** Output is redacted as
   `[REDACTED:<rule>:<n bytes>]` and cut as `[TRUNCATED:<n bytes>]`. Nothing downstream
   (report, audit log, persisted run, verbose output, fixtures) may see pre-redaction
   bytes.
6. **SSH: canary first.** The first command on a session is `sys.canary`; a mismatch
   exits 3 before any other command. Do not weaken the canary string or make the quoter
   "smarter"; both are tested over the whole catalog.
7. **Elevation is `sudo -n --` as a prefix, nothing else.** Never prompt for, read, or
   transmit a password. Never read credentials from a config file or the engagement
   file; API credentials come from the environment or the provider's own login.
8. **Exactly one catalog entry has `Canary: true`.** It is the only literal allowed to
   contain shell metacharacters. The invariants test enforces this; do not add
   exemptions.

## Layout

| Path | Owns |
|---|---|
| `cmd/scheck` | cobra commands: `run` (an engagement file or `--host`, through the report, or a run directory, which it resumes; `legacy.go` refuses a 0.0.1 config file), `init` (the interview, `init.go`, E8), `local` and `ssh` as deprecated aliases of `run --host` (`alias.go`), `diff` (two runs compared, `diff.go`, G6), `catalog`, `explain`, `sudoers`, `providers` and the hidden `eval` (model flags only, `model.go`); flag parsing; exit codes; the tty/`NO_COLOR`/width decision (`terminal.go`) |
| `internal/target` | `Target` interface; `local`, `ssh`, `fixture` implementations |
| `internal/check` | `Check`/`Param` types, registry, `Bind`, invariants `Validate`, parsers and the typed shapes (`listeners`, `accounts`, `file_mode`, `find_ls`, …); the argv builders of the credential finds and the `creds.app_env_N` slot ids (`credfind.go`, G5); `CloudVendor` and its versioned DMI table (`cloud.go`, G5 step 2), which names a cloud VM on the fact sheet from `sys.dmi` and judges nothing; the argv builders of the runtime package reads and the `packages` shape (`runtimes.go`, G8 step 1) |
| `internal/advisory` | the dated table of named runtime disclosures (PHP, Node.js; `TableVersion`), the dpkg version ordering and `Assess` and `Covers`, the distributions whose package names the reads cover (G8 step 1, `docs/spec/host-collector.md §1`, §11). A leaf: standard library and `internal/check` only; the rules R7 to R9 in `internal/engagement/rules` call it (G8 step 2) |
| `internal/check/{common,linux,macos}` | the catalog itself; `internal/check/all` imports them and runs the invariants test |
| `internal/policy` | path policy (metadata-only trees and names, including the application trees and `AppPathPrefixes` an `app_paths` entry falls under), redactor, budgets, JSONL audit log |
| `internal/runner` | the one exec path (rule 3) |
| `internal/baseline` | the host plan, run and fact sheet; the golden command traces in `testdata/golden` |
| `internal/report` | the host report envelope and JSON renderer (`Build`, or `Evidence` then `Assess`; `SheetFrom` rebuilds the fact sheet from a persisted envelope), embedded whole in the engagement report; the fact sheet the engagement report prints per host at `-v` (`text.go`, `text_layout.go`, `domains.go`); golden fact sheets and JSON reports in `testdata/golden`; `docs/report-schema.json` |
| `internal/finding` | finding id catalog with base severities, posture rules and their evaluator; reads the fact sheet, never executes. `ValidateRules` is its invariants test. Network collector definitions are here (`web.go`, `github.go`, `github_ci.go`, `github_alerts.go`, `github_history.go`), their rules in each collector; shared collector `Judgment` and `Subject` types in `judgment.go`, the `Selection` and `KindSelection` types a coverage population carries (`selection.go`, E9 step 6a), the shared observation-time clock (`LeftAt`, collection-time reasons) in `clock.go` (E9 step 1d), and the `CoveragePlan` a network collector words its coverage in (`coverage_plan.go`), `Def.ReadsDeclarations` (a rule that reads the engagement file without a `declared:` read, which `scheck diff` reads like one) and `ReadsDeclarations(id)` (`declarations.go`: the one answer `scheck diff` uses, adding the identity area, nine named ids and an unknown id), `Def.CeilingWhy` (the sentence of a stop at the ceiling, when the generic one is wrong), `Def.MattersMostRaises` and `Def.HostAccess` (which findings a `data.matters_most` entry moves, E9 step 9; on a host, `HostAccess` or the secrets area, G5), a host's facts as the posture rules and the multi-fact rules read them (`facts.go`, `Facts`/`FactsOf`, from what a persisted envelope keeps) and the multi-fact definitions (`multifact.go`, `Def.MultiFact`, including `php.fix_missing`, `node.fix_missing` and `node.line_unsupported`, subject kind `package`, G8), and the credential-on-disk rules' `CredFiles` predicate and versioned name tables (`credfiles.go`, G5) |
| `internal/state` | the state directory, under which run directories live |
| `internal/engagement` | the engagement file: schema, locators and canonical ids, validation before any target contact, a host's `app_paths` (`appPathProblems`, G5), the resolved view (E1a); `--host` engagements built in memory, the stages and the locked run directory (E1b); the report input and the Report stage (E2); the engagement's scope as the gate checks it, passive discovery in Scope, and resume: `run.json`, what a session keeps and the 7-day age it keeps it to (`resume.go`, E4, E9 step 8); `ReadReport`, which opens a run directory or a `report.json` for `scheck diff` (`readreport.go`, G6: locked for the instant of the read, hash checked against `run.json`, links refused); Recon of domain roots through the web collector (`collect_web.go`, E7), GitHub inventory, identity attribution and per-account candidates (E5); the interview's questions and their consumers (`interview.go`, E8; the `app_paths` question, G5; the `data.matters_most` question and the `context` service line's audience, `interview_matters.go`, E9 step 9); stage document types in `stage_docs.go`, sequencing in `stages.go`; the network collectors' `Judge` calls and each host's grading in Analyze (`judge.go`, E9 steps 1b and 1c), so `recon.json`, `check.json` and `evidence/` hold no verdict; Plan and Check for GitHub and Workspace (E9 steps 6a and 6b: `plan.go`, the closed not-judged list; `github.go`, `planGitHub` and `checkGitHub`; `collect_workspace.go`, `planWorkspace` and `checkWorkspace`; writing `plan.json` and `check.json`); the follow-up table, F1's loop and the `gateOps` a row names (`followup.go`, E9 step 7); the context notes C1 to C3 (`notes.go`, E9 step 5b) and the versioned C3 table `ContextTableVersion` |
| `internal/engagement/gate` | the scope gate (E4): the one place an HTTP request, API call or DNS query is sent; the op registry and its invariants, admission, its own DNS client with records reads and the follow-ups of the names their answers point at (E7), the response pipeline, throttle and retries, authorization windows, the audit lines and the resume ledger; the single local read-only mirror boundary (`mirror.go`); private E6 token exchange and tenant bootstrap (`google_credential.go`, `workspace.go`), and each optional Workspace surface's own one-scope token, profile gate and remembered failure from one surface table, with the Gmail forwarding surface's per-mailbox tokens, admission from current inventory and from a current `authorization.mailboxes` entry loaded for the gate session (`mailbox_auth.go`), breaker and exchange cap, and projection before redaction (`workspace.go`); the `CollaboratorLogin` parameter type, only the `{username}` of the repository permission read (`op.go`, `github_ci.go`, E9 step 7) |
| `internal/collector/github` | E5 GET-only principal, organization, repository-access, SHA-pinned CI and projected secret/alert reads through the gate; typed evidence, identity/MFA/access (`EffectiveAdmin`, `EffectiveWrite`; on a fired leaver judgment the R4 facts `repository_admin`, `write`, and `write_held`/`write_unsettled` on the carrier, never reading `deploys_to`), CI, secret-sharing and provider-alert rules, supported syntax, in-process mirror object/ref parsing, credential-location rules and explicit permission/runtime/scan/history gaps; the facts the context notes read (`facts.go`: `ActionUses`, `SecretNames`, `RepositoryState`); the repository tiers, the 4,000-request budget and the breadth-first reads by kind (`selection.go`, E9 step 6a: `TiersVersion`, `Select` in Plan, `CollectRepositories` in Check, `CollectInventory` in Recon), a kind the budget did not reach marked `Sampled` so the CI and alert rules judge nothing from it; the permission follow-up's read and interpretation (`permission.go`, E9 step 7: `CollectPermission`, `PermissionOpen`, the answer's reading into write, not write, admin or unknown) |
| `internal/collector/workspace` | E6 private `Bind`, tenant inventory and admitted per-user administrative reads through the gate, people attribution, identity/admin rules (`rules.go`) and observed 2-step verification rules (`twostep.go`), optional per-account OAuth grant reads (read in Check), the versioned scope table and the broad-scope rule (`oauth.go`), its coverage plan and collection outcome (`coverage_plan.go`), optional per-mailbox Gmail forwarding reads and the forwarding rule, with its read set, destination classes and notes (`mail.go`), the per-user tiers and read order (`selection.go`, E9 step 6b: `UserTiersVersion`, `Select` in Plan, `CollectUsers` in Check, `readAccounts` the shared optional-surface read loop), and collector-owned definitions/notes; `TenantDomains` and `Mailboxes`, exported for the context notes |
| `internal/collector/web` | the domain, email and web collector (E7, `docs/spec/web-collector.md`): its declared ops (`web.front`, `web.entry`) and `Collect`, which reads a domain root's mail records, NS, the names they point at and each read name's front page over https and http, the https read giving its certificate, through the gate; `Judge`, called in Analyze, its DNS rules over Scope's lookups and what `Collect` read, each verdict `fired`, `disproved` or `abstained` on one subject; the versioned takeover table (`takeover.go`), provider fingerprints and wildcard judgments (E7 step 2b); the email rules over collected DNS (`email.go`, `dmarc.go`, `spf.go`, `dkim.go`), an embedded public-suffix snapshot and exact sender-include table (E7 step 3); entry-point enrichment after takeover suspensions and TLS, HTTP, header, cookie, secret and security-contact rules with pinned browser data (E7 step 4); restricted URL reachability from a declared vantage (E7 step 5); `MailUse`, the mail use Judge reads, exported so Plan names the email rules that will not decide (E9 step 6a) |
| `internal/engagement/severity` | the engagement's closed severity table (E9 step 1a, `docs/spec/engagement.md`, "Severity in context"): `Declarations` (`Exposed`, `MattersMost`, `Production`, built from the resolved engagement in `internal/engagement/adjust.go`), `Grade` and `GradeAll` (with R4's `attribute:production_write` row and its not-applied move, E9 step 4), which give every fired network-collector judgment its chain in Analyze, after `partitionGitHubJudgments`, and `GradeHost` (E9 step 9: a host posture finding whose `finding.Def.HostAccess` is set moves on a `data.matters_most` host, after the host collector's table, and the `exposure:internet` row now moves `php.fix_missing` too; the chain is kept as `host_chains` in `findings.json`, the host envelope keeping the collector's severity); the report renders the chain and decides none |
| `internal/engagement/rules` | the multi-fact rules over a host's facts (E9 step 3a, `docs/spec/engagement.md`, "The multi-fact rules of 0.0.2"): `Rule` with declared `Reads`, the `View` that hands a rule only those and records the rest, `Judge(hosts)` giving each host its judgments and coverage plan, the withdrawal of a disproval resting on a partial fact, `Validate`; R1 `db.listens_unfiltered` (`db.go`, `listeners.go`, the versioned database table) and the firewall reading (`firewall.go`: ufw, firewalld, nft and the iptables backend, the versioned ufw profile table), which R3 reuses; R2 `accounts.empty_password_remote` (E9 step 3b, `ssh.go`: the sshd settings, the password methods and where sshd listens). R3 `svc.listens_beyond_declared` (E9 step 5a, `svc.go`: the declared services against their audience); R6 `svc.sensitive_listens_unfiltered` (G5 step 3, `svc_sensitive.go`: remote-administration services against the versioned `SensitiveServicesVersion` table, R1's mechanics); R7 `php.fix_missing`, R8 `node.fix_missing` and R9 `node.line_unsupported` (G8 step 2, `runtime.go`: the PHP and Node.js packages against `internal/advisory`, the versioned `WebServersVersion` list behind `attribute:serves_web`, `Rule.Gap`, the standing coverage gap `unavailable:runtime_installs` that makes their groups at most partial, `Rule.OwnPartial`, by which they settle a partial read themselves as `unavailable:packages_partial`, and `Host.Collected`/`View.Collected()`, the collection time R9 judges a line's end of support at); R1, R3, R6 and R7 share the listener grouping (`listeners.go`) and one lazily read firewall (`firewall.go`). `Databases`, exported for the C3 `data` note. Reads facts already collected; runs nothing |
| `internal/engagement/report` | the engagement report (E2): built from what a run collected, never contacting a target; coverage marked from the rules that decided, the Hosts row's sub-rows, where a group with a standing `Gap` (`host.go`, G8) counts as decided but leaves its sub-row partial and prints the gap's reason, findings keyed `{id, asset, subject}`, a network collector's verdicts as findings, assessments and coverage (`judged.go`, E7), a collector's coverage plan marked (`coverage_plan.go`), each risk area's fixed not-judged list (`fixed.go`, E9 step 2), ranking, the "People who left" lines and `person` items (`people.go`, E9 step 4), the selection wording and the `sampled` reason of a budget cut (`selection.go`, E9 step 6a), the `summary.matters_most[]` readout of each `data.matters_most` entry (`matters.go`, E9 step 9: outcomes `raised`, `read`, `partial`, `not_judged`, `not_read`, said `read` only over checks that decided) and the named-asset items first in "Not checked", the departed-people `detail` line on how far the permission follow-up got (`github.go`, E9 step 7), acceptances' outcomes, the exit code; `ReadJSON`, the strict reader of a `report.json` (`read.go`, G6: another schema MAJOR, a newer MINOR or an unknown field refused, each host's embedded envelope dropped) and the report's fixed phrases the comparison shares (`phrases.go`); `docs/engagement-report-schema.json` |
| `internal/engagement/compare` | the comparison of two runs of one engagement (G6, `docs/spec/runs.md`, "Comparing two runs"): `Compare` over two `report.Report`s, matching instances and assets (`match.go`), the conditions for *fixed* and *new* (`recheck.go`), instances and their categories (`instances.go`), text (`text.go`) and JSON (`json.go`, `docs/engagement-comparison-schema.json`); goldens over the synthetic pair in `testdata/lab`. Reads no file, contacts nothing; `scripts/depcheck.sh` limits its imports to `internal/engagement/report`, `internal/finding` and `internal/report` |
| `internal/engagement/hostasset` | the host collector as an asset: reach (local, SSH dial, canary, platform), the baseline through the runner, the evidence envelope Recon writes (`Evidence`), the posture rules graded in Analyze through the asset's context (`Grade`), `Restore` of a kept host; the `creds.app_env_N` slots, one per declared `app_paths` folder, run through the runner after the baseline (G5); fixture recording (`--record-fixtures`) |
| `internal/sudoers` | NOPASSWD fragment generator from elevated checks |
| `internal/operator` | operator context for the host collector: sources, schema, per-kind merge, budget, the `<operator_context>` block |
| `internal/llm` | the provider contract, token accounting (`CheckFit`), the registry; `mock`, `openai` (the default adapter), `conformance`, `all` |
| `internal/agent` | the model path's system prompt, three tools and loop; every execution through `runner.RunAs`, every finding through `finding.Store`; `internal/eval` is its only caller |
| `internal/eval` | the evaluation harness: arms, metrics, adversarial pairs, the comparison report |
| `internal/bounded` | the bounded arm (R1 of `docs/spec/bounded.md`): code enumerates candidates, runs a fixed follow-up table through `runner.RunAs`, asks a few yes/no questions per item and decides in code. Offline, scripted answers, `internal/eval` its only caller |
| `testdata/context`, `testdata/eval`, `testdata/transcripts` | injection corpus with benign controls; labeled evaluation cases; mock transcripts |
| `testdata/fixtures/<name>` | recorded exec fixtures (`manifest.yaml` + files) |
| `test/live` | opt-in tests that spend real money (`make live`, build tag `live`) |
| `test/containers`, `test/integ` | Docker images and `integration`-tagged tests |

Everything is under `internal/`; nothing is importable from outside the module. New
engagement packages arrive slice by slice with `docs/ROADMAP.md`; do not create them
ahead of their slice. Where each lands, decided before E1 so that slices do not argue
about it:

| Path | Owns | Slice |
|---|---|---|
| `internal/engagement` | the engagement file (schema, validation: E1a; `--host` engagements built in memory: E1b), the stages and the run directory (E1b), resume (E4), the interview's questions and their consumers (E8) (`docs/spec/engagement.md`, "One command, one file"; `docs/spec/runs.md`, "Runs, state and configuration") | E1a, E1b, E4, E8, E9 (step 5b: context notes; step 6a: Plan and Check for GitHub; step 6b: Plan and Check for Workspace; step 7: follow-up table and F1; step 9: the interview's `data.matters_most` question and service audience, `interview_matters.go`) |
| `internal/engagement/gate` | the scope gate: the one place an HTTP request or API call is sent; scope, exclusion, first-party evidence, level and mode, window, throttle, timeout, redaction, audit; on resume, an earlier success answered without sending | E4, E9 (step 7: `CollaboratorLogin`) |
| `internal/engagement/severity` | the closed severity table as data: declarations in, a severity chain out | E9 (step 1a; step 4: `attribute:production_write`; step 9: `GradeHost`) |
| `internal/engagement/report` | the coverage table, the engagement report (text and JSON), `docs/engagement-report-schema.json`, goldens | E2, E9 (step 7: the departed-people `detail`; step 9: `summary.matters_most[]`, `matters.go`) |
| `internal/engagement/rules` | the multi-fact rules over a host's facts, one rule per finding id with its declared reads and fixtures | E9 (step 3a: framework and R1; step 3b: R2; step 5a: R3; G5 step 3: R6; G8 step 2: R7 to R9) |
| `internal/collector/github`, `internal/collector/workspace`, `internal/collector/web` | one package per collector: a declared list of read requests, their parsers and single-fact rules. A collector describes requests; the gate sends them | E5, E6, E7 |
| `internal/engagement/hostasset` | the host collector as an asset: runs `baseline` through the runner and maps its facts and findings into the asset map; the only engagement package that imports `internal/runner` | E1b |
| `cmd/scheck` | `run --stop-after intake` (E1a); `run` and `--host` (E1b); `--jump` (E1c); `local` and `ssh` as aliases of `run --host`, and `config` removed with `internal/config` (E2); `init` (E8) | E1a–E1c, E2, E8 |

`scripts/depcheck.sh` holds the engagement's rules from E1a: `internal/engagement/...` and
`internal/collector/...` have no `internal/llm`, `internal/agent` or `internal/bounded`
in their dependency graph (rules only through 0.0.3), and none but
`internal/engagement/hostasset` imports `internal/runner` or `internal/target` directly
(the catalogs import them, so the rule cannot be on the whole graph). `internal/report`
declares the envelope's model fields itself (`ModelNative`, `ModelLimits`, `ModelUsage`,
which convert from the `llm` types field for field), so the engagement can carry the host
envelope without the model path in its graph (cut in E1b). E4 adds the rest: a collector's
dependency graph, beyond what the gate, `internal/policy` and `internal/finding` bring
in, holds nothing that can reach the network or run a process (`net` and its
subpackages other than `net/url`, `net/netip` and `net/mail`, `crypto/tls`, `os/exec`,
`syscall`, `unsafe`, `plugin`, `golang.org/x/net`, `golang.org/x/sys`,
`golang.org/x/crypto/ssh`) and no package from outside the
module and the standard library, so an SDK that wraps `net/http` is caught too; only
the gate sends requests. `internal/engagement/compare` (G6) may import only
`internal/engagement/report`, `internal/finding` and `internal/report` from the module,
imports no `os`, `io/fs`, `path/filepath`, `net`, `os/exec` or `syscall`, and has no gate,
collector, host asset, rules, state or `internal/engagement` in its dependency graph. No
collector imports another collector, and no non-test file
sets `InsecureSkipVerify`. A collector that needs something from another's
facts gets it through a multi-fact rule in `internal/engagement`, never by import.

For the practitioner's view of what to build, use the `security-consultant` subagent
([.agents/agents/security-consultant.md](.agents/agents/security-consultant.md)): the
consultant whose work scheck automates. Ask it in *define* mode before a slice's checks,
rules, interview questions or report wording are fixed, and in *review* mode on the
result. Its *seed* and *rank* modes are blind and run only in a session that has not
read the collector code; never run them as a subagent of an implementing session.

For the operator's view, use the `client` subagent
([.agents/agents/client.md](.agents/agents/client.md)): the CTO, founder or lone IT
person who answers `scheck init` and acts on the report, played from a fixed company
profile in `.agents/clients/`. Run its *interview* mode whenever interview wording
changes, and its *fixture* mode for the engagement files that interview tests use; its
improvised and wrong answers are the point, so do not tidy them. Run its *report* mode
on report wording (E2 and later). It never reads code, and it does not judge security;
the security-consultant does.

For the code itself, use the `code-reviewer` subagent
([.agents/agents/code-reviewer.md](.agents/agents/code-reviewer.md)): an adversarial
reviewer that tries to make scheck send what it should refuse, reveal what it should
redact, touch what it must not, or report what it did not observe, and confirms each
finding before reporting it. Run it **without being asked**:

- **On any change to the security boundary, whatever its size**, even one line:
  `internal/runner`, `internal/policy`, `internal/target`, the catalog
  (`internal/check/...`), `internal/engagement/gate`, `internal/collector/...`,
  `internal/engagement/hostasset`, the engagement file's validation and locators,
  credential handling, exit codes, the report contract (goldens, schemas, what never
  appears), `scripts/depcheck.sh`, and `test/integ` tolerances.
- **On any large change**: a new package, each build step of a slice, or a few hundred
  changed non-test lines anywhere.
- **Before the commit or pull request that closes a slice**, on the whole slice.

When it runs: after `make check` is green and before committing, on a fresh subagent
each time (never one that wrote the code). Tell it what the change implements, which
spec sections and roadmap entry govern it, and what is deliberately left for a later
step. It never edits; the implementing session fixes. Fix every *must-fix* before
committing and run the reviewer once more on those fixes when they touch the boundary;
bring *should-fix* and *nits* to the user with a recommendation, and record what is
deferred in the slice's roadmap entry. Skip it for documentation-only changes (the
`security-consultant` reviews specs) and for comments, typos and test-only renames.

For module shape, use the `modularity` subagent
([.agents/agents/modularity.md](.agents/agents/modularity.md)). It reads
`.agents/skills/software-design-philosophy/SKILL.md` and judges depth: whether one
decision lives in one place, and whether a caller can use the module without knowing
how it works. Ask it in *design* mode before a new collector's or package's interface
is fixed, and in *assess* mode when a change copies a type, a notes builder, or a
collect sequence into a second package, or when the gate or engagement is about to
absorb another collector's protocol. It does not replace the `code-reviewer`, and it
does not decide what is checked, refused, redacted, or how severe a finding is. It
never edits; the implementing session does.

For the documents, use the `spec-steward` subagent
([.agents/agents/spec-steward.md](.agents/agents/spec-steward.md)): it keeps `docs/`
(including `docs/examples/`), this file, the README and the `scheck` skill true to the
code and to each other, and edits nothing else. Use *sync* at each build step of a
slice, before `make check` and the
`code-reviewer`, so the spec change lands in the same commit as the code; *audit* before
the commit that closes a slice, and after renaming or moving a spec heading (code
comments cite them); *draft* to turn a `security-consultant` define output or a decision
of the user's into spec text; *record* for `docs/eval/` and a slice's carried and
deferred items. A collector surface an operator runs on its own gets an example under
`docs/examples/` in that same commit; an example that would fail intake, or that tells
the operator to grant or send something the gate refuses, is drift.
`TestExamplesValidate` parses every file there. The steward never decides what is checked,
refused, redacted or how severe it is:
it returns those as open decisions, and the implementing session brings them to the
`security-consultant` or the user. It reports drift in code, goldens and schemas rather
than fixing it. It reads code, so it is never used for *seed* or *rank*.

For agents operating the CLI, use the `scheck` skill at
[.agents/skills/scheck/SKILL.md](.agents/skills/scheck/SKILL.md). It covers running
`scheck run` and interpreting the engagement report, not implementation work on this
repository. Prefer JSON, read `refused`, `incomplete`, `exit` and `coverage` before the
findings, and never treat exit 0 as a security verdict. Update it in the same commit as
any change to the report, the exit codes or the command surface.

For keeping the runtime advisory table (`internal/advisory`, G8) current, use the
`advisory-refresh` skill at [.agents/skills/advisory-refresh/SKILL.md](.agents/skills/advisory-refresh/SKILL.md):
it searches the primary sources for a new PHP or Node.js disclosure, adds verified rows,
tests them and opens one pull request per disclosure. It never merges and never changes
rules, severity or wording.

## Commands

```sh
make check      # vet + go fix + golangci-lint + go test -race ./...   (must be green before every commit)
make build      # bin/scheck
make integ      # integration tests; needs Docker or Podman running
make fixtures   # re-record testdata/fixtures/{ubuntu,fedora} from the containers
go run ./cmd/scheck init                                  # interview; writes engagement.yaml; contacts nothing
go run ./cmd/scheck init engagement.yaml                  # asks only what that file does not answer
go run ./cmd/scheck run engagement.yaml --stop-after intake   # validate, print resolved; contacts nothing
go run ./cmd/scheck run engagement.yaml --stop-after plan     # Recon runs, then Plan prints the repository order and the not-judged list; Check sends nothing until resumed
go run ./cmd/scheck run --host local --no-persist              # one-host engagement; the engagement report
go run ./cmd/scheck run --host user@host --identity ~/.ssh/k --format json   # report.json; run directory under the state dir
go run ./cmd/scheck run --host local --write-engagement e.yaml # write the --host engagement as a file; contacts nothing
go run ./cmd/scheck run ~/.local/state/scheck/engagements/<name>/<started>   # resume that run in its directory
go run ./cmd/scheck diff <earlier run dir> <later run dir>   # fixed, still open, new, not checked again; reads two report.json files, contacts nothing
go run ./cmd/scheck run --host local -v --no-persist        # the report and the host's fact sheet
go run ./cmd/scheck catalog --profile hardened
go run ./cmd/scheck explain sshd.config --format json
go run ./cmd/scheck run --host local --format json --include-evidence --no-persist   # with the captures
go run ./cmd/scheck sudoers --platform macos
go run ./cmd/scheck explain sshd.password_auth_enabled --exposure internet
go run ./cmd/scheck eval --provider mock          # the harness on the mock; no claim
go run ./cmd/scheck eval --provider mock --arms rules,bounded --no-pairs   # the bounded arm, scripted
make live                                        # opt-in live tests; spends money
make probe                                       # the Jev recall probe; needs TYPESAFE_API_KEY, spends cents
go test ./internal/engagement/report -update   # rewrite the golden engagement reports, then read the diff
go test ./internal/report -update    # rewrite the golden fact sheets and host JSON reports, then read the diff
go test ./internal/baseline -update  # rewrite the golden command traces, then read the diff
```

`make check` also runs `scripts/depcheck.sh`: `agent`, `policy`, `check`, `finding`,
`report`, `llm` and `bounded` must have no adapter or SDK in their dependency graph, and
none of the first six may import `internal/bounded`. It also holds the engagement rules
above, and the pin behind the report's "nothing was sent to the makers of scheck": no
module outside a fixed list is in the build for linux or darwin; each import of an API
that dials, resolves, sends HTTP, runs a process or makes a raw system call (and of
`golang.org/x/crypto`, a model adapter or `test/...`) is allowed per package (the gate,
the SSH transport, the model adapters, the local target); `cmd/scheck` and the host
asset use `net` only to split and join a host and port, `cmd/scheck` names the OpenAI
adapter only for its flags, the run directory uses `syscall` only to lock itself, to
open its files without following a link and to read who owns a file and how many links
it has, nothing calls `os.StartProcess` or imports
`C`, `unsafe`, `plugin` or `log/syslog`; and only the hidden `eval` command and `scheck providers` refer to `llm.Build`,
the only constructor (`llm.Lookup` returns no factory), wherever `internal/llm` is imported, never aliased. Adding a module or such an import is a change to
the pin, reviewed as one.

`make check` includes the user's `fix` target (`go fix ./...`); keep it in the chain.
If `go fix` proposes conflicting rewrites and never converges, apply the modernization
by hand (this happened with `slices.Contains` in `internal/check`).

## Adding a catalog check

1. Add the entry in `internal/check/{common,linux,macos}` with `ID`, `Description`,
   `Domain`, literal `Argv`, `Parser`, `Baseline`, `MinProfile`. Set `ExitOK` when a
   non-zero exit is an answer (`check.AnyExit` for `systemctl is-*`). Set `Elevated`
   when root is needed. Set `PathUse` on any check with a `Path` param. Set `Extract`
   to keep one line of a chatty command. Set `Unit` on a `lines` or `kv` check (the
   plural noun for one record), or pick a typed shape when a summary, a rule or a
   future diff needs fields; a typed parser keyed to a new tool's output format goes in
   `internal/check/typed.go` and is selected from `Argv[0]`, never by sniffing output.
2. Run `make check`. The invariants test names the rule you broke; fix the entry, not
   the rule.
3. If the check is elevated, `internal/sudoers` needs the binary's absolute path in its
   per-platform table, and `scheck sudoers` must still pass `visudo -cf` (integration).
4. Record it into the fixtures with `make fixtures` (Linux) and review the diff; for
   macOS, run with `--record-fixtures DIR` locally and scrub hostname, user and
   serial numbers before committing.
5. Keep the baseline tier at or under the cap (40 on-demand entries at `baseline`).

## Adding a rule

Host posture rules read one fact, or two of the same host joined per subject through a
join predicate when the first alone cannot tell a weakness from a harmless state
(`With`; `accounts.empty_password` is the one such rule, `docs/spec/host-collector.md §6.5`). Engagement rules
may combine facts from several checks or assets (`docs/spec/engagement.md`, "Multi-fact
rules"). Both must declare exactly what they read and abstain when it is unknown. Over
a population the gate marks incomplete (a cap, a page limit, an exclusion drop), a rule
may fire on what it saw but is never disproved, and its counts print as "at least"
(`docs/spec/scope.md`, "Responses").

The steps below are for a host rule. A network collector's rules live in its package
beside its reads (`Judge` in `internal/collector/web`, `internal/collector/github` and `internal/collector/workspace`), their definitions in
`internal/finding` as step 1 says, and the collector's tests prove each fires, is
disproved and abstains.

1. Add or reuse a `finding.Def` in `internal/finding/catalog.go`: a rule finding has no
   model to write its text, so title, category, base severity, impact and remediation
   are all required. So are `Area`, the engagement report's risk area, and `Exposure`,
   whether "exposed on purpose" may move it (`docs/spec/engagement.md`, "Severity in
   context"); place a new base severity against that section's anchors. Set `Subject`
   when one finding is about one instance (an account, an OAuth app, a DNS name): an
   acceptance must then name it (`docs/spec/engagement.md`, "Accepted risks"). No host
   posture finding sets it in 0.0.2; the multi-fact `db.listens_unfiltered` does
   (`service`). Set `ReadsDeclarations` when the rule reads the engagement file
   without naming it as a `declared:` read in `rule.reads` (mail senders, selectors,
   `no_mail`; a host's `app_paths`): `scheck diff` then treats the finding like a
   `declared:` rule across an edit of the file. The invariants test requires it on
   every `email.*` definition and on `creds.env_file_exposed`. `finding.ReadsDeclarations`
   (`declarations.go`) is the one answer `scheck diff` uses: it is also true for every
   finding in the identity area, for `svc.expected_missing`, `github.too_many_owners`,
   `github.undeclared_public_repository`, the four `dns.dangling_external`,
   `dns.dangling_internal`, `dns.takeover_candidate` and `dns.unclaimed_at_provider` ids
   (which one a DNS record is filed as depends on the declared roots and excludes),
   `web.secret_in_response` and `web.version_disclosed` (the pages read include every
   intent URL the file lists), and for an id the build does not know.
2. Add the `Rule` in `internal/finding/rule.go`. Pick the predicate that matches the
   check's parser and fill in what makes the evidence *recognizable* (`Requires`,
   `Known`, `Recognize`) — without it the predicate cannot abstain, and an answer scheck
   does not understand would be read as a pass.
3. Add all three fixtures to `TestEveryRuleFiresDisprovesAndAbstains`: firing,
   disproved, and insufficient evidence. The test fails when a rule has no fixtures.
4. Run `make check`; `ValidateRules` names the invariant you broke. Regenerate the
   golden reports and read the diff.

If a rule seems to need a new command, add a catalog check first.

An engagement rule over a host's facts (`db.listens_unfiltered`) is not added by these
steps. Its definition is `MultiFact` in `internal/finding/multifact.go`, and the rule
lives in `internal/engagement/rules` with its declared `Reads`, a `Group` and `Unbuilt`
wording for the coverage plan, and its fixtures in that package's tests: `Validate` and
the tests there require that it fires, is disproved and abstains, reads only what it
declares and uses every declared read, and never disproves on a partial read. A table it
matches against (databases, ufw profiles) is versioned data; changing it changes its
version constant.

## Testing rules

- Unit tests never touch the network or a real target; use `internal/target/fixture`
  for hosts and `httptest` fake servers for HTTP and API collectors.
- Anything that needs a real shell, sshd or sudo goes in `test/integ` behind the
  `integration` build tag and runs in `test/containers`.
- A seeded secret in any fixture must be asserted absent from report, audit log and
  persisted run, and its marker asserted present. See `internal/report/redaction_test.go`
  and `TestRunSeededSecretNeverReachesTheRunDirectory` in `cmd/scheck`.
- Run `go test` with `set -o pipefail` if you pipe it; a piped `grep` hides failures.
- `--sudo` cannot be exercised non-interactively on a workstation where sudo prompts.
  Use `sudo -v` first, or install the `scheck sudoers` fragment, or rely on the Ubuntu
  container test.

## Conventions

- One commit per roadmap slice, `make check` green at every commit, message in the
  imperative describing the slice. 0.0.2 slices are pull requests into
  `release/v0.0.2`, one per slice, with CI green; the branch merges into `main` once the
  0.0.2 gates are recorded in `docs/eval/acceptance-0.0.2.md`. `main` stays at v0.0.1
  behaviour until then.
- Exit codes: 0 ok, 1 findings, 2 incomplete, 3 usage/policy/canary. Do not invent a
  fifth.
- The host report's `schema_version` is `MAJOR.MINOR` since v0.0.1: additions bump
  MINOR; renames, removals and type changes bump MAJOR
  (`docs/spec/host-collector.md §6.4`). The engagement file and engagement report are
  new in 0.0.2 and may change freely until 0.0.2 is published; do not build
  compatibility shims or migrations for them.
- Rules require recognized evidence; unknown is not safe or unsafe. Preserve coverage
  in JSON and text, and test partial evidence.
- The engagement report is a contract (`docs/spec/report.md`, "The report") pinned by
  its text and JSON goldens in `internal/engagement/report/testdata/golden`, the JSON
  validated against `docs/engagement-report-schema.json`. Regenerate with `go test
  ./internal/engagement/report -update` and read the diff as a review item. Beside the
  host collector (`docs/spec/host-collector.md §9`): the fact sheet the report prints per
  host at `-v`, the host JSON report validated against `docs/report-schema.json`, and the
  command trace in `internal/baseline`, which is the run's audit log — argv, decision
  and output hash per attempted check, in order. A diff there means what reaches the
  target changed; explain it or fix it, never regenerate past it.
- In every report: a status word describes execution, never posture; target-derived
  text is control-character escaped before it is printed; and terminal decisions
  (width, tty, `NO_COLOR`) stay in `cmd/scheck`, never in `internal/report`.
- Flags reserved for later stay registered and exit 3 with "not available in this
  build". Do not remove them and do not half-implement them.
- Design lens: keep modules deep, pull complexity into the runner, the scope gate and
  policy rather than out to callers, and define errors out of existence where the spec
  allows (`unavailable` is a result, not an error).

## Model path rules

These hold for `internal/agent`, `internal/llm` and the harness that drives them. The
code is tested offline in `make check`, and a change that breaks one is still wrong.

- Implement a provider under `internal/llm/<name>` with net/http, not an SDK, register
  it in `init` with `llm.Register` and import it from `internal/llm/all`. Construction
  takes `llm.Config` and performs no I/O; credentials are read from the environment at
  request time and never printed. Absorb capability differences inside the adapter
  (`docs/spec/model.md §4`); never add a provider name or capability boolean to an `if`
  in `internal/agent`. Pass `conformance.Run` through a fake server and classify
  failures as `llm.Error` kinds.
- `run_check` and `read_file` call `runner.RunAs` with an `Origin`; the menu gate
  (profile tier, no canary) is enforced there, not in the tool. `report_finding` goes
  through `finding.Store.Report`, which validates every excerpt against the exact cited
  observation's output and refuses an id the posture rules already settled and an id
  that is not a host finding's (another collector's findings are not the model's, and
  the prompt's catalog lists host findings only). Put a new deterministic guard there,
  never in the prompt alone. A `verdict: ruled_out` call goes through
  `finding.Store.RuleOut`: validated the same way, a non-host id refused too, never a
  finding.
- Severity never comes from the model. A `severity` in `report_finding` is ignored.
- Every budget in `policy.Budgets` ends the run `incomplete` by name; a request is
  checked with `llm.CheckFit` before it is sent, and overflow never drops evidence.
- The `<operator_context>` block and check output are data; `testdata/context` is the
  corpus and `internal/agent/injection_test.go` the boundary tests. They prove policy,
  not model resistance: only a live run recorded in `docs/eval/` does.
- A model flag on `local` or `ssh` exits 3 (`modelFlags` in `cmd/scheck/root.go`); the
  provider pre-flight lives in `cmd/scheck/evalcmd.go`. Keep both there.

## The bounded arm (`internal/bounded`)

R1 of `docs/spec/bounded.md` is implemented and offline; its pattern is the design of
the `auto` gate planned for 0.0.4. Three rules hold, and a change that breaks one is
wrong even if the arm scores better:

- **Nothing is filed from the absence of an explanation.** Every decision rule needs an
  affirmative signal; "nobody declared this" is a property of the operator's notes, not
  of the host, and it is what produced the phase 2 false positives.
- **Insufficient evidence is never sent and never filed.** A source check that did not
  return `ok` yields no candidates; a truncated, redacted or marked capture is settled
  by code as `insufficient` before any question exists.
- **The follow-up table is a table.** No model picks a check, a path or an argument, and
  every read goes through `runner.RunAs` with the arm's `Origin`.

A question that names a state field must not be asked when that field is empty, or when
the command that produced it is known to degrade it: the candidate is `insufficient`
instead. Listeners are the worked example both ways — `ss` names no process
unprivileged, and `lsof` shortens the name without `+c 0` — and the second test reads
the argv that produced the capture, so it lifts by itself when the catalog entry
improves.

Questions, criteria and thresholds are versioned data (`bounded.QuestionsVersion`);
changing any of them invalidates a threshold measured against the old ones. Answer
sources are attributed separately in every record — scripted answers make no quality
claim of any kind.

## Not in the current build

Registered and exiting 3: `--only`, SARIF, `--local-only`,
the `anthropic` and `ollama` providers, and
`--bounded-source openai|jev`. Tool-call emulation and chunking are not built. The
remaining network-collector steps, probes, scans, full scope and
`auto` arrive with their slices in `docs/ROADMAP.md`. Do not scaffold empty abstractions
for any of them ahead of their slice.
