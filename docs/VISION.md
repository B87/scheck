# scheck — vision

**scheck is a security consultant in a CLI.** You describe what you run and what
matters to you; scheck plans an assessment, gathers evidence across your cloud
accounts, SaaS tools, code, machines and websites, follows up on what it finds, and
writes a prioritized report that says which risk areas it covered and which it did not.

This page says what scheck is for. How it works is in the documents listed at the end.
When a design choice is unclear, pick the option that brings a run closer to what a
good consultant would do in the first days of an engagement.

## Why

Scanners are generic. They run the same list against every target and bury the few
findings that matter for *this* company under many that do not. What makes something
critical is usually context only insiders know: which account can deploy to
production, which admin panel is public on purpose, which database holds customer data.

A consultant's value is mostly that context work: an intake interview, a map of what
exists, a prioritized plan, targeted checks, and judgement about the results. scheck
gives that process to the people who already hold the context: engineers, operators,
and the one person on the team who "does security". It is for assessing systems you
own or are authorized to assess, never anyone else's.

**What it replaces, honestly.** scheck automates the collection and first-pass
judgement of an engagement: the external surface, configuration of cloud, SaaS and
hosts, secrets, and the links between them. It does not replace authenticated testing
of your application's logic, a review of your processes, or a human who signs the
report. It should make a consultant's time go further, or make the first one
affordable.

## How it works

A run is an **engagement**:

**Intake → Scope → Recon → Plan → Check → Analyze → (back to Plan) → Report**

You answer an interview once (`scheck init`), which writes an engagement file,
including who authorized the assessment. Each later stage produces something you can
read, edit, stop at or resume from. The loop ends when every hypothesis is settled or
a limit is reached. The report puts first what matters most for your setup.

scheck assesses **assets and the links between them**, because the risk is usually in
the link. In a small company today, most links are identities and permissions, not
network paths: *a contractor's GitHub token can push to the repository that deploys to
production, and that repository holds the payment provider's key.* Assets are:

- **Cloud accounts** (GCP first) and **SaaS tenants** (Google Workspace and GitHub
  first), read through read-only API access;
- **Repositories and CI**, including their history;
- **Hosts** (macOS and Linux, local or over SSH);
- **Web applications and sites**, and the **domains** they live on.

## Principles

1. **Context first.** What you tell scheck decides what it examines and in what order,
   not only how severe a finding is afterwards. Without context it still runs, as a
   generic baseline, and the report says so.
2. **Explicit, authorized scope, enforced in code.** You name the domains, networks,
   accounts and hosts that are yours, and who authorized the assessment. scheck
   checks what is under them unless you exclude it, contacts nothing outside them,
   and only probes an asset once it has evidence the asset is really yours. Probing
   beyond reading is opt-in, and every run is throttled and has a timeout and a cost
   limit. scheck never exploits, never modifies a target, and never generates load
   you did not ask for.
3. **Useful without a model; better with one.** With rules alone, the plan is a
   checklist per asset type and links come from deterministic rules that combine
   facts. A model adds what rules cannot: hypotheses drawn from your own words,
   follow-ups, and judgement across assets. That part is unproven, and it never writes
   a command, widens scope or sets severity on its own say-so.
4. **Every finding cites evidence, and the report shows its coverage.** Unknown is
   neither safe nor unsafe. The report states, for every risk area, whether it was
   assessed, partly assessed or not assessed, so a short list of findings is never
   mistaken for a clean bill of health.
5. **Measured, not assumed.** The model-driven path becomes the default only when it
   beats the rules-only path on labeled cases the authors of the checks did not write.
   The 0.0.1 evaluation is the reason: its agent loop never called a tool in 45 of 45
   runs, and nothing short of a measurement would have shown that.
6. **Reuse good tools, later.** Established scanners are wrapped as declared checks
   once the engagement itself works, not before.

## Not in scope

- Offensive work: exploitation, credential attacks, anything outside declared scope.
- Authenticated testing of application logic (access control, business rules).
- Replacing a vulnerability scanner. scheck may call one; its job is prioritization and
  judgement.
- Remediation. It says what to fix and how; it changes nothing.
- Continuous monitoring or fleets. One engagement at a time; comparing two is fine.

## Success

An engineer at a small company whose product runs on a cloud platform and a handful of
SaaS tools runs one engagement in under an hour. The report's coverage table is
accurate, and its top five findings agree with an independent consultant's ranking of
the same environment. On labeled cases it finds what a scan without context misses,
with fewer irrelevant findings, and context both raises and lowers severity where it
should.

## Read next

| Document | What it covers |
|---|---|
| [ROADMAP.md](ROADMAP.md) | 0.0.2 the first engagement, 0.0.3 cloud and identity, 0.0.4 judgement and depth |
| [spec/engagement.md](spec/engagement.md) | The stages, the engagement file, the report's coverage, and where rules and the model each act |
| [spec/scope.md](spec/scope.md) | Authorization, roots and exclusions, impact levels per asset type, active modes and limits |
| [spec/host-collector.md](spec/host-collector.md) | The host collector released in v0.0.1: catalog, runner, policy, SSH, posture rules, host report |
| [spec/model.md](spec/model.md) | The model path: provider contract, agent loop and tools, kept offline until it earns its place |
| [spec/bounded.md](spec/bounded.md) | The bounded yes/no decision pattern (Jev) behind the `auto` gate |
| [eval/](eval/) | Recorded evidence: the 0.0.1 acceptance pass and the phase 2 evaluation |
