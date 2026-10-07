# scheck — scope specification

What scheck may do to each asset, and how the operator controls it. The principle is in
[VISION.md](../VISION.md) (principle 2); the stage that builds the scope is in
[engagement.md](engagement.md). Status: design. A section becomes contract when the
release that implements it lands ([ROADMAP.md](../ROADMAP.md)); until then it describes
the target, not the build.

## Rules that never change

- scheck never exploits a weakness, never modifies a target, and never attacks
  credentials.
- Nothing is sent to an asset outside scope, and an excluded asset is never contacted,
  whatever the mode or limits.
- Scope is enforced in code at the one point every check passes through, not by a
  prompt or by convention.
- Every request, command and API call is logged in the audit log.
- Credentials are never stored in the engagement file. Cloud and SaaS collectors call
  only a declared list of read operations, whatever the credentials would allow.
- Third-party data sources are not targets. Certificate transparency services, DNS
  resolvers and the providers' API endpoints are a declared list of their own, sent
  through the same gate and audited the same way; a request to one never names an
  asset outside scope as its target.

## Authorization

Real engagements start with a signed authorization. The engagement file records it,
and the report prints it, so the operator can show who approved what and when if a
hosting provider's abuse desk, which sees only the traffic, asks. The block is the
operator's own declaration; scheck checks that it is present and current, not that it
is true.

```yaml
authorization:
  by: "CTO, Example Ltd"
  date: 2026-10-06
  windows:                    # a list: real windows are often several days with daily hours
    - {from: 2026-10-07T09:00:00+02:00, to: 2026-10-07T18:00:00+02:00}
  source: [203.0.113.10/32]   # where requests come from, if fixed
  note: "Annual self-assessment; contact on-call before any scan."
```

Passive checks and reading (the observe level: SSH to the operator's hosts, read-only
cloud and SaaS APIs, a site's entry points) need no authorization block. Probes and
scans (below) do, and they run only inside a window. `source`, when given, is printed
for the abuse desk; it is not a run condition, since scheck cannot verify its own
egress address without asking a third party. The end
of a window stops probes and scans even when the run's timeout is off. Timestamps are
RFC 3339 with seconds and an explicit offset (`engagement.md`, "Identity, references
and validation").

## What is in scope

**Anything under a declared root is in scope, unless it is excluded.** The engagement
file names *roots*. Recon and cloud inventory discover what is under them, and
everything found can be checked without being listed one by one.

| Root | In scope by default |
|---|---|
| `domain: example.com` | the domain and every subdomain recon finds, and the sites they serve |
| `network: 203.0.113.0/28` | every address in the range and the services listening on it |
| `host: deploy@203.0.113.5` | the host over SSH, and the services and data stores it shows |
| `url: https://shop.example.com/` | the site, when no domain root covers it |
| `cloud: gcp:example-prod` | the GCP project (or `gcp:organizations/123` for an organization), read through read-only roles, and the resources in it |
| `saas: github:example-org` | the tenant, read through read-only scopes; likewise `google-workspace:example.com` |
| `repo: ./` or `repo: github:example-org/shop` | the repository and its history (a local checkout from 0.0.2 E4, when the gate decides how history is read) |

```yaml
roots:
  - domain: example.com
  - cloud: gcp:organizations/123456789012
  - saas: github:example-org
  - saas: google-workspace:example.com
  - host: deploy@203.0.113.5
exclude:
  - domain: legacy-billing.example.com      # a subdomain and everything under it
  - network: 203.0.113.9/32
  - url: https://shop.example.com/checkout/ # a path prefix on an in-scope site
  - repo: github:example-org/client-nda     # a repository under an organization root
  - {saas: google-workspace:example.com, org_unit: "/Board"}   # the unit and every unit under it
  - cloud: gcp:example-sandbox              # a project under an organization root
defaults:                                   # applied to every asset, declared or discovered
  probe: off
  scan: off
  throttle: {rate: 5/s, concurrency: 2}
```

`exclude` always wins: over `roots`, over an asset's own settings, over every mode and
over full scope. An excluded asset gets no request of any level, and the report lists it
as excluded. For an asset read through an API, "never contacted" is not enough: a call
that lists users or repositories returns the excluded ones too. The gate drops excluded
items from every response before anything is stored, and the audit log records the
count it dropped. Excluding an organizational unit drops its users from every identity
rule. Those are often the most targeted accounts, so the Identity and access row is at
most *partial* and names the unit.

An `assets` entry never adds scope: its locator must equal a root or fall under one, or
validation exits 3. Scope has one source, `roots`, narrowed by `exclude`.

### First-party evidence

A name under your domain is not proof that the server behind it is yours: a forgotten
DNS record can point at an address another cloud customer now uses. So an asset is
**first-party** only with positive evidence:

- its address is inside a declared `network` root, or
- it is a resource in a declared `cloud` account's inventory, or
- it is a `host` or `url` root, or
- its `assets` entry carries `first_party: {confirmed_by, date}`, which the Scope stage
  writes into the engagement file when the operator confirms it, so the next run keeps
  it.

An `assets` entry without `first_party` only changes settings; it is not evidence.
Intent URLs are never evidence.

The first two are evidence; the last two are the operator's word. A small company on a
cloud platform rarely owns a network range, so until its cloud inventory is read
(ROADMAP, 0.0.3 G2) the operator's word is most of what there is. That is the same
guarantee every tool offers, and scheck does not pretend otherwise: the report names
the evidence behind every probed asset, and "operator confirmed" is printed as such.

Without any of it, an asset gets passive checks and the observe checks that read its
front page and certificate, and nothing more. Those two reads do contact a server that
may belong to someone else, as any browser following the name would; they are the only
requests scheck sends without first-party evidence, and the audit log records each.

Two cases are recorded, never contacted beyond that:

- **Outside every root.** A third party the company depends on (a CDN, a payment
  provider, an analytics script) is listed in the report from passive recon. If the
  operator is authorized to assess it, they add it as a root.
- **Inside a root but run by a third party.** A subdomain that points at a hosted
  service (`shop.example.com` → a SaaS storefront) is yours by name, not by server. A
  name pointing at a service that no longer exists is itself a finding (subdomain
  takeover), and spotting it is passive.

Discovered assets take `defaults`; an entry under `assets` overrides them for one asset.
The Scope stage shows the resolved list (roots, what discovery added, first-party
evidence, what was excluded and why) before anything beyond passive runs. Showing is
not approving: the list is printed and written to `scope.json`, and only a first-party
confirmation or a `confirm`-mode probe or scan waits for the operator. A run with no
terminal goes on with the observe level and records every pending confirmation as
not given.

A name is resolved again when a request is sent, and the request goes to the address
just resolved. An address that moved into an excluded range, or that no longer has
the first-party evidence the Scope stage recorded, is refused and audited.

## Impact levels

Every check declares one level.

| Level | Meaning | Default |
|---|---|---|
| *passive* | No contact with the target: public DNS, certificate transparency, the operator's own files and repositories | Always allowed |
| *observe* | Reading through the interfaces meant for it: a site's known entry points, a host over SSH, a cloud or SaaS API with read-only access | Allowed for every in-scope asset |
| *probe* | A fixed, reviewed list of single, harmless requests for well-known sensitive locations on a first-party site | `confirm` from 0.0.3; `off` before |
| *scan* | Anything broader: port scans, path discovery, scanner templates, authenticated requests | `off` |

Probes find the most valuable web issues with a few requests each; scans generate
traffic that looks like an attack. That is why they have separate gates.

## Per asset type

### Web applications and sites

| Level | Checks |
|---|---|
| *passive* | DNS records, certificate transparency, SPF, DKIM and DMARC records |
| *observe* | TLS handshake and certificate; `GET`/`HEAD` of the site's known entry points (its `url` root or entry and the `intent` URLs on it, or the root of a discovered site), plus `robots.txt` and `/.well-known/` entries such as `security.txt`; headers, cookies and technology fingerprint from those responses |
| *probe* | single `GET` requests from the reviewed list: `/.git/HEAD`, `/.env`, framework debug routes, common admin panels |
| *scan* | path discovery, scanner templates, authenticated requests, port scans |

### Cloud accounts and SaaS tenants

*Observe* only: a declared list of read API calls per provider, using credentials from
the environment or the provider's own CLI login, never from the engagement file. Use a
read-only role (for GCP, Security Reviewer and Cloud Asset Viewer; for Google Workspace,
read-only Admin SDK scopes); if the credentials allow
more, scheck still calls only its read list, and the report notes the broader grant as
a finding. This is how data stores are judged from the control plane: whether a
database is publicly accessible, what its VPC firewall rules and authorized networks
allow, where its backups live.

The throttle for an API follows the provider's rate-limit headers, within the
configured ceiling, rather than a fixed rate per asset. Evidence keeps only the fields
a rule reads; a full directory record carries recovery phone numbers and addresses no
rule needs.

### Repositories

*Passive* for a checkout the operator provides; *observe* through the code host's API.
Secrets are searched in history as well as the current tree, and are redacted in every
output: the report shows where a secret is and what kind it is, never its value. Where
the code host has its own secret scanning, its alerts are read as well.

Reading history needs a git transport, and running `git` would send requests the gate
does not see. How history is fetched (through the gate, or from a checkout the operator
provides as a passive source) is decided with the gate in 0.0.2 E4, before the GitHub
collector exists.

### Hosts

The host collector described in `host-collector.md` is *observe*: read-only commands from a
compiled catalog, locally or over SSH, with path policy and redaction. Its three known
writes (`host-collector.md §1`) stay listed and tested.

## Running probes and scans

Probes and scans each have a mode, set under `defaults` or per asset:

```yaml
assets:
  shop:
    url: https://shop.example.com
    probe: all
    scan: confirm
```

| Mode | What runs |
|---|---|
| `off` | Nothing. The report lists what would have applied as *not run*. |
| `confirm` | What the operator approves from a preview listing every planned request: method, URL and count. A run with no terminal treats them as *not run*. |
| `auto` | Experimental: what passes the decision gate below. |
| `all` | Everything at that level that applies to the asset. |

Every mode other than `off` needs first-party evidence for the asset and an
authorization window, and stays inside the rules at the top of this page. The throttle, timeout and cost limit
(last section) apply in every mode. A model may propose probes and scans during Plan;
whether they run is still decided by the asset's mode.

### Full scope

`scheck run --full-scope` (or `scope: full` in the engagement file) sets `probe: all`
and `scan: all` on every first-party, non-excluded asset, including those discovered
under the roots, and lets Plan choose any check that applies to them. It changes
*which checks may run*, nothing else: roots, first-party evidence, `exclude`, any
asset's explicitly set mode, the authorization window, the never-change rules, the
throttle, the timeout and the cost limit all still hold. The Scope stage marks the
resolved list as full scope before anything beyond passive runs, and the report and
audit log record it.

### `auto`: an experimental decision gate

`auto` is not offered as a default until it is measured (VISION principle 5). Its use
is an unattended run with scans on: with `confirm` the operator already sees and
approves every planned request, so `auto` saves nothing until there are more requests
than a person will review, which is why it follows the scan level in the roadmap. It
uses Jev (TypeSafe's yes/no decision model, see [bounded.md](bounded.md)) only where
code cannot decide by itself:

1. **Code decides relevance where it can.** Every probe and scan is tagged with what it
   targets; a fingerprint that matches or rules out the tag settles it. A check that does
   not depend on the technology (an exposed `.git` directory) is always relevant.
2. **Jev answers only what code cannot**, each a probability over one asset's context
   and recon facts:
   - *Inconclusive fingerprint:* does the evidence indicate this asset uses what the
     check targets? (Asked only when the fingerprint is hidden, for example behind a
     CDN.)
   - *The operator's own words:* does the prose context ask that this asset or path not
     be probed? A request the operator wrote in prose but never put in `exclude`. Only
     prose the operator wrote in the engagement file is read for this; text that came
     from a target (a page, a banner, a host's own context file) is never an input, so
     a target cannot talk the gate out of probing it.
3. **Code decides, and fails closed:** an answer near 0.5 is uncertain and the check does
   not run. A check runs because there is evidence it applies.
4. **Every decision is recorded:** the probabilities, thresholds, model id and outcome.

There is no "could this request cause harm" question: a check that could harm a target
does not belong in the catalog, and a fragile path belongs in `exclude`. `auto` can
never run more than `all` would on the same asset. Without Jev credentials, an asset set
to `auto` is a usage error before any target is contacted.

## Throttle, timeout and cost

These are always in force, in every mode, including full scope.

**Throttle, per asset.** A request rate and a concurrency, with conservative defaults,
set under `defaults` or per asset.

**Timeout and maximum cost, per run.** Both have defaults and are configurable;
`none` means no limit for that one setting, and `0` is rejected rather than read as
"no limit". Reaching either ends the run as *incomplete*, never as a clean result. The
authorization windows still bound probes and scans in a run whose timeout is `none`.
`max_cost` is rejected until a model runs (0.0.4), so a file written for an earlier
release can never turn into unlimited spend.

```yaml
limits:
  timeout: 1h        # none = no timeout
  max_cost: 2.00     # USD of model spend; none = no cost limit (0.0.4 on)
```

The loop never re-runs a check that succeeded with the same inputs, so a run without a
timeout still ends when no follow-up is open.
