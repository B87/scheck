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

## Authorization

Real engagements start with a signed authorization. The engagement file records it,
and the report prints it, so the client's legal team or a hosting provider's abuse desk
can see who approved what.

```yaml
authorization:
  by: "CTO, Example Ltd"
  date: 2026-10-06
  window: {from: 2026-10-07T09:00Z, to: 2026-10-07T18:00Z}
  source: 203.0.113.10        # where requests come from, if fixed
  note: "Annual self-assessment; contact on-call before any scan."
```

Passive checks and reading the operator's own hosts over SSH need no authorization
block. Probes and scans (below) do, and they run only inside the window. The end of the
window stops a run even when its timeout is off.

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
| `repo: ./` or `repo: github:example-org/shop` | the repository and its history |

```yaml
roots:
  - domain: example.com
  - cloud: gcp:example-prod
  - saas: github:example-org
  - host: deploy@203.0.113.5
exclude:
  - domain: legacy-billing.example.com      # a subdomain and everything under it
  - network: 203.0.113.9/32
  - url: https://shop.example.com/checkout/ # a path prefix on an in-scope site
defaults:                                   # applied to every asset, declared or discovered
  probe: confirm
  scan: off
  throttle: {rate: 5/s, concurrency: 2}
```

`exclude` always wins: over `roots`, over an asset's own settings, over every mode and
over full scope. An excluded asset gets no request of any level, and the report lists it
as excluded.

### First-party evidence

A name under your domain is not proof that the server behind it is yours: a forgotten
DNS record can point at an address another cloud customer now uses. So an asset is
**first-party** only with positive evidence:

- its address is inside a declared `network` root, or
- it is a resource in a declared `cloud` account's inventory, or
- it is a declared `host` or `url`, or
- the operator confirms it in the Scope stage.

Without that evidence, an asset gets passive checks and the observe checks that read its
front page and certificate, and nothing more. The report shows which evidence made each
asset first-party.

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
evidence, what was excluded and why) before anything beyond passive runs.

## Impact levels

Every check declares one level.

| Level | Meaning | Default |
|---|---|---|
| *passive* | No contact with the target: public DNS, certificate transparency, the operator's own files and repositories | Always allowed |
| *observe* | Reading through the interfaces meant for it: a site's known entry points, a host over SSH, a cloud or SaaS API with read-only access | Allowed for every in-scope asset |
| *probe* | A fixed, reviewed list of single, harmless requests for well-known sensitive locations on a first-party site | `confirm` |
| *scan* | Anything broader: port scans, path discovery, scanner templates, authenticated requests | `off` |

Probes find the most valuable web issues with a few requests each; scans generate
traffic that looks like an attack. That is why they have separate gates.

## Per asset type

### Web applications and sites

| Level | Checks |
|---|---|
| *passive* | DNS records, certificate transparency, SPF, DKIM and DMARC records |
| *observe* | TLS handshake and certificate; `GET`/`HEAD` of the site's known entry points (declared URLs, or the root of a discovered site), plus `robots.txt` and `/.well-known/` entries such as `security.txt`; headers, cookies and technology fingerprint from those responses |
| *probe* | single `GET` requests from the reviewed list: `/.git/HEAD`, `/.env`, framework debug routes, common admin panels |
| *scan* | path discovery, scanner templates, authenticated requests, port scans |

### Cloud accounts and SaaS tenants

*Observe* only: a declared list of read API calls per provider, using credentials from
the environment or the provider's own CLI login, never from the engagement file. Use a
read-only role (for GCP, Security Reviewer and Cloud Asset Viewer; for Google Workspace,
read-only Admin SDK scopes); if the credentials allow
more, scheck still calls only its read list, and the report notes the broader grant as
a finding. This is how data stores are judged from the control plane: whether a
database is publicly accessible, what its security group allows, where its backups
live.

### Repositories

*Passive* for a checkout the operator provides; *observe* through the code host's API.
Secrets are searched in history as well as the current tree, and are redacted in every
output: the report shows where a secret is and what kind it is, never its value.

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

Every mode needs first-party evidence for the asset and an authorization window, and
stays inside the rules at the top of this page. The throttle, timeout and cost limit
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

`auto` is not offered as a default until it is measured (VISION principle 5). It uses
Jev (TypeSafe's yes/no decision model, see [bounded.md](bounded.md))
only where code cannot decide by itself:

1. **Code decides relevance where it can.** Every probe and scan is tagged with what it
   targets; a fingerprint that matches or rules out the tag settles it. A check that does
   not depend on the technology (an exposed `.git` directory) is always relevant.
2. **Jev answers only what code cannot**, each a probability over one asset's context
   and recon facts:
   - *Inconclusive fingerprint:* does the evidence indicate this asset uses what the
     check targets? (Asked only when the fingerprint is hidden, for example behind a
     CDN.)
   - *The operator's own words:* does the prose context ask that this asset or path not
     be probed? A request the operator wrote in prose but never put in `exclude`.
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

**Timeout and maximum cost, per run.** Both have defaults and are configurable; `0`
means no limit for that one setting. Reaching either ends the run as *incomplete*,
never as a clean result. The authorization window still bounds a run whose timeout is
`0`.

```yaml
limits:
  timeout: 1h        # 0 = no timeout
  max_cost: 2.00     # USD of model spend; 0 = no cost limit
```

The loop never re-runs a check with the same inputs, so a run without a timeout still
ends when no hypothesis is open.
