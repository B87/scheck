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
- Every request, command and API call is logged in the audit log; a run that cannot
  keep one sends nothing through the gate.
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
| `repo: github:example-org/shop` | the repository, and its history when its `checkout` is set ("Repositories"); without it, history coverage is *partial* |

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
- its `assets` entry carries `first_party: {confirmed_by, date, target}`, which the
  Scope stage writes into the engagement file when the operator confirms it, so the
  next run keeps it.

An `assets` entry without `first_party` only changes settings; it is not evidence.
Intent URLs are never evidence.

The first two are evidence; the last two are the operator's word. A small company on a
cloud platform rarely owns a network range, so until its cloud inventory is read
(ROADMAP, 0.0.3 G2) the operator's word is most of what there is. That is the same
guarantee every tool offers, and scheck does not pretend otherwise: the report names
the evidence behind every probed asset, and "operator confirmed" is printed as such.

**A confirmation names what was confirmed, and expires.** `target` is where the name
pointed when the operator confirmed it: the first name of its CNAME chain outside
every root when it has one (what the company's own record says; later hops are the
provider's internals, which differ by region and vantage), otherwise its addresses,
sorted and joined with commas. A name whose current chain or addresses no longer match
`target` has lost the confirmation: the gate refuses what needed it as
`refused:address_moved`, and the report says it was re-asked because its target
changed. That catches a record repointed; it does not catch a change of owner behind
the same provider name (a released app name claimed by someone else). Expiry bounds
how long the confirmation can last. From 0.0.2 E7 step 2b-ii a positive provider
fingerprint suspends operator confirmation in the live gate and persisted
`scope.json`. Suspension applies to the exact subject name or the names listed as
members of a wildcard finding, never every descendant or a nested root. Explicit
roots keep their root evidence. A name with no CNAME whose addresses rotate (an apex alias to a load
balancer or CDN) loses its confirmation whenever they change; the report counts those
so the churn is visible. A confirmation is valid from `date` through `date` plus 365
days, until 24:00 in `engagement.timezone`; one dated after the run (a typo for a year
to come) is not evidence, and the Scope listing says so; after that the name has no evidence and the report
notes "confirmation of `<date>` expired". An expired or moved `first_party` entry stays
in the file and is listed under "Notes for the readout" so someone removes it.

**Confirming in 0.0.2.** Scope asks nothing and prints no stanza to paste: in 0.0.2 a
confirmation unlocks only `robots.txt` and `security.txt`, and dozens of prompts, or
stanzas pasted in bulk, would teach operators to say yes without reading before 0.0.3
makes a confirmation unlock probes. Scope lists each name with what it points at,
which is its `target`, so an operator who knows a server is theirs can write the entry
by hand. The prompt arrives with probes (0.0.3): after the observe reads, only for
names that answered HTTP(S), asking who runs the server at that address rather than
whether the name is theirs, with fixed answers (us or our IT provider on our account;
a service we pay for; an agency or freelancer; I don't recognise it), grouped by where
names point, with progress and "decide later", and a "no" remembered per engagement in
the state directory for 90 days.

Without any of it, an asset gets passive checks and the observe checks that read its
front page over https and http, the https read's handshake giving its certificate, and
nothing more. Those two reads do contact a server that
may belong to someone else, as any browser following the name would; they are the only
requests scheck sends without first-party evidence, and the audit log records each.

### Discovery

The Scope stage expands each `domain` root into the names under it, from certificate
transparency and DNS only. It contacts no server of the company's or anyone else's: it
asks `crt.sh` once per domain root and the system's resolver for each name
("Third-party sources").

1. **Control queries.** Before anything else, Scope asks for a random 20-character
   label under each domain root, and one under `invalid.` (RFC 6761: it names no one's
   asset, and is the only lookup outside every root scheck sends). If `invalid.` gets
   an address, the resolver answers names that do not exist with its own address:
   every dangling verdict is then *insufficient evidence*, no discovered name without
   first-party evidence is read, and the report says "Your DNS resolver answers names
   that do not exist with its own address, so discovered names were not checked. Run
   from a network whose resolver does not do this." If a root's control label gets an
   address, the root has wildcard DNS, and a discovered name whose answer equals the
   control answer in outcome, whole CNAME chain and addresses is recorded as
   "matches the wildcard" and is not read on its own,
   listed under not checked; a declared name (an `assets` entry or a `url` root) is
   read even then. Answers must be recognized: shared IPs alone, different chains
   and equal redaction or truncation markers never establish a match. A nonempty
   dangling chain matching the control's chain, outcome and addresses is grouped
   the same way. `domains[].control` keeps the
   concrete control name, chain, addresses, outcome and request id; Recon judges that
   answer once on `*.<root>` (E7 step 2b-ii,
   [web-collector.md](web-collector.md#takeover-fingerprints), "Wildcards"). The
   control names are random. A resolver that answers `.invalid`
   itself, as RFC 6761 lets it, and rewrites everything else passes the first control;
   the per-root control is the safety net, and under rewriting a dangling verdict can
   only be missed, never invented. `scope.json`'s `resolver` records what the
   `invalid.` lookup came to (`control_outcome`: its outcome, or the gate's decision
   when it was not sent) beside `rewrites_nxdomain`. Whether the resolver rewrites is
   known only when that lookup said NXDOMAIN or NODATA, or got an address. Otherwise no
   discovered name without first-party evidence is read ("not read: whether the
   resolver answers names that do not exist is unknown"), a declared name is read even
   then, and every DNS verdict of the web collector abstains as
   `unavailable:resolver_unchecked`
   ([web-collector.md](web-collector.md#dns-and-takeover)). Each session that runs
   Recon on a domain root sends a control lookup of its own under `invalid.`, once,
   before its first read through the resolver, since a resumed session may be on
   another network; the web collector's verdicts stand only when both Scope's resolver
   and that session's are known not to invent answers.
2. **Names.** Every domain root, every `domain`, `url` and `host` asset written by name
   under it, and every name certificate transparency returns under it. A wildcard
   entry `*.x` is recorded as "wildcard certificate for x" and never queried
   literally. A name seen only in expired certificates is kept, since old names are
   where dangling records are, and marked "seen only in expired certificates".
3. **Excluded names are never resolved.** A name an exclude covers is dropped and
   counted, before any query: a query for it reaches its authoritative servers, which
   may be the excluded party's. A name is covered by a `domain` exclude over it, a
   `host` exclude written as that name, or a `url` exclude at the root of that name's
   site on its default port; a `url` exclude below the root or on another port leaves
   the name. A CNAME chain from an in-scope name that enters an excluded name stops
   there and is recorded as excluded, with the exclude; the resolver may already have
   followed it, and scheck sends no query of its own for it. The gate decides each of
   these and writes its audit line; discovery records the gate's answer.
4. **Resolution.** Each name is asked for A and AAAA, following its CNAME chain, at
   most 8 hops. The gate asks for the CNAME of the chain's end, once per name, when
   the address queries at that end find nothing (NXDOMAIN or NODATA), or when the
   resolver's chain ends in NXDOMAIN at a name scheck did not ask: a DNS host may
   answer an address query for an in-zone CNAME whose target does not exist with
   NXDOMAIN and no CNAME, a provider may hide its own CNAME one hop down, and only a
   CNAME query shows the chain (`eval/lab-0.0.2-domain.md`). A CNAME found there
   extends the chain and the chase goes on; a failure of that query is the lookup's
   outcome. A name that does not exist is therefore asked for its CNAME too, and a
   dangling chain the resolver answered whole costs one CNAME query for its end,
   outside the roots: following a chain is part of resolving the in-scope name
   ("Third-party sources"). The outcome is one of:
   - **addresses**, with the chain that led there;
   - **dangling**: the chain ends in NXDOMAIN, or in NODATA ("the target exists but
     has no address"; a DNS host's compact denial of existence answers a name that
     does not exist as NODATA, NOERROR with no record). A target inside a declared
     root is a stale record; a target outside every root is a takeover candidate or a
     dangling external record. All
     are findings from DNS alone (0.0.2 E7 files them by the rules of
     [web-collector.md](web-collector.md#dns-and-takeover)), with nothing to contact;
   - **no longer exists**: NXDOMAIN on the name itself, with no chain; or **no
     address**: NODATA on the name itself. Recorded, not findings;
   - **insufficient evidence**: SERVFAIL, REFUSED, a timeout, a chain that loops or
     passes 8 hops. Never dangling and never resolved; retried on resume.
5. **Caps.** Scope resolves at most 1000 names per root, and marks at most 200 names
   without first-party evidence for their front-page reads. The order is fixed, so a
   resume and a comparison see the same names: declared names first, then names in
   unexpired certificates by latest `not_after`, then names seen only in expired
   ones, each group by name. The rest are listed as not checked, and counts over them
   print as "at least".

Scope records which names Recon reads; the gate does not decide that. The gate enforces
scope, exclusion, entry points and addresses from the file and live resolution, and a
collector reads only the names `scope.json` marks for it, plus the concrete wildcard
control when its resolving chain matches an enabled body-fingerprint provider and
both resolvers are known not to invent answers. That control receives one https/http
front-page pair through the normal gate; matching undeclared discovered names and
the literal `*.<root>` receive none. Declared names retain their own reads and
judgments even with matching DNS, since their HTTP Host bindings may differ.

**Outside every root.** Recorded, never resolved on their own or contacted, in two
lists:

- *Services your names point at*: CNAME targets outside every root
  (`shop.example.com → shops.myshopify.com`), the company's real third-party
  dependencies, from discovery's own lookups. From 0.0.2 E7 the list counts the names
  whose provider has no takeover fingerprint ("*N* not checked for takeover: no
  fingerprint for this provider").
- *Other names on your certificates* (from 0.0.2 E7): names outside every root on a
  certificate the observe reads receive in their TLS handshake, listed only when that
  certificate names at most 5 of them; larger shared certificates (a CDN's, a host's)
  are counted, not listed. Certificate transparency cannot give this list: `crt.sh`
  returns only the identities that matched the query.

scheck does not offer to add either as a root. Adding one is the operator's statement
that they are authorized to assess it.

**Inside a root but run by a third party.** A subdomain that points at a hosted service
(`shop.example.com` → a SaaS storefront) is yours by name, not by server. A name
pointing at a service that no longer exists is itself a finding (subdomain takeover).
Spotting it takes DNS alone when the chain dangles, and the one front-page read when
the provider still answers: a chain that ends at a provider's address is not dangling,
and the response to that read is what a provider fingerprint (0.0.2 E7,
[web-collector.md](web-collector.md#takeover-fingerprints)) reads.

**What certificate transparency cannot find.** Every report with a domain root prints:
"Subdomains were discovered from certificate transparency (crt.sh) and DNS only. Not
found this way: names that never had a publicly trusted certificate (internal,
HTTP-only, or covered by a wildcard certificate such as `*.example.com`). Your DNS zone
was not read; your DNS provider can export every name."

Discovered assets take `defaults`; an entry under `assets` overrides them for one asset.
The Scope stage shows the resolved list (roots, what discovery added, first-party
evidence, what was excluded and why) before anything beyond passive runs. Showing is
not approving: the list is printed and written to `scope.json`, and only a first-party
confirmation or a `confirm`-mode probe or scan waits for the operator. A run with no
terminal goes on with the observe level and records every pending confirmation as
not given ([engagement.md](engagement.md#runs-state-and-configuration), "Scope
confirmations persist").

A name is resolved again when a request is sent, and the request goes to the address
just resolved. A name with an address in an excluded range, an address that is not
public (loopback, private, link-local, cloud metadata), or that no longer has the
first-party evidence the Scope stage recorded, is refused and audited ("The scope
gate", "Addresses").

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
| *passive* | DNS records, certificate transparency, SPF, DKIM and DMARC records, MX and NS; the names the company's own MX, NS and SPF records point at, resolved and never contacted ("Third-party sources") |
| *observe* | TLS handshake and certificate; `GET`/`HEAD` of the site's known entry points (its `url` root or entry and the `intent` URLs on it), plus `/robots.txt` and `/.well-known/security.txt`, and one redirect hop on the same host ("Connections"); a discovered name with first-party evidence has `/` as its entry point and reads the same; one without it gets only `GET /` over https and http, whose https handshake is its certificate read. Headers, cookies and technology fingerprint come from those responses |
| *probe* | single `GET` requests from the reviewed list: `/.git/HEAD`, `/.env`, framework debug routes, common admin panels |
| *scan* | path discovery, scanner templates, authenticated requests, port scans |

Header, cookie, `security.txt` and plain-HTTP rules judge declared sites only: a `url`
root, a `url` asset entry, or a name with first-party evidence. Every other name read
is listed as read, not judged, with a count; the DNS, takeover, certificate,
version-disclosure and secret rules judge every name read
([web-collector.md](web-collector.md#reads)).

**What a site's responses never lead to**, in 0.0.2 and in 0.0.3:

- a path from `robots.txt` as a request; its `Disallow` entries are counted, never read;
- a script fetched, a link followed, or a sitemap read;
- a redirect followed beyond one hop on a declared or first-party site, or to another
  name ("Connections");
- an HSTS preload list, WHOIS or RDAP;
- more than one TLS handshake per name.

### Cloud accounts and SaaS tenants

*Observe* only: a declared list of read API calls per provider, using credentials from
the environment or the provider's own CLI login, never from the engagement file. Use a
read-only role (for GCP, Security Reviewer and Cloud Asset Viewer; for Google Workspace,
read-only Admin SDK scopes); if the credentials allow
more, scheck still calls only its read list, and the report notes the broader grant as
a finding. This is how data stores are judged from the control plane: whether a
database is publicly accessible, what its VPC firewall rules and authorized networks
allow, where its backups live.

The throttle for an API follows the provider's rate-limit headers, within a compiled
ceiling per provider, rather than the web throttle under `defaults` ("The scope gate",
"Throttle, timeouts and retries"). Evidence keeps only the fields a rule reads; a full
directory record carries recovery phone numbers and addresses no rule needs.

### Repositories

*Passive* for a checkout the operator provides; *observe* through the code host's API.
Secrets are searched in history as well as the current tree, and are redacted in every
output: the report shows where a secret is and what kind it is, never its value. Where
the code host has its own secret scanning, its alerts are read as well.

**History comes from the operator's mirror checkout, read in-process (decided in 0.0.2
E4).** scheck has no git transport. Running `git` would send requests the gate never
sees. Cloning through the gate would need a `POST` to `git-upload-pack` and would leave
plaintext secrets in a temporary directory on the operator's laptop, with a cleanup
that a crash skips. The operator already holds the clone:

- **The setting.** A repository asset names it with `checkout: /abs/path`, a path, like
  a host's `identity`, never a credential. The asset id stays
  `repo:github:owner/name`. The operator makes it with `git clone --mirror`, which
  brings `refs/pull/*`, where secrets from deleted branches live.
- **Checks before reading.** The remote in the checkout's `config` must match the
  locator, compared after removing userinfo, or the checkout is refused. The config's
  content is never stored or printed, and a credential in a remote URL
  (`https://x:ghp_…@github.com/…`) is reported as a finding. Its heads are compared with the branch heads the
  API returns through the gate. A stale checkout is read, and coverage says "behind
  origin". Missing pull refs make coverage *partial*.
- **The reader.** It is in-process: loose objects and packs read with the standard
  library's zlib, files opened read-only, every path confined under the checkout after
  realpath. Nothing is executed. Each repository gets one audit line with its object
  counts.
- **Detection is redaction.** A compiled secret-shape rule, or the run's own
  `credential` rule, matching blob content is the finding, recorded as `(commit, path,
  line, rule)`. Only the marker is kept, never the value or a hash of it. A
  `redact_extra` match is redacted and counted, never filed: those patterns hide what a
  client wants unseen, such as a customer's name, not secrets.
- **Coverage.** "History read for k of N repositories" is *partial* when k < N. The code
  host's own secret-scanning alerts are read through the API where the token can see
  them. Commits GitHub still serves by SHA after their branch was deleted without a
  pull request are not in a mirror, and coverage says they are *not assessed*.
- **When.** `checkout` is accepted from E5, which reads it. Validation checks only that
  the path is absolute; the remote and heads are checked when E5 reads the checkout.

A gate-mediated fetch is reconsidered in 0.0.3 if operators find mirroring a burden.

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
set under `defaults` or per asset. `defaults.throttle` governs web assets only. An API
follows its provider's compiled ceiling and rate-limit headers, and a throttle set on
the SaaS asset's own `assets` entry can only lower that ceiling ("The scope gate", "Throttle, timeouts and retries").

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

## The scope gate

Built in 0.0.2 E4, with its rules defined by the `security-consultant`.
`internal/engagement/gate` is the one place an HTTP request, an API call or a DNS query
for a web, domain or SaaS asset is sent, as `runner.Runner.Run` is for host commands. A
host's name is resolved by its SSH transport and audited on the host's dial line, and
the address it dials is refused before the connection opens when an exclude covers it
in any form ("Addresses"), as is a jump host's. Through a jump host the hop resolves
the host's name, so scheck never sees that address: a host written as a name behind a
jump host is accepted only when the file has no address exclude, and refused with exit
3 otherwise, naming the fix ("write this host as its address"). Resolving the name here
would prove nothing, since split-horizon DNS is the normal case behind a bastion, and
nothing runs on a jump host to ask it. A collector describes requests,
and the gate decides whether each one is sent, sends it and hands back what may be
stored. No collector imports `net` or `net/http`, and none calls a target any other
way (`AGENTS.md`, `scripts/depcheck.sh`).

### Operations

**A collector names an operation, never a URL.** A request is `{op, asset, params}`.
The op comes from a compiled registry, the gate's equivalent of the host catalog. Each
op declares:

- its provider and literal host;
- its method and path template, with typed placeholders;
- its impact level and how a credential binds to it;
- the response content types it accepts;
- for a list, the item path, the exclusion key and the subject kind;
- the fields it keeps, and its size cap.

The gate has no "fetch this URL" call. An invariants test, like `ValidateRules`,
rejects:

- an op that leaves out any of these;
- a non-`GET` op outside the allowlist under "Methods and credentials";
- a list op over an excludable kind (repository, user, organizational unit, project)
  with no exclusion key;
- a placeholder in the URL's host or path that is not in the subject, so the subject
  admitted is the target sent to (only the query, a page or a cursor, varies outside
  it);
- a principal op or a credential exchange with any parameter, since only its asset
  scopes it.

A web op declares no subject: its subject is its URL, `url:<scheme>://<host><path>`, and
it sends no query. Every tool that leaks scope does
it through a generic client someone called "just once".

### Admission

Each request passes these checks in order. The first failure stops it and writes an
audit line:

1. The op is registered.
2. Its parameters bind to their types. Each type has a tight charset: a GitHub login or
   repository name, a DNS label, a Workspace customer id, an opaque cursor with a
   length cap.
3. The destination is classed: a target asset or a third-party source.
4. The subject falls under a root.
5. The subject is not excluded.
6. The op's level is allowed by the asset's mode.
7. For a web asset, the path is one of its entry points.
8. The level or path has the first-party evidence it needs.
9. For probe and above, the time is inside an authorization window.
10. A credential is present when the op binds one.
11. Time is left under `limits.timeout`.
12. The name is resolved, and every address passes ("Addresses").
13. The throttle admits it.
14. The audit line is written, then the request is sent.

On a resume, a request with a success on record is answered from it after step 12 and
skips steps 13 and 14 ("Resume").

The Scope stage computes and shows; the gate decides. Each decision comes from the
engagement file, whose hash is checked, and from live resolution, never from
`scope.json` or any other stage output. In 0.0.2 every kind of first-party evidence
can be derived that way: a `network` root, a `host` or `url` root, and `first_party`
confirmations in the file. How inventory evidence enters the gate is decided with
0.0.3 G2.

**In scope, per kind:**

- **GitHub.** The subject is the organization, or `owner/repo` with the owner equal to
  the organization root, compared case-folded. `/user` and the token's scopes headers
  are *principal* ops: allowed and audited, never a target. Another organization's
  repository is out of scope, including an action's source that would resolve a tag,
  so an action counts as pinned by syntax alone: a 40-hex commit SHA. Impostor commits
  from forks are *not assessed*.
- **Google Workspace.** The subject is the tenant's customer id, or `my_customer` bound
  to it. A per-user op's subject is `saas:google-workspace:<domain>/users/<key>`, placed
  as its tenant; whether the user is excluded is the excluded-subject set's to say
  ("Exclusion in responses"), so a unit exclude never covers the tenant itself. A
  per-user op on a user in an excluded unit is refused.
- **Discovered names.** A name is in scope when it sits under a domain root on a label
  boundary (`x.example.com` yes, `xexample.com` no) and under no exclude.
- **URL roots.** A `url` root holds its own path prefix, and also its origin's
  `/robots.txt` and `/.well-known/security.txt`, which sit outside a root such as
  `https://example.com/app/`; nothing else at the origin.
- **URL excludes.** These match by path segment after percent-encoding is normalized:
  `/checkout/` excludes `/check%6Fut/x` and `/checkout`, not `/checkoutx`. An intent URL
  or an `assets` entry an exclude covers fails validation. An exclude covers its site over both `https`
  and `http`, since every discovered name is read over both; ports match when each is
  its scheme's default, or when both are read on the same port, written or the
  scheme's default (`https://x/` covers `http://x:443/`).
- **Address excludes.** An address is excluded by a `network` exclude holding it, or a
  `host` exclude written as that address, on every port: SSH and web alike. A `host`
  exclude written as a name likewise covers that name on every port. Addresses are
  compared in every form: an exclude written inside NAT64 (64:ff9b::/96) or 6to4
  (2002::/16) also holds the IPv4 addresses it carries, one holding the whole of
  either prefix (`::/0`, `2000::/3`) holds every IPv4 address, and an address written in
  either form is held by an exclude of the IPv4 address it carries. An IPv6 zone
  (`%en0`) names an interface, not a machine, and is dropped before any comparison. A
  `network` root holds an address in either form too: one written inside NAT64 or 6to4
  holds the IPv6 addresses written in it. Validation applies
  the same test to roots (a `network` root included), `assets` entries and jump hosts,
  and refuses an address or network inside RFC 8215's local-use prefix
  (64:ff9b:1::/48), which the gate never contacts.
- **Organizational unit excludes.** These match by path segment: `/Board` excludes
  `/Board/Sub` and not `/Boardroom`.

**Levels in 0.0.2.** Only passive and observe are admitted, whatever a registry
defines. A discovered name without first-party evidence gets two reads and nothing
more: `GET https://name/`, whose TLS handshake on 443 is the name's certificate read,
and `GET http://name/`. It gets no
`robots.txt` or `.well-known`. A first-party `url` root gets its entry points,
`/robots.txt` and `/.well-known/security.txt`: a fixed list, not "any `.well-known`". A
discovered name with first-party evidence has `/` as its entry point and reads
`/robots.txt` and `/.well-known/security.txt` like a `url` root. From 0.0.2 E7 both
read one redirect hop on the same host ("Connections"). There are no other ports, no query strings and no `HEAD` fallbacks. The intent URLs on
a first-party site are entry points too; on a name without first-party evidence they
are not. Step 6 is that compiled ceiling alone: no asset's mode is read, since
validation refuses every probe and scan mode but `off`. The per-asset mode check is
built before anything raises the ceiling (probes, 0.0.3 G3). Evidence that only a `network` root holding every address can give is checked
when the gate resolves the name; a file with no `network` root has none to give, so a
request beyond the front page of a name without evidence is `refused:entry_point`, and
with one it is `refused:address_moved` when an address is outside every network root.

### Addresses

At send time the gate resolves A and AAAA for the name as a fully qualified name with a
trailing dot, so no search domain is ever appended. It checks **every** address in the
answer, not only the one it will dial:

- **A CNAME chain that enters a name an exclude covers** ("Discovery", step 3: a
  `domain`, `host` or site-root `url` exclude) refuses the name as `refused:excluded`;
  the gate sends no query of its own for the excluded name, nor for a chain hop that is
  not a valid DNS name.
- **An address in an excluded network** refuses the whole name as
  `refused:address_excluded`. An exclude is compared with both forms of an
  IPv4-mapped, NAT64 or 6to4 address: the IPv6 address and the IPv4 address it carries.
  One function reads these embeddings (`gate.Forms`, `gate.Carried`) for the gate, the
  engagement's excludes and the SSH transport's check alike. Coverage shows `excluded_by_operator` with the exclude
  entry.
- **A special-purpose address** is `refused:address_not_public` unless it is inside a
  declared `network` root. These are loopback, RFC 1918, CGNAT (100.64.0.0/10),
  link-local, unique local and multicast addresses, IPv4-mapped IPv6, and
  the IPv4 address embedded in NAT64 (64:ff9b::/96) or 6to4.
- **Never admitted, whatever the roots:** loopback, unspecified (dialling 0.0.0.0
  reaches this machine), link-local and cloud metadata
  addresses (169.254.0.0/16, fd00:ec2::254, and 100.100.100.200 inside the CGNAT range a
  network root may cover), and RFC 8215's local-use NAT64 prefix (64:ff9b:1::/48),
  whose embedding scheme scheck does not read.
- **An address that lost the first-party evidence** the Scope stage recorded is
  `refused:address_moved`: a network root no longer holds every address, or a
  confirmed name's CNAME chain or addresses no longer match its `target`.

The gate dials the checked address itself and sends SNI and `Host` from the name. It
tries addresses one at a time in a fixed order, with no happy eyeballs. scheck runs in
CI on cloud machines, where a taken-over CNAME pointed at 169.254.169.254 would put the
runner's own metadata, and its credentials, into evidence. That is the threat this
rule exists for, more than drift into an excluded range.

Tests inject a resolver, a dialer and the roots TLS verifies against through the gate's
`Net` seams. No flag or file reaches them, and a test asserts that no non-test file
outside the gate names them. Special-purpose addresses stay refused under every seam:
a test reaches its fake server through a dialer that maps a public test address to it,
never by admitting loopback.

### Connections

- **Redirects are never followed automatically.** A 3xx is evidence: its status and its
  `Location`, its userinfo, query components and fragment replaced by markers. A
  collector may ask for the next hop as a new request, admitted from step 1, at most
  three hops deep, each audited with `redirect_of`. The gate keeps where each 3xx it
  received pointed: a hop that names no such 3xx for the same asset, or goes anywhere
  but where it pointed (compared without query or fragment, its path's escaping
  normalized as a bound URL path's is), is `refused:redirect`,
  and a fourth hop is `refused:redirect_depth`. A hop out of scope is
  `unavailable:redirect_out_of_scope`, which is what an SSO login or a storefront on
  its provider's domain looks like; an excluded one stays `excluded_by_operator`. A hop
  to a page of the same site that is not one of its entry points (`/` → `/en/`, the
  commonest redirect there is) is `unavailable:redirect_not_entry_point`: the 3xx is
  the evidence. On a declared or first-party site (a `url` root, a `url` asset entry,
  or a name with first-party evidence), the web collector reads one hop (0.0.2 E7):
  only from a 3xx the gate kept, to the same scheme, host and port or from `http` to
  `https` on the same host, its path checked against the excludes. A hop to another
  name is not admitted; that name is read on its own if discovery found it. The page
  reached is evidence for that origin's rules, never an entry point anything derives
  from. A name without first-party evidence gets no hop, and a hop after that one is
  `unavailable:redirect_not_entry_point`. An API
  redirect is followed only to the op's declared host. Pagination `Link` URLs are never
  used verbatim: the gate parses the typed cursor and rebuilds the request from the
  template. A collector never passes a cursor: it asks for the next page by the id of
  the page before (`next_of`), repeating that page's parameters, and the gate fills in
  the cursor it kept. A cursor passed, an invented or spent `next_of`, one already
  being read, or changed parameters are `refused:bind`. A page's cursor is spent once
  the page after it is kept. A paged list declares its page limit.
- **TLS** is verified against the system roots, version 1.2 or later, by Go's own
  verifier on every platform. On macOS the gate reads the roots the system bundles in
  `/etc/ssl/cert.pem` into its own pool rather than hand verification to the operating
  system, which fetches a missing intermediate from the certificate's AIA URL: a
  request no admission, exclude or audit line sees. A root installed only in the macOS
  keychain (an MDM's, a TLS-interception product's) therefore does not verify there.
  Elsewhere the gate uses the system pool, read from files. When no root can be read,
  or the pool read is empty (Go returns an empty pool, and no error, on Linux when no
  bundle exists), the gate has no roots on any platform: every certificate fails to
  verify, each failure is classed `unclassified`, so the certificate rules abstain, and
  the report notes "scheck could not read the system's root certificates, so no
  certificate verified and none was judged". There is no custom CA and no client
  certificate, and `InsecureSkipVerify` appears in no non-test file, which
  `scripts/depcheck.sh` checks.
  The gate completes every TLS handshake itself, for an op whose method is `TLS` (the
  handshake and nothing after it, which no collector declares in 0.0.2) and as the HTTP
  transport's TLS dialer, with the same settings: TLS 1.2 minimum, the gate's roots, ALPN
  `h2` and `http/1.1`, and the TLS timeout ("Throttle, timeouts and retries"). The chain
  and the verification result are recorded on the response, an `unavailable:tls_invalid`,
  `tls_handshake` or `tls_refused` one included, so a name's `GET https://name/` is its
  certificate read; a failed verification aborts the handshake
  before any HTTP byte is sent. A failed verification carries a typed class beside the error's text,
  since the certificate rules read the class
  ([web-collector.md](web-collector.md#tls-and-certificate)): `expired` (past the
  certificate's `NotAfter`), `hostname_mismatch`, `missing_intermediate` (the server
  sent one certificate, not self-signed, that names where its issuer's certificate is
  published; scheck fetches nothing), `untrusted_issuer` (any other chain no trusted
  root signs, a self-signed one included), or `unclassified` (a certificate not yet
  valid among them). An expired, self-signed or mismatched certificate is a finding,
  and the name's headers are `unavailable:tls_invalid`. A chain counts with an alert
  only when the handshake completed, which proves the server holds its certificate's
  key (its signature over the handshake, then its Finished). A verified chain alone is
  not enough, since Go verifies the chain before that proof, and neither is the server
  asking for a client certificate: at TLS 1.2 it may skip its signed ServerKeyExchange
  and go straight to CertificateRequest. A handshake the server ends with a TLS alert
  before it completed, or in which the server chooses a version below 1.2 (scheck
  answers with its own `protocol_version` alert), is `unavailable:tls_handshake`, with
  the alert's name: `protocol_version`, `handshake_failure`, `bad_certificate`,
  `illegal_parameter`, `insufficient_security`, `internal_error`, `unrecognized_name`,
  `no_application_protocol`, `certificate_required`, or `alert` for another; no chain
  is kept and nothing counts as verified. It is never retried at a lower version. That
  includes a server that requires a client certificate at TLS 1.2 (`handshake_failure`
  from Go's server) and a server replaying a valid certificate it holds no key for. The
  gate sends no client certificate, only the empty one a client without one sends. An
  alert after the handshake completed and before any response was read comes from a
  server that requires a client certificate at TLS 1.3 (`certificate_required` arrives
  on the first read), or from any TLS 1.3 server that ends the connection then. The
  server answered, so its verified chain is kept with the alert recorded: a `TLS` op is
  a success (it ends before the alert arrives, so none is recorded), and an HTTP read is `unavailable:tls_refused`, nothing read. An alert
  after a response was read is a transport error ("Outcomes"), and the response is
  kept. A chain from an issuer on
  the versioned TLS-interception list (0.0.2 E7 step 4) means the operator's network inspects TLS:
  the certificate rules abstain. Reading a bad certificate needs no bypass.
- **Collector provenance.** E7 step 4 retains the gate's first-party admission decision,
  actual response collection time and redaction detector hits beside a page. A reused
  response retains that collection time across resume. Marker
  text alone is not proof that the gate found a secret. A refused TCP connection is
  typed `unavailable:connection_refused`; the HTTP rule may distinguish it from a
  timeout without inspecting error text.
- **No proxy in 0.0.2.** The gate ignores `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`, and
  prints a note when one is set. A proxy resolves names itself, which defeats
  "Addresses", and it sees every URL. A later proxy would be a flag recorded as `via`,
  with `CONNECT` to the checked address, never to a name.
- **The User-Agent is honest:** `scheck/<version> (security self-assessment)`, never a
  browser's. Abuse desks read it. A firewall that blocks it is a coverage gap,
  `unavailable:blocked`, which E7's web collector decides from the page it is served:
  a status of 403, 429 or 503 **and** a body marker from a versioned list of block
  pages (Cloudflare, Akamai, Imperva, Sucuri, AWS WAF, Vercel's checkpoint;
  [web-collector.md](web-collector.md#facts-not-findings)). Every rule over that
  response abstains, and the exit code does not change. The gate alone cannot tell a
  block page from a site's own.

### Third-party sources

Each source is a family of ops with its own literal host:

| Source | Host | What leaves the machine |
|---|---|---|
| Certificate transparency | `crt.sh` | each declared domain root, once |
| DNS resolver | the system's, recorded by address | every name queried |
| GitHub | `api.github.com` | the organization name, repository names, the token |
| Google | `admin.googleapis.com`, `oauth2.googleapis.com` | the customer id, user ids, the credential |

A query to a source names only an in-scope root or asset. Following a CNAME chain is
part of resolving the in-scope name; a standalone lookup of a name outside every root
is refused, except the control queries under `invalid.` ("Discovery"), the literal
hosts of the sources in this table, which the gate resolves to reach them, and the
names the company's own records point at ("Follow-ups" below), resolved as a CNAME
chain is followed: A and AAAA of its MX and NS targets, and TXT of the targets of its SPF
`include:` and `redirect=`, within SPF's budget of 10 DNS-querying terms per
evaluation, counted across the whole tree as RFC 7208 §4.6.4 counts them (`a`, `mx`,
`ptr` and `exists` are counted and never resolved;
[web-collector.md](web-collector.md#reads)). Those names are recorded, never contacted. An SOA lookup of a dangling target's
registrable domain, which would tell whether anyone can register it, is 0.0.3. Certificate
transparency results outside every root are recorded as "outside every root" and never
contacted, and excluded names in them are dropped and counted.

**Certificate transparency.** The op sends `q=%.<root>&output=json&deduplicate=Y` and
keeps only `name_value` and `not_after`. Before anything is stored, the gate splits
`name_value` on newlines, lowercases each entry, strips a trailing dot and keeps only
valid DNS names (letters, digits and hyphens, or punycode, with an optional leading
`*.`). Anything else, email identities from S/MIME certificates included, is dropped
and counted, never stored; a name is counted once per rule however many certificates
carry it. If `crt.sh` fails after its retries, times out, or answers
past the op's size cap (never parsed cut), that root's discovery is
`unavailable:ct_source`, and the gap text names it: the domain row is *checked in part*, the
dangling-record rule over the root is never disproved and counts "at least", and resume
retries it. The exit code does not change, as for `server_error`: `crt.sh` is down
often enough that exit 2 would teach pipelines to ignore exit 2. A second CT service is
not added; the real fix is the zone itself (Cloud DNS in 0.0.3 G2).

**The resolver.** The gate sends its own DNS queries, to the first `nameserver` in the
system's `/etc/resolv.conf`, recorded by address, for discovery and for every request it
sends. It reads rcodes and CNAME chains, which the system's lookup functions hide, and
the resolver it names is the one it asked. A pinned public resolver would hide what the
operator's network sees. Queries are for fully qualified names with a trailing dot, so
no search domain is appended, over UDP with TCP on a truncated answer, 5 s each. It
asks for A, AAAA, CNAME, TXT, MX and NS. A TXT record is kept as one value, its strings
joined with no separator (RFC 7208 §3.3), as a rule reads it; an MX record is its
preference and its target, a null MX's target empty. A name is one of three types. A
host name, which discovery resolves and a request is sent to, takes no underscore. A
name scheck builds from the engagement file to read its records is a host name with
`_dmarc` as its first label (`_dmarc.<d>`) or one `_domainkey` label after a DKIM
selector (`<sel>._domainkey.<d>`); a selector follows RFC 6376's sub-domain syntax with
no underscore, at most 63 characters a label, written in either case, and the name built
from it is lowercase. A name read from an answer (a CNAME hop, an MX or NS target, an
SPF `include:` or `redirect=`) may hold underscore labels
anywhere, within the gate's length and charset checks (`_spf.google.com`). A label
holding a dot byte, which joined with dots would read as another name, makes the whole
answer unreadable: the lookup's outcome is `error`. With
no nameserver there, a lookup is `unavailable:no_resolver`: not sent, not counted. On
macOS, `/etc/resolv.conf` names only the primary resolver: per-interface (VPN)
resolvers are not used, the report says so, and, once a run declares its vantage, a
run with `vantage: vpn` on macOS warns at its start. Discovery from the public view is also the attacker's view, which
is the right one for takeover. A host's SSH transport resolves its name with the
system's own lookup, outside this client, as it does a jump host's; the report names
both when written as names, and names the hosts a jump host resolved instead. A name in
an answer that `redact_extra` matches is redacted where a lookup leaves the gate, in
`scope.json`, the report and the audit log alike. The lookup's own name is redacted
too, including on a refusal; changing it makes a sent lookup's outcome `error`.
Discovery keeps only that redacted name. A marked wildcard control is insufficient
evidence and never becomes an HTTP host or front-page read. The gate decides on the names as
answered (an exclude in the chain, the service a name points at, whether a dangling
target is under a root, whether a confirmation's target still holds) and redacts them
only where the lookup leaves it, so what discovery records is the gate's verdict; the
audit log's answers are redacted name by name and address by address, as the gate
judges them, so an anchored pattern matches there too. A name from certificate
transparency that `redact_extra` matches, in the answer as a whole, or on its own as
written, lowercased or without its leading `*.`, is dropped and counted (`redacted`), never stored with a marker; a record
whose names are missing or not a string is counted `unattributable`: a marker kept as a name would become
a request target. Like any drop, it leaves the root's population incomplete. A confirmation's `target` is
compared as written and redacted in `scope.json` like the chain beside it. An address
`redact_extra` matches can be neither dialled nor recorded: its lookup is
`insufficient evidence`, and a request to it, by name or as written, is
`unavailable:dns_error`. The resolver's own address, and what the SSH transport quotes
in an error (an address a name resolved to, a jump host's refusal), are redacted the
same way. When the vantage is `vpn` or `lan`, the
report notes that split-horizon answers may differ from the internet's.

**Records reads** (0.0.2 E7 step 1b). A records read asks TXT, MX or NS at a name scheck
builds from the engagement file: TXT at a domain, at `_dmarc.<d>` or at
`<sel>._domainkey.<d>`, MX or NS at a domain ([web-collector.md](web-collector.md#reads)).
It is admitted as a discovery lookup is: the name binds to its type, falls under the
asset's root and under no exclude, time is left under `limits.timeout`, and a nameserver
is there to ask (`unavailable:no_resolver` otherwise). The engagement places a name with
underscore labels by its labels, so `_dmarc.<root>` is under the root and an exclude
covering the domain covers it. The gate follows the CNAME chain as an address lookup
does, a DKIM selector's CNAME to its sending service among them, with the same hop
limit, the same stop at an excluded name and the same CNAME query at the chain's end
("Discovery"). The outcome is `records`, `nxdomain`, `nodata` or a failure, which is
*insufficient evidence*, and the result says whether the name the chain ends at is
under a root. Names in the result, the chain and MX and NS targets, are
redacted as a lookup's are. A TXT record's strings are joined first and the joined
value redacted once, so a value split across two strings is redacted whole and no
marker is redacted again. An MX or NS
target that is not a name ends the read as `error`.

**Follow-ups** (0.0.2 E7 step 2a). A records read's result lists the names its answer
points at, redacted, each with how: an MX target (a null MX has none), an NS target, or
the target of an `include:` or `redirect=` term of a `v=spf1` TXT record, read from the
record as answered; a term whose target is a macro or not a name has none. A TXT answer
points at SPF targets only when it is a domain's own TXT read or an `include:` or
`redirect=` follow-up, never at `_dmarc.<d>` or a DKIM selector, and only when it holds exactly one `v=spf1` record:
with two, SPF is broken and nothing is followed. The
collector asks for one by the request id of the read and the target's index in its
answer, never by name: a target of an answer the gate gave for the same asset, each
once, or `refused:bind`. The gate looks the name up as answered, outside every root if
that is where it is; an exclude covering it refuses it unasked (`refused:excluded`),
and `limits.timeout` and a missing nameserver stop it as they stop a records read. An
MX or NS target gets A and AAAA, its CNAME chain followed. An `include:` or `redirect=`
target gets TXT, and its own targets belong to the same SPF evaluation. An evaluation
begins at a domain's own TXT read and is one per asset and domain, so reading the
domain's TXT again does not renew it; the gate sends at most 10 `include:` and
`redirect=` reads per evaluation, whatever the collector counts, and refuses the next
(`refused:spf_budget`). The collector counts SPF's budget itself, over every
DNS-querying term ([web-collector.md](web-collector.md#reads)), and the gate's cap
holds whether it does or not. In E7 step 3 the collector narrows these reads to
syntactically valid SPF records and terms before the first `all`, ignoring `redirect`
when `all` is present; the gate's admitted surface and independent cap do not change.
Email rules consume only collected evidence, including organizational-domain DMARC
records collected under another root; they send no additional lookup. Each follow-up's
result, like a records read's, says
whether the name its chain ends at is under a root.

The report prints what left the machine as one fixed block (`engagement.md`, "The
report").

### Methods and credentials

**Methods.** Only `GET` and `HEAD`. The one exception is a `POST` to a declared token
endpoint (`oauth2.googleapis.com/token`), op class `credential_exchange`. The
credential source builds its body, its response never enters the evidence path, and it
is audited with its status only. There is no GraphQL in 0.0.2. From 0.0.3 a read-only
`POST` (GCP `testIamPermissions`) is a reviewed registry entry with a literal body
template and a cited provider document, and the invariants test enforces it. Until
the Workspace collector builds its credential source (0.0.2 E6), the gate refuses a
credential exchange as `refused:method`.

**How credentials attach.** The gate attaches a credential by the op's binding, after
admission; a collector never holds one. A request to a web asset never carries an
`Authorization` header.

**Where credentials come from:**

- **GitHub:** `GITHUB_TOKEN` or `GH_TOKEN` only. Running `gh auth token` would start a
  process outside every enforcement point, so scheck prints it as a hint instead.
- **Google Workspace:** an application default credentials file or a service-account
  JSON named by the environment.
- **Never a fragment of a token.** A value shorter than 20 characters is refused as
  `no_credentials`: no GitHub token is that short, and redacting it by value would
  mangle every response.
- **Never in a URL.** An endpoint that takes a token only in the query string
  (tokeninfo) is not called, and the permissions are `unknown`.

**The credential is redacted by value.** The gate adds the credential's exact value as a
redaction rule (`credential`) for every body, header and error string from that
provider, including Go error text, which embeds URLs.

**A token with write access is not refused.** The gate reads `X-OAuth-Scopes`, the
collector files the broad-grant finding, and the run warns at the start. Most small
teams will use the token they already have: refusing it ends the engagement, while
reporting it fixes something.

### Responses

A response goes through these steps in order, and nothing is stored before the last:

1. **Read** up to the op's cap plus 4 KiB, the host runner's redaction slack, so a
   secret straddling the cap is whole when it is redacted. Only `gzip` is accepted
   (`Accept-Encoding: gzip`); any other encoding is
   `unavailable:unexpected_content_encoding`. Decompressed bytes are capped, and so are
   compressed ones. A body that decompresses past the cap at more than 100 times the
   compressed bytes it took is a compression bomb, `unavailable:compression_bomb`; one
   that merely runs past the cap is cut like any other. A corrupt stream is
   `unavailable:malformed_response`. A body the server stops sending (a reset,
   `limits.timeout`) is never a read: the status and headers are kept, the partial
   body is not, and it is not retried.
2. **Check the content type** against the op: the same type, a wildcard the op
   declares, or JSON for JSON (GitHub answers `application/json` to
   `application/vnd.github+json`); an op that declares `*/*` takes any body, one with
   no `Content-Type` too. A body of another type is hashed, not kept. On a 2xx that is
   `unavailable:unexpected_content_type`; on any other status the status decides, so
   a `robots.txt` 404 served as an HTML page is a 404.
3. **Redact the raw bytes:** the compiled rules, the credential's value and
   `redact_extra`. A JSON body is redacted value by value: every string, key and number
   is redacted as text with its escapes decoded, and written back encoded. Redacted as
   one text, a span could start in one string and end in a later one, and the result
   could still parse with every item between them gone, an excluded user among them.
   Value by value, no span crosses a string, and an escape (`\n` before a token, `\/`
   inside one) cannot hide a secret. Under a key that looks secret (`json-secret`),
   every scalar is redacted whole, in an array too; a narrower rule's marker stands
   only when one hit covered the whole value. Under such a key, only these stay as they
   are: the literals `true`, `false` and `null`, the empty string `""`, and `0` or `1`,
   as a number or a string. Every other value is redacted whole, words included:
   `"yes"`, `"no"`, `"none"`, `"x"`, `"*"` and `"required"` alike. JSON spells a
   setting as a literal or a number, so a word under a secret-shaped key is a value
   someone chose, and a value someone chose for `password` may be the password. The
   longer list host output keeps after such a key (`PermitEmptyPasswords no`,
   [host-collector.md §4](host-collector.md)) is the host collector's own. An API's
   error body that is JSON is redacted value by value too, so the same body reveals
   no more as an error than as a success; one from a JSON op that is not one JSON
   document (a byte-order mark, two documents, a proxy's HTML) is kept only as its
   hash, as a malformed 2xx is, and its status still decides. An object under such a key is read
   member by member (`"secret_scanning": {"status": …}` is configuration). A number a
   rule matches becomes a string holding its marker. Two keys redacted to the same
   marker stay two members, of which a decoder keeps one; a secret-shaped key is rare
   enough that scheck accepts this rather than invent markers. A body that is not one
   JSON document is `unavailable:malformed_response`, and nothing is read from it.
4. **Parse the redacted bytes**, never the pre-redaction ones. If they do not parse,
   which value-by-value redaction rules out, the result is
   `unavailable:redaction_broke_structure`. Only a 2xx is parsed: an API's error body
   is kept as redacted text, cut at the cap, for the status to be read with. A 2xx
   with no body (a 204) is kept as its status, which is the evidence for an endpoint
   that answers "enabled" with 204 and "disabled" with 404; a list always has a
   body.
5. **Drop excluded items** ("Exclusion in responses").
6. **Project** to the op's declared fields, dotted paths through objects and arrays.
   A field the response lacks stays absent, which a rule reads as unknown; `null` is
   kept. A list's body is the array of its kept items.
7. **Cut text** with `[TRUNCATED:<n bytes>]`, `<n>+` when the read stopped before the
   end, never inside a redaction marker, by the same code as the host runner. JSON over
   its cap is never parsed cut and not kept; its status and headers still decide the
   outcome (a 401, a rate limit), and only a success too large to keep is
   `unavailable:response_too_large`.
8. **Store**, and hash the redacted body for the audit line.

**Headers kept.** Everything else is dropped and counted:

- `content-type`, `location` (query values redacted), `server`, `x-powered-by`;
- the six security headers: HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy`, `Permissions-Policy`;
- `set-cookie` as its name and attributes, never its value;
- certificate fields (subjects, issuers, names, the verification error), which are
  target-derived and redacted like a body;
- rate-limit headers and `retry-after`;
- `x-oauth-scopes`, `x-accepted-oauth-scopes`, `github-authentication-token-expiration`,
  and `x-github-sso` with its URL's query redacted.

**The compiled redaction rules grow in E4**, for host output as well:

- a key/value rule that matches JSON (`{"access_token": "…"}`), which the `kv-secret`
  rule misses because a closing quote sits between the key and the colon. It redacts
  inside the quotes in text, and is applied per member to a JSON body. A key that only
  looks secret keeps its value: one ending `_url`, `_uri`, `_type`, `_enabled` or
  `_at`, and a page token, which the gate reads its next cursor from. `kv-secret`
  itself is unchanged, so host output is redacted at least as before;
- Google token shapes (`ya29.`, `1//`, `AIza`, `GOCSPX-`), Stripe (`sk_live_`,
  `rk_live_`), npm (`npm_`) and Slack webhook URLs (the path after the kind; the
  host stays, since a webhook's existence is evidence). The engagement file's
  credential detector refuses the same shapes;
- a property test that redacted JSON still parses and keeps its keys and array
  lengths, over generated documents with secrets in members, URLs and prose, split
  across strings and behind escapes.

The recorded host fixtures hold none of these shapes, so no host golden changed; a
runner test seeds them in a command's output.

**Exclusion in responses fails closed:**

- A list item is dropped by the op's exclusion key before projection: a repository's
  `owner/name` checked against the excludes, a user's or a unit's unit path matched by
  segment (`/Board` holds `/board/Sub`, case-insensitively, and not `/Boardroom`). An
  item that falls under no root of the request's asset is dropped as `out_of_scope`.
  The audit line records `dropped: [{rule: "exclude[i]", count}]`, never the names.
- For an excluded organizational unit, the gate builds an excluded-subject set (user
  ids and addresses) from the users list; with no unit excluded there is no set, and
  the users list excludes no one. Every later op with a user-reference key
  drops by that set: role assignments, group members, tokens. A per-user op (a user
  key in its URL) on a user in the set is `refused:excluded`. A user with no unit
  joins the set too, since its unit may be excluded. Every key of a dropped user is
  excluded, its contact addresses too. The set also records every user the list
  returned and the tenant's domains: the domain in the tenant's asset id, and those
  read from the fields that identify a user inside the tenant (id, primary address,
  aliases), never from a contact address a user put on file. An id, or an address in one of those domains, that the list never
  returned is unattributable: a user hidden from the principal may be an excluded
  one. An address in another domain stays: an
  external group member is evidence, not an excluded person. A reference that is
  neither a user id nor an address is dropped as unattributable too.
- One op per provider builds the set, and it reads the whole tenant: its cursor and at
  most one page size, each once and under the provider's own key for it (Google's
  `pageToken` and `maxResults`), and no other query but a literal customer, so a
  filtered list (`isAdmin=true`, or a filter dressed as a cursor or a page size) can
  never replace the set with a partial one. The registry refuses a second builder.
- The set is known when no organizational unit is excluded under the tenant, or once
  a users list was read whole, every page through the last. Half a list is not a set.
  Until it is known, an op that names or lists users is not sent:
  `unavailable:exclusion_unknown`, never stored unfiltered. A users list that failed
  or stopped at its page limit leaves it unknown, and so does one that returned no
  user at all while a unit is excluded: it tells no excluded user apart from a kept
  one.
- An item without its key is dropped and counted as unattributable.
- Excluded people can still appear by GitHub login in other objects when nothing maps
  them. The Identity and access row says so, and it is at most *partial* ("What is in
  scope").

**An incomplete population proves presence, never absence.** A list cut by a cap, a
page limit or a drop can still let a rule fire on an instance it saw: one admin without
two-step verification is real. It never lets a rule be disproved, and a count from it is
a lower bound ("at least 4 super admins"). This is how "we read two pages" most often
becomes "no issue". Each list page carries its population: the items it held and kept,
the drops by rule, and what makes it incomplete (`dropped`, `page_limit`, or
`next_page_unreadable` when the provider's next cursor did not bind). A JSON page over
its cap is not kept at all, so the list it belongs to is incomplete too.

### Throttle, timeouts and retries

**Defaults per provider.** These are compiled ceilings. A throttle in the engagement
file only lowers them.

| Provider | Concurrency | Rate | Other |
|---|---|---|---|
| GitHub | 1 | 10/s | stops when remaining falls below max(100, 20% of the limit) |
| Google Admin SDK | 2 | 5/s | |
| `crt.sh` | 1 | 1/s | 60 s timeout |
| DNS | | 20 queries/s | 5 s timeout, TCP on a truncated answer |
| Web assets | the asset's throttle (default 5/s, 2) | | plus a ceiling of 5/s per address, across assets, since CDNs share addresses |

GitHub asks for serial requests, and the token is often a person's, shared with their
CI, so scheck stops with a fifth of it left rather than starve it. A request waits for
its provider's ceiling and, when its asset sets a throttle of its own, for that too, so
one organization's lower throttle never binds another's. It takes the asset's throttle
first, so a slow asset never holds the provider's slot while it waits. A SaaS asset's own throttle is
only what its `assets` entry sets, a rate, a concurrency or both, never the defaults;
the asset a request names is its canonical id, so one asset has one throttle.

**Per request:** dial 10 s, TLS 10 s, headers 20 s, total 30 s. Each is cut to what is
left of `limits.timeout`, the engagement's only deadline. When the deadline passes, the
request in flight is cancelled and the rest are `refused:deadline`, never sent.

**Retries** apply to idempotent requests only, on 429, 502, 503, 504, or a connection
reset before the response:

- up to three retries, after 1, 4 and 16 s, each jittered by up to a fifth and each
  admitted again from step 1;
- `Retry-After` honoured up to 300 s, and only if it ends before the deadline;
- a rate limit that holds through every retry, or asks for a longer wait, stops that
  provider with `limit_reached`, and the run exits 2;
- a retry whose wait would pass `limits.timeout` is `refused:deadline` with its own
  audit line, and stops the provider only when it was a rate limit;
- a web site is retried the same way, but its status is what the site serves: a 429,
  502, 503 or 504 left after the retries, or after a `Retry-After` longer than 300 s,
  is kept as evidence of that page, never a failed read, and stops no provider.

**Status codes that mislead:**

- A GitHub 403 with `x-ratelimit-remaining: 0`, and a Google 403 with reason
  `rateLimitExceeded` or `userRateLimitExceeded`, are rate limits, not permission
  errors.
- A GitHub 404 on a subject known to exist is `insufficient_permission`, never "not
  configured".
- A 403 with `X-GitHub-SSO: required` is `insufficient_permission:sso_authorization`,
  and its detail says to authorize the token for SAML single sign-on.
- A server error left after the retries is `unavailable:server_error`: coverage is
  *partial*, the request is retried on resume, and the exit code does not change.

Branch protection is read through `branches/{branch}` (`protected`) and
`rules/branches/{branch}`, which need no admin. The protection endpoint's 404 cannot
tell "unprotected" from "not allowed".

### Audit

The gate writes JSONL lines into `audit.jsonl`, beside the host lines, each with an
`event`: `send`, written **before** the dial with `decision: sent`; `result`, keyed to
it by `request_id`; `refused`, the one line of a request admission stopped; `reused`, the
one line of a request a resume answered from the earlier run's success, with `decision:
reused`, its `status` and the stored body's `output_sha256` ("Resume"); and `dns` and
`dns_answer`, a query's line before it is sent and its answers after. A DNS lookup
admission stops is one `refused` line with op `dns.lookup` for discovery,
`dns.records` for a records read or `dns.follow` for a follow-up, whose `params` are
`from` and `index` and, once bound, the target's `name` and `via` (`mx`, `ns`,
`include` or `redirect`); one it sends is the `dns` and `dns_answer` lines of its
queries, under its `request_id`. A `dns` line's `params` are the `name` and its
`type` (`A`, `AAAA`, `CNAME`, `TXT`, `MX` or `NS`). A `dns_answer` line's `answers`
hold one record each: `<name> <address>`, `<name> CNAME <target>`, `<name> NS
<target>`, `<name> MX <preference> <target>`, or `<name> TXT "<record>"`, each name
and address redacted on its own, and a TXT record joined and redacted as a records read
keeps it ("Third-party sources"), quoted as one string. The line does not redact its
answers again as a whole, which would redact their markers. A send line that
cannot be written stops the request (`unavailable:audit_failed`), and a gate cannot be
built without an audit log. "Did scheck send this at 14:03?" must have an answer even if
scheck crashed mid-request.

Fields:

- `time`, `request_id`, `stage`, `asset`, `op`;
- `params`, bound and redacted;
- `method`, and `url` as scheme, host and path, with query values redacted except
  declared typed parameters;
- `dest_ip`, `port`, `level`, and `tls`: the version, `invalid` for a failed
  verification, or `alert:<name>` for a TLS alert the server ended with, before or
  after the handshake completed ("Connections");
- `principal`: the login or service-account address, never the credential;
- `window`: for probe and above, the index into `authorization.windows` of the window
  the request was admitted in;
- `source` for a third party, or `via`;
- `decision`: `sent`, `reused`, `refused:<rule>` or `unavailable:<code>`, with a
  redacted `detail`. The rules, in admission order: `unknown_op`, `bind`, `method`,
  `redirect`, `redirect_depth`, `spf_budget` (a follow-up past SPF's budget,
  "Third-party sources"), `out_of_scope`, `excluded`, `level`, `entry_point`,
  `window` (checked again after the throttle wait), `no_credentials`, `deadline`,
  `rate_limit`, `address_excluded`, `address_not_public`, `address_moved`, `canceled`
  (the run was cancelled while the request waited for its throttle or its retry). A
  request or a DNS lookup cut in flight by `limits.timeout` is `unavailable:deadline`,
  and a request cut in flight by its window's end is `unavailable:window_ended`, both
  with the coverage reason `limit_reached`;
- `status`, `attempt`, `retry_of`, `redirect_of`, `next_of` and `page` for a list's
  later pages;
- `bytes_in`, `bytes_stored`, `output_sha256` (of the redacted body), `redactions`,
  `truncated`, `dropped`, `headers_dropped`, `duration_ms`.

The gate's audit log is never optional. It is the record of what scheck sent, to
whom and when, and only a run directory keeps it: a run whose roots or assets include
anything but hosts (a domain, url, network, SaaS, repository or cloud root, or such an
asset, a url under a host root among them, whether or not its collector is built yet)
is refused under `--no-persist` with exit 3 before any contact, naming `--state-dir` for a run kept somewhere disposable. A host run keeps
`--no-persist`, since its command trace travels in the report. The gate refuses to be
built on a log that keeps nothing (`io.Discard`), and a line that cannot be written
stops the request or lookup before it is sent.

### Outcomes

| Outcome | Coverage reason | Exit |
|---|---|---|
| A credential present but rejected (401, invalid grant) | `refused`, kind `access` | 3, and the other assets are still collected, as for a failed SSH login |
| No credential for a declared SaaS root | `no_credentials` | 2, the root unassessed. A warning before any contact lets the operator stop |
| An address excluded | `excluded_by_operator` | no change |
| An address that lost the first-party evidence Scope recorded (`refused:address_moved`) | `unavailable:address_moved` | no change; the next Scope run shows the asset without it |
| An address not public, a redirect out of scope or off the entry points, an invalid certificate, a handshake the server ended with a TLS alert, a TLS alert after the handshake completed and before any response (`unavailable:tls_invalid`, `unavailable:tls_handshake`, `unavailable:tls_refused`) | `unavailable:<code>` | no change, like `path_denied` |
| A provider rate limit, `limits.timeout`, or a request outside every authorization window or cut by its end (`refused:window`, `unavailable:window_ended`), or a run cancelled with the request in flight (`unavailable:canceled`) | `limit_reached` | 2 |
| A request that got no answer: the connection reset after its retries, a timeout, the address unreachable, or no nameserver to resolve its name (`unavailable:connection_refused`, `unavailable:connection_reset`, `unavailable:timeout`, `unavailable:unreachable`, `unavailable:no_resolver`) | `unavailable:<code>` | 2 for something declared: a `url` root or entry, the DNS of a domain root or a mail domain itself, an intent URL other than `not_exposed`. Nothing was read, so it says nothing about the target, and a rerun or a resume sends it again. A discovered name records "did not answer from this machine" and does not change the exit code; for a `not_exposed` URL read from the `internet` vantage, no answer is the evidence that disproves the contradiction (`engagement.md`, "Reachability and vantage") |
| A page served by a firewall that blocks scheck (`unavailable:blocked`, "Connections") | `unavailable:blocked` | no change; every rule over it abstains |
| `refused:unknown_op`, `out_of_scope` or `method` on a collector's request | `unavailable:refused_by_gate` | no change. It is a defect, and a collector's tests fail on any |

A refusal carries `effect: {requests_not_sent}`. Its detail names the fix: "set
`GITHUB_TOKEN` to a fine-grained, read-only token", "needs
`admin.directory.user.readonly`", "GitHub's rate limit for this token resets at 15:02
(Europe/Madrid)", the time in `engagement.timezone`.

A public name that resolves to a private address is also an informational fact for its
domain, not only a coverage gap: it tells an outsider about internal addressing.

### Resume

A request's identity is a hash of its op as this build compiled it, its asset, bound
parameters, whether its subject is known to exist (a list returned it), its principal
fingerprint and the redaction rules (the scheck version, whose compiled rules it
carries, and `redact_extra`). A changed build, op or `redact_extra` reuses nothing, so a
stored body is never one today's rules would redact differently. A build whose version
names no commit (`dev`) or carries uncommitted changes (`-dirty`) cannot be told from
another one, and reuses nothing at all. A web asset's vantage joins it when `--vantage` lands in 0.0.2 E7, and the vantage is
recorded on DNS evidence too, so a resume from another vantage reads the names again
(`engagement.md`, "Reachability and vantage"); this build has no `--vantage`. The fingerprint is a hash
of the principal's identity and sorted scopes, never of the token. A resume reuses only
a success with the same identity. Everything else is retried, and every retry is
admitted again from step 1, re-resolution and window included: a resume never replays
an earlier decision, so a request refused before is refused again under the same file.

A request with a success on record is still admitted again from step 1 through step 12,
its name resolved now and every address checked, so an address excluded since, or a name
that moved away from its first-party evidence, is refused as on a fresh run. Only then
is it answered from the record, with a `reused` audit line. It skips steps 13 and 14: no
throttle and nothing sent to the target; its lookup is counted with the resolver's
queries like any other.

Some successes are never reused, and are sent again:

- a list, and any op that names or lists users, whose answer the gate filters by the
  engagement's excludes and the users it finds now; a paginated list is read again
  whole, since cursors expire and a mixed snapshot invents or loses users;
- an authenticated request whose credential's principal is not known, since the
  credential may be another one; no principal is known until a principal op answers
  (E5);
- a redirect, since the hop after it needs the gate's own record of the 3xx;
- a web page answered with 429 or a 5xx, kept as evidence but not a page that was read;
- a records read and a follow-up ("Third-party sources"), which keep no record to
  answer from until 0.0.2 E7 step 5, whose resume after a changed `mail` or `intent`
  URL reads again only the names it affects.

A record is checked the same way when it is looked up, since a resume's records come
from stage files the operator may have edited: a redirect, a 429 or a 5xx on record is
sent again.

The successes a resume may reuse are written after each stage to
`evidence/requests/<identity>.json`, post-redaction, and listed in `run.json`;
`scheck run <directory>` hands the next session's gate only those `run.json` lists, so a
file placed there by hand is never a success on record. The gate reports which records
it reused, and the report names each one that changed since scheck wrote it
(`engagement.md`, "Stop and resume"). A resumed session's request ids carry its number,
`g<session>-<seq>` (`g2-000001`) after the first session's `g000001`, so ids stay
unique in the run's one `audit.jsonl`. A host is resumed as a unit (`engagement.md`,
"Stop and resume").

### Authorization windows

For probe and above, the time must be inside some `authorization.windows` entry, from
its `from` up to but not including its `to`. The check runs on every request, not once
per run, and again after the throttle wait; a request outside every window is
`refused:window`. A request's deadline is the earlier of 30 s and the window's end, and
the window's end cancels requests in flight as `unavailable:window_ended`. Both are
`limit_reached`, as `limits.timeout` is. The audit line records the window's index.
Passive and observe requests are never checked against windows. Validation rejects
probe modes in 0.0.2 and the gate admits nothing above observe, so the window is tested
with a test-only probe op under a ceiling only that test raises.

### Not built in 0.0.2

No generic HTTP client. No GraphQL. No proxies, custom CAs, client certificates or
"insecure" flag. No link following, crawling, sitemap parsing or JavaScript rendering.
No subdomain brute force, zone transfer or port check. No git transport and no `gh`
exec. No `confirm` preview (0.0.3 G3) and no inventory evidence (0.0.3 G2).
