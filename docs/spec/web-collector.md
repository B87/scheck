# scheck — domain, email and web collector specification

The rules of the collector for domain roots, mail domains and sites
(`internal/collector/web`, 0.0.2 E7): what it reads, what each rule fires on, is
disproved by and abstains on, its base severity, and what the report never claims.
Defined with the `security-consultant` and accepted by the user on 2026-10-09. Status:
design. It becomes contract when E7 lands ([ROADMAP.md](../ROADMAP.md)); until then it
describes the target, not the build.

What the gate admits, sends and keeps is [scope.md](scope.md) ("The scope gate"); base
severity anchors and context adjustments are [engagement.md](engagement.md) ("Severity
in context"); the report's wording when an intake answer is missing is
[engagement.md](engagement.md) ("Coverage", "A missing intake answer"). This file holds
the rules and the data they read.

## Reads

Every read goes through the gate, and the collector reads only what a rule consumes.

| Level | Read | Fields kept |
|---|---|---|
| passive | TXT at the apex | `v=spf1` records only; each record's strings concatenated (RFC 7208 §3.3); the count of SPF records |
| passive | TXT `_dmarc.<d>` | DMARC records (below); the tags `p`, `sp`, `np`, `pct`, `t`, `adkim`, `aspf`, and whether `rua` has a value |
| passive | MX `<d>` | targets and preferences; a null MX (`0 .`) |
| passive | NS `<d>` | host names |
| passive | TXT `<sel>._domainkey.<d>` for each selector declared under `mail.senders`, following its CNAME | DKIM keys (below): `v`, `k`, `p`, `t` (the rule computes the key's modulus size from `p`); the count of other records |
| passive | what Scope resolved for each name | the chain, its outcome, addresses, whether the chain ends under a root, the lookup's request id and the control label's answer, already in `scope.json` |
| passive | A and AAAA of MX and NS targets, inside a root or outside every root; TXT of the targets of SPF `include:` and `redirect=`, within SPF's budget (below) | rcode and chain: resolved and recorded, never contacted ([scope.md](scope.md#third-party-sources)) |
| observe | the TLS handshake on 443 of `GET https://name/` (below), the read name's one handshake | version, verified, the gate's typed verification class, the TLS alert the server ended with, before the handshake completed or after (the chain kept), and the chain's subjects, issuers, names and validity |
| observe | `GET https://name/` and `GET http://name/` for every read name; for a declared or first-party site also its entry points, `/robots.txt`, `/.well-known/security.txt` and one redirect hop on the same host ([scope.md](scope.md#connections)) | status, `location`, `server`, `x-powered-by`, the six security headers, `set-cookie` names and attributes, the redacted body within its cap |

The gate's DNS client reads TXT (each record its strings joined into one value, TCP when
the answer is truncated), MX and NS ([scope.md](scope.md#third-party-sources), "The
resolver"). A name scheck builds from the engagement file takes no underscore label but
`_dmarc` and `_domainkey`; a name it reads from an answer (a CNAME hop, an SPF
`include:` or `redirect=`, an MX or NS target) may hold underscore labels anywhere,
within the gate's length and charset checks (`_spf.google.com`). A DKIM selector follows
RFC 6376's sub-domain syntax, in either case, at most 63 characters a label, with no
underscore; the name built from it is lowercase.

**SPF's budget** is 10 DNS-querying terms per evaluation, counted across the whole tree
(`include`, `a`, `mx`, `ptr`, `exists`, `redirect`; RFC 7208 §4.6.4). Only `include`
and `redirect` targets are queried, as TXT; `a`, `mx`, `ptr` and `exists` are counted
and never resolved. An eleventh term fires `email.spf_invalid` and stops the evaluation.
The collector reads the tree only when the domain has exactly one `v=spf1` record, depth
first in the order its terms are written, and reads nothing more once the count passes
10; the gate sends at most 10 `include:` and `redirect=` reads per evaluation, one
evaluation per domain, whatever the collector counts
([scope.md](scope.md#third-party-sources), "Follow-ups"). The tree is complete
(`spf_complete`) when nothing in it is unknown: the domain's TXT was read, and either
it holds no single `v=spf1` record to walk or every `include:` and `redirect=` within
the budget was read. A failed read of the domain or of an include, a term whose target
the gate gave none for (a macro), or a count past 10 leaves it incomplete, and so does a
record at the domain or an include that redaction marked before anything showed it is
not SPF (the text before the marker could still begin `v=spf1`), since how many SPF
records there are is then unknown.

**DMARC records and DKIM keys.** A DMARC record is a record at `_dmarc.<d>` whose first
tag is `v` with the value exactly `DMARC1` (RFC 7489 §6.3); any other record there is
not a DMARC record and is not kept. A DKIM key is a record at a selector with a `p=` tag
and, when it has a version, `v=DKIM1` as its first tag (RFC 6376 §3.6.1); any other
record there (not a key, another version, `v` not first) is counted as `other`, not
kept. DMARC's tag names compare case-insensitively and `v`'s value exactly (`DMARC1`);
other values are kept as written, and a rule reads `p`, `sp` and `np` case-insensitively,
as RFC 7489's grammar does. DKIM's tag names are case-sensitive (RFC 6376 §3.2), and a
part of a key that is not a tag breaks its format. Whitespace is allowed around `=`. A
record in which a tag repeats, or a key whose format is broken, is invalid: it is kept as
`malformed`, without its tags. `rua` counts only when it has a value. A record a
redaction marked that may have been a DMARC record (the text before the marker could
still begin `v=DMARC1`) or, at a selector, any marked record that is not seen as a key,
is counted apart (`dmarc_marked`, a selector's `marked`), so a rule over that domain or
selector abstains on it rather than reading it as absent.

**Built in E7 step 2a:** Recon reads each domain root with `Collect`: for the root and
each mail domain under it, in that order, TXT at the domain and at `_dmarc.<d>`, MX and
its targets' addresses, the SPF include tree and each declared DKIM selector; the root's
NS and its targets' addresses; and for each name Scope marked to read, `GET /` over
https, then http (`web.front`, the collector's one op), the https read's handshake
giving the certificate and TLS result. A mail domain is read once, under the most
specific domain root that holds it, so nested roots never read it twice or give it two
SPF budgets. It keeps only the fields in the table above: no TXT record but `v=spf1`
ones at a domain and in the include tree, each DMARC record's tags and whether `rua`
has a value but never its address, each DKIM key's tags. What it read is in
`recon.json`, under the asset's `web`. Recon then judges it ("Rules", built in step
2b) and the root is `collected`. It is `limit_reached`
when `limits.timeout` ends the engagement before the root is read (`not_collected`), or
while it is: the deadline ended or refused one of its reads (`refused:deadline`,
`unavailable:deadline`, or a `limit_reached` reason on a page), or ended the engagement
as `Collect` returned (`incomplete`). A declared or first-party site's
entry points, `/robots.txt`, `/.well-known/security.txt` and its redirect hop are step
4; a `url` root is not read yet. A declared `domain` asset under a root that was read
is read with it: it is recorded with the root's status and the detail "read with
*root*", and its findings are those whose subject it holds ("Subjects").

**Not read in 0.0.2:** SOA, CAA, DNSKEY and DS, `_mta-sts`, `_smtp._tls`, BIMI.

**Which names each family judges:**

| Family | Judges |
|---|---|
| DNS, takeover, certificate | every read name |
| headers, cookies, `security.txt`, plain HTTP | declared sites only: a `url` root, a `url` asset entry, or a name with first-party evidence. Other names are listed as read, not judged, with a count |
| version disclosure, a secret in a response | every read name |

## Rules

Every rule declares what it reads and abstains when it is unknown (`AGENTS.md`, "Adding
a rule"). Bases are placed against the anchors frozen on 2026-10-09
([engagement.md](engagement.md#severity-in-context)). *Exposure* is the definition's
`exposure_finding`: whether "exposed on purpose" may move it. `web.version_disclosed` is
this collector's only exposure finding. Every `email.*`, `tls.*` and `dns.*` finding, and
`web.secret_in_response`, `web.hsts_missing`, `web.plaintext_http`, `web.plaintext_http_clients`,
`web.session_cookie_flags`, `web.security_headers` and `web.security_txt`, are
configuration findings, which it never moves; `web.restricted_reachable` is a
contradiction of a declared restriction, which is never an exposure finding
([engagement.md](engagement.md#severity-in-context)).

### DNS and takeover

| Rule | Fires | Disproved | Abstains | Base | Area | Exposure |
|---|---|---|---|---|---|---|
| `dns.takeover_candidate`: "*name* points at *provider*, which says nothing is set up there; anyone with an account there may be able to claim it" | the chain ends in NXDOMAIN at a suffix whose table entry's evidence is NXDOMAIN; or it ends at a fingerprinted suffix and an https or http response matches that entry's status and body marker (and its server marker, where the entry has one) | the chain ends at a fingerprinted provider and a response is 2xx or 3xx with no marker, worded "the provider serves a site for this name; whose site it is was not checked" | SERVFAIL, REFUSED, a timeout or a loop; a resolver that rewrites NXDOMAIN or is not known not to ("Nothing unread counts as nothing found"); both responses unavailable (timeout, blocked, 5xx, 429); an answer equal to the root's wildcard answer (filed once on `*.root`, "Takeover fingerprints"); a provider that verifies ownership (`dns.unclaimed_at_provider` instead) | high | external | no |
| `dns.unclaimed_at_provider`: "*name* points at *provider*, which says nothing is set up there; its policy requires ownership verification when moving a domain from another account; this binding's ownership was not checked" | the marker matched for a provider that verifies ownership | as `dns.takeover_candidate` | as `dns.takeover_candidate` | low | external | no |
| `dns.dangling_external`: "*name* (or the MX or NS of *d*) points at *target*, which does not exist" | every dangling chain outside every root that `dns.takeover_candidate` did not decide: NODATA at any suffix, NXDOMAIN at a suffix whose entry's evidence is the body, NXDOMAIN at a suffix with no entry; an MX or NS target outside every root that is NXDOMAIN or NODATA; an SPF `include:` target outside every root that is NXDOMAIN. NODATA at a claimable suffix is worded "the provider still knows this name but serves no address for it" | the target resolves | a lookup failure; a resolver that rewrites NXDOMAIN or is not known not to | medium | external | no |
| `dns.dangling_internal`: "a record points at *target* under your own domain, which does not exist" | the dangling target is inside a root | it resolves | as `dns.dangling_external` | info | external | no |
| `dns.private_address`: "*name* publishes a private address" | every address is RFC 1918, unique local, CGNAT or loopback | any public address | a lookup failure; a resolver that rewrites NXDOMAIN or is not known not to | info | external | no |

A complete lookup whose provider has no entry in the takeover table is not applicable
to the takeover rules. When the lookup is unknown and no provider can be recognized,
both takeover rules abstain. An unmatched external target is listed under "Services
your names point at" ([scope.md](scope.md#discovery)) with "*N* not checked for
takeover: no fingerprint for this provider". An unknown-provider wildcard control is
listed once as `*.<root>`, even when certificate logs supplied no matching names; its
grouped members are not listed separately. A dangling finding for such a name also says under `not_checked` that
whether another account could claim its target was not assessed.

**Built in E7 step 2b:** `dns.dangling_external`, `dns.dangling_internal` and
`dns.private_address` (2b-i), and `dns.takeover_candidate` and
`dns.unclaimed_at_provider` (2b-ii). `Judge` in `internal/collector/web` applies them
to each domain root in Recon, right after `Collect`, over Scope's lookups and what `Collect` read; the
session's first `Collect` follows its own control lookup under `invalid.`
([scope.md](scope.md#discovery)), counted as a control. Each
verdict is `fired`, `disproved` or `abstained` on one subject ("Subjects"), with the
coverage reason of an abstention and the gate request ids it read, and is kept in
`recon.json` under the asset's `judged`. One subject gets one verdict per rule: fired
stands over abstained, abstained over disproved, and the verdict keeps the reads of every
verdict merged into it. A name Scope looked up is judged only under the most specific
domain root holding it, as a mail domain is read, so nested roots never judge it twice.
A positive provider fingerprint replaces the name's `dns.dangling_external` verdict;
an abstention leaves an observed dangling chain to that rule. A target under a root
never enters the takeover table. As built:

- **Through a CNAME** (subject `dns_name`): a name with no CNAME is not judged. Scope's
  status `dangling` fires, as `dns.dangling_internal` when the chain ends under a root;
  `resolves` disproves.
- **Through an MX, NS or SPF include target** (subject `dns_record`): NXDOMAIN fires,
  and so does NODATA for an MX or NS target; a target that resolves disproves. An
  include target that exists with no SPF record is `email.spf_invalid`'s and disproves
  these rules. A `redirect=` target is not judged by them: one that does not exist is
  SPF's own error (step 3). An excluded target is judged by no rule. These records
  never become takeover findings, even when their target matches a table suffix.
- **`dns.private_address`** (subject `dns_name`): every name Scope resolved to at least
  one address, its addresses as `scope.json` keeps them; it fires when every address is
  private and is disproved by any public one. An address `redact_extra` matches leaves the lookup
  *insufficient evidence* ([scope.md](scope.md#third-party-sources)), so the name
  abstains as `unavailable:dns_error`.
- **An undeclared discovered name matching the root's wildcard answer** is judged by
  no name rule on its own:
  the control answer is judged once on `*.<root>`, with matching names grouped under
  it ("Wildcards"). Declared names keep their own reads and judgments.

**Nothing unread counts as nothing found.** Each of these abstains, never disproves:

| What was not read | Abstains on | Reason |
|---|---|---|
| a resolver that rewrites NXDOMAIN: Scope's (`scope.json` `resolver.rewrites_nxdomain`) or the one this session's Recon reads through | every applicable subject of the DNS and takeover rules, names and records alike, in place of any other verdict and reason | `unavailable:resolver_rewrites` |
| a resolver not known not to rewrite: Scope's control lookup under `invalid.` (`resolver.control_outcome`) or this session's in Recon was neither NXDOMAIN nor NODATA nor answered, because it failed or was not sent, or `scope.json` records no resolver ([scope.md](scope.md#discovery)) | as above | `unavailable:resolver_unchecked` |
| a name Scope did not check (`not_checked`) | the name, for the dangling and private-address rules and the applicable takeover rule, or both takeover rules when its provider is unknown | `sampled` past the cap; for a refusal (a deadline), the gate's reason |
| a name whose lookup said nothing, with or without a chain (`insufficient_evidence`) | the name, for the dangling and private-address rules and the applicable takeover rule, or both takeover rules when its provider is unknown | `unavailable:dns_<outcome>`; `limit_reached` for a deadline or a cancel |
| names Scope could not list: certificate transparency did not answer, the gate dropped names from its answer for any rule but an exclude and `not_a_name` (`redacted`, `unattributable`; [scope.md](scope.md#third-party-sources)), or Scope's list is missing | `*.<root>`, for `dns.dangling_external`, `dns.private_address` and both takeover rules | `unavailable:ct_source`, `unavailable:<rule>`, `unavailable:not_listed` |
| a records read that said nothing (MX, NS, the domain's TXT) | `<owner>/<TYPE>`, for `dns.dangling_external` | the read's reason |
| an SPF tree not read to its end | `<domain>/TXT`, for `dns.dangling_external` | `unavailable:spf_incomplete` |
| a target read that said nothing | its `dns_record` | the read's reason |

A wildcard finding does not settle a gap in the names listed: the merged verdict keeps
the gap's reason, its assessment incomplete and its coverage partial. A matching body
marker may fire in a truncated capture, but a marked or truncated capture never proves
its absence. A generic 4xx page settles neither configured nor unclaimed.

A read the gate refused or could not make takes its reason from the gate's own table
([scope.md](scope.md#outcomes)); a deadline or a cancel in a lookup is `limit_reached`.

**Severity in context.** These are configuration findings, so only the engagement's
`data_matters_most` moves them ([engagement.md](engagement.md#severity-in-context)):
a finding whose asset is named under `data.matters_most` is raised one step, `by:
engagement`, its source the file's `data.matters_most`, with the why-here line "You
listed *asset* under data.matters_most, so this ranks one step higher." Any other
finding of theirs says "This is the standard rating: it is about how the records are
set up, which nothing you declared changes."

The collector's reads are unauthenticated: its evidence's principal is `anonymous`, and
an observation is the gate request it read.

### Email

Declared mail domains, and domain roots judged from the mail use they show when nothing
was declared ([engagement.md](engagement.md#intake-the-engagement-file), "Mail").

| Rule | Fires | Disproved | Abstains | Base | Area |
|---|---|---|---|---|---|
| `email.dmarc_not_enforced`: "Mail pretending to come from *d* is not rejected or quarantined (DMARC *state*)" | no `v=DMARC1` record; more than one; `p=none`; `p` missing or invalid; `pct=0`; `t=y` | exactly one record, `p=quarantine` or `p=reject`, with `pct` absent or from 1 to 100 and no `t=y` | a lookup failure; a truncated answer not retried over TCP; *d* not registrable, its organizational domain not a root, and `_dmarc.<d>` absent (read with the public-suffix snapshot) | medium | email |
| `email.dmarc_partial`: "DMARC on *d* applies its policy to only *pct*% of mail that fails authentication" | `pct` from 1 to 99 with an enforcing `p` and no `t=y`; not applicable when `email.dmarc_not_enforced` fires, since nothing is enforced to apply partly | an enforcing `p` with `pct` 100 or absent | as `email.dmarc_not_enforced` | low | email |
| `email.dmarc_subdomains_open`: "Subdomains of *d* can be spoofed" | `p` enforces and `sp=none` (or `np=none`) | `sp` absent or enforcing | as `email.dmarc_not_enforced` | low | email |
| `email.no_mail_spoofable`: "*d* sends no mail but does not tell receivers to reject mail claiming to come from it" | SPF absent or not exactly `v=spf1 -all`, or DMARC not `p=reject` at 100% | `v=spf1 -all` and `p=reject` | a lookup failure | low | email |
| `email.spf_permits_anyone`: "SPF lets any server send as *d*" | `+all`, a bare `all`, an `ip4` of /8 or wider, an `ip6` of /16 or wider | `-all`, `~all` or `?all` with no such range | a `redirect=` to a name not read | high | email |
| `email.spf_missing`: "*d* publishes no SPF record, so receivers cannot check which servers may send as it" | a sending or mail-use domain with no `v=spf1` record | one record | a lookup failure | low | email |
| `email.spf_invalid`: "SPF for *d* is broken, so receivers ignore it" | more than one `v=spf1` record; a syntax error; an eleventh DNS-querying term ("Reads", SPF's budget); an `include:` target with no SPF record (a permerror, RFC 7208 §5.2); more than two void lookups | one valid record within the budget | when includes were not read, the count fires on what it saw, is never disproved and prints "at least" | low | email |
| `email.spf_undeclared_sender`: "SPF authorizes *service*, which you did not list as sending for *d*" | an include on the include-to-service table, for a service not declared; runs only when `mail.senders` lists at least one sender for *d* | every mapped include is declared | unmapped includes, `ip4` and `ip6` are listed, not judged | low | email |
| `email.dkim_missing`: "No DKIM key for *service* at *sel*._domainkey.*d*" | NXDOMAIN or NODATA; not a DKIM record; an empty `p=` | a valid key | a lookup failure; no selector declared, which coverage words as "no selector given", never "missing" | low | email |
| `email.dkim_key_breakable`: "The DKIM key at *sel*._domainkey.*d* is short enough to break, which would let anyone sign mail as *d*" | an RSA modulus under 1024 bits | 1024 bits or more, or ed25519 | unparseable | high | email |
| `email.dkim_key_1024`: "The DKIM key at *sel*._domainkey.*d* is 1024-bit; 2048-bit is the current recommendation" | an RSA modulus of 1024 bits | over 1024 bits, or ed25519 | unparseable | info | email |

- The three DMARC outcomes are exclusive per domain: `pct=0`, `t=y`, or `p` missing,
  invalid or `none` fire `email.dmarc_not_enforced`; `pct` from 1 to 99 with an
  enforcing `p` fires `email.dmarc_partial` and disproves `email.dmarc_not_enforced`;
  `pct` absent or 100 with an enforcing `p` disproves both. `t=y` is recognized wherever
  `pct` is read.
- `~all` is never a finding when DMARC enforces.
- Alignment (`adkim`, `aspf`) is printed as read, with "whether your senders' mail
  actually aligns is not visible in DNS", and is never a finding.
- A domain declared under `mail.no_mail` whose SPF authorizes a sender, or that has DKIM
  or MX records, is a note for the readout, not a finding.

### TLS and certificate

| Rule | Fires | Disproved | Abstains | Base | Area |
|---|---|---|---|---|---|
| `tls.certificate_invalid`: "The certificate for *name* is *expired / for another name / not from a trusted issuer / missing its intermediate*" | the gate's typed verification class | verified | no handshake; an unclassified error; an issuer on the TLS-interception list, worded "your network inspects TLS, so certificates were not judged"; the name is a takeover candidate, which subsumes it | low | external |
| `tls.certificate_expiring`: "The certificate for *name* expires in *n* days; automatic renewal may be failing" | valid, with 14 days or fewer left, worded: ACME clients renew at about a third of a certificate's lifetime, so this usually means renewal is failing | more than 14 days left | as `tls.certificate_invalid` | info | external |
| `tls.legacy_only`: "*name* accepts only TLS versions older than 1.2, which current browsers refuse" | the name's one handshake, at TLS 1.2 or later, gets a `protocol_version` alert | it succeeds | `handshake_failure` or any other alert (`unavailable:tls_handshake`); an issuer on the TLS-interception list. The handshake is never retried at a lower version | low | external |

A missing intermediate is worded "browsers may still accept it; command-line tools and
API clients will not." scheck fetches no intermediate from the certificate's AIA URL,
on any platform ([scope.md](scope.md#connections)). When the gate could read no root
certificate, every verification failure is classed `unclassified`, so the certificate
rules abstain on every name.

**The TLS-interception list** is versioned data in the tree: the issuers of products
that inspect TLS on the operator's network (Zscaler, Netskope, Fortinet, Palo Alto,
Cisco Umbrella, Sophos, Kaspersky, ESET, Avast, Bitdefender). A chain from one makes
every certificate rule abstain for that name.

### Headers and cookies

Declared or first-party sites, except where a row says every read name.

| Rule | Fires | Disproved | Abstains | Base | Area | Exposure |
|---|---|---|---|---|---|---|
| `web.hsts_missing`: "*origin* does not tell browsers to always use HTTPS (HSTS)" | no valid `Strict-Transport-Security` on any https response of the origin; one invalid under RFC 6797; `max-age` under 86400 | valid on any https response of the origin; the subject is the origin. Also disproved when the name's own last label is a preloaded TLD ("Preloaded TLDs") | only 5xx, 429 or blocked responses; an invalid certificate | low | web | no |
| `web.plaintext_http`: "*origin* serves pages over plain HTTP instead of redirecting to HTTPS" | the http `GET` is a 2xx with a body, or a 3xx to `http:`; +1 `attribute:password_form` when the body holds `<input type="password">` | a 3xx to `https:`; refused on port 80; a timeout on port 80, which counts as disproved from this vantage. Also disproved, with no `attribute:password_form` raise, when the name's own last label is a preloaded TLD | 5xx, 429, blocked | low (+1: medium) | web | no |
| `web.plaintext_http_clients`: "*origin* still answers over plain HTTP; browsers never use it on .*tld*, but scripts and API clients configured with http:// would send their requests unencrypted". On a name whose own last label is a preloaded TLD; the subject is the origin | port 80 returns a 2xx with a body | a 3xx to `https:`; a refused connection | as `web.plaintext_http` | info | web | no |
| `web.session_cookie_flags`: "A session cookie on *origin* is readable by scripts or can be sent unencrypted" | a cookie with a session-like name without `Secure` (on https, or set over http) or without `HttpOnly` | never: only entry points are read | no session cookie seen, worded "the login flow was not read, so session cookies were not checked" | low | web | no |
| `web.security_headers`: one item per origin listing which are missing of `X-Content-Type-Options`, frame protection (`X-Frame-Options` or CSP `frame-ancestors`), `Referrer-Policy` and CSP | any missing | all present | as `web.hsts_missing` | info | web | no |
| `web.version_disclosed`: "*url* reveals software versions (*what*)". Every read name; the subject is the URL | a version number in `server` or `x-powered-by`, in `<meta name="generator">`, or in a JSON body's top-level version, build or commit | none, or a product without a version (`nginx`, `cloudflare`, `AmazonS3`, `Vercel`) | blocked; 5xx; a body cut before `</head>` with no version in the headers | low | web | yes: to info |
| `web.secret_in_response`: "A secret is published in the page at *url*". Every read name | a redaction hit from `private-key`, `github-token`, `slack-token`, `google-access-token`, `google-refresh-token`, `google-client-secret`, `stripe-key`, `npm-token` or `slack-webhook` | HTML read whole with no hit, for that HTML only | a truncated body fires on what it saw and is never disproved. Never fires on `google-api-key`, `jwt`, `bearer`, `kv-secret` or `json-secret`, an AWS key id alone, or `extra:*` | critical; a Slack webhook high | secrets | no |
| `web.security_txt`: "No current security contact at *origin*" | a 404; `Expires` in the past; no `Contact` | a valid file | blocked; 5xx; a redirect off the entry points | info | web | no |
| `web.restricted_reachable`: "*url*, which you said is reachable only from *audience*, answered from the internet" | the vantage is `internet`, the declared audience is not, and the response is a 2xx, a 401, or a 3xx to a login page on the same site or an identity provider | refused or timed out from the `internet` vantage, worded "did not answer from here; scheck cannot tell a firewall from a server that is down" | the vantage is not `internet` or not given; 403 or 404; blocked; 5xx; an invalid certificate | medium, +1 `contradiction`: high | external | no; validation also refuses one URL under both `intent` lists |

**Preloaded TLDs.** `PreloadedTLDs` is versioned data in the tree, taken from
Chromium's `net/http/transport_security_state_static.json`, pinned to a commit and
dated: the entries that are a single label, with mode `force-https`,
`include_subdomains` true and a policy other than `test`. Known members include `app`,
`dev`, `page`, `bank`, `insurance` and `foo`; the rest come only from the pinned file.
It is part of `rules_version`, regenerated each release by a small script that reads
the pinned file, and a test asserts that the data's header names the commit. Only a
name's own last label counts, in punycode, never a CNAME target's. An apex preloaded on
its own is not handled in 0.0.2.

| Rule disproved | Text | JSON |
|---|---|---|
| `web.hsts_missing` | `checked (HSTS): not needed on <name>: browsers have .<tld> on their built-in HTTPS-only list, so they use HTTPS there whatever the site's headers say.` | outcome `disproved`, detail `{reason: "tld_preloaded", tld, list_version}` |
| `web.plaintext_http` | `checked (plain HTTP): browsers never use plain HTTP on .<tld>; see the informational finding for other clients` when `web.plaintext_http_clients` fired, otherwise `checked (plain HTTP): redirects to HTTPS` | outcome `disproved` |

**Session-like names** are a versioned list: `session`, `sess`, `sid`, `connect.sid`,
`PHPSESSID`, `JSESSIONID`, `laravel_session`, `_*_session`, `auth*`, `jwt`, `token`.

**The include-to-service table** that `email.spf_undeclared_sender` reads is versioned
data in the tree.

### Facts, not findings

- **Technology fingerprint**, from headers, cookie names, the generator meta tag and
  body markers (`/wp-content/`, `__NEXT_DATA__`, `ng-version`,
  `csrfmiddlewaretoken`). Each item says what it came from; a CDN named in `server` is
  labelled as the CDN, not as the site's software.
- **`robots.txt`**: the count of its `Disallow` entries. Its paths never become requests
  ([scope.md](scope.md#web-applications-and-sites)).
- **`unavailable:blocked`**: a status of 403, 429 or 503 **and** a body marker from the
  versioned list: Cloudflare ("Just a moment…", "Attention Required!"), Akamai
  ("Reference #"), Imperva ("Incapsula incident ID"), Sucuri, AWS WAF and Vercel's
  checkpoint. Every rule over that response abstains, and the exit code does not change
  ([scope.md](scope.md#connections)). Its JSON detail is `{vendor, status, url}`; its
  text is in [engagement.md](engagement.md#coverage) ("Reason wording"). The report
  never praises the protection and never advises turning it off.

## Subjects

Each finding is one record per `{id, asset, subject}`
([engagement.md](engagement.md#findings)). A key is lowercase, with punycode A-labels,
no trailing dot, default ports dropped, no query or fragment and no spaces; a key that
`redact_extra` matches renders as its marker.

| Kind | Key | Rules |
|---|---|---|
| `origin` | `scheme://host[:port]`, no path | `web.hsts_missing` (the https origin), `web.plaintext_http` and `web.plaintext_http_clients` (the http origin), `web.session_cookie_flags` (the cookie names under `affected.listed`), `web.security_headers`, `web.security_txt` |
| `url` | the URL | `web.version_disclosed`, `web.restricted_reachable` |
| `secret_location` | `<detector>:<url>`, one per detector per page, the count under `derived` | `web.secret_in_response` |
| `dns_name` | the name, or `*.<root>` for a dangling wildcard and for names Scope could not list | `dns.takeover_candidate`, `dns.unclaimed_at_provider`, `dns.dangling_*` through a CNAME, `dns.private_address`, `tls.*` (port 443 implied) |
| `dns_record` | `<owner>/<TYPE>/<target>`, `TYPE` one of `MX`, `NS` and `TXT` (an SPF include target), the owner the name whose record points at the target: the domain, or for a nested include the include whose record names it. Labelled "MX of example.com → mx.oldhost.net", "NS of example.com → ns1.dns-host.example", "SPF include of example.com → _spf.gone.example". A records read that said nothing is `<owner>/<TYPE>` | `dns.dangling_*` through an MX, an NS or an SPF include whose target is gone |
| `mail_domain` | the mail domain; its label adds "declared sending (…)", "declared no mail" or "not declared" | `email.dmarc_*`, `email.spf_missing`, `email.spf_invalid`, `email.spf_permits_anyone`, `email.no_mail_spoofable` |
| `dkim_selector` | `<sel>._domainkey.<domain>`, labelled "selector google (google-workspace) on example.com" | `email.dkim_*` |
| `spf_mechanism` | `<domain>/include:<target>`, one per include | `email.spf_undeclared_sender` |

A finding's asset is the most specific asset that holds its subject. A `dns_name`'s is
the name's own id (`domain:<name>`), declared or not, and the root for the root itself
and for a name the engagement file cannot name as an asset (one holding an underscore
label, or one redaction marked); a `dns_record`'s is that of the domain whose records
were read (the root for its NS, the mail domain for its MX and its whole SPF tree). An
`origin` or `url` belongs to the declared `url` asset, else to the name's id; an email
finding to the domain root the mail domain falls under. Acceptances and assessments go
by that asset, and an undeclared name's findings print the name as their asset and its
canonical id as the paste's `asset` ([engagement.md](engagement.md#findings), "The
paste"). An acceptance covers its own asset's instances only, never those of a name
under it ([engagement.md](engagement.md#findings), "Acceptances"). The DNS finding
definitions, including both takeover findings, declare `Subject: "dns_name"`, so an
acceptance must name its subject; record findings still use their `dns_record` key.

## Takeover fingerprints

The takeover table in `internal/collector/web/takeover.go` is versioned data,
refreshed each release. Version `2026-10-09.1`, reviewed on `2026-10-09`, uses
[`can-i-take-over-xyz`'s `fingerprints.json`](https://github.com/EdOverflow/can-i-take-over-xyz/blob/5bd4e12837911c8475486f1da922c9b9c706e632/fingerprints.json)
at commit `5bd4e12837911c8475486f1da922c9b9c706e632` (`2025-02-08`), with the
provider sources below. Each enabled entry holds the provider, anchored DNS suffix
pattern, evidence kind, status and markers where applicable, ownership tier, source
and caveat. A change invalidates recall comparisons across versions.

| Enabled provider | Suffixes | Evidence | Tier and source |
|---|---|---|---|
| GitHub Pages | `*.github.io` | 404 and "There isn't a GitHub Pages site here.", read from http (https does not match) | claimable; `not_checked`: whether the organization [verified the domain](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages), which can prevent another account claiming it |
| AWS S3 | `*.s3-website[-.]<region>.amazonaws.com`, `*.s3[.-]<region>.amazonaws.com`, `*.s3.amazonaws.com` | 404 and `NoSuchBucket`, with `Server: AmazonS3` | claimable; [virtual hosting and custom domains](https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html) |
| Elastic Beanstalk | `*.<region>.elasticbeanstalk.com` | NXDOMAIN | claimable; [custom domains](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/customdomains.html) |
| Azure | names below `azurewebsites.net`, `cloudapp.net`, `cloudapp.azure.com`, `trafficmanager.net`, `blob.core.windows.net`, `azure-api.net` | NXDOMAIN | claimable; [subdomain takeover](https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover); only for `azurewebsites.net`, `not_checked` names App Service's `asuid` TXT ownership record, which can prevent another account binding the domain |
| Vercel | exactly `cname.vercel-dns.com` or `cname.vercel-dns-0.com` | 404 and `DEPLOYMENT_NOT_FOUND` | verifies ownership: `dns.unclaimed_at_provider`, low; [the error and its status](https://vercel.com/docs/errors/deployment_not_found), [ownership policy](https://vercel.com/docs/domains/working-with-domains/claim-domain-ownership) |

**No verified fingerprint in this version:** Heroku (legacy `herokuapp.com`) and
Bitbucket have no status in the pinned source; their body marker alone is not enough.
Pantheon, Surge, WordPress.com, Ghost, Netlify, Shopify, Fastly, Webflow, Zendesk and
CloudFront have no enabled status, marker and ownership combination. Names pointing
at these providers are listed as not checked for takeover, as are other unmatched
providers; an unknown provider's dangling chain still fires `dns.dangling_external`.
They are not presumed safe or claimable. `herokudns.com` is not on the claimable list.

**Two kinds of evidence, never one alone:** NXDOMAIN at a claimable suffix; or the
suffix **and** the status **and** the body marker.

**Wildcards.**

- An undeclared discovered name whose answer equals its root's control answer is not
  read on its own ([scope.md](scope.md#discovery)). A declared name keeps its own HTTP
  reads and judgments: the same DNS answer does not establish the same Host binding.
  Answers match only when recognized and equal in outcome, whole CNAME chain and
  addresses. Shared addresses alone, different chains, and equal redaction or
  truncation markers never establish a match. Scope keeps the gate's redacted control
  name, chain, addresses, outcome and request id as `domains[].control` in
  `scope.json`. A marked control name is insufficient evidence, never an HTTP host
  or a reason to read a page. A control marked `insufficient_evidence` or
  `not_checked` leaves Scope incomplete and is retried on resume; a successful
  control is kept when Scope is complete.
  A dangling wildcard needs a nonempty chain; an
  ordinary random NXDOMAIN with no chain is not a wildcard finding.
- When the control label's own chain dangles or is fingerprinted, that is **one**
  instance, on `*.root`, and the certificate-transparency names with the same chain are
  grouped under it. When a resolving control points at an enabled body-fingerprint
  provider and both resolvers are known not to invent answers, Recon sends the control
  name's one https/http front-page pair through the normal gate. It never sends a
  literal `*.<root>` or reads matching undeclared certificate-log names separately.
  The evidence says those names matched DNS, and their pages were not read. A dangling
  control needs no page; neither does an unknown provider.
- On a provider's own wildcard (`github.io`, `herokuapp.com`, S3), only the body is
  evidence.
- Under a resolver that rewrites NXDOMAIN, every NXDOMAIN verdict is insufficient
  evidence.

**Never claim a name.** No provider account, no call to a provider's API, no request
beyond the two reads of a name without first-party evidence, and no read repeated. A
matched fingerprint suspends operator `first_party` confirmations for that name in
the live scope and persisted `scope.json`; a wildcard match suspends confirmations
only for its listed member names, never every descendant or a nested root. Explicit
roots remain authorized by their root evidence
([scope.md](scope.md#first-party-evidence)). The finding's `not_checked` says whether
someone already claimed the name was not checked, with the provider's caveat where
applicable.

## What the report never says

**Never claimed**, with what is said instead:

| Never | Instead |
|---|---|
| "cannot be spoofed" | "receivers that honour DMARC reject mail that fails authentication"; lookalike domains are untouched |
| "alignment verified" | alignment printed as read ("Email") |
| "TLS configuration is good" | "one connection negotiated TLS 1.3; other versions, ciphers and revocation were not tested" |
| "no takeover" | "among *N* names found in certificate logs; names never in a public certificate were not checked" |
| that a version is vulnerable, or any CVE | the version, as read |
| "clickjacking" or "XSS" from headers | what the header tells browsers |
| that a discovered name's server is the company's | the name and what it points at |
| "no secrets on the site" | "none in the HTML of the pages read; scripts the pages load were not read" |

**Wording.**

- Headers are hardening, worded as what they tell browsers ("tells browsers to…").
- A version banner exposed on purpose stays `info` with the operator's reason; a secret
  on the same URL stays critical.
- A 403 on a restricted URL is not "reachable".
- A cookie rule that saw no session cookie says "not checked".
- `~all` is not a finding.

**False-positive traps**, each a fixture: `AIza` keys, `pk_live_` keys and Supabase anon
JWTs (meant for browsers); CSRF tokens; `Server: cloudflare`; a provider's default
certificate; WAF challenge pages; clients behind TLS inspection; Workspace DKIM never
switched on, worded both ways; a TXT record over 255 characters split into strings.

## Not assessed

Each is printed with its reason, under the coverage row it belongs to
([engagement.md](engagement.md#coverage)):

- names never in a public certificate, or covered by a wildcard certificate;
- dangling NS delegations; a SERVFAIL is hinted "may be a delegation to a DNS zone you
  deleted; check its NS records at your DNS host";
- cloud addresses released and taken by someone else (0.0.3 G2);
- whether a dangling target's domain is unregistered (an SOA lookup, 0.0.3);
- the SPF include tree beyond the 10 lookups of "Reads";
- DKIM selectors nobody declared, and whether mail actually aligns;
- MTA-STS, TLS-RPT, DANE, DNSSEC and BIMI;
- TLS versions and ciphers other than the one negotiated, and revocation;
- pages beyond the entry points, the login flow and cookies set after it, and scripts;
- whether a name pointing at a provider is still the company's;
- the registrar account: who can sign in, its 2-step verification, auto-renew and the
  domain's expiry;
- whether the company's own domain is on browsers' built-in HTTPS-only list. Every run
  with a domain or url root prints: `Only whole domain endings (such as .page, .dev,
  .app) were looked up in browsers' built-in HTTPS-only list; whether your own domain
  is on it was not checked.`

## Remediation

| Rule | Fix |
|---|---|
| `dns.takeover_candidate` | Delete the record at *DNS host* today, or claim the name again in your *provider* account; then check whether anyone already served content there. |
| `dns.unclaimed_at_provider` | Remove the stale DNS record, or finish configuring the domain in the provider account. |
| `dns.dangling_external` | Delete the record, or point it at the service's current name. |
| `email.dmarc_not_enforced` | If there is no record, publish `v=DMARC1; p=none; rua=mailto:<a mailbox you read>`; read two to four weeks of reports; confirm that each sender under `mail.senders` passes; then move to `quarantine`, then `reject`. Do not jump straight to `reject`. |
| `email.spf_permits_anyone` | Replace `+all` or `all` with `~all`, or `-all` once DMARC enforces. |
| `email.no_mail_spoofable` | Publish `v=spf1 -all`, `v=DMARC1; p=reject;` and a null MX (`MX 0 .`). |
| `email.dkim_missing` | For Google: Admin console > Apps > Google Workspace > Gmail > Authenticate email > Generate, publish, then Start authentication. Otherwise read `s=` in the DKIM-Signature of a message the service sent. |
| `email.dkim_key_breakable` | Publish a 2048-bit key under a new selector, switch to it, then remove the old one. |
| `web.secret_in_response` | Revoke it at the provider first, then remove it from the page. |
| `web.restricted_reachable` | Restrict it at the proxy or firewall to the VPN's addresses, and confirm from outside. |
| `web.hsts_missing` | `Strict-Transport-Security: max-age=31536000`; add `includeSubDomains` only after checking that no subdomain is served over HTTP only. |
| `web.plaintext_http_clients` | Redirect port 80 to HTTPS, or close it. |
| `tls.certificate_invalid` | Renew or reissue it for *name*; for a missing intermediate, serve the full chain. |

## Data in the tree

Versioned with the rules, each change reviewed as one:

- the takeover table ("Takeover fingerprints");
- the public-suffix snapshot, embedded, which tells a registrable domain from a public
  suffix (`golang.org/x/net/publicsuffix` is barred by `scripts/depcheck.sh`);
- `PreloadedTLDs` ("Headers and cookies", "Preloaded TLDs");
- the TLS-interception list ("TLS and certificate");
- the list of session-like cookie names and the include-to-service table ("Headers and
  cookies");
- the block-page markers of `unavailable:blocked` ("Facts, not findings").
