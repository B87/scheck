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
| passive | TXT `_dmarc.<d>` | `v=DMARC1` records; the tags `p`, `sp`, `np`, `pct`, `t`, `adkim`, `aspf`, and whether `rua` is present |
| passive | MX `<d>` | targets and preferences; a null MX (`0 .`) |
| passive | NS `<d>` | host names |
| passive | TXT `<sel>._domainkey.<d>` for each selector declared under `mail.senders`, following its CNAME | `v`, `k`, `p`, `t`, and the key's modulus size |
| passive | what Scope resolved for each name | the chain, rcode, addresses and the control label's answer, already in `scope.json` |
| passive | A and AAAA of MX and NS targets outside every root; TXT of the targets of SPF `include:` and `redirect=`, within SPF's budget (below) | rcode and chain: resolved and recorded, never contacted ([scope.md](scope.md#third-party-sources)) |
| observe | one TLS handshake on 443 per read name | version, verified, the gate's typed verification class, and the chain's subjects, issuers, names and validity |
| observe | `GET https://name/` and `GET http://name/` for every read name; for a declared or first-party site also its entry points, `/robots.txt`, `/.well-known/security.txt` and one redirect hop on the same host ([scope.md](scope.md#connections)) | status, `location`, `server`, `x-powered-by`, the six security headers, `set-cookie` names and attributes, the redacted body within its cap |

The gate's DNS client reads TXT (several strings per record, TCP when the answer is
truncated), MX and NS ([scope.md](scope.md#third-party-sources), "The resolver"). A
name scheck builds from the engagement file takes no underscore label but `_dmarc` and
`_domainkey`; a name it reads from an answer (a CNAME hop, an SPF `include:` or
`redirect=`, an MX or NS target) may hold underscore labels anywhere, within the gate's
length and charset checks (`_spf.google.com`). A DKIM selector follows RFC 6376's
sub-domain syntax, lowercased, at most 63 characters a label, with no underscore.

**SPF's budget** is 10 DNS-querying terms per evaluation, counted across the whole tree
(`include`, `a`, `mx`, `ptr`, `exists`, `redirect`; RFC 7208 §4.6.4). Only `include`
and `redirect` targets are queried, as TXT; `a`, `mx`, `ptr` and `exists` are counted
and never resolved. An eleventh term fires `email.spf_invalid` and stops the evaluation.

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
`web.secret_in_response`, `web.hsts_missing`, `web.plaintext_http`,
`web.session_cookie_flags`, `web.security_headers` and `web.security_txt`, are
configuration findings, which it never moves; `web.restricted_reachable` is a
contradiction of a declared restriction, which is never an exposure finding
([engagement.md](engagement.md#severity-in-context)).

### DNS and takeover

| Rule | Fires | Disproved | Abstains | Base | Area | Exposure |
|---|---|---|---|---|---|---|
| `dns.takeover_candidate`: "*name* points at *provider*, which says nothing is set up there; anyone with an account there may be able to claim it" | the chain ends in NXDOMAIN at a suffix whose table entry's evidence is NXDOMAIN; or it ends at a fingerprinted suffix and an https or http response matches that entry's status and body marker (and its server marker, where the entry has one) | the chain ends at a fingerprinted provider and a response is 2xx or 3xx with no marker, worded "the provider serves a site for this name; whose site it is was not checked" | SERVFAIL, REFUSED, a timeout or a loop; a resolver that rewrites NXDOMAIN; both responses unavailable (timeout, blocked, 5xx, 429); an answer equal to the root's wildcard answer (filed once on `*.root`, "Takeover fingerprints"); a provider that verifies ownership (`dns.unclaimed_at_provider` instead) | high | external | no |
| `dns.unclaimed_at_provider`: "*name* points at *provider*, which says nothing is set up there; *provider* checks ownership before another account can use it" | the marker matched for a provider that verifies ownership | as `dns.takeover_candidate` | as `dns.takeover_candidate` | low | external | no |
| `dns.dangling_external`: "*name* (or the MX or NS of *d*) points at *target*, which does not exist" | every dangling chain outside every root that `dns.takeover_candidate` did not decide: NODATA at any suffix, NXDOMAIN at a suffix whose entry's evidence is the body, NXDOMAIN at a suffix with no entry; an MX or NS target outside every root that is NXDOMAIN or NODATA; an SPF `include:` target outside every root that is NXDOMAIN. NODATA at a claimable suffix is worded "the provider still knows this name but serves no address for it" | the target resolves | a lookup failure; a resolver that rewrites NXDOMAIN | medium | external | no |
| `dns.dangling_internal`: "a record points at *target* under your own domain, which does not exist" | the dangling target is inside a root | it resolves | as `dns.dangling_external` | info | external | no |
| `dns.private_address`: "*name* publishes a private address" | every address is RFC 1918, unique local, CGNAT or loopback | any public address | a lookup failure | info | external | no |

A name whose provider has no entry in the takeover table is not applicable to the
takeover rules. It is listed under "Services your names point at"
([scope.md](scope.md#discovery)) with "*N* not checked for takeover: no fingerprint for
this provider".

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
API clients will not." scheck fetches no intermediate from the certificate's AIA URL.

**The TLS-interception list** is versioned data in the tree: the issuers of products
that inspect TLS on the operator's network (Zscaler, Netskope, Fortinet, Palo Alto,
Cisco Umbrella, Sophos, Kaspersky, ESET, Avast, Bitdefender). A chain from one makes
every certificate rule abstain for that name.

### Headers and cookies

Declared or first-party sites, except where a row says every read name.

| Rule | Fires | Disproved | Abstains | Base | Area | Exposure |
|---|---|---|---|---|---|---|
| `web.hsts_missing`: "*origin* does not tell browsers to always use HTTPS (HSTS)" | no valid `Strict-Transport-Security` on any https response of the origin; one invalid under RFC 6797; `max-age` under 86400 | valid on any https response of the origin; the subject is the origin | only 5xx, 429 or blocked responses; an invalid certificate | low | web | no |
| `web.plaintext_http`: "*origin* serves pages over plain HTTP instead of redirecting to HTTPS" | the http `GET` is a 2xx with a body, or a 3xx to `http:`; +1 `attribute:password_form` when the body holds `<input type="password">` | a 3xx to `https:`; refused on port 80; a timeout on port 80, which counts as disproved from this vantage | 5xx, 429, blocked | low (+1: medium) | web | no |
| `web.session_cookie_flags`: "A session cookie on *origin* is readable by scripts or can be sent unencrypted" | a cookie with a session-like name without `Secure` (on https, or set over http) or without `HttpOnly` | never: only entry points are read | no session cookie seen, worded "the login flow was not read, so session cookies were not checked" | low | web | no |
| `web.security_headers`: one item per origin listing which are missing of `X-Content-Type-Options`, frame protection (`X-Frame-Options` or CSP `frame-ancestors`), `Referrer-Policy` and CSP | any missing | all present | as `web.hsts_missing` | info | web | no |
| `web.version_disclosed`: "*url* reveals software versions (*what*)". Every read name; the subject is the URL | a version number in `server` or `x-powered-by`, in `<meta name="generator">`, or in a JSON body's top-level version, build or commit | none, or a product without a version (`nginx`, `cloudflare`, `AmazonS3`, `Vercel`) | blocked; 5xx; a body cut before `</head>` with no version in the headers | low | web | yes: to info |
| `web.secret_in_response`: "A secret is published in the page at *url*". Every read name | a redaction hit from `private-key`, `github-token`, `slack-token`, `google-access-token`, `google-refresh-token`, `google-client-secret`, `stripe-key`, `npm-token` or `slack-webhook` | HTML read whole with no hit, for that HTML only | a truncated body fires on what it saw and is never disproved. Never fires on `google-api-key`, `jwt`, `bearer`, `kv-secret` or `json-secret`, an AWS key id alone, or `extra:*` | critical; a Slack webhook high | secrets | no |
| `web.security_txt`: "No current security contact at *origin*" | a 404; `Expires` in the past; no `Contact` | a valid file | blocked; 5xx; a redirect off the entry points | info | web | no |
| `web.restricted_reachable`: "*url*, which you said is reachable only from *audience*, answered from the internet" | the vantage is `internet`, the declared audience is not, and the response is a 2xx, a 401, or a 3xx to a login page on the same site or an identity provider | refused or timed out from the `internet` vantage, worded "did not answer from here; scheck cannot tell a firewall from a server that is down" | the vantage is not `internet` or not given; 403 or 404; blocked; 5xx; an invalid certificate | medium, +1 `contradiction`: high | external | no; validation also refuses one URL under both `intent` lists |

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
| `origin` | `scheme://host[:port]`, no path | `web.hsts_missing` (the https origin), `web.plaintext_http` (the http origin), `web.session_cookie_flags` (the cookie names under `affected.listed`), `web.security_headers`, `web.security_txt` |
| `url` | the URL | `web.version_disclosed`, `web.restricted_reachable` |
| `secret_location` | `<detector>:<url>`, one per detector per page, the count under `derived` | `web.secret_in_response` |
| `dns_name` | the name, or `*.<root>` for a dangling wildcard | `dns.takeover_candidate`, `dns.unclaimed_at_provider`, `dns.dangling_*` through a CNAME, `dns.private_address`, `tls.*` (port 443 implied) |
| `dns_record` | `<owner>/<TYPE>/<target>`, labelled "MX of example.com → mx.oldhost.net" | `dns.dangling_*` through an MX, an NS or an SPF include whose target is gone |
| `mail_domain` | the mail domain; its label adds "declared sending (…)", "declared no mail" or "not declared" | `email.dmarc_*`, `email.spf_missing`, `email.spf_invalid`, `email.spf_permits_anyone`, `email.no_mail_spoofable` |
| `dkim_selector` | `<sel>._domainkey.<domain>`, labelled "selector google (google-workspace) on example.com" | `email.dkim_*` |
| `spf_mechanism` | `<domain>/include:<target>`, one per include | `email.spf_undeclared_sender` |

A finding's asset is the most specific asset that holds its subject: the declared `url`
asset; else the discovered name's id; for an email finding, the domain root the mail
domain falls under.

## Takeover fingerprints

The takeover table is versioned data in the tree, refreshed each release. Each entry
holds the provider, its suffixes, the kind of evidence, its tier, the marker, and its
source: a URL and the `can-i-take-over-xyz` commit and date it was taken from. A change
to the table invalidates recall comparisons across it.

| Provider | Suffixes | Evidence | Tier |
|---|---|---|---|
| GitHub Pages | `*.github.io` | 404 and "There isn't a GitHub Pages site here.", read from http (https does not match) | claimable; `not_checked`: "unless your organization verified this domain at GitHub" |
| AWS S3 | `*.s3-website[-.]<region>.amazonaws.com`, `*.s3[.-]<region>.amazonaws.com`, `*.s3.amazonaws.com` | 404 and `NoSuchBucket` (with `Server: AmazonS3`) | claimable |
| Elastic Beanstalk | `*.<region>.elasticbeanstalk.com` | NXDOMAIN | claimable |
| Azure | `azurewebsites.net`, `cloudapp.net`, `cloudapp.azure.com`, `trafficmanager.net`, `blob.core.windows.net`, `azure-api.net` | NXDOMAIN | claimable; `not_checked` names App Service's `asuid` TXT record |
| Heroku (legacy) | `*.herokuapp.com`; `herokudns.com` is not on the list | "No such app" | claimable |
| Bitbucket | `*.bitbucket.io` | "Repository not found" | claimable |
| Pantheon, Surge, WordPress.com, Ghost | per source | the body | claimable per source; second tier, added only once their marker is verified |
| Netlify, Vercel, Shopify, Fastly, Webflow, Zendesk, CloudFront | per source | the provider's "not configured" page | verifies ownership: `dns.unclaimed_at_provider`, low |

**Two kinds of evidence, never one alone:** NXDOMAIN at a claimable suffix; or the
suffix **and** the status **and** the body marker.

**Wildcards.**

- A name whose answer equals its root's control answer is not read
  ([scope.md](scope.md#discovery)).
- When the control label's own chain dangles or is fingerprinted, that is **one**
  instance, on `*.root`, and the certificate-transparency names with the same chain are
  grouped under it.
- On a provider's own wildcard (`github.io`, `herokuapp.com`, S3), only the body is
  evidence.
- Under a resolver that rewrites NXDOMAIN, every NXDOMAIN verdict is insufficient
  evidence.

**Never claim a name.** No provider account, no call to a provider's API, no request
beyond the three reads of a name without first-party evidence, and no read repeated. A
matched fingerprint suspends a `first_party` confirmation
([scope.md](scope.md#first-party-evidence)). The report says that scheck cannot tell
whether someone has already claimed a name.

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
  domain's expiry.

## Remediation

| Rule | Fix |
|---|---|
| `dns.takeover_candidate` | Delete the record at *DNS host* today, or claim the name again in your *provider* account; then check whether anyone already served content there. |
| `dns.dangling_external` | Delete the record, or point it at the service's current name. |
| `email.dmarc_not_enforced` | If there is no record, publish `v=DMARC1; p=none; rua=mailto:<a mailbox you read>`; read two to four weeks of reports; confirm that each sender under `mail.senders` passes; then move to `quarantine`, then `reject`. Do not jump straight to `reject`. |
| `email.spf_permits_anyone` | Replace `+all` or `all` with `~all`, or `-all` once DMARC enforces. |
| `email.no_mail_spoofable` | Publish `v=spf1 -all`, `v=DMARC1; p=reject;` and a null MX (`MX 0 .`). |
| `email.dkim_missing` | For Google: Admin console > Apps > Google Workspace > Gmail > Authenticate email > Generate, publish, then Start authentication. Otherwise read `s=` in the DKIM-Signature of a message the service sent. |
| `email.dkim_key_breakable` | Publish a 2048-bit key under a new selector, switch to it, then remove the old one. |
| `web.secret_in_response` | Revoke it at the provider first, then remove it from the page. |
| `web.restricted_reachable` | Restrict it at the proxy or firewall to the VPN's addresses, and confirm from outside. |
| `web.hsts_missing` | `Strict-Transport-Security: max-age=31536000`; add `includeSubDomains` only after checking that no subdomain is served over HTTP only. |
| `tls.certificate_invalid` | Renew or reissue it for *name*; for a missing intermediate, serve the full chain. |

## Data in the tree

Versioned with the rules, each change reviewed as one:

- the takeover table ("Takeover fingerprints");
- the public-suffix snapshot, embedded, which tells a registrable domain from a public
  suffix (`golang.org/x/net/publicsuffix` is barred by `scripts/depcheck.sh`);
- the TLS-interception list ("TLS and certificate");
- the list of session-like cookie names and the include-to-service table ("Headers and
  cookies");
- the block-page markers of `unavailable:blocked` ("Facts, not findings").
