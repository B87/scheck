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
[report.md](report.md) ("Coverage", "A missing intake answer"). This file holds
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

**SPF record selection** requires case-insensitive `v=spf1` at byte zero, followed by
ASCII space or the end of the record (RFC 7208 §4.5). Leading whitespace or a different
version delimiter does not identify an SPF record.

**SPF's budget** is 10 DNS-querying terms per evaluation, counted across the whole tree
(`include`, `a`, `mx`, `ptr`, `exists`, `redirect`; RFC 7208 §4.6.4). Only `include`
and `redirect` targets are queried, as TXT; `a`, `mx`, `ptr` and `exists` are counted
and never resolved. Step 3 validates the whole record, including syntax after `all`,
but follows and counts only mechanisms before the first `all`; a record with `all`
ignores `redirect`. Invalid syntax yields no follow-ups. An eleventh term fires
`email.spf_invalid` and stops further collection.
The collector reads the tree only when the domain has exactly one `v=spf1` record, depth
first in the order its terms are written, and reads nothing more once the count passes
10; the gate sends at most 10 `include:` and `redirect=` reads per evaluation, one
evaluation per domain, whatever the collector counts
([scope.md](scope.md#third-party-sources), "Follow-ups"). The tree is complete
(`spf_complete`) when nothing in it is unknown: the domain's TXT was read, and either
it holds no single `v=spf1` record to walk or every reachable `include:` and
`redirect=` within the budget was read. A failed read of the domain or of an include, a term whose target
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
`malformed`, without its tags. Plain unmarked DMARC remainder fragments that are not
tags are ignored under RFC 7489 §6.3; they produce no standalone-fragment finding.
`rua` counts only when it has a value. Any marker in a recognized DMARC record or DKIM
key is counted before tags are reduced, including markers inside a tag name or a
fragment. Both redaction and truncation markers count, including before version
recognition. For a marked record that could have begun `v=DMARC1`, recognition of the
remaining prefix allows the same leading whitespace and whitespace around `=` as the
tag parser, including tabs and CRLF. SPF's potential version prefix remains strict at
byte zero, without whitespace trimming. Any marked record at a selector that is not
recognized as a key is counted too. These counts (`dmarc_marked`, a selector's
`marked`) make a rule over the domain or selector abstain rather than treating marked
evidence as absence or valid evidence.

**Built in E7 step 2a:** Recon reads each domain root with `Collect`: for the root and
each mail domain under it, in that order, TXT at the domain and at `_dmarc.<d>`, MX and
its targets' addresses, the SPF include tree and each declared DKIM selector; the root's
NS and its targets' addresses; and for each name Scope marked to read, `GET /` over
https, then http (`web.front`), the https read's handshake
giving the certificate and TLS result. A mail domain is read once, under the most
specific domain root that holds it, so nested roots never read it twice or give it two
SPF budgets. It keeps only the fields in the table above: no TXT record but `v=spf1`
ones at a domain and in the include tree, each DMARC record's tags and whether `rua`
has a value but never its address, each DKIM key's tags. What it read is in
`recon.json`, under the asset's `web`. After all roots have been read, Recon judges it ("Rules", DNS in step 2b and
email in step 3) and the root is `collected`. It is `limit_reached`
when `limits.timeout` ends the engagement before the root is read (`not_collected`), or
while it is: the deadline ended or refused one of its reads (`refused:deadline`,
`unavailable:deadline`, or a `limit_reached` reason on a page), or ended the engagement
as `Collect` returned (`incomplete`). A declared `domain` asset under a root that was read
is read with it: it is recorded with the root's status and the detail "read with
*root*", and its findings are those whose subject it holds ("Subjects").

**Built in E7 step 4:** Recon also reads `url` roots and declared URL assets. After
DNS takeover judgments have suspended stale first-party confirmations, `Enrich`
requests declared entries and the two well-known files through the typed `web.entry`
op. A declared URL asset contained by a URL root contributes its exact entry path
using the root's first-party evidence; a domain root alone does not grant it. URL
assets read with a root retain that relationship for report coverage. Intent URLs
are entry points but never first-party evidence or sufficient on their own to make a site eligible for header rules. Every read rechecks live admission at
the gate. One same-host redirect per initial read is submitted with its source
request id; it is never followed automatically. A redirect that was not read does
not satisfy an ordinary declared-entry read: that request is admitted independently,
and both attempts remain recorded. `robots.txt` retains only the count
of nonempty `Disallow` entries; its body and paths are discarded from Recon and never
become requests. A URL root on a nondefault port does not imply a second read on 443;
its absent port-443 certificate evidence stays unknown. Pages retain the gate's
first-party admission metadata and actual collection time. A URL root plans only
its own declared path and descendants, not peer paths on the same origin. After
collection, judgments join captured pages from matching site names across roots so
origin-wide rules see all observed responses; this merge sends no additional read.

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
| a resolver that rewrites NXDOMAIN: Scope's (`scope.json` `resolver.rewrites_nxdomain`) or the one this session's Recon reads through | every applicable subject of the DNS, takeover and email rules, names and records alike, in place of any other verdict and reason | `unavailable:resolver_rewrites` |
| a resolver not known not to rewrite: Scope's control lookup under `invalid.` (`resolver.control_outcome`) or this session's in Recon was neither NXDOMAIN nor NODATA nor answered, because it failed or was not sent, or `scope.json` records no resolver ([scope.md](scope.md#discovery)) | as above | `unavailable:resolver_unchecked` |
| a name Scope did not check (`not_checked`) | the name, for the dangling and private-address rules and the applicable takeover rule, or both takeover rules when its provider is unknown | `sampled` past the cap; for a refusal (a deadline), the gate's reason |
| a name whose lookup said nothing, with or without a chain (`insufficient_evidence`) | the name, for the dangling and private-address rules and the applicable takeover rule, or both takeover rules when its provider is unknown | `unavailable:dns_<outcome>`; `limit_reached` for a deadline or a cancel |
| names Scope could not list: certificate transparency did not answer, the gate dropped names from its answer for any rule but an exclude and `not_a_name` (`redacted`, `unattributable`; [scope.md](scope.md#third-party-sources)), or Scope's list is missing | `*.<root>`, for `dns.dangling_external`, `dns.private_address` and both takeover rules | `unavailable:ct_source`, `unavailable:<rule>`, `unavailable:not_listed` |
| a records read that said nothing (MX, NS, the domain's TXT) | `<owner>/<TYPE>`, for `dns.dangling_external` | the read's reason |
| an SPF tree not read to its end | `<domain>/TXT`, for `dns.dangling_external` | `unavailable:spf_incomplete` |
| a target read that said nothing | its `dns_record` | the read's reason |

Resolver-control doubt affects only DNS-derived rules (`dns.*` and `email.*`). TLS
and response rules use the gate's connection and capture evidence, preserving their
own abstentions for unread, blocked or otherwise insufficient evidence. A URL-only
run does not need discovery's resolver control to judge those captures.

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

**Built in E7 step 3:** eleven rules over the mail DNS already collected. No email
rule sends a request. An uncollected read or unknown read decision is
`unavailable:not_read`, including a declared DKIM selector with no read at all.
Absent collected evidence is never interpreted as a missing record or a no-mail
domain. They judge declared mail domains and domain roots from the mail
use they show when nothing was declared
([engagement.md](engagement.md#intake-the-engagement-file), "Mail"). A non-null MX
or recognized SPF authorization is evidence of mail use, not proof of current sending.
A domain is inferred to send no mail only when its MX and complete SPF evidence are
recognized, show no authorization and contain no SPF error. A deny-only include does
not establish sending; missing or failed evidence leaves mail use unknown.

This is a DNS configuration review, not a test of delivered mail. DMARC uses the legacy
organizational-domain fallback and `pct`, and recognizes `t=y`; current RFC 9989
receiver DNS tree walking is not assessed. The embedded ICANN and private public-suffix
snapshot is commit `3929462652695bad04f0a27afb600974014a3c8b` (`2026-10-07`) of
[the Public Suffix List](https://github.com/publicsuffix/list/blob/3929462652695bad04f0a27afb600974014a3c8b/public_suffix_list.dat).
It adds no network dependency. An unknown suffix gives no organizational-domain
conclusion. An absent subdomain policy can inherit only from organizational-domain
records already collected, including a different declared root. Judgment happens after
all roots' reads, so collection order cannot change inheritance. If those records were
not read, the rule abstains; it sends no parent lookup. `sp` overrides the inherited
`p`; `np` applies only to a child whose TXT and MX both prove NXDOMAIN. Recognized
records or NODATA establish existence. When existence is unknown and `np` would change
the inherited policy, the rule abstains.

| Rule | Fires | Disproved | Abstains | Base | Area |
|---|---|---|---|---|---|
| `email.dmarc_not_enforced`: "DMARC does not request its full enforcement policy" | no DMARC record after bounded fallback; multiple or malformed records; `p` missing, invalid or `none`; legacy `pct=0`; `t=y` | one usable policy, `p=quarantine` or `p=reject`, legacy `pct` absent or 1–100, no `t=y` | lookup failure or marked evidence; unknown mail use or inherited policy; unrecognized `pct` or `t` | medium | email |
| `email.dmarc_partial`: "DMARC publishes a partial percentage for legacy receivers" | legacy `pct` 1–99 with an enforcing policy and no `t=y` | enforcing policy with legacy `pct` 100 or absent | as `email.dmarc_not_enforced`; not applicable when that rule fires | low | email |
| `email.dmarc_subdomains_open`: "DMARC leaves subdomains without a requested enforcement policy" | organizational domain has an enforcing policy and `sp=none` or `np=none` | enforcing policy, `sp` and `np` absent or enforcing | as `email.dmarc_not_enforced`; invalid `sp` or `np`; domain is not the organizational domain (descendant policy is unknown) | low | email |
| `email.no_mail_spoofable`: "A domain with no mail use lacks a full no-mail policy" | declared or inferred no-mail domain: SPF absent or not exactly `v=spf1 -all`, or DMARC not a full `p=reject` policy | exact SPF denial and full DMARC rejection (`pct` 100 or absent, no `t=y`) | neither side proves a defect and one is unknown; unknown mail use | low | email |
| `email.spf_permits_anyone`: "SPF authorizes any sender or a very broad address range" | reachable positive `all`, `ip4` /8 or wider, or `ip6` /16 or wider, including an allowing include or redirect path | recognized complete valid tree has no such authorization | unknown or invalid evidence before a possible grant, unread target, macro or incomplete tree | high | email |
| `email.spf_missing`: "A mail domain publishes no SPF record" | sending or mail-use domain has no SPF record | SPF is present; validity is judged separately | failed or marked evidence; unknown mail use | low | email |
| `email.spf_invalid`: "SPF contains an error or can exceed its lookup limit" | multiple records; syntax error; static tree exceeds ten DNS-querying terms or two void lookups; include or redirect has no single SPF record | recognized complete valid tree within the limits | missing or unknown evidence without an observed error; observed errors may fire on an incomplete tree, whose counts say "at least" | low | email |
| `email.spf_undeclared_sender`: "SPF includes a service absent from the declared senders" | recognized positive include can grant a pass and maps to a service not declared for that domain; at least one sender is declared | mapped service is declared, or complete valid evidence has no includes or unmapped terms to compare | no senders declared; incomplete or invalid tree; unmapped include or literal IP range (listed, not judged) | low | email |
| `email.dkim_missing`: "A declared DKIM selector has no usable published key" | NXDOMAIN or NODATA; no DKIM key record; revoked empty `p=` | one recognized public key | lookup failure, marked evidence, multiple keys or unparseable key; no declared selector is "no selector given", never "missing" | low | email |
| `email.dkim_key_breakable`: "A DKIM RSA key is shorter than 1024 bits" | recognized RSA modulus under 1024 bits | RSA at least 1024 bits or recognized Ed25519 key | as `email.dkim_missing`, including missing or revoked key | high | email |
| `email.dkim_key_1024`: "A DKIM RSA key is 1024-bit" | recognized RSA modulus exactly 1024 bits | recognized RSA of another size or Ed25519 key | as `email.dkim_key_breakable` | info | email |

Legacy `pct` must contain one to three ASCII digits and be from 0 to 100
(RFC 7489 §6.4); other values leave the policy unrecognized.
`email.dmarc_not_enforced` and `email.dmarc_partial` cannot both fire. The partial
and subdomain-policy rules are not applicable when the domain has no enforcing policy. A test-mode
`p=reject` or legacy `pct=0; p=reject` can still request quarantine; the report never
calls either "no quarantine or rejection". No-mail domains use
`email.no_mail_spoofable` instead of the three sending-domain DMARC rules. A confirmed
defect on one side of a no-mail policy may fire while the other is unknown, retaining
the gap so coverage stays partial.

SPF is a static review of reachable configuration, not an evaluation for a particular
sender. Record syntax is checked even after `all`, but valid mechanisms after it are
ignored; known modifier syntax is validated even when the modifier is ignored.
Qualifiers are honored; a negative include of an all-passing child ends the path.
Otherwise an earlier nonpositive mechanism leaves later grants uncertain
(`unavailable:spf_path`), since this review cannot establish whether the earlier
mechanism matches a sender. An unknown or erroneous child likewise prevents
conclusions about authorization later on that path. Lookup-limit findings say the tree *can* exceed a limit, never that every
message does. `a`, `mx`, `ptr` and `exists` count without address evaluation; macros
remain unknown. `~all` alone is never a finding. A mapped provider's internal include
tree is not treated as another business service to declare.

The exact include-to-service table (`SenderTableVersion` `2026-10-09.1`, reviewed
`2026-10-09`) is:

| Service | Exact includes | Accepted declaration aliases | Source |
|---|---|---|---|
| `google-workspace` | `_spf.google.com` | `google workspace`, `g suite`, `gsuite` | [Google](https://support.google.com/a/answer/33786) |
| `microsoft-365` | `spf.protection.outlook.com`, `spf.protection.office365.us`, `spf.protection.partner.outlook.cn` | `microsoft 365`, `office 365`, `office365` | [Microsoft](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure) |
| `sendgrid` | `sendgrid.net` | `twilio sendgrid` | [Twilio](https://www.twilio.com/docs/sendgrid/ui/sending-email/verify-sender-with-spf) |
| `amazon-ses` | `amazonses.com` | `amazon ses`, `aws ses` | [Amazon](https://docs.aws.amazon.com/ses/latest/dg/mail-from.html) |

Service names compare without case and surrounding whitespace; there is no fuzzy
match. Unmapped includes and literal `ip4`/`ip6` grants are listed as not compared.
DKIM strength requires a decoded RSA public key (PKIX or PKCS#1 DER) with positive
modulus and an odd exponent at least three, or exactly 32 decoded bytes for Ed25519.
A published key does not show that the selector signs current mail.

The report's `mail_context` notes show declarations or inferred mail use, alignment
(`adkim`, `aspf`, including default relaxed values), and whether an aggregate-report
destination is present, never its address. They state that actual message alignment,
delivery and current selector use were not assessed. The DMARC note says coverage is
limited to the DNS records read, including legacy `pct` percentages: receivers may
discover or apply policies differently, and actual mail handling was not tested.
Missing senders and selectors stay coverage gaps, with the domain and service named
even in default text coverage. A declared no-mail domain with recognized
SPF authorization, a non-null MX or a published DKIM key gets a context note, not a
separate finding.

### TLS and certificate

| Rule | Fires | Disproved | Abstains | Base | Area |
|---|---|---|---|---|---|
| `tls.certificate_invalid`: "The certificate for *name* is *expired / for another name / not from a trusted issuer / missing its intermediate*" | the gate's typed verification class | verified | no handshake; an unclassified error; an issuer on the TLS-interception list, worded "your network inspects TLS, so certificates were not judged"; the name is a takeover candidate, which subsumes it | low | external |
| `tls.certificate_expiring`: "The certificate for *name* expires in *n* days; confirm renewal is working" | valid, with 14 days or fewer left at collection; proximity alone does not prove renewal is failing | more than 14 days left | as `tls.certificate_invalid` | info | external |
| `tls.legacy_only`: "*name* did not negotiate TLS 1.2 or later" | the name's one handshake, at TLS 1.2 or later, gets a `protocol_version` alert | it succeeds | `handshake_failure` or any other alert (`unavailable:tls_handshake`); an issuer on the TLS-interception list. The handshake is never retried at a lower version | low | external |

A missing intermediate is worded "browsers may recover, but clients that do not fetch
intermediates may fail." scheck fetches no intermediate from the certificate's AIA URL,
on any platform ([scope.md](scope.md#connections)). When the gate could read no root
certificate, every verification failure is classed `unclassified`, so the certificate
rules abstain on every name.

**The TLS-interception list** is versioned data in the tree: the issuers of products
that inspect TLS on the operator's network (Zscaler, Netskope, Fortinet, Palo Alto,
Cisco Umbrella, Sophos, Kaspersky, ESET, Avast, Bitdefender). A chain from one makes
every certificate rule abstain for that name. A wildcard takeover candidate also
subsumes certificate judgments on the concrete wildcard-control hostname.

### Headers and cookies

Declared or first-party sites, except where a row says every read name. Built in
E7 step 4: the three TLS and eight web rules below. E7 step 5 adds
`web.restricted_reachable`. Each requires its subject kind in an acceptance.

HSTS parses the complete syntax of the first header field: duplicate directives,
invalid tokens or values, and valued `includeSubDomains` or `preload` are invalid.
Quoted decimal values decode HTTP quoted-pairs literally, not Go escape sequences.
A valid policy on any observed HTTPS entry disproves the origin finding. Security
headers require recognized values, including supported CSP source grammar; an
unknown CSP source or marked header makes its protection unknown, never present.
Nonce and hash sources require a nonempty base64-value payload.
Password inputs and generator metadata are read from active HTML tags, excluding
comments and inert script, style, nested template and text containers. Cookie
attribute names are trimmed and compared by name: assigned `Secure` and `HttpOnly`
attributes still count, including retained `Secure=true`.
A correctly flagged cookie does not disprove the cookie rule for the origin: the
login flow was not read. Session-like names were seen in anonymous responses; their
authentication role was not verified. A password input is observed without submitting
any form, and its page supplies the evidence for the severity attribute. Attribute
tokens are parsed whole; text inside a malformed quoted attribute never invents a
password field. HTML tag names end at ASCII HTML whitespace or a slash, for opening
and closing tags alike; slash-delimited attributes do not hide active password
inputs or inert containers. Only a nested template increases the inert template depth.
Raw-text and RCDATA closing tags are recognized before ordinary comment or attribute
parsing, including inside templates. Script escaped and double-escaped states follow
the HTML Standard: text inside them stays inert, and content after the real closing
tag can supply a generator or password input.

Secret findings use only detector hits with the gate's trusted redaction provenance,
never marker-shaped text supplied by a page. A marked body blocks negative secret
claims. `security.txt` must be HTTPS plain text with a usable Contact URI and a single
parseable future Expires; Canonical, when present, must include the read URL.
Malformed or unrecognized fields that prevent this judgment leave coverage unknown.
A cleartext-signed file is parsed for its contact fields; signature trust and contact
delivery are not checked. Malformed `mailto:` and `tel:` contacts never validate.
A trusted 404 is absence evidence both when sent and when reused on resume.

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
| `web.restricted_reachable`: "*url*, which you said is reachable only from *audience*, answered from the internet" | the vantage is `internet`, the declared audience is not, and the response is a 2xx, a 401, or a 3xx to a login page on the same site or an identity provider | refused or timed out from the `internet` vantage, worded "did not answer from here; scheck cannot tell a firewall from a server that is down" | the vantage is not `internet` or not given; 403, 404 or 429; blocked; 5xx; an invalid or intercepted certificate; policy refusal; unrecognized redirect | medium, +1 `contradiction`: high | external | no; validation also refuses one URL under both `intent` lists |

**Restricted reachability (E7 step 5).** The subject is the exact canonical URL in
`intent.not_exposed`, using only its original response, never a redirect destination's
response. Canonical escaped paths are retained through ordinary entry reads,
redirect-hop admission and judgment, including reserved characters encoded in a
path segment. `internet` declares that this invocation comes from outside every
permitted source, including office allowlists and VPN. A successful response establishes outside
reachability, not a bypass of authentication. The medium base gains the declaration's
`contradiction` raise to high; exposed-on-purpose never lowers it. The report identifies
this as a multi-fact rule and prints the exact URL/audience declaration and declared
`--vantage` alongside the observation.

A same-origin redirect keeps the original scheme, host and port and is recognized
only when a path segment is `login`, `signin`, `sign-in` or `log-in`.
`LoginRedirectVersion` (`2026-10-09.1`) pins a minimal identity provider list:
HTTPS on the default port at `accounts.google.com/o/oauth2/auth` or
`/o/oauth2/v2/auth`, and `login.microsoftonline.com/<tenant>/oauth2/authorize` or
`/<tenant>/oauth2/v2.0/authorize`. These destinations are inspected, never contacted
by this rule. A connection refusal or timeout disproves the contradiction from this
vantage with the outage caveat; a gate refusal or other transport failure does not.

**Preloaded TLDs.** `PreloadedTLDs` is versioned data in the tree, taken from
Chromium's `net/http/transport_security_state_static.json`, pinned to a commit and
dated: the entries that are a single label, with mode `force-https`,
`include_subdomains` true and a policy other than `test`. Known members include `app`,
`dev`, `page`, `bank`, `insurance` and `foo`; the rest come only from the pinned file.
Step 4 embeds 51 TLDs in `data/preloaded_tlds.txt`, version `2026-10-09.1`, from
Chromium commit `d5e6fd51b430fec89732a3976e666011ecffa0a2` (`2026-09-11`). The
local `scripts/preloaded_tlds.py` reads the pinned input; it sends no request. The list
is part of `rules_version`, refreshed each release, and a test pins its commit header.
The inspection issuers, session names and block markers share version `2026-10-09.1`.
Only a name's own last label counts, in punycode, never a CNAME target's. An apex preloaded on
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
  text is in [report.md](report.md#coverage) ("Reason wording"). The report
  never praises the protection and never advises turning it off.

## Reachability and vantage

Whether something is reachable depends on where the request came from. `scheck run
--vantage internet|vpn|lan` records the run's vantage in the run, not in the file. A
`not_exposed` rule fires only when the run's vantage is `internet` and the declared
audience is not `internet`; every other combination, and an unknown vantage, abstains.
`/admin` declared VPN-only and reached from the VPN is not a contradiction; from the
`internet` vantage, a connection refusal or timeout disproves the contradiction
with an outage caveat, rather than making that restricted read incomplete ([web-collector.md](web-collector.md#headers-and-cookies),
`web.restricted_reachable`). The vantage is the operator's word, declared separately
on each invocation; omission
means unknown, including on resume. `internet` means outside every permitted source,
including office allowlists and VPN. scheck does not detect or verify it, and asks no
external service for an egress address. It is printed in the report
header and recorded on each piece of evidence like the principal, DNS evidence
included; a resume with a different vantage reads those names and entry points again.
A run whose file lists `intent.not_exposed` and that has no `--vantage` warns at its
start that those URLs will not be checked for reachability; it does not refuse to run.

## Subjects

Each finding is one record per `{id, asset, subject}`
([report.md](report.md#findings)). A key is lowercase, with punycode A-labels,
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
| `spf_mechanism` | `<domain>/include:<target>`, the target lowercase with no trailing dot; dotted and undotted spellings deduplicate to one subject and acceptance key | `email.spf_undeclared_sender` |

A finding's asset is the most specific asset that holds its subject. A `dns_name`'s is
the name's own id (`domain:<name>`), declared or not, and the root for the root itself
and for a name the engagement file cannot name as an asset (one holding an underscore
label, or one redaction marked); a `dns_record`'s is that of the domain whose records
were read (the root for its NS, the mail domain for its MX and its whole SPF tree). An
`origin` belongs to the same-origin declared `/` URL asset when there is one, otherwise
to the deepest declared path on that origin (lexical asset id breaks a tie). A `url`
belongs to the longest declared path containing it. Without a declared URL owner,
both belong to the name's id; an email
finding to the domain root the mail domain falls under. Acceptances and assessments go
by that asset, and an undeclared name's findings print the name as their asset and its
canonical id as the paste's `asset` ([report.md](report.md#findings), "The
paste"). An acceptance covers its own asset's instances only, never those of a name
under it ([report.md](report.md#findings), "Acceptances"). The DNS finding
definitions, including both takeover findings, declare `Subject: "dns_name"`, so an
acceptance must name its subject; record findings still use their `dns_record` key.
All email definitions likewise require their tabled subject kind in an acceptance.
Email findings remain on the most specific domain root holding the mail domain, even
when that mail domain is also a declared asset. A missing selector has a coverage-only
key `<domain>/no-selector`; sender-comparison gaps use `<domain>/SPF` or
`<domain>/unmapped`, never an invented include finding.

On an asset a network collector judged (a domain root and the names under it), acceptance is per instance and by the finding's asset
([web-collector.md](web-collector.md#subjects)): the entry in effect for an instance is
the last one for its asset and id that names its subject or none, and an entry that
later entries displace on every instance it touches is `not_applied`, with that reason.
An entry covers its own asset's instances only. When its asset holds no instance of its
id (with its subject, when it names one) and a name under it, a `domain:` asset of its
own, holds one that no unexpired entry of its own accepts, the outcome is `rule_not_decided` with
"an instance is open under it, on *name*, which is its own asset: accept it there
(asset: domain:*name*)", never `not_matched` or `subject_not_found`. A `domain:` name
under a root the collector read was read with it, declared or not, so an entry that
names a subject on a name now gone is `subject_not_found` only when the applicable
population on the owning asset and collector is complete; an unrelated asset's
incomplete collection does not change that population. Incomplete or unknown evidence
there gives `rule_not_decided`. For a complete population the message is "nothing
with that subject points anywhere on this run: if the record was removed, remove the entry", never "the
asset was not read on this run". When that subject was read on a name under the entry's
asset, it is `subject_not_found` with "that subject was read on *name*, which is its own
asset (asset: domain:*name*)".

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
([report.md](report.md#coverage)):

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
| `email.spf_permits_anyone` | Remove `+all` or bare `all`; replace broad IP ranges with the exact sender ranges documented by the mail services. |
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
