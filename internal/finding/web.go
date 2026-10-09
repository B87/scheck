package finding

// Finding ids of the domain, email and web collector
// (docs/spec/web-collector.md, "Rules"). Its rules live with the collector,
// which judges its own evidence; these definitions give each finding its
// title, area, base severity, impact and fix.
const (
	IDTLSCertificateInvalid    = "tls.certificate_invalid"
	IDTLSCertificateExpiring   = "tls.certificate_expiring"
	IDTLSLegacyOnly            = "tls.legacy_only"
	IDWebRestrictedReachable   = "web.restricted_reachable"
	IDWebHSTSMissing           = "web.hsts_missing"
	IDWebPlaintextHTTP         = "web.plaintext_http"
	IDWebPlaintextHTTPClients  = "web.plaintext_http_clients"
	IDWebSessionCookieFlags    = "web.session_cookie_flags"
	IDWebSecurityHeaders       = "web.security_headers"
	IDWebVersionDisclosed      = "web.version_disclosed"
	IDWebSecretInResponse      = "web.secret_in_response" // #nosec G101 -- catalog finding id, not a credential.
	IDWebSecurityTXT           = "web.security_txt"
	IDEmailDMARCNotEnforced    = "email.dmarc_not_enforced"
	IDEmailDMARCPartial        = "email.dmarc_partial"
	IDEmailDMARCSubdomainsOpen = "email.dmarc_subdomains_open"
	IDEmailNoMailSpoofable     = "email.no_mail_spoofable"
	IDEmailSPFPermitsAnyone    = "email.spf_permits_anyone"
	IDEmailSPFMissing          = "email.spf_missing"
	IDEmailSPFInvalid          = "email.spf_invalid"
	IDEmailSPFUndeclaredSender = "email.spf_undeclared_sender"
	IDEmailDKIMMissing         = "email.dkim_missing"
	IDEmailDKIMKeyBreakable    = "email.dkim_key_breakable"
	IDEmailDKIMKey1024         = "email.dkim_key_1024"
	IDDNSTakeoverCandidate     = "dns.takeover_candidate"
	IDDNSUnclaimedAtProvider   = "dns.unclaimed_at_provider"
	IDDNSDanglingExternal      = "dns.dangling_external"
	IDDNSDanglingInternal      = "dns.dangling_internal"
	IDDNSPrivateAddress        = "dns.private_address"
)

// CategoryDNS is the category of the DNS findings.
const CategoryDNS = "dns"

const CategoryEmail = "email"

var webDefs = []Def{
	{ID: IDWebRestrictedReachable, Title: "A URL declared restricted answered from the internet", Category: "web", Area: AreaExternal, Exposure: NotExposure, Subject: "url", Judges: "declared restricted URL reachability", BaseSeverity: SevMedium, Impact: "The endpoint answered from a source declared outside every permitted network. A login page or 401 still means it is reachable; authenticated access and login bypass were not tested.", Remediation: Remediation{Summary: "Restrict access at the reverse proxy, gateway or firewall to the intended network. Repeat this check from outside every permitted source, including office allowlists and VPN."}},
	{ID: IDTLSCertificateInvalid, Title: "The certificate failed verification", Category: "tls", Area: AreaExternal, Exposure: NotExposure, Subject: "dns_name", Judges: "The certificate failed verification", BaseSeverity: SevLow, Impact: "The served certificate is expired, for another name, untrusted, or may lack an intermediate. Browser recovery and other clients can differ.", Remediation: Remediation{Summary: "Renew or reissue the certificate for this name; for a missing intermediate, serve the full chain."}},
	{ID: IDTLSCertificateExpiring, Title: "The certificate expires within 14 days", Category: "tls", Area: AreaExternal, Exposure: NotExposure, Subject: "dns_name", Judges: "The certificate expires within 14 days", BaseSeverity: SevInfo, Impact: "Expiry is approaching. Short-lived certificates can renew normally within this window; renewal success was not checked.", Remediation: Remediation{Summary: "Confirm automatic renewal is working and monitor the replacement certificate."}},
	{ID: IDTLSLegacyOnly, Title: "The site did not negotiate TLS 1.2 or later", Category: "tls", Area: AreaExternal, Exposure: NotExposure, Subject: "dns_name", Judges: "The site did not negotiate TLS 1.2 or later", BaseSeverity: SevLow, Impact: "The offered TLS 1.2-or-later handshake was rejected for its protocol version. This does not establish which older versions the server accepts.", Remediation: Remediation{Summary: "Configure the endpoint to support TLS 1.2 or later, then check current-client compatibility."}},
	{ID: IDWebHSTSMissing, Title: "The origin does not tell browsers to always use HTTPS (HSTS)", Category: "web", Area: AreaWeb, Exposure: NotExposure, Subject: "origin", Judges: "The origin does not tell browsers to always use HTTPS (HSTS)", BaseSeverity: SevLow, Impact: "Without a recognized HSTS policy browsers may initially use HTTP for this origin.", Remediation: Remediation{Summary: "Set Strict-Transport-Security: max-age=31536000 on HTTPS responses. Add includeSubDomains only after checking all subdomains support HTTPS."}},
	{ID: IDWebPlaintextHTTP, Title: "The origin serves plain HTTP instead of redirecting to HTTPS", Category: "web", Area: AreaWeb, Exposure: NotExposure, Subject: "origin", Judges: "The origin serves plain HTTP instead of redirecting to HTTPS", BaseSeverity: SevLow, Impact: "Clients configured for HTTP can send and receive unencrypted data.", Remediation: Remediation{Summary: "Redirect HTTP entry points to HTTPS, or close port 80."}},
	{ID: IDWebPlaintextHTTPClients, Title: "The origin still serves plain HTTP to scripts and API clients", Category: "web", Area: AreaWeb, Exposure: NotExposure, Subject: "origin", Judges: "The origin still serves plain HTTP to scripts and API clients", BaseSeverity: SevInfo, Impact: "Browsers force HTTPS for this preloaded domain ending, but clients explicitly configured for HTTP can send requests unencrypted.", Remediation: Remediation{Summary: "Redirect port 80 to HTTPS, or close it."}},
	{ID: IDWebSessionCookieFlags, Title: "An observed session cookie lacks Secure or HttpOnly", Category: "web", Area: AreaWeb, Exposure: NotExposure, Subject: "origin", Judges: "An observed session cookie lacks Secure or HttpOnly", BaseSeverity: SevLow, Impact: "A session-like cookie may be readable by scripts or sent without encryption. Names alone do not prove it authenticates a session.", Remediation: Remediation{Summary: "Set Secure and HttpOnly on session cookies, and serve their application over HTTPS."}},
	{ID: IDWebSecurityHeaders, Title: "Entry responses lack some browser security instructions", Category: "web", Area: AreaWeb, Exposure: NotExposure, Subject: "origin", Judges: "Entry responses lack some browser security instructions", BaseSeverity: SevInfo, Impact: "These headers tell browsers how to handle content, framing and referrers. Missing hardening does not prove XSS or clickjacking.", Remediation: Remediation{Summary: "Add the listed instructions at the application or proxy; design and test CSP for the application."}},
	{ID: IDWebVersionDisclosed, Title: "The URL reveals a software version", Category: "web", Area: AreaWeb, Exposure: IsExposure, Subject: "url", Judges: "The URL reveals a software version", BaseSeverity: SevLow, Impact: "The response reveals a software version or build identifier. This does not establish any vulnerability.", Remediation: Remediation{Summary: "Remove unnecessary version details from headers, generator metadata and public version responses."}},
	{ID: IDWebSecretInResponse, Title: "A secret-shaped credential is published in the response", Category: "web", Area: AreaSecrets, Exposure: NotExposure, Subject: "secret_location", Judges: "A secret-shaped credential is published in the response", BaseSeverity: SevCritical, Impact: "The response contains a credential matching a specific secret detector. Validity was not tested; it may already have been copied.", Remediation: Remediation{Summary: "Revoke the credential at its provider first, then remove it from the response and review its use."}},
	{ID: IDWebSecurityTXT, Title: "The origin has no current published security contact", Category: "web", Area: AreaWeb, Exposure: NotExposure, Subject: "origin", Judges: "The origin has no current published security contact", BaseSeverity: SevInfo, Impact: "Someone reporting a security issue may not find a current contact at the standard location.", Remediation: Remediation{Summary: "Publish HTTPS /.well-known/security.txt with a Contact URI and a future Expires timestamp; keep it current."}},

	{ID: IDEmailDMARCNotEnforced, Title: "DMARC does not request its full enforcement policy", Category: CategoryEmail, Area: AreaEmail, Exposure: NotExposure, Subject: "mail_domain", Judges: "DMARC enforcement", BaseSeverity: SevMedium, Impact: "Mail that fails authentication is not subject to the full published DMARC policy. Receivers choose how to handle it; DNS does not prove what they deliver.", Remediation: Remediation{Summary: "If no policy exists, publish v=DMARC1; p=none with an aggregate reporting mailbox. Review two to four weeks of reports and confirm every sender passes before moving to quarantine, then reject. For an existing policy, finish that review before removing testing or sampling."}},
	{ID: IDEmailDMARCPartial, Title: "DMARC publishes a partial percentage for legacy receivers", Category: CategoryEmail, Area: AreaEmail, Exposure: NotExposure, Subject: "mail_domain", Judges: "DMARC sampling", BaseSeverity: SevLow, Impact: "The published pct value asks legacy receivers to apply the policy to only some failing mail. Current DMARC receivers may ignore this historic tag.", Remediation: Remediation{Summary: "Verify each legitimate sender in DMARC reports, then remove pct or set it to 100."}},
	{ID: IDEmailDMARCSubdomainsOpen, Title: "DMARC leaves subdomains without a requested enforcement policy", Category: CategoryEmail, Area: AreaEmail, Exposure: NotExposure, Subject: "mail_domain", Judges: "DMARC subdomain policy", BaseSeverity: SevLow, Impact: "The domain requests enforcement for itself but publishes sp=none or np=none for subdomains. A subdomain may publish its own policy; those policies were not all checked.", Remediation: Remediation{Summary: "Inventory subdomain senders, then set sp=reject and remove np=none after confirming their mail authenticates."}},
	{ID: IDEmailNoMailSpoofable, Title: "A domain with no mail use lacks a full no-mail policy", Category: CategoryEmail, Area: AreaEmail, Exposure: NotExposure, Subject: "mail_domain", Judges: "no-mail policy", BaseSeverity: SevLow, Impact: "The domain does not publish both SPF denial and a full DMARC rejection policy. Receivers lack that explicit instruction for mail claiming to come from it.", Remediation: Remediation{Summary: "Confirm the domain sends no mail, then publish v=spf1 -all and v=DMARC1; p=reject, and a null MX (MX 0 .)."}},
	{ID: IDEmailSPFPermitsAnyone, Title: "SPF authorizes any sender or a very broad address range", Category: CategoryEmail, Area: AreaEmail, Exposure: NotExposure, Subject: "mail_domain", Judges: "SPF authorization", BaseSeverity: SevHigh, Impact: "The published SPF policy grants a passing result to any address or to a very broad range. SPF checks the envelope sender; whether mail aligns with the visible From address was not assessed.", Remediation: Remediation{Summary: "Remove +all or bare all and replace broad IP ranges with the exact sender ranges documented by your mail services."}},
	{ID: IDEmailSPFMissing, Title: "A mail domain publishes no SPF record", Category: CategoryEmail, Area: AreaEmail, Exposure: NotExposure, Subject: "mail_domain", Judges: "SPF presence", BaseSeverity: SevLow, Impact: "Receivers cannot use SPF to check which servers may send with this envelope domain. DKIM may still authenticate mail.", Remediation: Remediation{Summary: "Publish one SPF record covering all legitimate senders, using each service’s documented include or IP ranges."}},
	{ID: IDEmailSPFInvalid, Title: "SPF contains an error or can exceed its lookup limit", Category: CategoryEmail, Area: AreaEmail, Exposure: NotExposure, Subject: "mail_domain", Judges: "SPF validity", BaseSeverity: SevLow, Impact: "The observed error can prevent SPF authentication. Lookup counts describe the static include tree; actual evaluation depends on the sender and the path it takes.", Remediation: Remediation{Summary: "Keep one syntactically valid SPF record, repair broken includes and redirects, and reduce DNS-querying terms to at most ten on each evaluation path. Check with your mail providers before removing a sender."}},
	{ID: IDEmailSPFUndeclaredSender, Title: "SPF includes a service absent from the declared senders", Category: CategoryEmail, Area: AreaEmail, Exposure: NotExposure, Subject: "spf_mechanism", Judges: "declared SPF senders", BaseSeverity: SevLow, Impact: "SPF includes a recognized sending service that was not listed for this domain. This may be an incomplete declaration or an obsolete authorization; DNS does not show whether the service is still used.", Remediation: Remediation{Summary: "Confirm who owns and uses this sending service. Add it to mail.senders if intended; otherwise remove its include after checking mail delivery."}},
	{ID: IDEmailDKIMMissing, Title: "A declared DKIM selector has no usable published key", Category: CategoryEmail, Area: AreaEmail, Exposure: NotExposure, Subject: "dkim_selector", Judges: "declared DKIM keys", BaseSeverity: SevLow, Impact: "The declared selector has no DKIM key or publishes a revoked key. Mail using this selector cannot be verified with that key; the service may use another selector.", Remediation: Remediation{Summary: "Check s= in a recent message’s DKIM-Signature header, correct the declared selector if stale, or publish the service’s current DKIM record."}},
	{ID: IDEmailDKIMKeyBreakable, Title: "A DKIM RSA key is shorter than 1024 bits", Category: CategoryEmail, Area: AreaEmail, Exposure: NotExposure, Subject: "dkim_selector", Judges: "DKIM key strength", BaseSeverity: SevHigh, Impact: "This RSA key is below the minimum DKIM key size and is weak enough to put signatures at risk of forgery. Whether the selector signs current mail was not checked.", Remediation: Remediation{Summary: "Rotate to a 2048-bit RSA key at your sender, publish its new selector, verify delivery, then retire the old key."}},
	{ID: IDEmailDKIMKey1024, Title: "A DKIM RSA key is 1024-bit", Category: CategoryEmail, Area: AreaEmail, Exposure: NotExposure, Subject: "dkim_selector", Judges: "DKIM key strength", BaseSeverity: SevInfo, Impact: "The key meets the minimum size but is below the recommended 2048 bits. Whether the selector signs current mail was not checked.", Remediation: Remediation{Summary: "Ask the sending service to rotate to a 2048-bit RSA DKIM key and publish its new selector before retiring the old one."}},
	{ID: IDDNSTakeoverCandidate, Title: "A DNS name may be claimable at its provider",
		Category: CategoryDNS, Area: AreaExternal, Exposure: NotExposure, Subject: "dns_name", Judges: "names pointing at a provider with a verified takeover fingerprint",
		BaseSeverity: SevHigh, Impact: "The provider says nothing is set up at the name your DNS points at. Another account may be able to claim it and serve content under your name. This is a candidate, not proof that the name can be claimed.",
		Remediation: Remediation{Summary: "Delete the DNS record today, or restore the service in your provider account; then check whether anyone already served content there."}},
	{ID: IDDNSUnclaimedAtProvider, Title: "A DNS name points at an unconfigured service that checks domain ownership",
		Category: CategoryDNS, Area: AreaExternal, Exposure: NotExposure, Subject: "dns_name", Judges: "names pointing at an unconfigured provider service that checks ownership",
		BaseSeverity: SevLow, Impact: "The provider says nothing is set up there. Its policy requires ownership verification when moving a domain from another account. This binding's ownership was not checked; the record leads to an unconfigured service.",
		Remediation: Remediation{Summary: "Remove the stale DNS record, or finish configuring the domain in your provider account."}},
	{
		ID: IDDNSDanglingExternal, Title: "A DNS record points at a name that does not exist",
		Category: CategoryDNS, Area: AreaExternal, Exposure: NotExposure, Subject: "dns_name", Judges: "records pointing at names that do not exist",
		BaseSeverity: SevMedium,
		Impact: "The record sends visitors, or mail, to a name outside your domains that nobody serves. If someone " +
			"registers that name or claims it at its provider, they receive what was meant for you.",
		Remediation: Remediation{Summary: "Delete the record, or point it at the service's current name."},
	},
	{
		ID: IDDNSDanglingInternal, Title: "A DNS record points at a name under your own domain that does not exist",
		Category: CategoryDNS, Area: AreaExternal, Exposure: NotExposure, Subject: "dns_name", Judges: "records pointing at names that do not exist",
		BaseSeverity: SevInfo,
		Impact: "The record leads nowhere. Only you can create the name it points at, so nobody else can take it, " +
			"but it is a leftover that can confuse the next change.",
		Remediation: Remediation{Summary: "Delete the stale record, or create the name it points at."},
	},
	{
		ID: IDDNSPrivateAddress, Title: "A public name publishes a private address",
		Category: CategoryDNS, Area: AreaExternal, Exposure: NotExposure, Subject: "dns_name", Judges: "public names publishing private addresses",
		BaseSeverity: SevInfo,
		Impact:       "Anyone can read the record, so it tells an outsider part of how your internal network is addressed.",
		Remediation:  Remediation{Summary: "Serve internal names from internal DNS only, or remove the record if it is no longer used."},
	},
}

// WebIDs lists the finding ids the web collector's rules raise, so its
// tests can prove each one fires, is disproved and abstains.
func WebIDs() []string {
	out := make([]string, 0, len(webDefs))
	for _, d := range webDefs {
		out = append(out, d.ID)
	}
	return out
}

func init() {
	for _, d := range webDefs {
		defs[d.ID] = d
	}
}
