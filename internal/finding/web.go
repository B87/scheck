package finding

// Finding ids of the domain, email and web collector
// (docs/spec/web-collector.md, "Rules"). Its rules live with the collector,
// which judges its own evidence; these definitions give each finding its
// title, area, base severity, impact and fix.
const (
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
