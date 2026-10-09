package finding

// Finding ids of the domain, email and web collector
// (docs/spec/web-collector.md, "Rules"). Its rules live with the collector,
// which judges its own evidence; these definitions give each finding its
// title, area, base severity, impact and fix.
const (
	IDDNSDanglingExternal = "dns.dangling_external"
	IDDNSDanglingInternal = "dns.dangling_internal"
	IDDNSPrivateAddress   = "dns.private_address"
)

// CategoryDNS is the category of the DNS findings.
const CategoryDNS = "dns"

var webDefs = []Def{
	{
		ID: IDDNSDanglingExternal, Title: "A DNS record points at a name that does not exist",
		Category: CategoryDNS, Area: AreaExternal, Exposure: NotExposure, Judges: "records pointing at names that do not exist",
		BaseSeverity: SevMedium,
		Impact: "The record sends visitors, or mail, to a name outside your domains that nobody serves. If someone " +
			"registers that name or claims it at its provider, they receive what was meant for you.",
		Remediation: Remediation{Summary: "Delete the record, or point it at the service's current name."},
	},
	{
		ID: IDDNSDanglingInternal, Title: "A DNS record points at a name under your own domain that does not exist",
		Category: CategoryDNS, Area: AreaExternal, Exposure: NotExposure, Judges: "records pointing at names that do not exist",
		BaseSeverity: SevInfo,
		Impact: "The record leads nowhere. Only you can create the name it points at, so nobody else can take it, " +
			"but it is a leftover that can confuse the next change.",
		Remediation: Remediation{Summary: "Delete the stale record, or create the name it points at."},
	},
	{
		ID: IDDNSPrivateAddress, Title: "A public name publishes a private address",
		Category: CategoryDNS, Area: AreaExternal, Exposure: NotExposure, Judges: "public names publishing private addresses",
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
