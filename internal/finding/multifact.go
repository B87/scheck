package finding

// Finding ids of the engagement's multi-fact rules over a host's facts
// (docs/spec/engagement.md, "The multi-fact rules of 0.0.2"). Their rules
// live in internal/engagement/rules; these definitions give each finding
// its title, area, base severity, impact and fix.
const (
	IDDBListensUnfiltered = "db.listens_unfiltered"
)

var multiFactDefs = []Def{
	{ID: IDDBListensUnfiltered, Title: "A database listens beyond localhost and the host firewall does not restrict it",
		Category: CategoryNetwork, Area: AreaData, Exposure: NotExposure, Subject: "service", MultiFact: true,
		Judges:       "databases listening beyond localhost with no host firewall rule in front",
		BaseSeverity: SevMedium, Ceiling: SevHigh, HostAccess: true,
		Impact: "The database accepts connections on an address other than localhost, and the host firewall does not " +
			"restrict that port, so anything that can reach the host on that port can try to sign in to the " +
			"database. Whether a cloud firewall or security group blocks it was not assessed, and the database's own " +
			"sign-in rules were not read.",
		Remediation: Remediation{
			Summary: "If only this host uses the database, bind it to localhost and restart it. If other machines need it, " +
				"allow the port only from their addresses. Check your cloud firewall rules too: scheck did not read them.",
			Commands: []string{
				"# only this host uses it: bind it to localhost, then restart the database",
				"#   postgres: listen_addresses = 'localhost'",
				"#   MySQL/MariaDB: bind-address = 127.0.0.1",
				"#   Redis: bind 127.0.0.1",
				"# other machines need it: allow only their addresses",
				"sudo ufw default deny incoming",
				"sudo ufw allow from 10.0.0.5 to any port 5432 proto tcp",
			},
			Caveat: "If ufw lets the port in by source port alone (from any port 53), delete that rule (ufw status numbered, " +
				"then ufw delete N): ufw already lets in replies to the host's own DNS queries through connection tracking, " +
				"so a source-port rule is not needed.",
		}},
}

func init() {
	for _, d := range multiFactDefs {
		Register(d)
	}
}
