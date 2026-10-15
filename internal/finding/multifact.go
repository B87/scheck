package finding

// Finding ids of the engagement's multi-fact rules over a host's facts
// (docs/spec/engagement.md, "The multi-fact rules of 0.0.2"). Their rules
// live in internal/engagement/rules; these definitions give each finding
// its title, area, base severity, impact and fix.
const (
	IDDBListensUnfiltered = "db.listens_unfiltered"
	IDEmptyPasswordRemote = "accounts.empty_password_remote"
	IDSvcListensBeyond    = "svc.listens_beyond_declared"
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
	{ID: IDEmptyPasswordRemote, Title: "An account with no password can log in over SSH",
		Category: CategoryRemoteAccess, Area: AreaHosts, Exposure: NotExposure, MultiFact: true,
		Judges: "accounts with no password that SSH lets in",
		// No host context step moves it: an account sshd lets in with an
		// empty password is usable by anyone who reaches sshd, whatever the
		// environment (docs/spec/engagement.md, R2).
		BaseSeverity: SevCritical, HostAccess: true,
		Impact: "These accounts have an empty password and a login shell, and sshd is set to accept an empty password " +
			"and listens beyond this host, so anyone who can reach sshd can sign in as them with no credential, and " +
			"become root if the account is root.",
		Remediation: Remediation{
			Summary: "Lock or set a password for these accounts, and set PermitEmptyPasswords no in sshd_config, then reload sshd.",
			Commands: []string{
				"sudo passwd -l <account>",
				"# in /etc/ssh/sshd_config: PermitEmptyPasswords no",
				"sudo sshd -t && sudo systemctl reload ssh || sudo systemctl reload sshd",
				"sudo sshd -T | grep -i permitemptypasswords",
			},
			Caveat: "Find out what each account is for before you lock it; locking stops password logins only.",
		}},
	{ID: IDSvcListensBeyond, Title: "A service listens beyond the audience you declared",
		Category: CategoryNetwork, Area: AreaExternal, Exposure: NotExposure, Subject: "service", MultiFact: true,
		Judges: "declared services listening beyond their audience",
		// It fires only against a declaration, so contradiction always
		// raises it: medium, high on an internet-facing host
		// (docs/spec/engagement.md, R3).
		BaseSeverity: SevLow, Ceiling: SevHigh,
		Impact: "The service listens on an address beyond the audience you declared for it, and the host firewall does " +
			"not restrict that port, so machines outside that audience can try to connect to it. Whether a cloud " +
			"firewall or security group blocks it was not assessed, and whether the service asks for a password or " +
			"key was not read.",
		Remediation: Remediation{
			Summary: "If only this host uses it, bind it to 127.0.0.1 and restart it; if it serves your LAN or VPN, bind it to " +
				"that interface's address instead of all addresses. Or allow the port only from the addresses that need it. " +
				"If Docker publishes it, publish it on 127.0.0.1 or the private address: Docker's rules bypass ufw. Check " +
				"your cloud firewall rules too: scheck did not read them. If the wider audience is intended, correct " +
				"expected_services.",
			Commands: []string{
				"# only this host uses it: bind it to 127.0.0.1 in its configuration, then restart it",
				"# or allow only the addresses that need it",
				"sudo ufw default deny incoming",
				"sudo ufw allow from 10.0.0.0/24 to any port 8080 proto tcp",
				"# Docker: publish on loopback, -p 127.0.0.1:8080:8080",
			},
		}},
}

func init() {
	for _, d := range multiFactDefs {
		Register(d)
	}
}
