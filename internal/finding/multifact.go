package finding

// Finding ids of the engagement's multi-fact rules over a host's facts
// (docs/spec/engagement.md, "The multi-fact rules of 0.0.2"). Their rules
// live in internal/engagement/rules; these definitions give each finding
// its title, area, base severity, impact and fix.
const (
	IDDBListensUnfiltered = "db.listens_unfiltered"
	IDEmptyPasswordRemote = "accounts.empty_password_remote"
	IDSvcListensBeyond    = "svc.listens_beyond_declared"
	IDSensitiveListens    = "svc.sensitive_listens_unfiltered"
	// The runtime-version rules over a host's package reads (G8, R7 to R9).
	IDPHPFixMissing       = "php.fix_missing"
	IDNodeFixMissing      = "node.fix_missing"
	IDNodeLineUnsupported = "node.line_unsupported"
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
				"#   Elasticsearch/OpenSearch: network.host: 127.0.0.1 in elasticsearch.yml or opensearch.yml",
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
	{ID: IDSensitiveListens, Title: "A remote-administration service listens beyond localhost and the host firewall does not restrict it",
		Category: CategoryNetwork, Area: AreaExternal, Exposure: NotExposure, Subject: "service", MultiFact: true,
		Judges: "remote-administration services listening beyond localhost with no host firewall rule in front",
		// Medium: the service is reachable, not shown to be usable. Classes
		// with no sign-in by default rank one step higher; the ceiling is
		// high because the cloud firewall and the service's own sign-in were
		// not read (docs/spec/engagement.md, R6).
		BaseSeverity: SevMedium, Ceiling: SevHigh, HostAccess: true,
		Attributes: []AttributeRaise{{Name: "unauthenticated_default", Delta: +1,
			Why: "This kind of service has no sign-in by default, so it ranks one step higher."}},
		Impact: "A service that gives control of the host or its data, or takes a login in clear text, listens on an address " +
			"other than localhost, and the host firewall does not restrict its port, so anything that can reach the host on " +
			"that port can try to use it. Whether a cloud firewall or security group blocks it was not assessed, and whether " +
			"the service asks for a password, a key or a certificate was not read.",
		Remediation: Remediation{
			Summary: "If you do not use it, stop and disable it. If only this host uses it, bind it to 127.0.0.1. Otherwise allow " +
				"its port only from the addresses that need it, or reach it through SSH or a VPN. Check your cloud firewall rules " +
				"too: scheck did not read them.",
			Commands: []string{
				"# stop and disable it if you do not use it",
				"# or bind it to 127.0.0.1 in its configuration, then restart it",
				"# or allow its port only from the addresses that need it, with your host firewall",
			},
			Caveat: "If Docker publishes the port, its rules bypass ufw and firewalld: publish it on 127.0.0.1 instead.",
		}},

	{ID: IDPHPFixMissing, Title: "PHP is missing a security fix for a remote code execution flaw",
		Category: "updates", Area: AreaHosts, Exposure: NotExposure, Subject: "package", MultiFact: true,
		Judges: "whether the installed PHP web packages carry the fix for the October 2026 PHP flaws",
		// Medium: a PHP that is behind is a pending fix. It ranks one step
		// higher when a web server on the host is reachable, and the ceiling
		// is high because the cloud firewall and whether the web server hands
		// requests to this PHP were not read (docs/spec/engagement.md, R7).
		BaseSeverity: SevMedium, Ceiling: SevHigh, HostAccess: true,
		CeilingWhy: "capped at high: whether the cloud firewall lets anyone reach this web server, and whether it passes requests to this PHP, were not read, so scheck cannot say anyone can reach this PHP now.",
		Attributes: []AttributeRaise{{Name: "serves_web", Delta: +1,
			Why: "A web server on this host listens beyond localhost and the host firewall lets any address in, which ranks one step higher."}},
		Impact: "The installed PHP is behind the release of 21 October 2026 that fixes CVE-2026-109618 and CVE-2026-109619, which the " +
			"PHP project rates 9.2 out of 10 and says let anyone who can send a request to PHP run code as the web server's account, " +
			"before your application runs. A complete exploit has been demonstrated against Apache with mod_php; the other ways of " +
			"running PHP are less clearly affected. A distribution's package is compared with that distribution's own fixed package, " +
			"never with PHP's version number. Whether the web server reaches the internet beyond this host's firewall was not assessed.",
		Remediation: Remediation{
			Summary: "Update PHP from the source you installed it from, then restart every PHP process: an installed update does not protect " +
				"workers that were started before it.",
			Commands: []string{
				"sudo apt update && sudo apt upgrade   # Debian, Ubuntu",
				"sudo dnf upgrade 'php*'   # Red Hat family, Fedora",
				"sudo systemctl restart php8.3-fpm   # and Apache or the web server, if PHP runs inside it",
			},
			Caveat: "Until you can update: set session.upload_progress.enabled=0 and post_max_size=8M (32M if you accept uploads) in php.ini or " +
				"the FPM pool, not in .user.ini. These reduce the risk; they do not remove it.",
		}},
	{ID: IDNodeFixMissing, Title: "Node.js is missing a security fix",
		Category: "updates", Area: AreaHosts, Exposure: NotExposure, Subject: "package", MultiFact: true,
		Judges:       "whether the installed Node.js carries the fixes of the October 2026 Node.js security release",
		BaseSeverity: SevMedium, Ceiling: SevHigh,
		Impact: "The installed Node.js is behind the security release of 21 October 2026, which fixed ten flaws. The worst, CVE-2026-111497, " +
			"corrupts memory in the Brotli decoder: an application that decompresses Brotli data an attacker supplies (an HTTP client " +
			"decompressing a response, or a server accepting compressed request bodies) can be crashed or made to run the attacker's code. " +
			"Others weaken TLS hostname checks and DNS lookups. Whether any application on this host decompresses such data was not read.",
		Remediation: Remediation{
			Summary: "Builds from nodejs.org, NodeSource or nvm: install 22.23.4, 24.22.1 or 26.12.1 or later, then restart. Distribution or " +
				"Homebrew Node.js: update the Brotli library (libbrotli1, brew upgrade brotli) and Node.js, then restart. Upgrading Node.js on " +
				"the host does not fix copies built into other things: rebuild Docker images from a fixed base image, and rebuild single " +
				"executable apps and snapshots with a fixed Node.js.",
			Commands: []string{"sudo apt update && sudo apt upgrade   # Debian, Ubuntu: updates libbrotli1 and nodejs", "# restart every Node.js process afterwards"},
		}},
	{ID: IDNodeLineUnsupported, Title: "This Node.js release line no longer receives security fixes",
		Category: "updates", Area: AreaHosts, Exposure: NotExposure, Subject: "package", MultiFact: true,
		Judges:       "whether the installed Node.js release line is still fixed by the Node.js project",
		BaseSeverity: SevMedium, Ceiling: SevHigh,
		Impact: "The Node.js project no longer fixes this release line: it is past its end of life, and the project says end-of-life " +
			"versions are always affected by the flaws it fixes on the lines it still supports (its release of 21 October 2026 fixed ten). " +
			"Flaws found later will not be fixed on this line either.",
		Remediation: Remediation{
			Summary: "Move to a Node.js line the project still fixes (nodejs.org lists them), test your application, and restart it.",
			Caveat:  "A distribution's package of an older line is fixed by the distribution, not by this rule's line.",
		}},
}

func init() {
	for _, d := range multiFactDefs {
		Register(d)
	}
}
