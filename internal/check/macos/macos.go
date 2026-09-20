// Package macos registers the macOS check catalog (SPEC.md §3 baseline table).
package macos

import "github.com/b87/scheck/internal/check"

const socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"

func base(id, desc string, domain check.Domain, parser check.ParserKind, argv ...string) check.Check {
	return check.Check{ID: id, Description: desc, Platform: check.MacOS, Domain: domain, Parser: parser, Baseline: true, Argv: argv}
}

func elevated(c check.Check) check.Check { c.Elevated = true; return c }

func exitOK(c check.Check, codes ...int) check.Check { c.ExitOK = codes; return c }

func extract(c check.Check, re string) check.Check { c.Extract = re; return c }

func output(c check.Check, n int) check.Check { c.Budget.Output = n; return c }

func init() {
	check.Register(
		// OS / host
		base("os.release", "macOS product name, version and build", check.DomainOS, check.ParseKV, "sw_vers"),
		extract(base("host.platform_uuid", "IOPlatformUUID (hashed into host.id)", check.DomainHost, check.ParseRaw, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice"),
			`"IOPlatformUUID" = "([0-9A-Fa-f-]+)"`),

		// Pending updates
		base("pkg.softwareupdate", "Pending macOS software updates (cached scan)", check.DomainUpdates, check.ParseLines, "softwareupdate", "-l", "--no-scan"),

		// Disk encryption
		base("disk.fdesetup", "FileVault status", check.DomainDisk, check.ParseRaw, "fdesetup", "status"),

		// Integrity
		base("integrity.csrutil", "System Integrity Protection status", check.DomainIntegrity, check.ParseRaw, "csrutil", "status"),
		exitOK(base("integrity.spctl", "Gatekeeper assessment status", check.DomainIntegrity, check.ParseRaw, "spctl", "--status"), check.AnyExit...),

		// Firewall
		base("fw.global", "Application firewall global state", check.DomainFirewall, check.ParseRaw, socketfilterfw, "--getglobalstate"),
		base("fw.blockall", "Application firewall block-all-incoming state", check.DomainFirewall, check.ParseRaw, socketfilterfw, "--getblockall"),
		base("fw.stealth", "Application firewall stealth mode", check.DomainFirewall, check.ParseRaw, socketfilterfw, "--getstealthmode"),

		// Listening sockets
		exitOK(base("net.listeners", "Listening TCP sockets with owning process", check.DomainNetwork, check.ParseLines, "lsof", "-nP", "-iTCP", "-sTCP:LISTEN"), 0, 1),

		// sshd
		elevated(base("sshd.config", "Effective sshd configuration", check.DomainSSHD, check.ParseKV, "sshd", "-T")),

		// Accounts
		base("accounts.users", "Local accounts with their UniqueID", check.DomainAccounts, check.ParseLines, "dscl", ".", "-list", "/Users", "UniqueID"),
		base("accounts.admins", "Members of the admin group", check.DomainAccounts, check.ParseRaw, "dscl", ".", "-read", "/Groups/admin", "GroupMembership"),

		// Privilege escalation
		elevated(base("privesc.sudoers", "sudoers policy", check.DomainPrivesc, check.ParseLines, "cat", "/etc/sudoers")),
		elevated(exitOK(base("privesc.sudoers_d", "sudoers.d drop-ins (file:line, non-empty lines)", check.DomainPrivesc, check.ParseLines, "grep", "-rH", ".", "/etc/sudoers.d"), 0, 1, 2)),

		// Remote access
		elevated(base("remote.login", "Remote Login (sshd) setting", check.DomainRemoteAccess, check.ParseRaw, "systemsetup", "-getremotelogin")),
		output(base("remote.launchd_disabled", "launchd service overrides in the system domain (screensharing, RemoteDesktop, ftpd, smbd ...)", check.DomainRemoteAccess, check.ParseLines, "launchctl", "print-disabled", "system"), 16<<10),

		// Persistence
		base("persist.launchctl", "Loaded launchd jobs in the session domain", check.DomainPersistence, check.ParseLines, "launchctl", "list"),
		exitOK(base("persist.launch_dirs", "Third-party LaunchDaemons and LaunchAgents", check.DomainPersistence, check.ParseLines, "find", "/Library/LaunchDaemons", "/Library/LaunchAgents", "-maxdepth", "1", "-type", "f"), 0, 1),

		// SUID / world-writable
		exitOK(base("fs.suid", "SUID binaries under local prefixes (depth-capped)", check.DomainFS, check.ParseLines,
			"find", "/usr/local", "/opt", "-xdev", "-maxdepth", "4", "-type", "f", "-perm", "-4000"), 0, 1),
		exitOK(base("fs.world_writable", "World-writable entries without the sticky bit under system prefixes (depth-capped)", check.DomainFS, check.ParseLines,
			"find", "/usr/local", "/opt", "/etc", "/Library/LaunchDaemons", "/Library/LaunchAgents", "-xdev", "-maxdepth", "4", "-perm", "-0002", "-not", "-perm", "-1000", "-not", "-type", "l"), 0, 1),

		// Logging
		elevated(base("log.status", "Unified logging configuration", check.DomainLogging, check.ParseRaw, "log", "config", "--status")),

		// Time sync
		elevated(base("time.ntp", "Network time synchronisation setting", check.DomainTime, check.ParseRaw, "systemsetup", "-getusingnetworktime")),
	)
}
