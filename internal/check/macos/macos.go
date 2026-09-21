// Package macos registers the macOS check catalog (docs/SPEC.md §3 baseline table).
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

// unit names what one line or key of a check means, so the fact's reading is
// "3 launchd plists" rather than "3 lines" (docs/SPEC.md §3).
func unit(c check.Check, noun string) check.Check { c.Unit = noun; return c }

func init() {
	check.Register(
		// OS / host
		unit(base("os.release", "macOS product name, version and build", check.DomainOS, check.ParseKV, "sw_vers"), "settings"),
		extract(base("host.platform_uuid", "IOPlatformUUID (hashed into host.id)", check.DomainHost, check.ParseRaw, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice"),
			`"IOPlatformUUID" = "([0-9A-Fa-f-]+)"`),

		// Pending updates
		base("pkg.softwareupdate", "Pending macOS software updates (cached scan)", check.DomainUpdates, check.ParseUpdates, "softwareupdate", "-l", "--no-scan"),

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
		exitOK(base("net.listeners", "Listening TCP sockets with owning process", check.DomainNetwork, check.ParseListeners, "lsof", "-nP", "+c", "0", "-iTCP", "-sTCP:LISTEN"), 0, 1),

		// sshd
		elevated(unit(base("sshd.config", "Effective sshd configuration", check.DomainSSHD, check.ParseKV, "sshd", "-T"), "settings")),

		// Accounts
		base("accounts.users", "Local accounts with their UniqueID", check.DomainAccounts, check.ParseAccounts, "dscl", ".", "-list", "/Users", "UniqueID"),
		base("accounts.admins", "Members of the admin group", check.DomainAccounts, check.ParseRaw, "dscl", ".", "-read", "/Groups/admin", "GroupMembership"),

		// Privilege escalation
		elevated(unit(base("privesc.sudoers", "sudoers policy", check.DomainPrivesc, check.ParseLines, "cat", "/etc/sudoers"), "sudoers lines")),
		elevated(exitOK(unit(base("privesc.sudoers_d", "sudoers.d drop-ins (file:line, non-empty lines)", check.DomainPrivesc, check.ParseLines, "grep", "-rH", ".", "/etc/sudoers.d"), "sudoers.d lines"), 0, 1, 2)),

		// Remote access
		elevated(base("remote.login", "Remote Login (sshd) setting", check.DomainRemoteAccess, check.ParseRaw, "systemsetup", "-getremotelogin")),
		output(unit(base("remote.launchd_disabled", "launchd service overrides in the system domain (screensharing, RemoteDesktop, ftpd, smbd ...)", check.DomainRemoteAccess, check.ParseLines, "launchctl", "print-disabled", "system"), "service overrides"), 16<<10),

		// Persistence
		base("persist.launchctl", "Loaded launchd jobs in the session domain", check.DomainPersistence, check.ParseLaunchd, "launchctl", "list"),
		unit(exitOK(base("persist.launch_dirs", "Third-party LaunchDaemons and LaunchAgents", check.DomainPersistence, check.ParseLines, "find", "/Library/LaunchDaemons", "/Library/LaunchAgents", "-maxdepth", "1", "-type", "f"), 0, 1), "launchd plists"),

		// SUID / world-writable
		unit(exitOK(base("fs.suid", "SUID binaries under local prefixes (depth-capped)", check.DomainFS, check.ParseLines,
			"find", "/usr/local", "/opt", "-xdev", "-maxdepth", "4", "-type", "f", "-perm", "-4000"), 0, 1), "SUID files"),
		unit(exitOK(base("fs.world_writable", "World-writable entries without the sticky bit under system prefixes (depth-capped)", check.DomainFS, check.ParseLines,
			"find", "/usr/local", "/opt", "/etc", "/Library/LaunchDaemons", "/Library/LaunchAgents", "-xdev", "-maxdepth", "4", "-perm", "-0002", "-not", "-perm", "-1000", "-not", "-type", "l"), 0, 1), "world-writable paths"),

		// Logging
		elevated(base("log.status", "Unified logging configuration", check.DomainLogging, check.ParseRaw, "log", "config", "--status")),

		// Time sync
		elevated(base("time.ntp", "Network time synchronisation setting", check.DomainTime, check.ParseRaw, "systemsetup", "-getusingnetworktime")),
	)
}
