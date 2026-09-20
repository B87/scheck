// Package linux registers the Linux check catalog (docs/SPEC.md §3 baseline table).
package linux

import "github.com/b87/scheck/internal/check"

func base(id, desc string, domain check.Domain, parser check.ParserKind, argv ...string) check.Check {
	return check.Check{ID: id, Description: desc, Platform: check.Linux, Domain: domain, Parser: parser, Baseline: true, Argv: argv}
}

func elevated(c check.Check) check.Check { c.Elevated = true; return c }

func exitOK(c check.Check, codes ...int) check.Check { c.ExitOK = codes; return c }

// unit names what one line or key of a check means, so the fact's reading is
// "9 SUID files" rather than "9 lines" (docs/SPEC.md §3).
func unit(c check.Check, noun string) check.Check { c.Unit = noun; return c }

func init() {
	check.Register(
		// OS / host
		unit(base("os.release", "Distribution identification", check.DomainOS, check.ParseKV, "cat", "/etc/os-release"), "settings"),
		base("host.machine_id", "Stable machine identifier (hashed into host.id)", check.DomainHost, check.ParseRaw, "cat", "/etc/machine-id"),

		// Pending updates: one check per package manager; the absent ones are unavailable.
		base("pkg.apt_upgradable", "Packages with pending upgrades (apt)", check.DomainUpdates, check.ParseUpdates, "apt", "list", "--upgradable"),
		exitOK(base("pkg.dnf_check_update", "Packages with pending upgrades (dnf; exit 100 means updates exist)", check.DomainUpdates, check.ParseUpdates, "dnf", "-q", "check-update"), 0, 100),
		base("pkg.zypper_lp", "Pending patches (zypper)", check.DomainUpdates, check.ParseUpdates, "zypper", "--non-interactive", "lp"),

		// Disk encryption
		unit(base("disk.lsblk", "Block devices, filesystems and crypt layers", check.DomainDisk, check.ParseLines, "lsblk", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT"), "block devices"),
		unit(base("disk.crypttab", "Configured encrypted volumes", check.DomainDisk, check.ParseLines, "cat", "/etc/crypttab"), "crypttab entries"),

		// Integrity / MAC
		unit(base("mac.sestatus", "SELinux status", check.DomainIntegrity, check.ParseKV, "sestatus"), "settings"),
		elevated(unit(base("mac.aa_status", "AppArmor profiles and enforcement", check.DomainIntegrity, check.ParseLines, "aa-status"), "AppArmor report lines")),

		// Firewall
		elevated(unit(base("fw.ufw", "ufw status and rules", check.DomainFirewall, check.ParseLines, "ufw", "status", "verbose"), "ufw report lines")),
		exitOK(base("fw.firewalld", "firewalld state", check.DomainFirewall, check.ParseRaw, "firewall-cmd", "--state"), check.AnyExit...),
		elevated(base("fw.nft", "nftables ruleset", check.DomainFirewall, check.ParseRaw, "nft", "list", "ruleset")),

		// Listening sockets
		base("net.listeners", "Listening TCP/UDP sockets with owning process", check.DomainNetwork, check.ParseListeners, "ss", "-tulpnH"),

		// sshd
		elevated(unit(base("sshd.config", "Effective sshd configuration", check.DomainSSHD, check.ParseKV, "sshd", "-T"), "settings")),

		// Accounts
		base("accounts.passwd", "Local accounts, shells and home directories", check.DomainAccounts, check.ParseAccounts, "cat", "/etc/passwd"),
		base("accounts.shadow_meta", "Permissions of /etc/shadow (metadata only, never contents)", check.DomainAccounts, check.ParseFileMode, "stat", "-c", "%A:%a:%U:%G:%s", "/etc/shadow"),
		elevated(base("accounts.passwd_status", "Password status per account (NP = no password, L = locked)", check.DomainAccounts, check.ParsePasswdStatus, "passwd", "-S", "-a")),

		// Privilege escalation
		elevated(unit(base("privesc.sudoers", "sudoers policy", check.DomainPrivesc, check.ParseLines, "cat", "/etc/sudoers"), "sudoers lines")),
		elevated(exitOK(unit(base("privesc.sudoers_d", "sudoers.d drop-ins (file:line, non-empty lines)", check.DomainPrivesc, check.ParseLines, "grep", "-rH", ".", "/etc/sudoers.d"), "sudoers.d lines"), 0, 1, 2)),

		// Remote access
		unit(exitOK(base("remote.sshd_enabled", "Whether the ssh service is enabled at boot (one state per unit name, in order)", check.DomainRemoteAccess, check.ParseLines, "systemctl", "is-enabled", "ssh", "sshd"), check.AnyExit...), "service states"),

		// Persistence
		base("persist.units", "Enabled systemd unit files", check.DomainPersistence, check.ParseUnits, "systemctl", "list-unit-files", "--state=enabled", "--no-pager", "--plain"),
		unit(base("persist.timers", "systemd timers", check.DomainPersistence, check.ParseLines, "systemctl", "list-timers", "--all", "--no-pager", "--plain"), "timer report lines"),
		exitOK(unit(base("persist.cron", "System crontab and cron.d entries (file:line, non-empty lines)", check.DomainPersistence, check.ParseLines, "grep", "-rH", ".", "/etc/crontab", "/etc/cron.d"), "cron entries"), 0, 1, 2),

		// SUID / world-writable
		unit(exitOK(base("fs.suid", "SUID binaries under system and local prefixes (depth-capped)", check.DomainFS, check.ParseLines,
			"find", "/usr/local", "/opt", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "-xdev", "-maxdepth", "4", "-type", "f", "-perm", "-4000"), 0, 1), "SUID files"),
		unit(exitOK(base("fs.world_writable", "World-writable files and directories without the sticky bit (depth-capped)", check.DomainFS, check.ParseLines,
			"find", "/usr/local", "/opt", "/etc", "-xdev", "-maxdepth", "4", "-perm", "-0002", "-not", "-perm", "-1000", "-not", "-type", "l"), 0, 1), "world-writable paths"),

		// Logging / audit
		exitOK(base("log.auditd", "Whether auditd is active", check.DomainLogging, check.ParseRaw, "systemctl", "is-active", "auditd"), check.AnyExit...),
		base("log.journal_usage", "Journal disk usage", check.DomainLogging, check.ParseRaw, "journalctl", "--disk-usage"),

		// Time sync
		unit(base("time.timedatectl", "Clock, timezone and NTP synchronisation state", check.DomainTime, check.ParseKV, "timedatectl", "show"), "settings"),
	)
}
