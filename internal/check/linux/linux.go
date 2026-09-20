// Package linux registers the Linux check catalog (SPEC.md §3 baseline table).
package linux

import "github.com/b87/scheck/internal/check"

func base(id, desc string, domain check.Domain, parser check.ParserKind, argv ...string) check.Check {
	return check.Check{ID: id, Description: desc, Platform: check.Linux, Domain: domain, Parser: parser, Baseline: true, Argv: argv}
}

func elevated(c check.Check) check.Check { c.Elevated = true; return c }

func exitOK(c check.Check, codes ...int) check.Check { c.ExitOK = codes; return c }

func init() {
	check.Register(
		// OS / host
		base("os.release", "Distribution identification", check.DomainOS, check.ParseKV, "cat", "/etc/os-release"),
		base("host.machine_id", "Stable machine identifier (hashed into host.id)", check.DomainHost, check.ParseRaw, "cat", "/etc/machine-id"),

		// Pending updates: one check per package manager; the absent ones are unavailable.
		base("pkg.apt_upgradable", "Packages with pending upgrades (apt)", check.DomainUpdates, check.ParseLines, "apt", "list", "--upgradable"),
		exitOK(base("pkg.dnf_check_update", "Packages with pending upgrades (dnf; exit 100 means updates exist)", check.DomainUpdates, check.ParseLines, "dnf", "-q", "check-update"), 0, 100),
		base("pkg.zypper_lp", "Pending patches (zypper)", check.DomainUpdates, check.ParseLines, "zypper", "--non-interactive", "lp"),

		// Disk encryption
		base("disk.lsblk", "Block devices, filesystems and crypt layers", check.DomainDisk, check.ParseLines, "lsblk", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT"),
		base("disk.crypttab", "Configured encrypted volumes", check.DomainDisk, check.ParseLines, "cat", "/etc/crypttab"),

		// Integrity / MAC
		base("mac.sestatus", "SELinux status", check.DomainIntegrity, check.ParseKV, "sestatus"),
		elevated(base("mac.aa_status", "AppArmor profiles and enforcement", check.DomainIntegrity, check.ParseLines, "aa-status")),

		// Firewall
		elevated(base("fw.ufw", "ufw status and rules", check.DomainFirewall, check.ParseLines, "ufw", "status", "verbose")),
		exitOK(base("fw.firewalld", "firewalld state", check.DomainFirewall, check.ParseRaw, "firewall-cmd", "--state"), check.AnyExit...),
		elevated(base("fw.nft", "nftables ruleset", check.DomainFirewall, check.ParseRaw, "nft", "list", "ruleset")),

		// Listening sockets
		base("net.listeners", "Listening TCP/UDP sockets with owning process", check.DomainNetwork, check.ParseLines, "ss", "-tulpnH"),

		// sshd
		elevated(base("sshd.config", "Effective sshd configuration", check.DomainSSHD, check.ParseKV, "sshd", "-T")),

		// Accounts
		base("accounts.passwd", "Local accounts, shells and home directories", check.DomainAccounts, check.ParseLines, "cat", "/etc/passwd"),
		base("accounts.shadow_meta", "Permissions of /etc/shadow (metadata only, never contents)", check.DomainAccounts, check.ParseRaw, "stat", "-c", "%A:%a:%U:%G:%s", "/etc/shadow"),
		elevated(base("accounts.passwd_status", "Password status per account (NP = no password, L = locked)", check.DomainAccounts, check.ParseLines, "passwd", "-S", "-a")),

		// Privilege escalation
		elevated(base("privesc.sudoers", "sudoers policy", check.DomainPrivesc, check.ParseLines, "cat", "/etc/sudoers")),
		elevated(exitOK(base("privesc.sudoers_d", "sudoers.d drop-ins (file:line, non-empty lines)", check.DomainPrivesc, check.ParseLines, "grep", "-rH", ".", "/etc/sudoers.d"), 0, 1, 2)),

		// Remote access
		exitOK(base("remote.sshd_enabled", "Whether the ssh service is enabled at boot", check.DomainRemoteAccess, check.ParseLines, "systemctl", "is-enabled", "ssh", "sshd"), check.AnyExit...),

		// Persistence
		base("persist.units", "Enabled systemd unit files", check.DomainPersistence, check.ParseLines, "systemctl", "list-unit-files", "--state=enabled", "--no-pager", "--plain"),
		base("persist.timers", "systemd timers", check.DomainPersistence, check.ParseLines, "systemctl", "list-timers", "--all", "--no-pager", "--plain"),
		exitOK(base("persist.cron", "System crontab and cron.d entries (file:line, non-empty lines)", check.DomainPersistence, check.ParseLines, "grep", "-rH", ".", "/etc/crontab", "/etc/cron.d"), 0, 1, 2),

		// SUID / world-writable
		exitOK(base("fs.suid", "SUID binaries under system and local prefixes (depth-capped)", check.DomainFS, check.ParseLines,
			"find", "/usr/local", "/opt", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "-xdev", "-maxdepth", "4", "-type", "f", "-perm", "-4000"), 0, 1),
		exitOK(base("fs.world_writable", "World-writable files and directories without the sticky bit (depth-capped)", check.DomainFS, check.ParseLines,
			"find", "/usr/local", "/opt", "/etc", "-xdev", "-maxdepth", "4", "-perm", "-0002", "-not", "-perm", "-1000", "-not", "-type", "l"), 0, 1),

		// Logging / audit
		exitOK(base("log.auditd", "Whether auditd is active", check.DomainLogging, check.ParseRaw, "systemctl", "is-active", "auditd"), check.AnyExit...),
		base("log.journal_usage", "Journal disk usage", check.DomainLogging, check.ParseRaw, "journalctl", "--disk-usage"),

		// Time sync
		base("time.timedatectl", "Clock, timezone and NTP synchronisation state", check.DomainTime, check.ParseKV, "timedatectl", "show"),
	)
}
