// Package linux registers the Linux check catalog (docs/spec/host-collector.md §3 baseline table).
package linux

import "github.com/b87/scheck/internal/check"

func base(id, desc string, domain check.Domain, parser check.ParserKind, argv ...string) check.Check {
	return check.Check{ID: id, Description: desc, Platform: check.Linux, Domain: domain, Parser: parser, Baseline: true, Argv: argv}
}

func elevated(c check.Check) check.Check { c.Elevated = true; return c }

func exitOK(c check.Check, codes ...int) check.Check { c.ExitOK = codes; return c }

// unit names what one line or key of a check means, so the fact's reading is
// "9 SUID files" rather than "9 lines" (docs/spec/host-collector.md §3).
func unit(c check.Check, noun string) check.Check { c.Unit = noun; return c }

// sampled marks a depth- or prefix-capped read (check.Check.Sampled).
func sampled(c check.Check) check.Check { c.Sampled = true; return c }

func init() {
	check.Register(
		// OS / host
		unit(base("os.release", "Distribution identification", check.DomainOS, check.ParseKV, "cat", "/etc/os-release"), "settings"),
		// The DMI vendor, to name a cloud VM on the fact sheet (G5); a label,
		// never a verdict. No DMI tree (a container) is exit 2, an answer.
		unit(exitOK(base("sys.dmi", "Hardware vendor and product from DMI, to name a cloud platform (read-only sysfs)", check.DomainHost, check.ParseLines,
			"grep", "-H", ".", "/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/product_name"), 0, 1, 2), "DMI fields"),
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
		// Which backend the iptables userspace drives, so an empty nftables
		// ruleset can be read as no filtering (docs/ROADMAP.md, E9, D3): exit 1
		// means no iptables userspace at all. iptables itself stays denied.
		exitOK(base("fw.iptables_backend", "iptables userspace backend (where /usr/sbin/iptables resolves; exit 1: none)", check.DomainFirewall, check.ParseRaw, "realpath", "-e", "/usr/sbin/iptables"), 0, 1),

		// Listening sockets
		// Elevated: ss names only the caller's own sockets' owners, and a database
		// runs as its own user (docs/ROADMAP.md, E9, D3b).
		elevated(base("net.listeners", "Listening TCP/UDP sockets with owning process", check.DomainNetwork, check.ParseListeners, "ss", "-tulpnH")),

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
		sampled(unit(exitOK(base("fs.suid", "SUID binaries under system and local prefixes (depth-capped)", check.DomainFS, check.ParseLines,
			"find", "/usr/local", "/opt", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "-xdev", "-maxdepth", "4", "-type", "f", "-perm", "-4000"), 0, 1), "SUID files")),
		sampled(unit(exitOK(base("fs.world_writable", "World-writable files and directories without the sticky bit (depth-capped)", check.DomainFS, check.ParseLines,
			"find", "/usr/local", "/opt", "/etc", "-xdev", "-maxdepth", "4", "-perm", "-0002", "-not", "-perm", "-1000", "-not", "-type", "l"), 0, 1), "world-writable paths")),

		// Credentials on disk and the container socket (G5). Elevated so a
		// home the audit account cannot list is read, not silently skipped;
		// Sampled because the walk is depth-capped.
		elevated(sampled(check.Check{ID: "creds.home_files", Description: "Private keys and cloud credential files under home directories, with the folders that stop others reaching them (names, modes and owners only, never contents; the capture also shows inode, size and time)",
			Platform: check.Linux, Domain: check.DomainCreds, Parser: check.ParseFindLS, Baseline: true, ExitOK: []int{0, 1}, PathUse: check.PathNone,
			Argv: check.CredFindArgv([]string{"/root", "/home"}, []string{"node_modules", ".git", ".cache"})})),
		sampled(check.Check{ID: "docker.sockets", Description: "Container engine sockets under /run with their owner and mode",
			Platform: check.Linux, Domain: check.DomainDocker, Parser: check.ParseFindLS, Baseline: true, ExitOK: []int{0, 1},
			Argv: []string{"find", "/run", "-maxdepth", "2", "-type", "s", "-name", "docker.sock", "-ls", "-o", "-type", "s", "-name", "podman.sock", "-ls", "-o", "-type", "s", "-name", "containerd.sock", "-ls"}}),

		// Logging / audit
		exitOK(base("log.auditd", "Whether auditd is active", check.DomainLogging, check.ParseRaw, "systemctl", "is-active", "auditd"), check.AnyExit...),
		base("log.journal_usage", "Journal disk usage", check.DomainLogging, check.ParseRaw, "journalctl", "--disk-usage"),

		// Time sync
		unit(base("time.timedatectl", "Clock, timezone and NTP synchronisation state", check.DomainTime, check.ParseKV, "timedatectl", "show"), "settings"),
	)
}
