package finding

import (
	"maps"
	"sort"
)

// Def is a finding id's compiled-in definition (docs/SPEC.md §7.1). Title,
// Impact and Remediation live here rather than only in a model's output,
// because a posture rule must produce a complete finding with no model in the
// loop.
type Def struct {
	ID           string
	Title        string
	Category     string // remote-access | network | accounts | privesc | integrity | updates | persistence | logging | fs | disk | time
	BaseSeverity Severity
	Impact       string
	Remediation  Remediation
	// Premise lists rule-covered finding ids this judgement presupposes. When
	// a posture rule has disproved a premise on complete evidence, the store
	// rejects a model candidate for this id (§7.5): a correlation cannot
	// stand on a fact the rule read and found the other way.
	Premise []string
}

// Finding ids. They are the join key for accepted risks, dedupe and
// cross-run diffing, so they are constants, never composed strings.
const (
	IDFileVaultOff         = "disk.filevault_off"
	IDSIPDisabled          = "integrity.sip_disabled"
	IDGatekeeperDisabled   = "integrity.gatekeeper_disabled"
	IDAppFirewallDisabled  = "fw.app_firewall_disabled"
	IDRemoteLoginEnabled   = "remote.login_enabled"
	IDNTPDisabled          = "time.ntp_disabled"
	IDPasswordAuthEnabled  = "sshd.password_auth_enabled"
	IDRootLoginEnabled     = "sshd.root_login_enabled"
	IDEmptyPassword        = "accounts.empty_password"
	IDShadowPermissions    = "accounts.shadow_permissions_unexpected"
	IDSELinuxDisabled      = "mac.selinux_disabled"
	IDAuditdInactive       = "log.auditd_inactive"
	IDNTPUnsynced          = "time.ntp_unsynced"
	IDUpdatesPending       = "updates.pending"
	IDWorldWritablePresent = "fs.world_writable_present"

	// Context-derived findings (docs/SPEC.md §6.3), produced by the grader.
	IDExpectedMissing   = "svc.expected_missing"
	IDAcceptanceExpired = "risk.acceptance_expired"

	// Judgement findings: no single-fact rule produces these; the model
	// classifies them in phase 2 from correlated evidence (§2.1, §7.2).
	IDUnexpectedListener  = "net.unexpected_listener"
	IDNoFirewallActive    = "fw.no_firewall_active"
	IDSudoNopasswdBroad   = "privesc.sudo_nopasswd_broad" //nolint:gosec // a finding id, not a credential
	IDUnexpectedSUID      = "fs.suid_unexpected"
	IDUnexpectedPersist   = "persist.unexpected_entry"
	IDUnexpectedAdmin     = "accounts.unexpected_admin"
	IDPasswordAuthExposed = "sshd.password_auth_exposed"
)

// IDs lists every catalog finding id, sorted.
func IDs() []string {
	out := make([]string, 0, len(defs))
	for id := range defs {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// defs is the finding catalog. Base severities are the §7.1 table's.
var defs = map[string]Def{
	IDFileVaultOff: {
		ID: IDFileVaultOff, Title: "FileVault disk encryption is off",
		Category: "disk", BaseSeverity: SevHigh,
		Impact: "The internal disk is not encrypted at rest, so its contents can be read by anyone " +
			"who gains physical possession of the machine or its disk.",
		Remediation: Remediation{
			Summary:  "Turn FileVault on in System Settings > Privacy & Security, or from the command line.",
			Commands: []string{"sudo fdesetup enable"},
			Caveat:   "Store the recovery key somewhere safe before rebooting; the initial encryption runs in the background.",
		},
	},
	IDSIPDisabled: {
		ID: IDSIPDisabled, Title: "System Integrity Protection is disabled",
		Category: "integrity", BaseSeverity: SevHigh,
		Impact: "Root-level processes can modify system files and load unsigned kernel extensions, " +
			"so other protections on this machine can be turned off without leaving a trace.",
		Remediation: Remediation{
			Summary:  "Re-enable SIP from macOS Recovery and reboot.",
			Commands: []string{"# boot into macOS Recovery, open Terminal:", "csrutil enable"},
			Caveat:   "SIP cannot be re-enabled from the running system; it needs a Recovery boot.",
		},
	},
	IDGatekeeperDisabled: {
		ID: IDGatekeeperDisabled, Title: "Gatekeeper assessment is disabled",
		Category: "integrity", BaseSeverity: SevMedium,
		Impact: "Applications run without any check on their signature or notarisation, so a downloaded " +
			"binary of unknown origin executes exactly like a trusted one.",
		Remediation: Remediation{
			Summary:  "Re-enable assessment of downloaded applications.",
			Commands: []string{"sudo spctl --global-enable"},
			Caveat:   "On recent macOS the same setting appears as System Settings > Privacy & Security > Allow applications from.",
		},
	},
	IDAppFirewallDisabled: {
		ID: IDAppFirewallDisabled, Title: "The macOS application firewall is disabled",
		Category: "network", BaseSeverity: SevMedium,
		Impact: "Every listening service on this machine accepts inbound connections without a " +
			"per-application decision, so a background agent that opens a port is reachable by default.",
		Remediation: Remediation{
			Summary:  "Turn the application firewall on.",
			Commands: []string{"sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"},
			Caveat:   "This is a per-application filter, not a packet filter; it does not replace a network firewall.",
		},
	},
	IDRemoteLoginEnabled: {
		ID: IDRemoteLoginEnabled, Title: "Remote Login (SSH) is enabled",
		Category: "remote-access", BaseSeverity: SevInfo,
		Impact: "The machine accepts SSH sessions. Whether that is correct depends on the machine's role, " +
			"so this is reported for confirmation rather than as a defect.",
		Remediation: Remediation{
			Summary:  "If this machine is not meant to be reachable over SSH, turn Remote Login off.",
			Commands: []string{"sudo systemsetup -setremotelogin off"},
			Caveat:   "Turning Remote Login off ends existing SSH sessions, including one you may be auditing through.",
		},
	},
	IDNTPDisabled: {
		ID: IDNTPDisabled, Title: "Network time synchronisation is off",
		Category: "time", BaseSeverity: SevLow,
		Impact: "An unsynchronised clock breaks certificate validity checks and makes this host's log " +
			"timestamps unusable for correlating an incident with other machines.",
		Remediation: Remediation{
			Summary:  "Turn network time on.",
			Commands: []string{"sudo systemsetup -setusingnetworktime on"},
		},
	},
	IDPasswordAuthEnabled: {
		ID: IDPasswordAuthEnabled, Title: "sshd accepts password authentication",
		Category: "remote-access", BaseSeverity: SevMedium,
		Impact: "Anyone who can reach this sshd can guess passwords online against every account that has " +
			"a usable one, at whatever rate the server allows.",
		Remediation: Remediation{
			Summary: "Set PasswordAuthentication no and rely on key authentication.",
			Commands: []string{
				"# review the effective configuration first:",
				"sudo sshd -T | grep -i passwordauthentication",
				"# then set PasswordAuthentication no in /etc/ssh/sshd_config or a file in /etc/ssh/sshd_config.d/",
				"sudo sshd -t && sudo systemctl reload sshd",
			},
			Caveat: "Confirm at least one working key-based login first, from a second session, or you will lock yourself out.",
		},
	},
	IDRootLoginEnabled: {
		ID: IDRootLoginEnabled, Title: "sshd permits direct root login",
		Category: "remote-access", BaseSeverity: SevHigh,
		Impact: "root can authenticate over the network directly, so a single credential is enough for full " +
			"control and there is no record of which operator escalated.",
		Remediation: Remediation{
			Summary: "Set PermitRootLogin no and log in as a user who escalates with sudo.",
			Commands: []string{
				"# set PermitRootLogin no in /etc/ssh/sshd_config or a file in /etc/ssh/sshd_config.d/",
				"sudo sshd -t && sudo systemctl reload sshd",
			},
			Caveat: "Make sure an unprivileged account with sudo rights can log in first. `prohibit-password` still allows key-based root login.",
		},
	},
	IDEmptyPassword: {
		ID: IDEmptyPassword, Title: "A local account has no password set",
		Category: "accounts", BaseSeverity: SevCritical,
		Impact: "The account authenticates with no credential wherever password authentication is accepted. " +
			"Whether that includes remote logins depends on this host's PAM and sshd configuration.",
		Remediation: Remediation{
			Summary: "Give the account a password or lock it, depending on what it is for.",
			Commands: []string{
				"# inspect first:",
				"sudo passwd -S <account>",
				"# then either lock it:",
				"sudo passwd -l <account>",
			},
			Caveat: "Locking an account a service depends on will break that service; find out what the account is for before changing it.",
		},
	},
	IDShadowPermissions: {
		ID: IDShadowPermissions, Title: "/etc/shadow has an unexpected mode",
		Category: "accounts", BaseSeverity: SevHigh,
		Impact: "The hashed-password file is expected to be readable only by root (mode 0, 600, or 640 with " +
			"group shadow). A different mode is a deviation worth explaining; it is not by itself evidence " +
			"that an unauthorized user has read the file.",
		Remediation: Remediation{
			Summary: "Restore the mode this distribution ships.",
			Commands: []string{
				"stat -c '%A %a %U:%G' /etc/shadow",
				"# Debian and Ubuntu: 640 root:shadow — Fedora and RHEL: 000 root:root",
			},
			Caveat: "Match the distribution's own default rather than copying a mode from another system.",
		},
	},
	IDSELinuxDisabled: {
		ID: IDSELinuxDisabled, Title: "SELinux is disabled",
		Category: "integrity", BaseSeverity: SevMedium,
		Impact: "The mandatory access control layer that confines services is not loaded, so a compromised " +
			"service is limited only by discretionary file permissions.",
		Remediation: Remediation{
			Summary: "Set SELINUX=enforcing in /etc/selinux/config, relabel, and reboot.",
			Commands: []string{
				"# review first; a system that has run disabled needs a relabel:",
				"sudo fixfiles -F onboot",
				"# set SELINUX=permissive in /etc/selinux/config, reboot, review denials, then set enforcing",
			},
			Caveat: "Switching straight to enforcing on a host that has run without SELinux can break services. Use permissive first and read the denials.",
		},
	},
	IDAuditdInactive: {
		ID: IDAuditdInactive, Title: "auditd is not running",
		Category: "logging", BaseSeverity: SevLow,
		Impact: "Kernel audit events are not being collected, so the host keeps no local record of the " +
			"syscalls and file accesses an audit policy would have captured.",
		Remediation: Remediation{
			Summary:  "Enable and start auditd.",
			Commands: []string{"sudo systemctl enable --now auditd"},
			Caveat:   "Not every distribution ships auditd, and a host that deliberately logs through journald alone may be configured correctly.",
		},
	},
	IDNTPUnsynced: {
		ID: IDNTPUnsynced, Title: "The system clock is not synchronised",
		Category: "time", BaseSeverity: SevLow,
		Impact: "An unsynchronised clock breaks certificate validity checks and makes this host's log " +
			"timestamps unusable for correlating an incident with other machines.",
		Remediation: Remediation{
			Summary:  "Enable network time synchronisation.",
			Commands: []string{"sudo timedatectl set-ntp true"},
		},
	},
	IDUpdatesPending: {
		ID: IDUpdatesPending, Title: "Software updates are pending",
		Category: "updates", BaseSeverity: SevLow,
		Impact: "Published fixes, including security fixes, are available but not installed. How serious " +
			"that is depends on which packages are behind.",
		Remediation: Remediation{
			Summary:  "Review the pending updates and apply them with the host's package manager.",
			Commands: []string{"# review the list first, then apply with apt / dnf / zypper / softwareupdate"},
			Caveat:   "Some updates need a restart to take effect; schedule accordingly.",
		},
	},
	IDWorldWritablePresent: {
		ID: IDWorldWritablePresent, Title: "World-writable paths without the sticky bit",
		Category: "fs", BaseSeverity: SevMedium,
		Impact: "Any local user can replace the contents of these paths. If a privileged process reads, " +
			"sources or executes one of them, that is a local privilege escalation path.",
		Remediation: Remediation{
			Summary:  "Review each path and remove world write where it is not deliberate.",
			Commands: []string{"# review first:", "ls -ld <path>", "sudo chmod o-w <path>"},
			Caveat:   "Shared directories that are world-writable by design (/tmp, /var/tmp) carry the sticky bit and are already excluded from this check.",
		},
	},
}

func init() {
	maps.Copy(defs, judgementDefs)
}

// judgementDefs are the findings only correlated evidence or operator
// context can produce. Their text is the default a model finding carries
// when the model supplies none (§7.1).
var judgementDefs = map[string]Def{
	IDExpectedMissing: {
		ID: IDExpectedMissing, Title: "A declared service is not listening",
		Category: CategoryNetwork, BaseSeverity: SevMedium,
		Impact: "Operator context declares a service on this port, but nothing is listening on it. Either " +
			"the service is down, the context is stale, or the host is not the one the context describes.",
		Remediation: Remediation{
			Summary:  "Confirm the service is meant to run here and start it, or correct expected_services in the context.",
			Commands: []string{"# review first:", "ss -tulpn   # Linux", "lsof -nP -iTCP -sTCP:LISTEN   # macOS"},
		},
	},
	IDAcceptanceExpired: {
		ID: IDAcceptanceExpired, Title: "An accepted-risk entry has expired",
		Category: CategoryGovernance, BaseSeverity: SevLow,
		Impact: "The acceptance no longer suppresses the finding it names, and the operator's record of " +
			"why the risk was tolerable is out of date.",
		Remediation: Remediation{
			Summary: "Re-review the risk: extend the acceptance with a new expires date and reason, or remediate the finding.",
			Caveat:  "The finding the acceptance named is reported as open until the entry is renewed.",
		},
	},
	IDUnexpectedListener: {
		ID: IDUnexpectedListener, Title: "A service is listening that the context does not explain",
		Category: CategoryNetwork, BaseSeverity: SevMedium,
		Impact: "A listener with no declared purpose is reachable from wherever this host's network " +
			"allows, and nobody has said it should be.",
		Remediation: Remediation{
			Summary:  "Identify the process, decide whether the listener is wanted, and either declare it in expected_services or stop and disable it.",
			Commands: []string{"# review first:", "ss -tulpn   # Linux", "lsof -nP -iTCP -sTCP:LISTEN   # macOS"},
		},
	},
	IDNoFirewallActive: {
		ID: IDNoFirewallActive, Title: "No host firewall is active",
		Category: CategoryNetwork, BaseSeverity: SevMedium,
		Impact: "Every listening service is reachable from any network the host is attached to; there is " +
			"no host-level filter between a service and the network.",
		Remediation: Remediation{
			Summary: "Enable the platform's host firewall and allow only the services this host is meant to expose.",
			Commands: []string{"# Linux: ufw enable / firewall-cmd --state / nft list ruleset",
				"# macOS: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"},
			Caveat: "Allow the administrative path (SSH) before enabling a default-deny policy.",
		},
	},
	IDSudoNopasswdBroad: {
		ID: IDSudoNopasswdBroad, Title: "A broad NOPASSWD sudo rule is in effect",
		Category: "privesc", BaseSeverity: SevHigh,
		Impact: "An account, or every member of a group, can become root without re-authenticating, so " +
			"any compromise of that account is a compromise of the host.",
		Remediation: Remediation{
			Summary:  "Restrict the rule to the specific commands that need it, or remove NOPASSWD.",
			Commands: []string{"sudo visudo   # edit; never edit sudoers with another tool"},
		},
	},
	IDUnexpectedSUID: {
		ID: IDUnexpectedSUID, Title: "An unexpected SUID binary is present",
		Category: "fs", BaseSeverity: SevMedium,
		Impact: "The binary runs with its owner's privileges for any local user; a flaw in it, or a " +
			"writable path to it, is a local privilege escalation.",
		Remediation: Remediation{
			Summary:  "Confirm the binary needs the SUID bit; if not, remove it.",
			Commands: []string{"# review first:", "ls -l <path>", "sudo chmod u-s <path>"},
		},
	},
	IDUnexpectedPersist: {
		ID: IDUnexpectedPersist, Title: "An unexplained persistence entry is enabled",
		Category: "persistence", BaseSeverity: SevMedium,
		Impact: "Something runs at boot or on a schedule that the host's stated role does not account " +
			"for; persistence is where an intruder or a forgotten tool survives a reboot.",
		Remediation: Remediation{
			Summary: "Identify the unit, timer, cron entry or launchd job, and disable it if it is not wanted.",
			Commands: []string{"# Linux: systemctl cat <unit>; systemctl disable --now <unit>",
				"# macOS: launchctl print system/<label>; sudo launchctl bootout system/<label>"},
		},
	},
	IDUnexpectedAdmin: {
		ID: IDUnexpectedAdmin, Title: "An account has administrative rights the context does not explain",
		Category: "accounts", BaseSeverity: SevMedium,
		Impact: "The account can escalate to root; if it is a service account, a leftover, or unknown to " +
			"the operator, that is an unmanaged path to full control.",
		Remediation: Remediation{
			Summary: "Confirm who the account is for and remove it from the administrative group if it does not need it.",
		},
	},
	IDPasswordAuthExposed: {
		ID: IDPasswordAuthExposed, Title: "sshd accepts passwords on a listener reachable beyond the host",
		Category: CategoryRemoteAccess, BaseSeverity: SevHigh, Premise: []string{IDPasswordAuthEnabled},
		Impact: "Password authentication is enabled and sshd listens on a non-loopback address, so online " +
			"password guessing is possible from wherever the listener is reachable.",
		Remediation: Remediation{
			Summary: "Set PasswordAuthentication no, or bind sshd to a management address only.",
			Commands: []string{"sudo sshd -T | grep -iE 'passwordauthentication|listenaddress'",
				"# then set PasswordAuthentication no and reload sshd"},
			Caveat: "Confirm a working key-based login first.",
		},
	},
}

// Lookup returns the definition for a finding id.
func Lookup(id string) (Def, bool) {
	d, ok := defs[id]
	return d, ok
}

// Defs returns every definition, sorted by id.
func Defs() []Def {
	out := make([]Def, 0, len(defs))
	for _, d := range defs {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
