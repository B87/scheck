package report

import "github.com/b87/scheck/internal/check"

// domainLabels maps a catalog domain to the words a person reads, in the
// order the report presents them: who the host is, then what protects it,
// then what exposes it, then the plumbing (docs/SPEC.md §7.6). Check ids are
// never translated — they are the join key into `scheck explain`, the audit
// log and the JSON.
var domainLabels = []struct {
	Domain check.Domain
	Label  string
}{
	{check.DomainHost, "Host identity"},
	{check.DomainOS, "Operating system"},
	{check.DomainUpdates, "Software updates"},
	{check.DomainDisk, "Disk encryption"},
	{check.DomainIntegrity, "System integrity"},
	{check.DomainFirewall, "Firewall"},
	{check.DomainNetwork, "Network exposure"},
	{check.DomainSSHD, "SSH server"},
	{check.DomainRemoteAccess, "Remote access"},
	{check.DomainAccounts, "Accounts"},
	{check.DomainPrivesc, "Privilege escalation"},
	{check.DomainPersistence, "Startup and persistence"},
	{check.DomainFS, "Filesystem"},
	{check.DomainLogging, "Logging and audit"},
	{check.DomainTime, "Time synchronisation"},
	{check.DomainSys, "Session and shell"},
	{check.DomainText, "Text utilities"},
}

// DomainLabel returns the human label for d, or d itself when the domain is
// not in the table (a new catalog domain still renders, unlabelled).
func DomainLabel(d check.Domain) string {
	for _, e := range domainLabels {
		if e.Domain == d {
			return e.Label
		}
	}
	return string(d)
}

// domainOrder returns the presentation rank of d; unknown domains sort last.
func domainOrder(d check.Domain) int {
	for i, e := range domainLabels {
		if e.Domain == d {
			return i
		}
	}
	return len(domainLabels)
}
