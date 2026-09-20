// Package linux registers the Linux check catalog (SPEC.md §3 baseline table).
package linux

import "github.com/b87/scheck/internal/check"

func base(id, desc string, domain check.Domain, parser check.ParserKind, argv ...string) check.Check {
	return check.Check{ID: id, Description: desc, Platform: check.Linux, Domain: domain, Parser: parser, Baseline: true, Argv: argv}
}

func init() {
	check.Register(
		base("os.release", "Distribution identification", check.DomainOS, check.ParseKV, "cat", "/etc/os-release"),
		base("host.machine_id", "Stable machine identifier (hashed into host.id)", check.DomainHost, check.ParseRaw, "cat", "/etc/machine-id"),
		base("net.listeners", "Listening TCP/UDP sockets with owning process", check.DomainNetwork, check.ParseLines, "ss", "-tulpnH"),
		elevated(base("sshd.config", "Effective sshd configuration", check.DomainSSHD, check.ParseKV, "sshd", "-T")),
	)
}

func elevated(c check.Check) check.Check { c.Elevated = true; return c }
