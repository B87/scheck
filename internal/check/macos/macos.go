// Package macos registers the macOS check catalog (SPEC.md §3 baseline table).
package macos

import "github.com/b87/scheck/internal/check"

func base(id, desc string, domain check.Domain, parser check.ParserKind, argv ...string) check.Check {
	return check.Check{ID: id, Description: desc, Platform: check.MacOS, Domain: domain, Parser: parser, Baseline: true, Argv: argv}
}

func init() {
	check.Register(
		base("os.release", "macOS product name, version and build", check.DomainOS, check.ParseKV, "sw_vers"),
		extract(base("host.platform_uuid", "IOPlatformUUID (hashed into host.id)", check.DomainHost, check.ParseRaw, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice"),
			`"IOPlatformUUID" = "([0-9A-Fa-f-]+)"`),
	)
}

func extract(c check.Check, re string) check.Check { c.Extract = re; return c }
