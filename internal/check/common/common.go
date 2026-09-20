// Package common registers the platform-agnostic checks: session bootstrap
// (canary, platform, uid), host identity helpers and the on-demand file
// primitives the runner and the model both rely on.
package common

import "github.com/b87/scheck/internal/check"

// CanaryString is echoed by sys.canary. It carries every character class the
// SSH quoter must survive: quotes, spaces, $, backticks, semicolons, pipes,
// globs and a backslash. The invariants test exempts exactly this one entry
// from the metacharacter rule.
const CanaryString = `scheck canary: 'single' "double" $HOME ` + "`id`" + ` ;| *? \back`

var pathParam = []check.Param{{Name: "path", Kind: check.KindPath}}

func init() {
	check.Register(
		check.Check{
			ID: "sys.canary", Description: "Round-trip a fixed string to verify remote quoting",
			Platform: check.Any, Domain: check.DomainSys, Parser: check.ParseRaw, Canary: true,
			MinProfile: check.ProfileHardened,
			Argv:       []string{"printf", "%s", CanaryString},
		},
		check.Check{
			ID: "sys.platform", Description: "Kernel name (uname -s), used for platform detection",
			Platform: check.Any, Domain: check.DomainSys, Parser: check.ParseRaw, Baseline: true,
			Argv: []string{"uname", "-s"},
		},
		check.Check{
			ID: "sys.uname", Description: "Full kernel identification",
			Platform: check.Any, Domain: check.DomainSys, Parser: check.ParseRaw, Baseline: true,
			Argv: []string{"uname", "-a"},
		},
		check.Check{
			ID: "sys.uid", Description: "Effective uid of the audit session",
			Platform: check.Any, Domain: check.DomainSys, Parser: check.ParseRaw, Baseline: true,
			Argv: []string{"id", "-u"},
		},
		check.Check{
			ID: "sys.shell", Description: "Login shell of the audit session",
			Platform: check.Any, Domain: check.DomainSys, Parser: check.ParseRaw, Baseline: true,
			ExitOK: check.AnyExit,
			Argv:   []string{"printenv", "SHELL"},
		},
		check.Check{
			ID: "host.hostname", Description: "Hostname",
			Platform: check.Any, Domain: check.DomainHost, Parser: check.ParseRaw, Baseline: true,
			Argv: []string{"hostname"},
		},
		check.Check{
			ID: "fs.realpath", Description: "Resolve symlinks in a path (used before every path decision)",
			Platform: check.Any, Domain: check.DomainFS, Parser: check.ParseRaw, PathUse: check.PathMetadata,
			Argv: []string{"realpath", "{path}"}, Params: pathParam,
		},
		check.Check{
			ID: "fs.stat", Description: "Mode, owner, group, size and type of a path (never its content)",
			Platform: check.Linux, Domain: check.DomainFS, Parser: check.ParseRaw, PathUse: check.PathMetadata,
			Argv: []string{"stat", "-c", "%A:%a:%U:%G:%s:%F:%N", "{path}"}, Params: pathParam,
		},
		check.Check{
			ID: "fs.stat", Description: "Mode, owner, group, size and type of a path (never its content)",
			Platform: check.MacOS, Domain: check.DomainFS, Parser: check.ParseRaw, PathUse: check.PathMetadata,
			Argv: []string{"stat", "-f", "%Sp:%Lp:%Su:%Sg:%z:%HT:%N", "{path}"}, Params: pathParam,
		},
		check.Check{
			ID: "fs.list", Description: "Directory listing with modes and owners",
			Platform: check.Any, Domain: check.DomainFS, Parser: check.ParseLines, PathUse: check.PathMetadata,
			Argv: []string{"ls", "-la", "{path}"}, Params: pathParam,
		},
		check.Check{
			ID: "text.cat", Description: "Contents of a file under an allowed prefix",
			Platform: check.Any, Domain: check.DomainText, Parser: check.ParseRaw, PathUse: check.PathContent,
			Argv: []string{"cat", "{path}"}, Params: pathParam,
		},
		check.Check{
			ID: "text.head", Description: "First N lines of a file under an allowed prefix",
			Platform: check.Any, Domain: check.DomainText, Parser: check.ParseRaw, PathUse: check.PathContent,
			Argv:   []string{"head", "-n", "{lines}", "{path}"},
			Params: []check.Param{{Name: "lines", Kind: check.KindInt, Min: 1, Max: 2000}, {Name: "path", Kind: check.KindPath}},
		},
	)
}
