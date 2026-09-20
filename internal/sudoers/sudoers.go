// Package sudoers generates the least-privilege NOPASSWD fragment for the
// catalog's elevated checks (docs/SPEC.md §8.1). The fragment is derived from the
// catalog, so it cannot drift from what scheck actually runs; scheck prints
// it and never installs it.
package sudoers

import (
	"fmt"
	"sort"
	"strings"

	"github.com/b87/scheck/internal/check"
)

// binaryPaths maps a catalog binary to the absolute path sudoers must name.
// sudo resolves the bare name through its secure_path, so the entry has to
// be where the platform actually installs it. A test asserts every elevated
// check's binary is present for its platform.
var binaryPaths = map[check.Platform]map[string]string{
	check.Linux: { //nolint:gosec // G101: binary paths, not credentials
		"sshd":         "/usr/sbin/sshd",
		"cat":          "/usr/bin/cat",
		"grep":         "/usr/bin/grep",
		"stat":         "/usr/bin/stat",
		"find":         "/usr/bin/find",
		"ufw":          "/usr/sbin/ufw",
		"nft":          "/usr/sbin/nft",
		"aa-status":    "/usr/sbin/aa-status",
		"passwd":       "/usr/bin/passwd",
		"firewall-cmd": "/usr/bin/firewall-cmd",
		"iptables":     "/usr/sbin/iptables",
		"auditctl":     "/usr/sbin/auditctl",
		"journalctl":   "/usr/bin/journalctl",
	},
	check.MacOS: {
		"sshd":                "/usr/sbin/sshd",
		"cat":                 "/bin/cat",
		"grep":                "/usr/bin/grep",
		"stat":                "/usr/bin/stat",
		"find":                "/usr/bin/find",
		"systemsetup":         "/usr/sbin/systemsetup",
		"fdesetup":            "/usr/bin/fdesetup",
		"softwareupdate":      "/usr/sbin/softwareupdate",
		"socketfilterfw":      "/usr/libexec/ApplicationFirewall/socketfilterfw",
		"launchctl":           "/bin/launchctl",
		"log":                 "/usr/bin/log",
		"defaults":            "/usr/bin/defaults",
		"dscl":                "/usr/bin/dscl",
		"csrutil":             "/usr/bin/csrutil",
		"spctl":               "/usr/sbin/spctl",
		"pfctl":               "/sbin/pfctl",
		"security":            "/usr/bin/security",
		"profiles":            "/usr/bin/profiles",
		"tmutil":              "/usr/bin/tmutil",
		"kextstat":            "/usr/sbin/kextstat",
		"systemextensionsctl": "/usr/bin/systemextensionsctl",
	},
}

// Generate renders the fragment for user on platform p. It fails when an
// elevated check names a binary with no known absolute path, because a
// guessed path would silently never match.
func Generate(p check.Platform, user string) (string, error) {
	paths := binaryPaths[p]
	if paths == nil {
		return "", fmt.Errorf("sudoers: unsupported platform %q", p)
	}
	var lines []string
	var wildcard []string
	for _, c := range check.ForPlatform(p, check.ProfileHardened) {
		if !c.Elevated {
			continue
		}
		bin := c.Argv[0]
		abs := bin
		if !strings.HasPrefix(bin, "/") {
			abs = paths[bin]
			if abs == "" {
				return "", fmt.Errorf("sudoers: no absolute path known for %q (check %s on %s); add it to binaryPaths", bin, c.ID, p)
			}
		}
		args := make([]string, 0, len(c.Argv)-1)
		for _, tok := range c.Argv[1:] {
			if check.Placeholder(tok) != "" {
				tok = "*"
				wildcard = append(wildcard, c.ID)
			}
			args = append(args, escape(tok))
		}
		cmd := abs
		if len(args) > 0 {
			cmd += " " + strings.Join(args, " ")
		} else {
			cmd += ` ""` // no arguments allowed at all
		}
		lines = append(lines, fmt.Sprintf("%s ALL=(root) NOPASSWD: %s  # %s", user, cmd, c.ID))
	}
	sort.Strings(lines)
	var b strings.Builder
	fmt.Fprintf(&b, "# scheck elevated checks for %s on %s — generated from the compiled catalog.\n", user, p)
	b.WriteString("# Review, then install with: visudo -cf - < fragment && install -m 440 fragment /etc/sudoers.d/scheck\n")
	b.WriteString("# Every line grants exactly one read-only command with fixed flags; scheck runs them as `sudo -n -- ...`.\n")
	if len(wildcard) > 0 {
		sort.Strings(wildcard)
		fmt.Fprintf(&b, "# Parameterised checks (%s) use a sudoers wildcard for the parameter; scheck itself\n", strings.Join(dedupe(wildcard), ", "))
		b.WriteString("# restricts the value to the parameter's charset and path policy before calling sudo.\n")
	}
	b.WriteString("Defaults:" + user + " !requiretty\n")
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	return b.String(), nil
}

// escape protects the few characters sudoers treats specially in command
// arguments. Catalog literals cannot contain them, but the canary can and
// an elevated canary would be a bug; escaping keeps the output parseable.
func escape(tok string) string {
	if tok == "" {
		return `""`
	}
	r := strings.NewReplacer(`\`, `\\`, `,`, `\,`, `:`, `\:`, `=`, `\=`, ` `, `\ `, `#`, `\#`)
	return r.Replace(tok)
}

func dedupe(in []string) []string {
	var out []string
	for i, v := range in {
		if i == 0 || v != in[i-1] {
			out = append(out, v)
		}
	}
	return out
}
