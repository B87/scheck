package check

import (
	"strings"
	"testing"
)

func good() Check {
	return Check{ID: "fs.stat", Platform: Any, Domain: DomainFS, Parser: ParseLines, Unit: "file entries",
		Argv: []string{"stat", "-c", "%a:%U", "{path}"}, PathUse: PathMetadata,
		Params: []Param{{Name: "path", Kind: KindPath}}}
}

func canary() Check {
	return Check{ID: "sys.canary", Platform: Any, Domain: DomainSys, Parser: ParseRaw, Canary: true,
		Argv: []string{"printf", "%s", "a b'c\"d$e`f;g"}}
}

func TestValidateAcceptsGoodCatalog(t *testing.T) {
	if vs := Validate([]Check{good(), canary()}); len(vs) != 0 {
		t.Fatalf("unexpected violations: %v", vs)
	}
}

// Every violation class must be caught by name, loudly, without panicking.
func TestValidateCatchesEachRule(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Check)
		rule   string
	}{
		{"metachar in literal", func(c *Check) { c.Argv = []string{"cat", "/etc/passwd;id"} }, RuleMetachar},
		{"metachar space", func(c *Check) { c.Argv = []string{"ls", "-la /etc"} }, RuleMetachar},
		{"metachar glob", func(c *Check) { c.Argv = []string{"cat", "/etc/sudoers.d/*"} }, RuleMetachar},
		{"metachar dollar", func(c *Check) { c.Argv = []string{"echo", "$HOME"} }, RuleMetachar},
		{"unbound placeholder", func(c *Check) { c.Argv = []string{"cat", "{file}"} }, RuleUnboundHole},
		{"multiply bound", func(c *Check) { c.Argv = []string{"diff", "{path}", "{path}"} }, RuleMultiplyBound},
		{"param without hole", func(c *Check) { c.Params = append(c.Params, Param{Name: "n", Kind: KindInt, Max: 5}) }, RuleParamWithoutHole},
		{"malformed placeholder", func(c *Check) { c.Argv = []string{"cat", "/etc/{path}"} }, RuleMalformedHole},
		{"mutating flag find -delete", func(c *Check) { c.Argv = []string{"find", "/tmp", "-delete"}; c.Params = nil }, RuleMutatingFlag},
		{"mutating flag find -exec", func(c *Check) { c.Argv = []string{"find", "/tmp", "-exec", "id"}; c.Params = nil }, RuleMutatingFlag},
		{"mutating prefix firewall-cmd", func(c *Check) { c.Argv = []string{"firewall-cmd", "--add-port=22/tcp"}; c.Params = nil }, RuleMutatingFlag},
		{"disallowed binary rm", func(c *Check) { c.Argv = []string{"rm", "-rf", "{path}"} }, RuleDisallowedBinary},
		{"disallowed binary sh", func(c *Check) { c.Argv = []string{"sh", "-c", "id"}; c.Params = nil }, RuleDisallowedBinary},
		{"disallowed binary by path", func(c *Check) { c.Argv = []string{"/bin/bash", "-c", "id"}; c.Params = nil }, RuleDisallowedBinary},
		{"verb not allowed systemctl", func(c *Check) { c.Argv = []string{"systemctl", "start", "sshd"}; c.Params = nil }, RuleVerbNotAllowed},
		{"verb missing systemctl", func(c *Check) { c.Argv = []string{"systemctl", "--no-pager"}; c.Params = nil }, RuleVerbNotAllowed},
		{"verb not allowed apt", func(c *Check) { c.Argv = []string{"apt", "install", "nmap"}; c.Params = nil }, RuleVerbNotAllowed},
		{"runtime php is denied", func(c *Check) { c.Argv = []string{"php", "-v"}; c.Params = nil }, RuleDisallowedBinary},
		{"runtime node is denied", func(c *Check) { c.Argv = []string{"node", "--version"}; c.Params = nil }, RuleDisallowedBinary},
		{"brew is denied", func(c *Check) { c.Argv = []string{"brew", "list", "--versions"}; c.Params = nil }, RuleDisallowedBinary},
		{"php-fpm version", func(c *Check) { c.Argv = []string{"php-fpm", "-v"}; c.Params = nil }, RuleDisallowedBinary},
		{"versioned php", func(c *Check) { c.Argv = []string{"/usr/bin/php8.3", "-i"}; c.Params = nil }, RuleDisallowedBinary},
		{"versioned php-fpm test", func(c *Check) { c.Argv = []string{"php-fpm8.3", "-t"}; c.Params = nil }, RuleDisallowedBinary},
		{"nodejs binary", func(c *Check) { c.Argv = []string{"nodejs", "--version"}; c.Params = nil }, RuleDisallowedBinary},
		{"npm", func(c *Check) { c.Argv = []string{"npm", "ls"}; c.Params = nil }, RuleDisallowedBinary},
		{"rpmquery sibling", func(c *Check) { c.Argv = []string{"rpmquery", "--pipe=x", "php"}; c.Params = nil }, RuleDisallowedBinary},
		{"rpmdb", func(c *Check) { c.Argv = []string{"rpmdb", "--rebuilddb"}; c.Params = nil }, RuleDisallowedBinary},
		{"dpkg purge", func(c *Check) { c.Argv = []string{"dpkg", "--purge", "x"}; c.Params = nil }, RuleDisallowedBinary},
		{"rpm install", func(c *Check) { c.Argv = []string{"rpm", "-i", "php"}; c.Params = nil }, RuleVerbNotAllowed},
		{"rpm query all", func(c *Check) { c.Argv = []string{"rpm", "-qa"}; c.Params = nil }, RuleVerbNotAllowed},
		{"rpm erase after query", func(c *Check) { c.Argv = []string{"rpm", "-q", "-e", "php"}; c.Params = nil }, RuleMutatingFlag},
		{"dpkg-query listing files", func(c *Check) { c.Argv = []string{"dpkg-query", "-L", "php"}; c.Params = nil }, RuleVerbNotAllowed},
		{"dpkg-query admindir", func(c *Check) { c.Argv = []string{"dpkg-query", "-s", "--admindir=/tmp/x", "php"}; c.Params = nil }, RuleVerbNotAllowed},
		{"rpm pipe", func(c *Check) { c.Argv = []string{"rpm", "-q", "--pipe=/tmp/x", "php"}; c.Params = nil }, RuleVerbNotAllowed},
		{"rpm rcfile", func(c *Check) { c.Argv = []string{"rpm", "-q", "--rcfile=/tmp/x", "php"}; c.Params = nil }, RuleVerbNotAllowed},
		{"rpm dbpath", func(c *Check) { c.Argv = []string{"rpm", "-q", "--dbpath=/tmp/x", "php"}; c.Params = nil }, RuleVerbNotAllowed},
		{"sudo in argv", func(c *Check) { c.Argv = []string{"sudo", "cat", "{path}"} }, RuleElevatedPrefixOnly},
		{"empty argv", func(c *Check) { c.Argv = nil; c.Params = nil }, RuleEmptyArgv},
		{"path param without pathuse", func(c *Check) { c.PathUse = PathNone }, RulePathUse},
		{"enum without values", func(c *Check) {
			c.Argv = []string{"stat", "{path}", "{mode}"}
			c.Params = append(c.Params, Param{Name: "mode", Kind: KindEnum})
		}, RuleBadParam},
		{"unknown parser", func(c *Check) { c.Parser = "xml" }, RuleParserKind},
		{"lines without unit", func(c *Check) { c.Unit = "" }, RuleMissingUnit},
		{"kv without unit", func(c *Check) { c.Parser, c.Unit = ParseKV, "" }, RuleMissingUnit},
		{"typed shape with unit", func(c *Check) { c.Parser = ParseListeners }, RuleMissingUnit},
		{"extract without group", func(c *Check) { c.Extract = "uuid" }, RuleExtract},
		{"extract invalid", func(c *Check) { c.Extract = "(" }, RuleExtract},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := good()
			tc.mutate(&c)
			vs := Validate([]Check{c, canary()})
			for _, v := range vs {
				if v.Rule == tc.rule {
					return
				}
			}
			t.Fatalf("rule %s not reported; got %v", tc.rule, vs)
		})
	}
}

func TestValidateCanaryCount(t *testing.T) {
	if vs := Validate([]Check{good()}); !hasRule(vs, RuleCanaryCount) {
		t.Errorf("zero canaries not reported: %v", vs)
	}
	c2 := canary()
	c2.ID = "sys.canary2"
	if vs := Validate([]Check{good(), canary(), c2}); !hasRule(vs, RuleCanaryCount) {
		t.Errorf("two canaries not reported: %v", vs)
	}
	// The canary is exempt from the metachar rule; nothing else is.
	notCanary := canary()
	notCanary.Canary = false
	if vs := Validate([]Check{notCanary, canary()}); !hasRule(vs, RuleMetachar) {
		t.Errorf("metachar literal outside the canary must be rejected: %v", vs)
	}
}

func TestValidateBaselineTierCap(t *testing.T) {
	cs := []Check{canary()}
	for i := 0; i <= BaselineTierCap; i++ {
		c := good()
		c.ID = "fs.stat_" + strings.Repeat("x", i+1)
		cs = append(cs, c)
	}
	if vs := Validate(cs); !hasRule(vs, RuleBaselineTierCap) {
		t.Errorf("cap not enforced: %v", vs)
	}
}

func hasRule(vs []Violation, rule string) bool {
	for _, v := range vs {
		if v.Rule == rule {
			return true
		}
	}
	return false
}
