package check

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Violation is one failed catalog invariant.
type Violation struct {
	CheckID string
	Rule    string
	Detail  string
}

func (v Violation) String() string { return v.CheckID + ": " + v.Rule + ": " + v.Detail }

// Rule names, so a test can assert which invariant caught a broken entry.
const (
	RuleMetachar           = "metachar-in-literal"
	RuleMalformedHole      = "malformed-placeholder"
	RuleUnboundHole        = "unbound-placeholder"
	RuleMultiplyBound      = "multiply-bound-placeholder"
	RuleParamWithoutHole   = "param-without-placeholder"
	RuleDisallowedBinary   = "disallowed-binary"
	RuleMutatingFlag       = "mutating-flag"
	RuleVerbNotAllowed     = "verb-not-allowed"
	RuleEmptyArgv          = "empty-argv"
	RuleBadParam           = "bad-param-definition"
	RulePathUse            = "path-param-without-pathuse"
	RuleCanaryCount        = "canary-count"
	RuleBaselineTierCap    = "baseline-tier-cap"
	RuleParserKind         = "unknown-parser"
	RuleElevatedPrefixOnly = "elevation-not-in-argv"
	RuleExtract            = "bad-extract"
)

// BaselineTierCap is the maximum number of on-demand checks visible under the
// baseline profile (SPEC.md §3, tiers).
const BaselineTierCap = 40

// literalRe is the whole character set a literal token may use. Everything
// the POSIX shell treats specially is outside it, which is what keeps the SSH
// quoter's input domain small (SPEC.md §4.3). An empty literal is allowed
// (`grep -rH "" dir`).
var literalRe = regexp.MustCompile(`^[A-Za-z0-9._/,:=+%@-]*$`)

// deniedBinaries can never be argv[0]: they write, spawn a shell, or execute
// arbitrary programs. Elevation prefixes (sudo) are added by the runner and
// must never appear in a catalog argv.
var deniedBinaries = map[string]bool{
	"rm": true, "rmdir": true, "mv": true, "cp": true, "dd": true, "tee": true, "ln": true,
	"chmod": true, "chown": true, "chgrp": true, "chflags": true, "touch": true, "mkdir": true,
	"install": true, "truncate": true, "shred": true, "sed": true, "awk": true, "perl": true,
	"python": true, "python3": true, "ruby": true, "node": true, "sh": true, "bash": true,
	"zsh": true, "dash": true, "ksh": true, "fish": true, "env": true, "xargs": true,
	"nohup": true, "sudo": true, "su": true, "doas": true, "run0": true, "eval": true,
	"exec": true, "curl": true, "wget": true, "nc": true, "ssh": true, "scp": true,
	"apt-get": true, "iptables": true, "ip6tables": true, "auditctl": true, "setenforce": true,
	"setsebool": true, "semanage": true, "visudo": true, "usermod": true, "useradd": true,
	"userdel": true, "kill": true, "pkill": true, "killall": true, "reboot": true,
	"shutdown": true, "mount": true, "umount": true, "crontab": true,
}

// binaryRule constrains a binary that has both query and mutating modes.
// verbs, when non-nil, is the allowlist for the first non-flag token (and it
// must be present). denyTokens and denyPrefixes are rejected anywhere in argv.
type binaryRule struct {
	verbs        []string
	denyTokens   []string
	denyPrefixes []string
}

var binaryRules = map[string]binaryRule{
	"find": {denyTokens: []string{"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"}},
	"systemctl": {verbs: []string{"is-active", "is-enabled", "is-failed", "is-system-running", "list-units",
		"list-unit-files", "list-timers", "list-sockets", "list-dependencies", "show", "status", "cat", "get-default"}},
	"launchctl":      {verbs: []string{"list", "print", "print-disabled", "dumpstate", "version"}},
	"apt":            {verbs: []string{"list", "policy", "show"}},
	"dnf":            {verbs: []string{"check-update", "list", "info", "repolist", "history"}},
	"yum":            {verbs: []string{"check-update", "list", "info", "repolist"}},
	"zypper":         {verbs: []string{"lp", "list-patches", "lu", "list-updates", "info", "se", "search", "pa", "packages"}},
	"pacman":         {verbs: []string{"-Q", "-Qu", "-Qi", "-Qk"}},
	"defaults":       {verbs: []string{"read", "read-type", "domains", "find"}},
	"dscl":           {denyTokens: []string{"-create", "-delete", "-append", "-change", "-changei", "-merge", "-passwd", "-authonly"}},
	"csrutil":        {verbs: []string{"status"}},
	"fdesetup":       {verbs: []string{"status", "list", "haspersonalrecoverykey", "hasinstitutionalrecoverykey", "isactive", "usingrecoverykey"}},
	"softwareupdate": {denyTokens: []string{"-i", "--install", "-ia", "-ir", "-d", "--download", "--fetch-full-installer", "--reset-ignored", "--ignore", "--schedule", "--background", "--evaluate-products"}},
	"spctl":          {denyTokens: []string{"--master-enable", "--master-disable", "--global-enable", "--global-disable", "--add", "--remove", "--enable", "--disable", "--rebuild"}},
	"socketfilterfw": {denyPrefixes: []string{"--set", "--add", "--remove", "--block", "--unblock"}, denyTokens: []string{"--listapps"}},
	"ufw":            {verbs: []string{"status", "version", "show"}},
	"firewall-cmd":   {denyPrefixes: []string{"--add", "--remove", "--set", "--new", "--delete", "--change", "--permanent", "--reload", "--complete-reload", "--load", "--runtime-to-permanent", "--panic-on", "--panic-off", "--lockdown-on", "--lockdown-off", "--direct"}},
	"nft":            {verbs: []string{"list", "describe"}, denyTokens: []string{"-f", "--file", "-i", "--interactive"}},
	"passwd":         {denyPrefixes: []string{"-d", "-l", "-u", "-e", "-x", "-n", "-w", "-i", "-k", "--delete", "--lock", "--unlock", "--expire"}},
	"systemsetup":    {denyPrefixes: []string{"-set"}},
	"timedatectl":    {verbs: []string{"status", "show", "timesync-status", "show-timesync", "list-timezones"}},
	"hostnamectl":    {verbs: []string{"status", "hostname"}, denyPrefixes: []string{"set-"}},
	"journalctl":     {denyPrefixes: []string{"--vacuum", "--rotate", "--flush", "--sync", "--relinquish", "--smart-relinquish", "--setup-keys", "--verify", "--update-catalog"}},
	"log":            {verbs: []string{"config", "show", "stats"}, denyTokens: []string{"--mode", "--subsystem", "--process", "--reset"}},
	"aa-status":      {},
	"sestatus":       {},
	"sshd":           {verbs: []string{"-T", "-t", "-G"}, denyTokens: []string{"-D", "-d", "-i", "-f", "-o", "-p", "-h", "-c", "-E"}},
	"git":            {verbs: []string{"status", "log", "diff", "show", "rev-parse", "config"}},
	"stat":           {},
	"lsblk":          {},
	"ss":             {},
	"lsof":           {},
}

// Validate applies every catalog invariant to cs and returns each failure.
// It never panics on a malformed entry; that is the point.
func Validate(cs []Check) []Violation {
	var out []Violation
	canaries := 0
	onDemandBaseline := 0
	for _, c := range cs {
		out = append(out, validateOne(c)...)
		if c.Canary {
			canaries++
		}
		if c.OnDemand() && c.MinProfile == ProfileBaseline {
			onDemandBaseline++
		}
	}
	if len(cs) > 0 && canaries != 1 {
		out = append(out, Violation{"<catalog>", RuleCanaryCount, fmt.Sprintf("want exactly 1 canary check, have %d", canaries)})
	}
	if onDemandBaseline > BaselineTierCap {
		out = append(out, Violation{"<catalog>", RuleBaselineTierCap,
			fmt.Sprintf("%d on-demand checks at baseline profile, cap is %d; promote frequent ones to Baseline instead", onDemandBaseline, BaselineTierCap)})
	}
	return out
}

func validateOne(c Check) []Violation {
	var vs []Violation
	add := func(rule, format string, args ...any) {
		vs = append(vs, Violation{c.ID, rule, fmt.Sprintf(format, args...)})
	}
	if len(c.Argv) == 0 {
		add(RuleEmptyArgv, "no argv")
		return vs
	}
	switch c.Parser {
	case ParseRaw, ParseLines, ParseKV, ParseJSON:
	default:
		add(RuleParserKind, "parser %q", c.Parser)
	}
	if c.Extract != "" {
		re, err := regexp.Compile(c.Extract)
		if err != nil {
			add(RuleExtract, "extract %q: %v", c.Extract, err)
		} else if re.NumSubexp() != 1 {
			add(RuleExtract, "extract %q must have exactly one capture group", c.Extract)
		}
	}

	declared := map[string]Param{}
	for _, p := range c.Params {
		if _, dup := declared[p.Name]; dup {
			add(RuleBadParam, "param %q declared twice", p.Name)
		}
		declared[p.Name] = p
		switch p.Kind {
		case KindEnum:
			if len(p.Enum) == 0 {
				add(RuleBadParam, "enum param %q has no values", p.Name)
			}
			for _, e := range p.Enum {
				if !literalRe.MatchString(e) || e == "" {
					add(RuleBadParam, "enum value %q for %q is not a clean literal", e, p.Name)
				}
			}
		case KindInt:
			if p.Min > p.Max {
				add(RuleBadParam, "int param %q has min > max", p.Name)
			}
		case KindPath:
			if c.PathUse == PathNone {
				add(RulePathUse, "check has a path param but no PathUse")
			}
		case KindIdent:
		default:
			add(RuleBadParam, "param %q has unknown kind %q", p.Name, p.Kind)
		}
	}

	bound := map[string]int{}
	for i, tok := range c.Argv {
		if name := Placeholder(tok); name != "" {
			if _, ok := declared[name]; !ok {
				add(RuleUnboundHole, "token %d {%s} has no param", i, name)
			}
			bound[name]++
			continue
		}
		if strings.ContainsAny(tok, "{}") {
			add(RuleMalformedHole, "token %d %q: braces only as a whole-token placeholder", i, tok)
			continue
		}
		if !c.Canary && !literalRe.MatchString(tok) {
			add(RuleMetachar, "token %d %q contains characters outside %s", i, tok, literalRe)
		}
	}
	for name, n := range bound {
		if n > 1 {
			add(RuleMultiplyBound, "{%s} bound %d times", name, n)
		}
	}
	for name := range declared {
		if bound[name] == 0 {
			add(RuleParamWithoutHole, "param %q never appears in argv", name)
		}
	}

	bin := baseName(c.Argv[0])
	if deniedBinaries[bin] {
		add(RuleDisallowedBinary, "%s is not a read-only binary", bin)
	}
	if bin == "sudo" || bin == "doas" {
		add(RuleElevatedPrefixOnly, "elevation is a runner prefix, never catalog argv")
	}
	if rule, ok := binaryRules[bin]; ok {
		vs = append(vs, checkBinaryRule(c, bin, rule)...)
	}
	return vs
}

func checkBinaryRule(c Check, bin string, rule binaryRule) []Violation {
	var vs []Violation
	args := c.Argv[1:]
	for _, tok := range args {
		if slices.Contains(rule.denyTokens, tok) {
			vs = append(vs, Violation{c.ID, RuleMutatingFlag, fmt.Sprintf("%s %s", bin, tok)})
		}
		for _, p := range rule.denyPrefixes {
			if strings.HasPrefix(tok, p) {
				vs = append(vs, Violation{c.ID, RuleMutatingFlag, fmt.Sprintf("%s %s (prefix %s)", bin, tok, p)})
			}
		}
	}
	if rule.verbs != nil {
		verb := ""
		for _, tok := range args {
			// pacman-style verbs are dash-prefixed; treat any token as the verb
			// when the allowlist is dash-prefixed.
			if !strings.HasPrefix(tok, "-") || strings.HasPrefix(rule.verbs[0], "-") {
				verb = tok
				break
			}
		}
		if !slices.Contains(rule.verbs, verb) {
			vs = append(vs, Violation{c.ID, RuleVerbNotAllowed, fmt.Sprintf("%s %q: allowed verbs %s", bin, verb, strings.Join(rule.verbs, "|"))})
		}
	}
	return vs
}

func baseName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}
