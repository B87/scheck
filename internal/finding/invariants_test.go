package finding

import (
	"strings"
	"testing"

	"github.com/b87/scheck/internal/check"
	_ "github.com/b87/scheck/internal/check/all" // the real catalog
)

// The compiled-in rule table is validated against the compiled-in check
// catalog: a rule can only name a check that exists on its platform, a
// finding that has a definition, and a predicate that can read that check's
// parser (docs/spec/host-collector.md §6.5).
func TestRuleTableInvariants(t *testing.T) {
	if vs := ValidateRules(); len(vs) != 0 {
		for _, v := range vs {
			t.Errorf("%s", v)
		}
	}
	if len(Rules()) == 0 || len(Defs()) == 0 {
		t.Fatal("the rule and finding catalogs must not be empty")
	}
}

// Each violation class is caught by name, loudly, without a panic.
func TestValidateRulesCatchesEachClass(t *testing.T) {
	saved := rules
	defer func() { rules = saved }()
	cases := []struct {
		name string
		rule Rule
		want string
	}{
		{"unknown finding id", Rule{Finding: "nope.invented", Check: "sshd.config", Platform: check.Any,
			When: KeyEquals{Key: "x", Value: "y"}}, RuleUnknownFinding},
		{"unknown check id", Rule{Finding: IDPasswordAuthEnabled, Check: "nope.invented", Platform: check.Any,
			When: KeyEquals{Key: "x", Value: "y"}}, RuleUnknownCheck},
		{"check missing on one platform", Rule{Finding: IDFileVaultOff, Check: "disk.fdesetup", Platform: check.Any,
			When: RawMatch{Regexp: "off"}}, RuleUnknownCheck},
		{"predicate cannot read the parser", Rule{Finding: IDPasswordAuthEnabled, Check: "sshd.config", Platform: check.Any,
			When: AnyLine{Regexp: "yes"}}, RuleParserMismatch},
		{"no predicate", Rule{Finding: IDPasswordAuthEnabled, Check: "sshd.config", Platform: check.Any},
			RuleNoPredicate},
		{"bad regexp", Rule{Finding: IDFileVaultOff, Check: "disk.fdesetup", Platform: check.MacOS,
			When: RawMatch{Regexp: "("}}, RuleBadRegexp},
		{"second check without a join predicate", Rule{Finding: IDEmptyPassword, Check: "accounts.passwd_status", With: "accounts.passwd",
			Platform: check.Linux, When: FieldEquals{Field: check.FieldStatus, Value: "NP"}}, RuleWithCheck},
		{"join predicate without a second check", Rule{Finding: IDEmptyPassword, Check: "accounts.passwd_status",
			Platform: check.Linux, When: StatusWithLoginShell{Field: check.FieldStatus, Value: "NP"}}, RuleWithCheck},
		{"second check is the first", Rule{Finding: IDEmptyPassword, Check: "accounts.passwd_status", With: "accounts.passwd_status",
			Platform: check.Linux, When: StatusWithLoginShell{Field: check.FieldStatus, Value: "NP"}}, RuleWithCheck},
		{"second check not in the catalog", Rule{Finding: IDEmptyPassword, Check: "accounts.passwd_status", With: "nope.invented",
			Platform: check.Linux, When: StatusWithLoginShell{Field: check.FieldStatus, Value: "NP"}}, RuleWithCheck},
		{"join predicate cannot read the second check", Rule{Finding: IDEmptyPassword, Check: "accounts.passwd_status", With: "accounts.shadow_meta",
			Platform: check.Linux, When: StatusWithLoginShell{Field: check.FieldStatus, Value: "NP"}}, RuleWithCheck},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules = []Rule{tc.rule}
			vs := ValidateRules()
			if len(vs) == 0 {
				t.Fatalf("no violation reported for %s", tc.name)
			}
			for _, v := range vs {
				if v.Rule == tc.want {
					return
				}
			}
			t.Fatalf("want %s, got %v", tc.want, vs)
		})
	}
}

// A definition without a risk area or an exposure declaration is caught by
// name: the engagement report cannot place or adjust it (docs/spec/engagement.md,
// "Severity in context").
func TestValidateRulesCatchesIncompleteDefs(t *testing.T) {
	saved := defs
	defer func() { defs = saved }()
	base := saved[IDPasswordAuthEnabled]
	cases := []struct {
		name string
		edit func(*Def)
		want string
	}{
		{"no area", func(d *Def) { d.Area = "" }, RuleDefArea},
		{"unknown area", func(d *Def) { d.Area = "network" }, RuleDefArea},
		{"exposure undeclared", func(d *Def) { d.Exposure = exposureUndeclared }, RuleDefExposure},
		{"judges missing", func(d *Def) { d.Judges = "" }, RuleDefJudges},
		{"unknown subject kind", func(d *Def) { d.Subject = "listener" }, RuleDefSubject},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := base
			tc.edit(&d)
			defs = map[string]Def{d.ID: d}
			for _, v := range ValidateRules() {
				if v.Subject == d.ID && v.Rule == tc.want {
					return
				}
			}
			t.Fatalf("want %s for %s", tc.want, tc.name)
		})
	}
}

// A rule finding has no model to write its text, so every definition carries
// its own title, impact and remediation (docs/spec/host-collector.md §6.1).
func TestEveryDefIsComplete(t *testing.T) {
	for _, d := range Defs() {
		if d.BaseSeverity.Rank() < 0 || d.Title == "" || d.Impact == "" || d.Remediation.Summary == "" {
			t.Errorf("%s is incomplete: %+v", d.ID, d)
		}
		if strings.HasSuffix(d.Title, ".") {
			t.Errorf("%s: a title is a phrase, not a sentence: %q", d.ID, d.Title)
		}
	}
	// Every finding id in the catalog is reachable: from a rule, from the
	// grader (context-derived) or from the model (judgement). An id nothing
	// can raise would never appear in a report.
	reachable := map[string]bool{}
	for _, r := range Rules() {
		reachable[r.Finding] = true
	}
	for id := range judgementDefs {
		reachable[id] = true
	}
	for _, d := range Defs() {
		if !reachable[d.ID] {
			t.Errorf("%s has no rule, grader or model path that can raise it", d.ID)
		}
	}
}
