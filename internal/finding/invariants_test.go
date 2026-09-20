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
// parser (docs/SPEC.md §7.5).
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

// A rule finding has no model to write its text, so every definition carries
// its own title, impact and remediation (docs/SPEC.md §7.1).
func TestEveryDefIsComplete(t *testing.T) {
	for _, d := range Defs() {
		if d.BaseSeverity.Rank() < 0 || d.Title == "" || d.Impact == "" || d.Remediation.Summary == "" {
			t.Errorf("%s is incomplete: %+v", d.ID, d)
		}
		if strings.HasSuffix(d.Title, ".") {
			t.Errorf("%s: a title is a phrase, not a sentence: %q", d.ID, d.Title)
		}
	}
	// Every finding id in the catalog is reachable from a rule; an id with no
	// rule and no model to raise it would never appear in a report.
	reachable := map[string]bool{}
	for _, r := range Rules() {
		reachable[r.Finding] = true
	}
	for _, d := range Defs() {
		if !reachable[d.ID] {
			t.Errorf("%s has no rule that can raise it", d.ID)
		}
	}
}
