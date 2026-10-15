package rules

import (
	"fmt"
	"slices"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
)

// Violation is one broken invariant of the rule table.
type Violation struct{ Rule, Problem string }

func (v Violation) String() string { return v.Rule + ": " + v.Problem }

// Validate checks the rule table as written: each rule produces a
// registered multi-fact finding, once, reads something, and every check it
// declares is in its platform's catalog. Its fixtures prove the rest: that
// it reads only what it declares and decides all three ways.
func Validate(rules []Rule) []Violation {
	var out []Violation
	seen := map[string]bool{}
	for _, r := range rules {
		bad := func(format string, args ...any) { out = append(out, Violation{r.ID, fmt.Sprintf(format, args...)}) }
		def, ok := finding.Lookup(r.ID)
		switch {
		case !ok:
			bad("no finding definition")
		case !def.MultiFact:
			bad("its definition is not marked MultiFact")
		}
		if seen[r.ID] {
			bad("listed twice")
		}
		seen[r.ID] = true
		if len(r.Reads) == 0 || r.Judge == nil {
			bad("reads nothing or has no judge")
		}
		if r.Group == "" || r.Unbuilt == "" || r.Incomplete.Reason == "" {
			bad("no coverage wording")
		}
		for _, read := range r.Reads {
			switch read.Kind {
			case ReadCheck:
				if _, ok := check.Lookup(read.Name, r.Platform); !ok {
					bad("reads %s, which is not in the %s catalog", read.Name, r.Platform)
				}
			case ReadDeclared:
				if read.Name != DeclaredServices {
					bad("reads declaration %s, which no host context carries", read.Name)
				}
			default:
				bad("read kind %q", read.Kind)
			}
		}
		for i, read := range r.Reads {
			if slices.Contains(r.Reads[i+1:], read) {
				bad("declares %s:%s twice", read.Kind, read.Name)
			}
		}
	}
	return out
}
