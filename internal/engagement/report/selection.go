package report

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/b87/scheck/internal/finding"
)

// kindWords names a collector's kind of budgeted read in the selection line.
var kindWords = map[string]string{
	"oauth_grants":      "third-party app grants",
	"mail_forwarding":   "mail forwarding",
	"access":            "access and branch protection",
	"ci":                "workflows",
	"secret_alerts":     "secret-scanning alerts",
	"dependabot_alerts": "Dependabot alerts",
	"secret_locations":  "secret alert locations",
}

// selectionText words a selection as docs/spec/report.md, "Coverage" has
// it: what chose the items read, in tier order, then the fallback, and
// the requests sent against the budget.
func selectionText(s finding.Selection) string {
	unit := s.Unit
	var b strings.Builder
	of := strconv.Itoa(s.InScope)
	if s.InScopeAtLeast {
		of = "at least " + of
	}
	switch {
	case s.Read == s.InScope && s.InScopeAtLeast:
		fmt.Fprintf(&b, "all %d %s listed read; the list was not complete, so more may be in scope", s.InScope, unit)
	case s.Read == s.InScope && s.Budget > 0:
		fmt.Fprintf(&b, "all %d %s read; the request budget cut nothing", s.InScope, unit)
	case s.Read == s.InScope:
		fmt.Fprintf(&b, "all %d %s read", s.InScope, unit)
	default:
		// Tiers in their own order; the fallback order's tier (no source)
		// and archived repositories after them.
		var parts []string
		declared := false
		pushed, archived := 0, 0
		fallback := fallbackWords(s)
		for _, t := range s.Tiers {
			switch {
			case t.Source != "":
				parts = append(parts, fmt.Sprintf("%s (%d, %s)", t.Basis, t.Count, t.Source))
				declared = declared || t.Source != "observed"
			case t.Basis == "archived":
				archived += t.Count
			default:
				pushed += t.Count
			}
		}
		switch {
		case !declared && pushed == 0:
			parts = append(parts, "no declaration named any "+singularUnit(unit))
		case !declared:
			parts = append(parts, fmt.Sprintf("no declaration named any %s; %s (%d)", singularUnit(unit), fallback, pushed))
		case pushed > 0:
			parts = append(parts, fmt.Sprintf("then %s (%d)", fallback, pushed))
		}
		if archived > 0 {
			parts = append(parts, fmt.Sprintf("archived (%d)", archived))
		}
		fmt.Fprintf(&b, "%d of %s %s: %s", s.Read, of, unit, strings.Join(parts, ", "))
	}
	if s.Budget > 0 {
		fmt.Fprintf(&b, "; sent %s of a %s budget", thousands(s.Spent), thousands(s.Budget))
	}
	b.WriteString(".")
	return b.String()
}

// thousands writes n with a comma between groups of three digits.
func thousands(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// selectionLines are a row's distinct selection lines, each naming its
// kind when the row's kinds reached differently.
func selectionLines(row Row) []string {
	type line struct{ kind, unit, text string }
	var lines []line
	texts := map[string]bool{}
	for _, si := range row.SubItems {
		p := si.Population
		if p == nil || p.Selection == nil {
			continue
		}
		t := selectionText(*p.Selection)
		if texts[t] {
			continue
		}
		texts[t] = true
		lines = append(lines, line{p.Selection.Kind, p.Selection.Unit, t})
	}
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = upper(l.unit) + ": " + l.text
		if len(lines) > 1 {
			out[i] = upper(l.unit) + " read for " + kindWords[l.kind] + ": " + l.text
		}
	}
	return out
}

// singularUnit is a selection's unit in the singular.
func singularUnit(unit string) string {
	switch unit {
	case "repositories":
		return "repository"
	case "users":
		return "user"
	}
	return strings.TrimSuffix(unit, "s")
}

// fallbackWords names a selection's fallback order: what orders the items
// no declaration put in a tier.
func fallbackWords(s finding.Selection) string {
	switch {
	case s.Unit == "repositories":
		return "most recently pushed"
	case s.Kind == "mail_forwarding":
		return "the rest, active first"
	case s.Unit == "users":
		return "the rest, active and most recently signed in first"
	}
	return s.Fallback
}
