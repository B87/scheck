package check

import (
	"fmt"
	"sort"
	"strings"
)

// Summary is the one-line reading of a parsed fact: "26 listening sockets",
// "0 SUID files", "FileVault is On." (docs/SPEC.md §7.6). The same string is
// `summary` in the envelope, the line in the text report, and — from phase 2
// — what the model reads, so it is produced here beside the parsers rather
// than in a renderer.
//
// It is a reading, never a verdict: it says what the command observed, not
// whether the host is configured well. That judgement belongs to the posture
// rules (§7.5).
func Summary(c Check, parsed any) string {
	switch v := parsed.(type) {
	case Records:
		return recordSummary(c, v)
	case string:
		return rawSummary(v)
	case []string:
		return countOf(len(v), unitOr(c, "lines")) + inlineLines(v)
	case map[string]string:
		return countOf(len(v), unitOr(c, "settings"))
	case map[string]any:
		return countOf(len(v), unitOr(c, "keys"))
	case []any:
		return countOf(len(v), unitOr(c, "items"))
	case nil:
		return "no output"
	default:
		return "output recorded"
	}
}

func unitOr(c Check, fallback string) string {
	if c.Unit != "" {
		return c.Unit
	}
	return fallback
}

// rawSummary reads the one line a single-answer command produced ("FileVault
// is On."). A chattier raw check says how much more there was rather than
// pretending its first line is the whole answer.
func rawSummary(v string) string {
	lines := parseLines([]byte(v))
	if len(lines) == 0 {
		return "no output"
	}
	s := clipRunes(strings.Join(strings.Fields(lines[0]), " "), 120)
	if n := len(lines) - 1; n > 0 {
		s += fmt.Sprintf(" (+%s)", countOf(n, "more lines"))
	}
	return s
}

// inlineLines shows the content of a very short lines fact, because "2
// service states" alone answers nothing while "2 service states: disabled,
// disabled" does. Anything longer stays a count: the full output is one
// `-vv` away.
func inlineLines(v []string) string {
	if len(v) == 0 || len(v) > 3 {
		return ""
	}
	parts := make([]string, 0, len(v))
	for _, l := range v {
		if isMarkerLine(l) {
			return ""
		}
		parts = append(parts, strings.Join(strings.Fields(l), " "))
	}
	joined := strings.Join(parts, ", ")
	if len([]rune(joined)) > 48 {
		return ""
	}
	return ": " + joined
}

func recordSummary(c Check, r Records) string {
	var s string
	switch r.Kind {
	case ParseListeners:
		s = countOf(r.Len(), "listening sockets")
	case ParseAccounts:
		s = countOf(r.Len(), "accounts")
		if n := countField(r, FieldShell, isLoginShell); n >= 0 {
			s += fmt.Sprintf(", %d with a login shell", n)
		}
	case ParsePasswdStatus:
		s = countOf(r.Len(), "accounts") + byValue(r, FieldStatus, map[string]string{
			"NP": "with no password", "L": "locked", "P": "with a password set",
		})
	case ParseUnits:
		s = countOf(r.Len(), "units") + byValue(r, FieldState, nil)
	case ParseUpdates:
		s = countOf(r.Len(), "updates") + " available"
	case ParseLaunchd:
		s = countOf(r.Len(), "launchd jobs")
		if n := countField(r, FieldPID, func(v string) bool { return v != "-" && v != "" }); n >= 0 {
			s += fmt.Sprintf(", %d running", n)
		}
	case ParseFileMode:
		s = fileModeSummary(r)
	default:
		s = countOf(r.Len(), unitOr(c, "records"))
	}
	if r.Partial {
		s += " (partial"
		if r.Note != "" {
			s += ": " + r.Note
		}
		s += ")"
	}
	return s
}

func fileModeSummary(r Records) string {
	if r.Len() == 0 {
		return "no mode recorded"
	}
	rec := r.Items[0]
	s := "mode " + rec[FieldMode]
	if o := strings.Trim(rec[FieldUser]+":"+rec[FieldGroup], ":"); o != "" {
		s += ", owner " + o
	}
	return s
}

// countField counts records whose field satisfies want, or -1 when no record
// carries the field at all (the tool did not report it).
func countField(r Records, field string, want func(string) bool) int {
	n, present := 0, false
	for _, rec := range r.Items {
		v, ok := rec[field]
		if !ok || v == "" {
			continue
		}
		present = true
		if want(v) {
			n++
		}
	}
	if !present {
		return -1
	}
	return n
}

// byValue tallies one field across the records, most common first, so a
// status column becomes a reading: "22 accounts: 22 locked".
func byValue(r Records, field string, label map[string]string) string {
	counts := map[string]int{}
	for _, rec := range r.Items {
		v := rec[field]
		if v == "" {
			v = "unknown"
		}
		counts[v]++
	}
	if len(counts) == 0 {
		return ""
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	name := func(k string) string {
		if l, ok := label[k]; ok {
			return l
		}
		return k
	}
	if len(keys) == 1 {
		return ", all " + name(keys[0])
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", counts[k], name(k)))
	}
	return ": " + strings.Join(parts, ", ")
}

// nologin shells are the conventional way to say "this account cannot log
// in"; anything else is treated as a usable shell for the count.
var nologinShells = map[string]bool{
	"/usr/sbin/nologin": true, "/sbin/nologin": true, "/usr/bin/nologin": true,
	"/bin/false": true, "/usr/bin/false": true, "/dev/null": true, "": true,
}

func isLoginShell(s string) bool { return !nologinShells[strings.TrimSpace(s)] }

// countOf writes "1 SUID file" rather than "1 SUID files"; Unit is a plural
// noun (docs/SPEC.md §3).
func countOf(n int, plural string) string {
	if n == 1 {
		return "1 " + singularize(plural)
	}
	return fmt.Sprintf("%d %s", n, plural)
}

func singularize(plural string) string {
	switch {
	case strings.HasSuffix(plural, "ies"):
		return strings.TrimSuffix(plural, "ies") + "y"
	case strings.HasSuffix(plural, "sses"), strings.HasSuffix(plural, "shes"), strings.HasSuffix(plural, "ches"):
		return strings.TrimSuffix(plural, "es")
	case strings.HasSuffix(plural, "s") && !strings.HasSuffix(plural, "ss"):
		return strings.TrimSuffix(plural, "s")
	}
	return plural
}

func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
