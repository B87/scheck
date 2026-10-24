package policy

import (
	"bytes"
	"regexp"
	"slices"
)

// SecretLocation exposes detector provenance, never matched bytes. History
// detection is redaction (docs/spec/github-collector.md, "Rules and subjects").
type SecretLocation struct {
	Rule   string
	Marker string
	Line   int
	Bytes  int
}

// SecretLocations uses only compiled redactions and the session credential.
// Operator extra patterns and entropy guesses cannot create findings.
func SecretLocations(b []byte, credential string) ([]SecretLocation, bool) {
	rules := slices.Clone(compiledRules)
	if credential != "" {
		rules = append([]redactRule{{name: "credential", re: regexp.MustCompile(regexp.QuoteMeta(credential))}}, rules...)
	}
	type match struct {
		start, end, order int
		rule              string
	}
	var matches []match
	complete := true
	for order, r := range rules {
		raw := r.re.FindAllSubmatchIndex(b, 10001)
		if len(raw) == 10001 {
			complete = false
		}
		for _, m := range raw {
			start, end := m[2*r.group], m[2*r.group+1]
			if start < 0 || end <= start || (r.keepIf != nil && r.keepIf.Match(b[start:end])) {
				continue
			}
			if r.skipKey != nil && m[2*r.keyGroup] >= 0 && r.skipKey.Match(b[m[2*r.keyGroup]:m[2*r.keyGroup+1]]) {
				continue
			}
			matches = append(matches, match{start, end, order, r.name})
		}
	}

	slices.SortFunc(matches, func(a, b match) int {
		if a.start != b.start {
			return a.start - b.start
		}
		return a.order - b.order
	})
	out := []SecretLocation{}
	last := 0
	line, previousStart := 1, 0
	for _, m := range matches {
		if m.start < last {
			continue
		}
		line += bytes.Count(b[previousStart:m.start], []byte{'\n'})
		previousStart = m.start
		out = append(out, SecretLocation{m.rule, Marker(m.rule, m.end-m.start), line, m.end - m.start})
		if len(out) >= 10001 {
			break
		}
		last = m.end
	}
	return out, complete
}

// ExtraRedactionCounts counts bounded operator matches without returning source bytes.
func (r *Redactor) ExtraRedactionCounts(b []byte) []Hit {
	var out []Hit
	for _, rule := range r.rules[len(compiledRules):] {
		for _, m := range rule.re.FindAllIndex(b, 10001) {
			if m[1] > m[0] {
				out = append(out, Hit{Rule: rule.name, Bytes: m[1] - m[0]})
			}
			if len(out) >= 10001 {
				return out
			}
		}
	}
	return out
}
