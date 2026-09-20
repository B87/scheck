package policy

import (
	"fmt"
	"regexp"
	"sort"
)

// Hit records one redaction for the report's accounting.
type Hit struct {
	Rule  string
	Bytes int
}

// redactRule replaces submatch `group` of every match of `re` with a marker.
type redactRule struct {
	name  string
	re    *regexp.Regexp
	group int
	// keepIf skips a match whose captured value matches this (e.g. "yes"/"no"
	// after "password=" is a setting, not a secret).
	keepIf *regexp.Regexp
}

var trivialValue = regexp.MustCompile(`(?i)^["']?(yes|no|true|false|none|null|off|on|0|1|-|\*|x|required|optional|prompt|ask)["']?$`)

// compiledRules are applied in order. Private-key blocks go first so a key
// is never partially redacted by a narrower rule.
var compiledRules = []redactRule{
	{name: "private-key", re: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----`)},
	// A block cut off by truncation is still a key: redact to the end.
	{name: "private-key", re: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----[\s\S]*$`)},
	{name: "aws-access-key", re: regexp.MustCompile(`\b(AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b`)},
	{name: "github-token", re: regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b`)},
	{name: "slack-token", re: regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`)},
	{name: "bearer", re: regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9\-._~+/]{8,}=*)`), group: 1},
	{name: "jwt", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)},
	{name: "kv-secret", group: 3, keepIf: trivialValue,
		re: regexp.MustCompile(`(?i)\b([A-Za-z0-9_.-]*(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key)[A-Za-z0-9_.-]*)\s*[=:]\s*("[^"\n]*"|'[^'\n]*'|[^\s,;]+)`)},
}

// Redactor applies the compiled rules plus config `redact_extra` patterns.
type Redactor struct {
	rules []redactRule
}

// NewRedactor compiles the extra patterns; an invalid pattern is a config
// error, reported before any check runs.
func NewRedactor(extra []string) (*Redactor, error) {
	r := &Redactor{rules: append([]redactRule(nil), compiledRules...)}
	for i, pat := range extra {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("redact_extra[%d] %q: %w", i, pat, err)
		}
		r.rules = append(r.rules, redactRule{name: fmt.Sprintf("extra:%d", i), re: re})
	}
	return r, nil
}

// Marker is the text that replaces a redacted span. It is never empty, so a
// reader can always tell that something was there (SPEC.md §4.2).
func Marker(rule string, n int) string {
	return fmt.Sprintf("[REDACTED:%s:%d bytes]", rule, n)
}

// Redact returns a copy of b with every matched span replaced by a Marker.
// All rules are matched against the original bytes in one pass, so a marker
// inserted for one rule can never be re-matched by another; where spans
// overlap the earliest-listed rule wins.
func (r *Redactor) Redact(b []byte) ([]byte, []Hit) {
	type span struct {
		start, end, order int
		rule              string
	}
	var spans []span
	for order, rule := range r.rules {
		for _, loc := range rule.re.FindAllSubmatchIndex(b, -1) {
			gi := 2 * rule.group
			start, end := loc[gi], loc[gi+1]
			if start < 0 || end <= start {
				continue
			}
			if rule.keepIf != nil && rule.keepIf.Match(b[start:end]) {
				continue
			}
			spans = append(spans, span{start, end, order, rule.name})
		}
	}
	if len(spans) == 0 {
		return b, nil
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].order < spans[j].order
	})
	out := make([]byte, 0, len(b))
	var hits []Hit
	last := 0
	for _, sp := range spans {
		if sp.start < last {
			continue // overlaps a span already redacted
		}
		out = append(out, b[last:sp.start]...)
		out = append(out, Marker(sp.rule, sp.end-sp.start)...)
		hits = append(hits, Hit{sp.rule, sp.end - sp.start})
		last = sp.end
	}
	out = append(out, b[last:]...)
	return out, hits
}

// RedactString is Redact for strings.
func (r *Redactor) RedactString(s string) (string, []Hit) {
	b, hits := r.Redact([]byte(s))
	return string(b), hits
}
