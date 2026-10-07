package policy

import (
	"math"
	"regexp"
	"slices"
)

// Credential detectors, by shape only (docs/spec/engagement.md, "Validation"):
// known token prefixes, PEM private-key headers, credentials inside a URL, and
// high-entropy strings. Keywords are not a signal here: a file that says
// "password" in a description holds no password, and a token pasted without
// one is still a token.
var (
	privateKeyHeader = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----`)
	urlUserinfo      = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@`)
	// bearerValue is the redactor's bearer shape with a token that has a
	// digit: "bearer authentication" is prose, "Bearer 3f9a…" is a token.
	bearerValue = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z\-._~+/]*[0-9][A-Za-z0-9\-._~+/]{7,}`)
	// entropyToken is a run of the characters keys and tokens are written in.
	entropyToken = regexp.MustCompile(`[A-Za-z0-9+/=_-]{20,}`)
	// segmentSep is where paths, names and slugs join words.
	segmentSep = regexp.MustCompile(`[/_-]`)
	hexToken   = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

var credentialShapes = []struct {
	name string
	re   *regexp.Regexp
}{
	{"private-key", privateKeyHeader},
	{"aws-access-key", awsAccessKey},
	{"github-token", githubToken},
	{"slack-token", slackToken},
	{"jwt", jwtToken},
	{"bearer", bearerValue},
	{"url-credentials", urlUserinfo},
}

// DetectCredential reports whether s holds a value shaped like a credential,
// and the name of the detector that matched. It never returns the value, so
// a caller cannot print it by accident.
func DetectCredential(s string) (detector string, found bool) {
	for _, c := range credentialShapes {
		if c.re.MatchString(s) {
			return c.name, true
		}
	}
	for _, tok := range entropyToken.FindAllString(s, -1) {
		if mixedCase(segmentSep.ReplaceAllString(tok, "")) || slices.ContainsFunc(segmentSep.Split(tok, -1), hexRun) {
			return "high-entropy", true
		}
	}
	return "", false
}

// Written text changes character class at word boundaries
// (ProductionBackup2026Q4 changes 6 times in 22 characters); a random token
// changes at about two of every three characters. So a run qualifies as
// generated when it is long, mixes classes, changes class often and has high
// per-character Shannon entropy. Words, CamelCase names, paths, hostnames,
// UUIDs and lowercase project ids do not qualify.

// mixedCase is the rule for a mixed-case alphanumeric run of 20 or more,
// read with path and slug separators removed so that a base64 / does not
// split a key, and a path's words still read as words.
func mixedCase(run string) bool {
	upper, lower, digit, ratio := classes(run)
	return len(run) >= 20 && upper && lower && digit && ratio >= 0.4 && entropy(run) >= 3.5
}

// hexRun is the rule for a hex run of 32 or more, read per segment so that a
// UUID's groups stay short.
func hexRun(seg string) bool {
	upper, lower, digit, ratio := classes(seg)
	return len(seg) >= 32 && hexToken.MatchString(seg) && digit && (upper || lower) && ratio >= 0.3 && entropy(seg) >= 3.0
}

// classes reports which classes s holds and the share of its characters at
// which the class changes.
func classes(s string) (upper, lower, digit bool, ratio float64) {
	changes, prev := 0, -1
	for i := 0; i < len(s); i++ {
		c := charClass(s[i])
		switch c {
		case 0:
			upper = true
		case 1:
			lower = true
		case 2:
			digit = true
		}
		if prev >= 0 && c != prev {
			changes++
		}
		prev = c
	}
	return upper, lower, digit, float64(changes) / float64(max(len(s)-1, 1))
}

// charClass is 0 upper, 1 lower, 2 digit, 3 anything else.
func charClass(b byte) int {
	switch {
	case b >= 'A' && b <= 'Z':
		return 0
	case b >= 'a' && b <= 'z':
		return 1
	case b >= '0' && b <= '9':
		return 2
	}
	return 3
}

// entropy is the Shannon entropy of s in bits per byte.
func entropy(s string) float64 {
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}
