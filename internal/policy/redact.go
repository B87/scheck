package policy

import (
	"bytes"
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
	// keyGroup and skipKey skip a match whose key (submatch keyGroup) is a
	// known non-secret: a sudoers tag such as `NOPASSWD:` is followed by a
	// command, and redacting it hides exactly what the model must judge
	// (docs/spec/host-collector.md §4.2).
	keyGroup int
	skipKey  *regexp.Regexp
}

// trivialValue is a setting after a secret-shaped key in host output
// (docs/spec/host-collector.md §4): `PermitEmptyPasswords no` stays.
var trivialValue = regexp.MustCompile(`(?i)^["']?(yes|no|true|false|none|null|off|on|0|1|-|\*|x|required|optional|prompt|ask)["']?$`)

// jsonTrivialValue is what a quoted JSON value under a secret-shaped key
// keeps: "", "0" and "1". JSON spells a setting as true, false, null or a
// number, so any other string there is redacted whole, "yes" and "none"
// included: an API answer is not a config file, and a word a person chose
// can be a password (docs/spec/scope.md, "Responses").
var jsonTrivialValue = regexp.MustCompile(`^(0|1)?$`)

// sudoersTag is the sudoers `PASSWD:`/`NOPASSWD:` tag: what follows it is
// the granted command, never a credential.
var sudoersTag = regexp.MustCompile(`(?i)^(no)?passwd$`)

// Token shapes shared by the redactor and the credential detector
// (credential.go), so a value the detector refuses is one the redactor would
// have hidden. The detector's bearer shape is a narrower form of bearerToken.
var (
	awsAccessKey = regexp.MustCompile(`\b(AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b`)
	githubToken  = regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b`)
	slackToken   = regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`)
	bearerToken  = regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9\-._~+/]{8,}=*)`)
	jwtToken     = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)
	// Google's OAuth access and refresh tokens, API keys and OAuth client
	// secrets; Stripe's live secret and restricted keys; npm's tokens; and
	// the path of a Slack incoming webhook, which is its credential
	// (docs/spec/scope.md, "Responses").
	googleAccessToken  = regexp.MustCompile(`\bya29\.[0-9A-Za-z_-]{20,}`)
	googleRefreshToken = regexp.MustCompile(`\b1//[0-9A-Za-z_-]{20,}`)
	googleAPIKey       = regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`)
	googleClientSecret = regexp.MustCompile(`\bGOCSPX-[0-9A-Za-z_-]{20,}`)
	stripeKey          = regexp.MustCompile(`\b[rs]k_live_[0-9A-Za-z]{20,}`)
	npmToken           = regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)
	slackWebhook       = regexp.MustCompile(`https://hooks\.slack\.com/(?:services|workflows|triggers)/([A-Za-z0-9_/-]{16,})`)
)

// secretKey is a key name that holds a secret, for the key/value rules.
//
//nolint:gosec // a pattern of key names, not a credential
const secretKey = `[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key)[A-Za-z0-9_.-]*`

// jsonPlainKey is a secret-looking JSON key whose value names a URL, a
// kind, a switch or a time, or is a page cursor (Google's nextPageToken),
// never a secret. The scope gate reads the cursor from the redacted body.
// RedactJSON uses it too.
var jsonPlainKey = regexp.MustCompile(`(?i)(_url|_uri|_type|_enabled|_at|page_?token)$`)

// compiledRules are applied in order. Private-key blocks go first so a key
// is never partially redacted by a narrower rule.
var compiledRules = []redactRule{
	{name: "private-key", re: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----`)},
	// A block cut off by truncation is still a key: redact to the end.
	{name: "private-key", re: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----[\s\S]*$`)},
	{name: "aws-access-key", re: awsAccessKey},
	{name: "github-token", re: githubToken},
	{name: "slack-token", re: slackToken},
	{name: "google-access-token", re: googleAccessToken},
	{name: "google-refresh-token", re: googleRefreshToken},
	{name: "google-api-key", re: googleAPIKey},
	{name: "google-client-secret", re: googleClientSecret},
	{name: "stripe-key", re: stripeKey},
	{name: "npm-token", re: npmToken},
	{name: "slack-webhook", re: slackWebhook, group: 1},
	{name: "bearer", re: bearerToken, group: 1},
	{name: "jwt", re: jwtToken},
	// A JSON member in text, which kv-secret misses: the key's closing
	// quote sits between it and the colon. A JSON body the scope gate reads
	// goes through RedactJSON instead, which applies it per member.
	{name: "json-secret", group: 2, keepIf: jsonTrivialValue, keyGroup: 1, skipKey: jsonPlainKey,
		re: regexp.MustCompile(`(?i)"(` + secretKey + `)"\s*:\s*"((?:[^"\\\n]|\\.)*)"`)},
	{name: "kv-secret", group: 2, keepIf: trivialValue, keyGroup: 1, skipKey: sudoersTag,
		re: regexp.MustCompile(`(?i)\b(` + secretKey + `)\s*[=:]\s*("[^"\n]*"|'[^'\n]*'|[^\s,;]+)`)},
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

// WithLiteral returns a copy of r that also redacts every occurrence of
// value under the rule name, ahead of every other rule. The scope gate adds
// the credential a provider was called with, so a token the provider echoes
// back is hidden even when no token shape matches it (docs/spec/scope.md,
// "Methods and credentials"). An empty value adds nothing.
func (r *Redactor) WithLiteral(name, value string) *Redactor {
	if value == "" {
		return r
	}
	rule := redactRule{name: name, re: regexp.MustCompile(regexp.QuoteMeta(value))}
	return &Redactor{rules: append([]redactRule{rule}, r.rules...)}
}

// WithWorkflowReferences preserves only whole built-in GitHub token references
// under secret-shaped keys. They name runtime credentials, not literal values.
// Other detectors, credential literals and extra rules remain active.
// docs/spec/github-collector.md, "Supported workflow syntax".
func (r *Redactor) WithWorkflowReferences() *Redactor {
	reference := `\$\{\{[ \t]{0,32}(?:github\.token|secrets\.GITHUB_TOKEN)[ \t]{0,32}\}\}`
	keep := regexp.MustCompile(`^(?:(?i:["']?(yes|no|true|false|none|null|off|on|0|1|-|\*|x|required|optional|prompt|ask)["']?)|` + reference + `[ \t]{0,32}|"` + reference + `"[ \t]{0,32}|'` + reference + `'[ \t]{0,32})$`)
	rules := append([]redactRule(nil), r.rules...)
	for i := range rules {
		if rules[i].name == "kv-secret" && rules[i].group == 2 {
			rules[i].re = regexp.MustCompile(`(?i)\b(` + secretKey + `)\s*[=:]\s*("\$\{\{[^\r\n]*|'\$\{\{[^\r\n]*|\$\{\{[^\r\n]*|"[^"\n]*"|'[^'\n]*'|[^\s,;]+)`)
			rules[i].keepIf = keep
		}
	}
	return &Redactor{rules: rules}
}

// Marker is the text that replaces a redacted span. It is never empty, so a
// reader can always tell that something was there (docs/spec/host-collector.md §4.2).
func Marker(rule string, n int) string {
	return fmt.Sprintf("[REDACTED:%s:%d bytes]", rule, n)
}

// Redact returns a copy of b with every matched span replaced by a Marker.
// All rules are matched against the original bytes in one pass, so a marker
// inserted for one rule can never be re-matched by another; where spans
// overlap the earliest-listed rule wins.
func (r *Redactor) Redact(b []byte) ([]byte, []Hit) {
	return r.redactUpTo(b, len(b))
}

// redactUpTo matches every rule against all of b but writes out only what
// derives from b[:upTo]: plain bytes before upTo, and the markers of spans
// that start before it. A secret that starts before upTo and ends after it
// is still hidden by its marker.
func (r *Redactor) redactUpTo(b []byte, upTo int) ([]byte, []Hit) {
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
			if rule.skipKey != nil && loc[2*rule.keyGroup] >= 0 && rule.skipKey.Match(b[loc[2*rule.keyGroup]:loc[2*rule.keyGroup+1]]) {
				continue
			}
			spans = append(spans, span{start, end, order, rule.name})
		}
	}
	if len(spans) == 0 {
		return b[:upTo], nil
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
		if sp.start >= upTo {
			break
		}
		out = append(out, b[last:sp.start]...)
		out = append(out, Marker(sp.rule, sp.end-sp.start)...)
		hits = append(hits, Hit{sp.rule, sp.end - sp.start})
		last = sp.end
	}
	if last < upTo {
		out = append(out, b[last:upTo]...)
	}
	return out, hits
}

// RedactString is Redact for strings.
func (r *Redactor) RedactString(s string) (string, []Hit) {
	b, hits := r.Redact([]byte(s))
	return string(b), hits
}

// Finish redacts b and then cuts it to capBytes with a marker, never inside
// a redaction marker: the marker is what tells a reader something was
// there, so it stays whole even past the cap. sourceTruncated says the
// source stopped reading before the end, so the marker counts what was cut
// as a lower bound (docs/spec/host-collector.md §4.2; AGENTS.md rule 5). The
// caller reads RedactSlack bytes past the cap, so a secret straddling the
// cap is whole when it is redacted. When the source was cut, the last
// RedactSlack bytes may hold the start of a secret whose end was never
// read, which no rule can match: nothing derived from them is kept, even
// when redaction elsewhere shrank the output under the cap.
func (r *Redactor) Finish(b []byte, sourceTruncated bool, capBytes int) ([]byte, bool, []Hit) {
	upTo := len(b)
	if sourceTruncated {
		upTo = max(len(b)-RedactSlack, 0)
	}
	red, hits := r.redactUpTo(b, upTo)
	red, truncated := Truncate(red, sourceTruncated, capBytes)
	return red, truncated, hits
}

// Truncate cuts text that is already redacted to capBytes, never through
// a marker, and marks the cut (rule 5: redact before truncate). Finish is
// Redact then Truncate; a caller that redacted another way, as RedactJSON
// does, cuts with this alone, so its markers never meet the text rules.
func Truncate(red []byte, sourceTruncated bool, capBytes int) ([]byte, bool) {
	truncated := sourceTruncated
	if len(red) > capBytes {
		cut := capBytes
		// The last marker that starts before the cut, even one the cut
		// splits inside "[REDACTED:" itself.
		open := []byte("[REDACTED:")
		if i := bytes.LastIndex(red[:min(len(red), cut+len(open)-1)], open); i >= 0 && i < cut && bytes.IndexByte(red[i:cut], ']') < 0 {
			if j := bytes.IndexByte(red[i:], ']'); j >= 0 {
				cut = i + j + 1
			}
		}
		dropped := len(red) - cut
		red = append([]byte(nil), red[:cut]...)
		marker := fmt.Sprintf("\n[TRUNCATED:%d bytes]", dropped)
		if sourceTruncated {
			marker = fmt.Sprintf("\n[TRUNCATED:%d+ bytes]", dropped)
		}
		red = append(red, marker...)
		truncated = true
	} else if sourceTruncated {
		red = append(append([]byte(nil), red...), "\n[TRUNCATED:unknown bytes]"...)
	}
	return red, truncated
}
