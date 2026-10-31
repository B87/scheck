package web

import (
	"strings"
	"testing"

	"github.com/b87/scheck/internal/finding"
)

// A text-file probe is judged by the order in the spec: a match fires, an
// HTML page is not the file, a redaction leaves it open, a listed text type
// rules it out, and any other type or none is unknown, never a pass.
func TestTextFileProbeVerdictsByType(t *testing.T) {
	for _, tc := range []struct {
		name, contentType string
		matched           bool
		redacted          []string
		verdict, reason   string
		excerpt           string
	}{
		{"matched with no type", "", true, nil, Fired, "", ""},
		{"matched as binary/octet-stream", "binary/octet-stream", true, nil, Fired, "", ""},
		{"matched as application/x-trash", "application/x-trash", true, nil, Fired, "", ""},
		{"a page", "text/html", false, nil, Disproved, "", "answered with a page, not the file"},
		{"a page with a redaction hit", "text/html", false, []string{"kv-secret:9"}, Disproved, "", "answered with a page, not the file"},
		{"an xhtml page", "application/xhtml+xml", false, nil, Disproved, "", "answered with a page, not the file"},
		{"plain text, no match", "text/plain", false, nil, Disproved, "", "not served at this path"},
		{"plain text, no match, redacted", "text/plain", false, []string{"kv-secret:9"}, Abstained, "unavailable:redacted", ""},
		{"no type, no match", "", false, nil, Abstained, "unavailable:content_type", ""},
		{"x-trash, no match", "application/x-trash", false, nil, Abstained, "unavailable:content_type", ""},
		{"binary/octet-stream, no match", "binary/octet-stream", false, nil, Abstained, "unavailable:content_type", ""},
	} {
		js := Judge(Input{Asset: "domain:example.com", Probes: &ProbeEvidence{Sites: []ProbeSite{{Name: "shop.example.com", Evidence: "url root", Reads: []ProbeRead{
			{Probe: "git_head", URL: "https://shop.example.com/.git/HEAD", Finding: finding.IDWebVCSMetadataExposed, RequestID: "r1", Decision: "sent",
				Status: 200, Matched: tc.matched, Redacted: tc.redacted, ContentType: tc.contentType}}}}}})
		if len(js) != 1 || js[0].Verdict != tc.verdict || js[0].Reason != tc.reason || !strings.Contains(js[0].Excerpt, tc.excerpt) {
			t.Errorf("%s: %+v", tc.name, js)
		}
	}
}
