package main

import (
	"bufio"
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement"
)

// Only a "y" approves a site; the preview shows every request first, and a
// closed input approves nothing.
func TestAskProbesApprovesOnlyWhatIsAnswered(t *testing.T) {
	sites := []engagement.ProbePreviewSite{
		{Site: "a.example.com", Evidence: "url root", Requests: []engagement.ProbeRequest{{Probe: "env", Method: "GET", URL: "https://a.example.com/.env"}}},
		{Site: "b.example.com", Evidence: "url root", Requests: []engagement.ProbeRequest{{Probe: "env", Method: "GET", URL: "https://b.example.com/.env"}}},
		{Site: "c.example.com", Evidence: "url root", Requests: []engagement.ProbeRequest{{Probe: "env", Method: "GET", URL: "https://c.example.com/.env"}}},
	}
	var out bytes.Buffer
	got := askProbes(bufio.NewReader(strings.NewReader("y\nno\n")), &out, sites)
	if !slices.Equal(got, []string{"a.example.com"}) {
		t.Errorf("approved %v", got)
	}
	for _, want := range []string{"GET https://a.example.com/.env", "GET https://c.example.com/.env", "Send these 1 requests to b.example.com?"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the preview lacks %q:\n%s", want, out.String())
		}
	}
}
