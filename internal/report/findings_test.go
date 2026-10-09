package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/runner"
)

// postureSheet is a fact sheet with the raw output of a few checks, run
// through the catalog's own parsers.
func postureSheet(t *testing.T, platform check.Platform, raw map[string]string) *baseline.FactSheet {
	t.Helper()
	fs := &baseline.FactSheet{Platform: platform, Results: map[string]runner.Result{}}
	for id, out := range raw {
		c, ok := check.Lookup(id, platform)
		if !ok {
			t.Fatalf("unknown check %s", id)
		}
		parsed, err := check.Parse(c, []byte(out))
		if err != nil {
			t.Fatal(err)
		}
		fs.Results[id] = runner.Result{CheckID: id, Status: runner.StatusOK, Attempted: true, Raw: out, Parsed: parsed}
	}
	return fs
}

func postureEnv(t *testing.T, platform check.Platform, raw map[string]string) Envelope {
	t.Helper()
	return Build(postureSheet(t, platform, raw), meta())
}

// The JSON carries each rule finding with its evidence and every selected
// rule's assessment.
func TestJSONCarriesRuleFindings(t *testing.T) {
	env := postureEnv(t, check.Linux, map[string]string{
		"sshd.config":            "passwordauthentication yes\npermitrootlogin no",
		"accounts.passwd_status": "root L 2026-09-11\nalice NP 2026-09-11",
		"accounts.passwd":        "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash",
	})
	var buf bytes.Buffer
	if err := WriteJSON(&buf, env); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []struct {
			ID           string `json:"id"`
			Severity     string `json:"severity"`
			SeverityBase string `json:"severity_base"`
			Source       string `json:"source"`
			Confidence   string `json:"confidence"`
			Status       string `json:"status"`
			Evidence     []struct {
				Check   string `json:"check"`
				Excerpt string `json:"excerpt"`
			} `json:"evidence"`
		} `json:"findings"`
		Assessments []finding.Assessment `json:"assessments"`
		Run         struct {
			Assessment string `json:"assessment"`
		} `json:"run"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) != 2 || doc.Run.Assessment != "rules" {
		t.Fatalf("json findings %+v, assessment %q", doc.Findings, doc.Run.Assessment)
	}
	for _, f := range doc.Findings {
		if f.Source != "rule" || f.Confidence != "high" || f.Status != "open" || f.Severity != f.SeverityBase || len(f.Evidence) == 0 {
			t.Errorf("phase 1 finding shape: %+v", f)
		}
	}
	// Every selected rule has a coverage entry, findings or not.
	if len(doc.Assessments) < len(doc.Findings) {
		t.Errorf("fewer assessments (%d) than findings (%d)", len(doc.Assessments), len(doc.Findings))
	}
}

// The exit-code question the CLI asks the envelope: which findings are open
// at or above the profile's threshold (docs/spec/host-collector.md §7).
func TestOpenFindingsPerProfile(t *testing.T) {
	// Remote Login on a Mac is an info finding: visible, never fatal.
	env := postureEnv(t, check.MacOS, map[string]string{"remote.login": "Remote Login: On"})
	if n := env.OpenFindings(check.ProfileBaseline); n != 0 {
		t.Errorf("info finding counted at baseline: %d", n)
	}
	if n := env.OpenFindings(check.ProfileHardened); n != 0 {
		t.Errorf("info finding counted at hardened: %d", n)
	}
	// A low finding fails only the hardened profile.
	low := postureEnv(t, check.MacOS, map[string]string{"time.ntp": "Network Time: Off"})
	if n := low.OpenFindings(check.ProfileBaseline); n != 0 {
		t.Errorf("low finding counted at baseline: %d", n)
	}
	if n := low.OpenFindings(check.ProfileHardened); n != 1 {
		t.Errorf("low finding not counted at hardened: %d", n)
	}
	high := postureEnv(t, check.MacOS, map[string]string{"disk.fdesetup": "FileVault is Off."})
	if n := high.OpenFindings(check.ProfileBaseline); n != 1 {
		t.Errorf("high finding not counted at baseline: %d", n)
	}
}
