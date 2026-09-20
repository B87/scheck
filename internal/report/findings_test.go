package report

import (
	"bytes"
	"encoding/json"
	"strings"
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

// Findings come before the fact sheet, with the evidence excerpt, the check
// it came from and the remediation summary (docs/SPEC.md §7.6).
func TestFindingsRenderFirstWithEvidenceAndRemedy(t *testing.T) {
	env := postureEnv(t, check.Linux, map[string]string{
		"sshd.config":       "passwordauthentication yes\npermitrootlogin yes",
		"fs.world_writable": "/opt/shared",
	})
	out := render(t, env, Options{Width: 110})
	for _, want := range []string{
		"3 findings (1 high, 2 medium)",
		"Findings (3)",
		"sshd permits direct root login [sshd.root_login_enabled]",
		"evidence  sshd.config: permitrootlogin yes",
		"fix       Set PermitRootLogin no",
		"high",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q from:\n%s", want, out)
		}
	}
	if strings.Index(out, "Findings (3)") > strings.Index(out, "DOMAIN") {
		t.Error("findings must come before the fact table")
	}
	// The highest severity is read first.
	if strings.Index(out, "sshd.root_login_enabled") > strings.Index(out, "sshd.password_auth_enabled") {
		t.Error("findings are ordered by severity")
	}
	// A check whose rule fired shows the severity, never a pass mark.
	if !strings.Contains(out, "[finding: high, finding: medium]") {
		t.Errorf("the fact row does not carry its findings:\n%s", out)
	}
}

// -v adds the impact, the commands and the caveat; the default report stays
// short.
func TestFindingVerbosity(t *testing.T) {
	env := postureEnv(t, check.Linux, map[string]string{"sshd.config": "passwordauthentication yes"})
	def := render(t, env, Options{Width: 110})
	v := render(t, env, Options{Width: 110, Verbose: 1})
	const caveat = "Confirm at least one working key-based login"
	if strings.Contains(def, caveat) {
		t.Error("the default report printed the caveat")
	}
	for _, want := range []string{caveat, "impact", "sudo sshd -t", "Rule coverage"} {
		if !strings.Contains(v, want) {
			t.Errorf("-v missing %q", want)
		}
	}
}

// Coverage is reported separately from findings: a rule that could not be
// evaluated is named, with the remedy of the check that let it down, and it
// is never counted as a finding (docs/SPEC.md §7.5).
func TestNotAssessedRulesAreNamedWithARemedy(t *testing.T) {
	sheet := postureSheet(t, check.MacOS, map[string]string{"disk.fdesetup": "FileVault is On."})
	sheet.Results["sshd.config"] = runner.Result{CheckID: "sshd.config", Status: runner.StatusUnavailable,
		Reason: "requires elevated read", ReasonCode: "requires_elevation"}
	env := Build(sheet, meta())
	out := render(t, env, Options{Width: 110})
	for _, want := range []string{
		"Not assessed",
		"sshd.config did not run: requires elevated read",
		"sshd.password_auth_enabled, sshd.root_login_enabled",
		"remedy: re-run with --sudo",
		"they are not passes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q from:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Findings (") {
		t.Error("a not-assessed rule was counted as a finding")
	}
}

// The footer says what was assessed and refuses to imply the rest is fine.
func TestFooterStatesAssessmentScope(t *testing.T) {
	env := postureEnv(t, check.MacOS, map[string]string{"disk.fdesetup": "FileVault is On."})
	out := render(t, env, Options{Width: 110})
	tail := out[strings.LastIndex(out, "assessment:"):]
	for _, want := range []string{"posture rules only", "rules had the evidence to decide",
		"not whether the host is configured safely", "not available in this build"} {
		if !strings.Contains(tail, want) {
			t.Errorf("footer %q lacks %q", tail, want)
		}
	}
}

// Text and JSON agree on the finding count, the severities and the
// assessment outcomes: they are rendered from the same envelope.
func TestJSONAndTextAgreeOnAssessment(t *testing.T) {
	env := postureEnv(t, check.Linux, map[string]string{
		"sshd.config":            "passwordauthentication yes\npermitrootlogin no",
		"accounts.passwd_status": "root L 2026-09-11\nalice NP 2026-09-11",
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
	text := render(t, env, Options{Width: 120})
	if !strings.Contains(text, "2 findings (1 critical, 1 medium)") {
		t.Errorf("text header disagrees with the JSON:\n%s", text)
	}
	for _, f := range doc.Findings {
		if f.Source != "rule" || f.Confidence != "high" || f.Status != "open" || f.Severity != f.SeverityBase {
			t.Errorf("phase 1 finding shape: %+v", f)
		}
		if !strings.Contains(text, f.ID) || !strings.Contains(text, f.Evidence[0].Excerpt) {
			t.Errorf("%s is in the JSON but not in the text report", f.ID)
		}
	}
	// Every selected rule has a coverage entry, findings or not.
	if len(doc.Assessments) < len(doc.Findings) {
		t.Errorf("fewer assessments (%d) than findings (%d)", len(doc.Assessments), len(doc.Findings))
	}
}

// The exit-code question the CLI asks the envelope: which findings are open
// at or above the profile's threshold (docs/SPEC.md §8).
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

// Findings carry target-derived excerpts, which are escaped like every other
// target string before they reach a terminal (docs/SPEC.md §7.6).
func TestFindingEvidenceIsEscaped(t *testing.T) {
	env := postureEnv(t, check.Linux, map[string]string{
		"sshd.config": "passwordauthentication yes\x1b[2J",
	})
	if len(env.Findings) == 0 {
		t.Skip("no finding to render")
	}
	out := render(t, env, Options{Width: 110})
	if strings.Contains(out, "\x1b[2J") {
		t.Error("an escape sequence from the target reached the report through a finding")
	}
}
