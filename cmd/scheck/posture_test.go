package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/config"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/runner"
	"github.com/b87/scheck/internal/target/fixture"
)

// postureSession builds the CLI's own reporting path over a hand-made fact
// sheet: no target is contacted, but the envelope, the renderer and the exit
// decision are the real ones.
func postureSession(t *testing.T, profile check.Profile, format string) (*session, *bytes.Buffer) {
	t.Helper()
	return &session{
		opts:    &globalOpts{Format: format, NoPersist: true},
		cfg:     &config.Config{},
		profile: profile,
		started: time.Now(),
		runner:  &runner.Runner{Target: fixture.New(check.Linux)},
		elevate: runner.ElevateNone,
	}, &bytes.Buffer{}
}

func postureSheet(t *testing.T, raw map[string]string) *baseline.FactSheet {
	t.Helper()
	return platformSheet(t, check.Linux, raw)
}

func platformSheet(t *testing.T, platform check.Platform, raw map[string]string) *baseline.FactSheet {
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

// Acceptance criterion 4 (docs/SPEC.md §12): offline, with no API key and no
// model, a host with FileVault off or PasswordAuthentication yes yields that
// finding, with its evidence and remediation, and exits 1.
func TestAcceptanceCriterion4(t *testing.T) {
	cases := []struct {
		name     string
		platform check.Platform
		raw      map[string]string
		finding  string
		excerpt  string
	}{
		{"macos filevault off", check.MacOS, map[string]string{"disk.fdesetup": "FileVault is Off."},
			"disk.filevault_off", "FileVault is Off."},
		{"linux password auth", check.Linux, map[string]string{"sshd.config": "passwordauthentication yes"},
			"sshd.password_auth_enabled", "passwordauthentication yes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess, out := postureSession(t, check.ProfileBaseline, "text")
			sess.opts.Verbose = 0
			err := reportAndExit(sess, out, platformSheet(t, tc.platform, tc.raw))
			if got := exitCodeOf(err); got != exitFindings {
				t.Fatalf("exit %d (%v), want 1", got, err)
			}
			text := out.String()
			for _, want := range []string{tc.finding, tc.excerpt, "fix       "} {
				if !strings.Contains(text, want) {
					t.Errorf("missing %q from the offline report:\n%s", want, text)
				}
			}
		})
	}
}

func exitCodeOf(err error) int {
	if err == nil {
		return exitOK
	}
	if ee, ok := errors.AsType[*exitError](err); ok {
		return ee.Code
	}
	return exitUsage
}

// A completed run with an open finding at or above the profile threshold
// exits 1; the same host under a profile whose threshold is higher exits 0.
// The report is written either way (docs/SPEC.md §8).
func TestExitCodeFollowsProfileThreshold(t *testing.T) {
	cases := []struct {
		name    string
		raw     map[string]string
		profile check.Profile
		want    int
	}{
		{"password auth at baseline", map[string]string{"sshd.config": "passwordauthentication yes"}, check.ProfileBaseline, exitFindings},
		{"clean host at baseline", map[string]string{"sshd.config": "passwordauthentication no"}, check.ProfileBaseline, exitOK},
		{"low finding at baseline", map[string]string{"time.timedatectl": "NTPSynchronized=no"}, check.ProfileBaseline, exitOK},
		{"low finding at hardened", map[string]string{"time.timedatectl": "NTPSynchronized=no"}, check.ProfileHardened, exitFindings},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess, out := postureSession(t, tc.profile, "text")
			err := reportAndExit(sess, out, postureSheet(t, tc.raw))
			if got := exitCodeOf(err); got != tc.want {
				t.Fatalf("exit %d (%v), want %d", got, err, tc.want)
			}
			if out.Len() == 0 {
				t.Fatal("no report was written")
			}
		})
	}
}

// Exit 2 takes precedence over exit 1: an incomplete run's silence is not a
// verdict, whatever the rules that did run concluded (docs/SPEC.md §8).
func TestIncompleteRunOutranksFindings(t *testing.T) {
	sess, out := postureSession(t, check.ProfileBaseline, "text")
	sheet := postureSheet(t, map[string]string{"sshd.config": "passwordauthentication yes"})
	sheet.Incomplete = true
	err := reportAndExit(sess, out, sheet)
	if got := exitCodeOf(err); got != exitIncomplete {
		t.Fatalf("exit %d (%v), want %d", got, err, exitIncomplete)
	}
	if !strings.Contains(out.String(), "Findings") {
		t.Error("an incomplete run still reports what it did find")
	}
}

// The findings the exit code is computed from are the ones in the JSON.
func TestJSONCarriesRuleFindings(t *testing.T) {
	sess, out := postureSession(t, check.ProfileBaseline, "json")
	err := reportAndExit(sess, out, postureSheet(t, map[string]string{
		"sshd.config": "passwordauthentication yes\npermitrootlogin yes"}))
	if got := exitCodeOf(err); got != exitFindings {
		t.Fatalf("exit %d (%v)", got, err)
	}
	var doc struct {
		SchemaVersion string               `json:"schema_version"`
		Findings      []finding.Finding    `json:"findings"`
		Assessments   []finding.Assessment `json:"assessments"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != "1.5" || len(doc.Findings) != 2 || len(doc.Assessments) == 0 {
		t.Fatalf("envelope: version %s, %d findings, %d assessments", doc.SchemaVersion, len(doc.Findings), len(doc.Assessments))
	}
	if n := finding.OpenAtOrAbove(doc.Findings, finding.Threshold(check.ProfileBaseline)); n != 2 {
		t.Fatalf("exit code and JSON disagree: %d open findings", n)
	}
}
