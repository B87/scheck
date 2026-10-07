package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// runEngagement executes `scheck run` with args and returns stdout, the
// error the process would print, and its exit code.
func runEngagement(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(append([]string{"run"}, args...))
	err := root.Execute()
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	return out.String(), msg, exitCodeOf(err)
}

const validEngagement = `schema: 1
engagement:
  name: acme
  timezone: Europe/Madrid
  trigger: routine
roots:
  - host: deploy@203.0.113.5
redact_extra: ["project-tangerine"]
assets:
  deploy:
    host: 203.0.113.5
    elevate: sudo
    disable_checks: [fs.suid]
`

func TestRunStopAfterIntakePrintsTheResolvedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "engagement.yaml")
	writeFile(t, path, validEngagement)

	out, msg, code := runEngagement(t, path, "--stop-after", "intake")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, msg)
	}
	for _, want := range []string{"valid; 1 root, 1 asset, nothing contacted", "id: host:203.0.113.5:22", "user: deploy", "elevate: sudo", "profile: baseline", "redact_extra_patterns: 1"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "tangerine") {
		t.Errorf("a redact_extra pattern was printed:\n%s", out)
	}

	out, msg, code = runEngagement(t, path, "--stop-after", "intake", "--format", "json")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, msg)
	}
	var doc struct {
		Assets []struct {
			Name, ID, Elevate string
		} `json:"assets"`
		RedactPatterns int `json:"redact_extra_patterns"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if len(doc.Assets) != 1 || doc.Assets[0].ID != "host:203.0.113.5:22" || doc.Assets[0].Elevate != "sudo" || doc.RedactPatterns != 1 {
		t.Fatalf("json = %+v", doc)
	}
	if strings.Contains(out, "tangerine") {
		t.Errorf("a redact_extra pattern was printed:\n%s", out)
	}
}

func TestRunRefusesWhatThisBuildDoesNotRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "engagement.yaml")
	writeFile(t, path, validEngagement)
	cases := []struct {
		name string
		args []string
		msg  string
	}{
		{"no stop-after", []string{path}, "only --stop-after intake"},
		{"later stage", []string{path, "--stop-after", "recon"}, "not available in this build"},
		{"unknown stage", []string{path, "--stop-after", "facts"}, "must be one of intake|scope|recon|plan|check|analyze|report"},
		{"host flag", []string{path, "--stop-after", "intake", "--sudo"}, "--sudo is not available for scheck run"},
		{"context flag", []string{path, "--stop-after", "intake", "--context", "x.yaml"}, "--context is not available for scheck run"},
		{"model flag", []string{path, "--stop-after", "intake", "--provider", "mock"}, "--provider is not available for scheck run"},
		{"no file", []string{"--stop-after", "intake"}, "one engagement file"},
		{"missing file", []string{filepath.Join(dir, "nope.yaml"), "--stop-after", "intake"}, "no such file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, msg, code := runEngagement(t, tc.args...)
			if code != exitUsage || !strings.Contains(msg, tc.msg) || out != "" {
				t.Fatalf("exit %d, %q, stdout %q; want exit 3 and %q", code, msg, out, tc.msg)
			}
		})
	}
}

func TestRunInvalidFileNamesEveryErrorAndNeverTheCredential(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "engagement.yaml")
	writeFile(t, path, validEngagement+"    identity: AKIAIOSFODNN7EXAMPLE\ncolour: blue\n")
	out, msg, code := runEngagement(t, path, "--stop-after", "intake")
	if code != exitUsage || out != "" {
		t.Fatalf("exit %d, stdout %q", code, out)
	}
	for _, want := range []string{"(2 errors)", path + ":14:assets.deploy.identity: holds a value shaped like a credential (detector aws-access-key)", path + ":15:colour: unknown key"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("the credential was printed:\n%s", msg)
	}
}
