package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/version"
)

// twoRuns runs the same engagement twice, a second apart, and returns the
// two run directories, earlier first.
func twoRuns(t *testing.T) (string, string) {
	t.Helper()
	state := hermetic(t)
	old := version.Version
	version.Version = "0.0.3"
	t.Cleanup(func() { version.Version = old })
	collectFrom(t, recorded(t, "ubuntu"))
	path := filepath.Join(t.TempDir(), "engagement.yaml")
	writeFile(t, path, validEngagement)
	for range 2 {
		if _, msg, code := runEngagement(t, path, "--state-dir", state); code == exitUsage {
			t.Fatalf("run: %s", msg)
		}
		time.Sleep(1100 * time.Millisecond)
	}
	dirs, err := filepath.Glob(filepath.Join(state, "engagements", "acme", "*"))
	if err != nil || len(dirs) != 2 {
		t.Fatalf("run directories: %v %v", dirs, err)
	}
	return dirs[0], dirs[1]
}

func runDiff(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	root := newRootCmd()
	var out strings.Builder
	root.SetOut(&out)
	root.SetErr(&strings.Builder{})
	root.SetArgs(append([]string{"diff"}, args...))
	err := root.Execute()
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	return out.String(), msg, exitCodeOf(err)
}

func TestDiffOfTwoRunsOfOneEngagement(t *testing.T) {
	a, b := twoRuns(t)
	out, msg, code := runDiff(t, a, b)
	if code != exitOK && code != exitFindings {
		t.Fatalf("exit %d: %s\n%s", code, msg, out)
	}
	for _, want := range []string{"Comparison of two runs of acme", "Nothing was contacted and nothing was checked again", "The same scheck release, the same engagement file and the same access"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// Two runs with nothing changed: nothing is new, nothing is fixed.
	if strings.Contains(out, "\nFixed\n") || strings.Contains(out, "\nNew since the earlier run\n") {
		t.Errorf("an unchanged pair reported a change:\n%s", out)
	}
	if code != exitOK {
		t.Errorf("exit %d on an unchanged pair", code)
	}
	js, _, code := runDiff(t, a, b, "--format", "json")
	if code != exitOK {
		t.Fatalf("json exit %d", code)
	}
	var v struct {
		SchemaVersion string `json:"schema_version"`
		Earlier       struct {
			RunRecordChecked bool `json:"run_record_checked"`
		} `json:"earlier"`
	}
	if err := json.Unmarshal([]byte(js), &v); err != nil || v.SchemaVersion != "1.0" || !v.Earlier.RunRecordChecked {
		t.Errorf("json: %v %+v", err, v)
	}
}

func TestDiffRefusesWhatCannotBeCompared(t *testing.T) {
	a, b := twoRuns(t)
	if _, msg, code := runDiff(t, b, a); code != exitUsage || !strings.Contains(msg, "earlier run first") {
		t.Errorf("swapped: %d %s", code, msg)
	}
	if _, msg, code := runDiff(t, a, a); code != exitUsage || !strings.Contains(msg, "same run") {
		t.Errorf("same run: %d %s", code, msg)
	}
	if _, _, code := runDiff(t, a); code != exitUsage {
		t.Errorf("one argument: %d", code)
	}
	if _, _, code := runDiff(t, a, filepath.Join(t.TempDir(), "missing")); code != exitUsage {
		t.Errorf("missing run: %d", code)
	}
	// A report edited after scheck wrote it is not a basis for "fixed".
	p := filepath.Join(b, "report.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(string(raw), `"findings": [`, `"findings": [ `, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, msg, code := runDiff(t, a, b); code != exitUsage || !strings.Contains(msg, "changed since scheck wrote it") {
		t.Errorf("edited report: %d %s", code, msg)
	}
}

func TestDiffRejectsFlagsItDoesNotHave(t *testing.T) {
	a, b := twoRuns(t)
	if _, _, code := runDiff(t, a, b, "--include-evidence"); code != exitUsage {
		t.Errorf("--include-evidence: %d", code)
	}
	if _, _, code := runDiff(t, a, b, "--only", "x"); code != exitUsage {
		t.Errorf("--only: %d", code)
	}
}
