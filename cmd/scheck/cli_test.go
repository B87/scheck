package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// runCLI executes scheck with args and returns stdout, stderr, the error
// the process would print and its exit code.
func runCLI(t *testing.T, args ...string) (string, string, string, int) {
	t.Helper()
	root := newRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err := root.Execute()
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	return out.String(), errOut.String(), msg, exitCodeOf(err)
}

// `scheck local` and `scheck ssh` were deprecated aliases of `scheck run --host`
// in 0.0.2 and are removed in 0.0.3 (docs/spec/engagement.md, "One command,
// one file"): ordinary unknown commands, exit 3, nothing collected.
func TestRemovedAliasesAreUnknownCommands(t *testing.T) {
	hermetic(t)
	calls := collectFrom(t, recorded(t, "ubuntu"))
	for _, args := range [][]string{
		{"local"},
		{"local", "--no-persist"},
		{"ssh", "deploy@203.0.113.5", "--sudo"},
	} {
		_, _, msg, code := runCLI(t, args...)
		if code != exitUsage || !strings.Contains(msg, "unknown command") || *calls != 0 {
			t.Errorf("%v: exit %d after %d collections: %s", args, code, *calls, msg)
		}
	}
}

// --format json --no-persist --include-evidence still prints a host's facts
// with their captures, inside its envelope (docs/ROADMAP.md, E2 "Done when").
func TestIncludeEvidenceReachesTheEnvelope(t *testing.T) {
	hermetic(t)
	collectFrom(t, recorded(t, "ubuntu"))
	for _, args := range [][]string{
		{"run", "--host", "local", "--format", "json", "--no-persist", "--include-evidence"},
	} {
		out, _, msg, code := runCLI(t, args...)
		if code == exitUsage {
			t.Fatalf("%v: %s", args, msg)
		}
		var doc struct {
			Assets []struct {
				Envelope struct {
					Facts map[string]struct {
						Evidence *struct{ Stdout string } `json:"evidence"`
					} `json:"facts"`
				} `json:"envelope"`
			} `json:"assets"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatal(err)
		}
		if f := doc.Assets[0].Envelope.Facts["sys.uname"]; f.Evidence == nil || f.Evidence.Stdout == "" {
			t.Errorf("%v: no capture for sys.uname", args)
		}
	}
	// Without the flag nothing captured is printed.
	out, _, _, _ := runCLI(t, "run", "--host", "local", "--format", "json", "--no-persist")
	if strings.Contains(out, `"evidence": {`) {
		t.Error("captures printed without --include-evidence")
	}
}

// run refuses 0.0.1's implicit context directory as it refuses a configuration
// file, whose accepted risks would otherwise vanish without a word (the
// scheck.yaml case is in run_test.go; docs/spec/host-collector.md, "No
// configuration file").
func TestRunRefusesALegacyContextDirectory(t *testing.T) {
	hermetic(t)
	calls := collectFrom(t, recorded(t, "ubuntu"))
	writeFile(t, ".scheck/context/gateway.yaml", "accepted_risks:\n  - {id: updates.pending, reason: window}\n")
	if _, _, msg, code := runCLI(t, "run", "--host", "local", "--no-persist"); code != exitUsage || !strings.Contains(msg, "intent.accepted_risks") || *calls != 0 {
		t.Errorf(".scheck/context: exit %d: %s", code, msg)
	}
}
