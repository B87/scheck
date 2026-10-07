package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement/hostasset"
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

// timeless drops what differs between two runs of the same collection: the
// times and durations, and nothing else.
func timeless(t *testing.T, raw string) any {
	t.Helper()
	var doc any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, raw)
	}
	var walk func(any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			for k := range x {
				switch k {
				case "at", "started", "from", "to", "collected_at", "duration_ms", "time", "finished":
					delete(x, k)
				default:
					x[k] = walk(x[k])
				}
			}
		case []any:
			for i := range x {
				x[i] = walk(x[i])
			}
		}
		return v
	}
	return walk(doc)
}

// `scheck ssh user@host` and `scheck local` are `scheck run --host`: the
// same report, the same command trace and the same exit code, after a
// deprecation line on stderr (docs/ROADMAP.md, E2 "Done when").
func TestAliasesGiveTheSameReportAndTrace(t *testing.T) {
	hermetic(t)
	collectFrom(t, recorded(t, "ubuntu"))
	started := time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)
	prev := runClock
	runClock = func() time.Time { return started }
	t.Cleanup(func() { runClock = prev })

	for _, pair := range [][2][]string{
		{{"ssh", "deploy@203.0.113.5", "--sudo"}, {"run", "--host", "deploy@203.0.113.5", "--sudo"}},
		{{"local"}, {"run", "--host", "local"}},
	} {
		common := []string{"--format", "json", "--no-persist"}
		aliasOut, aliasErr, _, aliasCode := runCLI(t, append(pair[0], common...)...)
		runOut, _, _, runCode := runCLI(t, append(pair[1], common...)...)
		if aliasCode != runCode {
			t.Errorf("%v exits %d, %v exits %d", pair[0], aliasCode, pair[1], runCode)
		}
		a, r := timeless(t, aliasOut), timeless(t, runOut)
		aj, _ := json.Marshal(a)
		rj, _ := json.Marshal(r)
		if !bytes.Equal(aj, rj) {
			t.Errorf("%v and %v differ:\n%s\n---\n%s", pair[0], pair[1], aj, rj)
		}
		if !strings.Contains(aliasErr, "scheck "+pair[0][0]+" is deprecated and is removed in 0.0.3") ||
			!strings.Contains(aliasErr, "assets[0].envelope.run.assessment") {
			t.Errorf("deprecation line: %q", aliasErr)
		}
	}
}

// Each 0.0.1 flag maps to its run equivalent, or exits 3 naming the
// replacement (docs/spec/engagement.md, "The aliases").
func TestAliasFlagsMapOrExitThree(t *testing.T) {
	hermetic(t)
	var got hostasset.Options
	calls := 0
	prev := collectHost
	collectHost = func(ctx context.Context, o hostasset.Options) (*hostasset.Collection, error) {
		calls++
		got = o
		o.Target = recorded(t, "ubuntu")()
		return hostasset.Collect(ctx, o)
	}
	t.Cleanup(func() { collectHost = prev })

	_, _, msg, code := runCLI(t, "ssh", "deploy@203.0.113.5", "--port", "2222", "--identity", "/k", "--known-hosts", "/kh",
		"--sudo", "--profile", "hardened", "--timeout", "90s", "--no-persist")
	if code == exitUsage || got.Port != 2222 || got.User != "deploy" || got.Host != "203.0.113.5" || got.Identity != "/k" ||
		got.KnownHosts != "/kh" || got.Elevate != "sudo" || got.Profile != "hardened" || got.RunTimeout != 90*time.Second {
		t.Fatalf("exit %d (%s); options %+v", code, msg, got)
	}
	if loc, _ := sshLocator("ops@[2001:db8::1]:2200", 0); loc != "ops@[2001:db8::1]:2200" {
		t.Errorf("IPv6 locator %q", loc)
	}
	if loc, _ := sshLocator("ops@host:22", 2222); loc != "ops@host:2222" {
		t.Errorf("--port wins over the argument's port, as in 0.0.1: %q", loc)
	}

	// --stop-after context is intake: validated and printed, nothing contacted.
	calls = 0
	out, _, msg, code := runCLI(t, "local", "--stop-after", "context")
	if code != exitOK || calls != 0 || !strings.Contains(out, "valid; 1 root, 1 asset, nothing contacted") {
		t.Fatalf("--stop-after context: exit %d (%s) after %d collections:\n%s", code, msg, calls, out)
	}
	// --stop-after facts is the run.
	if _, _, msg, code := runCLI(t, "local", "--stop-after", "facts", "--no-persist", "--format", "json", "--include-evidence"); code == exitUsage || calls != 1 {
		t.Fatalf("--stop-after facts: exit %d (%s) after %d collections", code, msg, calls)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"local", "--stop-after", "plan"}, "scheck catalog --platform"},
		{[]string{"local", "--context", "gateway.yaml"}, "assets.<name>.context"},
		{[]string{"local", "--ignore-context"}, "reads no context"},
		{[]string{"ssh", "deploy@203.0.113.5", "--audit-log", "/tmp/a.jsonl"}, "audit.jsonl"},
		{[]string{"local", "--model", "gpt-5"}, "no model assesses a host"},
		{[]string{"local", "--only", "network"}, "not available in this build"},
		{[]string{"local", "--format", "sarif"}, "sarif is not available"},
		{[]string{"ssh", "203.0.113.5"}, "has no SSH user"},
		{[]string{"ssh", "local"}, "is not a remote host"},
		{[]string{"ssh", "ops@local"}, "is not a remote host"},
	} {
		calls = 0
		_, _, msg, code := runCLI(t, tc.args...)
		if code != exitUsage || !strings.Contains(msg, tc.want) || calls != 0 {
			t.Errorf("%v: exit %d after %d collections: %s", tc.args, code, calls, msg)
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
		{"local", "--format", "json", "--no-persist", "--include-evidence"},
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

// The aliases refuse a 0.0.1 configuration file as run does: no code path
// reads a setting from one (docs/spec/engagement.md, "No configuration file").
func TestAliasesRefuseALegacyConfigFile(t *testing.T) {
	hermetic(t)
	calls := collectFrom(t, recorded(t, "ubuntu"))
	writeFile(t, "scheck.yaml", "profile: hardened\ndeny_paths: [/srv]\n")
	for _, args := range [][]string{{"local", "--no-persist"}, {"ssh", "deploy@203.0.113.5", "--no-persist"}} {
		_, _, msg, code := runCLI(t, args...)
		if code != exitUsage || !strings.Contains(msg, "deny_paths -> assets.<name>.deny_paths") || *calls != 0 {
			t.Errorf("%v: exit %d after %d collections: %s", args, code, *calls, msg)
		}
	}
	// So is 0.0.1's implicit context directory, whose accepted risks would
	// otherwise vanish without a word.
	if err := os.Remove("scheck.yaml"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, ".scheck/context/gateway.yaml", "accepted_risks:\n  - {id: updates.pending, reason: window}\n")
	if _, _, msg, code := runCLI(t, "local", "--no-persist"); code != exitUsage || !strings.Contains(msg, "intent.accepted_risks") || *calls != 0 {
		t.Errorf(".scheck/context: exit %d: %s", code, msg)
	}
}
