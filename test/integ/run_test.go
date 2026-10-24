//go:build integration

package integ

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/b87/scheck/test/containers"
)

// `scheck run --host` reaches a real host through the same collector as
// `scheck ssh`: a schema-valid engagement report on stdout and in the run
// directory, a schema-valid host envelope under evidence/, an audit log of
// catalog argv only that the report's trace repeats, and a target the run
// left as the exact allowlist of docs/spec/host-collector.md §1 says
// (docs/ROADMAP.md, E1b, E2).
func TestRunHostOnContainers(t *testing.T) {
	bin := containers.BuildScheck(t)
	schema := loadSchema(t)
	engagementSchema := loadSchemaFile(t, "engagement-report-schema.json")
	for _, name := range []string{"ubuntu", "fedora"} {
		t.Run(name, func(t *testing.T) {
			c := containers.Start(t, name)
			before := c.Diff(t)
			stateDir := t.TempDir()
			out, errOut, code := containers.Run(t, bin, "run", "--host", "ops@"+c.Addr(), "--identity", c.Identity,
				"--known-hosts", c.KnownHosts, "--format", "json", "--state-dir", stateDir)
			if code != 0 && code != 1 {
				t.Fatalf("exit %d\n%s", code, errOut)
			}
			dirs, _ := filepath.Glob(filepath.Join(stateDir, "engagements", "*", "*"))
			if len(dirs) != 1 {
				t.Fatalf("run directories: %q", dirs)
			}
			dir := dirs[0]
			var doc any
			if err := json.Unmarshal([]byte(out), &doc); err != nil {
				t.Fatal(err)
			}
			if err := engagementSchema.Validate(doc); err != nil {
				cov, _ := json.MarshalIndent(doc.(map[string]any)["coverage"], "", " ")
				t.Fatalf("the report violates docs/engagement-report-schema.json: %v\ncoverage: %s", err, cov)
			}
			if written, _ := os.ReadFile(filepath.Join(dir, "report.json")); string(written) != out {
				t.Error("stdout is not report.json")
			}
			var rep struct {
				Exit   struct{ Code int } `json:"exit"`
				Assets []struct {
					Status, Evidence string
					Trace            []struct{ Check string } `json:"trace"`
				} `json:"assets"`
			}
			if err := json.Unmarshal([]byte(out), &rep); err != nil {
				t.Fatal(err)
			}
			if len(rep.Assets) != 1 || rep.Assets[0].Status != "collected" || rep.Exit.Code != code {
				t.Fatalf("report: %+v, exit %d", rep, code)
			}
			if tr := rep.Assets[0].Trace; len(tr) == 0 || tr[0].Check != "sys.canary" {
				t.Errorf("the report's trace does not open with the canary: %+v", tr)
			}
			raw, err := os.ReadFile(filepath.Join(dir, rep.Assets[0].Evidence))
			if err != nil {
				t.Fatal(err)
			}
			var env map[string]any
			if err := json.Unmarshal(raw, &env); err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(env); err != nil {
				t.Fatalf("the host envelope violates docs/report-schema.json: %v", err)
			}
			if host := env["host"].(map[string]any); host["transport"] != "ssh" || host["canary"] != "ok" {
				t.Errorf("host block: %v", host)
			}
			audit, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSpace(string(audit)), "\n")
			if len(lines) != len(rep.Assets[0].Trace) {
				t.Errorf("audit.jsonl has %d lines, the report's trace %d", len(lines), len(rep.Assets[0].Trace))
			}
			if !strings.Contains(lines[0], `"check":"sys.canary"`) {
				t.Errorf("the canary is not the first command: %s", lines[0])
			}
			for _, line := range lines {
				if strings.Contains(line, `"decision":"denied`) || !strings.Contains(line, `"argv":[`) {
					t.Errorf("audit line: %s", line)
				}
			}
			assertReadOnly(t, c, before, name)
		})
	}
}

// A host that never answers is a transport failure: the run is incomplete
// (exit 2). A canary mismatch is a policy error (exit 3), as in 0.0.1.
func TestRunHostExitCodes(t *testing.T) {
	c := containers.Start(t, "shell-matrix")
	bin := containers.BuildScheck(t)
	reach := []string{"--identity", c.Identity, "--known-hosts", c.KnownHosts, "--no-persist"}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()
	_, errOut, code := containers.Run(t, bin, append([]string{"run", "--host", "u_bash@127.0.0.1:" + closed}, reach...)...)
	if code != 2 || !strings.Contains(errOut, "host unreachable") {
		t.Fatalf("closed port: code=%d stderr=%q", code, errOut)
	}
	_, errOut, code = containers.Run(t, bin, append([]string{"run", "--host", "u_fish@" + c.Addr()}, reach...)...)
	if code != 3 || !strings.Contains(errOut, "canary") {
		t.Fatalf("fish: code=%d stderr=%q", code, errOut)
	}
}

// `scheck ssh user@host` and `scheck run --host user@host` give the same
// report and the same command trace on a real host (docs/ROADMAP.md, E2
// "Done when"); only times differ.
func TestSSHAliasEqualsRunHost(t *testing.T) {
	bin := containers.BuildScheck(t)
	c := containers.Start(t, "ubuntu")
	common := []string{"--identity", c.Identity, "--known-hosts", c.KnownHosts, "--sudo", "--format", "json", "--no-persist"}
	aliasOut, errOut, aliasCode := containers.Run(t, bin, append([]string{"ssh", "ops@" + c.Addr()}, common...)...)
	if !strings.Contains(errOut, "deprecated") {
		t.Errorf("no deprecation line: %q", errOut)
	}
	runOut, _, runCode := containers.Run(t, bin, append([]string{"run", "--host", "ops@" + c.Addr()}, common...)...)
	if aliasCode != runCode {
		t.Fatalf("exit %d vs %d", aliasCode, runCode)
	}
	type step struct{ Check, Decision, OutputSHA256 string }
	trace := func(out string) []step {
		var rep struct {
			Assets []struct {
				Trace []struct {
					Check        string `json:"check"`
					Decision     string `json:"decision"`
					OutputSHA256 string `json:"output_sha256"`
				} `json:"trace"`
			} `json:"assets"`
			Findings []struct{ ID, Severity string } `json:"findings"`
		}
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatal(err)
		}
		var out2 []step
		for _, e := range rep.Assets[0].Trace {
			// Output hashes of time-dependent checks differ between runs.
			out2 = append(out2, step{e.Check, e.Decision, ""})
		}
		return out2
	}
	a, r := trace(aliasOut), trace(runOut)
	if len(a) == 0 || len(a) != len(r) {
		t.Fatalf("traces: %d vs %d entries", len(a), len(r))
	}
	for i := range a {
		if a[i] != r[i] {
			t.Errorf("trace %d: %+v vs %+v", i, a[i], r[i])
		}
	}
	if envelopeOf(t, aliasOut)["findings"] == nil || len(envelopeOf(t, aliasOut)["facts"].(map[string]any)) !=
		len(envelopeOf(t, runOut)["facts"].(map[string]any)) {
		t.Error("the two runs read different facts")
	}
}
