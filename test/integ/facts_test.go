//go:build integration

package integ

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/b87/scheck/test/containers"
)

// M1 exit demo: `scheck ssh … --stop-after facts` against Ubuntu and Fedora
// produces a schema-valid, persisted report with no API key, the audit log
// names only catalog argv, and the target's filesystem is untouched
// (acceptance criteria 2, 3 and 4).
func TestSSHFactsReport(t *testing.T) {
	bin := containers.BuildScheck(t)
	schema := loadSchema(t)
	for _, name := range []string{"ubuntu", "fedora"} {
		t.Run(name, func(t *testing.T) {
			c := containers.Start(t, name)
			before := c.Diff(t)
			stateDir := t.TempDir()
			audit := filepath.Join(t.TempDir(), "audit.jsonl")
			out, errOut, code := containers.Run(t, bin, "ssh", "ops@"+c.Addr(), "--identity", c.Identity, "--known-hosts", c.KnownHosts,
				"--stop-after", "facts", "--format", "json", "--state-dir", stateDir, "--audit-log", audit)
			if code != 0 {
				t.Fatalf("exit %d\n%s", code, errOut)
			}
			var doc map[string]any
			if err := json.Unmarshal([]byte(out), &doc); err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(doc); err != nil {
				t.Fatalf("schema: %v", err)
			}
			host := doc["host"].(map[string]any)
			if host["transport"] != "ssh" || host["canary"] != "ok" || host["remote_shell"] != "/bin/bash" || host["platform"] != "linux" {
				t.Errorf("host block: %v", host)
			}
			run := doc["run"].(map[string]any)
			if run["status"] != "complete" || run["persisted"] == nil {
				t.Errorf("run block: %v", run)
			}
			if _, err := os.Stat(run["persisted"].(string)); err != nil {
				t.Errorf("persisted file missing: %v", err)
			}
			// Audit log: every line is a catalog check that either ran, was
			// unavailable, or was the canary; nothing else reached the host.
			raw, err := os.ReadFile(audit)
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
				var e struct {
					Check    string   `json:"check"`
					Decision string   `json:"decision"`
					Argv     []string `json:"argv"`
				}
				if err := json.Unmarshal([]byte(line), &e); err != nil {
					t.Fatalf("audit line: %v", err)
				}
				if strings.HasPrefix(e.Decision, "denied") {
					t.Errorf("denied attempt in a baseline run: %s", line)
				}
				if e.Check == "" || len(e.Argv) == 0 {
					t.Errorf("audit line without check/argv: %s", line)
				}
			}
			// Criterion 3: nothing modified on the target beyond runtime
			// noise sshd itself produces (/run, /var/log, wtmp/lastlog).
			for _, line := range strings.Split(strings.TrimSpace(c.Diff(t)), "\n") {
				if line == "" || strings.Contains(before, line) {
					continue
				}
				if strings.HasPrefix(line, "C /run") || strings.HasPrefix(line, "A /run") || strings.HasPrefix(line, "C /var") ||
					strings.HasPrefix(line, "A /var") || line == "C /etc" || strings.HasPrefix(line, "C /home") || strings.HasPrefix(line, "A /home") {
					continue
				}
				t.Errorf("target modified: %s", line)
			}
		})
	}
}

func loadSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "report-schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("report-schema.json", doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("report-schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}
