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
// `scheck ssh`: a schema-valid host envelope under evidence/, an audit log
// of catalog argv only, and a target the run left as the exact allowlist
// of docs/spec/host-collector.md §1 says (docs/ROADMAP.md, E1b).
func TestRunHostOnContainers(t *testing.T) {
	bin := containers.BuildScheck(t)
	schema := loadSchema(t)
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
			var findings struct {
				Assets []struct {
					Status, Evidence string
				} `json:"assets"`
			}
			if err := json.Unmarshal([]byte(out), &findings); err != nil {
				t.Fatal(err)
			}
			if len(findings.Assets) != 1 || findings.Assets[0].Status != "collected" {
				t.Fatalf("findings.json assets: %+v", findings.Assets)
			}
			raw, err := os.ReadFile(filepath.Join(dir, findings.Assets[0].Evidence))
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
