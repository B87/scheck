//go:build integration

package integ

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/b87/scheck/test/containers"
)

// `scheck run --host ... --jump ...` reaches a target that only a jump host
// can see: the canary is the first command on the target, every audit line
// names the hop, nothing runs on the hop and its filesystem is left as it
// was, and the target's diff stays the exact allowlist. A hop whose key is
// not known exits 3 before the target is contacted (docs/ROADMAP.md, E1c).
func TestRunThroughAJumpHost(t *testing.T) {
	bin := containers.BuildScheck(t)
	engagementSchema := loadSchemaFile(t, "engagement-report-schema.json")
	hop, dst := containers.StartBehindJump(t, "ubuntu")
	hopBefore, dstBefore := hop.Diff(t), dst.Diff(t)
	dstLogs := dst.Logs(t)
	jump := "ops@" + hop.Addr()
	via := "ops@" + hop.Host + ":" + strconv.Itoa(hop.Port)

	dir := t.TempDir()
	onlyTarget := filepath.Join(dir, "known_hosts.target-only")
	both := filepath.Join(dir, "known_hosts")
	hopKey, err := os.ReadFile(hop.KnownHosts)
	if err != nil {
		t.Fatal(err)
	}
	dstKey, err := os.ReadFile(dst.KnownHosts)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(onlyTarget, dstKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(both, append(append([]byte{}, hopKey...), dstKey...), 0o600); err != nil {
		t.Fatal(err)
	}

	type report struct {
		Exit   struct{ Code int } `json:"exit"`
		Assets []struct {
			Status, Via string
			Trace       []struct{ Check string } `json:"trace"`
		} `json:"assets"`
		Refused []struct{ Kind string } `json:"refused"`
	}
	runVia := func(knownHosts string) (report, string, string, int) {
		stateDir := t.TempDir()
		out, errOut, code := containers.Run(t, bin, "run", "--host", "ops@"+containers.TargetAlias, "--jump", jump,
			"--identity", dst.Identity, "--known-hosts", knownHosts, "--format", "json", "--state-dir", stateDir)
		var doc any
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("exit %d, not JSON: %v\n%s\n%s", code, err, out, errOut)
		}
		if err := engagementSchema.Validate(doc); err != nil {
			t.Fatalf("the report violates docs/engagement-report-schema.json: %v", err)
		}
		var rep report
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatal(err)
		}
		dirs, _ := filepath.Glob(filepath.Join(stateDir, "engagements", "*", "*"))
		if len(dirs) != 1 {
			t.Fatalf("run directories: %q", dirs)
		}
		audit, err := os.ReadFile(filepath.Join(dirs[0], "audit.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		return rep, string(audit), errOut, code
	}

	t.Run("unknown jump host key", func(t *testing.T) {
		rep, audit, errOut, code := runVia(onlyTarget)
		if code != 3 || len(rep.Refused) != 1 || rep.Refused[0].Kind != "jump_host_key_unknown" {
			t.Fatalf("exit %d, refused %+v\n%s", code, rep.Refused, errOut)
		}
		if a := rep.Assets[0]; a.Status != "refused" || a.Via != via || len(a.Trace) != 0 {
			t.Errorf("asset %+v", a)
		}
		if strings.TrimSpace(audit) != "" {
			t.Errorf("a command was sent: %s", audit)
		}
		if logs := dst.Logs(t); logs != dstLogs {
			t.Errorf("the target was contacted:\n%s", strings.TrimPrefix(logs, dstLogs))
		}
		if strings.Contains(hop.Logs(t), "Accepted publickey") {
			t.Error("scheck logged in to a jump host whose key it does not know")
		}
	})

	t.Run("collected through the hop", func(t *testing.T) {
		rep, audit, errOut, code := runVia(both)
		if code != 0 && code != 1 {
			t.Fatalf("exit %d\n%s", code, errOut)
		}
		if len(rep.Assets) != 1 || rep.Assets[0].Status != "collected" || rep.Assets[0].Via != via {
			t.Fatalf("assets %+v", rep.Assets)
		}
		if tr := rep.Assets[0].Trace; len(tr) == 0 || tr[0].Check != "sys.canary" {
			t.Errorf("the target's trace does not open with the canary: %+v", tr)
		}
		lines := strings.Split(strings.TrimSpace(audit), "\n")
		for _, line := range lines {
			var e struct{ Check, Via string }
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				t.Fatal(err)
			}
			if e.Via != via {
				t.Errorf("audit line without the hop: %s", line)
			}
		}
		if !strings.Contains(lines[0], `"check":"sys.canary"`) {
			t.Errorf("the first command is not the canary: %s", lines[0])
		}
		assertReadOnly(t, dst, dstBefore, "ubuntu")
		assertHopUntouched(t, hop, hopBefore)
	})
}

// assertHopUntouched holds the jump host to less than a target: it only
// forwarded a connection, so not even the documented runtime artefacts may
// appear, only what sshd writes for an authenticated connection.
func assertHopUntouched(t *testing.T, hop *containers.Container, before string) {
	t.Helper()
	var noise []string
	for _, line := range strings.Split(strings.TrimSpace(hop.Diff(t)), "\n") {
		if line == "" || strings.Contains(before, line) {
			continue
		}
		if loginNoise[line] || homeNoise.MatchString(line) {
			noise = append(noise, line)
			continue
		}
		t.Errorf("jump host modified: %s", line)
	}
	t.Logf("jump host docker diff: %d login-noise lines: %s", len(noise), strings.Join(noise, " | "))
	if logs := hop.Logs(t); strings.Contains(logs, "session opened") || strings.Contains(logs, "Starting session") {
		t.Errorf("a session was opened on the jump host:\n%s", logs)
	}
}
