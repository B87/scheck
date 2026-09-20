//go:build integration

package integ

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/b87/scheck/test/containers"
)

// M0.8 exit demo: the generated fragment parses under visudo, and installing
// it flips sshd.config from unavailable to populated under --sudo.
func TestSudoersFragmentOnUbuntu(t *testing.T) {
	c := containers.Start(t, "ubuntu")
	bin := containers.BuildScheck(t)
	frag, errOut, code := containers.Run(t, bin, "sudoers", "--platform", "linux", "--user", "ops")
	if code != 0 {
		t.Fatalf("sudoers: %d %s", code, errOut)
	}
	if out, err := c.ExecInput(t, frag, "visudo", "-cf", "-"); err != nil {
		t.Fatalf("visudo rejected the fragment: %v\n%s\n%s", err, out, frag)
	}

	sshArgs := func(extra ...string) []string {
		return append([]string{"ssh", "ops@" + c.Addr(), "--identity", c.Identity, "--known-hosts", c.KnownHosts,
			"--stop-after", "facts", "--format", "json"}, extra...)
	}
	facts := func(args []string) map[string]map[string]any {
		out, errOut, code := containers.Run(t, bin, args...)
		if code != 0 {
			t.Fatalf("scheck ssh: %d\n%s", code, errOut)
		}
		var doc struct {
			Facts map[string]map[string]any `json:"facts"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("json: %v\n%s", err, out)
		}
		return doc.Facts
	}

	// Without the fragment: sudo -n is refused and the check degrades.
	f := facts(sshArgs("--sudo"))
	if f["sshd.config"]["status"] != "unavailable" || !strings.HasPrefix(f["sshd.config"]["reason"].(string), "sudo:") {
		t.Fatalf("before install: %v", f["sshd.config"])
	}
	// Under --elevate none, the check is skipped without contacting sudo.
	f = facts(sshArgs())
	if f["sshd.config"]["reason"] != "requires elevated read" {
		t.Fatalf("elevate none: %v", f["sshd.config"])
	}

	if out, err := c.ExecInput(t, frag, "sh", "-c", "cat > /etc/sudoers.d/scheck && chmod 440 /etc/sudoers.d/scheck"); err != nil {
		t.Fatalf("install: %v %s", err, out)
	}
	f = facts(sshArgs("--sudo"))
	if f["sshd.config"]["status"] != "ok" {
		t.Fatalf("after install: %v", f["sshd.config"])
	}
	parsed := f["sshd.config"]["parsed"].(map[string]any)
	if parsed["passwordauthentication"] != "no" {
		t.Errorf("sshd -T not parsed: %v", parsed)
	}
	// Elevated read must not have widened anything: the fragment we installed
	// is the only filesystem change caused by the tests.
	for _, line := range strings.Split(strings.TrimSpace(c.Diff(t)), "\n") {
		if line == "" || strings.HasPrefix(line, "C /etc/sudoers.d") || strings.HasPrefix(line, "A /etc/sudoers.d/scheck") ||
			strings.HasPrefix(line, "C /etc") || strings.HasPrefix(line, "C /run") || strings.HasPrefix(line, "C /var") ||
			strings.HasPrefix(line, "A /run") || strings.HasPrefix(line, "A /var") || strings.HasPrefix(line, "C /home") ||
			strings.HasPrefix(line, "A /home") || strings.HasPrefix(line, "C /root") || strings.HasPrefix(line, "A /root") {
			continue
		}
		t.Errorf("unexpected change on target: %s", line)
	}
}
