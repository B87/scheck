//go:build integration

package integ

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/b87/scheck/test/containers"
)

// loginNoise is every diff line an ssh login may leave behind, as exact
// paths. Directory entries appear because a child changed.
var loginNoise = map[string]bool{
	"C /home": true, "C /root": true, "C /run": true, "C /var": true, "C /var/log": true,
	"A /run/motd.dynamic": true, "C /run/motd.dynamic": true,
	"A /run/sshd.pid": true, "C /run/sshd.pid": true,
	"A /run/utmp": true, "C /run/utmp": true,
	"C /var/log/wtmp": true, "C /var/log/lastlog": true, "C /var/log/btmp": true,
	"C /var/log/auth.log": true, "C /var/log/secure": true,
}

// homeNoise matches the per-user artefacts of a login: pam's motd cache and
// the directories above it, for whichever account the test logs in as.
var homeNoise = regexp.MustCompile(`^[CA] (/root|/home/[^/]+)(/\.cache(/motd\.legal-displayed)?)?$`)

// runtimeArtifacts matches every write scheck itself is known to cause: the
// documented exceptions to "it never modifies the target" (docs/SPEC.md §1).
// All of them are a tool's record of its own invocation in runtime or cache
// state; none is configuration, a package, a unit or a credential. They are
// named exactly, so any other write fails the assertion.
var runtimeArtifacts = regexp.MustCompile(`^[CA] (` +
	// pkg.dnf_check_update: dnf's per-user cache and logs. dnf4 writes
	// /var/tmp/dnf-<user>-<random>/, dnf5 writes under the invoking user's
	// home. Measured 2026-09-22: no argv avoids it — --cacheonly still
	// creates the directory and writes its logs.
	`/var/tmp|/var/tmp/dnf-[^/]+(/.*)?|/home/[^/]+/\.cache/libdnf5(/.*)?|/home/[^/]+/\.local/state(/dnf5\.log)?` +
	// Elevation: `sudo -n --` creates its timestamp directory for the uid.
	`|/run/sudo(/ts(/[0-9]+)?)?` +
	// fw.ufw: `ufw status verbose` takes a lock file to read the status.
	`|/run/ufw\.lock` +
	`)$`)

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
			// Criterion 3: nothing modified on the target beyond the noise an
			// ssh login itself produces, plus the one write scheck is known to
			// cause and documents (docs/SPEC.md §1). Both sets are exact: an
			// earlier prefix match on /run, /var and /home tolerated whole
			// trees, so a check writing into one of them would have passed
			// unnoticed — which is how the dnf cache reached the M4.6 pass as
			// a reading of the log rather than a test failure. The classified
			// lines are logged so the acceptance record can show what a
			// read-only run leaves behind
			// (docs/SPEC.md §12, docs/eval/acceptance-0.0.1.md).
			var noise, documented []string
			for _, line := range strings.Split(strings.TrimSpace(c.Diff(t)), "\n") {
				if line == "" || strings.Contains(before, line) {
					continue
				}
				switch {
				case runtimeArtifacts.MatchString(line):
					documented = append(documented, line)
				case loginNoise[line] || homeNoise.MatchString(line):
					noise = append(noise, line)
				default:
					t.Errorf("target modified outside the login noise and the one documented exception: %s", line)
				}
			}
			t.Logf("post-run docker diff: %d login-noise lines, %d documented-exception lines: %s",
				len(noise), len(documented), strings.Join(append(append([]string{}, noise...), documented...), " | "))
			// Without --sudo neither the elevation timestamp nor ufw's lock
			// exists, so Ubuntu's only possible artefact source is apt, which
			// writes nothing. A match here would mean the pattern is picking
			// up something other than what it names.
			if name != "fedora" && len(documented) > 0 {
				t.Errorf("%s: runtime-artifact pattern matched on a distribution that runs none of the commands that cause them: %v", name, documented)
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

// The read-only classification is the assertion criterion 3 rests on, so it
// is tested directly rather than only through a container run: a write
// outside the login noise and the one documented exception must be rejected.
func TestReadOnlyDiffClassification(t *testing.T) {
	for _, tc := range []struct {
		line, class string
	}{
		{"C /home/ops", "noise"},
		{"A /home/ops/.cache/motd.legal-displayed", "noise"},
		{"A /run/motd.dynamic", "noise"},
		{"C /var/log/lastlog", "noise"},
		{"C /var/tmp", "documented"},
		{"C /run/sudo", "documented"},
		{"A /run/sudo/ts/1001", "documented"},
		{"A /run/ufw.lock", "documented"},
		{"A /var/tmp/dnf-ops-4nzsbt6h/dnf.log", "documented"},
		{"A /home/ops/.cache/libdnf5/fedora/repodata/repomd.xml", "documented"},
		{"C /home/ops/.local/state/dnf5.log", "documented"},
		// Everything a check could plausibly write must fail.
		{"A /etc/sudoers.d/evil", "rejected"},
		{"C /etc/ssh/sshd_config", "rejected"},
		{"A /var/lib/nginx/body", "rejected"},
		{"A /run/nginx.pid", "rejected"},
		{"C /home/ops/.ssh/authorized_keys", "rejected"},
		{"A /var/tmp/not-dnf", "rejected"},
		{"A /run/sudoers", "rejected"},
		{"A /run/ufw.lock.bak", "rejected"},
		{"A /usr/bin/thing", "rejected"},
	} {
		var got string
		switch {
		case runtimeArtifacts.MatchString(tc.line):
			got = "documented"
		case loginNoise[tc.line] || homeNoise.MatchString(tc.line):
			got = "noise"
		default:
			got = "rejected"
		}
		if got != tc.class {
			t.Errorf("%q classified as %s, want %s", tc.line, got, tc.class)
		}
	}
}
