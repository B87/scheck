//go:build integration

package integ

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/b87/scheck/test/containers"
)

// G8 (docs/ROADMAP.md): PHP and Node.js are judged from the package database,
// never by running them. The Ubuntu container is seeded as root with stub
// packages that carry the versions under test (a stub is a package record,
// nothing runs), and with a real nginx on every address. The read-only diff
// starts after the seeds and keeps its exact allowlist.
//
// Ubuntu 24.04's fixed PHP package carries upstream version 8.3.6, far below
// the upstream fix 8.3.36: the second variant is the false-positive trap and
// must not be reported.
func TestRuntimePackagesOnUbuntu(t *testing.T) {
	bin := containers.BuildScheck(t)
	for _, tc := range []struct {
		name, phpVersion string
		wantPHP          bool
	}{
		{"php below the distribution's fix", "8.3.6-0ubuntu0.24.04.9", true},
		{"php at the distribution's fix", "8.3.6-0ubuntu0.24.04.13", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := containers.Start(t, "ubuntu")
			installSudoers(t, c, bin)
			seed := `set -e
mk() { d=$(mktemp -d); mkdir -p "$d/DEBIAN"; chmod 0755 "$d" "$d/DEBIAN"; printf 'Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: lab <lab@example.invalid>\nDescription: lab stub\n' "$1" "$2" > "$d/DEBIAN/control"; dpkg-deb --build "$d" "/tmp/$1.deb" >/dev/null; dpkg -i "/tmp/$1.deb" >/dev/null; rm -rf "$d" "/tmp/$1.deb"; }
mk php8.3-fpm ` + tc.phpVersion + `
mk nodejs 24.20.0-1nodesource1
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx >/dev/null
nginx`
			if out, err := c.ExecInput(t, seed, "sh"); err != nil {
				t.Fatalf("seed: %v %s", err, out)
			}
			before := c.Diff(t)
			out, stateDir := runLab(t, c, bin, "")
			rep := runtimeFindings(t, out)
			php, ok := rep["php.fix_missing"]
			if tc.wantPHP {
				// The container cannot run ufw (no network administration), so
				// the firewall is unknown: the web server is not shown
				// reachable and the rating stays at its base, which the
				// report says.
				if !ok || php.Severity != "medium" || php.Subject != "php8.3-fpm" {
					t.Errorf("php.fix_missing: %+v (all: %v)", php, rep)
				}
				if !strings.Contains(out, "rated at its base") {
					t.Errorf("the report does not say the web server's reach was not established")
				}
			} else {
				if ok {
					t.Errorf("the distribution's fixed package was reported: %+v", php)
				}
				// Not reported because it was judged and found fixed, not
				// because it was never judged: the PHP group is decided.
				if !strings.Contains(strings.Join(runtimeJudged(t, out), "|"), "PHP web packages against the October 2026 fix") {
					t.Errorf("the PHP rule did not decide: %v", runtimeJudged(t, out))
				}
			}
			if node, ok := rep["node.fix_missing"]; !ok || node.Subject != "nodejs" {
				t.Errorf("node.fix_missing: %+v (all: %v)", node, rep)
			}
			if _, ok := rep["node.line_unsupported"]; ok {
				t.Errorf("a supported Node.js line was reported as unsupported: %v", rep)
			}
			// Nothing ran a runtime: no command the run attempted, in its audit
			// log or anywhere else it persisted, starts with a runtime.
			assertNoRuntimeExec(t, stateDir)
			assertReadOnly(t, c, before, "ubuntu")
		})
	}
}

// On Fedora the rpm database answers, finds itself, and shows no PHP or
// Node.js: nothing is reported, and the read is a usable one.
func TestRuntimePackagesOnFedora(t *testing.T) {
	bin := containers.BuildScheck(t)
	c := containers.Start(t, "fedora")
	installSudoers(t, c, bin)
	before := c.Diff(t)
	out, stateDir := runLab(t, c, bin, "")
	assertNoRuntimeExec(t, stateDir)
	if rep := runtimeFindings(t, out); len(rep) != 0 {
		t.Errorf("findings on a host with no PHP or Node.js: %v", rep)
	}
	env := envelopeOf(t, out)
	facts, _ := env["facts"].(map[string]any)
	rpm, _ := facts["pkg.rpm_runtimes"].(map[string]any)
	if rpm == nil || rpm["attempted"] != true {
		t.Fatalf("pkg.rpm_runtimes was not read: %v", rpm)
	}
	if parsed, _ := rpm["parsed"].(map[string]any); parsed == nil || parsed["partial"] == true {
		t.Errorf("the rpm read is not whole: %v", rpm)
	}
	assertReadOnly(t, c, before, "fedora")
}

func installSudoers(t *testing.T, c *containers.Container, bin string) {
	t.Helper()
	frag, _, code := containers.Run(t, bin, "sudoers", "--platform", "linux", "--user", "ops")
	if code != 0 {
		t.Fatal("sudoers failed")
	}
	if out, err := c.ExecInput(t, frag, "sh", "-c", "cat > /etc/sudoers.d/scheck && chmod 440 /etc/sudoers.d/scheck"); err != nil {
		t.Fatalf("install: %v %s", err, out)
	}
}

// runLab runs scheck over SSH against the container with sudo and returns the
// JSON report.
func runLab(t *testing.T, c *containers.Container, bin, extra string) (string, string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "engagement.yaml")
	yaml := "schema: 1\nengagement:\n  name: runtimes-lab\n  operator: lab\n  timezone: UTC\n  trigger: routine\n" +
		"roots:\n  - host: ops@" + c.Addr() + "\nassets:\n  lab:\n    host: ops@" + c.Addr() + "\n" +
		"    identity: " + c.Identity + "\n    known_hosts: " + c.KnownHosts + "\n    elevate: sudo\n" + extra
	if err := os.WriteFile(file, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	out, errOut, code := containers.Run(t, bin, "run", file, "--format", "json", "--state-dir", stateDir)
	if code > 1 {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	return out, stateDir
}

// runtimeExec matches a command line whose program is a runtime or brew.
var runtimeExec = regexp.MustCompile(`"argv":\s*\[\s*("sudo",\s*"-n",\s*"--",\s*)?"(php[0-9.\-]*|php-fpm[0-9.]*|php-cgi[0-9.]*|node|nodejs|npm|npx|brew)"`)

// assertNoRuntimeExec fails when anything the run persisted records an
// attempt to run a runtime: the package databases are read, never the
// programs.
func assertNoRuntimeExec(t *testing.T, stateDir string) {
	t.Helper()
	seen := 0
	_ = filepath.WalkDir(stateDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		if strings.Contains(string(raw), "dpkg-query") || strings.Contains(string(raw), `"rpm"`) {
			seen++
		}
		if m := runtimeExec.Find(raw); m != nil {
			t.Errorf("%s records an attempt to run a runtime: %s", p, m)
		}
		return nil
	})
	if seen == 0 {
		t.Error("the run directory holds no record of the package reads, so the check proves nothing")
	}
}

// runtimeJudged are the names the report's Hosts row lists as judged for the
// Runtimes line.
func runtimeJudged(t *testing.T, out string) []string {
	t.Helper()
	var rep struct {
		Coverage []struct {
			Area     string
			SubItems []struct {
				Name   string
				Judged []string
			} `json:"sub_items"`
		}
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, row := range rep.Coverage {
		for _, si := range row.SubItems {
			if row.Area == "hosts" && strings.HasPrefix(si.Name, "Runtimes") {
				got = append(got, si.Judged...)
			}
		}
	}
	return got
}

type runtimeFinding struct{ Severity, Subject string }

// runtimeFindings are the report's G8 findings by id.
func runtimeFindings(t *testing.T, out string) map[string]runtimeFinding {
	t.Helper()
	var rep struct {
		Findings []struct {
			ID       string
			Severity string
			Key      struct{ Subject *string }
		}
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	got := map[string]runtimeFinding{}
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.ID, "php.") || strings.HasPrefix(f.ID, "node.") {
			rf := runtimeFinding{Severity: f.Severity}
			if f.Key.Subject != nil {
				rf.Subject = *f.Key.Subject
			}
			got[f.ID] = rf
		}
	}
	return got
}
