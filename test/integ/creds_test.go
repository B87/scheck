//go:build integration

package integ

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b87/scheck/test/containers"
)

// G5 (docs/ROADMAP.md): credential files are judged by mode bits and the
// folders above them. The target is seeded as root before the run, so the
// read-only diff below starts after the seeds: a .env that every account can
// read under a declared application folder, a private key readable by all in
// a home others can enter, and the same file modes inside a private home,
// which must not be reported. The run lists names and modes; no seeded
// content may reach the report.
func TestCredentialFilesOnContainers(t *testing.T) {
	bin := containers.BuildScheck(t)
	for _, name := range []string{"ubuntu", "fedora"} {
		t.Run(name, func(t *testing.T) {
			c := containers.Start(t, name)
			frag, _, code := containers.Run(t, bin, "sudoers", "--platform", "linux", "--user", "ops")
			if code != 0 {
				t.Fatal("sudoers failed")
			}
			if out, err := c.ExecInput(t, frag, "sh", "-c", "cat > /etc/sudoers.d/scheck && chmod 440 /etc/sudoers.d/scheck"); err != nil {
				t.Fatalf("install: %v %s", err, out)
			}
			seed := `set -e
install -d -m 755 /srv/shop
printf 'DB_PASSWORD=seeded-secret-marker\n' > /srv/shop/.env && chmod 644 /srv/shop/.env
install -d -m 700 -o ops -g ops /srv/closed
printf 'DB_PASSWORD=seeded-secret-marker\n' > /srv/closed/.env && chown ops:ops /srv/closed/.env && chmod 644 /srv/closed/.env
useradd -m -s /bin/bash deploy && chmod 755 /home/deploy
install -d -m 755 -o deploy -g deploy /home/deploy/.ssh
printf 'seeded-secret-marker\n' > /home/deploy/.ssh/id_ed25519
chown deploy:deploy /home/deploy/.ssh/id_ed25519 && chmod 644 /home/deploy/.ssh/id_ed25519
install -d -m 700 -o ops -g ops /home/ops/.aws
printf 'seeded-secret-marker\n' > /home/ops/.aws/credentials
chown ops:ops /home/ops/.aws/credentials && chmod 644 /home/ops/.aws/credentials
chmod 750 /home/ops`
			if out, err := c.ExecInput(t, seed, "sh"); err != nil {
				t.Fatalf("seed: %v %s", err, out)
			}
			before := c.Diff(t)

			file := filepath.Join(t.TempDir(), "engagement.yaml")
			yaml := "schema: 1\nengagement:\n  name: creds-lab\n  operator: lab\n  timezone: UTC\n  trigger: routine\n" +
				"roots:\n  - host: ops@" + c.Addr() + "\nassets:\n  lab:\n    host: ops@" + c.Addr() + "\n" +
				"    identity: " + c.Identity + "\n    known_hosts: " + c.KnownHosts + "\n    elevate: sudo\n" +
				"    app_paths: [/srv/shop, /srv/closed]\n"
			if err := os.WriteFile(file, []byte(yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			stateDir := t.TempDir()
			out, errOut, code := containers.Run(t, bin, "run", file, "--format", "json", "--state-dir", stateDir)
			if code > 1 {
				t.Fatalf("exit %d\n%s", code, errOut)
			}
			if strings.Contains(out, "seeded-secret-marker") {
				t.Fatal("seeded file content reached the report")
			}
			// Nor the audit log or anything else the run persisted.
			_ = filepath.WalkDir(stateDir, func(p string, d os.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					if raw, rerr := os.ReadFile(p); rerr == nil && strings.Contains(string(raw), "seeded-secret-marker") {
						t.Errorf("seeded file content reached the run directory: %s", p)
					}
				}
				return nil
			})
			var rep struct {
				Findings []struct {
					ID       string
					Evidence []struct{ Excerpt string }
				}
			}
			if err := json.Unmarshal([]byte(out), &rep); err != nil {
				t.Fatal(err)
			}
			got := map[string]string{}
			for _, f := range rep.Findings {
				for _, e := range f.Evidence {
					got[f.ID] += e.Excerpt + "\n"
				}
				if _, ok := got[f.ID]; !ok {
					got[f.ID] = ""
				}
			}
			if !strings.Contains(got["creds.env_file_exposed"], "/srv/shop/.env") {
				t.Errorf("the world-readable .env was not found: %v", got)
			}
			if !strings.Contains(out, "/srv/closed/.env") {
				t.Errorf("the .env in the closed folder was not even listed: the folder logic was not exercised")
			}
			if strings.Contains(got["creds.env_file_exposed"], "/srv/closed/.env") {
				t.Errorf("a .env inside a closed folder was reported: %v", got)
			}
			if !strings.Contains(got["creds.ssh_key_exposed"], "/home/deploy/.ssh/id_ed25519") {
				t.Errorf("the readable private key was not found: %v", got)
			}
			if _, ok := got["creds.cloud_credentials_exposed"]; ok {
				t.Errorf("a credentials file inside a private home was reported: %v", got)
			}
			// An elevated run runs ufw on Ubuntu too, so its documented lock
			// file is expected on both distributions: the "fedora" branch of
			// the shared assertion, with no tolerance widened.
			assertReadOnly(t, c, before, "fedora")
		})
	}
}
