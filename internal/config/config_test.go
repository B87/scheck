package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/b87/scheck/internal/check/all"
)

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadMergesAndNarrows(t *testing.T) {
	user := write(t, "user.yaml", "profile: hardened\nelevate: sudo\ndisable_checks: [net.listeners]\ndeny_paths: [/etc/a]\n")
	proj := write(t, "scheck.yaml", "profile: baseline\ndisable_checks: [sshd.config, net.listeners]\ndeny_paths: [/etc/b]\ntargets:\n  bastion: {host: 10.0.0.5, user: ops}\ncontext:\n  role: gateway\n")
	c, err := LoadFiles(user, proj, filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Profile != "baseline" || c.Elevate != "sudo" {
		t.Errorf("scalars: %+v", c)
	}
	if strings.Join(c.DisableChecks, ",") != "net.listeners,sshd.config" || strings.Join(c.DenyPaths, ",") != "/etc/a,/etc/b" {
		t.Errorf("lists must union: %v %v", c.DisableChecks, c.DenyPaths)
	}
	if c.Targets["bastion"].Host != "10.0.0.5" || c.Context.IsZero() || len(c.Sources) != 2 {
		t.Errorf("targets/context/sources: %+v", c)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsTypos(t *testing.T) {
	for _, body := range []string{
		"disable_checks: [net.listnrs]\n",
		"profile: paranoid\n",
		"elevate: doas\n",
		"redact_extra: ['(']\n",
	} {
		c, err := LoadFiles(write(t, "scheck.yaml", body))
		if err != nil {
			t.Fatalf("%q: load: %v", body, err)
		}
		if err := c.Validate(); err == nil {
			t.Errorf("%q accepted", body)
		}
	}
	if _, err := LoadFiles(write(t, "scheck.yaml", "api_key: nope\n")); err == nil {
		t.Error("unknown top-level key accepted")
	}
}
