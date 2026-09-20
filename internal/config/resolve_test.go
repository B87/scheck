package config

import (
	"strings"
	"testing"
)

// Precedence is defaults → user file → project file → explicit flags, and
// every value knows where it came from (docs/SPEC.md §9).
func TestResolveProvenance(t *testing.T) {
	user := write(t, "user.yaml", "model: gpt-5\nprofile: hardened\ndisable_checks: [net.listeners]\nredact_extra: ['corp\\.example']\n")
	proj := write(t, "scheck.yaml", "profile: baseline\nelevate: sudo\ndisable_checks: [net.listeners, sshd.config]\ntargets:\n  bastion: {host: 10.0.0.5, user: ops}\ncontext:\n  role: gateway\n")
	layers, err := LoadLayers(user, proj, "/nonexistent/scheck.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !layers[0].Present || !layers[1].Present || layers[2].Present {
		t.Fatalf("presence: %+v", layers)
	}
	r := Resolve(layers, Overrides{Profile: new("baseline"), MaxContext: nil})
	c := r.Config
	if c.Model != "gpt-5" || r.Origin["model"] != user {
		t.Errorf("model: %q from %q", c.Model, r.Origin["model"])
	}
	if c.Profile != "baseline" || r.Origin["profile"] != SourceFlag {
		t.Errorf("profile: %q from %q (the flag was explicitly set)", c.Profile, r.Origin["profile"])
	}
	if c.Elevate != "sudo" || r.Origin["elevate"] != proj {
		t.Errorf("elevate: %q from %q", c.Elevate, r.Origin["elevate"])
	}
	if c.Provider != "openai-compatible" || r.Origin["provider"] != SourceDefault {
		t.Errorf("provider default: %q from %q", c.Provider, r.Origin["provider"])
	}
	if got := r.Entries["disable_checks"]["net.listeners"]; got != user+", "+proj {
		t.Errorf("net.listeners attributed to %q, want both files", got)
	}
	if got := r.Entries["disable_checks"]["sshd.config"]; got != proj {
		t.Errorf("sshd.config attributed to %q", got)
	}
	if r.Entries["redact_extra"]["corp\\.example"] != user || r.Entries["targets"]["bastion"] != proj {
		t.Errorf("entries: %+v", r.Entries)
	}
	if c.ContextSource != proj || r.Origin["context"] != proj {
		t.Errorf("context from %q", c.ContextSource)
	}
	if strings.Join(c.Sources, ",") != user+","+proj {
		t.Errorf("sources: %v", c.Sources)
	}
}

// A flag that was not explicitly set contributes nothing: a registered
// default must never override a file (ROADMAP M2.2a).
func TestUnsetFlagDoesNotOverrideFile(t *testing.T) {
	proj := write(t, "scheck.yaml", "profile: hardened\nmax_context: 9000\n")
	layers, _ := LoadLayers(proj)
	r := Resolve(layers, Overrides{})
	if r.Config.Profile != "hardened" || r.Config.MaxContext != 9000 {
		t.Errorf("file values lost: %+v", r.Config)
	}
	// An explicitly set flag wins even when its value equals the default.
	r = Resolve(layers, Overrides{Profile: new("baseline")})
	if r.Config.Profile != "baseline" || r.Origin["profile"] != SourceFlag {
		t.Errorf("explicit flag: %q from %q", r.Config.Profile, r.Origin["profile"])
	}
	local := true
	r = Resolve(layers, Overrides{LocalOnly: &local})
	if r.Config.AllowEgress == nil || *r.Config.AllowEgress || !strings.HasPrefix(r.Origin["allow_egress"], SourceFlag) {
		t.Errorf("--local-only did not narrow allow_egress: %+v %v", r.Config.AllowEgress, r.Origin)
	}
}

func TestStripUserInfo(t *testing.T) {
	cases := map[string]string{
		"https://api.openai.com/v1":            "https://api.openai.com/v1",
		"https://u:hunter2@api.example.com/v1": "https://api.example.com/v1 (credentials stripped)",
		"http://token@localhost:11434":         "http://localhost:11434 (credentials stripped)",
		"not a url":                            "not a url",
	}
	for in, want := range cases {
		if got := StripUserInfo(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
		if strings.Contains(StripUserInfo(in), "hunter2") {
			t.Errorf("credential leaked from %q", in)
		}
	}
}

func TestValidateEffortAndMaxContext(t *testing.T) {
	for _, body := range []string{"effort: extreme\n", "max_context: -1\n"} {
		c, err := LoadFiles(write(t, "scheck.yaml", body))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Validate(); err == nil {
			t.Errorf("%q accepted", body)
		}
	}
}
