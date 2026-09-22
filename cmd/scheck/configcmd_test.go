package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runIn executes the CLI in dir with HOME pointed at a scratch directory so
// only the files the test wrote are read.
func runIn(t *testing.T, dir string, args ...string) (string, int) {
	t.Helper()
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	wd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(wd) }()
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), exitCodeOf(err)
}

func userConfigPath(t *testing.T, dir string) string {
	t.Helper()
	// os.UserConfigDir honours XDG_CONFIG_HOME on Linux and uses
	// ~/Library/Application Support on macOS; runIn sets both roots under
	// dir/home, so the test resolves the path the same way the binary does.
	t.Setenv("HOME", filepath.Join(dir, "home"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "home", ".config"))
	p, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(p, "scheck", "config.yaml")
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The M2.2a demo: a user default selects the model, the project selects
// hardened, and an explicit --profile is attributed to the flag while the
// model keeps its file origin. The run path resolves identically.
func TestConfigShowProvenance(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, userConfigPath(t, dir), "model: gpt-5\ndisable_checks: [net.listeners]\n")
	writeFile(t, filepath.Join(dir, "scheck.yaml"), "profile: hardened\ndisable_checks: [net.listeners, fs.suid]\n")
	out, code := runIn(t, dir, "config", "show", "--profile", "baseline", "--format", "json")
	if code != exitOK {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	var doc inspection
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Settings["profile"].Value != "baseline" || doc.Settings["profile"].Source != "flag" {
		t.Errorf("profile: %+v", doc.Settings["profile"])
	}
	if doc.Settings["model"].Value != "gpt-5" || !strings.HasSuffix(doc.Settings["model"].Source, filepath.Join("scheck", "config.yaml")) {
		t.Errorf("model: %+v", doc.Settings["model"])
	}
	if doc.Settings["provider"].Source != "default" || doc.Settings["elevate"].Value != "none" {
		t.Errorf("defaults: %+v", doc.Settings)
	}
	var listeners, suid string
	for _, e := range doc.Lists["disable_checks"] {
		switch e.Value {
		case "net.listeners":
			listeners = e.Sources
		case "fs.suid":
			suid = e.Sources
		}
	}
	if !strings.Contains(listeners, "config.yaml") || !strings.Contains(listeners, "scheck.yaml") || suid != "scheck.yaml" {
		t.Errorf("accumulated attribution: listeners %q suid %q", listeners, suid)
	}
	// The ordinary run path resolves the same effective settings: the plan
	// honours the accumulated disable_checks and the flag's profile.
	plan, code := runIn(t, dir, "local", "--profile", "baseline", "--stop-after", "plan", "--format", "json")
	if code != exitOK {
		t.Fatalf("plan: exit %d:\n%s", code, plan)
	}
	var pdoc struct {
		Profile string `json:"profile"`
		Checks  []struct {
			ID string `json:"id"`
		} `json:"checks"`
	}
	if err := json.Unmarshal([]byte(plan), &pdoc); err != nil {
		t.Fatal(err)
	}
	if pdoc.Profile != "baseline" {
		t.Errorf("run path profile %q", pdoc.Profile)
	}
	for _, c := range pdoc.Checks {
		if c.ID == "net.listeners" || c.ID == "fs.suid" {
			t.Errorf("run path ignored an accumulated disable_checks entry: %s", c.ID)
		}
	}
	text, _ := runIn(t, dir, "config", "show", "--profile", "baseline")
	for _, want := range []string{"profile", "baseline", "flag", "gpt-5", "net.listeners", "<-"} {
		if !strings.Contains(text, want) {
			t.Errorf("text show lacks %q:\n%s", want, text)
		}
	}
}

// validate exits 0 for a valid local configuration and 3 for a usage or
// config error, naming the source; a target: source is unresolved, not read.
func TestConfigValidateExitCodes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts", "gateway.yaml"), "context:\n  exposure: internet\n")
	out, code := runIn(t, dir, "config", "validate", "--context", "hosts/gateway.yaml", "--context", "target")
	if code != exitOK || !strings.Contains(out, "configuration ok") || !strings.Contains(out, "1 unresolved target") {
		t.Fatalf("valid: exit %d\n%s", code, out)
	}
	writeFile(t, filepath.Join(dir, "hosts", "bad.yaml"), "context:\n  exposure: internet\n  accepted_risks:\n    - { id: sshd.pasword_auth_enabled }\n")
	_, code = runIn(t, dir, "config", "validate", "--context", "hosts/bad.yaml")
	if code != exitUsage {
		t.Fatalf("invalid context field: exit %d, want 3", code)
	}
	writeFile(t, filepath.Join(dir, "scheck.yaml"), "profile: paranoid\n")
	_, code = runIn(t, dir, "config", "validate")
	if code != exitUsage {
		t.Fatalf("invalid profile: exit %d, want 3", code)
	}
	// show still displays the broken configuration, with the error.
	out, code = runIn(t, dir, "config", "show", "--format", "json")
	if code != exitOK {
		t.Fatalf("show on a broken config: exit %d", code)
	}
	var doc inspection
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(doc.Error, "paranoid") || doc.Settings["profile"].Value != "paranoid" {
		t.Errorf("broken config not shown: %+v", doc)
	}
}

// Seeded credentials never reach text, JSON or diagnostics, and
// target-derived text cannot control the terminal.
func TestConfigShowLeaksNothing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENAI_API_KEY", "sk-live-should-not-print")
	writeFile(t, filepath.Join(dir, "scheck.yaml"), "base_url: https://ops:hunter2@llm.example.com/v1\ntargets:\n  evil: { host: \"10.0.0.5\\x1b[2J\", user: ops }\n")
	note := "note:the password=s3cretvalue is here"
	for _, format := range []string{"text", "json"} {
		out, code := runIn(t, dir, "config", "show", "--format", format, "--context", note)
		if code != exitOK {
			t.Fatalf("%s: exit %d", format, code)
		}
		for _, secret := range []string{"hunter2", "s3cretvalue", "sk-live-should-not-print", "\x1b[2J"} {
			if strings.Contains(out, secret) {
				t.Errorf("%s output leaks %q:\n%s", format, secret, out)
			}
		}
		if !strings.Contains(out, "credentials stripped") || !strings.Contains(out, "[REDACTED:kv-secret:") || !strings.Contains(out, `\x1b`) {
			t.Errorf("%s output not redacted/escaped:\n%s", format, out)
		}
	}
}

// OpenAI's endpoint defaults to gpt-5.6-luna; a different base URL does not
// invent a model name (docs/SPEC.md §5.2).
func TestOpenAIEndpointDefaultsToLuna(t *testing.T) {
	dir := t.TempDir()
	out, code := runIn(t, dir, "config", "show", "--format", "json")
	if code != exitOK {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	var doc inspection
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Settings["model"].Value != "gpt-5.6-luna" || doc.Settings["model"].Source != "default" {
		t.Errorf("openai default: %+v", doc.Settings["model"])
	}
	out, code = runIn(t, dir, "config", "show", "--base-url", "http://localhost:8000/v1", "--format", "json")
	if code != exitOK {
		t.Fatalf("custom endpoint: exit %d:\n%s", code, out)
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Settings["model"].Value != "" {
		t.Errorf("custom endpoint invented a model: %+v", doc.Settings["model"])
	}
}

// A target that names no port is rendered as "-" and omits the JSON field: a
// port of 0 is not configuration, it is the absence of it, and printing 0
// reads as a port the operator wrote. The M4.6 acceptance pass carried this
// as open item 2 (`docs/eval/acceptance-0.0.1.md`).
func TestConfigShowRendersAnUnsetPortAsAbsent(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "scheck.yaml"),
		"targets:\n  plain:\n    host: a.example\n    user: ops\n  explicit:\n    host: b.example\n    user: ops\n    port: 2222\n")

	out, code := runIn(t, dir, "config", "show", "--format", "json")
	if code != exitOK {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	var doc inspection
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if got := doc.Targets["plain"].Port; got != 0 {
		t.Errorf("unset port decoded as %d, want the field absent", got)
	}
	if !strings.Contains(out, `"host": "a.example"`) || strings.Contains(out, `"port": 0`) {
		t.Errorf("json still carries a zero port:\n%s", out)
	}
	if got := doc.Targets["explicit"].Port; got != 2222 {
		t.Errorf("explicit port %d, want 2222", got)
	}

	text, code := runIn(t, dir, "config", "show")
	if code != exitOK {
		t.Fatalf("text exit %d:\n%s", code, text)
	}
	if !strings.Contains(text, "ops@a.example port - identity") {
		t.Errorf("unset port is not rendered as a dash:\n%s", text)
	}
	if !strings.Contains(text, "ops@b.example port 2222 identity") {
		t.Errorf("explicit port is not rendered:\n%s", text)
	}
}
