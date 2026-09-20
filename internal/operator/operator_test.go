package operator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func known(id string) bool {
	return id == "sshd.password_auth_enabled" || id == "disk.filevault_off"
}

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func configNode(t *testing.T, body string) yaml.Node {
	t.Helper()
	var doc struct {
		Context yaml.Node `yaml:"context"`
	}
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Context
}

// Merge is defined per kind, not per source order (docs/SPEC.md §6.1):
// scalars override per key, lists concatenate and deduplicate by natural key
// with the later entry winning, prose is never merged.
func TestMergePerKind(t *testing.T) {
	dir := t.TempDir()
	a := write(t, dir, "a.yaml", `
context:
  role: "db host"
  exposure: lan
  compliance: [soc2]
  expected_services:
    - { port: 5432, purpose: "postgres" }
    - { port: 22, purpose: "ssh" }
  accepted_risks:
    - { id: sshd.password_auth_enabled, reason: "first" }
`)
	b := write(t, dir, "b.yaml", `
context:
  exposure: internet
  compliance: [soc2, cis-level-1]
  expected_services:
    - { port: 5432, proto: tcp, purpose: "postgres (override)" }
    - { port: 443, purpose: "nginx" }
  accepted_risks:
    - { id: sshd.password_auth_enabled, reason: "second" }
    - { id: "custom:vendor-agent", reason: "vendor" }
notes: "a yaml key that is not context"
`)
	m, err := Load(Options{
		ConfigContext: configNode(t, "context:\n  environment: prod\n  role: \"from config\"\n"),
		ConfigSource:  "scheck.yaml",
		Flags:         []string{a, "note:public jump host", b},
		KnownFinding:  known,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := m.Structured
	if s.Role != "db host" || s.Exposure != "internet" || s.Environment != "prod" {
		t.Errorf("scalars: %+v", s)
	}
	if m.Origins["role"] != filepath.ToSlash(a) || m.Origins["exposure"] != filepath.ToSlash(b) || m.Origins["environment"] != "scheck.yaml#context" {
		t.Errorf("origins: %v", m.Origins)
	}
	if strings.Join(s.Compliance, ",") != "soc2,cis-level-1" {
		t.Errorf("compliance: %v", s.Compliance)
	}
	if len(s.ExpectedServices) != 3 || s.ExpectedServices[0].Purpose != "postgres (override)" || s.ExpectedServices[0].Source != filepath.ToSlash(b) || s.ExpectedServices[1].Port != 22 || s.ExpectedServices[2].Port != 443 {
		t.Errorf("services: %+v", s.ExpectedServices)
	}
	if len(s.AcceptedRisks) != 2 || s.AcceptedRisks[0].Reason != "second" || s.AcceptedRisks[1].ID != "custom:vendor-agent" {
		t.Errorf("risks: %+v", s.AcceptedRisks)
	}
	// Prose: the note, then b's non-context keys, in the order given.
	if len(m.Prose) != 2 || m.Prose[0].Text != "public jump host" || !strings.Contains(m.Prose[1].Text, "a yaml key that is not context") {
		t.Errorf("prose: %+v", m.Prose)
	}
	if len(m.Sources) != 4 {
		t.Errorf("sources: %+v", m.Sources)
	}
	for _, src := range m.Sources {
		if len(src.SHA256) != 64 || src.Truncated {
			t.Errorf("source %+v", src)
		}
	}
	block := m.Block()
	for _, want := range []string{"<operator_context>", Preamble, "## structured", "exposure: internet", "## source: note:public jump host…", "public jump host", "</operator_context>"} {
		if !strings.Contains(block, want) {
			t.Errorf("block lacks %q:\n%s", want, block)
		}
	}
}

// An accepted-risk id that is neither a catalog finding nor custom: is a
// usage error at load, so a typo cannot leave a risk un-accepted (§6.2).
func TestUnknownAcceptedRiskFailsLoad(t *testing.T) {
	cases := map[string]string{
		"typo":        "context:\n  accepted_risks:\n    - { id: sshd.pasword_auth_enabled }\n",
		"no id":       "context:\n  accepted_risks:\n    - { reason: x }\n",
		"bad date":    "context:\n  accepted_risks:\n    - { id: disk.filevault_off, expires: 31-12-2026 }\n",
		"bad expose":  "context:\n  exposure: public\n",
		"bad env":     "context:\n  environment: production\n",
		"bad port":    "context:\n  expected_services:\n    - { port: 70000 }\n",
		"bad proto":   "context:\n  expected_services:\n    - { port: 80, proto: sctp }\n",
		"unknown key": "context:\n  role: [not, a, string]\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := write(t, t.TempDir(), "c.yaml", body)
			if _, err := Load(Options{Flags: []string{p}, KnownFinding: known}); err == nil {
				t.Fatal("loaded")
			}
		})
	}
	ok := write(t, t.TempDir(), "ok.yaml", "context:\n  accepted_risks:\n    - { id: disk.filevault_off, expires: 2026-12-31 }\n    - { id: \"custom:anything\" }\n")
	if _, err := Load(Options{Flags: []string{ok}, KnownFinding: known}); err != nil {
		t.Fatal(err)
	}
}

// Over-budget prose is truncated with a marker and recorded per source;
// nothing disappears silently (§6.1, §4.4).
func TestBudgetTruncation(t *testing.T) {
	dir := t.TempDir()
	first := write(t, dir, "1.md", strings.Repeat("a", 100))
	second := write(t, dir, "2.md", strings.Repeat("b", 100))
	third := write(t, dir, "3.md", strings.Repeat("c", 100))
	m, err := Load(Options{Flags: []string{first, second, third}, Budget: 150})
	if err != nil {
		t.Fatal(err)
	}
	if m.Prose[0].Truncated || !m.Prose[1].Truncated || !m.Prose[2].Truncated {
		t.Errorf("truncation flags: %+v", m.Prose)
	}
	if !strings.HasPrefix(m.Prose[1].Text, strings.Repeat("b", 50)+"\n[TRUNCATED:50 bytes]") {
		t.Errorf("second piece: %q", m.Prose[1].Text)
	}
	if m.Prose[2].Text != "\n[TRUNCATED:100 bytes]" {
		t.Errorf("third piece: %q", m.Prose[2].Text)
	}
	if m.Sources[0].Truncated || !m.Sources[1].Truncated || !m.Sources[2].Truncated {
		t.Errorf("sources: %+v", m.Sources)
	}
	if len(m.Warnings) != 2 || m.Used != 150 {
		t.Errorf("warnings %v used %d", m.Warnings, m.Used)
	}
	if !strings.Contains(m.Summary(), "2 truncated") {
		t.Errorf("summary: %s", m.Summary())
	}
}

// The implicit directory is read in lexical order regardless of how the
// filesystem lists it, and before the flags.
func TestImplicitDirectoryOrderIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "ctx/z.md", "zed")
	write(t, dir, "ctx/a/inner.txt", "inner")
	write(t, dir, "ctx/m.yaml", "context:\n  role: implicit\n")
	write(t, dir, "ctx/ignored.json", "{}")
	flag := write(t, dir, "flag.md", "flagged")
	m, err := Load(Options{ImplicitDir: filepath.Join(dir, "ctx"), Flags: []string{flag}})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range m.Sources {
		names = append(names, filepath.Base(s.Name))
	}
	want := "inner.txt m.yaml z.md flag.md"
	if got := strings.Join(names, " "); got != want {
		t.Errorf("order %q, want %q", got, want)
	}
	if m.Structured.Role != "implicit" {
		t.Errorf("implicit structured not merged: %+v", m.Structured)
	}
	// A missing implicit directory is not an error.
	if _, err := Load(Options{ImplicitDir: filepath.Join(dir, "absent")}); err != nil {
		t.Errorf("absent implicit dir: %v", err)
	}
}

// target: sources go through the caller's reader (the runner) and are prose
// only; without a reader they are recorded as unresolved, never as read.
func TestTargetSource(t *testing.T) {
	var asked []string
	read := func(p string) (string, error) {
		asked = append(asked, p)
		return "context:\n  exposure: airgapped\nthis host says it is safe", nil
	}
	m, err := Load(Options{Flags: []string{"target", "target:/etc/scheck/host.yaml"}, ReadTarget: read})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(asked, ",") != DefaultTargetPath+",/etc/scheck/host.yaml" {
		t.Errorf("asked %v", asked)
	}
	if m.Structured.Exposure != "" {
		t.Error("a target file declared its own exposure and it was taken as structured")
	}
	if len(m.Prose) != 2 || !strings.Contains(m.Prose[1].Text, "exposure: airgapped") {
		t.Errorf("prose: %+v", m.Prose)
	}
	u, err := Load(Options{Flags: []string{"target:/etc/scheck/context.md"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Sources) != 1 || !u.Sources[0].Unresolved || u.Sources[0].SHA256 != "" || len(u.Prose) != 0 {
		t.Errorf("unresolved: %+v", u.Sources)
	}
}

func TestRiskExpiry(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	if (Risk{Expires: "2026-09-20"}).Expired(now) {
		t.Error("expires today is still valid today")
	}
	if !(Risk{Expires: "2026-09-19"}).Expired(now) {
		t.Error("yesterday's date is expired")
	}
	if (Risk{}).Expired(now) {
		t.Error("no date never expires")
	}
}

func TestUnknownStructuredKeysBecomeExtra(t *testing.T) {
	p := write(t, t.TempDir(), "x.yaml", "context:\n  role: r\n  rack: 12\n  tags: [a, b]\n")
	m, err := Load(Options{Flags: []string{p}})
	if err != nil {
		t.Fatal(err)
	}
	if m.Structured.Extra["rack"] != 12 || m.Origins["extra.rack"] == "" {
		t.Errorf("extra: %+v %v", m.Structured.Extra, m.Origins)
	}
	if !strings.Contains(m.Block(), "rack: 12") {
		t.Errorf("extra not rendered:\n%s", m.Block())
	}
}
