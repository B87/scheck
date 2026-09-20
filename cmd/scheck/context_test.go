package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/config"
	"github.com/b87/scheck/internal/operator"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/runner"
	"github.com/b87/scheck/internal/target/fixture"
)

// contextSession is a session over a fixture target with an in-memory audit
// log, so a target: context source can be watched going through the runner.
func contextSession(t *testing.T, fx *fixture.Target, flags ...string) (*session, *bytes.Buffer) {
	t.Helper()
	var audit bytes.Buffer
	red, _ := policy.NewRedactor(nil)
	b := policy.DefaultBudgets()
	r := &runner.Runner{Target: fx, Paths: policy.NewPathPolicy(nil), Redactor: red, Budgets: b, Audit: policy.NewAudit(&audit)}
	return &session{
		opts:    &globalOpts{Format: "json", NoPersist: true, Context: flags},
		cfg:     &config.Config{},
		budgets: b, runner: r, started: time.Now(), elevate: runner.ElevateNone,
	}, &audit
}

// A target: source is read as the text.cat catalog binding through the
// runner: it is in the audit log like any other check, under the path
// policy, and never a second read path (docs/SPEC.md §6.1).
func TestTargetContextIsAnOrdinaryCatalogBinding(t *testing.T) {
	fx := fixture.New(check.Linux,
		fixture.Exec{Argv: []string{"realpath", "/etc/scheck/context.md"}, Stdout: "/etc/scheck/context.md\n"},
		fixture.Exec{Argv: []string{"cat", "/etc/scheck/context.md"}, Stdout: "this host is the public jump host\n"},
		fixture.Exec{Argv: []string{"realpath", "/etc/shadow"}, Stdout: "/etc/shadow\n"},
	)
	sess, audit := contextSession(t, fx, "target", "target:/etc/shadow", "target:/root/notes.md")
	err := sess.loadContext(context.Background())
	if err == nil {
		t.Fatal("a denied target path loaded")
	}
	if got := exitCodeOf(err); got != exitUsage {
		t.Fatalf("exit %d, want 3", got)
	}
	lines := strings.Split(strings.TrimSpace(audit.String()), "\n")
	var sawCat, sawShadow bool
	for _, l := range lines {
		var e policy.AuditEntry
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatal(err)
		}
		if e.CheckID == "text.cat" && e.Decision == "run" && e.Params["path"] == "/etc/scheck/context.md" {
			sawCat = true
		}
		if e.CheckID == "fs.stat" || (e.CheckID == "text.cat" && strings.HasPrefix(e.Decision, "denied")) || strings.Contains(e.Decision, "metadata") {
			sawShadow = true
		}
	}
	if !sawCat {
		t.Errorf("target context read is not audited as text.cat:\n%s", audit.String())
	}
	if !sawShadow {
		t.Errorf("sensitive target path was not routed through the policy:\n%s", audit.String())
	}
	// The happy path: only the default target file.
	sess, _ = contextSession(t, fx, "target")
	if err := sess.loadContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sess.context.Prose) != 1 || !strings.Contains(sess.context.Prose[0].Text, "public jump host") || sess.context.Sources[0].Name != "target:/etc/scheck/context.md" {
		t.Errorf("target prose: %+v", sess.context)
	}
}

// The facts report carries run.context_sources with a hash per source, a
// truncated flag when the budget cut a source, and the warning.
func TestFactsReportRecordsContextSources(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.md")
	if err := os.WriteFile(big, bytes.Repeat([]byte("x"), 2000), 0o600); err != nil {
		t.Fatal(err)
	}
	sess, _ := contextSession(t, fixture.New(check.Linux), "note:public jump host", big)
	sess.budgets.ContextBytes = 100
	if err := sess.loadContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := reportAndExit(sess, &out, postureSheet(t, map[string]string{"sshd.config": "passwordauthentication no"})); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		SchemaVersion string `json:"schema_version"`
		Run           struct {
			ContextSources []operator.Source `json:"context_sources"`
			Warnings       []string          `json:"warnings"`
		} `json:"run"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != "1.6" || len(doc.Run.ContextSources) != 2 {
		t.Fatalf("envelope: %+v", doc)
	}
	note, file := doc.Run.ContextSources[0], doc.Run.ContextSources[1]
	if note.Kind != "note" || len(note.SHA256) != 64 || note.Truncated {
		t.Errorf("note source: %+v", note)
	}
	if file.Kind != "file" || !file.Truncated || file.Bytes != 2000 {
		t.Errorf("file source: %+v", file)
	}
	if len(doc.Run.Warnings) == 0 || !strings.Contains(doc.Run.Warnings[0], "truncated") {
		t.Errorf("warnings: %v", doc.Run.Warnings)
	}
}

// --stop-after context prints the merged block with per-source headings and
// the budget line; --ignore-context reads nothing.
func TestStopAfterContextPrintsMergedBlock(t *testing.T) {
	dir := t.TempDir()
	arch := filepath.Join(dir, "arch.md")
	if err := os.WriteFile(arch, []byte("# Architecture\nnginx fronts the API.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctxYAML := filepath.Join(dir, "host.yaml")
	if err := os.WriteFile(ctxYAML, []byte("context:\n  exposure: internet\n  accepted_risks:\n    - { id: sshd.password_auth_enabled, reason: \"bastion MFA\" }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sess, _ := contextSession(t, fixture.New(check.Linux), "note:public jump host", arch, ctxYAML)
	sess.opts.Format = "text"
	if err := sess.loadContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := writeContext(&out, sess.context, "text"); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"<operator_context>", "## structured", "exposure: internet", "## source: note:public jump host", "## source: " + filepath.ToSlash(arch), "nginx fronts the API.", "context: 3 sources", "of " + itoa(sess.budgets.ContextBytes) + " budget", "sha256"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q:\n%s", want, text)
		}
	}
	ignored, _ := contextSession(t, fixture.New(check.Linux), arch)
	ignored.opts.IgnoreCtx = true
	if err := ignored.loadContext(context.Background()); err != nil || ignored.context != nil {
		t.Errorf("--ignore-context: %v %+v", err, ignored.context)
	}
}

// An unknown accepted-risk id exits 3 whether it comes from a --context
// file or from scheck.yaml (docs/SPEC.md §6.2).
func TestUnknownAcceptedRiskExitsThree(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("context:\n  accepted_risks:\n    - { id: sshd.pasword_auth, reason: typo }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sess, _ := contextSession(t, fixture.New(check.Linux), bad)
	if got := exitCodeOf(sess.loadContext(context.Background())); got != exitUsage {
		t.Fatalf("--context: exit %d, want 3", got)
	}
	cfgFile := filepath.Join(dir, "scheck.yaml")
	if err := os.WriteFile(cfgFile, []byte("context:\n  accepted_risks:\n    - { id: not.a.finding }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFiles(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "not.a.finding") {
		t.Fatalf("config validation: %v", err)
	}
}

func itoa(n int) string { return fmt.Sprint(n) }
