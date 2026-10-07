package report

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/check"
	_ "github.com/b87/scheck/internal/check/all"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/runner"
	"github.com/b87/scheck/internal/target/fixture"
)

// Acceptance criterion 6, end to end: a seeded secret in check output never
// reaches the fact sheet, the JSON report, the audit log or the persisted
// evidence file, and every one of them carries the redaction marker instead.
func TestSeededSecretNeverPersists(t *testing.T) {
	const secret = "AKIAIOSFODNN7EXAMPLE"
	fx := fixture.New(check.Linux,
		fixture.Exec{Argv: []string{"uname", "-a"}, Stdout: "Linux box 6.8 key=" + secret + " x\n"},
		fixture.Exec{Argv: []string{"cat", "/etc/machine-id"}, Stdout: "0123456789abcdef0123456789abcdef\n"},
		fixture.Exec{Argv: []string{"uname", "-n"}, Stdout: "box\n"},
	)
	var audit bytes.Buffer
	red, _ := policy.NewRedactor(nil)
	r := &runner.Runner{Target: fx, Paths: policy.NewPathPolicy(nil), Redactor: red, Budgets: policy.DefaultBudgets(),
		Audit: policy.NewAudit(&audit), Elevate: runner.ElevateNone}
	sheet := baseline.Run(context.Background(), r, baseline.Plan(check.Linux, nil), nil)
	env := Build(sheet, Meta{Started: time.Now(), Transport: "fixture", Canary: "n/a", Elevation: "none", Profile: "baseline", Version: "test"})
	persisted := evidenceFile(t, env)
	var text, verbose, js bytes.Buffer
	_ = WriteFactSheet(&text, env, Options{})
	// Verbose text exposes check output (docs/spec/host-collector.md §6.6); it must show
	// the marker, not the key. Opt-in JSON evidence is covered below.
	_ = WriteFactSheet(&verbose, env, Options{Verbose: 2, Width: 200})
	_ = WriteJSON(&js, env)
	outputs := map[string]string{
		"text":      text.String(),
		"text -vv":  verbose.String(),
		"json":      js.String(),
		"audit":     audit.String(),
		"persisted": persisted,
	}
	for name, out := range outputs {
		if strings.Contains(out, secret) {
			t.Errorf("%s: secret present", name)
		}
		if name != "audit" && !strings.Contains(out, "[REDACTED:aws-access-key:20 bytes]") {
			t.Errorf("%s: marker missing", name)
		}
	}
	// -vv shows strictly more of the same redacted bytes, never a second
	// copy of the capture from before the redactor ran.
	if !strings.Contains(outputs["text -vv"], "| Linux box 6.8 key=[REDACTED:aws-access-key:20 bytes] x") {
		t.Errorf("-vv did not render the redacted output:\n%s", outputs["text -vv"])
	}
}

// Failed checks retain only policy-filtered diagnostics. Opt-in JSON evidence
// must never introduce raw captures into persisted runs (docs/spec/host-collector.md §4.2, §6.4).
func TestFailedDiagnosticsRedactedAndNotPersisted(t *testing.T) {
	const secret = "AKIAIOSFODNN7EXAMPLE"
	fx := fixture.New(check.Linux, fixture.Exec{Argv: []string{"uname", "-a"}, Stdout: "failure key=" + secret, Stderr: "error key=" + secret, Code: 1})
	red, _ := policy.NewRedactor(nil)
	r := &runner.Runner{Target: fx, Paths: policy.NewPathPolicy(nil), Redactor: red, Budgets: policy.DefaultBudgets()}
	res := r.Run(context.Background(), "sys.uname", nil)
	env := Build(&baseline.FactSheet{Platform: check.Linux, Results: map[string]runner.Result{"sys.uname": res}}, Meta{Started: time.Now(), Transport: "fixture", Profile: "baseline", Elevation: "none", Canary: "n/a"})
	var verbose, js, compact bytes.Buffer
	if err := WriteFactSheet(&verbose, env, Options{Verbose: 2, Width: 200}); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSONEvidence(&js, env, true); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&compact, env); err != nil {
		t.Fatal(err)
	}
	persisted := evidenceFile(t, env)
	for name, out := range map[string]string{"verbose": verbose.String(), "evidence": js.String(), "compact": compact.String(), "persisted": persisted} {
		if strings.Contains(out, secret) {
			t.Fatalf("%s leaked a secret", name)
		}
		if !strings.Contains(out, "[REDACTED:aws-access-key:20 bytes]") {
			t.Fatalf("%s missing marker", name)
		}
	}
	for _, out := range []string{compact.String(), persisted} {
		if strings.Contains(out, `"evidence"`) {
			t.Fatal("optional capture persisted")
		}
	}
	if !strings.Contains(verbose.String(), "| failure key=[REDACTED:") || !strings.Contains(js.String(), `"stdout": "failure key=[REDACTED:`) {
		t.Fatal("failed stdout not available")
	}
}

// A posture rule's evidence excerpt is target text like any other: it comes
// from the runner's already-redacted capture, so a secret in a matching line
// cannot reach the finding, the report or the persisted run (docs/spec/host-collector.md §4.2, §6.5).
func TestFindingEvidenceIsRedacted(t *testing.T) {
	const secret = "AKIAIOSFODNN7EXAMPLE"
	fx := fixture.New(check.Linux,
		fixture.Exec{Argv: []string{"find", "/usr/local", "/opt", "/etc", "-xdev", "-maxdepth", "4",
			"-perm", "-0002", "-not", "-perm", "-1000", "-not", "-type", "l"},
			Stdout: "/opt/backup-" + secret + "/dump\n"},
	)
	red, _ := policy.NewRedactor(nil)
	r := &runner.Runner{Target: fx, Paths: policy.NewPathPolicy(nil), Redactor: red, Budgets: policy.DefaultBudgets()}
	res := r.Run(context.Background(), "fs.world_writable", nil)
	env := Build(&baseline.FactSheet{Platform: check.Linux, Results: map[string]runner.Result{"fs.world_writable": res}},
		Meta{Started: time.Now(), Transport: "fixture", Profile: "baseline", Elevation: "none", Canary: "n/a"})
	if len(env.Findings) != 1 {
		t.Fatalf("want the world-writable finding, got %+v", env.Findings)
	}
	excerpt := env.Findings[0].Evidence[0].Excerpt
	if strings.Contains(excerpt, secret) || !strings.Contains(excerpt, "[REDACTED:aws-access-key:20 bytes]") {
		t.Fatalf("finding evidence is not redacted: %q", excerpt)
	}
	var text, js bytes.Buffer
	_ = WriteFactSheet(&text, env, Options{Verbose: 2, Width: 200})
	_ = WriteJSON(&js, env)
	persisted := evidenceFile(t, env)
	for name, out := range map[string]string{"text": text.String(), "json": js.String(), "persisted": persisted} {
		if strings.Contains(out, secret) {
			t.Fatalf("%s leaked a secret through a finding", name)
		}
		if !strings.Contains(out, "[REDACTED:aws-access-key:20 bytes]") {
			t.Fatalf("%s lost the marker", name)
		}
	}
}

// evidenceFile is the envelope as the engagement persists it under
// evidence/<asset>.json: the run directory's own JSON encoding of the
// struct, not this package's renderer, so it is a separate path to check.
func evidenceFile(t *testing.T, env Envelope) string {
	t.Helper()
	raw, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
