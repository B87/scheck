package state

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/check"
	_ "github.com/b87/scheck/internal/check/all"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/report"
	"github.com/b87/scheck/internal/runner"
	"github.com/b87/scheck/internal/target/fixture"
)

// Acceptance criterion 6, end to end: a seeded secret in check output never
// reaches the text report, the JSON report, the audit log or the persisted
// run, and every one of them carries the redaction marker instead.
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
	env := report.Build(sheet, report.Meta{Started: time.Now(), Transport: "fixture", Canary: "n/a", Elevation: "none", Profile: "baseline", Version: "test"})
	path, err := Write(t.TempDir(), &env)
	if err != nil {
		t.Fatal(err)
	}
	persisted, _ := os.ReadFile(path)
	var text, verbose, js bytes.Buffer
	_ = report.WriteText(&text, env, report.Options{})
	// Verbose text exposes check output (docs/SPEC.md §7.6); it must show
	// the marker, not the key. Opt-in JSON evidence is covered below.
	_ = report.WriteText(&verbose, env, report.Options{Verbose: 2, Width: 200})
	_ = report.WriteJSON(&js, env)
	outputs := map[string]string{
		"text":      text.String(),
		"text -vv":  verbose.String(),
		"json":      js.String(),
		"audit":     audit.String(),
		"persisted": string(persisted),
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
// must never introduce raw captures into persisted runs (SPEC §4.2, §7.4).
func TestFailedDiagnosticsRedactedAndNotPersisted(t *testing.T) {
	const secret = "AKIAIOSFODNN7EXAMPLE"
	fx := fixture.New(check.Linux, fixture.Exec{Argv: []string{"uname", "-a"}, Stdout: "failure key=" + secret, Stderr: "error key=" + secret, Code: 1})
	red, _ := policy.NewRedactor(nil)
	r := &runner.Runner{Target: fx, Paths: policy.NewPathPolicy(nil), Redactor: red, Budgets: policy.DefaultBudgets()}
	res := r.Run(context.Background(), "sys.uname", nil)
	env := report.Build(&baseline.FactSheet{Platform: check.Linux, Results: map[string]runner.Result{"sys.uname": res}}, report.Meta{Started: time.Now(), Transport: "fixture", Profile: "baseline", Elevation: "none", Canary: "n/a"})
	var verbose, js, compact bytes.Buffer
	if err := report.WriteText(&verbose, env, report.Options{Verbose: 2, Width: 200}); err != nil {
		t.Fatal(err)
	}
	if err := report.WriteJSONEvidence(&js, env, true); err != nil {
		t.Fatal(err)
	}
	if err := report.WriteJSON(&compact, env); err != nil {
		t.Fatal(err)
	}
	path, err := Write(t.TempDir(), &env)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"verbose": verbose.String(), "evidence": js.String(), "compact": compact.String(), "persisted": string(persisted)} {
		if strings.Contains(out, secret) {
			t.Fatalf("%s leaked a secret", name)
		}
		if !strings.Contains(out, "[REDACTED:aws-access-key:20 bytes]") {
			t.Fatalf("%s missing marker", name)
		}
	}
	for _, out := range []string{compact.String(), string(persisted)} {
		if strings.Contains(out, `"evidence"`) {
			t.Fatal("optional capture persisted")
		}
	}
	if !strings.Contains(verbose.String(), "| failure key=[REDACTED:") || !strings.Contains(js.String(), `"stdout": "failure key=[REDACTED:`) {
		t.Fatal("failed stdout not available")
	}
}
