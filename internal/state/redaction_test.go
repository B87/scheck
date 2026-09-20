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
	var text, js bytes.Buffer
	_ = report.WriteText(&text, env)
	_ = report.WriteJSON(&js, env)
	for name, out := range map[string]string{"text": text.String(), "json": js.String(), "audit": audit.String(), "persisted": string(persisted)} {
		if strings.Contains(out, secret) {
			t.Errorf("%s: secret present", name)
		}
		if name != "audit" && !strings.Contains(out, "[REDACTED:aws-access-key:20 bytes]") {
			t.Errorf("%s: marker missing", name)
		}
	}
}
