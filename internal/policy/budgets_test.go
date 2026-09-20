package policy

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestDefaultBudgetsValid(t *testing.T) {
	if err := DefaultBudgets().Validate(); err != nil {
		t.Fatal(err)
	}
	if DefaultBudgets().CaptureLimit() <= DefaultBudgets().PerCheckOutput {
		t.Error("capture limit must exceed output cap")
	}
	b := DefaultBudgets()
	b.PerCheckSoft = time.Minute
	if b.Validate() == nil {
		t.Error("soft > hard accepted")
	}
}

func TestAuditNilAndJSONL(t *testing.T) {
	var nilAudit *Audit
	if err := nilAudit.Log(AuditEntry{CheckID: "x"}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	a := NewAudit(&buf)
	code := 0
	if err := a.Log(AuditEntry{CheckID: "sys.uname", Argv: []string{"uname", "-a"}, Decision: "run", ExitCode: &code}); err != nil {
		t.Fatal(err)
	}
	if err := a.Log(AuditEntry{CheckID: "text.cat", Decision: "denied:path.not_allowed"}); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %s", len(lines), buf.String())
	}
	var e AuditEntry
	if err := json.Unmarshal(lines[1], &e); err != nil || e.Decision != "denied:path.not_allowed" || e.Time.IsZero() {
		t.Errorf("bad entry: %+v %v", e, err)
	}
}
