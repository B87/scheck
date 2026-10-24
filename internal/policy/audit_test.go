package policy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// A host reached through a jump host has every audit line name the hop,
// and a direct host none (docs/ROADMAP.md, E1c).
func TestAuditNamesTheJumpHost(t *testing.T) {
	var buf bytes.Buffer
	a := NewAudit(&buf)
	if err := a.Log(AuditEntry{CheckID: "sys.canary", Decision: "run"}); err != nil {
		t.Fatal(err)
	}
	a.SetVia("ops@198.51.100.7:22")
	for _, id := range []string{"sys.canary", "sys.uname"} {
		if err := a.Log(AuditEntry{CheckID: id, Decision: "run"}); err != nil {
			t.Fatal(err)
		}
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	for i, want := range []string{"", "ops@198.51.100.7:22", "ops@198.51.100.7:22"} {
		var e AuditEntry
		if err := json.Unmarshal([]byte(lines[i]), &e); err != nil {
			t.Fatal(err)
		}
		if e.Via != want {
			t.Errorf("line %d: via %q, want %q", i, e.Via, want)
		}
	}
	var nilAudit *Audit
	nilAudit.SetVia("ops@198.51.100.7:22") // a nil log discards, and does not panic
}
