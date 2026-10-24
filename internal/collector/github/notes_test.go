package github

import (
	"strings"
	"testing"
)

func TestUnavailableReadNotesHaveDetail(t *testing.T) {
	for _, op := range []string{OpDependabotAlerts, OpRepositorySecrets, OpPrincipal} {
		notes := ReadNotes(Read{Op: op, Reason: "insufficient_permission"})
		if len(notes) != 1 || !strings.Contains(notes[0].Detail, "Read unavailable") || strings.Contains(notes[0].Detail, ": .") {
			t.Fatalf("%s: %+v", op, notes)
		}
	}
	notes := ReadNotes(Read{Op: OpDependabotAlerts, Reason: "insufficient_permission", Detail: "SSO authorization required"})
	if len(notes) != 1 || !strings.Contains(notes[0].Detail, "SSO authorization required") || !strings.Contains(notes[0].Detail, "feature availability") {
		t.Fatal(notes)
	}
}
