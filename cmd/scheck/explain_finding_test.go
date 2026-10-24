package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/finding"
)

// scheck explain FINDING-ID prints the chain and honours the docs/spec/host-collector.md §5.2 keys as
// flags (docs/spec/host-collector.md §7).
func TestExplainFinding(t *testing.T) {
	run := func(args ...string) (string, int) {
		root := newRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&bytes.Buffer{})
		root.SetArgs(append([]string{"explain"}, args...))
		code := exitCodeOf(root.Execute())
		return out.String(), code
	}
	out, code := run("sshd.password_auth_enabled", "--exposure", "internet")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"base", "medium", "adjustment", "medium → high", "exposure:internet", "final", "high"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	out, _ = run("sshd.password_auth_enabled", "--accepted", "--format", "json")
	var doc struct {
		Kind   string         `json:"kind"`
		Status string         `json:"status"`
		Chain  []finding.Step `json:"chain"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Kind != "finding" || doc.Status != "accepted" || doc.Chain[0].Stage != "base" || doc.Chain[len(doc.Chain)-1].Stage != "final" {
		t.Errorf("json: %+v", doc)
	}
	if _, code := run("sshd.password_auth_enabled", "--exposure", "public"); code != exitUsage {
		t.Errorf("bad exposure exit %d", code)
	}
	if _, code := run("no.such_id"); code != exitUsage {
		t.Errorf("unknown id exit %d", code)
	}
	// A check id still explains the check.
	if out, code := run("sshd.config"); code != exitOK || !strings.Contains(out, "sshd -T") {
		t.Errorf("check explain broke: %d\n%s", code, out)
	}
}
