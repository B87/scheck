package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/target/fixture"
)

const gatewayContext = "context:\n  exposure: internet\n  expected_services:\n    - { port: 22, purpose: ssh }\n    - { port: 8443, purpose: \"admin ui\" }\n  accepted_risks:\n    - { id: sshd.root_login_enabled, reason: \"jump host, keys only\", expires: 2099-01-01 }\n    - { id: time.ntp_unsynced, reason: \"stale\", expires: 2020-01-01 }\n"

func gradedRun(t *testing.T, ignore bool, flags ...string) (string, int) {
	t.Helper()
	sess, _ := contextSession(t, fixture.New(check.Linux), flags...)
	sess.opts.IgnoreCtx = ignore
	if err := sess.loadContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := reportAndExit(sess, &out, postureSheet(t, map[string]string{
		"sshd.config":      "passwordauthentication yes\npermitrootlogin yes\n",
		"time.timedatectl": "NTPSynchronized=no\n",
		"net.listeners":    "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n",
	}))
	return out.String(), exitCodeOf(err)
}

type gradedDoc struct {
	Findings    []finding.Finding    `json:"findings"`
	Assessments []finding.Assessment `json:"assessments"`
}

// The M2.3 demo: one finding escalated by exposure: internet, one accepted
// and excluded from the exit code, an expired acceptance that does not
// suppress its finding and is a finding of its own, and a declared service
// that is not listening (acceptance criterion 9, deterministic half).
func TestContextGradesTheFactsReport(t *testing.T) {
	dir := t.TempDir()
	ctxFile := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(ctxFile, []byte(gatewayContext), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := gradedRun(t, false, ctxFile)
	var doc gradedDoc
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	byID := map[string]finding.Finding{}
	for _, f := range doc.Findings {
		byID[f.ID] = f
	}
	pw := byID[finding.IDPasswordAuthEnabled]
	if pw.Severity != finding.SevHigh || pw.SeverityBase != finding.SevMedium || len(pw.Adjustments) != 1 || pw.Adjustments[0].Rule != "exposure:internet" || !strings.HasSuffix(pw.Adjustments[0].Source, "gateway.yaml#context.exposure") {
		t.Errorf("escalation: %+v", pw)
	}
	root := byID[finding.IDRootLoginEnabled]
	if root.Status != finding.StatusAccepted || root.AcceptedReason != "jump host, keys only" || root.Severity != finding.SevCritical {
		t.Errorf("accepted: %+v", root)
	}
	ntp := byID[finding.IDNTPUnsynced]
	if ntp.Status != finding.StatusOpen {
		t.Errorf("expired acceptance suppressed: %+v", ntp)
	}
	if exp, ok := byID[finding.IDAcceptanceExpired]; !ok || !strings.Contains(exp.Evidence[0].Excerpt, "time.ntp_unsynced") {
		t.Errorf("risk.acceptance_expired: %+v", exp)
	}
	if miss, ok := byID[finding.IDExpectedMissing]; !ok || !strings.Contains(miss.Evidence[0].Excerpt, "8443/tcp") {
		t.Errorf("svc.expected_missing: %+v", miss)
	}
	if code != exitFindings {
		t.Errorf("exit %d", code)
	}
	// Only open findings count: the accepted critical does not; the two
	// escalated network/remote-access findings do.
	if n := finding.OpenAtOrAbove(doc.Findings, finding.SevHigh); n != 2 {
		t.Errorf("%d open findings at high+, want 2 (the accepted one is excluded)", n)
	}
	// Text renders the acceptance and the attribution.
	sess, _ := contextSession(t, fixture.New(check.Linux), ctxFile)
	sess.opts.Format, sess.opts.Verbose = "text", 1
	_ = sess.loadContext(context.Background())
	var text bytes.Buffer
	_ = reportAndExit(sess, &text, postureSheet(t, map[string]string{"sshd.config": "passwordauthentication yes\npermitrootlogin yes\n"}))
	for _, want := range []string{"[accepted]", "jump host, keys only", "excluded from the exit code", "base medium → high", "exposure:internet (+1, from", "1 accepted"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text lacks %q:\n%s", want, text.String())
		}
	}
}

// --ignore-context reproduces base severities byte-for-byte: the findings
// of an ignoring run equal those of a run with no context at all (§6.4).
func TestIgnoreContextReproducesBaseSeverity(t *testing.T) {
	dir := t.TempDir()
	ctxFile := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(ctxFile, []byte(gatewayContext), 0o600); err != nil {
		t.Fatal(err)
	}
	ignored, _ := gradedRun(t, true, ctxFile)
	none, _ := gradedRun(t, false)
	with, _ := gradedRun(t, false, ctxFile)
	findingsOf := func(raw string) string {
		var doc struct {
			Findings json.RawMessage `json:"findings"`
		}
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			t.Fatal(err)
		}
		return string(doc.Findings)
	}
	if findingsOf(ignored) != findingsOf(none) {
		t.Errorf("--ignore-context differs from no context:\n%s\n---\n%s", findingsOf(ignored), findingsOf(none))
	}
	if findingsOf(with) == findingsOf(none) {
		t.Error("context did not change the report")
	}
	var baseDoc gradedDoc
	if err := json.Unmarshal([]byte(none), &baseDoc); err != nil {
		t.Fatal(err)
	}
	for _, f := range baseDoc.Findings {
		if f.Severity != f.SeverityBase || len(f.Adjustments) != 0 || f.Status != finding.StatusOpen {
			t.Errorf("base run is adjusted: %+v", f)
		}
	}
}

// scheck explain FINDING-ID prints the chain and honours the §6.2 keys as
// flags (docs/SPEC.md §8).
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
