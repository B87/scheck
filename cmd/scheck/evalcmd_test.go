package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// No model assesses a host in this build (docs/SPEC.md §2.1): every flag
// that selects one is a usage error on local and ssh, with nothing
// executed and no report written. The same settings in a configuration
// file are simply unused, since a run never builds a provider.
func TestModelFlagsAreRejectedByLocalAndSSH(t *testing.T) {
	dir := t.TempDir()
	cases := [][]string{
		{"local", "--provider", "mock"},
		{"local", "--provider", "openai-compatible"},
		{"local", "--model", "gpt-5"},
		{"local", "--base-url", "http://localhost:8000/v1"},
		{"local", "--effort", "high"},
		{"local", "--transcript", filepath.Join("..", "..", "testdata", "transcripts", "correlated-finding-linux.json")},
		{"local", "--max-context", "8192"},
		{"local", "--only", "network", "--stop-after", "facts"},
		{"local", "--local-only", "--stop-after", "facts"},
		{"ssh", "user@host", "--model", "gpt-5"},
		{"ssh", "user@host", "--provider", "mock"},
		// --include-evidence belongs to the fact stage of local and ssh only.
		{"local", "--include-evidence", "--stop-after", "plan", "--format", "json"},
		{"local", "--include-evidence", "--stop-after", "facts"},
		{"catalog", "--include-evidence", "--format", "json"},
	}
	for _, args := range cases {
		out, code := runIn(t, dir, args...)
		if code != exitUsage || out != "" {
			t.Errorf("%v: exit %d, output %q", args, code, out)
		}
	}
	// A configured provider, model and refusal of egress cannot fail a run
	// that never contacts a provider.
	writeFile(t, filepath.Join(dir, "scheck.yaml"), "provider: anthropic\nmodel: gpt-5\nallow_egress: false\n")
	for _, args := range [][]string{{"local", "--stop-after", "plan"}, {"local", "--stop-after", "context"}} {
		if out, code := runIn(t, dir, args...); code != exitOK {
			t.Errorf("%v with model settings configured: exit %d %q", args, code, out)
		}
	}
}

// The evaluation harness is the one caller of phase 2 left, so it owns the
// provider pre-flight: a deferred or unknown adapter, a missing transcript,
// a missing credential and an unknown context window each exit 3 before a
// case runs (docs/SPEC.md §5.2, §5.3).
func TestEvalProviderPreflightExitsThree(t *testing.T) {
	dir := t.TempDir()
	suite := filepath.Join("..", "..", "testdata", "eval")
	t.Setenv("OPENAI_API_KEY", "")
	_ = os.Unsetenv("OPENAI_API_KEY")
	cases := [][]string{
		{"eval", "--suite", suite, "--provider", "anthropic", "--model", "x"},
		{"eval", "--suite", suite, "--provider", "ollama", "--model", "x"},
		{"eval", "--suite", suite, "--provider", "nope", "--model", "x"},
		{"eval", "--suite", suite, "--provider", "mock", "--transcript", filepath.Join(dir, "missing.json")},
		{"eval", "--suite", suite, "--local-only", "--model", "gpt-5"},
		{"eval", "--suite", suite},                           // default luna, no credential
		{"eval", "--suite", suite, "--model", "gpt-5"},       // no credential
		{"eval", "--suite", "nowhere", "--provider", "mock"}, // no suite
	}
	for _, args := range cases {
		out, code := runIn(t, dir, args...)
		if code != exitUsage || out != "" {
			t.Errorf("%v: exit %d, output %q", args, code, out)
		}
	}
	// With a credential the unknown-window guard is what refuses.
	t.Setenv("OPENAI_API_KEY", "sk-test")
	if out, code := runIn(t, dir, "eval", "--suite", suite, "--model", "mystery-7b"); code != exitUsage || out != "" {
		t.Errorf("unknown window: exit %d %q", code, out)
	}
	writeFile(t, filepath.Join(dir, "scheck.yaml"), "allow_egress: false\nmodel: gpt-5\n")
	if out, code := runIn(t, dir, "eval", "--suite", suite); code != exitUsage || out != "" {
		t.Errorf("allow_egress false: exit %d %q", code, out)
	}
}

// `scheck providers` reports adapter readiness for the selected model
// without contacting anything and without printing a credential.
func TestOpenAICompatibleConfiguration(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENAI_API_KEY", "sk-test")
	out, code := runIn(t, dir, "providers", "--model", "gpt-5", "--format", "json")
	if code != exitOK {
		t.Fatalf("providers: exit %d", code)
	}
	var doc struct {
		Providers []providerStatus `json:"providers"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	for _, p := range doc.Providers {
		if p.Name != "openai-compatible" {
			continue
		}
		if p.Status != "ready" || p.Limits == nil || p.Limits.MaxContext != 400000 || p.Native == nil || !p.Native.ToolCalling || p.Native.PromptCaching {
			t.Errorf("openai-compatible: %+v", p)
		}
	}
	if strings.Contains(out, "sk-test") {
		t.Error("credential printed")
	}
	out, code = runIn(t, dir, "providers", "--format", "json")
	if code != exitOK {
		t.Fatalf("providers default model: exit %d", code)
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	for _, p := range doc.Providers {
		if p.Name != "openai-compatible" {
			continue
		}
		if p.Status != "ready" || p.Limits == nil || p.Limits.MaxContext != 1050000 {
			t.Errorf("default luna window: %+v", p)
		}
	}
	out, _ = runIn(t, dir, "providers", "--model", "mystery-7b", "--base-url", "http://localhost:8000/v1", "--max-context", "8192")
	if !strings.Contains(out, "openai-compatible") || !strings.Contains(out, "ready") || !strings.Contains(out, "8192") {
		t.Errorf("declared window not honoured:\n%s", out)
	}
}

// The hidden eval command runs the suite with the mock provider and emits
// the record; it never contacts a live target.
func TestEvalCommandWithMock(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"eval", "--provider", "mock", "--suite", filepath.Join("..", "..", "testdata", "eval"),
		"--corpus", filepath.Join("..", "..", "testdata", "context"), "--repeat", "1", "--format", "json"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	var res struct {
		Live     bool     `json:"live"`
		Provider string   `json:"provider"`
		Notes    []string `json:"notes"`
		Runs     []struct {
			Arm string `json:"arm"`
		} `json:"runs"`
		Pairs []any `json:"pairs"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Live || res.Provider != "mock" || len(res.Notes) == 0 || len(res.Runs) < 45 || len(res.Pairs) != 8 {
		t.Errorf("record: live=%v provider=%s runs=%d pairs=%d", res.Live, res.Provider, len(res.Runs), len(res.Pairs))
	}
	root = newRootCmd()
	out.Reset()
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"eval", "--provider", "mock", "--suite", filepath.Join("..", "..", "testdata", "eval"), "--no-pairs"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "# Phase 2 evaluation") || !strings.Contains(out.String(), "not** a pass or fail") {
		t.Errorf("markdown:\n%s", out.String())
	}
	// --cases narrows the suite and --out receives the record (rewritten
	// after every run); progress lines go to stderr without -v.
	root = newRootCmd()
	out.Reset()
	var errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	record := filepath.Join(t.TempDir(), "record.md")
	root.SetArgs([]string{"eval", "--provider", "mock", "--suite", filepath.Join("..", "..", "testdata", "eval"), "--no-pairs",
		"--cases", "linux-clean", "--out", record})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(record)
	if err != nil || !strings.Contains(string(raw), "| linux-clean |") || strings.Contains(string(raw), "| macos-clean |") || out.Len() != 0 {
		t.Errorf("record: %v stdout=%q\n%s", err, out.String(), raw)
	}
	if !strings.Contains(errOut.String(), "below the frozen minimums") || !strings.Contains(errOut.String(), "unexpected=") {
		t.Errorf("stderr:\n%s", errOut.String())
	}
}
