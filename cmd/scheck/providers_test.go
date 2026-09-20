package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/llm"
)

// `scheck providers` is the smoke test that an adapter registered: every
// registered name appears, with a status, and never a credential value.
func TestProvidersListsEveryRegisteredAdapter(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-should-never-print")
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"providers", "--format", "json"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Kind      string           `json:"kind"`
		Default   string           `json:"default"`
		Providers []providerStatus `json:"providers"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Kind != "providers" || doc.Default != "openai-compatible" {
		t.Fatalf("envelope: %+v", doc)
	}
	seen := map[string]providerStatus{}
	for _, p := range doc.Providers {
		seen[p.Name] = p
	}
	for _, info := range llm.Providers() {
		p, ok := seen[info.Name]
		if !ok {
			t.Errorf("%s not listed", info.Name)
			continue
		}
		if p.Status == "" {
			t.Errorf("%s has no status", info.Name)
		}
		if info.Deferred && p.Status != "unavailable" {
			t.Errorf("deferred %s listed as %s", info.Name, p.Status)
		}
	}
	if strings.Contains(out.String(), "sk-should-never-print") {
		t.Fatal("credential value printed")
	}
}

// With a transcript the mock is ready and reports the limits it declares.
func TestProvidersReportsMockLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.json")
	if err := os.WriteFile(path, []byte(`{"limits":{"max_context":9000},"native":{"tool_calling":true},"turns":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"providers", "--transcript", path})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "mock") || !strings.Contains(out.String(), "9000") || !strings.Contains(out.String(), "ready") {
		t.Fatalf("mock not ready with its limits:\n%s", out.String())
	}
}
