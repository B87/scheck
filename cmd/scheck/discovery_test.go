package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/config"
	"github.com/b87/scheck/internal/runner"
	"github.com/b87/scheck/internal/target/fixture"
	"github.com/spf13/cobra"
)

func TestDiscoveryJSON(t *testing.T) {
	for _, args := range [][]string{{"catalog", "--platform", "linux"}, {"explain", "fs.stat"}} {
		t.Run(args[0], func(t *testing.T) {
			root := newRootCmd()
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetArgs(append(args, "--format", "json"))
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Kind   string             `json:"kind"`
				Checks []checkDescription `json:"checks"`
			}
			if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
				t.Fatal(err)
			}
			if doc.Kind != args[0] || len(doc.Checks) == 0 {
				t.Fatalf("bad discovery: %+v", doc)
			}
			for _, c := range doc.Checks {
				original, ok := check.Lookup(c.ID, c.Platform)
				if !ok || !reflect.DeepEqual(c.Argv, original.Argv) || c.Params == nil {
					t.Fatalf("lost catalog structure: %+v", c)
				}
			}
		})
	}
}

func TestDiscoveryOutputFile(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	path := filepath.Join(t.TempDir(), "explain.json")
	root.SetArgs([]string{"explain", "sshd.config", "--format", "json", "--out", path})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 || !json.Valid(b) {
		t.Fatalf("invalid output routing: %s / %s", out.String(), b)
	}
}

func TestPlanJSONDoesNotExecute(t *testing.T) {
	fx := fixture.New(check.Linux)
	sess := &session{opts: &globalOpts{StopAfter: "plan", Format: "json"}, cfg: &config.Config{}, runner: &runner.Runner{Target: fx}, elevate: runner.ElevateNone}
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	if err := runStopAfter(cmd, sess); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Kind   string             `json:"kind"`
		Checks []checkDescription `json:"checks"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(fx.Calls) != 0 {
		t.Fatal("plan executed commands")
	}
	if doc.Kind != "plan" || len(doc.Checks) == 0 {
		t.Fatalf("bad plan: %+v", doc)
	}
	for _, c := range doc.Checks {
		if !c.Baseline {
			t.Fatalf("non-baseline check in plan: %s", c.ID)
		}
	}
}

func TestInvalidFormatRejectedBeforeOutput(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"explain", "sshd.config", "--format", "sarif"})
	if err := root.Execute(); err == nil || out.Len() != 0 {
		t.Fatal("unsupported format was silently accepted")
	}
}

func TestFactsJSONWithEvidenceFromFixture(t *testing.T) {
	// Exercise the actual CLI rendering path without touching a real target.
	sess := &session{opts: &globalOpts{Format: "json", NoPersist: true, IncludeEvidence: true}, cfg: &config.Config{}, started: time.Now(), runner: &runner.Runner{Target: fixture.New(check.Linux)}, elevate: runner.ElevateNone}
	var out bytes.Buffer
	sheet := &baseline.FactSheet{Platform: check.Linux, Results: map[string]runner.Result{"sys.uname": {Status: runner.StatusOK, Attempted: true, Raw: "Linux fixture", Parsed: "Linux fixture"}}}
	if _, err := sess.writeReport(&out, sheet); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	// Phase 1 assesses with the posture rules and says so; the assessment
	// scope is a field of its own, never inferred from an empty findings
	// array (docs/SPEC.md §7.4).
	if doc["run"].(map[string]any)["assessment"] != "rules" {
		t.Fatalf("assessment scope: %v", doc["run"].(map[string]any)["assessment"])
	}
	if _, ok := doc["assessments"].([]any); !ok {
		t.Fatal("no assessment coverage array")
	}
	if doc["facts"].(map[string]any)["sys.uname"].(map[string]any)["summary"] != "Linux fixture" {
		t.Fatalf("fact summary: %v", doc["facts"].(map[string]any)["sys.uname"])
	}
	f := doc["facts"].(map[string]any)["sys.uname"].(map[string]any)
	if f["evidence"].(map[string]any)["stdout"] != "Linux fixture" {
		t.Fatal("missing evidence")
	}
}
