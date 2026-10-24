package report

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/b87/scheck/internal/baseline"
	_ "github.com/b87/scheck/internal/check/all"
	"github.com/b87/scheck/internal/operator"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/runner"
	"github.com/b87/scheck/internal/target/fixture"
)

func sheetFor(t *testing.T, name string, elevate runner.Elevation) *baseline.FactSheet {
	t.Helper()
	fx, err := fixture.Load(filepath.Join("..", "..", "testdata", "fixtures", name))
	if err != nil {
		t.Skip(err)
	}
	red, _ := policy.NewRedactor(nil)
	r := &runner.Runner{Target: fx, Paths: policy.NewPathPolicy(nil), Redactor: red, Budgets: policy.DefaultBudgets(), Elevate: elevate}
	return baseline.Run(context.Background(), r, baseline.Plan(fx.Platform(), nil), nil)
}

func meta() Meta {
	return Meta{Started: time.Now().Add(-time.Second), Transport: "fixture", Canary: "n/a", Elevation: "sudo", Profile: "baseline", Version: "test"}
}

// reportSchema compiles docs/report-schema.json, which is the contract both
// the freshly rendered envelope and the committed golden JSON are held to.
func reportSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "report-schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schemaDoc any
	if err := json.Unmarshal(raw, &schemaDoc); err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("report-schema.json", schemaDoc); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile("report-schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

// Every fixture's rendered JSON validates against docs/report-schema.json.
func TestEnvelopeMatchesSchema(t *testing.T) {
	schema := reportSchema(t)
	for _, name := range []string{"ubuntu", "fedora", "macos"} {
		t.Run(name, func(t *testing.T) {
			env := Build(sheetFor(t, name, runner.ElevateSudo), meta())
			resolve := func(ref, id string) {
				t.Helper()
				o, ok := env.Observations[ref]
				if !ok || o.Check != id || o.Observation != ref {
					t.Fatalf("unresolved %s for %s", ref, id)
				}
			}
			for id, f := range env.Facts {
				resolve(f.Observation, id)
			}
			for _, f := range env.Findings {
				for _, e := range f.Evidence {
					if e.Check != "context" {
						resolve(e.Observation, e.Check)
					}
				}
			}
			for _, a := range env.Assessments {
				if a.Observation != "" {
					resolve(a.Observation, a.Check)
				} else if a.Status == "matched" || a.Status == "not_matched" || a.Reason == "" {
					t.Fatalf("missing assessment observation: %+v", a)
				}
			}

			var buf bytes.Buffer
			if err := WriteJSONEvidence(&buf, env, true); err != nil {
				t.Fatal(err)
			}
			var doc any
			if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(doc); err != nil {
				t.Fatalf("schema violation:\n%v", err)
			}
		})
	}
}

func TestHostIdentityStableAndDerived(t *testing.T) {
	a := Build(sheetFor(t, "ubuntu", runner.ElevateSudo), meta())
	b := Build(sheetFor(t, "ubuntu", runner.ElevateSudo), meta())
	if a.Host.ID != b.Host.ID || len(a.Host.ID) != 64 {
		t.Errorf("host.id unstable: %s vs %s", a.Host.ID, b.Host.ID)
	}
	if a.Host.OS == "" || !strings.HasPrefix(a.Host.OS, "Ubuntu") || a.Host.Kernel == "" || a.Host.Hostname == "" {
		t.Errorf("host block incomplete: %+v", a.Host)
	}
	m := Build(sheetFor(t, "macos", runner.ElevateNone), meta())
	if !strings.HasPrefix(m.Host.OS, "macOS") || m.Host.ID == a.Host.ID || len(m.Run.Warnings) != 0 {
		t.Errorf("macos host block: %+v warnings %v", m.Host, m.Run.Warnings)
	}
	// No machine id at all: derived from hostname, with a warning.
	sheet := &baseline.FactSheet{Platform: "linux", Results: map[string]runner.Result{
		"host.hostname": {Status: runner.StatusOK, Raw: "box\n"},
	}}
	d := Build(sheet, meta())
	if len(d.Host.ID) != 64 || len(d.Run.Warnings) != 1 || d.Host.ID != HashID("hostname:box") {
		t.Errorf("derived id: %+v %v", d.Host, d.Run.Warnings)
	}
}

func TestFactSheetMentionsEveryCheck(t *testing.T) {
	env := Build(sheetFor(t, "ubuntu", runner.ElevateSudo), meta())
	var buf bytes.Buffer
	if err := WriteFactSheet(&buf, env, Options{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for id := range env.Facts {
		if !strings.Contains(out, id) {
			t.Errorf("%s missing from text report", id)
		}
	}
	for _, want := range []string{"SSH server", "Network exposure", "skipped"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q missing from text report:\n%s", want, out)
		}
	}
}

// A kept host's facts, read back from its persisted evidence envelope, are
// assessed and graded exactly as the facts the session collected: every
// fixture, both profiles, and a context whose expected_services read the
// typed listeners and whose acceptance grades a finding
// (docs/spec/runs.md, "Verdicts are not evidence").
func TestKeptFactsAssessAsCollected(t *testing.T) {
	for _, name := range []string{"ubuntu", "fedora", "macos"} {
		for _, elev := range []runner.Elevation{runner.ElevateSudo, runner.ElevateNone} {
			sheet := sheetFor(t, name, elev)
			// The first finding's id, when the fixture opens one.
			accepted := "sshd.password_auth_enabled"
			if first := Build(sheet, meta()).Findings; len(first) > 0 {
				accepted = first[0].ID
			}
			for _, profile := range []string{"baseline", "hardened"} {
				m := meta()
				m.Profile, m.Now = profile, time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
				m.Context = &operator.Merged{Structured: operator.Structured{Exposure: "internet",
					ExpectedServices: []operator.Service{{Port: 22, Proto: "tcp", Purpose: "ssh", Source: "e"}, {Port: 8443, Proto: "tcp", Purpose: "app", Source: "e"}},
					AcceptedRisks:    []operator.Risk{{ID: accepted, Reason: "known", Expires: "2026-12-31", Source: "e"}}},
					Origins: map[string]string{"exposure": "e", "expected_services": "e", "accepted_risks": "e"},
					Sources: []operator.Source{{Name: "e", Kind: "config"}}, Warnings: []string{"a context warning"}}
				want := Build(sheet, m)
				raw, err := json.Marshal(Evidence(sheet, m))
				if err != nil {
					t.Fatal(err)
				}
				var kept Envelope
				if err := json.Unmarshal(raw, &kept); err != nil {
					t.Fatal(err)
				}
				if len(kept.Findings) != 0 || len(kept.Assessments) != 0 || len(kept.Run.ContextSources) != 0 {
					t.Fatalf("%s: the evidence envelope holds a verdict or context", name)
				}
				back, err := SheetFrom(kept)
				if err != nil {
					t.Fatalf("%s %s: %v", name, elev, err)
				}
				if !slices.Equal(back.Order, sortedByOccurrence(sheet)) {
					t.Errorf("%s: order %v", name, back.Order)
				}
				got := Assess(kept, back, m)
				for label, pair := range map[string][2]any{
					"assessments": {want.Assessments, got.Assessments}, "findings": {want.Findings, got.Findings},
					"context_sources": {want.Run.ContextSources, got.Run.ContextSources}, "warnings": {want.Run.Warnings, got.Run.Warnings},
					"host": {want.Host, got.Host},
					// Typed, as the collector parsed them, summaries included.
					"facts": {FactsFrom(sheet), FactsFrom(back)},
				} {
					w, _ := json.Marshal(pair[0])
					g, _ := json.Marshal(pair[1])
					if !bytes.Equal(w, g) {
						t.Errorf("%s %s %s: %s differ\n--- collected ---\n%.1500s\n--- kept ---\n%.1500s", name, elev, profile, label, w, g)
					}
				}
			}
		}
	}
}

func sortedByOccurrence(sheet *baseline.FactSheet) []string {
	ids := slices.Collect(maps.Keys(sheet.Results))
	slices.SortFunc(ids, func(a, b string) int { return sheet.Results[a].Occurrence - sheet.Results[b].Occurrence })
	return ids
}

// A persisted fact this build cannot read back is refused, never graded
// as something else: the host is collected again.
func TestSheetFromRefusesWhatItCannotReadBack(t *testing.T) {
	sheet := sheetFor(t, "ubuntu", runner.ElevateSudo)
	for label, edit := range map[string]func(*Envelope){
		"platform": func(e *Envelope) { e.Host.Platform = "plan9" },
		"status":   func(e *Envelope) { f := e.Facts["net.listeners"]; f.Status = "maybe"; e.Facts["net.listeners"] = f },
		"shape": func(e *Envelope) {
			f := e.Facts["net.listeners"]
			f.Parsed = []any{"tcp 0.0.0.0:22"}
			e.Facts["net.listeners"] = f
		},
		"kind": func(e *Envelope) {
			f := e.Facts["net.listeners"]
			f.Parsed = map[string]any{"kind": "units", "items": []any{}, "partial": false}
			e.Facts["net.listeners"] = f
		},
		"missing parsed": func(e *Envelope) { f := e.Facts["sshd.config"]; f.Parsed = nil; e.Facts["sshd.config"] = f },
		"unknown check": func(e *Envelope) {
			e.Facts["no.such"] = Fact{Observation: "no.such#1", Status: "ok", Parsed: "x"}
			e.Observations["no.such#1"] = Observation{Check: "no.such"}
		},
		"foreign observation": func(e *Envelope) {
			f := e.Facts["sshd.config"]
			f.Observation = e.Facts["net.listeners"].Observation
			e.Facts["sshd.config"] = f
		},
	} {
		raw, _ := json.Marshal(Evidence(sheet, meta()))
		var env Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatal(err)
		}
		edit(&env)
		if _, err := SheetFrom(env); err == nil {
			t.Errorf("%s: read back", label)
		}
	}
}
