package report

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/b87/scheck/internal/baseline"
	_ "github.com/b87/scheck/internal/check/all"
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

// Every fixture's rendered JSON validates against docs/report-schema.json.
func TestEnvelopeMatchesSchema(t *testing.T) {
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
	for _, name := range []string{"ubuntu", "fedora", "macos"} {
		t.Run(name, func(t *testing.T) {
			env := Build(sheetFor(t, name, runner.ElevateSudo), meta())
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

func TestTextRendererMentionsEveryCheck(t *testing.T) {
	env := Build(sheetFor(t, "ubuntu", runner.ElevateSudo), meta())
	var buf bytes.Buffer
	if err := WriteText(&buf, env, Options{}); err != nil {
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
